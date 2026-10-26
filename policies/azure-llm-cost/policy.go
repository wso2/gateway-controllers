/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package azurellmcost

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	MetadataLLMCost       = "x-llm-cost"
	MetadataLLMCostStatus = "x-llm-cost-status"

	metadataPromptTokenCount     = "aitoken:prompttokencount"
	metadataCompletionTokenCount = "aitoken:completiontokencount"
	metadataTotalTokenCount      = "aitoken:totaltokencount"
	metadataModelID              = "aitoken:modelid"

	metadataTemplateHandle = "template_handle"

	costStatusCalculated    = "calculated"
	costStatusNotCalculated = "not_calculated"
)

// AzureLLMCostPolicy prices Azure OpenAI and Azure AI Foundry responses.
type AzureLLMCostPolicy struct {
	pricingMap map[string]ModelPricing

	// Keyed by lowercased deployment name. Needed because most Azure endpoints
	// echo the deployment rather than the model, and never report the tier.
	modelMappings map[string]deploymentMapping
}

type deploymentMapping struct {
	model  string
	region azureRegion
}

// GetPolicy returns a fresh instance per call, since modelMappings is
// per-attachment. The pricing map itself is cached by file path.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	pricingFile, _ := params["pricing_file"].(string)
	if pricingFile == "" {
		return nil, fmt.Errorf("azure-llm-cost: pricing_file system parameter is required but not set")
	}
	pm, err := loadPricingFromFile(pricingFile)
	if err != nil {
		return nil, fmt.Errorf("azure-llm-cost: failed to load pricing file %q: %w", pricingFile, err)
	}
	mappings, err := parseModelMappings(params["modelMappings"])
	if err != nil {
		return nil, fmt.Errorf("azure-llm-cost: invalid modelMappings: %w", err)
	}
	if len(mappings) == 0 {
		slog.Warn("azure-llm-cost: no modelMappings configured; only endpoints that " +
			"report a resolvable model name will be priced under global standard rates")
	}
	slog.Info("azure-llm-cost: policy instance created",
		"pricing_file", pricingFile, "entries", len(pm), "model_mappings", len(mappings))
	return &AzureLLMCostPolicy{pricingMap: pm, modelMappings: mappings}, nil
}

// parseRegion falls back to Global Standard for anything unrecognized.
func parseRegion(raw interface{}) azureRegion {
	s, _ := raw.(string)
	switch r := azureRegion(strings.ToLower(strings.TrimSpace(s))); r {
	case regionUS, regionEU, regionAPAC, regionRegional, regionGlobalStandard, regionProvisioned:
		return r
	default:
		return regionGlobalStandard
	}
}

// parseModelMappings builds a lookup keyed by the lowercased deployment name.
func parseModelMappings(raw interface{}) (map[string]deploymentMapping, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected an array, got %T", raw)
	}
	mappings := make(map[string]deploymentMapping, len(list))
	for i, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("entry %d: expected an object, got %T", i, item)
		}
		deployment, _ := entry["deployment"].(string)
		model, _ := entry["model"].(string)
		deployment = strings.ToLower(strings.TrimSpace(deployment))
		model = strings.TrimSpace(model)
		if deployment == "" || model == "" {
			return nil, fmt.Errorf("entry %d: both 'deployment' and 'model' are required", i)
		}
		mappings[deployment] = deploymentMapping{model: model, region: parseRegion(entry["region"])}
	}
	return mappings, nil
}

// Streaming also covers buffered responses, delivered as one chunk with
// EndOfStream. The request is buffered so $.model stays readable.
func (p *AzureLLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// NeedsMoreResponseData is always false; chunks are accumulated manually.
func (p *AzureLLMCostPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody handles the buffered fallback path.
func (p *AzureLLMCostPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}
	var body []byte
	if respCtx.ResponseBody != nil && respCtx.ResponseBody.Present {
		body = respCtx.ResponseBody.Content
	}
	result := p.computeCost(body, requestBody, respCtx.RequestPath, templateHandleFrom(respCtx.SharedContext))
	setCostMetadata(respCtx.SharedContext, result)
	return policy.DownstreamResponseModifications{AnalyticsMetadata: analyticsFor(result)}
}

// OnResponseBodyChunk accumulates chunks and prices at end of stream.
func (p *AzureLLMCostPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if len(chunk.Chunk) > 0 {
		if respCtx.Metadata == nil {
			respCtx.Metadata = make(map[string]interface{})
		}
		existing, _ := respCtx.Metadata[streamAccumKey].([]byte)
		respCtx.Metadata[streamAccumKey] = append(existing, chunk.Chunk...)
	}

	if !chunk.EndOfStream {
		return policy.ForwardResponseChunk{}
	}

	var accumulated []byte
	if respCtx.Metadata != nil {
		accumulated, _ = respCtx.Metadata[streamAccumKey].([]byte)
		delete(respCtx.Metadata, streamAccumKey)
	}
	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	result := p.computeCost(accumulated, requestBody, respCtx.RequestPath, templateHandleFrom(respCtx.SharedContext))
	setCostMetadata(respCtx.SharedContext, result)

	return policy.ForwardResponseChunk{AnalyticsMetadata: analyticsFor(result)}
}

// analyticsFor builds the analytics metadata both response phases publish, so a
// streamed and a buffered response report the same fields.
func analyticsFor(result costResult) map[string]interface{} {
	metadata := map[string]interface{}{MetadataLLMCost: result.cost}
	if !result.calculated {
		return metadata
	}
	metadata[metadataModelID] = result.modelKey
	metadata[metadataPromptTokenCount] = strconv.FormatInt(result.usage.TotalInputTokens, 10)
	metadata[metadataCompletionTokenCount] = strconv.FormatInt(result.usage.OutputTokens, 10)
	metadata[metadataTotalTokenCount] = strconv.FormatInt(result.usage.TotalInputTokens+result.usage.OutputTokens, 10)
	return metadata
}

type costResult struct {
	cost       float64
	modelKey   string
	usage      Usage
	calculated bool
}

// computeCost never errors; every failure yields an uncalculated result.
func (p *AzureLLMCostPolicy) computeCost(responseBody, requestBody []byte, requestPath, templateHandle string) costResult {
	if len(responseBody) == 0 {
		slog.Warn("azure-llm-cost: empty response body, skipping cost calculation")
		return costResult{}
	}

	region := p.regionForRequest(requestBody, requestPath)
	if region == regionProvisioned {
		slog.Debug("azure-llm-cost: provisioned deployment bills reserved capacity, request not priced")
		return costResult{}
	}

	normalized, err := normalizeStreamBody(responseBody)
	if err != nil {
		slog.Warn("azure-llm-cost: failed to prepare response body", "error", err)
		return costResult{}
	}

	pricing, key, candidates, found := p.resolvePricingForRegion(normalized, requestBody, requestPath, templateHandle, region)
	if !found {
		slog.Warn("azure-llm-cost: model not found for costing, request not priced",
			"candidates", strings.Join(candidates, ","))
		return costResult{}
	}
	if pricing.Unpriced() {
		slog.Warn("azure-llm-cost: model has no per-token pricing, request not priced", "model", key)
		return costResult{}
	}

	usage, err := normalizeUsage(normalized)
	if err != nil {
		slog.Warn("azure-llm-cost: failed to parse usage object", "model", key, "error", err)
		return costResult{}
	}
	if usage.TotalInputTokens == 0 && usage.OutputTokens == 0 {
		slog.Warn("azure-llm-cost: response has no usage data, request not priced", "model", key)
		return costResult{}
	}

	cost := calculateCost(usage, pricing)
	slog.Debug("azure-llm-cost: calculated cost",
		"model", key,
		"input_tokens", usage.TotalInputTokens, "output_tokens", usage.OutputTokens,
		"cached_tokens", usage.CachedReadTokens, "cost_usd", cost,
	)
	return costResult{cost: cost, modelKey: key, usage: usage, calculated: true}
}

// templateHandleFrom reads the handle the kernel records for the route.
func templateHandleFrom(sharedCtx *policy.SharedContext) string {
	if sharedCtx == nil || sharedCtx.Metadata == nil {
		return ""
	}
	handle, _ := sharedCtx.Metadata[metadataTemplateHandle].(string)
	return handle
}

// setCostMetadata publishes the cost and its status for downstream policies.
func setCostMetadata(sharedCtx *policy.SharedContext, result costResult) {
	if sharedCtx == nil {
		slog.Warn("azure-llm-cost: SharedContext is nil, cannot set cost metadata")
		return
	}
	if sharedCtx.Metadata == nil {
		sharedCtx.Metadata = make(map[string]interface{})
	}
	status := costStatusNotCalculated
	if result.calculated {
		status = costStatusCalculated
	}
	sharedCtx.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", result.cost)
	sharedCtx.Metadata[MetadataLLMCostStatus] = status
}
