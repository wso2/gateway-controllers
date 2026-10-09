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

	"github.com/wso2/api-platform/sdk/ai/llmusage"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	MetadataLLMCost       = "x-llm-cost"
	MetadataLLMCostStatus = "x-llm-cost-status"

	metadataPromptTokenCount     = "aitoken:prompttokencount"
	metadataCompletionTokenCount = "aitoken:completiontokencount"
	metadataTotalTokenCount      = "aitoken:totaltokencount"
	metadataModelID              = "aitoken:modelid"

	CostStatusCalculated    = "calculated"
	CostStatusNotCalculated = "not_calculated"
)

// AzureLLMCostPolicy prices Azure OpenAI and Azure AI Foundry responses from
// the token locations the route's provider template declares.
type AzureLLMCostPolicy struct {
	pricingMap map[string]ModelPricing

	// Keyed by lowercased deployment name. Azure reports the deployment rather
	// than the model on most endpoints, and never reports the tier.
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
		return nil, fmt.Errorf("azure-llm-cost: pricing_file is required")
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
	case regionUS, regionEU, regionAPAC, regionRegional, regionGlobalStandard:
		return r
	default:
		return regionGlobalStandard
	}
}

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
// EndOfStream. The request is buffered so the model stays readable.
func (p *AzureLLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

func (p *AzureLLMCostPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody handles the buffered fallback path.
func (p *AzureLLMCostPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	var body []byte
	if respCtx.ResponseBody != nil && respCtx.ResponseBody.Present {
		body = respCtx.ResponseBody.Content
	}
	result := p.computeCost(respCtx.SharedContext, body, requestBodyOf(respCtx.RequestBody), respCtx.RequestPath)
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
	accumulated := llmusage.Accumulate(respCtx.SharedContext, chunk)
	if !chunk.EndOfStream {
		return policy.ForwardResponseChunk{}
	}

	result := p.computeCost(respCtx.SharedContext, accumulated, requestBodyOf(respCtx.RequestBody), respCtx.RequestPath)
	setCostMetadata(respCtx.SharedContext, result)

	return policy.ForwardResponseChunk{AnalyticsMetadata: analyticsFor(result)}
}

func requestBodyOf(b *policy.Body) []byte {
	if b == nil || !b.Present {
		return nil
	}
	return b.Content
}

type costResult struct {
	cost       float64
	modelKey   string
	usage      llmusage.Usage
	calculated bool
}

// computeCost never errors; every failure yields an uncalculated result.
func (p *AzureLLMCostPolicy) computeCost(sc *policy.SharedContext, body, requestBody []byte, requestPath string) costResult {
	if len(body) == 0 {
		slog.Warn("azure-llm-cost: empty response body, skipping cost calculation")
		return costResult{}
	}
	v := selectVendor(templateHandleFrom(sc))
	if v == nil {
		return costResult{}
	}

	usage, err := llmusage.Get(sc, body, requestBody, resourcePathFrom(sc, requestPath))
	if err != nil {
		slog.Warn("azure-llm-cost: could not extract usage", "path", requestPath, "error", err)
		return costResult{}
	}

	pricing, key, candidates, found := p.resolvePricing(usage, requestPath, v)
	if !found {
		slog.Warn("azure-llm-cost: model not found for costing, request not priced",
			"candidates", strings.Join(candidates, ","))
		return costResult{}
	}
	if pricing.Unpriced() {
		slog.Warn("azure-llm-cost: model has no per-token pricing, request not priced", "model", key)
		return costResult{}
	}
	if usage.TotalInputTokens == 0 && usage.OutputTokens == 0 {
		slog.Warn("azure-llm-cost: response has no usage data, request not priced.", "model", key)
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

func templateHandleFrom(sc *policy.SharedContext) string {
	if sc == nil || sc.Metadata == nil {
		return ""
	}
	handle, _ := sc.Metadata[llmusage.MetadataTemplateHandle].(string)
	return handle
}

// resourcePathFrom derives the path resourceMappings are matched against. The
// route's declared path collapses to "/*" when the provider allows everything,
// so the called URL is used instead, with the API's context trimmed off.
func resourcePathFrom(sc *policy.SharedContext, requestPath string) string {
	if i := strings.IndexByte(requestPath, '?'); i >= 0 {
		requestPath = requestPath[:i]
	}
	if sc == nil {
		return requestPath
	}
	ctx := strings.ReplaceAll(sc.APIContext, "$version", sc.APIVersion)
	if ctx != "" && ctx != "/" {
		requestPath = strings.TrimPrefix(requestPath, ctx)
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	return requestPath
}

// analyticsFor builds the metadata both response phases publish, so a streamed
// and a buffered response report the same fields.
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

func setCostMetadata(sc *policy.SharedContext, result costResult) {
	if sc == nil {
		slog.Warn("azure-llm-cost: SharedContext is nil, cannot set cost metadata")
		return
	}
	if sc.Metadata == nil {
		sc.Metadata = make(map[string]interface{})
	}
	status := CostStatusNotCalculated
	if result.calculated {
		status = CostStatusCalculated
	}
	sc.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", result.cost)
	sc.Metadata[MetadataLLMCostStatus] = status
}

// The kernel type-asserts the policy when it builds a route's chain; an
// unsatisfied assertion is logged and the policy silently skipped.
var (
	_ policy.ResponsePolicy          = (*AzureLLMCostPolicy)(nil)
	_ policy.StreamingResponsePolicy = (*AzureLLMCostPolicy)(nil)
)
