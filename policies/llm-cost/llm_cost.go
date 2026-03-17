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

package llmcost

import (
	"encoding/json"
	"fmt"
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	// MetadataLLMCost is the SharedContext metadata key for the calculated LLM cost.
	// Value is a USD float formatted to 10 decimal places.
	MetadataLLMCost = "x-llm-cost"

	// MetadataLLMCostStatus indicates whether the cost was successfully calculated.
	// Value is either "calculated" or "not_calculated".
	// This disambiguates x-llm-cost: 0 (which could mean zero cost or a failed calculation).
	MetadataLLMCostStatus = "x-llm-cost-status"

	costStatusCalculated    = "calculated"
	costStatusNotCalculated = "not_calculated"
)

// LLMCostPolicy calculates the cost of an LLM API call from the response body
// and stores the result in SharedContext.Metadata under "x-llm-cost" (USD float).
type LLMCostPolicy struct {
	pricingMap map[string]ModelPricing
}

// GetPolicy instantiates a new LLMCostPolicy. It loads the pricing database
// from the pricing_file system parameter once at route-instantiation time.
func GetPolicy(
	_ policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	pricingFile, _ := params["pricing_file"].(string)
	if pricingFile == "" {
		return nil, fmt.Errorf("llm-cost: pricing_file system parameter is required but not set")
	}
	pm, err := loadPricingFromFile(pricingFile)
	if err != nil {
		return nil, fmt.Errorf("llm-cost: failed to load pricing file %q: %w", pricingFile, err)
	}
	slog.Info("llm-cost: pricing map loaded", "path", pricingFile, "entries", len(pm))
	return &LLMCostPolicy{pricingMap: pm}, nil
}

// Mode declares the SDK processing requirements:
//   - RequestBodyMode=Buffer: buffer the request so ctx.RequestBody is available
//     in OnResponse (needed for Anthropic speed parameter).
//   - ResponseBodyMode=Buffer: buffer the full response body so we can parse
//     the usage object and model name.
func (p *LLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestBodyMode:  policy.BodyModeBuffer,
		ResponseBodyMode: policy.BodyModeBuffer,
	}
}

// OnRequest is a no-op — all work is done in OnResponse.
func (p *LLMCostPolicy) OnRequest(ctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	return policy.UpstreamRequestModifications{}
}

// OnResponse reads the LLM response, looks up model pricing, calculates cost,
// and stores the result in SharedContext.Metadata.
func (p *LLMCostPolicy) OnResponse(ctx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if ctx.ResponseBody == nil || !ctx.ResponseBody.Present || len(ctx.ResponseBody.Content) == 0 {
		slog.Warn("llm-cost: empty or missing response body, skipping cost calculation")
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	responseBody := ctx.ResponseBody.Content

	// Extract model name from response body.
	// OpenAI-compatible providers use $.model; Gemini uses $.modelVersion.
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
	}
	if err := json.Unmarshal(responseBody, &probe); err != nil {
		slog.Warn("llm-cost: could not parse response body", "error", err)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in response body ($.model or $.modelVersion)")
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Look up pricing entry.
	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Select provider calculator.
	calc := selectCalculator(pricing.Provider)

	// Get buffered request body (may be nil for providers that don't need it).
	var requestBody []byte
	if ctx.RequestBody != nil && ctx.RequestBody.Present {
		requestBody = ctx.RequestBody.Content
	}

	// Normalize provider-specific usage fields into our common Usage struct.
	usage, err := calc.Normalize(responseBody, requestBody)
	if err != nil {
		slog.Warn("llm-cost: failed to normalize usage", "model", modelName, "error", err)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Calculate base cost using the provider-agnostic generic calculator.
	baseCost := genericCalculateCost(usage, pricing)

	// Apply provider-specific adjustments (geo/speed multipliers, router flat cost, etc.).
	finalCost := calc.Adjust(baseCost, usage, pricing)

	slog.Debug("llm-cost: calculated cost",
		"model", modelName,
		"provider", pricing.Provider,
		"prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens,
		"cost_usd", finalCost,
	)

	return setCostMetadata(ctx, finalCost, costStatusCalculated)
}

// setCostMetadata writes x-llm-cost and x-llm-cost-status into SharedContext.Metadata
// so downstream policies can read the cost without it being exposed as a response header.
func setCostMetadata(ctx *policy.ResponseContext, costUSD float64, status string) policy.ResponseAction {
	if ctx.SharedContext == nil {
		slog.Warn("llm-cost: SharedContext is nil, cannot set cost metadata")
		return policy.UpstreamResponseModifications{}
	}
	if ctx.SharedContext.Metadata == nil {
		ctx.SharedContext.Metadata = make(map[string]interface{})
	}
	ctx.SharedContext.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", costUSD)
	ctx.SharedContext.Metadata[MetadataLLMCostStatus] = status
	return policy.UpstreamResponseModifications{}
}
