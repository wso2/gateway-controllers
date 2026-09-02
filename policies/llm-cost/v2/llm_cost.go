package llmcost

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

	CostStatusCalculated    = "calculated"
	CostStatusNotCalculated = "not_calculated"

	metadataPromptTokenCount     = "aitoken:prompttokencount"
	metadataCompletionTokenCount = "aitoken:completiontokencount"
	metadataTotalTokenCount      = "aitoken:totaltokencount"
	metadataModelID              = "aitoken:modelid"
)

// LLMCostPolicy prices LLM calls from the route's provider template.
type LLMCostPolicy struct {
	pricingMap map[string]ModelPricing
}

// GetPolicy reads the pricing file once, at startup.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	pricingFile, ok := params["pricing_file"].(string)
	if !ok || pricingFile == "" {
		return nil, fmt.Errorf("llm-cost: pricing_file is required")
	}

	pricingMap, err := loadPricingFromFile(pricingFile)
	if err != nil {
		return nil, fmt.Errorf("llm-cost: failed to load pricing file %q: %w", pricingFile, err)
	}

	slog.Info("llm-cost: pricing map loaded", "path", pricingFile, "entries", len(pricingMap))
	return &LLMCostPolicy{pricingMap: pricingMap}, nil
}

// Mode buffers the request so the model name is readable in the response phase,
// and takes the response as chunks so streaming and buffered share one path.
func (p *LLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// NeedsMoreResponseData always returns false; chunks are accumulated manually.
func (p *LLMCostPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBodyChunk accumulates the response and prices it at end of stream.
func (p *LLMCostPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	accumulated := llmusage.Accumulate(respCtx.SharedContext, chunk)

	if !chunk.EndOfStream {
		return policy.ForwardResponseChunk{}
	}

	// Check for Bedrock event-stream framing and unwrap to JSON if present.
	accumulated = decodeIfEventStream(accumulated)

	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	result := p.price(respCtx.SharedContext, accumulated, requestBody, respCtx.RequestPath)
	setCostMetadata(respCtx.SharedContext, result)

	return policy.ForwardResponseChunk{AnalyticsMetadata: analyticsFor(result)}
}

// OnResponseBody prices a response delivered whole. Required even when unused:
// StreamingResponsePolicy embeds ResponsePolicy, and a policy failing that
// assertion is skipped by the kernel without an error.
func (p *LLMCostPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	var body []byte
	if respCtx.ResponseBody != nil && respCtx.ResponseBody.Present {
		body = decodeIfEventStream(respCtx.ResponseBody.Content)
	}

	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	result := p.price(respCtx.SharedContext, body, requestBody, respCtx.RequestPath)
	setCostMetadata(respCtx.SharedContext, result)

	return policy.DownstreamResponseModifications{AnalyticsMetadata: analyticsFor(result)}
}

// analyticsFor builds the analytics metadata. Cost is always reported; the rest
// only when pricing succeeded, and the pipeline needs modelid to emit AI data.
func analyticsFor(result costResult) map[string]any {
	metadata := map[string]any{MetadataLLMCost: result.cost}
	if result.calculated {
		metadata[metadataModelID] = result.modelKey
		metadata[metadataPromptTokenCount] = strconv.FormatInt(result.promptTokens, 10)
		metadata[metadataCompletionTokenCount] = strconv.FormatInt(result.completionTokens, 10)
		metadata[metadataTotalTokenCount] = strconv.FormatInt(result.totalTokens, 10)
	}
	return metadata
}

// costResult carries the outcome of pricing one response.
type costResult struct {
	cost             float64
	modelKey         string
	promptTokens     int64
	completionTokens int64
	totalTokens      int64
	calculated       bool
}

// resourcePathFrom derives the path resourceMappings are matched against. The
// route's declared path collapses to "/*" when the provider allows everything,
// so the called URL is used instead, with the API's context trimmed off. What
// remains still carries any pathParam value, which sits after the context.
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

// price resolves usage, looks up the model and computes the cost. Every failure
// yields an uncalculated result and leaves the response untouched.
func (p *LLMCostPolicy) price(sc *policy.SharedContext, body, requestBody []byte, requestPath string) costResult {
	if len(body) == 0 {
		slog.Warn("llm-cost: empty response body, skipping cost calculation")
		return costResult{}
	}

	extracted, err := llmusage.Get(sc, body, requestBody, resourcePathFrom(sc, requestPath))
	if err != nil {
		slog.Warn("llm-cost: could not extract usage", "path", requestPath, "error", err)
		return costResult{}
	}
	if extracted.Model == "" {
		slog.Warn("llm-cost: no model name in response or request", "path", requestPath)
		return costResult{}
	}

	pricing, modelKey, found := LookupPricingWithKey(p.pricingMap, extracted.Model)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0",
			"model", extracted.Model, "candidates", extracted.ModelCandidates)
		return costResult{}
	}

	usage := ToPricingUsage(extracted)

	calc := SelectCalculator(pricing.Provider)
	if calc != nil {
		usage = ApplyFees(calc, usage, sc, body, requestBody, requestPath)
	}

	components := CalculateCostComponents(usage, pricing)
	cost := components.Total()
	if calc != nil {
		cost = calc.Adjust(cost, usage, pricing)
	}

	return costResult{
		cost:             cost,
		modelKey:         modelKey,
		promptTokens:     usage.PromptTokens,
		completionTokens: usage.CompletionTokens,
		totalTokens:      usage.TotalTokens,
		calculated:       true,
	}
}

// setCostMetadata publishes the cost and its status for downstream policies.
func setCostMetadata(sc *policy.SharedContext, result costResult) {
	if sc == nil {
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
