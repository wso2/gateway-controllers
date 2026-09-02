package llmcost

import (
	"github.com/wso2/api-platform/sdk/ai/llmusage"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ToPricingUsage maps template-extracted usage onto the struct the pricing
// arithmetic consumes. PromptTokens carries the full input total because
// GenericCalculateCost subtracts the cached, cache-write and audio categories.
func ToPricingUsage(u llmusage.Usage) Usage {
	usage := Usage{
		PromptTokens:          u.TotalInputTokens,
		CompletionTokens:      u.OutputTokens,
		TotalTokens:           u.TotalTokens,
		InputTokensForTiering: u.TotalInputTokens,
		CachedReadTokens:      u.CachedReadTokens,
		CacheWriteTokens:      u.CacheWriteTokens,
		CacheWrite1hrTokens:   u.CacheWrite1hTokens,
		ReasoningTokens:       u.ReasoningTokens,
		AudioInputTokens:      u.AudioInputTokens,
		AudioOutputTokens:     u.AudioOutputTokens,
		ServiceTier:           u.ServiceTier,
	}
	return usage
}

// ApplyFees adds the charges a field path cannot express.
func ApplyFees(calc feeCalculator, usage Usage, sc *policy.SharedContext,
	body, requestBody []byte, requestPath string) Usage {

	return calc.fees(fieldLookups{
		Response: func(name string) (interface{}, bool) {
			return llmusage.ProviderField(sc, body, requestPath, name)
		},
		Request: func(name string) (interface{}, bool) {
			return llmusage.ProviderFieldFromRequest(sc, requestBody, requestPath, name)
		},
	}, usage)
}

// toFloat reads a JSON number, which decodes as float64, into a float.
func toFloat(raw interface{}) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case int64:
		return float64(value), true
	}
	return 0, false
}
