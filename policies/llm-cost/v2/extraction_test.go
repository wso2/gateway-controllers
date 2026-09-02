package llmcost_test

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"reflect"
	"testing"

	"github.com/wso2/api-platform/sdk/ai/llmusage"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	llmcost "github.com/wso2/gateway-controllers/policies/llm-cost/v2"
)

// Tests for the layer between the response body and the pricing struct: what a
// provider template extracts, what a calculator's fees() adds on top, and the
// Bedrock event-stream unwrap that has to happen before either can read a
// field. These drive the extraction pipeline directly rather than through the
// policy entry point.

// fieldSource records where a Usage field is expected to come from now.
type fieldSource int

const (
	fromTemplate fieldSource = iota
	fromFees
)

// coverage lists every Usage field each provider populates, and which layer
// supplies it: the route's provider template, or a fees() method for a value a
// template field path cannot express. The per-provider
// TestCoverage_*FieldsArrive tests drive a real response through the extraction
// pipeline and confirm each listed field is actually non-zero, which is what
// would have caught Gemini's ServiceTier and Bedrock's CacheWrite1hrTokens
// going missing.
var coverage = map[string]map[string]fieldSource{
	"openai": {
		"PromptTokens": fromTemplate, "CompletionTokens": fromTemplate,
		"TotalTokens": fromTemplate, "CachedReadTokens": fromTemplate,
		"ReasoningTokens": fromTemplate, "AudioInputTokens": fromTemplate,
		"AudioOutputTokens": fromTemplate, "ServiceTier": fromTemplate,
		"WebSearchRequests": fromFees, "SearchContextSize": fromFees,
	},
	"anthropic": {
		"PromptTokens": fromTemplate, "CompletionTokens": fromTemplate,
		"TotalTokens": fromTemplate, "InputTokensForTiering": fromTemplate,
		"CachedReadTokens": fromTemplate, "CacheWriteTokens": fromTemplate,
		"CacheWrite1hrTokens": fromTemplate,
		"InferenceGeo":        fromFees, "Speed": fromFees,
		"WebSearchRequests": fromFees, "SearchContextSize": fromFees,
	},
	"gemini": {
		"PromptTokens": fromTemplate, "CompletionTokens": fromTemplate,
		"TotalTokens": fromTemplate, "ReasoningTokens": fromTemplate,
		"CachedReadTokens":       fromTemplate,
		"CachedAudioInputTokens": fromFees, "AudioInputTokens": fromFees,
		"AudioOutputTokens": fromFees, "ImageOutputTokens": fromFees,
		"ToolUsePromptTokens": fromFees, "ServiceTier": fromFees,
		"GeminiWebSearchRequests": fromFees,
	},
	"mistral": {
		"PromptTokens": fromTemplate, "CompletionTokens": fromTemplate,
		"TotalTokens": fromTemplate, "AudioInputSeconds": fromFees,
	},
	"bedrock": {
		"PromptTokens": fromTemplate, "CompletionTokens": fromTemplate,
		"TotalTokens": fromTemplate, "InputTokensForTiering": fromTemplate,
		"CachedReadTokens": fromTemplate,
		"CacheWriteTokens": fromFees, "CacheWrite1hrTokens": fromFees,
	},
}

// driveUsage runs body and requestBody through the same extraction,
// pricing-usage mapping, and fees step that OnResponseBodyChunk runs, using
// the template stored under handle, and returns the resulting Usage.
func driveUsage(t *testing.T, handle, provider string, body, requestBody []byte, path string) llmcost.Usage {
	t.Helper()

	sc := &policy.SharedContext{Metadata: map[string]interface{}{
		llmusage.MetadataTemplateHandle: handle,
	}}
	extracted, err := llmusage.Get(sc, body, requestBody, path)
	if err != nil {
		t.Fatalf("llmusage.Get failed: %v", err)
	}
	usage := llmcost.ToPricingUsage(extracted)
	if calc := llmcost.SelectCalculator(provider); calc != nil {
		usage = llmcost.ApplyFees(calc, usage, sc, body, requestBody, path)
	}
	return usage
}

// assertFieldsArrived checks, by the Usage field names in fields, that each
// one is non-zero, skipping any name present in skip.
func assertFieldsArrived(t *testing.T, usage llmcost.Usage, fields map[string]fieldSource, skip map[string]bool) {
	t.Helper()

	v := reflect.ValueOf(usage)
	for name := range fields {
		if skip[name] {
			continue
		}
		f := v.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("Usage has no field %q", name)
		}
		if f.IsZero() {
			t.Errorf("%s is zero; the response populated it but it did not reach Usage", name)
		}
	}
}

// TestCoverage_OpenAIFieldsArrive drives a response populating every field in
// coverage["openai"] and confirms each one lands non-zero on Usage.
func TestCoverage_OpenAIFieldsArrive(t *testing.T) {
	loadShippedTemplate(t, "openai", "openai-template.yaml")

	body := []byte(`{"model":"gpt-4o-audio-preview","service_tier":"priority",` +
		`"usage":{"prompt_tokens":1000,"completion_tokens":300,"total_tokens":1300,` +
		`"prompt_tokens_details":{"cached_tokens":200,"audio_tokens":50},` +
		`"completion_tokens_details":{"reasoning_tokens":40,"audio_tokens":20}},` +
		`"choices":[{"message":{"annotations":[{"type":"url_citation"}]}}]}`)
	requestBody := []byte(`{"web_search_options":{"search_context_size":"high"}}`)

	usage := driveUsage(t, "openai", "openai", body, requestBody, "/chat/completions")
	assertFieldsArrived(t, usage, coverage["openai"], nil)
}

// TestCoverage_AnthropicFieldsArrive drives a response populating every field
// in coverage["anthropic"] and confirms each one lands non-zero on Usage.
func TestCoverage_AnthropicFieldsArrive(t *testing.T) {
	loadShippedTemplate(t, "anthropic", "anthropic-template.yaml")

	body := []byte(`{"model":"claude-sonnet-4-5","usage":{` +
		`"input_tokens":1000,"output_tokens":200,"cache_read_input_tokens":300,` +
		`"cache_creation":{"ephemeral_5m_input_tokens":150,"ephemeral_1h_input_tokens":100},` +
		`"inference_geo":"eu","server_tool_use":{"web_search_requests":2}}}`)
	requestBody := []byte(`{"speed":"fast","web_search_options":{"search_context_size":"medium"}}`)

	usage := driveUsage(t, "anthropic", "anthropic", body, requestBody, "/v1/messages")
	assertFieldsArrived(t, usage, coverage["anthropic"], nil)
}

// TestCoverage_GeminiFieldsArrive drives a response populating every field in
// coverage["gemini"], including the audio and image modality counts, and
// confirms each lands non-zero on Usage. ServiceTier is the field that
// previously vanished for Gemini.
func TestCoverage_GeminiFieldsArrive(t *testing.T) {
	loadShippedTemplate(t, "gemini", "gemini-template.yaml")

	body := []byte(`{"modelVersion":"gemini-1.5-pro",` +
		`"candidates":[{"groundingMetadata":{"webSearchQueries":["q1","q2"]}}],` +
		`"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":300,"totalTokenCount":1400,` +
		`"thoughtsTokenCount":100,"cachedContentTokenCount":200,` +
		`"promptTokensDetails":[{"modality":"AUDIO","tokenCount":90}],` +
		`"cacheTokensDetails":[{"modality":"AUDIO","tokenCount":40}],` +
		`"candidatesTokensDetails":[{"modality":"IMAGE","tokenCount":25},{"modality":"AUDIO","tokenCount":60}],` +
		`"toolUsePromptTokenCount":15,"trafficType":"ON_DEMAND_PRIORITY"}}`)

	usage := driveUsage(t, "gemini", "gemini", body, nil, "/v1beta/models/gemini-1.5-pro:generateContent")

	assertFieldsArrived(t, usage, coverage["gemini"], nil)
}

// TestCoverage_MistralFieldsArrive drives a response populating every field in
// coverage["mistral"] and confirms each one lands non-zero on Usage.
func TestCoverage_MistralFieldsArrive(t *testing.T) {
	loadShippedTemplate(t, "mistral", "mistral-template.yaml")

	body := []byte(`{"model":"voxtral-mini-latest","usage":{` +
		`"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"prompt_audio_seconds":30}}`)

	usage := driveUsage(t, "mistral", "mistral", body, nil, "/v1/chat/completions")
	assertFieldsArrived(t, usage, coverage["mistral"], nil)
}

// TestCoverage_BedrockFieldsArrive drives a response populating every field in
// coverage["bedrock"] and confirms each one lands non-zero on Usage.
// CacheWrite1hrTokens is the field that previously vanished for Bedrock.
func TestCoverage_BedrockFieldsArrive(t *testing.T) {
	loadShippedTemplate(t, "awsbedrock", "awsbedrock-template.yaml")

	body := []byte(`{"usage":{"inputTokens":1000,"outputTokens":200,"totalTokens":1500,` +
		`"cacheReadInputTokens":300,"cacheWriteInputTokens":250,` +
		`"cacheDetails":[{"ttl":"5m","inputTokens":100},{"ttl":"1h","inputTokens":150}]}}`)

	usage := driveUsage(t, "awsbedrock", "bedrock", body, nil,
		"/model/anthropic.claude-haiku-4-5-20251001-v1:0/converse")
	assertFieldsArrived(t, usage, coverage["bedrock"], nil)
}

// feeCtx stores a template declaring the given provider-specific locations and
// returns a context pointing at it, so ApplyFees can resolve them the way it
// does at runtime.
func feeCtx(t *testing.T, handle string, providerFields map[string]string) *policy.SharedContext {
	t.Helper()

	declared := map[string]interface{}{}
	for name, path := range providerFields {
		declared[name] = map[string]interface{}{"location": "payload", "identifier": path}
	}

	store := policy.GetLazyResourceStoreInstance()
	if err := store.StoreResource(&policy.LazyResource{
		ID:           handle,
		ResourceType: llmusage.ResourceTypeLLMProviderTemplate,
		Resource:     map[string]interface{}{"providerFields": declared},
	}); err != nil {
		t.Fatalf("store template: %v", err)
	}
	t.Cleanup(func() {
		_ = store.RemoveResourceByIDAndType(handle, llmusage.ResourceTypeLLMProviderTemplate)
	})

	return &policy.SharedContext{Metadata: map[string]interface{}{
		llmusage.MetadataTemplateHandle: handle,
	}}
}

func TestApplyFees_OpenAIWebSearchDetected(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"annotations":[{"type":"url_citation"}]}}]}`)
	requestBody := []byte(`{"web_search_options":{"search_context_size":"high"}}`)

	got := llmcost.ApplyFees(&llmcost.OpenAICalculator{}, llmcost.Usage{PromptTokens: 10}, feeCtx(t, "oa1", map[string]string{"choices": "$.choices", "searchContextSize": "$.web_search_options.search_context_size"}), body, requestBody, "/v1/chat/completions")

	if got.WebSearchRequests != 1 {
		t.Errorf("WebSearchRequests = %d, want 1", got.WebSearchRequests)
	}
	if got.SearchContextSize != "high" {
		t.Errorf("SearchContextSize = %q, want high", got.SearchContextSize)
	}
}

func TestApplyFees_OpenAINoSearchLeavesZero(t *testing.T) {
	got := llmcost.ApplyFees(&llmcost.OpenAICalculator{}, llmcost.Usage{PromptTokens: 10}, feeCtx(t, "oa2", map[string]string{"choices": "$.choices", "searchContextSize": "$.web_search_options.search_context_size"}),
		[]byte(`{"choices":[{"message":{}}]}`), nil, "/v1/chat/completions")

	if got.WebSearchRequests != 0 {
		t.Errorf("WebSearchRequests = %d, want 0", got.WebSearchRequests)
	}
}

func TestApplyFees_PreservesExtractedCounts(t *testing.T) {
	// Fee detection must never disturb the token counts the template produced.
	body := []byte(`{"choices":[{"message":{"annotations":[{"type":"url_citation"}]}}]}`)
	in := llmcost.Usage{PromptTokens: 1000, CompletionTokens: 300, CachedReadTokens: 800}

	got := llmcost.ApplyFees(&llmcost.OpenAICalculator{}, in, feeCtx(t, "oa3", map[string]string{"choices": "$.choices", "searchContextSize": "$.web_search_options.search_context_size"}), body, nil, "/v1/chat/completions")

	if got.PromptTokens != 1000 || got.CompletionTokens != 300 || got.CachedReadTokens != 800 {
		t.Errorf("token counts altered by fee detection: %+v", got)
	}
}

func TestApplyFees_BedrockSplitsCacheWritesByTTL(t *testing.T) {
	// Bedrock reports the per-TTL split inside cacheDetails, which a JSONPath
	// cannot select from, so the split is computed here.
	body := []byte(`{"usage":{
		"inputTokens":1000,"outputTokens":200,
		"cacheWriteInputTokens":500,
		"cacheDetails":[{"ttl":"5m","inputTokens":300},{"ttl":"1h","inputTokens":200}]}}`)

	sc := feeCtx(t, "bd1", map[string]string{"cacheDetails": "$.usage.cacheDetails"})
	got := llmcost.ApplyFees(&llmcost.BedrockCalculator{}, llmcost.Usage{PromptTokens: 1000}, sc, body, nil, "/converse")

	if got.CacheWriteTokens != 300 {
		t.Errorf("CacheWriteTokens = %d, want 300 (the 5m bucket)", got.CacheWriteTokens)
	}
	if got.CacheWrite1hrTokens != 200 {
		t.Errorf("CacheWrite1hrTokens = %d, want 200 (the 1h bucket)", got.CacheWrite1hrTokens)
	}
}

func TestApplyFees_BedrockDoesNotInheritOpenAIWebSearch(t *testing.T) {
	// BedrockCalculator has no web-search fee of its own, so an OpenAI-shaped
	// url_citation annotation in the body must not be detected as one.
	body := []byte(`{"choices":[{"message":{"annotations":[{"type":"url_citation"}]}}],
		"usage":{"inputTokens":10,"outputTokens":5}}`)

	sc := feeCtx(t, "bd2", map[string]string{"cacheDetails": "$.usage.cacheDetails"})
	got := llmcost.ApplyFees(&llmcost.BedrockCalculator{}, llmcost.Usage{PromptTokens: 10}, sc, body, nil, "/converse")

	if got.WebSearchRequests != 0 {
		t.Errorf("WebSearchRequests = %d, want 0; Bedrock has no web-search fee", got.WebSearchRequests)
	}
}

// The service tier is declared in the provider template and already present in
// the usage handed to fees(), so a calculator must pass it through. A
// calculator that assigned it would silently override the template, and the
// response body still carries the provider's own tier field to assign from.
func TestApplyFees_GeminiPreservesTemplateServiceTier(t *testing.T) {
	body := []byte(`{"usageMetadata":{"promptTokenCount":10,"trafficType":"ON_DEMAND_PRIORITY"}}`)

	for _, tier := range []string{"priority", "flex", "batch", ""} {
		got := llmcost.ApplyFees(&llmcost.GeminiCalculator{}, llmcost.Usage{PromptTokens: 10, ServiceTier: tier}, feeCtx(t, "gm-"+tier, nil), body, nil, "/v1/models/x:generateContent")
		if got.ServiceTier != tier {
			t.Errorf("ServiceTier = %q, want %q preserved from the template", got.ServiceTier, tier)
		}
	}
}

// esFrame encodes one vnd.amazon.eventstream message per the published format:
// a 12-byte prelude (total length, headers length, prelude CRC32), packed
// headers (uint8 name length, name, type byte; type 7 is a uint16 length plus
// UTF-8), the payload, then a CRC32 over everything preceding it. Written from
// the format spec rather than from the decoder, so this test can fail it.
func esFrame(eventType string, payload []byte) []byte {
	var h bytes.Buffer
	addStr := func(name, val string) {
		h.WriteByte(byte(len(name)))
		h.WriteString(name)
		h.WriteByte(7)
		_ = binary.Write(&h, binary.BigEndian, uint16(len(val)))
		h.WriteString(val)
	}
	addStr(":event-type", eventType)
	addStr(":content-type", "application/json")
	addStr(":message-type", "event")
	headers := h.Bytes()

	prelude := make([]byte, 8)
	binary.BigEndian.PutUint32(prelude[0:4], uint32(12+len(headers)+len(payload)+4))
	binary.BigEndian.PutUint32(prelude[4:8], uint32(len(headers)))

	buf := append([]byte{}, prelude...)
	buf = binary.BigEndian.AppendUint32(buf, crc32.ChecksumIEEE(prelude))
	buf = append(buf, headers...)
	buf = append(buf, payload...)
	return binary.BigEndian.AppendUint32(buf, crc32.ChecksumIEEE(buf))
}

// A ConverseStream response arrives as binary frames, not JSON. Nothing in the
// template or the SDK can address a JSON path inside them, so if the policy
// does not unwrap the framing first the usage never resolves and the request
// silently prices at zero.
func TestBedrockConverseStream_PricesFromTheMetadataFrame(t *testing.T) {
	loadShippedTemplate(t, "bdstream", "awsbedrock-template.yaml")
	p := newTestPolicy(t)

	stream := esFrame("contentBlockDelta", []byte(`{"delta":{"text":"hi"},"contentBlockIndex":0}`))
	stream = append(stream, esFrame("contentBlockStop", []byte(`{"contentBlockIndex":0}`))...)
	stream = append(stream, esFrame("metadata",
		[]byte(`{"usage":{"inputTokens":10,"outputTokens":3,"totalTokens":13},"metrics":{"latencyMs":100}}`))...)

	cost, status := runResponse(t, p, "bdstream", stream, nil,
		"/model/anthropic.claude-3-7-sonnet-20250219-v1:0/converse-stream")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q — the event-stream framing was not decoded", status,
			llmcost.CostStatusCalculated)
	}
	// Same rates as the buffered Converse test: 10 input + 3 output tokens.
	if want := "0.0000750000"; cost != want {
		t.Fatalf("cost = %q, want %q", cost, want)
	}
}

// The unwrap step must not disturb ordinary JSON bodies, which is every other
// provider and Bedrock's own non-streaming replies.
func TestBedrockConverseStream_PlainJSONBodyUnaffected(t *testing.T) {
	loadShippedTemplate(t, "bdplain", "awsbedrock-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"usage":{"inputTokens":10,"outputTokens":3,"totalTokens":13}}`)
	cost, status := runResponse(t, p, "bdplain", body, nil,
		"/model/anthropic.claude-3-7-sonnet-20250219-v1:0/converse")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000750000"; cost != want {
		t.Fatalf("cost = %q, want %q", cost, want)
	}
}

// A body that is neither JSON nor a decodable frame must not panic or be
// mistaken for one; it simply stays unpriced.
func TestBedrockConverseStream_GarbageBodyStaysUnpriced(t *testing.T) {
	loadShippedTemplate(t, "bdjunk", "awsbedrock-template.yaml")
	p := newTestPolicy(t)

	_, status := runResponse(t, p, "bdjunk", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}, nil,
		"/model/anthropic.claude-3-7-sonnet-20250219-v1:0/converse-stream")

	if status == llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want it not calculated for an undecodable body", status)
	}
}
