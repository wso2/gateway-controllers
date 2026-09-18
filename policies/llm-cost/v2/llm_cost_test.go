package llmcost_test

import (
	"context"
	"os"
	"testing"

	"github.com/wso2/api-platform/sdk/ai/llmusage"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	llmcost "github.com/wso2/gateway-controllers/policies/llm-cost/v2"
	"gopkg.in/yaml.v3"
)

// End-to-end tests: a response body goes in through OnResponseBodyChunk and the
// published cost and status come out, using the templates the gateway actually
// ships and the pricing file under testdata.

// The kernel type-asserts each policy against these interfaces when it builds a
// route's chain. An unsatisfied assertion is not an error: the policy is logged
// and skipped, so it stops contributing analytics while every unit test that
// calls its methods directly still passes. StreamingResponsePolicy embeds
// ResponsePolicy, so declaring a non-SKIP ResponseBodyMode requires the
// buffered entry point as well as the streaming one.
var (
	_ policy.ResponsePolicy          = (*llmcost.LLMCostPolicy)(nil)
	_ policy.StreamingResponsePolicy = (*llmcost.LLMCostPolicy)(nil)
)

// loadShippedTemplate reads a provider template from the gateway's shipped set
// and puts it in the lazy-resource store under handle, removing it afterwards.
func loadShippedTemplate(t *testing.T, handle, file string) {
	t.Helper()

	// Copies of the provider templates the gateway ships; api-platform's
	// default-llm-provider-templates is the source of truth for them.
	raw, err := os.ReadFile("testdata/templates/" + file)
	if err != nil {
		t.Fatalf("read template %s: %v", file, err)
	}
	var doc struct {
		Spec map[string]interface{} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse template %s: %v", file, err)
	}
	store := policy.GetLazyResourceStoreInstance()
	if err := store.StoreResource(&policy.LazyResource{
		ID: handle, ResourceType: llmusage.ResourceTypeLLMProviderTemplate, Resource: doc.Spec,
	}); err != nil {
		t.Fatalf("store template: %v", err)
	}
	t.Cleanup(func() { _ = store.RemoveResourceByIDAndType(handle, llmusage.ResourceTypeLLMProviderTemplate) })
}

func newTestPolicy(t *testing.T) *llmcost.LLMCostPolicy {
	t.Helper()

	p, err := llmcost.GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"pricing_file": "testdata/model_prices.json",
	})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	return p.(*llmcost.LLMCostPolicy)
}

// runResponse drives one buffered response through the policy and returns the
// published cost string and status.
func runResponse(t *testing.T, p *llmcost.LLMCostPolicy, handle string, body, requestBody []byte, path string) (string, string) {
	t.Helper()

	sc := &policy.SharedContext{Metadata: map[string]interface{}{
		llmusage.MetadataTemplateHandle: handle,
	}}
	respCtx := &policy.ResponseStreamContext{SharedContext: sc, RequestPath: path}
	if requestBody != nil {
		respCtx.RequestBody = &policy.Body{Content: requestBody, Present: true}
	}

	p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: body, EndOfStream: true, Index: 0}, nil)

	cost, _ := sc.Metadata[llmcost.MetadataLLMCost].(string)
	status, _ := sc.Metadata[llmcost.MetadataLLMCostStatus].(string)
	return cost, status
}

func TestOpenAIBufferedResponseIsPriced(t *testing.T) {
	loadShippedTemplate(t, "openai", "openai-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"gpt-4o-mini-2024-07-18","usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200}}`)

	cost, status := runResponse(t, p, "openai", body, nil, "/chat/completions")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if cost == "" || cost == "0.0000000000" {
		t.Fatalf("cost = %q, want a non-zero calculated cost", cost)
	}
	t.Logf("openai buffered cost = %s", cost)
}

// gpt-4o-mini-2024-07-18 at 10 prompt / 5 completion tokens:
// 10*1.5e-7 + 5*6e-7 = "0.0000045000". The figure pins the whole chain —
// extraction, the pricing-usage bridge, the rate arithmetic and the format.
func TestOpenAIExactCost(t *testing.T) {
	loadShippedTemplate(t, "openai", "openai-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"gpt-4o-mini-2024-07-18","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)

	cost, status := runResponse(t, p, "openai", body, nil, "/chat/completions")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000045000"; cost != want {
		t.Fatalf("cost = %q, want %q (llm-cost reference)", cost, want)
	}
}

func TestOpenAICachedTokensDiscounted(t *testing.T) {
	loadShippedTemplate(t, "openai", "openai-template.yaml")
	p := newTestPolicy(t)

	plain := []byte(`{"model":"gpt-4o-mini-2024-07-18","usage":{"prompt_tokens":1000,"completion_tokens":100}}`)
	cached := []byte(`{"model":"gpt-4o-mini-2024-07-18","usage":{"prompt_tokens":1000,"completion_tokens":100,"prompt_tokens_details":{"cached_tokens":800}}}`)

	plainCost, _ := runResponse(t, p, "openai", plain, nil, "/chat/completions")
	cachedCost, _ := runResponse(t, p, "openai", cached, nil, "/chat/completions")

	if plainCost == cachedCost {
		t.Errorf("cached and uncached cost are identical (%s); the cache discount was not applied", plainCost)
	}
	t.Logf("uncached=%s cached=%s", plainCost, cachedCost)
}

func TestUnknownModelIsUnpriced(t *testing.T) {
	loadShippedTemplate(t, "openai", "openai-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"not-a-real-model-xyz","usage":{"prompt_tokens":10,"completion_tokens":5}}`)

	cost, status := runResponse(t, p, "openai", body, nil, "/chat/completions")

	if status != llmcost.CostStatusNotCalculated {
		t.Errorf("status = %q, want %q", status, llmcost.CostStatusNotCalculated)
	}
	if cost != "0.0000000000" {
		t.Errorf("cost = %q, want 0.0000000000", cost)
	}
}

func TestNoTemplateIsUnpricedNotFatal(t *testing.T) {
	p := newTestPolicy(t)

	sc := &policy.SharedContext{Metadata: map[string]interface{}{}}
	respCtx := &policy.ResponseStreamContext{SharedContext: sc, RequestPath: "/chat/completions"}
	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{
			Chunk:       []byte(`{"model":"gpt-4o-mini-2024-07-18","usage":{"prompt_tokens":10}}`),
			EndOfStream: true, Index: 0,
		}, nil)

	if action == nil {
		t.Fatal("action is nil; the response must still be forwarded")
	}
	if got, _ := sc.Metadata[llmcost.MetadataLLMCostStatus].(string); got != llmcost.CostStatusNotCalculated {
		t.Errorf("status = %q, want %q", got, llmcost.CostStatusNotCalculated)
	}
}

// claude-3-5-haiku-20241022 at 10 input / 5 output tokens, no caching:
// 10*8e-7 + 5*4e-6 = "0.0000280000".
func TestAnthropicExactCost(t *testing.T) {
	loadShippedTemplate(t, "anthropic", "anthropic-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"claude-3-5-haiku-20241022","usage":{"input_tokens":10,"output_tokens":5}}`)

	cost, status := runResponse(t, p, "anthropic", body, nil, "/v1/messages")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000280000"; cost != want {
		t.Fatalf("cost = %q, want %q (llm-cost reference)", cost, want)
	}
}

// Anthropic's streaming envelope nests usage under "message" in message_start,
// while message_delta carries a top-level usage with only the output count. The
// core token fields therefore need the nested location declared as a fallback,
// the way providerFields already does; without it a streamed request bills no
// input tokens at all.
func TestAnthropicStreamingReadsUsageFromTheMessageEnvelope(t *testing.T) {
	loadShippedTemplate(t, "anthropic-stream", "anthropic-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`event: message_start
data: {"type":"message_start","message":{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":10,"output_tokens":1}}}

event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":3}}

`)

	cost, status := runResponse(t, p, "anthropic-stream", body, nil, "/v1/messages")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	// Same 10 input / 3 output tokens as the buffered Anthropic parity test.
	if want := "0.0000750000"; cost != want {
		t.Fatalf("cost = %q, want %q — input tokens were not read from message.usage", cost, want)
	}
}

// gemini/gemini-1.5-flash at 10 prompt / 5 candidate tokens:
// 10*7.5e-8 + 5*3e-7 = "0.0000022500".
func TestGeminiExactCost(t *testing.T) {
	loadShippedTemplate(t, "gemini", "gemini-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"modelVersion":"gemini/gemini-1.5-flash","usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}`)

	cost, status := runResponse(t, p, "gemini", body, nil, "/v1beta/models/gemini-1.5-flash:generateContent")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000022500"; cost != want {
		t.Fatalf("cost = %q, want %q (llm-cost reference)", cost, want)
	}
}

// The Gemini tier is declared in the shipped template's valueMap, so a priority
// response must price above an otherwise identical standard-tier one.
func TestGeminiPriorityTierComesFromTemplate(t *testing.T) {
	loadShippedTemplate(t, "gemini", "gemini-template.yaml")
	p := newTestPolicy(t)

	standard := []byte(`{"modelVersion":"gemini-3-flash-preview","usageMetadata":{"promptTokenCount":100000,"candidatesTokenCount":1000,"trafficType":"ON_DEMAND"}}`)
	priority := []byte(`{"modelVersion":"gemini-3-flash-preview","usageMetadata":{"promptTokenCount":100000,"candidatesTokenCount":1000,"trafficType":"ON_DEMAND_PRIORITY"}}`)

	path := "/v1/models/gemini-3-flash-preview:generateContent"

	standardCost, standardStatus := runResponse(t, p, "gemini", standard, nil, path)
	priorityCost, priorityStatus := runResponse(t, p, "gemini", priority, nil, path)

	if standardStatus != llmcost.CostStatusCalculated || priorityStatus != llmcost.CostStatusCalculated {
		t.Fatalf("statuses = %q / %q, want both %q", standardStatus, priorityStatus, llmcost.CostStatusCalculated)
	}
	t.Logf("gemini standard = %s  priority = %s", standardCost, priorityCost)

	if standardCost == priorityCost {
		t.Errorf("priority cost %s equals standard cost %s; the tier is not reaching pricing",
			priorityCost, standardCost)
	}
}

// Gemini is reachable through two Google APIs that report the tier under
// different names: the Developer API uses usageMetadata.serviceTier with
// "priority"/"flex"/"standard", Vertex AI uses usageMetadata.trafficType with
// the ON_DEMAND_* enum. The shipped template must price both identically.
func TestGeminiTierFromBothGoogleAPIs(t *testing.T) {
	loadShippedTemplate(t, "gemini", "gemini-template.yaml")
	p := newTestPolicy(t)

	const model = "gemini-3-flash-preview"
	path := "/v1beta/models/" + model + ":generateContent"

	body := func(tierField, tierValue string) []byte {
		return []byte(`{"modelVersion":"` + model + `","usageMetadata":{` +
			`"promptTokenCount":10000,"candidatesTokenCount":500,"` +
			tierField + `":"` + tierValue + `"}}`)
	}

	cases := []struct {
		name       string
		field, val string
		wantSame   string // "standard" or "priority"
	}{
		{"developer api standard", "serviceTier", "standard", "standard"},
		{"developer api priority", "serviceTier", "priority", "priority"},
		{"vertex standard", "trafficType", "ON_DEMAND", "standard"},
		{"vertex priority", "trafficType", "ON_DEMAND_PRIORITY", "priority"},
	}

	got := map[string]string{}
	for _, c := range cases {
		cost, status := runResponse(t, p, "gemini", body(c.field, c.val), nil, path)
		if status != llmcost.CostStatusCalculated {
			t.Fatalf("%s: status = %q, want %q", c.name, status, llmcost.CostStatusCalculated)
		}
		t.Logf("%-24s %s -> %s", c.name, c.val, cost)
		if prev, seen := got[c.wantSame]; seen && prev != cost {
			t.Errorf("%s: cost %s disagrees with the other %s-tier response %s",
				c.name, cost, c.wantSame, prev)
		}
		got[c.wantSame] = cost
	}

	if got["standard"] == got["priority"] {
		t.Errorf("priority %s equals standard %s; the tier is not reaching pricing",
			got["priority"], got["standard"])
	}
}

// Gemini declares requestModel as a path param, which is the only source of a
// model name when the response omits modelVersion. The pattern therefore has to
// compile under Go's regexp engine and expose a capture group; a lookbehind or a
// missing group fails silently, leaving the request unpriced.
func TestGeminiModelResolvesFromURLWhenResponseOmitsIt(t *testing.T) {
	loadShippedTemplate(t, "gemini-url", "gemini-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}`)

	cost, status := runResponse(t, p, "gemini-url", body, nil,
		"/v1beta/models/gemini-1.5-flash:generateContent")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q — the model was not recovered from the URL", status,
			llmcost.CostStatusCalculated)
	}
	// Same rates as the buffered Gemini test: 10 prompt + 5 candidate tokens.
	if want := "0.0000022500"; cost != want {
		t.Fatalf("cost = %q, want %q", cost, want)
	}
}

// mistral-small-latest at 10 prompt / 5 completion tokens:
// 10*1e-7 + 5*3e-7 = "0.0000025000". The model is priced under the key
// "mistral/mistral-small-latest", so this also covers the provider-prefix
// lookup path.
func TestMistralExactCost(t *testing.T) {
	loadShippedTemplate(t, "mistral", "mistral-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"mistral-small-latest","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)

	cost, status := runResponse(t, p, "mistral", body, nil, "/v1/chat/completions")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000025000"; cost != want {
		t.Fatalf("cost = %q, want %q (llm-cost reference)", cost, want)
	}
}

// 10 input / 3 output / 4 cache-read / 2 cache-write tokens on
// anthropic.claude-3-7-sonnet-20250219-v1:0 come to "0.0000837000", with the
// model ID taken from the request URL
// (/model/anthropic.claude-3-7-sonnet-20250219-v1:0/converse). The shipped
// template resolves requestModel/responseModel via location: pathParam, which
// the extraction library's readString resolves against the request path
// (see sdk/ai/llmusage/decode.go and pathparam.go), so no payload or request
// body model field is needed.
func TestBedrockNativeCacheCost(t *testing.T) {
	loadShippedTemplate(t, "awsbedrock", "awsbedrock-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"usage":{"inputTokens":10,"outputTokens":3,"totalTokens":13,"cacheReadInputTokens":4,"cacheWriteInputTokens":2}}`)

	cost, status := runResponse(t, p, "awsbedrock", body, nil, "/model/anthropic.claude-3-7-sonnet-20250219-v1:0/converse")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000837000"; cost != want {
		t.Fatalf("cost = %q, want %q (llm-cost reference)", cost, want)
	}
}

// TestBedrockModelResolutionAcrossResponseShapes drives the same model
// (16 prompt / 4 completion tokens → 16*3e-6 + 4*1.5e-5 = "0.0001080000") through
// four different request-path/response-body shapes: native Converse, the
// snake_case usage object InvokeModel returns for Anthropic models, Titan's
// top-level token-count fields, and a percent-encoded ARN in place of a bare
// model ID. All four must price identically, since they name the same model.
func TestBedrockModelResolutionAcrossResponseShapes(t *testing.T) {
	const wantCost = "0.0001080000"

	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "converse plain model id",
			path: "/model/anthropic.claude-3-7-sonnet-20250219-v1:0/converse",
			body: `{"usage":{"inputTokens":16,"outputTokens":4,"totalTokens":20}}`,
		},
		{
			name: "anthropic invokemodel shape",
			path: "/model/anthropic.claude-3-7-sonnet-20250219-v1:0/invoke",
			body: `{"usage":{"input_tokens":16,"output_tokens":4}}`,
		},
		{
			name: "titan shape",
			path: "/model/anthropic.claude-3-7-sonnet-20250219-v1:0/invoke",
			body: `{"inputTextTokenCount":16,"results":[{"tokenCount":4}]}`,
		},
		{
			name: "percent-encoded ARN",
			path: "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Afoundation-model%2Fanthropic.claude-3-7-sonnet-20250219-v1%3A0/converse",
			body: `{"usage":{"inputTokens":16,"outputTokens":4}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadShippedTemplate(t, "awsbedrock", "awsbedrock-template.yaml")
			p := newTestPolicy(t)

			cost, status := runResponse(t, p, "awsbedrock", []byte(tt.body), nil, tt.path)

			if status != llmcost.CostStatusCalculated {
				t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
			}
			if cost != wantCost {
				t.Fatalf("cost = %q, want %q", cost, wantCost)
			}
		})
	}
}

// runResponseInContext drives a response for an API published under a context,
// so the resource path the policy derives is exercised rather than assumed.
func runResponseInContext(t *testing.T, p *llmcost.LLMCostPolicy, handle string,
	body []byte, requestPath, apiContext, apiVersion string) (string, string) {
	t.Helper()

	sc := &policy.SharedContext{
		APIContext: apiContext,
		APIVersion: apiVersion,
		Metadata:   map[string]interface{}{llmusage.MetadataTemplateHandle: handle},
	}
	respCtx := &policy.ResponseStreamContext{SharedContext: sc, RequestPath: requestPath}

	p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: body, EndOfStream: true, Index: 0}, nil)

	cost, _ := sc.Metadata[llmcost.MetadataLLMCost].(string)
	status, _ := sc.Metadata[llmcost.MetadataLLMCostStatus].(string)
	return cost, status
}

// A provider set to allow every path publishes one catch-all operation, so the
// called URL is the only thing that still identifies the resource.
func TestResponsesPricedUnderAPIContext(t *testing.T) {
	body := []byte(`{"model":"gpt-4.1-2025-04-14","usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500}}`)
	const wantCost = "0.0060000000"

	tests := []struct {
		name        string
		requestPath string
		apiContext  string
		apiVersion  string
	}{
		{"no context", "/responses", "", ""},
		{"context", "/openai-01/responses", "/openai-01", ""},
		{"versioned context", "/openai-01/v1/responses", "/openai-01/$version", "v1"},
		{"query string", "/openai-01/responses?stream=false", "/openai-01", ""},
		{"context only", "/responses", "/", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadShippedTemplate(t, "openai", "openai-template.yaml")
			p := newTestPolicy(t)

			cost, status := runResponseInContext(t, p, "openai", body, tt.requestPath, tt.apiContext, tt.apiVersion)

			if status != llmcost.CostStatusCalculated {
				t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
			}
			if cost != wantCost {
				t.Fatalf("cost = %q, want %q", cost, wantCost)
			}
		})
	}
}

// Trimming the context must leave the part a pathParam identifier reads the
// model from intact.
func TestPathParamModelSurvivesContextTrim(t *testing.T) {
	loadShippedTemplate(t, "gemini", "gemini-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}`)
	path := "/gemini-01/v1beta/models/gemini-1.5-flash:generateContent"

	cost, status := runResponseInContext(t, p, "gemini", body, path, "/gemini-01", "")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if cost == "" || cost == "0.0000000000" {
		t.Fatalf("cost = %q, want a priced value", cost)
	}
}
