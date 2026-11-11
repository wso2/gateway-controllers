/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package openaitomistral

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// TestGetPolicy_ValidatesParams guards the shape of the params, not their
// presence: `model` is optional, and an unset model means each request names
// its own. Non-string values are still rejected.
func TestGetPolicy_ValidatesParams(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err != nil {
		t.Fatalf("model override should be optional: %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"model": "mistral-large-latest", "providerId": "mistral-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
	for _, params := range []map[string]interface{}{
		{"model": 42},
		{"model": "mistral-large-latest", "providerId": true},
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("expected invalid params to fail: %#v", params)
		}
	}
}

// TestOnRequestBody_SetsModelAndStripsUnsupportedFields: the request's own
// model reaches the upstream body even when the policy configures another one,
// and the fields Mistral rejects are still stripped.
func TestOnRequestBody_SetsModelAndStripsUnsupportedFields(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	reqBody := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hi"}],
		"n": 2,
		"logprobs": true,
		"user": "abc",
		"temperature": 0.5
	}`
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Present: true, Content: []byte(reqBody)},
	}

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Path == nil || *mods.Path != MistralChatCompletionsPath {
		t.Fatalf("expected path %q, got %v", MistralChatCompletionsPath, mods.Path)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	if body["model"] != "gpt-4o" {
		t.Errorf("expected the request's own model to reach the upstream, got %v", body["model"])
	}
	// Unsupported fields Mistral rejects must be stripped.
	for _, field := range []string{"n", "logprobs", "user"} {
		if _, present := body[field]; present {
			t.Errorf("expected unsupported field %q to be stripped", field)
		}
	}
	// Supported fields must be preserved.
	if _, present := body["temperature"]; !present {
		t.Error("expected supported field 'temperature' to be preserved")
	}
	if _, present := body["messages"]; !present {
		t.Error("expected 'messages' to be preserved")
	}
}

func newSharedCtx(metadata map[string]interface{}) *policy.SharedContext {
	return &policy.SharedContext{Metadata: metadata}
}

// TestShouldRun_RoutingGates covers single-provider mode (no selection -> run)
// and multi-provider mode (run only on a matching selected_provider).
func TestShouldRun_RoutingGates(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest", ProviderID: "mistral-provider"}}

	cases := []struct {
		name     string
		metadata map[string]interface{}
		wantRun  bool
	}{
		{"single-provider mode (no selection)", map[string]interface{}{}, true},
		{"matching provider", map[string]interface{}{"selected_provider": "mistral-provider"}, true},
		{"matching provider, different case", map[string]interface{}{"selected_provider": "MISTRAL-PROVIDER"}, true},
		{"non-matching provider", map[string]interface{}{"selected_provider": "gemini-provider"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := &policy.RequestContext{SharedContext: newSharedCtx(tc.metadata)}
			if got := p.shouldRun(reqCtx); got != tc.wantRun {
				t.Errorf("shouldRun = %v, want %v", got, tc.wantRun)
			}
			respCtx := &policy.ResponseContext{SharedContext: newSharedCtx(tc.metadata)}
			if got := p.shouldRunResponse(respCtx); got != tc.wantRun {
				t.Errorf("shouldRunResponse = %v, want %v", got, tc.wantRun)
			}
		})
	}
}

// TestOnResponseBody_SSEPassthrough verifies a streaming SSE body is returned
// unmodified (translating SSE requires a stateful chunk-level policy), while a
// JSON body is translated.
func TestOnResponseBody_SSEPassthrough(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}

	sse := []byte("data: {\"id\":\"cmpl-1\"}\n\ndata: [DONE]\n\n")
	action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  newSharedCtx(map[string]interface{}{}),
		ResponseStatus: 200,
		ResponseBody:   &policy.Body{Present: true, Content: sse},
	}, nil)

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if mods.Body != nil {
		t.Errorf("SSE body must pass through unmodified, got Body=%s", string(mods.Body))
	}

	// A JSON body, by contrast, is translated (non-nil Body).
	jsonBody := []byte(`{"id":"cmpl-1","object":"chat.completion","model":"mistral-large-latest",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`)
	action = p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  newSharedCtx(map[string]interface{}{}),
		ResponseStatus: 200,
		ResponseBody:   &policy.Body{Present: true, Content: jsonBody},
	}, nil)
	mods, ok = action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if mods.Body == nil {
		t.Error("expected a JSON response body to be translated, got nil Body")
	}
}

func TestTranslateResponse_JSONShape(t *testing.T) {
	// Mistral already emits OpenAI-shaped success bodies; the translator ensures
	// the response model is populated and passes the body through in OpenAI shape.
	mistral := `{"id":"cmpl-1","object":"chat.completion","model":"mistral-large-latest",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`
	action := translateResponse([]byte(mistral), 200, "mistral-large-latest")

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(mods.Body, &out); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	choices, _ := out["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %v", out["choices"])
	}
}

// TestConfiguredModelIsFallback pins the compatibility guarantee that survives
// the payload-first rule: a proxy that sets `model` behaves exactly as it did
// for every request whose payload names no model. A request that does name one
// is covered by TestResolveModel — it is served the client's model, which is the
// one intended behaviour change.
//
// Mistral has no streaming translator, so a buffered response is the only
// reporting path there is.
func TestConfiguredModelIsFallback(t *testing.T) {
	const configured = "mistral-large-latest"
	p := &TranslatorPolicy{params: PolicyParams{Model: configured}}
	shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

	// With no model in the payload, the configured one drives everything.
	req := &policy.RequestContext{SharedContext: shared, Body: &policy.Body{Present: true, Content: []byte(
		`{"messages":[{"role":"user","content":"hello"}]}`)}}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, isUpstream := action.(policy.UpstreamRequestModifications)
	if !isUpstream {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	var upstream map[string]interface{}
	if err := json.Unmarshal(mods.Body, &upstream); err != nil {
		t.Fatalf("upstream body is not JSON: %v", err)
	}
	if upstream["model"] != configured {
		t.Errorf("upstream model = %v, want the configured fallback %q", upstream["model"], configured)
	}

	// The buffered response reports it.
	respCtx := &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		ResponseBody: &policy.Body{Present: true, Content: []byte(
			`{"id":"cmpl-1","object":"chat.completion","model":"` + configured + `",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},` +
				`"finish_reason":"stop"}]}`)},
	}
	respAction := p.OnResponseBody(context.Background(), respCtx, nil)
	respMods, isDownstream := respAction.(policy.DownstreamResponseModifications)
	if !isDownstream {
		t.Fatalf("expected DownstreamResponseModifications, got %T", respAction)
	}
	var buffered map[string]interface{}
	if err := json.Unmarshal(respMods.Body, &buffered); err != nil {
		t.Fatalf("translated response is not JSON: %v", err)
	}
	if buffered["model"] != configured {
		t.Errorf("buffered response model = %v, want %q", buffered["model"], configured)
	}
}

// TestResolveModel covers every row of the resolution table: the request's own
// model wins when it names one, the configured model is the fallback used only
// when it does not, and a request that names no usable model is rejected naming
// both sources.
func TestResolveModel(t *testing.T) {
	const configured = "mistral-large-latest"
	const requested = "mistral-small-latest"

	cases := []struct {
		name       string
		configured string
		payload    string
		wantModel  string // empty means the request must be rejected
		wantErr    string
	}{
		{"request overrides the configured model", configured, `{"model":"` + requested + `","messages":[{"role":"user","content":"hi"}]}`, requested, ""},
		{"configured model is the fallback when the request names none", configured, `{"messages":[{"role":"user","content":"hi"}]}`, configured, ""},
		{"empty request model falls back to the configured model", configured, `{"model":"","messages":[{"role":"user","content":"hi"}]}`, configured, ""},
		{"null request model falls back to the configured model", configured, `{"model":null,"messages":[{"role":"user","content":"hi"}]}`, configured, ""},
		{"request model used when none is configured", "", `{"model":"` + requested + `","messages":[{"role":"user","content":"hi"}]}`, requested, ""},
		{"padded request model is trimmed, not rejected", "", `{"model":"  ` + requested + `  ","messages":[{"role":"user","content":"hi"}]}`, requested, ""},
		{"neither source supplies one", "", `{"messages":[{"role":"user","content":"hi"}]}`, "", "either the policy configuration or request body"},
		{"empty request model with nothing configured", "", `{"model":"","messages":[{"role":"user","content":"hi"}]}`, "", "either the policy configuration or request body"},
		{"whitespace-only request model is malformed", "", `{"model":"   ","messages":[{"role":"user","content":"hi"}]}`, "", "must not be blank"},
		{"whitespace-only is malformed even with a configured model", configured, `{"model":"   ","messages":[{"role":"user","content":"hi"}]}`, "", "must not be blank"},
		{"non-string request model is a bad request", "", `{"model":123,"messages":[{"role":"user","content":"hi"}]}`, "", "must be a string"},
		{"non-string is a bad request even with a configured model", configured, `{"model":123,"messages":[{"role":"user","content":"hi"}]}`, "", "must be a string"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{Model: tc.configured}}
			req := &policy.RequestContext{
				SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
				Body:          &policy.Body{Present: true, Content: []byte(tc.payload)},
			}

			action := p.OnRequestBody(context.Background(), req, nil)

			if tc.wantModel == "" {
				rejected, isImmediate := action.(policy.ImmediateResponse)
				if !isImmediate {
					t.Fatalf("expected the request to be rejected, got %T", action)
				}
				if rejected.StatusCode != 400 {
					t.Errorf("status = %d, want 400", rejected.StatusCode)
				}
				if !strings.Contains(string(rejected.Body), tc.wantErr) {
					t.Errorf("error body = %s, want it to mention %q", rejected.Body, tc.wantErr)
				}
				return
			}

			mods, isUpstream := action.(policy.UpstreamRequestModifications)
			if !isUpstream {
				t.Fatalf("expected UpstreamRequestModifications, got %T", action)
			}
			if got := upstreamModelFromBody(t, mods.Body); got != tc.wantModel {
				t.Errorf("model sent upstream = %q, want %q", got, tc.wantModel)
			}
		})
	}
}

func upstreamModelFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var upstream map[string]interface{}
	if err := json.Unmarshal(body, &upstream); err != nil {
		t.Fatalf("upstream body is not JSON: %v", err)
	}
	model, _ := upstream["model"].(string)
	return model
}

// Mistral backfills the model only when the upstream omits it — it never
// overwrites a model the upstream reported. The backfill is the path that used
// to carry the configured model and now carries the effective one.
const mistralBufferedBody = `{"id":"cmpl-1","object":"chat.completion",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`

const mistralBufferedBodyWithModel = `{"id":"cmpl-1","object":"chat.completion","model":"upstream-echo",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`

// TestEffectiveModel_ReportsModelThatServedRequest covers both resolution paths.
// Mistral has no streaming translator, so the buffered response is the only
// reporting path.
func TestEffectiveModel_ReportsModelThatServedRequest(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		requested  string
		want       string
	}{
		{"request-supplied model is reported", "", "mistral-small-latest", "mistral-small-latest"},
		{"request-supplied model wins over the configured one", "mistral-large-latest", "mistral-small-latest", "mistral-small-latest"},
		{"configured fallback is reported when the request names none", "mistral-large-latest", "", "mistral-large-latest"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{Model: tc.configured}}
			shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

			payload := `{"messages":[{"role":"user","content":"hi"}]}`
			if tc.requested != "" {
				payload = `{"model":"` + tc.requested + `","messages":[{"role":"user","content":"hi"}]}`
			}
			req := &policy.RequestContext{SharedContext: shared, Body: &policy.Body{Present: true, Content: []byte(payload)}}
			if action := p.OnRequestBody(context.Background(), req, nil); action == nil {
				t.Fatal("request phase returned no action")
			}
			if got := shared.Metadata[MetadataKeyEffectiveModel]; got != tc.want {
				t.Fatalf("effective model recorded = %v, want %q", got, tc.want)
			}
			if got := bufferedModel(t, p, shared, mistralBufferedBody); got != tc.want {
				t.Errorf("buffered response model = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEffectiveModel_FallsBackToConfigured is the guard that no response path
// can report nothing: with no effective model recorded — a response reaching
// this policy without its request phase having run — the configured model is
// reported.
func TestEffectiveModel_FallsBackToConfigured(t *testing.T) {
	const configured = "mistral-large-latest"
	p := &TranslatorPolicy{params: PolicyParams{Model: configured}}
	shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

	if got := bufferedModel(t, p, shared, mistralBufferedBody); got != configured {
		t.Errorf("buffered response model = %q, want the configured fallback %q", got, configured)
	}
	if got := effectiveModel(nil, configured); got != configured {
		t.Errorf("nil shared context: model = %q, want %q", got, configured)
	}

	// A model the upstream reported is still left alone — backfill only.
	if got := bufferedModel(t, p, shared, mistralBufferedBodyWithModel); got != "upstream-echo" {
		t.Errorf("upstream-reported model = %q, want it left untouched", got)
	}
}

func bufferedModel(t *testing.T, p *TranslatorPolicy, shared *policy.SharedContext, body string) string {
	t.Helper()
	action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		ResponseBody:   &policy.Body{Present: true, Content: []byte(body)},
	}, nil)
	mods, isDownstream := action.(policy.DownstreamResponseModifications)
	if !isDownstream {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	var translated map[string]interface{}
	if err := json.Unmarshal(mods.Body, &translated); err != nil {
		t.Fatalf("translated response is not JSON: %v", err)
	}
	model, _ := translated["model"].(string)
	return model
}

// TestErrResponseDirectionAndCode covers what this translator refuses and how it labels it.
//
// Direction is the point: a payload the caller sent that will not convert is a
// request-side refusal, while a provider reply that will not translate back is a
// response-side one. They share a helper and nothing else, and only the caller knows which
// it made — so it is passed in rather than inferred from the status.
func TestErrResponseDirectionAndCode(t *testing.T) {
	t.Run("request side", func(t *testing.T) {
		resp := errResponse(400, "Request body is empty.",
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a refused request")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeInvalidRequestBody {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeInvalidRequestBody, resp.Fault.Code)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
		if resp.Fault.Type != policy.FaultTypeValidation {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeValidation, resp.Fault.Type)
		}
	})

	t.Run("response side", func(t *testing.T) {
		resp := errResponse(500, "failed to translate response",
			policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a failed translation")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeMediationFailed {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
		}
		if resp.Fault.Direction != policy.DirectionResponse {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionResponse, resp.Fault.Direction)
		}
	})
}

// TestOnRequestBody_RejectionsDeclareFault drives each request rejection through
// OnRequestBody and checks the fault it declares, and that the client body is unchanged.
func TestOnRequestBody_RejectionsDeclareFault(t *testing.T) {
	cases := []struct {
		name     string
		body     *policy.Body
		wantBody string
	}{
		{"missing body", nil, `{"error":"Request body is empty."}`},
		{"empty body", &policy.Body{Present: true}, `{"error":"Request body is empty."}`},
		{"invalid JSON", &policy.Body{Present: true, Content: []byte(`{"messages":`)}, `{"error":"Invalid JSON in request body: unexpected end of JSON input"}`},
		{"unresolvable model", &policy.Body{Present: true, Content: []byte(`{"model":42,"messages":[]}`)}, `{"error":"request field 'model' must be a string"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{}}
			action := p.OnRequestBody(context.Background(), &policy.RequestContext{
				SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
				Body:          c.body,
			}, nil)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok || resp.StatusCode != 400 {
				t.Fatalf("expected a 400 ImmediateResponse, got %#v", action)
			}
			if resp.Headers["Content-Type"] != "application/json" || string(resp.Body) != c.wantBody {
				t.Fatalf("client response changed: headers %v, body %s", resp.Headers, resp.Body)
			}
			if !resp.IsFault || resp.Fault == nil {
				t.Fatalf("expected IsFault=true and Fault set")
			}
			if resp.Fault.Code != policy.FaultCodeInvalidRequestBody ||
				resp.Fault.Type != policy.FaultTypeValidation ||
				resp.Fault.Direction != policy.DirectionRequest {
				t.Fatalf("unexpected fault code/type/direction: %q/%q/%q",
					resp.Fault.Code, resp.Fault.Type, resp.Fault.Direction)
			}
		})
	}
}
