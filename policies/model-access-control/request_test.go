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

package modelaccesscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func onBody(t *testing.T, p *Policy, ctx *policy.RequestContext) policy.RequestAction {
	t.Helper()
	return p.OnRequestBody(context.Background(), ctx, nil)
}

func bodyMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("action = %T (%+v), want UpstreamRequestModifications", action, action)
	}
	return mods
}

func immediate(t *testing.T, action any) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("action = %T (%+v), want ImmediateResponse", action, action)
	}
	return resp
}

// ─── Payload location ────────────────────────────────────────────────────────

func TestOnRequestBody_PermittedModelIsForwardedUnchanged(t *testing.T) {
	p := governed(t, payloadModel())
	ctx := jsonBody(`{"model":" GPT-4o ","messages":[]}`)
	mods := bodyMods(t, onBody(t, p, ctx))
	if mods.Body != nil || mods.UpstreamName != nil || mods.Path != nil || mods.HeadersToSet != nil {
		t.Fatalf("mods = %+v, want no request change", mods)
	}
	if _, set := ctx.Metadata[MetadataSelectedProvider]; set {
		t.Error("selected_provider set for a permitted model")
	}
	if ctx.Metadata[MetadataDecision] != decisionPermitted || ctx.Metadata[MetadataRequestedModel] != "GPT-4o" {
		t.Errorf("metadata = %v", ctx.Metadata)
	}
	if mods.AnalyticsMetadata[analyticsDecision] != decisionPermitted {
		t.Errorf("analytics = %v", mods.AnalyticsMetadata)
	}
}

func TestOnRequestBody_PermittedModelNeverUsesAMapping(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       allowOnly("gpt-4o"),
		"fallback":     map[string]any{"mappingPatterns": []any{literalRule("gpt-4o", "other", "anthropic")}},
	})
	mods := bodyMods(t, onBody(t, p, jsonBody(`{"model":"gpt-4o"}`)))
	if mods.Body != nil || mods.UpstreamName != nil {
		t.Fatalf("mods = %+v; a permitted model must not be mapped", mods)
	}
}

func TestOnRequestBody_FallbackOnPrimaryProvider(t *testing.T) {
	p := governed(t, payloadModel())
	ctx := jsonBody(`{"model":"old-model","messages":[{"role":"user","content":"hi"}]}`)
	mods := bodyMods(t, onBody(t, p, ctx))
	if got := bodyModel(t, mods.Body); got != "gpt-4o" {
		t.Errorf("rewritten model = %q, want gpt-4o", got)
	}
	if !strings.Contains(string(mods.Body), `"content":"hi"`) {
		t.Errorf("rewritten body lost the messages: %s", mods.Body)
	}
	if mods.UpstreamName != nil {
		t.Errorf("UpstreamName = %q, want nil for a primary-provider mapping", *mods.UpstreamName)
	}
	if _, set := ctx.Metadata[MetadataSelectedProvider]; set {
		t.Error("selected_provider set for a primary-provider mapping")
	}
	if ctx.Metadata[MetadataDecision] != decisionMapped || ctx.Metadata[MetadataEffectiveModel] != "gpt-4o" || ctx.Metadata[MetadataMappingMatched] != true {
		t.Errorf("metadata = %v", ctx.Metadata)
	}
}

func TestOnRequestBody_FallbackSelectsProvider(t *testing.T) {
	p := governed(t, payloadModel())
	ctx := jsonBody(`{"model":"Claude-Friendly"}`)
	mods := bodyMods(t, onBody(t, p, ctx))
	if got := bodyModel(t, mods.Body); got != "claude-sonnet" {
		t.Errorf("rewritten model = %q", got)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "anthropic" {
		t.Fatalf("UpstreamName = %v, want anthropic", mods.UpstreamName)
	}
	if ctx.Metadata[MetadataSelectedProvider] != "anthropic" {
		t.Errorf("selected_provider = %v, want anthropic", ctx.Metadata[MetadataSelectedProvider])
	}
}

func TestOnRequestBody_FallbackTargetIsNotReevaluated(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       allowOnly("gpt-4o"),
		"fallback":     map[string]any{"mappingPatterns": []any{literalRule("alias", "not-in-the-allow-list", "")}},
	})
	mods := bodyMods(t, onBody(t, p, jsonBody(`{"model":"alias"}`)))
	if got := bodyModel(t, mods.Body); got != "not-in-the-allow-list" {
		t.Errorf("rewritten model = %q", got)
	}
}

func TestOnRequestBody_DenyModeRestrictsListedModels(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       denyOnly("gpt-4-32k", "gpt-4-turbo"),
		"fallback":     map[string]any{"mappingPatterns": []any{literalRule("gpt-4-turbo", "gpt-4o", "")}},
	})
	bodyMods(t, onBody(t, p, jsonBody(`{"model":"anything-else"}`)))
	mods := bodyMods(t, onBody(t, p, jsonBody(`{"model":"gpt-4-turbo"}`)))
	if bodyModel(t, mods.Body) != "gpt-4o" {
		t.Errorf("restricted, mapped model was not rewritten: %s", mods.Body)
	}
	resp := immediate(t, onBody(t, p, jsonBody(`{"model":"gpt-4-32k"}`)))
	assertFault(t, resp, 404, bodyModelNotFound, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)
}

func TestOnRequestBody_DeniedWithoutMapping(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "allow", "models": []any{"gpt-4o"}},
	})
	ctx := jsonBody(`{"model":"secret-internal-model"}`)
	resp := immediate(t, onBody(t, p, ctx))
	assertFault(t, resp, 404, bodyModelNotFound, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)
	for _, leak := range []string{"secret-internal-model", "gpt-4o"} {
		if strings.Contains(string(resp.Body), leak) || strings.Contains(resp.Fault.Message, leak) {
			t.Errorf("client-facing text reveals %q", leak)
		}
	}
	if !strings.Contains(resp.Fault.Description, "secret-internal-model") {
		t.Errorf("Description = %q, want the internal detail", resp.Fault.Description)
	}
	if ctx.Metadata[MetadataDecision] != decisionDenied {
		t.Errorf("decision = %v", ctx.Metadata[MetadataDecision])
	}
	if resp.AnalyticsMetadata[analyticsDecision] != decisionDenied {
		t.Errorf("analytics = %v", resp.AnalyticsMetadata)
	}
}

func TestOnRequestBody_PatternFallbackWithCaptures(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access": map[string]any{
			"mode": "allow", "models": []any{"gpt-4o"},
			"modelPatterns": []any{`anthropic\.claude-.*`},
		},
		"fallback": map[string]any{
			"mappingPatterns": []any{patternRule(`claude-(\w+)`, "anthropic.claude-$1-v1:0", "bedrock")},
		},
	})
	ctx := jsonBody(`{"model":"claude-sonnet"}`)
	mods := bodyMods(t, onBody(t, p, ctx))
	if got := bodyModel(t, mods.Body); got != "anthropic.claude-sonnet-v1:0" {
		t.Errorf("rewritten model = %q", got)
	}
	if ctx.Metadata[MetadataSelectedProvider] != "bedrock" {
		t.Errorf("selected_provider = %v", ctx.Metadata[MetadataSelectedProvider])
	}
}

func TestOnRequestBody_UnusableExpansionIsARoutingError(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       allowOnly("gpt-4o"),
		"fallback": map[string]any{
			"mappingPatterns": []any{patternRule("x-(.*)", "$1", "anthropic")},
		},
	})
	ctx := jsonBody(`{"model":"x-"}`)
	resp := immediate(t, onBody(t, p, ctx))
	assertFault(t, resp, 500, bodyRoutingError, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	if _, set := ctx.Metadata[MetadataSelectedProvider]; set {
		t.Error("selected_provider set on a routing error")
	}
}

func TestOnRequestBody_MissingOrUnreadableModel(t *testing.T) {
	p := governed(t, payloadModel())
	for name, body := range map[string]string{
		"empty body":     ``,
		"blank body":     `   `,
		"no model":       `{"messages":[]}`,
		"blank model":    `{"model":""}`,
		"model number":   `{"model":7}`,
		"malformed":      `{"model":"gpt-4o"`,
		"duplicate keys": `{"model":"gpt-4o","model":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := immediate(t, onBody(t, p, jsonBody(body)))
			assertFault(t, resp, 400, bodyInvalidModel, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
		})
	}
}

func TestOnRequestBody_SkipOnlyForModelLessRequests(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "allow", "models": []any{"gpt-4o"}, "onMissingModel": "skip"},
	})
	skipped := []*policy.RequestContext{
		bodyContext("GET", "", ""),
		bodyContext("DELETE", "application/json", ""),
		bodyContext("POST", "multipart/form-data; boundary=x", multipartBody("x", map[string]string{"purpose": "batch"})),
		bodyContext("POST", "application/x-www-form-urlencoded", "purpose=batch"),
		bodyContext("POST", "application/octet-stream", "\x00\x01binary"),
	}
	for i, ctx := range skipped {
		mods := bodyMods(t, onBody(t, p, ctx))
		if mods.Body != nil {
			t.Errorf("case %d: body changed", i)
		}
		if ctx.Metadata[MetadataDecision] != decisionSkipped {
			t.Errorf("case %d: decision = %v, want skipped", i, ctx.Metadata[MetadataDecision])
		}
	}
	rejected := []*policy.RequestContext{
		jsonBody(`{"messages":[]}`),
		jsonBody(``),
		bodyContext("POST", "application/vnd.api+json", `{"messages":[]}`),
		bodyContext("POST", "", `{"messages":[]}`),
		jsonBody(`{"model":"a","model":"b"}`),
		bodyContext("GET", "", `{"model":"a","model":"b"}`),
		// A text body that is not JSON could still be read as JSON by a lenient upstream.
		bodyContext("POST", "text/plain", "not json"),
		// A body that parses as JSON is JSON whatever its content type says.
		bodyContext("POST", "text/plain", `{"messages":[]}`),
		bodyContext("POST", "application/octet-stream", `{"messages":[]}`),
		// A form that cannot be parsed, or names the model twice.
		bodyContext("POST", "multipart/form-data; boundary=x", "--x\r\n..."),
		bodyContext("POST", "multipart/form-data", "--x\r\n"),
		bodyContext("POST", "application/x-www-form-urlencoded", "model=a&model=b"),
	}
	for i, ctx := range rejected {
		immediate(t, onBody(t, p, ctx))
		if ctx.Metadata[MetadataDecision] != decisionDenied {
			t.Errorf("case %d: decision = %v, want denied", i, ctx.Metadata[MetadataDecision])
		}
	}
	// A model that is present is always evaluated, even on a skip-eligible request.
	immediate(t, onBody(t, p, bodyContext("GET", "", `{"model":"denied"}`)))
}

func TestOnRequestBody_ProviderConflicts(t *testing.T) {
	p := governed(t, payloadModel())
	tests := []struct {
		name     string
		existing any
		body     string
		conflict bool
	}{
		{"same provider", "anthropic", `{"model":"claude-friendly"}`, false},
		{"different provider", "openai-extra", `{"model":"claude-friendly"}`, true},
		{"provider differs only by case", "Anthropic", `{"model":"claude-friendly"}`, true},
		{"primary mapping after a selection", "anthropic", `{"model":"old-model"}`, true},
		{"malformed selection", 42, `{"model":"claude-friendly"}`, true},
		{"blank selection", " ", `{"model":"claude-friendly"}`, true},
		{"permitted model ignores a selection", "anthropic", `{"model":"gpt-4o"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := jsonBody(tt.body)
			ctx.Metadata[MetadataSelectedProvider] = tt.existing
			action := onBody(t, p, ctx)
			if !tt.conflict {
				bodyMods(t, action)
				return
			}
			resp := immediate(t, action)
			assertFault(t, resp, 500, bodyRoutingError, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
			if ctx.Metadata[MetadataSelectedProvider] != tt.existing {
				t.Errorf("selected_provider changed to %v on a conflict", ctx.Metadata[MetadataSelectedProvider])
			}
			if strings.Contains(string(resp.Body), "anthropic") || strings.Contains(resp.Fault.Message, "anthropic") {
				t.Error("client-facing text reveals a provider name")
			}
		})
	}
}

func TestOnRequestBody_NilMetadataIsInitialized(t *testing.T) {
	p := governed(t, payloadModel())
	ctx := jsonBody(`{"model":"claude-friendly"}`)
	ctx.Metadata = nil
	bodyMods(t, onBody(t, p, ctx))
	if ctx.Metadata[MetadataSelectedProvider] != "anthropic" {
		t.Errorf("selected_provider = %v", ctx.Metadata[MetadataSelectedProvider])
	}
}

// ─── Header, query and path locations ────────────────────────────────────────

func TestOnRequestHeaders_AllLocations(t *testing.T) {
	tests := []struct {
		name      string
		location  map[string]any
		ctx       func(model string) *policy.RequestHeaderContext
		rewritten func(t *testing.T, mods policy.UpstreamRequestHeaderModifications) string
	}{
		{
			name:     "header",
			location: headerModel(),
			ctx: func(model string) *policy.RequestHeaderContext {
				return headerContext("POST", "/proxy/chat", map[string][]string{"x-model": {model}, "content-type": {"application/json"}})
			},
			rewritten: func(t *testing.T, mods policy.UpstreamRequestHeaderModifications) string {
				return mods.HeadersToSet["x-model"]
			},
		},
		{
			name:     "query",
			location: queryModel(),
			ctx: func(model string) *policy.RequestHeaderContext {
				return headerContext("POST", "/proxy/chat?api-version=2024&model="+model, nil)
			},
			rewritten: func(t *testing.T, mods policy.UpstreamRequestHeaderModifications) string {
				if mods.Path == nil {
					return ""
				}
				if !strings.HasPrefix(*mods.Path, "/proxy/chat?api-version=2024&model=") {
					t.Errorf("path = %q", *mods.Path)
				}
				return strings.TrimPrefix(*mods.Path, "/proxy/chat?api-version=2024&model=")
			},
		},
		{
			name:     "path",
			location: pathModel(),
			ctx: func(model string) *policy.RequestHeaderContext {
				return headerContext("POST", "/proxy/models/"+model+"/chat", nil)
			},
			rewritten: func(t *testing.T, mods policy.UpstreamRequestHeaderModifications) string {
				if mods.Path == nil {
					return ""
				}
				return strings.TrimSuffix(strings.TrimPrefix(*mods.Path, "/proxy/models/"), "/chat")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := governed(t, tt.location)
			if mode := p.Mode(); mode.RequestHeaderMode != policy.HeaderModeProcess || mode.RequestBodyMode != policy.BodyModeSkip {
				t.Errorf("Mode() = %+v", mode)
			}

			// Permitted: nothing changes.
			mods, ok := p.OnRequestHeaders(context.Background(), tt.ctx("gpt-4o"), nil).(policy.UpstreamRequestHeaderModifications)
			if !ok || mods.Path != nil || mods.HeadersToSet != nil || mods.UpstreamName != nil {
				t.Fatalf("permitted: %+v", mods)
			}

			// Primary fallback: model rewritten, no provider.
			mods, ok = p.OnRequestHeaders(context.Background(), tt.ctx("old-model"), nil).(policy.UpstreamRequestHeaderModifications)
			if !ok || tt.rewritten(t, mods) != "gpt-4o" || mods.UpstreamName != nil {
				t.Fatalf("primary fallback: %+v", mods)
			}

			// Provider fallback.
			ctx := tt.ctx("claude-friendly")
			mods, ok = p.OnRequestHeaders(context.Background(), ctx, nil).(policy.UpstreamRequestHeaderModifications)
			if !ok || tt.rewritten(t, mods) != "claude-sonnet" || mods.UpstreamName == nil || *mods.UpstreamName != "anthropic" {
				t.Fatalf("provider fallback: %+v", mods)
			}
			if ctx.Metadata[MetadataSelectedProvider] != "anthropic" {
				t.Errorf("selected_provider = %v", ctx.Metadata[MetadataSelectedProvider])
			}

			// Denied.
			resp := immediate(t, p.OnRequestHeaders(context.Background(), tt.ctx("unknown"), nil))
			assertFault(t, resp, 404, bodyModelNotFound, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)

			// The body callback is a no-op for these locations.
			if _, ok := p.OnRequestBody(context.Background(), jsonBody(`{"model":"unknown"}`), nil).(policy.UpstreamRequestModifications); !ok {
				t.Error("OnRequestBody should pass through for a non-payload location")
			}
		})
	}
}

func TestOnRequestHeaders_MissingAndAmbiguous(t *testing.T) {
	tests := []struct {
		name     string
		location map[string]any
		ctx      *policy.RequestHeaderContext
		code     string
	}{
		{"header absent", headerModel(), headerContext("POST", "/chat", map[string][]string{"content-type": {"application/json"}}), policy.FaultCodeInvalidRequestHeader},
		{"header duplicate", headerModel(), headerContext("POST", "/chat", map[string][]string{"x-model": {"gpt-4o", "other"}}), policy.FaultCodeInvalidRequestHeader},
		{"query absent", queryModel(), headerContext("POST", "/chat", nil), policy.FaultCodeInvalidRequestURI},
		{"query duplicate", queryModel(), headerContext("POST", "/chat?model=gpt-4o&model=x", nil), policy.FaultCodeInvalidRequestURI},
		{"query bad encoding", queryModel(), headerContext("POST", "/chat?model=%zz", nil), policy.FaultCodeInvalidRequestURI},
		{"path absent", pathModel(), headerContext("POST", "/chat", nil), policy.FaultCodeInvalidRequestURI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := governed(t, tt.location)
			resp := immediate(t, p.OnRequestHeaders(context.Background(), tt.ctx, nil))
			assertFault(t, resp, 400, bodyInvalidModel, tt.code, policy.FaultTypeValidation)
		})
	}
}

func TestOnRequestHeaders_SkipNeverCoversDuplicates(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": headerModel(),
		"access":       map[string]any{"mode": "allow", "models": []any{"gpt-4o"}, "onMissingModel": "skip"},
	})
	if _, ok := p.OnRequestHeaders(context.Background(), headerContext("GET", "/models", nil), nil).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Error("a GET without the header should be skipped")
	}
	immediate(t, p.OnRequestHeaders(context.Background(), headerContext("GET", "/models", map[string][]string{"x-model": {"a", "b"}}), nil))
	immediate(t, p.OnRequestHeaders(context.Background(), headerContext("POST", "/chat", map[string][]string{"content-type": {"application/json"}}), nil))
}

// ─── Contract ────────────────────────────────────────────────────────────────

func TestMode_PayloadBuffersOnlyTheRequestBody(t *testing.T) {
	mode := governed(t, payloadModel()).Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if mode != want {
		t.Errorf("Mode() = %+v, want %+v", mode, want)
	}
}

func TestPolicy_HasNoResponseProcessing(t *testing.T) {
	var p any = governed(t, payloadModel())
	if _, ok := p.(policy.ResponseHeaderPolicy); ok {
		t.Error("the policy implements ResponseHeaderPolicy")
	}
	if _, ok := p.(policy.ResponsePolicy); ok {
		t.Error("the policy implements ResponsePolicy")
	}
	if _, ok := p.(policy.StreamingResponsePolicy); ok {
		t.Error("the policy implements StreamingResponsePolicy")
	}
	for _, loc := range []map[string]any{payloadModel(), headerModel(), queryModel(), pathModel()} {
		mode := governed(t, loc).Mode()
		if mode.ResponseHeaderMode != policy.HeaderModeSkip || mode.ResponseBodyMode != policy.BodyModeSkip {
			t.Errorf("location %v: Mode() processes the response: %+v", loc["location"], mode)
		}
	}
}

func TestConcurrentRequestsDoNotShareState(t *testing.T) {
	p := governed(t, payloadModel())
	models := []struct{ requested, effective, provider string }{
		{"gpt-4o", "", ""},
		{"old-model", "gpt-4o", ""},
		{"claude-friendly", "claude-sonnet", "anthropic"},
		{"denied", "", ""},
	}
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(c struct{ requested, effective, provider string }) {
			defer wg.Done()
			ctx := jsonBody(fmt.Sprintf(`{"model":%q}`, c.requested))
			action := p.OnRequestBody(context.Background(), ctx, nil)
			switch {
			case c.requested == "denied":
				if _, ok := action.(policy.ImmediateResponse); !ok {
					errs <- fmt.Errorf("%s: %T", c.requested, action)
				}
			case c.effective == "":
				if mods := action.(policy.UpstreamRequestModifications); mods.Body != nil {
					errs <- fmt.Errorf("%s: body changed", c.requested)
				}
			default:
				mods := action.(policy.UpstreamRequestModifications)
				if !strings.Contains(string(mods.Body), c.effective) {
					errs <- fmt.Errorf("%s: body %s", c.requested, mods.Body)
				}
				if got, _ := ctx.Metadata[MetadataSelectedProvider].(string); got != c.provider {
					errs <- fmt.Errorf("%s: provider %q", c.requested, got)
				}
			}
		}(models[i%len(models)])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestDeniedLongModelIsBoundedInAnalytics(t *testing.T) {
	p := governed(t, payloadModel())
	long := strings.Repeat("é", 200)
	resp := immediate(t, onBody(t, p, jsonBody(fmt.Sprintf(`{"model":%q}`, long))))
	got, _ := resp.AnalyticsMetadata[analyticsRequestedModel].(string)
	if !strings.HasSuffix(got, "...(truncated)") || len(got) > maxLoggedModelLength+len("...(truncated)") {
		t.Errorf("analytics model = %q, want a bounded value", got)
	}
}

func multipartBody(boundary string, fields map[string]string) string {
	var b strings.Builder
	for _, name := range []string{"model", "purpose", "file"} {
		value, ok := fields[name]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", boundary, name, value)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

// Multipart and URL-encoded bodies (audio transcription, image edits) carry the model
// as a form field. It is checked like a JSON model, under deny and skip alike.
func TestOnRequestBody_FormBodiesAreChecked(t *testing.T) {
	for _, missing := range []string{"deny", "skip"} {
		t.Run(missing, func(t *testing.T) {
			p := mustPolicy(t, map[string]any{
				"requestModel": payloadModel(),
				"access":       map[string]any{"mode": "allow", "models": []any{"whisper-1"}, "onMissingModel": missing},
				"fallback":     map[string]any{"mappingPatterns": []any{literalRule("whisper-large", "whisper-1", "")}},
			})
			multipartType := "multipart/form-data; boundary=b0undary"

			denied := bodyContext("POST", multipartType, multipartBody("b0undary", map[string]string{"model": "llama-3", "file": "AUDIO"}))
			assertFault(t, immediate(t, onBody(t, p, denied)), 404, bodyModelNotFound, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)

			assertFault(t, immediate(t, onBody(t, p, bodyContext("POST", "application/x-www-form-urlencoded", "model=llama-3&x=1"))),
				404, bodyModelNotFound, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)

			permitted := bodyContext("POST", multipartType, multipartBody("b0undary", map[string]string{"model": "whisper-1", "file": "AUDIO"}))
			if mods := bodyMods(t, onBody(t, p, permitted)); mods.Body != nil {
				t.Error("permitted multipart body was changed")
			}

			mapped := bodyContext("POST", multipartType, multipartBody("b0undary", map[string]string{"model": "whisper-large", "file": "AUDIO"}))
			body := string(bodyMods(t, onBody(t, p, mapped)).Body)
			if !strings.Contains(body, "name=\"model\"\r\n\r\nwhisper-1\r\n") || !strings.Contains(body, "AUDIO") || strings.Contains(body, "whisper-large") {
				t.Errorf("rewritten multipart body = %q", body)
			}

			form := bodyContext("POST", "application/x-www-form-urlencoded", "a=1&model=whisper-large&z=%2F")
			if got := string(bodyMods(t, onBody(t, p, form)).Body); got != "a=1&model=whisper-1&z=%2F" {
				t.Errorf("rewritten form = %q", got)
			}
		})
	}
}

// A fallback target built from capture groups is partly chosen by the client, so it
// must pass the access rule; a fixed target is still not re-evaluated.
func TestOnRequestBody_CaptureFallbackTargetIsChecked(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       allowOnly("gpt-4o-mini", "gpt-4o"),
		"fallback":     map[string]any{"mappingPatterns": []any{patternRule(`(?i)legacy-(.*)`, "$1", "")}},
	})
	assertFault(t, immediate(t, onBody(t, p, jsonBody(`{"model":"legacy-gpt-4-32k"}`))),
		404, bodyModelNotFound, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)
	mods := bodyMods(t, onBody(t, p, jsonBody(`{"model":"legacy-gpt-4o"}`)))
	if got := bodyModel(t, mods.Body); got != "gpt-4o" {
		t.Errorf("rewritten model = %q, want gpt-4o", got)
	}
}

func TestOnRequestBody_CaseVariantModelKeysAreAmbiguous(t *testing.T) {
	p := governed(t, payloadModel())
	for _, body := range []string{
		`{"model":"gpt-4o","MODEL":"llama-3"}`,
		`{"Model":"llama-3","model":"gpt-4o"}`,
	} {
		assertFault(t, immediate(t, onBody(t, p, jsonBody(body))), 400, bodyInvalidModel, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	}
	// Other keys may differ only in case.
	bodyMods(t, onBody(t, p, jsonBody(`{"model":"gpt-4o","messages":[],"Messages":[]}`)))
}

func TestOnRequestBody_OverlongModelIsRejected(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "deny", "models": []any{"x"}},
	})
	long := strings.Repeat("a", maxModelLength+1)
	assertFault(t, immediate(t, onBody(t, p, jsonBody(fmt.Sprintf(`{"model":%q}`, long)))),
		400, bodyInvalidModel, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	bodyMods(t, onBody(t, p, jsonBody(fmt.Sprintf(`{"model":%q}`, strings.Repeat("a", maxModelLength)))))
}

// Under skip, a body cannot hide its model by its Content-Type or by a multipart form
// that parsers read differently. Each input once reached the upstream unchecked.
func TestOnRequestBody_SkipCannotBeTrickedByBodyShape(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "allow", "models": []any{"gpt-4o-mini"}, "onMissingModel": "skip"},
	})
	mp := "multipart/form-data; boundary=b"
	part := func(headers, value string) string {
		return "--b\r\n" + headers + "\r\n\r\n" + value + "\r\n--b--\r\n"
	}
	tests := []struct {
		name   string
		ctx    *policy.RequestContext
		status int
	}{
		{"JSON labelled as a form", bodyContext("POST", "application/x-www-form-urlencoded", `{"model":"llama-3","messages":[]}`), 404},
		{"JSON labelled as multipart", bodyContext("POST", mp, `{"model":"llama-3"}`), 404},
		{"JSON labelled as binary", bodyContext("POST", "application/octet-stream", ` {"model":"llama-3"}`), 404},
		{"JSON with a BOM", bodyContext("POST", "application/octet-stream", "\xef\xbb\xbf{\"model\":\"llama-3\"}"), 400},
		{"JSON with a trailing comma", bodyContext("POST", "application/octet-stream", `{"model":"llama-3",}`), 400},
		{"repeated name parameter", bodyContext("POST", mp, part(`Content-Disposition: form-data; name="x"; name="model"`, "llama-3")), 400},
		{"two Content-Disposition headers", bodyContext("POST", mp, part("Content-Disposition: form-data; name=\"x\"\r\nContent-Disposition: form-data; name=\"model\"", "llama-3")), 400},
		{"RFC 2231 name", bodyContext("POST", mp, part(`Content-Disposition: form-data; name*=utf-8''model`, "llama-3")), 400},
		{"encoded model part", bodyContext("POST", mp, part("Content-Disposition: form-data; name=\"model\"\r\nContent-Transfer-Encoding: quoted-printable", "=67pt-4o-mini")), 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := immediate(t, onBody(t, p, tt.ctx))
			if resp.StatusCode != tt.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
	// A file part may still use an RFC 2231 filename.
	upload := part(`Content-Disposition: form-data; name="file"; filename*=utf-8''r%C3%A9sum%C3%A9.jsonl`, "{}")
	if mods := bodyMods(t, onBody(t, p, bodyContext("POST", mp, upload))); mods.Body != nil {
		t.Error("file upload body changed")
	}
}

func payloadModel() map[string]any {
	return map[string]any{"location": "payload", "identifier": "$.model"}
}

func headerModel() map[string]any {
	return map[string]any{"location": "header", "identifier": "x-model"}
}

func queryModel() map[string]any {
	return map[string]any{"location": "queryParam", "identifier": "model"}
}

func pathModel() map[string]any {
	return map[string]any{"location": "pathParam", "identifier": "/models/([^/]+)/chat"}
}

// literalRule is a pattern that matches one model name, ignoring case.
func literalRule(from, to, provider string) map[string]any {
	m := map[string]any{"fromPattern": "(?i)" + regexp.QuoteMeta(from), "to": to}
	if provider != "" {
		m["provider"] = provider
	}
	return m
}

func patternRule(from, to, provider string) map[string]any {
	m := map[string]any{"fromPattern": from, "to": to}
	if provider != "" {
		m["provider"] = provider
	}
	return m
}

// allowOnly permits the listed models and denies every other model.
func allowOnly(models ...any) map[string]any {
	return map[string]any{"mode": "allow", "models": models}
}

// denyOnly denies the listed models and permits every other model.
func denyOnly(models ...any) map[string]any {
	return map[string]any{"mode": "deny", "models": models}
}

func mustPolicy(t *testing.T, params map[string]any) *Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	return p.(*Policy)
}

// governed is the reference configuration: gpt-4o and claude-sonnet are permitted,
// old-model falls back to gpt-4o on the primary provider and claude-friendly falls
// back to claude-sonnet on the anthropic provider.
func governed(t *testing.T, location map[string]any) *Policy {
	t.Helper()
	return mustPolicy(t, map[string]any{
		"requestModel": location,
		"access":       allowOnly("gpt-4o", "claude-sonnet"),
		"fallback": map[string]any{
			"mappingPatterns": []any{
				literalRule("old-model", "gpt-4o", ""),
				literalRule("claude-friendly", "claude-sonnet", "anthropic"),
			},
		},
	})
}

func bodyContext(method, contentType, body string) *policy.RequestContext {
	headers := map[string][]string{}
	if contentType != "" {
		headers["content-type"] = []string{contentType}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata:      map[string]any{},
			APIId:         "api-1",
			OperationPath: "/chat/completions",
		},
		Headers: policy.NewHeaders(headers),
		Body:    &policy.Body{Content: []byte(body), Present: body != "", EndOfStream: true},
		Path:    "/proxy/chat/completions",
		Method:  method,
	}
}

func jsonBody(body string) *policy.RequestContext {
	return bodyContext("POST", "application/json", body)
}

func headerContext(method, path string, headers map[string][]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata:      map[string]any{},
			APIId:         "api-1",
			OperationPath: "/chat/completions",
		},
		Headers: policy.NewHeaders(headers),
		Path:    path,
		Method:  method,
	}
}

func bodyModel(t *testing.T, body []byte) string {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("rewritten body is not JSON: %v (%s)", err, body)
	}
	model, _ := payload["model"].(string)
	return model
}

// assertFault checks an immediate response's status, body and fault declaration.
func assertFault(t *testing.T, resp policy.ImmediateResponse, status int, body []byte, code, faultType string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, status)
	}
	if string(resp.Body) != string(body) {
		t.Errorf("Body = %s, want %s", resp.Body, body)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Errorf("content-type = %q, want application/json", resp.Headers["content-type"])
	}
	if !resp.IsFault {
		t.Error("IsFault = false, want true")
	}
	if resp.Fault == nil {
		t.Fatal("Fault = nil")
	}
	if resp.Fault.Code != code {
		t.Errorf("Fault.Code = %q, want %q", resp.Fault.Code, code)
	}
	if resp.Fault.Type != faultType {
		t.Errorf("Fault.Type = %q, want %q", resp.Fault.Type, faultType)
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Errorf("Fault.Direction = %q, want %q", resp.Fault.Direction, policy.DirectionRequest)
	}
	if resp.Fault.Message == "" {
		t.Error("Fault.Message is empty")
	}
	if resp.Fault.Policy != "" {
		t.Errorf("Fault.Policy = %q, want it left for the gateway", resp.Fault.Policy)
	}
}
