package piimaskingregex

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestPIIMaskingRegexPolicy_Mode(t *testing.T) {
	p := &PIIMaskingRegexPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestPIIMaskingRegexPolicy_GetPolicy_ParseErrors(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "no detectors",
			params:         map[string]interface{}{},
			wantErrContain: "at least one PII detector must be configured",
		},
		{
			name: "customPIIEntities wrong type",
			params: map[string]interface{}{
				"customPIIEntities": 1,
			},
			wantErrContain: "'customPIIEntities' must be an array or JSON string",
		},
		{
			name: "customPIIEntities malformed json",
			params: map[string]interface{}{
				"customPIIEntities": `[{"piiEntity":"EMAIL","piiRegex":"abc"}`,
			},
			wantErrContain: "error unmarshaling PII entities",
		},
		{
			name: "customPIIEntities element non-object",
			params: map[string]interface{}{
				"customPIIEntities": []interface{}{"x"},
			},
			wantErrContain: "'customPIIEntities[0]' must be an object",
		},
		{
			name: "custom piiEntity invalid",
			params: map[string]interface{}{
				"customPIIEntities": []interface{}{
					map[string]interface{}{"piiEntity": "email", "piiRegex": "a+"},
				},
			},
			wantErrContain: "'customPIIEntities[0].piiEntity' must match ^[A-Z_]+$",
		},
		{
			name: "custom piiRegex invalid",
			params: map[string]interface{}{
				"customPIIEntities": []interface{}{
					map[string]interface{}{"piiEntity": "EMAIL", "piiRegex": "["},
				},
			},
			wantErrContain: "'customPIIEntities[0].piiRegex' is invalid",
		},
		{
			name: "duplicate custom piiEntity",
			params: map[string]interface{}{
				"customPIIEntities": []interface{}{
					map[string]interface{}{"piiEntity": "EMAIL", "piiRegex": "a+"},
					map[string]interface{}{"piiEntity": "EMAIL", "piiRegex": "b+"},
				},
			},
			wantErrContain: `duplicate piiEntity: "EMAIL"`,
		},
		{
			name: "duplicate builtin and custom",
			params: map[string]interface{}{
				"customPIIEntities": []interface{}{
					map[string]interface{}{"piiEntity": "EMAIL", "piiRegex": "a+"},
				},
				"email": true,
			},
			wantErrContain: `duplicate piiEntity: "EMAIL"`,
		},
		{
			name: "email wrong type",
			params: map[string]interface{}{
				"email": "true",
			},
			wantErrContain: "'email' must be a boolean",
		},
		{
			name: "jsonPath wrong type",
			params: map[string]interface{}{
				"email":    true,
				"jsonPath": false,
			},
			wantErrContain: "'jsonPath' must be a string",
		},
		{
			name: "redactPII wrong type",
			params: map[string]interface{}{
				"email":     true,
				"redactPII": "true",
			},
			wantErrContain: "'redactPII' must be a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestPIIMaskingRegexPolicy_GetPolicy_DefaultsAndBuiltins(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email": true,
		"phone": true,
		"ssn":   true,
	})

	if got := p.params.JsonPath; got != "$.messages" {
		t.Fatalf("expected default jsonPath '$.messages', got %q", got)
	}
	if p.params.RedactPII {
		t.Fatalf("expected default redactPII=false")
	}
	if len(p.params.PIIEntities) != 3 {
		t.Fatalf("expected 3 built-in detectors, got %d", len(p.params.PIIEntities))
	}
}

func TestPIIMaskingRegexPolicy_GetPolicy_CustomJSONString(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"customPIIEntities": `[{"piiEntity":"ORDER_ID","piiRegex":"ORD-[0-9]+"}]`,
		"jsonPath":          "$.content",
		"redactPII":         true,
	})

	if got := p.params.JsonPath; got != "$.content" {
		t.Fatalf("expected custom jsonPath, got %q", got)
	}
	if !p.params.RedactPII {
		t.Fatalf("expected redactPII=true")
	}
	if _, ok := p.params.PIIEntities["ORDER_ID"]; !ok {
		t.Fatalf("expected ORDER_ID custom detector")
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_MaskAndStoreMetadata(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email": true,
	})

	ctx := piiRequestContext(`{"messages":"Contact me at a.user@example.com please"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustPIIRequestMods(t, action)
	if len(mods.Body) == 0 {
		t.Fatalf("expected modified body")
	}

	out := decodeJSONMapPII(t, mods.Body)
	msg, _ := out["messages"].(string)
	matched, err := regexp.MatchString(`\[EMAIL_[0-9a-f]{4}\]`, msg)
	if err != nil {
		t.Fatalf("failed regex match: %v", err)
	}
	if !matched {
		t.Fatalf("expected masked email placeholder, got %q", msg)
	}

	metaVal, exists := ctx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		t.Fatalf("expected pii metadata to be stored")
	}
	mapping, ok := metaVal.(map[string]string)
	if !ok || len(mapping) == 0 {
		t.Fatalf("expected pii metadata mapping, got %T", metaVal)
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_RedactMode(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email":     true,
		"redactPII": true,
	})

	ctx := piiRequestContext(`{"messages":"email a.user@example.com"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustPIIRequestMods(t, action)
	out := decodeJSONMapPII(t, mods.Body)
	msg, _ := out["messages"].(string)
	if !strings.Contains(msg, "*****") {
		t.Fatalf("expected redacted content, got %q", msg)
	}
	if _, exists := ctx.Metadata[MetadataKeyPIIEntities]; exists {
		t.Fatalf("did not expect metadata mapping in redact mode")
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_NoMatch_NoOp(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email": true,
	})

	ctx := piiRequestContext(`{"messages":"no pii here"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustPIIRequestMods(t, action)
	if mods.Body != nil {
		t.Fatalf("expected no modifications when no pii match, got body=%s", string(mods.Body))
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_JSONPathError(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email":    true,
		"jsonPath": "$.missing.value",
	})

	ctx := piiRequestContext(`{"messages":"a.user@example.com"}`)
	action := p.OnRequest(ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for extraction error, got %T", action)
	}
	if resp.StatusCode != APIMInternalErrorCode {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
}

func TestPIIMaskingRegexPolicy_OnResponse_RestoreMaskedPII(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email": true,
	})

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata: map[string]interface{}{
				MetadataKeyPIIEntities: map[string]string{
					"a.user@example.com": "[EMAIL_0000]",
				},
			},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"answer":"Found [EMAIL_0000]"}`),
			Present: true,
		},
	}
	action := p.OnResponse(ctx, nil)
	mods, ok := action.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
	if !strings.Contains(string(mods.Body), "a.user@example.com") {
		t.Fatalf("expected placeholder to be restored, got %s", string(mods.Body))
	}
}

func TestPIIMaskingRegexPolicy_OnResponse_NoOpCases(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email": true,
	})

	// No metadata
	ctx1 := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"x":"y"}`),
			Present: true,
		},
	}
	a1 := p.OnResponse(ctx1, nil)
	if _, ok := a1.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", a1)
	}

	// Redact mode always no-op for response restoration
	pRedact := mustGetPIIPolicy(t, map[string]interface{}{
		"email":     true,
		"redactPII": true,
	})
	ctx2 := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata: map[string]interface{}{
				MetadataKeyPIIEntities: map[string]string{"a.user@example.com": "[EMAIL_0000]"},
			},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"x":"[EMAIL_0000]"}`),
			Present: true,
		},
	}
	a2 := pRedact.OnResponse(ctx2, nil)
	if _, ok := a2.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", a2)
	}
}

func mustGetPIIPolicy(t *testing.T, params map[string]interface{}) *PIIMaskingRegexPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	pp, ok := p.(*PIIMaskingRegexPolicy)
	if !ok {
		t.Fatalf("expected *PIIMaskingRegexPolicy, got %T", p)
	}
	return pp
}

func mustPIIRequestMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func piiRequestContext(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func decodeJSONMapPII(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}
	return m
}
