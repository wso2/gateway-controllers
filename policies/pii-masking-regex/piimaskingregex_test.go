package piimaskingregex

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

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
			name: "custom piiEntity invalid characters",
			params: map[string]interface{}{
				"customPIIEntities": []interface{}{
					map[string]interface{}{"piiEntity": "email-1", "piiRegex": "a+"},
				},
			},
			wantErrContain: "'customPIIEntities[0].piiEntity' must contain only letters and underscores",
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
					map[string]interface{}{"piiEntity": "email", "piiRegex": "a+"},
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

	if got := p.params.JsonPath; got != "$" {
		t.Fatalf("expected default jsonPath '$', got %q", got)
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

func TestPIIMaskingRegexPolicy_GetPolicy_CustomEntityName_IsNormalizedToUppercase(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"customPIIEntities": []interface{}{
			map[string]interface{}{"piiEntity": "order_id", "piiRegex": "ORD-[0-9]+"},
		},
	})

	if _, ok := p.params.PIIEntities["ORDER_ID"]; !ok {
		t.Fatalf("expected lowercase custom entity name to be normalized to ORDER_ID")
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_MaskAndStoreMetadata(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email": true,
	})

	ctx := piiRequestContext(`{"messages":[{"content":"Contact me at a.user@example.com please"}]}`)
	action := p.OnRequestBody(context.Background(), ctx, nil)
	mods := mustPIIRequestMods(t, action)
	if len(mods.Body) == 0 {
		t.Fatalf("expected modified body")
	}

	out := decodeJSONMapPII(t, mods.Body)
	msg := mustGetLastMessageContent(t, out)
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

	ctx := piiRequestContext(`{"messages":[{"content":"email a.user@example.com"}]}`)
	action := p.OnRequestBody(context.Background(), ctx, nil)
	mods := mustPIIRequestMods(t, action)
	out := decodeJSONMapPII(t, mods.Body)
	msg := mustGetLastMessageContent(t, out)
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

	ctx := piiRequestContext(`{"messages":[{"content":"no pii here"}]}`)
	action := p.OnRequestBody(context.Background(), ctx, nil)
	mods := mustPIIRequestMods(t, action)
	if mods.Body != nil {
		t.Fatalf("expected no modifications when no pii match, got body=%s", string(mods.Body))
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_RootJSONPathUsesWholePayload(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email":    true,
		"jsonPath": "$",
	})

	ctx := piiRequestContext(`{"owner":"owner@example.com","message":"hello"}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	if strings.Contains(string(mods.Body), "owner@example.com") {
		t.Fatalf("expected email in the whole payload to be masked, got %s", mods.Body)
	}
	if !json.Valid(mods.Body) {
		t.Fatalf("expected the masked payload to remain valid JSON, got %s", mods.Body)
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_JSONPathError(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{
		"email":    true,
		"jsonPath": "$.missing.value",
	})

	ctx := piiRequestContext(`{"messages":"a.user@example.com"}`)
	action := p.OnRequestBody(context.Background(), ctx, nil)
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
	action := p.OnResponseBody(context.Background(), ctx, nil)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
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
	a1 := p.OnResponseBody(context.Background(), ctx1, nil)
	if _, ok := a1.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", a1)
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
	a2 := pRedact.OnResponseBody(context.Background(), ctx2, nil)
	if _, ok := a2.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", a2)
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

func mustGetLastMessageContent(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	messages, ok := payload["messages"].([]interface{})
	if !ok || len(messages) == 0 {
		t.Fatalf("expected payload.messages to be a non-empty array, got %T", payload["messages"])
	}

	lastMessage, ok := messages[len(messages)-1].(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload.messages[-1] to be an object, got %T", messages[len(messages)-1])
	}

	content, ok := lastMessage["content"].(string)
	if !ok {
		t.Fatalf("expected payload.messages[-1].content to be a string, got %T", lastMessage["content"])
	}

	return content
}

// conversation is the second turn of a chat as an agent sends it: the system prompt, the history,
// then the newest message. The email is in an earlier turn, and the newest message is content parts.
const conversation = `{"model":"gpt-4o-mini","messages":[
  {"role":"system","content":"You are a helpdesk assistant."},
  {"role":"user","content":"My email is alice.chen@acmecorp.com"},
  {"role":"assistant","content":"Noted, alice.chen@acmecorp.com."},
  {"role":"user","content":[{"type":"text","text":"Please cc bob@example.org"}]}]}`

func TestPIIMaskingRegexPolicy_OnRequest_DefaultMasksEveryTurn(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})

	ctx := piiRequestContext(conversation)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	for _, email := range []string{"alice.chen@acmecorp.com", "bob@example.org"} {
		if strings.Contains(string(mods.Body), email) {
			t.Fatalf("%q reached the upstream unmasked: %s", email, mods.Body)
		}
	}
	if !json.Valid(mods.Body) {
		t.Fatalf("expected valid JSON, got %s", mods.Body)
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_WildcardMasksEveryMessage(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[*].content"})

	ctx := piiRequestContext(`{"messages":[
	  {"role":"user","content":"I am alice.chen@acmecorp.com"},
	  {"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
	  {"role":"tool","tool_call_id":"c1","content":"record for bob@example.org"},
	  {"role":"user","content":"Again, I am alice.chen@acmecorp.com"}]}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))

	out := decodeJSONMapPII(t, mods.Body)
	messages := out["messages"].([]interface{})
	first := messages[0].(map[string]interface{})["content"].(string)
	tool := messages[2].(map[string]interface{})["content"].(string)
	last := messages[3].(map[string]interface{})["content"].(string)
	if first != "I am [EMAIL_0000]" || last != "Again, I am [EMAIL_0000]" {
		t.Fatalf("the same email must get the same placeholder in every message, got %q and %q", first, last)
	}
	if tool != "record for [EMAIL_0001]" {
		t.Fatalf("a different email must get a different placeholder, got %q", tool)
	}
	if _, ok := messages[1].(map[string]interface{})["tool_calls"]; !ok {
		t.Fatalf("a message without content must be left as it is, got %v", messages[1])
	}
	mapping := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if len(mapping) != 2 || mapping["alice.chen@acmecorp.com"] != "[EMAIL_0000]" || mapping["bob@example.org"] != "[EMAIL_0001]" {
		t.Fatalf("expected both emails recorded for restoration, got %v", mapping)
	}

	// The response restores both originals.
	respCtx := &policy.ResponseContext{
		SharedContext: ctx.SharedContext,
		ResponseBody: &policy.Body{
			Content: []byte(`{"choices":[{"message":{"content":"[EMAIL_0000] and [EMAIL_0001]"}}]}`),
			Present: true,
		},
	}
	resp, ok := p.OnResponseBody(context.Background(), respCtx, nil).(policy.DownstreamResponseModifications)
	if !ok || !strings.Contains(string(resp.Body), "alice.chen@acmecorp.com and bob@example.org") {
		t.Fatalf("expected both placeholders restored, got %s", resp.Body)
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_WildcardRedact(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[*].content", "redactPII": true})

	ctx := piiRequestContext(`{"messages":[{"content":"a.user@example.com"},{"content":"b.user@example.com"}]}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	if strings.Count(string(mods.Body), "*****") != 2 || strings.Contains(string(mods.Body), "@example.com") {
		t.Fatalf("expected every message redacted, got %s", mods.Body)
	}
	if _, exists := ctx.Metadata[MetadataKeyPIIEntities]; exists {
		t.Fatalf("did not expect metadata mapping in redact mode")
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_NestedWildcardMasksContentParts(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[*].content[*].text"})

	ctx := piiRequestContext(`{"messages":[
	  {"role":"system","content":"no parts here"},
	  {"role":"user","content":[{"type":"text","text":"I am alice.chen@acmecorp.com"},{"type":"text","text":"cc bob@example.org"}]}]}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	if strings.Contains(string(mods.Body), "@") {
		t.Fatalf("expected every text part masked, got %s", mods.Body)
	}
	if !strings.Contains(string(mods.Body), `"content":"no parts here"`) {
		t.Fatalf("a message whose content is not an array must be left as it is, got %s", mods.Body)
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_WildcardWithoutTheArrayIsRejected(t *testing.T) {
	tests := map[string]struct {
		body    string
		message string
	}{
		"missing array": {`{"input":"a.user@example.com"}`, "error extracting value from JSONPath: key not found: messages"},
		"not an array":  {`{"messages":"a.user@example.com"}`, "error extracting value from JSONPath: not an array: messages"},
		"invalid JSON":  {`not json a.user@example.com`, "error extracting value from JSONPath: invalid character"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[*].content"})
			resp, ok := p.OnRequestBody(context.Background(), piiRequestContext(tt.body), nil).(policy.ImmediateResponse)
			if !ok || resp.StatusCode != APIMInternalErrorCode {
				t.Fatalf("expected a 500 rejection, got %T", resp)
			}
			if !strings.Contains(string(resp.Body), tt.message) {
				t.Fatalf("expected %q in %s", tt.message, resp.Body)
			}
		})
	}
}

func TestExpandWildcardPaths(t *testing.T) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(`{"messages":[{"content":[{"text":"a"}]},{"content":"b"},{"content":[{"text":"c"},{"text":"d"}]}]}`), &data); err != nil {
		t.Fatal(err)
	}
	got, err := expandWildcardPaths(data, "$.messages[*].content[*].text", true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"$.messages[0].content[0].text", "$.messages[2].content[0].text", "$.messages[2].content[1].text"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, _ := expandWildcardPaths(data, "$.messages[1].content", true); len(got) != 1 || got[0] != "$.messages[1].content" {
		t.Fatalf("a path without a wildcard must be returned as it is, got %v", got)
	}
}
