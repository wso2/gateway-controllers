package respond

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func mustImmediateResponse(t *testing.T, action policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	return resp
}

func assertConfigError(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	if resp.StatusCode != 500 {
		t.Fatalf("expected status code 500, got %d", resp.StatusCode)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", resp.Headers["content-type"])
	}

	var payload map[string]string
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if payload["error"] != "Configuration Error" {
		t.Fatalf("unexpected error type: %q", payload["error"])
	}
	if payload["message"] == "" {
		t.Fatalf("expected non-empty config error message")
	}
}

func TestGetPolicyReturnsSingleton(t *testing.T) {
	first, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	second, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestMode(t *testing.T) {
	p := &RespondPolicy{}
	mode := p.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Fatalf("unexpected request header mode: %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Fatalf("unexpected request body mode: %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatalf("unexpected response header mode: %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("unexpected response body mode: %v", mode.ResponseBodyMode)
	}
}

func TestOnResponseReturnsNil(t *testing.T) {
	p := &RespondPolicy{}
	if got := p.OnResponse(&policy.ResponseContext{}, map[string]interface{}{}); got != nil {
		t.Fatalf("expected nil response action, got %T", got)
	}
}

func TestOnRequestDefaults(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequest(&policy.RequestContext{}, map[string]interface{}{}))

	if resp.StatusCode != 200 {
		t.Fatalf("expected default status 200, got %d", resp.StatusCode)
	}
	if len(resp.Headers) != 0 {
		t.Fatalf("expected no default headers, got %#v", resp.Headers)
	}
	if len(resp.Body) != 0 {
		t.Fatalf("expected empty default body, got %q", string(resp.Body))
	}
}

func TestOnRequestValidConfig(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequest(&policy.RequestContext{}, map[string]interface{}{
		"statusCode": 201,
		"body":       `{"ok":true}`,
		"headers": []interface{}{
			map[string]interface{}{"name": "content-type", "value": "application/json"},
			map[string]interface{}{"name": "x-trace-id", "value": "abc123"},
		},
	}))

	if resp.StatusCode != 201 {
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %q", string(resp.Body))
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("unexpected content-type header: %q", resp.Headers["content-type"])
	}
	if resp.Headers["x-trace-id"] != "abc123" {
		t.Fatalf("unexpected x-trace-id header: %q", resp.Headers["x-trace-id"])
	}
}

func TestOnRequestStatusCodeValidation(t *testing.T) {
	p := &RespondPolicy{}
	tests := []map[string]interface{}{
		{"statusCode": 99},
		{"statusCode": 600},
		{"statusCode": 201.5},
		{"statusCode": "200"},
	}

	for _, params := range tests {
		resp := mustImmediateResponse(t, p.OnRequest(&policy.RequestContext{}, params))
		assertConfigError(t, resp)
	}
}

func TestOnRequestBodyTypeValidation(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequest(&policy.RequestContext{}, map[string]interface{}{
		"body": 42,
	}))
	assertConfigError(t, resp)
}

func TestOnRequestHeadersTypeValidation(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequest(&policy.RequestContext{}, map[string]interface{}{
		"headers": "not-an-array",
	}))
	assertConfigError(t, resp)
}

func TestOnRequestHeaderObjectValidation(t *testing.T) {
	p := &RespondPolicy{}

	tests := []struct {
		name    string
		headers []interface{}
	}{
		{
			name:    "non object entry",
			headers: []interface{}{"invalid"},
		},
		{
			name:    "missing name",
			headers: []interface{}{map[string]interface{}{"value": "v"}},
		},
		{
			name:    "missing value",
			headers: []interface{}{map[string]interface{}{"name": "x-a"}},
		},
		{
			name:    "unsupported field",
			headers: []interface{}{map[string]interface{}{"name": "x-a", "value": "v", "extra": "x"}},
		},
		{
			name:    "invalid name characters",
			headers: []interface{}{map[string]interface{}{"name": "x bad", "value": "v"}},
		},
		{
			name:    "name too long",
			headers: []interface{}{map[string]interface{}{"name": strings.Repeat("a", 257), "value": "v"}},
		},
		{
			name:    "value too long",
			headers: []interface{}{map[string]interface{}{"name": "x-a", "value": strings.Repeat("a", 8193)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mustImmediateResponse(t, p.OnRequest(&policy.RequestContext{}, map[string]interface{}{
				"headers": tt.headers,
			}))
			assertConfigError(t, resp)
		})
	}
}
