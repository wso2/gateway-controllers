package respond

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mustImmediateResponse(t *testing.T, action policy.RequestHeaderAction) policy.ImmediateResponse {
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
	// A misconfigured policy refuses every request, so the fault policies should see it.
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on a configuration error")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated on a configuration error")
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
	}
	if resp.Fault.Type != policy.FaultTypeConfiguration {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeConfiguration, resp.Fault.Type)
	}
}

func TestGetPolicyReturnsSingleton(t *testing.T) {
	first, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicyV2 failed: %v", err)
	}
	second, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicyV2 failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestOnRequestHeadersDefaults(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, map[string]interface{}{}))

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

func TestOnRequestHeadersValidConfig(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, map[string]interface{}{
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

func TestOnRequestHeadersStatusCodeValidation(t *testing.T) {
	p := &RespondPolicy{}
	tests := []map[string]interface{}{
		{"statusCode": 99},
		{"statusCode": 600},
		{"statusCode": 201.5},
		{"statusCode": "200"},
	}

	for _, params := range tests {
		resp := mustImmediateResponse(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, params))
		assertConfigError(t, resp)
	}
}

func TestOnRequestHeadersBodyTypeValidation(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, map[string]interface{}{
		"body": 42,
	}))
	assertConfigError(t, resp)
}

func TestOnRequestHeadersHeadersTypeValidation(t *testing.T) {
	p := &RespondPolicy{}
	resp := mustImmediateResponse(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, map[string]interface{}{
		"headers": "not-an-array",
	}))
	assertConfigError(t, resp)
}

func TestOnRequestHeadersHeaderObjectValidation(t *testing.T) {
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
			resp := mustImmediateResponse(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, map[string]interface{}{
				"headers": tt.headers,
			}))
			assertConfigError(t, resp)
		})
	}
}

// A configured response is a deliberate end to the request, whatever status the operator
// chose. This policy therefore describes nothing: it has no failure to account for.
//
// It does not declare a fault either, at any status. A configured 404 or 503 is the answer
// the operator asked for, and this policy has no grounds for overruling that — which is
// exactly what an explicit declaration lets it avoid. A status rule could not: it would
// report every canned 404 as a failure and leave the operator narrowing it back out with
// `executionCondition: 'fault.Status < 500'`.
//
// What must NOT happen is this policy inventing a description for a response the operator
// chose, which is what the assertion below still guards.
func TestConfiguredResponseIsNotDescribed(t *testing.T) {
	for _, status := range []int{200, 404, 418, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			p := &RespondPolicy{}
			action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, map[string]interface{}{
				"statusCode": float64(status),
				"body":       "configured body",
			})
			resp := mustImmediateResponse(t, action)
			if resp.StatusCode != status {
				t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
			}
			if resp.IsFault {
				t.Fatalf("a configured %d response must not be a fault", status)
			}
			if resp.Fault != nil {
				t.Fatalf("a configured %d response must not describe an error", status)
			}
		})
	}
}
