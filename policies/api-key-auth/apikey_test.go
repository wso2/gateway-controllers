package apikey

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	apikeycommon "github.com/wso2/api-platform/common/apikey"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestAPIKeyPolicy_Mode(t *testing.T) {
	p := &APIKeyPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}

	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestGetPolicy_ReturnsSingleton(t *testing.T) {
	p1, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	p2, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestAPIKeyPolicy_OnRequest_SuccessFromHeader(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("x-api-key"): {"header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequest(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Fatalf("expected auth.success=true, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}
	if ctx.Metadata[MetadataKeyAuthMethod] != "api-key" {
		t.Fatalf("expected auth.method=api-key, got %v", ctx.Metadata[MetadataKeyAuthMethod])
	}
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestAPIKeyPolicy_OnRequest_SuccessFromQuery(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-2", "query-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders?x_api_key=query-secret", nil, "api-2", "OrdersAPI", "v1", "/orders")

	action := p.OnRequest(ctx, map[string]interface{}{
		"key": "x_api_key",
		"in":  "query",
	})

	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Fatalf("expected auth.success=true, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestAPIKeyPolicy_OnRequest_MissingOrInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
	}{
		{
			name: "missing key",
			params: map[string]interface{}{
				"in": "header",
			},
		},
		{
			name: "missing in",
			params: map[string]interface{}{
				"key": "x-api-key",
			},
		},
		{
			name: "unsupported in",
			params: map[string]interface{}{
				"key": "x-api-key",
				"in":  "cookie",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetAPIKeyStore(t)
			p := &APIKeyPolicy{}
			ctx := newRequestContext(t, "GET", "/orders", map[string][]string{
				"x-api-key": {"header-secret"},
			}, "api-1", "OrdersAPI", "v1", "/orders")

			action := p.OnRequest(ctx, tt.params)
			assertUnauthorizedJSON(t, action)

			if ctx.Metadata[MetadataKeyAuthSuccess] != false {
				t.Fatalf("expected auth.success=false, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
			}
		})
	}
}

func TestAPIKeyPolicy_OnRequest_FailsWhenAPIKeyMissing(t *testing.T) {
	resetAPIKeyStore(t)
	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders?foo=bar", nil, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequest(ctx, map[string]interface{}{
		"key": "x_api_key",
		"in":  "query",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequest_FailsWhenAPIDetailsMissing(t *testing.T) {
	resetAPIKeyStore(t)
	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"header-secret"},
	}, "api-1", "", "v1", "/orders")

	action := p.OnRequest(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequest_FailsWhenValidationReturnsFalse(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "different-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"wrong-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequest(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequest_FailsWhenValidationErrors(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "bad-ops-secret", `not-json`)

	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"bad-ops-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequest(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnResponse_NoOp(t *testing.T) {
	p := &APIKeyPolicy{}
	action := p.OnResponse(&policy.ResponseContext{}, nil)
	if action != nil {
		t.Fatalf("expected nil response action, got %T", action)
	}
}

func TestAPIKeyPolicy_HandleAuthFailure_PlainFormat(t *testing.T) {
	p := &APIKeyPolicy{}
	ctx := newRequestContext(t, "GET", "/orders", nil, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.handleAuthFailure(ctx, 401, "plain", "Auth failed", "test failure")
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.Headers["content-type"] != "text/plain" {
		t.Fatalf("unexpected content-type: %q", resp.Headers["content-type"])
	}
	if string(resp.Body) != "Auth failed" {
		t.Fatalf("unexpected body: %q", string(resp.Body))
	}
}

func TestExtractQueryParam(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		param    string
		expected string
	}{
		{
			name:     "simple query",
			path:     "/orders?token=abc123",
			param:    "token",
			expected: "abc123",
		},
		{
			name:     "encoded path",
			path:     "/orders%3Ftoken%3Dabc123",
			param:    "token",
			expected: "abc123",
		},
		{
			name:     "multiple values takes first",
			path:     "/orders?token=first&token=second",
			param:    "token",
			expected: "first",
		},
		{
			name:     "missing query",
			path:     "/orders",
			param:    "token",
			expected: "",
		},
		{
			name:     "invalid escaped path",
			path:     "%",
			param:    "token",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractQueryParam(tt.path, tt.param)
			if got != tt.expected {
				t.Fatalf("unexpected value: got %q, want %q", got, tt.expected)
			}
		})
	}
}

func newRequestContext(t *testing.T, method, path string, headers map[string][]string, apiID, apiName, apiVersion, opPath string) *policy.RequestContext {
	t.Helper()
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "req-1",
			Metadata:      map[string]interface{}{},
			APIId:         apiID,
			APIName:       apiName,
			APIVersion:    apiVersion,
			OperationPath: opPath,
		},
		Headers: policy.NewHeaders(headers),
		Method:  method,
		Path:    path,
	}
}

func assertUnauthorizedJSON(t *testing.T, action policy.RequestAction) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", resp.Headers["content-type"])
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] != "Unauthorized" {
		t.Fatalf("unexpected error value: %v", body["error"])
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "Valid API key required") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func resetAPIKeyStore(t *testing.T) {
	t.Helper()
	if err := apikeycommon.GetAPIkeyStoreInstance().ClearAll(); err != nil {
		t.Fatalf("failed to clear API key store: %v", err)
	}
}

func seedExternalAPIKey(t *testing.T, apiID, plainKey, operations string) {
	t.Helper()
	key := &apikeycommon.APIKey{
		ID:          "id-" + sanitizeTestName(t.Name()),
		Name:        "name-" + sanitizeTestName(t.Name()),
		DisplayName: "test-key",
		APIKey:      plainKey,
		APIId:       apiID,
		Operations:  operations,
		Status:      apikeycommon.Active,
		Source:      "external",
		IndexKey:    hashExternalIndexKey(plainKey),
	}
	if err := apikeycommon.GetAPIkeyStoreInstance().StoreAPIKey(apiID, key); err != nil {
		t.Fatalf("failed to store API key: %v", err)
	}
}

func hashExternalIndexKey(v string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(v)))
	return hex.EncodeToString(h[:])
}

func sanitizeTestName(v string) string {
	v = strings.ReplaceAll(v, "/", "-")
	v = strings.ReplaceAll(v, " ", "-")
	return strings.ToLower(v)
}
