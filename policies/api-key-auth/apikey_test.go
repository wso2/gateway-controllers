package apikey

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	apikeycommon "github.com/wso2/api-platform/common/apikey"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

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

func TestAPIKeyPolicy_OnRequestHeaders_SuccessFromHeader(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("x-api-key"): {"header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=true")
	}
	if ctx.SharedContext.AuthContext.AuthType != "apikey" {
		t.Fatalf("expected AuthType='apikey', got %q", ctx.SharedContext.AuthContext.AuthType)
	}
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != http.CanonicalHeaderKey("x-api-key") {
		t.Fatalf("expected HeadersToRemove=[%q], got %v", http.CanonicalHeaderKey("x-api-key"), mods.HeadersToRemove)
	}
	if got, ok := mods.AnalyticsMetadata[applicationNameMetadataKey]; !ok || got != "test-app-name" {
		t.Fatalf("expected %q metadata to be %q, got %v", applicationNameMetadataKey, "test-app-name", got)
	}
	if got, ok := mods.AnalyticsMetadata[applicationIDMetadataKey]; !ok || got != "test-app-id" {
		t.Fatalf("expected %q metadata to be %q, got %v", applicationIDMetadataKey, "test-app-id", got)
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_SuccessFromQuery(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-2", "query-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders?x_api_key=query-secret", nil, "api-2", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x_api_key",
		"in":  "query",
	})

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=true")
	}
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if len(mods.QueryParametersToRemove) != 1 || mods.QueryParametersToRemove[0] != "x_api_key" {
		t.Fatalf("expected QueryParametersToRemove=[%q], got %v", "x_api_key", mods.QueryParametersToRemove)
	}
	if got, ok := mods.AnalyticsMetadata[applicationNameMetadataKey]; !ok || got != "test-app-name" {
		t.Fatalf("expected %q metadata to be %q, got %v", applicationNameMetadataKey, "test-app-name", got)
	}
	if got, ok := mods.AnalyticsMetadata[applicationIDMetadataKey]; !ok || got != "test-app-id" {
		t.Fatalf("expected %q metadata to be %q, got %v", applicationIDMetadataKey, "test-app-id", got)
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_MissingOrInvalidConfig(t *testing.T) {
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
			ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
				"x-api-key": {"header-secret"},
			}, "api-1", "OrdersAPI", "v1", "/orders")

			action := p.OnRequestHeaders(context.Background(), ctx, tt.params)
			assertUnauthorizedJSON(t, action)

			if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
				t.Fatalf("expected AuthContext.Authenticated=false")
			}
		})
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenAPIKeyMissing(t *testing.T) {
	resetAPIKeyStore(t)
	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders?foo=bar", nil, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x_api_key",
		"in":  "query",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenAPIDetailsMissing(t *testing.T) {
	resetAPIKeyStore(t)
	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"header-secret"},
	}, "api-1", "", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenValidationReturnsFalse(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "different-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"wrong-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenValidationErrors(t *testing.T) {
	resetAPIKeyStore(t)
	// Do not seed any key for "api-1" so ValidateAPIKey returns ErrNotFound.

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"no-matching-key"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_SuccessWithValuePrefix(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("authorization"): {"Bearer header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key":         "authorization",
		"in":          "header",
		"valuePrefix": "Bearer ",
	})

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=true")
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_ValuePrefixIsCaseInsensitive(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	// Header sends "Bearer " while the configured prefix is "bearer ".
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("authorization"): {"Bearer header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key":         "authorization",
		"in":          "header",
		"valuePrefix": "bearer ",
	})

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=true")
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenValuePrefixMissing(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	// Header value does not carry the configured prefix, so stripping yields
	// an empty key and the request must be rejected as malformed.
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("authorization"): {"header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key":         "authorization",
		"in":          "header",
		"valuePrefix": "Bearer ",
	})

	assertUnauthorizedJSON(t, action)
	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=false")
	}
}

func TestStripPrefix(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		prefix   string
		expected string
	}{
		{
			name:     "exact case match",
			value:    "Bearer secret",
			prefix:   "Bearer ",
			expected: "secret",
		},
		{
			name:     "case-insensitive match",
			value:    "Bearer secret",
			prefix:   "bearer ",
			expected: "secret",
		},
		{
			name:     "prefix not present",
			value:    "secret",
			prefix:   "Bearer ",
			expected: "",
		},
		{
			name:     "prefix longer than value",
			value:    "Bea",
			prefix:   "Bearer ",
			expected: "",
		},
		{
			name:     "prefix equals value",
			value:    "Bearer ",
			prefix:   "Bearer ",
			expected: "",
		},
		{
			name:     "mismatch after partial prefix",
			value:    "Basic secret",
			prefix:   "Bearer ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripPrefix(tt.value, tt.prefix)
			if got != tt.expected {
				t.Fatalf("unexpected value: got %q, want %q", got, tt.expected)
			}
		})
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

func newRequestHeaderContext(t *testing.T, method, path string, headers map[string][]string, apiID, apiName, apiVersion, opPath string) *policy.RequestHeaderContext {
	t.Helper()
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
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

func assertUnauthorizedJSON(t *testing.T, action policy.RequestHeaderAction) {
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

	// Every rejection this policy makes must reach the gateway's fault flow, and must
	// describe itself well enough for a renderer and for analytics categorisation.
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on an auth rejection")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated on an auth rejection")
	}
	if resp.Fault.Type != policy.FaultTypeAuthentication {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthentication, resp.Fault.Type)
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
	}
	switch resp.Fault.Code {
	case policy.FaultCodeAuthGeneral, policy.FaultCodeAuthInvalidCredentials, policy.FaultCodeAuthMissingCredentials:
	default:
		t.Fatalf("unexpected Error.Code %q", resp.Fault.Code)
	}
}

// TestAPIKeyPolicy_RejectionErrorCodes pins the code chosen per rejection condition.
func TestAPIKeyPolicy_RejectionErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]interface{}
		headers  map[string][]string
		apiName  string
		wantCode string
	}{
		{
			name:     "missing key configuration",
			params:   map[string]interface{}{"in": "header"},
			headers:  map[string][]string{"x-api-key": {"header-secret"}},
			apiName:  "OrdersAPI",
			wantCode: policy.FaultCodeAuthGeneral,
		},
		{
			name:     "no api key presented",
			params:   map[string]interface{}{"key": "x-api-key", "in": "header"},
			headers:  nil,
			apiName:  "OrdersAPI",
			wantCode: policy.FaultCodeAuthMissingCredentials,
		},
		{
			name:     "api key rejected",
			params:   map[string]interface{}{"key": "x-api-key", "in": "header"},
			headers:  map[string][]string{"x-api-key": {"wrong-secret"}},
			apiName:  "OrdersAPI",
			wantCode: policy.FaultCodeAuthInvalidCredentials,
		},
		{
			name:     "api details missing",
			params:   map[string]interface{}{"key": "x-api-key", "in": "header"},
			headers:  map[string][]string{"x-api-key": {"header-secret"}},
			apiName:  "",
			wantCode: policy.FaultCodeAuthGeneral,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetAPIKeyStore(t)
			seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

			p := &APIKeyPolicy{}
			ctx := newRequestHeaderContext(t, "GET", "/orders", tt.headers,
				"api-1", tt.apiName, "v1", "/orders")

			action := p.OnRequestHeaders(context.Background(), ctx, tt.params)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if !resp.IsFault {
				t.Fatalf("expected IsFault=true")
			}
			if resp.Fault == nil {
				t.Fatalf("expected Error to be populated")
			}
			if resp.Fault.Code != tt.wantCode {
				t.Fatalf("expected Error.Code=%q, got %q", tt.wantCode, resp.Fault.Code)
			}
			// Description carries the internal diagnostic and must not leak into the body.
			if resp.Fault.Description == "" {
				t.Fatalf("expected Error.Description to carry the internal reason")
			}
			if strings.Contains(string(resp.Body), resp.Fault.Description) {
				t.Fatalf("Description leaked into the client body: %q", resp.Fault.Description)
			}
		})
	}
}

// TestAPIKeyPolicy_OnRequestHeaders_WritesApplicationIDToSharedContextMetadata verifies
// that after a successful authentication, the application ID is written to
// SharedContext.Metadata so that downstream rate limiting policies can read it.
func TestAPIKeyPolicy_OnRequestHeaders_WritesApplicationIDToSharedContextMetadata(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("x-api-key"): {"header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	got, ok := ctx.SharedContext.Metadata[applicationIDMetadataKey]
	if !ok {
		t.Fatalf("expected %q to be present in SharedContext.Metadata", applicationIDMetadataKey)
	}
	if got != "test-app-id" {
		t.Errorf("expected SharedContext.Metadata[%q]=%q, got %v", applicationIDMetadataKey, "test-app-id", got)
	}
}

// TestAPIKeyPolicy_OnRequestHeaders_DoesNotWriteMetadataOnFailure verifies that
// SharedContext.Metadata is not populated with the application ID when auth fails.
func TestAPIKeyPolicy_OnRequestHeaders_DoesNotWriteMetadataOnFailure(t *testing.T) {
	resetAPIKeyStore(t)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("x-api-key"): {"wrong-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	if _, ok := ctx.SharedContext.Metadata[applicationIDMetadataKey]; ok {
		t.Errorf("expected %q to be absent from SharedContext.Metadata on auth failure", applicationIDMetadataKey)
	}
}

func TestAPIKeyPolicy_AuthContext_PreviousPreserved_OnSuccess(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	prior := &policy.AuthContext{Authenticated: true, AuthType: "other"}

	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"X-Api-Key": {"header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")
	ctx.SharedContext.AuthContext = prior

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", ctx.SharedContext.AuthContext.Previous)
	}
}

func TestAPIKeyPolicy_AuthContext_PreviousPreserved_OnFailure(t *testing.T) {
	resetAPIKeyStore(t)

	p := &APIKeyPolicy{}
	prior := &policy.AuthContext{Authenticated: true, AuthType: "other"}

	shared := &policy.SharedContext{
		RequestID:     "req-1",
		Metadata:      map[string]interface{}{},
		APIId:         "api-1",
		APIName:       "OrdersAPI",
		APIVersion:    "v1",
		OperationPath: "/orders",
	}
	shared.AuthContext = prior

	resp := p.failAuth(shared, 401, "json", "Valid API key required", "invalid API key", policy.FaultCodeAuthInvalidCredentials)

	if resp == nil {
		t.Fatal("Expected ImmediateResponse from failAuth")
	}
	if shared.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if shared.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", shared.AuthContext.Previous)
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
		ID:              "id-" + sanitizeTestName(t.Name()),
		Name:            "name-" + sanitizeTestName(t.Name()),
		DisplayName:     "test-key",
		ApplicationID:   "test-app-id",
		ApplicationName: "test-app-name",
		APIKey:          apikeycommon.ComputeAPIKeyHash(plainKey),
		APIId:           apiID,
		Operations:      operations,
		Status:          apikeycommon.Active,
		Source:          "external",
	}
	if err := apikeycommon.GetAPIkeyStoreInstance().StoreAPIKey(apiID, key); err != nil {
		t.Fatalf("failed to store API key: %v", err)
	}
}

func sanitizeTestName(v string) string {
	v = strings.ReplaceAll(v, "/", "-")
	v = strings.ReplaceAll(v, " ", "-")
	return strings.ToLower(v)
}
