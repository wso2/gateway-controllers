package basicauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newBasicRequestHeaderContext(headers map[string][]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(headers),
		Method:  "GET",
		Path:    "/api/resource",
	}
}

func basicAuthHeader(username, password string) string {
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + creds
}

func defaultParams() map[string]interface{} {
	return map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}
}

func TestGetPolicy_ReturnsSingleton(t *testing.T) {
	p1, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	p2, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_ValidCredentials(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(map[string][]string{
		"authorization": {basicAuthHeader("admin", "secret")},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, defaultParams())

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if !ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if ctx.SharedContext.AuthContext.AuthType != "basic" {
		t.Errorf("expected AuthType='basic', got %q", ctx.SharedContext.AuthContext.AuthType)
	}
	if ctx.SharedContext.AuthContext.Subject != "admin" {
		t.Errorf("expected Subject='admin', got %q", ctx.SharedContext.AuthContext.Subject)
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_WrongPassword(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(map[string][]string{
		"authorization": {basicAuthHeader("admin", "wrong-password")},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, defaultParams())

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=false for wrong password")
	}
	if ctx.SharedContext.AuthContext.AuthType != "basic" {
		t.Errorf("expected AuthType='basic', got %q", ctx.SharedContext.AuthContext.AuthType)
	}

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_MissingAuthorizationHeader(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	action := p.OnRequestHeaders(context.Background(), ctx, defaultParams())

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
	assertJSONError(t, resp.Body)
}

func TestBasicAuthPolicy_OnRequestHeaders_MalformedAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"not basic scheme", "Bearer some-token"},
		{"no space after Basic", "Basicadmin:secret"},
		{"invalid base64", "Basic !!!not-base64!!!"},
		{"no colon separator", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BasicAuthPolicy{}
			ctx := newBasicRequestHeaderContext(map[string][]string{
				"authorization": {tt.header},
			})

			action := p.OnRequestHeaders(context.Background(), ctx, defaultParams())

			if ctx.SharedContext.AuthContext == nil {
				t.Fatal("expected AuthContext to be set on failure")
			}
			if ctx.SharedContext.AuthContext.Authenticated {
				t.Error("expected Authenticated=false")
			}

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if resp.StatusCode != 401 {
				t.Errorf("expected status 401, got %d", resp.StatusCode)
			}
		})
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_AllowUnauthenticated(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil) // no authorization header

	params := map[string]interface{}{
		"username":             "admin",
		"password":             "secret",
		"allowUnauthenticated": true,
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	// Should allow through even without credentials
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications (allow through), got %T", action)
	}
	// AuthContext should still reflect the failure
	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=false even when allowUnauthenticated=true")
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_CustomRealm(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	params := map[string]interface{}{
		"username": "admin",
		"password": "secret",
		"realm":    "My API",
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	wwwAuth := resp.Headers["www-authenticate"]
	expected := fmt.Sprintf(`Basic realm="My API"`)
	if wwwAuth != expected {
		t.Errorf("expected WWW-Authenticate=%q, got %q", expected, wwwAuth)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_InvalidConfig_NoUsername(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	params := map[string]interface{}{
		"password": "secret",
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500 for invalid config, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_InvalidConfig_NoPassword(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	params := map[string]interface{}{
		"username": "admin",
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500 for invalid config, got %d", resp.StatusCode)
	}
}

func assertJSONError(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("expected JSON body, got: %s", string(body))
	}
	if result["error"] == "" {
		t.Error("expected non-empty 'error' field in JSON body")
	}
}

// TestBasicAuthPolicy_RejectionErrorCodes pins the fault declaration and the code chosen
func TestBasicAuthPolicy_RejectionErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		params   map[string]interface{}
		wantCode string
	}{
		{
			name:     "no authorization header",
			headers:  nil,
			params:   defaultParams(),
			wantCode: policy.FaultCodeAuthMissingCredentials,
		},
		{
			name:     "not the Basic scheme",
			headers:  map[string][]string{"authorization": {"Bearer abc"}},
			params:   defaultParams(),
			wantCode: policy.FaultCodeAuthMissingCredentials,
		},
		{
			name:     "credentials are not base64",
			headers:  map[string][]string{"authorization": {"Basic !!!not-base64!!!"}},
			params:   defaultParams(),
			wantCode: policy.FaultCodeAuthInvalidCredentials,
		},
		{
			name:     "wrong password",
			headers:  map[string][]string{"authorization": {basicAuthHeader("admin", "wrong")}},
			params:   defaultParams(),
			wantCode: policy.FaultCodeAuthInvalidCredentials,
		},
		{
			name:     "policy misconfigured",
			headers:  map[string][]string{"authorization": {basicAuthHeader("admin", "secret")}},
			params:   map[string]interface{}{"password": "secret"},
			wantCode: policy.FaultCodeAuthGeneral,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BasicAuthPolicy{}
			ctx := newBasicRequestHeaderContext(tt.headers)

			action := p.OnRequestHeaders(context.Background(), ctx, tt.params)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if !resp.IsFault {
				t.Fatalf("expected IsFault=true on a rejection")
			}
			if resp.Fault == nil {
				t.Fatalf("expected Error to be populated on a rejection")
			}
			if resp.Fault.Code != tt.wantCode {
				t.Fatalf("expected Error.Code=%q, got %q", tt.wantCode, resp.Fault.Code)
			}
			if resp.Fault.Type != policy.FaultTypeAuthentication {
				t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthentication, resp.Fault.Type)
			}
			if resp.Fault.Direction != policy.DirectionRequest {
				t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
			}
			if resp.Fault.Description == "" {
				t.Fatalf("expected Error.Description to carry the internal reason")
			}
		})
	}
}

// TestBasicAuthPolicy_AllowUnauthenticatedIsNotAFault covers the deliberate non-rejection:
// with allowUnauthenticated set, a caller with no credentials passes through. There is no
// ImmediateResponse at all, so nothing can be a fault — asserting it keeps a future change
// from turning a permitted anonymous request into a paged failure.
func TestBasicAuthPolicy_AllowUnauthenticatedIsNotAFault(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)
	params := defaultParams()
	params["allowUnauthenticated"] = true

	action := p.OnRequestHeaders(context.Background(), ctx, params)
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatalf("expected the request to pass through, got an ImmediateResponse")
	}
}
