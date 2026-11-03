package interceptorservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mustGetPolicy(t *testing.T, params map[string]interface{}) *InterceptorServicePolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	ip, ok := p.(*InterceptorServicePolicy)
	if !ok {
		t.Fatalf("unexpected type %T", p)
	}
	return ip
}

func reqCtx(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:  "req-id",
			APIName:    "PetStore",
			APIVersion: "v1.0.0",
			APIContext: "/petstore",
			Metadata:   map[string]interface{}{},
		},
		Body:   &policy.Body{Content: []byte(body), Present: body != ""},
		Path:   "/petstore/pets/1",
		Method: "POST",
		Vhost:  "localhost",
		Scheme: "https",
	}
}

func respCtx(body string, status int, shared *policy.SharedContext) *policy.ResponseContext {
	if shared == nil {
		shared = &policy.SharedContext{RequestID: "req-id", Metadata: map[string]interface{}{}}
	}
	return &policy.ResponseContext{
		SharedContext:  shared,
		ResponseBody:   &policy.Body{Content: []byte(body), Present: body != ""},
		ResponseStatus: status,
		RequestPath:    "/petstore/pets/1",
		RequestMethod:  "POST",
	}
}

func TestGetPolicy_RequiredParams(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err == nil ||
		!strings.Contains(err.Error(), "'endpoint' parameter is required") {
		t.Fatalf("expected endpoint required error, got %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"endpoint": "https://x"}); err == nil ||
		!strings.Contains(err.Error(), "at least one of 'request' or 'response'") {
		t.Fatalf("expected anyOf error, got %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "https://x", "timeoutMillis": 50,
		"request": map[string]interface{}{},
	}); err == nil || !strings.Contains(err.Error(), "timeoutMillis") {
		t.Fatalf("expected timeout range error, got %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "://bad", "request": map[string]interface{}{},
	}); err == nil || !strings.Contains(err.Error(), "valid URL") {
		t.Fatalf("expected URL validation error, got %v", err)
	}
}

func TestMode(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://x", "request": map[string]interface{}{},
	})
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("mode mismatch: got %+v want %+v", got, want)
	}

	p2 := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://x", "response": map[string]interface{}{},
	})
	if p2.Mode().ResponseBodyMode != policy.BodyModeBuffer || p2.Mode().RequestBodyMode != policy.BodyModeSkip {
		t.Fatalf("unexpected mode: %+v", p2.Mode())
	}
}

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		handler(w, r)
	}))
}

func writeReply(t *testing.T, w http.ResponseWriter, reply map[string]interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc, _ := json.Marshal(reply)
	_, _ = w.Write(enc)
}

func TestOnRequestBody_Passthrough_EmptyReply(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/handle-request") {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		writeReply(t, w, map[string]interface{}{})
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{"hi":1}`), nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Body != nil || mods.Path != nil || mods.UpstreamName != nil ||
		len(mods.HeadersToSet) != 0 || len(mods.HeadersToRemove) != 0 {
		t.Fatalf("expected empty mods, got %+v", mods)
	}
}

func TestOnRequestBody_HeadersAndBodyMutation(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body handleRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.RequestBody == "" {
			t.Fatalf("expected base64 request body")
		}
		decoded, _ := base64.StdEncoding.DecodeString(body.RequestBody)
		if string(decoded) != `{"hi":1}` {
			t.Fatalf("body roundtrip mismatch: %s", decoded)
		}
		newBody := base64.StdEncoding.EncodeToString([]byte("mutated"))
		writeReply(t, w, map[string]interface{}{
			"headersToAdd":     map[string]string{"X-Add": "a", "X-Both": "fromAdd"},
			"headersToReplace": map[string]string{"X-Repl": "r", "X-Both": "fromRepl"},
			"headersToRemove":  []string{"X-Remove"},
			"body":             newBody,
		})
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{"hi":1}`), nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if string(mods.Body) != "mutated" {
		t.Fatalf("body mismatch: %s", mods.Body)
	}
	if mods.HeadersToSet["X-Add"] != "a" || mods.HeadersToSet["X-Repl"] != "r" {
		t.Fatalf("missing headers: %+v", mods.HeadersToSet)
	}
	if mods.HeadersToSet["X-Both"] != "fromRepl" {
		t.Fatalf("expected replace to win, got %q", mods.HeadersToSet["X-Both"])
	}
	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "X-Remove" {
		t.Fatalf("expected X-Remove, got %v", mods.HeadersToRemove)
	}
}

func TestOnRequestBody_DirectRespond(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		body := base64.StdEncoding.EncodeToString([]byte("denied"))
		writeReply(t, w, map[string]interface{}{
			"directRespond": true,
			"responseCode":  403,
			"headersToAdd":  map[string]string{"X-Reason": "policy"},
			"body":          body,
		})
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("status mismatch: %d", resp.StatusCode)
	}
	if string(resp.Body) != "denied" {
		t.Fatalf("body mismatch: %s", resp.Body)
	}
	if resp.Headers["X-Reason"] != "policy" {
		t.Fatalf("missing header: %+v", resp.Headers)
	}
}

func TestOnRequestBody_PathRewrite_WithQuery(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeReply(t, w, map[string]interface{}{
			"pathToRewrite": "/v2/things?foo=1&bar=2",
		})
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Path == nil || *mods.Path != "/v2/things" {
		t.Fatalf("expected path /v2/things, got %v", mods.Path)
	}
	if got := mods.QueryParametersToAdd["foo"]; len(got) != 1 || got[0] != "1" {
		t.Fatalf("foo query mismatch: %v", got)
	}
	if got := mods.QueryParametersToAdd["bar"]; len(got) != 1 || got[0] != "2" {
		t.Fatalf("bar query mismatch: %v", got)
	}
}

func TestOnRequestBody_DynamicEndpoint(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeReply(t, w, map[string]interface{}{
			"dynamicEndpoint": map[string]interface{}{"endpointName": "my-upstream"},
		})
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL, "request": map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected mods, got %T", action)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "my-upstream" {
		t.Fatalf("upstream mismatch: %v", mods.UpstreamName)
	}
}

func TestOnRequestBody_ErrorPassthroughOrFail(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"err":"boom"}`))
	})
	defer srv.Close()

	pPass := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{"passthroughOnError": true},
	})
	a := pPass.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	if _, ok := a.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected passthrough mods, got %T", a)
	}

	pFail := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{"passthroughOnError": false},
	})
	a2 := pFail.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	resp, ok := a2.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", a2)
	}
	if resp.StatusCode != interceptorErrorStatus {
		t.Fatalf("status mismatch: %d", resp.StatusCode)
	}
}

func TestOnRequestBody_MaxResponseSize(t *testing.T) {
	bigBody := strings.Repeat("x", 2048)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"body":"` + bigBody + `"}`))
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint":        srv.URL,
		"maxResponseSize": 1024,
		"request":         map[string]interface{}{"passthroughOnError": false},
	})
	a := p.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	resp, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", a)
	}
	if resp.StatusCode != interceptorErrorStatus {
		t.Fatalf("status mismatch: %d", resp.StatusCode)
	}
}

func TestOnRequestBody_TimeoutPassthrough(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		writeReply(t, w, map[string]interface{}{})
	})
	defer srv.Close()

	pPass := mustGetPolicy(t, map[string]interface{}{
		"endpoint":      srv.URL,
		"timeoutMillis": 100,
		"request":       map[string]interface{}{"passthroughOnError": true},
	})
	a := pPass.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	if _, ok := a.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected passthrough on timeout, got %T", a)
	}

	pFail := mustGetPolicy(t, map[string]interface{}{
		"endpoint":      srv.URL,
		"timeoutMillis": 100,
		"request":       map[string]interface{}{"passthroughOnError": false},
	})
	a2 := pFail.OnRequestBody(context.Background(), reqCtx(`{}`), nil)
	if _, ok := a2.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse on timeout, got %T", a2)
	}
}

func TestOnResponseBody_StatusAndBodyRewrite(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/handle-response") {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body handleResponseBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.ResponseCode != 201 {
			t.Fatalf("expected upstream status 201, got %d", body.ResponseCode)
		}
		newBody := base64.StdEncoding.EncodeToString([]byte("rewritten"))
		writeReply(t, w, map[string]interface{}{
			"responseCode": 418,
			"body":         newBody,
			"headersToAdd": map[string]string{"X-Note": "ok"},
		})
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"response": map[string]interface{}{},
	})
	action := p.OnResponseBody(context.Background(), respCtx(`{"k":1}`, 201, nil), nil)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if mods.StatusCode == nil || *mods.StatusCode != 418 {
		t.Fatalf("status mismatch: %v", mods.StatusCode)
	}
	if string(mods.Body) != "rewritten" {
		t.Fatalf("body mismatch: %s", mods.Body)
	}
	if mods.HeadersToSet["X-Note"] != "ok" {
		t.Fatalf("header missing: %+v", mods.HeadersToSet)
	}
}

func TestInterceptorContext_RoundTrip(t *testing.T) {
	requestSrv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeReply(t, w, map[string]interface{}{
			"interceptorContext": map[string]string{"trace": "abc-123"},
		})
	})
	defer requestSrv.Close()

	var seenContext map[string]string
	responseSrv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body handleResponseBody
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		seenContext = body.InterceptorContext
		writeReply(t, w, map[string]interface{}{})
	})
	defer responseSrv.Close()

	pReq := mustGetPolicy(t, map[string]interface{}{
		"endpoint": requestSrv.URL,
		"request":  map[string]interface{}{},
	})
	rc := reqCtx(`{}`)
	if _, ok := pReq.OnRequestBody(context.Background(), rc, nil).(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("request phase failed")
	}
	stored, ok := rc.SharedContext.Metadata[sharedContextKey].(map[string]string)
	if !ok || stored["trace"] != "abc-123" {
		t.Fatalf("context not stored: %+v", rc.SharedContext.Metadata)
	}

	pResp := mustGetPolicy(t, map[string]interface{}{
		"endpoint": responseSrv.URL,
		"response": map[string]interface{}{},
	})
	if _, ok := pResp.OnResponseBody(context.Background(), respCtx(`{}`, 200, rc.SharedContext), nil).(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("response phase failed")
	}
	if seenContext["trace"] != "abc-123" {
		t.Fatalf("interceptor did not see context: %+v", seenContext)
	}
}

// TestInterceptorUnavailableDeclaresFault covers the one rejection this policy makes: the
// interceptor could not be reached and passthroughOnError is off, so the gateway refuses.
// Only the deployment can fix an unreachable interceptor, which is what makes notifying
// worthwhile.
func TestInterceptorUnavailableDeclaresFault(t *testing.T) {
	resp := interceptorErrorImmediate(fmt.Errorf("dial tcp: connection refused"), policy.DirectionRequest)

	if !resp.IsFault {
		t.Fatalf("expected IsFault=true when the interceptor cannot be reached")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated")
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
	}
	if resp.Fault.Type != policy.FaultTypeMediation {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeMediation, resp.Fault.Type)
	}
	if resp.Fault.Description == "" {
		t.Fatalf("expected Error.Description to carry the connectivity detail")
	}
	// The gateway's own connectivity detail must not reach the caller.
	if strings.Contains(string(resp.Body), resp.Fault.Description) {
		t.Fatalf("Description leaked into the client body: %q", resp.Fault.Description)
	}
}

// The response-phase rejection declares the same fault, with the response direction.
func TestOnResponseBody_InterceptorFailureDeclaresFault(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"err":"boom"}`))
	})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"response": map[string]interface{}{"passthroughOnError": false},
	})
	action := p.OnResponseBody(context.Background(), respCtx(`{"k":1}`, 200, nil), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != interceptorErrorStatus || string(resp.Body) != interceptorErrorBody {
		t.Fatalf("client response changed: %d %s", resp.StatusCode, resp.Body)
	}
	if resp.Headers["Content-Type"] != contentTypeJSON {
		t.Fatalf("content type changed: %+v", resp.Headers)
	}
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected a declared fault, got IsFault=%v Fault=%v", resp.IsFault, resp.Fault)
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed || resp.Fault.Type != policy.FaultTypeMediation {
		t.Fatalf("fault = %s/%s, want %s/%s", resp.Fault.Code, resp.Fault.Type,
			policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	}
	if resp.Fault.Direction != policy.DirectionResponse {
		t.Fatalf("direction = %q, want %q", resp.Fault.Direction, policy.DirectionResponse)
	}
	if resp.Fault.Description == "" || strings.Contains(string(resp.Body), resp.Fault.Description) {
		t.Fatalf("Description missing or leaked into the client body: %q", resp.Fault.Description)
	}
}

// This policy carries the external interceptor's own status, headers and body; it describes
// nothing of its own, because it did not decide anything.
//
// So it does not declare either. The interceptor is acting as a backend, and its 404 is its
// contract rather than this policy's failure — this policy has no basis for calling it one.
// An operator who does want an interceptor's 5xx reported has the backend-error path for it,
// which reaches the fault chain on its own status without this policy asserting anything.
//
// What this policy must still not do is DESCRIBE the failure. It has no account of it —
// inventing a code for someone else's 503 would misreport it.
func TestAppliedInterceptorReplyIsNotDescribed(t *testing.T) {
	for _, status := range []int{200, 403, 503} {
		t.Run(fmt.Sprintf("interceptor returned %d", status), func(t *testing.T) {
			resp := buildImmediateResponse(&interceptorReply{ResponseCode: status})
			if resp.StatusCode != status {
				t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
			}
			if resp.IsFault {
				t.Fatalf("applying the interceptor's own %d must not be a fault", status)
			}
			if resp.Fault != nil {
				t.Fatalf("applying the interceptor's own %d must not describe an error", status)
			}
		})
	}
}
