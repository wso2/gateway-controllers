package modelroundrobin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestModelRoundRobinPolicy_Mode(t *testing.T) {
	p := &ModelRoundRobinPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestModelRoundRobinPolicy_GetPolicy_ParseErrors(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "missing models",
			params:         map[string]interface{}{},
			wantErrContain: "'models' parameter is required",
		},
		{
			name: "models wrong type",
			params: map[string]interface{}{
				"models": "not-array",
			},
			wantErrContain: "'models' must be an array",
		},
		{
			name: "models empty",
			params: map[string]interface{}{
				"models": []interface{}{},
			},
			wantErrContain: "'models' array must contain at least one model",
		},
		{
			name: "model item not object",
			params: map[string]interface{}{
				"models": []interface{}{"a"},
			},
			wantErrContain: "'models[0]' must be an object",
		},
		{
			name: "model missing name",
			params: map[string]interface{}{
				"models": []interface{}{map[string]interface{}{}},
			},
			wantErrContain: "'models[0].model' is required",
		},
		{
			name: "model name wrong type",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": 1},
				},
			},
			wantErrContain: "'models[0].model' must be a string",
		},
		{
			name: "model name empty",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": ""},
				},
			},
			wantErrContain: "'models[0].model' must have a minimum length of 1",
		},
		{
			name: "suspendDuration invalid",
			params: map[string]interface{}{
				"models":          baseRRModels(),
				"suspendDuration": "30",
			},
			wantErrContain: "'suspendDuration' must be an integer",
		},
		{
			name: "suspendDuration negative",
			params: map[string]interface{}{
				"models":          baseRRModels(),
				"suspendDuration": -1,
			},
			wantErrContain: "'suspendDuration' must be >= 0",
		},
		{
			name: "requestModel missing",
			params: map[string]interface{}{
				"models": baseRRModels(),
			},
			wantErrContain: "'requestModel' configuration is required",
		},
		{
			name: "requestModel wrong type",
			params: map[string]interface{}{
				"models":       baseRRModels(),
				"requestModel": "x",
			},
			wantErrContain: "'requestModel' must be an object",
		},
		{
			name: "requestModel location missing",
			params: map[string]interface{}{
				"models":       baseRRModels(),
				"requestModel": map[string]interface{}{"identifier": "$.model"},
			},
			wantErrContain: "'requestModel.location' is required",
		},
		{
			name: "requestModel location invalid",
			params: map[string]interface{}{
				"models": baseRRModels(),
				"requestModel": map[string]interface{}{
					"location":   "cookie",
					"identifier": "$.model",
				},
			},
			wantErrContain: "'requestModel.location' must be one of: payload, header, queryParam, pathParam",
		},
		{
			name: "requestModel identifier missing",
			params: map[string]interface{}{
				"models": baseRRModels(),
				"requestModel": map[string]interface{}{
					"location": "payload",
				},
			},
			wantErrContain: "'requestModel.identifier' is required",
		},
		{
			name: "requestModel identifier wrong type",
			params: map[string]interface{}{
				"models": baseRRModels(),
				"requestModel": map[string]interface{}{
					"location":   "payload",
					"identifier": 1,
				},
			},
			wantErrContain: "'requestModel.identifier' must be a string",
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

func TestModelRoundRobinPolicy_GetPolicy_SuccessAndDefaults(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	if len(p.params.Models) != 2 {
		t.Fatalf("expected two models, got %d", len(p.params.Models))
	}
	if p.params.SuspendDuration != DefaultSuspendDuration {
		t.Fatalf("expected default suspendDuration=%d, got %d", DefaultSuspendDuration, p.params.SuspendDuration)
	}
}

func TestModelRoundRobinPolicy_OnRequestBody_PayloadRoundRobin(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	// Phase 1: headers — selects model and stores in metadata
	shared1 := rrSharedContext()
	headerCtx1 := &policy.RequestHeaderContext{SharedContext: shared1}
	p.OnRequestHeaders(context.Background(), headerCtx1, nil)

	// Phase 2: body — substitutes selected model into payload
	bodyCtx1 := &policy.RequestContext{
		SharedContext: shared1,
		Body:          &policy.Body{Content: []byte(`{"model":"original","x":"y"}`), Present: true},
	}
	action1 := p.OnRequestBody(context.Background(), bodyCtx1, nil)
	mods1 := mustRRRequestMods(t, action1)
	got1 := decodeJSONMapRR(t, mods1.Body)
	if got1["model"] != "gpt-4" {
		t.Fatalf("expected first selected model gpt-4, got %v", got1["model"])
	}
	if shared1.Metadata[MetadataKeySelectedModel] != "gpt-4" {
		t.Fatalf("expected selected model metadata to be set")
	}

	shared2 := rrSharedContext()
	headerCtx2 := &policy.RequestHeaderContext{SharedContext: shared2}
	p.OnRequestHeaders(context.Background(), headerCtx2, nil)

	bodyCtx2 := &policy.RequestContext{
		SharedContext: shared2,
		Body:          &policy.Body{Content: []byte(`{"model":"original2"}`), Present: true},
	}
	action2 := p.OnRequestBody(context.Background(), bodyCtx2, nil)
	mods2 := mustRRRequestMods(t, action2)
	got2 := decodeJSONMapRR(t, mods2.Body)
	if got2["model"] != "gpt-35" {
		t.Fatalf("expected second selected model gpt-35, got %v", got2["model"])
	}
}

func TestModelRoundRobinPolicy_OnRequestHeaders_QueryParamAndPathParamMutation(t *testing.T) {
	pQuery := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "queryParam",
			"identifier": "model",
		},
	})
	queryCtx := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Path:          "/v1/chat?model=old&x=1",
	}
	queryAction := pQuery.OnRequestHeaders(context.Background(), queryCtx, nil)
	queryMods := mustRRRequestHeaderMods(t, queryAction)
	if queryMods.Path == nil || !strings.Contains(*queryMods.Path, "model=gpt-4") {
		t.Fatalf("expected query path to include new model, got %v", queryMods.Path)
	}

	pPath := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "pathParam",
			"identifier": `/models/([^/]+)`,
		},
	})
	pathCtx := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Path:          "/v1/models/old/completions?x=1",
	}
	pathAction := pPath.OnRequestHeaders(context.Background(), pathCtx, nil)
	pathMods := mustRRRequestHeaderMods(t, pathAction)
	if pathMods.Path == nil || !strings.Contains(*pathMods.Path, "/models/gpt-4/") {
		t.Fatalf("expected path to include new model, got %v", pathMods.Path)
	}
}

func TestModelRoundRobinPolicy_OnRequestHeaders_AllModelsSuspended(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	until := time.Now().Add(10 * time.Minute)
	p.suspendedModels["gpt-4"] = until
	p.suspendedModels["gpt-35"] = until

	ctx := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-model": {"orig"}}),
	}
	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when all models suspended, got %T", action)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("unexpected status code: got %d, want 503", resp.StatusCode)
	}
}

func TestModelRoundRobinPolicy_OnResponseHeaders_SuspendsModelOnError(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"suspendDuration": 60,
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	sharedCtx := &policy.SharedContext{
		RequestID: "test-id",
		Metadata: map[string]interface{}{
			MetadataKeySelectedModel: "gpt-4",
		},
	}
	ctx := &policy.ResponseHeaderContext{
		SharedContext:  sharedCtx,
		ResponseStatus: 500,
	}

	action := p.OnResponseHeaders(context.Background(), ctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	until, exists := p.suspendedModels["gpt-4"]
	if !exists {
		t.Fatalf("expected model to be suspended")
	}
	if !until.After(time.Now()) {
		t.Fatalf("expected suspension expiry in future")
	}
}

func TestModelRoundRobinPolicy_SelectNextAvailableModel_SkipsAndRecoversSuspended(t *testing.T) {
	p := &ModelRoundRobinPolicy{
		currentIndex:    0,
		suspendedModels: map[string]time.Time{"a": time.Now().Add(5 * time.Minute)},
	}
	models := []ModelConfig{{Model: "a"}, {Model: "b"}}

	got := p.selectNextAvailableModel(models)
	if got == nil || got.Model != "b" {
		t.Fatalf("expected to skip suspended a and pick b, got %+v", got)
	}

	p.suspendedModels["a"] = time.Now().Add(-1 * time.Minute)
	got2 := p.selectNextAvailableModel(models)
	if got2 == nil || got2.Model != "a" {
		t.Fatalf("expected expired suspension model a to be selected, got %+v", got2)
	}
}

func TestModelRoundRobinPolicy_ExtractInt(t *testing.T) {
	if v, err := extractInt(3); err != nil || v != 3 {
		t.Fatalf("expected int extraction to work, got v=%d err=%v", v, err)
	}
	if v, err := extractInt(float64(4)); err != nil || v != 4 {
		t.Fatalf("expected float integer extraction to work, got v=%d err=%v", v, err)
	}
	if _, err := extractInt(float64(4.2)); err == nil {
		t.Fatalf("expected error for non-integer float")
	}
}

func mustGetRRPolicy(t *testing.T, params map[string]interface{}) *ModelRoundRobinPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	rp, ok := p.(*ModelRoundRobinPolicy)
	if !ok {
		t.Fatalf("expected *ModelRoundRobinPolicy, got %T", p)
	}
	return rp
}

func mustRRRequestHeaderMods(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	return mods
}

func mustRRRequestMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func decodeJSONMapRR(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("failed to unmarshal json body: %v", err)
	}
	return m
}

func rrSharedContext() *policy.SharedContext {
	return &policy.SharedContext{
		RequestID: "req-id",
		Metadata:  map[string]interface{}{},
	}
}

func baseRRModels() []interface{} {
	return []interface{}{
		map[string]interface{}{"model": "gpt-4"},
		map[string]interface{}{"model": "gpt-35"},
	}
}

func TestModelRoundRobinPolicy_StickyKey_ParseValidation(t *testing.T) {
	// 1. Invalid stickyKey type
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       "not-an-object",
	})
	if err == nil || !strings.Contains(err.Error(), "'stickyKey' must be an object") {
		t.Fatalf("expected 'stickyKey must be an object' error, got %v", err)
	}

	// 2. Missing location
	_, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'stickyKey.location' is required") {
		t.Fatalf("expected 'stickyKey.location is required' error, got %v", err)
	}

	// 3. Invalid location value
	_, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "invalid-loc"},
	})
	if err == nil || !strings.Contains(err.Error(), "'stickyKey.location' must be one of") {
		t.Fatalf("expected 'location must be one of' error, got %v", err)
	}

	// 4. Missing identifier when location is header
	_, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header"},
	})
	if err == nil || !strings.Contains(err.Error(), "'stickyKey.identifier' is required when location is 'header'") {
		t.Fatalf("expected 'identifier is required' error, got %v", err)
	}

	// 5. Success with location 'ip' without identifier
	_, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "ip"},
	})
	if err != nil {
		t.Fatalf("unexpected error parsing valid stickyKey: %v", err)
	}
}

func TestModelRoundRobinPolicy_StickyKey_HeaderRouting(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header", "identifier": "x-session-id"},
	})

	// Use same session ID multiple times -> must always route to same model
	sessionID := "user-session-abc"
	ctx1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-session-id": {sessionID}}),
	}
	action1 := p.OnRequestHeaders(context.Background(), ctx1, nil)
	mods1 := mustRRRequestHeaderMods(t, action1)
	selectedModel1 := mods1.HeadersToSet["x-model"]

	for i := 0; i < 5; i++ {
		ctx2 := &policy.RequestHeaderContext{
			SharedContext: rrSharedContext(),
			Headers:       policy.NewHeaders(map[string][]string{"x-session-id": {sessionID}}),
		}
		action2 := p.OnRequestHeaders(context.Background(), ctx2, nil)
		mods2 := mustRRRequestHeaderMods(t, action2)
		selectedModel2 := mods2.HeadersToSet["x-model"]
		if selectedModel1 != selectedModel2 {
			t.Fatalf("expected same model %s, but got %s on call %d", selectedModel1, selectedModel2, i)
		}
	}
}

func TestModelRoundRobinPolicy_StickyKey_FallbackTiers(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header", "identifier": "x-session-id", "fallbackToAuth": true, "fallbackToIP": true},
	})

	// 1. Missing custom session-id but has Authorization token -> should be sticky on Authorization token
	authToken := "Bearer 12345"
	ctx1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"authorization": {authToken}}),
	}
	action1 := p.OnRequestHeaders(context.Background(), ctx1, nil)
	mods1 := mustRRRequestHeaderMods(t, action1)
	selectedModel1 := mods1.HeadersToSet["x-model"]

	ctx2 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"authorization": {authToken}}),
	}
	action2 := p.OnRequestHeaders(context.Background(), ctx2, nil)
	mods2 := mustRRRequestHeaderMods(t, action2)
	selectedModel2 := mods2.HeadersToSet["x-model"]

	if selectedModel1 != selectedModel2 {
		t.Fatalf("expected sticky routing on fallback authorization header: %s vs %s", selectedModel1, selectedModel2)
	}

	// 2. Missing custom session-id & Authorization header but has Client IP -> should be sticky on IP
	clientIP := "203.0.113.195"
	ctxIP1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-forwarded-for": {clientIP}}),
	}
	actionIP1 := p.OnRequestHeaders(context.Background(), ctxIP1, nil)
	modsIP1 := mustRRRequestHeaderMods(t, actionIP1)
	selectedModelIP1 := modsIP1.HeadersToSet["x-model"]

	ctxIP2 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-forwarded-for": {clientIP}}),
	}
	actionIP2 := p.OnRequestHeaders(context.Background(), ctxIP2, nil)
	modsIP2 := mustRRRequestHeaderMods(t, actionIP2)
	selectedModelIP2 := modsIP2.HeadersToSet["x-model"]

	if selectedModelIP1 != selectedModelIP2 {
		t.Fatalf("expected sticky routing on fallback IP address: %s vs %s", selectedModelIP1, selectedModelIP2)
	}

	// 3. Missing everything -> should fall back to sequential round-robin and generate a gateway session ID
	ctxRR1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{}),
	}
	actionRR1 := p.OnRequestHeaders(context.Background(), ctxRR1, nil)
	modsRR1 := mustRRRequestHeaderMods(t, actionRR1)
	selectedModelRR1 := modsRR1.HeadersToSet["x-model"]

	// Verify a gateway session ID was generated
	if genID, ok := ctxRR1.Metadata[MetadataKeyGeneratedSessionID]; !ok || genID == "" {
		t.Fatalf("expected a gateway-generated session ID in metadata when no session key is present")
	}

	ctxRR2 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{}),
	}
	actionRR2 := p.OnRequestHeaders(context.Background(), ctxRR2, nil)
	modsRR2 := mustRRRequestHeaderMods(t, actionRR2)
	selectedModelRR2 := modsRR2.HeadersToSet["x-model"]

	if selectedModelRR1 == selectedModelRR2 {
		t.Fatalf("expected fallback round-robin sequential distribution, but got same model: %s", selectedModelRR1)
	}
}

func TestModelRoundRobinPolicy_StickyKey_RehashingFailover(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(), // "gpt-4" and "gpt-35"
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header", "identifier": "x-session-id"},
	})

	sessionID := "user-session-failover"
	
	// Determine which model is selected for this session ID
	ctx1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-session-id": {sessionID}}),
	}
	action1 := p.OnRequestHeaders(context.Background(), ctx1, nil)
	mods1 := mustRRRequestHeaderMods(t, action1)
	firstModel := mods1.HeadersToSet["x-model"]

	// Now suspend the selected model
	p.suspendedModels[firstModel] = time.Now().Add(5 * time.Minute)

	// Make the request again -> it must failover and select the other model
	ctx2 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-session-id": {sessionID}}),
	}
	action2 := p.OnRequestHeaders(context.Background(), ctx2, nil)
	mods2 := mustRRRequestHeaderMods(t, action2)
	failoverModel := mods2.HeadersToSet["x-model"]

	if failoverModel == firstModel {
		t.Fatalf("expected failover to a different model, but got the suspended model %s", firstModel)
	}
	if failoverModel == "" {
		t.Fatalf("expected to route to healthy model, got empty")
	}
}

func TestModelRoundRobinPolicy_StickyKey_PayloadRouting(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "payload", "identifier": "$.model"},
		"stickyKey":       map[string]interface{}{"location": "payload", "identifier": "$.session_id"},
	})

	// First request header phase (should not select the model yet)
	shared1 := rrSharedContext()
	headerCtx1 := &policy.RequestHeaderContext{SharedContext: shared1}
	p.OnRequestHeaders(context.Background(), headerCtx1, nil)

	if shared1.Metadata[MetadataKeySelectedModel] != nil {
		t.Fatalf("expected model selection to be deferred during OnRequestHeaders")
	}

	// First request body phase -> extracts key from body, hashes, selects model, writes to body
	bodyCtx1 := &policy.RequestContext{
		SharedContext: shared1,
		Body:          &policy.Body{Content: []byte(`{"session_id":"sess-123","model":"original"}`), Present: true},
	}
	action1 := p.OnRequestBody(context.Background(), bodyCtx1, nil)
	mods1 := mustRRRequestMods(t, action1)
	got1 := decodeJSONMapRR(t, mods1.Body)
	selectedModel1 := got1["model"].(string)

	// Repeat with same session ID -> must map to the same model
	for i := 0; i < 3; i++ {
		sharedLoop := rrSharedContext()
		headerCtxLoop := &policy.RequestHeaderContext{SharedContext: sharedLoop}
		p.OnRequestHeaders(context.Background(), headerCtxLoop, nil)

		bodyCtxLoop := &policy.RequestContext{
			SharedContext: sharedLoop,
			Body:          &policy.Body{Content: []byte(`{"session_id":"sess-123","model":"original"}`), Present: true},
		}
		actionLoop := p.OnRequestBody(context.Background(), bodyCtxLoop, nil)
		modsLoop := mustRRRequestMods(t, actionLoop)
		gotLoop := decodeJSONMapRR(t, modsLoop.Body)
		selectedModelLoop := gotLoop["model"].(string)

		if selectedModel1 != selectedModelLoop {
			t.Fatalf("expected same model %s, but got %s for payload-based session on call %d", selectedModel1, selectedModelLoop, i)
		}
	}
}

func TestModelRoundRobinPolicy_GatewayGeneratedSessionID_RoundTrip(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header", "identifier": "x-session-id"},
	})

	// Step 1: Send request without session ID -> should get a generated ID
	ctx1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{}),
	}
	action1 := p.OnRequestHeaders(context.Background(), ctx1, nil)
	mods1 := mustRRRequestHeaderMods(t, action1)
	selectedModel1 := mods1.HeadersToSet["x-model"]

	generatedID, ok := ctx1.Metadata[MetadataKeyGeneratedSessionID].(string)
	if !ok || generatedID == "" {
		t.Fatalf("expected a gateway-generated session ID, got none")
	}

	// Verify the generated ID has the correct format (_M<index>)
	if _, isGW := isGatewayGeneratedID(generatedID); !isGW {
		t.Fatalf("generated ID %q does not match gateway format", generatedID)
	}

	// Step 2: Send the generated session ID back -> should route to the same model
	for i := 0; i < 5; i++ {
		ctx2 := &policy.RequestHeaderContext{
			SharedContext: rrSharedContext(),
			Headers:       policy.NewHeaders(map[string][]string{"x-session-id": {generatedID}}),
		}
		action2 := p.OnRequestHeaders(context.Background(), ctx2, nil)
		mods2 := mustRRRequestHeaderMods(t, action2)
		selectedModel2 := mods2.HeadersToSet["x-model"]

		if selectedModel1 != selectedModel2 {
			t.Fatalf("expected gateway-generated ID to route to %s, but got %s on call %d", selectedModel1, selectedModel2, i)
		}

		// Verify no new session ID is generated when the client sends one
		if _, hasNewID := ctx2.Metadata[MetadataKeyGeneratedSessionID]; hasNewID {
			t.Fatalf("should not generate a new session ID when client sends a gateway-generated one")
		}
	}
}

func TestModelRoundRobinPolicy_GatewayGeneratedSessionID_ResponseHeader(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header", "identifier": "x-session-id"},
	})

	// Send request without session ID
	shared := rrSharedContext()
	ctx1 := &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(map[string][]string{}),
	}
	p.OnRequestHeaders(context.Background(), ctx1, nil)

	generatedID, ok := shared.Metadata[MetadataKeyGeneratedSessionID].(string)
	if !ok || generatedID == "" {
		t.Fatalf("expected a generated session ID in metadata")
	}

	// Simulate OnResponseHeaders -> should return the generated ID in response header
	respCtx := &policy.ResponseHeaderContext{
		SharedContext:  shared,
		ResponseStatus: 200,
	}
	respAction := p.OnResponseHeaders(context.Background(), respCtx, nil)
	respMods, ok := respAction.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", respAction)
	}
	if respMods.HeadersToSet == nil {
		t.Fatalf("expected response headers to be set with generated session ID")
	}
	if respMods.HeadersToSet["x-session-id"] != generatedID {
		t.Fatalf("expected response header x-session-id=%s, got %s", generatedID, respMods.HeadersToSet["x-session-id"])
	}
}

func TestModelRoundRobinPolicy_FallbacksDisabledByDefault(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"requestModel":    map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":       map[string]interface{}{"location": "header", "identifier": "x-session-id"},
	})

	// Send request with Authorization header but no session ID
	// With fallbacks disabled, the auth header should NOT be used for stickiness
	ctx1 := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"authorization": {"Bearer token123"}}),
	}
	p.OnRequestHeaders(context.Background(), ctx1, nil)

	// Should have generated a gateway session ID (fell back to round-robin)
	if _, ok := ctx1.Metadata[MetadataKeyGeneratedSessionID]; !ok {
		t.Fatalf("expected gateway-generated session ID when fallbacks are disabled and no session key is sent")
	}
}

func TestIsGatewayGeneratedID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		wantIndex int
		wantOK    bool
	}{
		// Genuine gateway IDs: 16 hex characters, "_M", then a non-negative index.
		{"valid index 0", "0123456789abcdef_M0", 0, true},
		{"valid index 1", "a1b2c3d4e5f67890_M1", 1, true},
		{"valid multi-digit index", "0123456789abcdef_M12", 12, true},

		// User-supplied keys that must NOT be mistaken for gateway IDs.
		{"short prefix", "abc123_M0", 0, false},
		{"human session key", "alice_M1", 0, false},
		{"non-hex prefix", "zzzzzzzzzzzzzzzz_M1", 0, false},
		{"prefix too long", "0123456789abcdef00_M1", 0, false},
		{"negative index", "0123456789abcdef_M-1", 0, false},

		{"no suffix", "user-session-abc", 0, false},
		{"no prefix before _M", "_M1", 0, false},
		{"non-numeric after _M", "0123456789abcdef_Mxyz", 0, false},
		{"empty", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, ok := isGatewayGeneratedID(tt.sessionID)
			if ok != tt.wantOK || idx != tt.wantIndex {
				t.Errorf("isGatewayGeneratedID(%q) = (%d, %v), want (%d, %v)",
					tt.sessionID, idx, ok, tt.wantIndex, tt.wantOK)
			}
		})
	}
}

// Generated IDs must always be recognised by the matching parser.
func TestGatewaySessionID_GenerateParseRoundTrip(t *testing.T) {
	for wantIndex := 0; wantIndex < 5; wantIndex++ {
		id := generateGatewaySessionID(wantIndex)
		gotIndex, ok := isGatewayGeneratedID(id)
		if !ok {
			t.Fatalf("generateGatewaySessionID(%d) produced %q, which isGatewayGeneratedID rejected",
				wantIndex, id)
		}
		if gotIndex != wantIndex {
			t.Fatalf("round trip for %q: got index %d, want %d", id, gotIndex, wantIndex)
		}
	}
}

// A user-supplied session key that merely resembles the gateway format must be routed by
// consistent hashing, not by the index embedded in the key.
func TestStickyKey_UserKeyResemblingGatewayIDIsHashed(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":       baseRRModels(),
		"requestModel": map[string]interface{}{"location": "header", "identifier": "x-model"},
		"stickyKey":    map[string]interface{}{"location": "header", "identifier": "x-session"},
	})

	if _, ok := isGatewayGeneratedID("alice_M1"); ok {
		t.Fatalf("'alice_M1' must not be treated as a gateway-generated ID")
	}

	// Consistent hashing must still be stable across repeated requests.
	var first string
	for i := 0; i < 4; i++ {
		shared := rrSharedContext()
		headers := policy.NewHeaders(map[string][]string{"x-session": {"alice_M1"}})
		p.OnRequestHeaders(context.Background(),
			&policy.RequestHeaderContext{SharedContext: shared, Headers: headers}, nil)

		selected, _ := shared.Metadata[MetadataKeySelectedModel].(string)
		if selected == "" {
			t.Fatalf("call %d: expected a model to be selected", i)
		}
		if i == 0 {
			first = selected
		} else if selected != first {
			t.Fatalf("call %d: sticky routing changed from %s to %s", i, first, selected)
		}
	}
}

// A payload sticky key requires a payload requestModel location. Any other combination
// would leave the request unrouted, so it must be rejected at configuration time.
func TestStickyKey_PayloadRequiresPayloadRequestModel(t *testing.T) {
	for _, loc := range []string{"header", "queryParam", "pathParam"} {
		t.Run(loc, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
				"models":       baseRRModels(),
				"requestModel": map[string]interface{}{"location": loc, "identifier": "x-model"},
				"stickyKey":    map[string]interface{}{"location": "payload", "identifier": "$.session_id"},
			})
			if err == nil {
				t.Fatalf("expected an error for stickyKey.location=payload with requestModel.location=%s", loc)
			}
			if !strings.Contains(err.Error(), "requires 'requestModel.location' to be 'payload'") {
				t.Fatalf("unexpected error message: %v", err)
			}
		})
	}

	// The supported combination must still be accepted.
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models":       baseRRModels(),
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
		"stickyKey":    map[string]interface{}{"location": "payload", "identifier": "$.session_id"},
	}); err != nil {
		t.Fatalf("payload/payload combination must remain valid, got: %v", err)
	}
}
