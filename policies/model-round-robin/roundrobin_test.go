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
	p.suspendedModels[suspensionKey("", "gpt-4")] = until
	p.suspendedModels[suspensionKey("", "gpt-35")] = until

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
	until, exists := p.suspendedModels[suspensionKey("", "gpt-4")]
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
		suspendedModels: map[string]time.Time{suspensionKey("", "a"): time.Now().Add(5 * time.Minute)},
	}
	models := []ModelConfig{{Model: "a"}, {Model: "b"}}

	got := p.selectNextAvailableModel(models)
	if got == nil || got.Model != "b" {
		t.Fatalf("expected to skip suspended a and pick b, got %+v", got)
	}

	p.suspendedModels[suspensionKey("", "a")] = time.Now().Add(-1 * time.Minute)
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

func TestModelRoundRobinPolicy_GetPolicy_ProviderParsing(t *testing.T) {
	// provider must be a string when present
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "gpt-4", "provider": 123},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})
	if err == nil || !strings.Contains(err.Error(), "'models[0].provider' must be a string") {
		t.Fatalf("expected provider type error, got %v", err)
	}

	// omitted provider defaults to empty; explicit provider is preserved
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "gpt-4o"},
			map[string]interface{}{"model": "claude-sonnet-4-5-20250929", "provider": "anthropic-provider"},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})
	if p.params.Models[0].Provider != "" {
		t.Fatalf("expected empty provider for first model, got %q", p.params.Models[0].Provider)
	}
	if p.params.Models[1].Provider != "anthropic-provider" {
		t.Fatalf("expected anthropic-provider for second model, got %q", p.params.Models[1].Provider)
	}
}

func TestModelRoundRobinPolicy_OnRequestHeaders_DefaultProvider(t *testing.T) {
	// A target with no provider must not set UpstreamName or the selected_provider
	// routing key, so the LlmProxy primary-provider fallback keeps working.
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":       []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	shared := rrSharedContext()
	ctx := &policy.RequestHeaderContext{SharedContext: shared}
	mods := mustRRRequestHeaderMods(t, p.OnRequestHeaders(context.Background(), ctx, nil))

	if mods.UpstreamName != nil {
		t.Fatalf("expected no UpstreamName for default provider, got %q", *mods.UpstreamName)
	}
	if _, ok := shared.Metadata[MetadataKeyProviderRouting]; ok {
		t.Fatalf("expected selected_provider metadata to be unset for default provider")
	}
	if shared.Metadata[MetadataKeySelectedModel] != "gpt-4o" {
		t.Fatalf("expected selected model metadata gpt-4o, got %v", shared.Metadata[MetadataKeySelectedModel])
	}
}

func TestModelRoundRobinPolicy_OnRequestHeaders_AdditionalProvider(t *testing.T) {
	// A target with a provider must route to its named upstream and expose the
	// provider to conditional auth/transformers via selected_provider.
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "claude-sonnet-4-5-20250929", "provider": "anthropic-provider"},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	shared := rrSharedContext()
	ctx := &policy.RequestHeaderContext{SharedContext: shared}
	mods := mustRRRequestHeaderMods(t, p.OnRequestHeaders(context.Background(), ctx, nil))

	if mods.UpstreamName == nil || *mods.UpstreamName != "anthropic-provider" {
		t.Fatalf("expected UpstreamName anthropic-provider, got %v", mods.UpstreamName)
	}
	if shared.Metadata[MetadataKeyProviderRouting] != "anthropic-provider" {
		t.Fatalf("expected selected_provider metadata anthropic-provider, got %v", shared.Metadata[MetadataKeyProviderRouting])
	}
}

func TestModelRoundRobinPolicy_IndependentSuspensionPerProvider(t *testing.T) {
	// The same model name behind two providers must be suspended independently.
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "shared-model", "provider": "provider-a"},
			map[string]interface{}{"model": "shared-model", "provider": "provider-b"},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	// Suspend only provider-a/shared-model.
	p.suspendedModels[suspensionKey("provider-a", "shared-model")] = time.Now().Add(10 * time.Minute)

	got := p.selectNextAvailableModel(p.params.Models)
	if got == nil || got.Provider != "provider-b" {
		t.Fatalf("expected provider-b to remain available, got %+v", got)
	}
	if _, suspended := p.suspendedModels[suspensionKey("provider-b", "shared-model")]; suspended {
		t.Fatalf("provider-b/shared-model should not be suspended")
	}
}

func TestModelRoundRobinPolicy_OnResponseHeaders_SuspendsProviderModelPair(t *testing.T) {
	// OnResponseHeaders must build the composite key from the selected provider
	// metadata, suspending only that provider/model pair.
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "shared-model", "provider": "provider-a"},
			map[string]interface{}{"model": "shared-model", "provider": "provider-b"},
		},
		"suspendDuration": 60,
		"requestModel":    map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "id",
			Metadata: map[string]interface{}{
				MetadataKeySelectedModel:    "shared-model",
				MetadataKeySelectedProvider: "provider-a",
			},
		},
		ResponseStatus: 429,
	}
	p.OnResponseHeaders(context.Background(), ctx, nil)

	if _, ok := p.suspendedModels[suspensionKey("provider-a", "shared-model")]; !ok {
		t.Fatalf("expected provider-a/shared-model to be suspended")
	}
	if _, ok := p.suspendedModels[suspensionKey("provider-b", "shared-model")]; ok {
		t.Fatalf("expected provider-b/shared-model to remain available")
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

// TestModelRoundRobin_RejectionsDeclareFault covers the conditions this policy refuses on, and pins
// which code each takes.
func TestModelRoundRobin_RejectionsDeclareFault(t *testing.T) {
	assertFault := func(t *testing.T, action interface{}, wantStatus int, wantBody, wantCode, wantType string) {
		t.Helper()
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse, got %T", action)
		}
		// The client response is unchanged by the fault declaration.
		if resp.StatusCode != wantStatus {
			t.Fatalf("expected status %d, got %d", wantStatus, resp.StatusCode)
		}
		if resp.Headers["Content-Type"] != "application/json" {
			t.Fatalf("unexpected headers: %v", resp.Headers)
		}
		if string(resp.Body) != wantBody {
			t.Fatalf("expected body %s, got %s", wantBody, resp.Body)
		}
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a rejection")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated on a rejection")
		}
		if resp.Fault.Code != wantCode {
			t.Fatalf("expected Error.Code=%q, got %q", wantCode, resp.Fault.Code)
		}
		if resp.Fault.Type != wantType {
			t.Fatalf("expected Error.Type=%q, got %q", wantType, resp.Fault.Type)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
	}

	t.Run("empty request body", func(t *testing.T) {
		p := &ModelRoundRobinPolicy{}
		p.params.RequestModel.Location = "payload"
		p.params.RequestModel.Identifier = "$.model"
		reqCtx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{MetadataKeySelectedModel: "gpt-4"},
			},
			Body: nil,
		}
		assertFault(t, p.OnRequestBody(context.Background(), reqCtx, nil), 400,
			`{"error":"Request body is empty."}`, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})

	t.Run("request body is not JSON", func(t *testing.T) {
		p := &ModelRoundRobinPolicy{}
		p.params.RequestModel.Location = "payload"
		p.params.RequestModel.Identifier = "$.model"
		reqCtx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{MetadataKeySelectedModel: "gpt-4"},
			},
			Body: &policy.Body{Content: []byte("{not json"), Present: true},
		}
		var v map[string]interface{}
		parseErr := json.Unmarshal([]byte("{not json"), &v)
		if parseErr == nil {
			t.Fatalf("expected the test body to be invalid JSON")
		}
		assertFault(t, p.OnRequestBody(context.Background(), reqCtx, nil), 400,
			`{"error":"Invalid JSON in request body: `+parseErr.Error()+`"}`, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})

	t.Run("model path is not in the request body", func(t *testing.T) {
		p := &ModelRoundRobinPolicy{}
		p.params.RequestModel.Location = "payload"
		p.params.RequestModel.Identifier = "$.nested.model"
		reqCtx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{MetadataKeySelectedModel: "gpt-4"},
			},
			Body: &policy.Body{Content: []byte(`{"model":"test"}`), Present: true},
		}
		assertFault(t, p.OnRequestBody(context.Background(), reqCtx, nil), 400,
			`{"error":"Invalid or missing model at '$.nested.model': key not found: nested"}`, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})

	t.Run("all models suspended", func(t *testing.T) {
		p := mustGetRRPolicy(t, map[string]interface{}{
			"models": baseRRModels(),
			"requestModel": map[string]interface{}{
				"location":   "header",
				"identifier": "x-model",
			},
		})
		until := time.Now().Add(10 * time.Minute)
		p.suspendedModels[suspensionKey("", "gpt-4")] = until
		p.suspendedModels[suspensionKey("", "gpt-35")] = until
		ctx := &policy.RequestHeaderContext{
			SharedContext: rrSharedContext(),
			Headers:       policy.NewHeaders(map[string][]string{"x-model": {"orig"}}),
		}
		assertFault(t, p.OnRequestHeaders(context.Background(), ctx, nil), 503,
			`{"error": "All models are currently unavailable"}`, policy.FaultCodeNoModelAvailable, policy.FaultTypeMediation)
	})
}
