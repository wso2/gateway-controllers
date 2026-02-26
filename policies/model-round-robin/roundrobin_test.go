package modelroundrobin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestModelRoundRobinPolicy_Mode(t *testing.T) {
	p := &ModelRoundRobinPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeBuffer,
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
		"models":          baseRRModels(),
		"suspendDuration": float64(30),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	if len(p.params.Models) != 2 {
		t.Fatalf("expected two models, got %d", len(p.params.Models))
	}
	if p.params.SuspendDuration != 30 {
		t.Fatalf("expected suspendDuration=30, got %d", p.params.SuspendDuration)
	}
}

func TestModelRoundRobinPolicy_OnRequest_PayloadRoundRobin(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	ctx1 := rrRequestContextWithBody(`{"model":"original","x":"y"}`)
	action1 := p.OnRequest(ctx1, nil)
	mods1 := mustRRRequestMods(t, action1)
	got1 := decodeJSONMapRR(t, mods1.Body)
	if got1["model"] != "gpt-4" {
		t.Fatalf("expected first selected model gpt-4, got %v", got1["model"])
	}
	if ctx1.Metadata[MetadataKeyOriginalModel] != "original" {
		t.Fatalf("expected original model metadata to be set")
	}
	if ctx1.Metadata[MetadataKeySelectedModel] != "gpt-4" {
		t.Fatalf("expected selected model metadata to be set")
	}

	ctx2 := rrRequestContextWithBody(`{"model":"original2"}`)
	action2 := p.OnRequest(ctx2, nil)
	mods2 := mustRRRequestMods(t, action2)
	got2 := decodeJSONMapRR(t, mods2.Body)
	if got2["model"] != "gpt-35" {
		t.Fatalf("expected second selected model gpt-35, got %v", got2["model"])
	}
}

func TestModelRoundRobinPolicy_OnRequest_QueryParamAndPathParamMutation(t *testing.T) {
	pQuery := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "queryParam",
			"identifier": "model",
		},
	})
	queryCtx := rrRequestContextWithPath("/v1/chat?model=old&x=1")
	queryAction := pQuery.OnRequest(queryCtx, nil)
	queryMods := mustRRRequestMods(t, queryAction)
	if got := queryMods.SetHeaders[":path"]; !strings.Contains(got, "model=gpt-4") {
		t.Fatalf("expected query path to include new model, got %q", got)
	}

	pPath := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "pathParam",
			"identifier": `/models/([^/]+)`,
		},
	})
	pathCtx := rrRequestContextWithPath("/v1/models/old/completions?x=1")
	pathAction := pPath.OnRequest(pathCtx, nil)
	pathMods := mustRRRequestMods(t, pathAction)
	if got := pathMods.SetHeaders[":path"]; !strings.Contains(got, "/models/gpt-4/") {
		t.Fatalf("expected path to include new model, got %q", got)
	}
}

func TestModelRoundRobinPolicy_OnRequest_AllModelsSuspended(t *testing.T) {
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

	action := p.OnRequest(rrRequestContextWithHeaders(map[string][]string{"x-model": {"orig"}}), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when all models suspended, got %T", action)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("unexpected status code: got %d, want 503", resp.StatusCode)
	}
}

func TestModelRoundRobinPolicy_OnResponse_SuspendsModelOnError(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"suspendDuration": 60,
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-id",
			Metadata: map[string]interface{}{
				MetadataKeySelectedModel: "gpt-4",
			},
		},
		ResponseStatus: 500,
	}

	action := p.OnResponse(ctx, nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
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

func rrRequestContextWithBody(body string) *policy.RequestContext {
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

func rrRequestContextWithPath(path string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Path: path,
	}
}

func rrRequestContextWithHeaders(headers map[string][]string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(headers),
	}
}

func baseRRModels() []interface{} {
	return []interface{}{
		map[string]interface{}{"model": "gpt-4"},
		map[string]interface{}{"model": "gpt-35"},
	}
}
