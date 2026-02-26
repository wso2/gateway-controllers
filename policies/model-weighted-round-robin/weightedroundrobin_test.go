package modelweightedroundrobin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestModelWeightedRoundRobinPolicy_Mode(t *testing.T) {
	p := &ModelWeightedRoundRobinPolicy{}
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

func TestModelWeightedRoundRobinPolicy_GetPolicy_ParseErrors(t *testing.T) {
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
			name: "missing weight",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": "gpt-4"},
				},
			},
			wantErrContain: "'models[0].weight' is required",
		},
		{
			name: "weight not integer",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": "gpt-4", "weight": 1.5},
				},
			},
			wantErrContain: "'models[0].weight' must be an integer",
		},
		{
			name: "weight too low",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": "gpt-4", "weight": 0},
				},
			},
			wantErrContain: "'models[0].weight' must be >= 1",
		},
		{
			name: "suspendDuration invalid",
			params: map[string]interface{}{
				"models":          baseWeightedModels(),
				"suspendDuration": "10",
			},
			wantErrContain: "'suspendDuration' must be an integer",
		},
		{
			name: "requestModel missing",
			params: map[string]interface{}{
				"models": baseWeightedModels(),
			},
			wantErrContain: "'requestModel' configuration is required",
		},
		{
			name: "requestModel invalid location",
			params: map[string]interface{}{
				"models": baseWeightedModels(),
				"requestModel": map[string]interface{}{
					"location":   "cookie",
					"identifier": "$.model",
				},
			},
			wantErrContain: "'requestModel.location' must be one of: payload, header, queryParam, pathParam",
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

func TestModelWeightedRoundRobinPolicy_GetPolicy_SuccessAndSequence(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models":          baseWeightedModels(),
		"suspendDuration": float64(20),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	if len(p.params.Models) != 2 {
		t.Fatalf("expected two models, got %d", len(p.params.Models))
	}
	if p.params.SuspendDuration != 20 {
		t.Fatalf("expected suspendDuration=20, got %d", p.params.SuspendDuration)
	}
	// weight 2 + 1 => sequence length 3
	if len(p.weightedSequence) != 3 {
		t.Fatalf("expected weighted sequence length 3, got %d", len(p.weightedSequence))
	}
}

func TestModelWeightedRoundRobinPolicy_BuildWeightedSequence(t *testing.T) {
	models := []*WeightedModel{
		{Model: "a", Weight: 2},
		{Model: "b", Weight: 1},
		{Model: "c", Weight: 0},
	}
	seq := buildWeightedSequence(models)
	if len(seq) != 3 {
		t.Fatalf("expected sequence length 3, got %d", len(seq))
	}
	if seq[0].Model != "a" || seq[1].Model != "a" || seq[2].Model != "b" {
		t.Fatalf("unexpected sequence order: %+v", []string{seq[0].Model, seq[1].Model, seq[2].Model})
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequest_PayloadWeightedSelection(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	// weight distribution: gpt-4, gpt-4, gpt-35, ...
	ctx1 := weightedRequestContextWithBody(`{"model":"orig"}`)
	a1 := p.OnRequest(ctx1, nil)
	m1 := mustWeightedRequestMods(t, a1)
	j1 := decodeJSONMapWeighted(t, m1.Body)
	if j1["model"] != "gpt-4" {
		t.Fatalf("expected first model gpt-4, got %v", j1["model"])
	}

	ctx2 := weightedRequestContextWithBody(`{"model":"orig2"}`)
	a2 := p.OnRequest(ctx2, nil)
	m2 := mustWeightedRequestMods(t, a2)
	j2 := decodeJSONMapWeighted(t, m2.Body)
	if j2["model"] != "gpt-4" {
		t.Fatalf("expected second model gpt-4, got %v", j2["model"])
	}

	ctx3 := weightedRequestContextWithBody(`{"model":"orig3"}`)
	a3 := p.OnRequest(ctx3, nil)
	m3 := mustWeightedRequestMods(t, a3)
	j3 := decodeJSONMapWeighted(t, m3.Body)
	if j3["model"] != "gpt-35" {
		t.Fatalf("expected third model gpt-35, got %v", j3["model"])
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequest_QueryAndPathMutation(t *testing.T) {
	pQuery := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "queryParam",
			"identifier": "model",
		},
	})
	queryCtx := weightedRequestContextWithPath("/v1/chat?model=old")
	queryAction := pQuery.OnRequest(queryCtx, nil)
	queryMods := mustWeightedRequestMods(t, queryAction)
	if got := queryMods.SetHeaders[":path"]; !strings.Contains(got, "model=gpt-4") {
		t.Fatalf("expected query path to include new model, got %q", got)
	}

	pPath := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "pathParam",
			"identifier": `/models/([^/]+)`,
		},
	})
	pathCtx := weightedRequestContextWithPath("/v1/models/old/completions")
	pathAction := pPath.OnRequest(pathCtx, nil)
	pathMods := mustWeightedRequestMods(t, pathAction)
	if got := pathMods.SetHeaders[":path"]; !strings.Contains(got, "/models/gpt-4/") {
		t.Fatalf("expected path to include new model, got %q", got)
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequest_AllModelsSuspended(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	until := time.Now().Add(10 * time.Minute)
	p.suspendedModels["gpt-4"] = until
	p.suspendedModels["gpt-35"] = until

	action := p.OnRequest(weightedRequestContextWithHeaders(map[string][]string{"x-model": {"orig"}}), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when all models suspended, got %T", action)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestModelWeightedRoundRobinPolicy_OnResponse_SuspendsSelectedModel(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models":          baseWeightedModels(),
		"suspendDuration": 30,
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "id",
			Metadata: map[string]interface{}{
				MetadataKeySelectedModel: "gpt-4",
			},
		},
		ResponseStatus: 429,
	}
	action := p.OnResponse(ctx, nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
	if until, exists := p.suspendedModels["gpt-4"]; !exists || !until.After(time.Now()) {
		t.Fatalf("expected selected model to be suspended")
	}
}

func TestModelWeightedRoundRobinPolicy_SelectNextAvailable_SkipsSuspended(t *testing.T) {
	p := &ModelWeightedRoundRobinPolicy{
		suspendedModels: map[string]time.Time{
			"a": time.Now().Add(5 * time.Minute),
		},
		weightedSequence: []*WeightedModel{
			{Model: "a", Weight: 2},
			{Model: "b", Weight: 1},
		},
	}

	got := p.selectNextAvailableWeightedModel()
	if got == nil || got.Model != "b" {
		t.Fatalf("expected to skip suspended model a and pick b, got %+v", got)
	}
}

func mustGetWeightedPolicy(t *testing.T, params map[string]interface{}) *ModelWeightedRoundRobinPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	wp, ok := p.(*ModelWeightedRoundRobinPolicy)
	if !ok {
		t.Fatalf("expected *ModelWeightedRoundRobinPolicy, got %T", p)
	}
	return wp
}

func mustWeightedRequestMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func decodeJSONMapWeighted(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("failed to unmarshal json body: %v", err)
	}
	return m
}

func weightedRequestContextWithBody(body string) *policy.RequestContext {
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

func weightedRequestContextWithPath(path string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Path: path,
	}
}

func weightedRequestContextWithHeaders(headers map[string][]string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(headers),
	}
}

func baseWeightedModels() []interface{} {
	return []interface{}{
		map[string]interface{}{"model": "gpt-4", "weight": 2},
		map[string]interface{}{"model": "gpt-35", "weight": 1},
	}
}
