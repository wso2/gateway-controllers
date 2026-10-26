package modelweightedroundrobin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestModelWeightedRoundRobinPolicy_Mode(t *testing.T) {
	p := &ModelWeightedRoundRobinPolicy{}
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
		"models": baseWeightedModels(),
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

func TestModelWeightedRoundRobinPolicy_OnRequestBody_PayloadWeightedSelection(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	// weight distribution: gpt-4, gpt-4, gpt-35, ...
	// Request 1
	shared1 := weightedSharedContext()
	headerCtx1 := &policy.RequestHeaderContext{SharedContext: shared1}
	p.OnRequestHeaders(context.Background(), headerCtx1, nil)

	bodyCtx1 := &policy.RequestContext{
		SharedContext: shared1,
		Body:          &policy.Body{Content: []byte(`{"model":"orig"}`), Present: true},
	}
	a1 := p.OnRequestBody(context.Background(), bodyCtx1, nil)
	m1 := mustWeightedRequestMods(t, a1)
	j1 := decodeJSONMapWeighted(t, m1.Body)
	if j1["model"] != "gpt-4" {
		t.Fatalf("expected first model gpt-4, got %v", j1["model"])
	}

	// Request 2
	shared2 := weightedSharedContext()
	headerCtx2 := &policy.RequestHeaderContext{SharedContext: shared2}
	p.OnRequestHeaders(context.Background(), headerCtx2, nil)

	bodyCtx2 := &policy.RequestContext{
		SharedContext: shared2,
		Body:          &policy.Body{Content: []byte(`{"model":"orig2"}`), Present: true},
	}
	a2 := p.OnRequestBody(context.Background(), bodyCtx2, nil)
	m2 := mustWeightedRequestMods(t, a2)
	j2 := decodeJSONMapWeighted(t, m2.Body)
	if j2["model"] != "gpt-4" {
		t.Fatalf("expected second model gpt-4, got %v", j2["model"])
	}

	// Request 3
	shared3 := weightedSharedContext()
	headerCtx3 := &policy.RequestHeaderContext{SharedContext: shared3}
	p.OnRequestHeaders(context.Background(), headerCtx3, nil)

	bodyCtx3 := &policy.RequestContext{
		SharedContext: shared3,
		Body:          &policy.Body{Content: []byte(`{"model":"orig3"}`), Present: true},
	}
	a3 := p.OnRequestBody(context.Background(), bodyCtx3, nil)
	m3 := mustWeightedRequestMods(t, a3)
	j3 := decodeJSONMapWeighted(t, m3.Body)
	if j3["model"] != "gpt-35" {
		t.Fatalf("expected third model gpt-35, got %v", j3["model"])
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestHeaders_QueryAndPathMutation(t *testing.T) {
	pQuery := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "queryParam",
			"identifier": "model",
		},
	})
	queryCtx := &policy.RequestHeaderContext{
		SharedContext: weightedSharedContext(),
		Path:          "/v1/chat?model=old",
	}
	queryAction := pQuery.OnRequestHeaders(context.Background(), queryCtx, nil)
	queryMods := mustWeightedRequestHeaderMods(t, queryAction)
	if queryMods.Path == nil || !strings.Contains(*queryMods.Path, "model=gpt-4") {
		t.Fatalf("expected query path to include new model, got %v", queryMods.Path)
	}

	pPath := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "pathParam",
			"identifier": `/models/([^/]+)`,
		},
	})
	pathCtx := &policy.RequestHeaderContext{
		SharedContext: weightedSharedContext(),
		Path:          "/v1/models/old/completions",
	}
	pathAction := pPath.OnRequestHeaders(context.Background(), pathCtx, nil)
	pathMods := mustWeightedRequestHeaderMods(t, pathAction)
	if pathMods.Path == nil || !strings.Contains(*pathMods.Path, "/models/gpt-4/") {
		t.Fatalf("expected path to include new model, got %v", pathMods.Path)
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestHeaders_AllModelsSuspended(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	until := time.Now().Add(10 * time.Minute)
	p.suspendedModels[suspensionKey("", "gpt-4")] = until
	p.suspendedModels[suspensionKey("", "gpt-35")] = until

	ctx := &policy.RequestHeaderContext{
		SharedContext: weightedSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-model": {"orig"}}),
	}
	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when all models suspended, got %T", action)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestModelWeightedRoundRobinPolicy_OnResponseHeaders_SuspendsSelectedModel(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models":          baseWeightedModels(),
		"suspendDuration": 30,
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	sharedCtx := &policy.SharedContext{
		RequestID: "id",
		Metadata: map[string]interface{}{
			MetadataKeySelectedModel: "gpt-4",
		},
	}
	ctx := &policy.ResponseHeaderContext{
		SharedContext:  sharedCtx,
		ResponseStatus: 429,
	}
	action := p.OnResponseHeaders(context.Background(), ctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	if until, exists := p.suspendedModels[suspensionKey("", "gpt-4")]; !exists || !until.After(time.Now()) {
		t.Fatalf("expected selected model to be suspended")
	}
}

func TestModelWeightedRoundRobinPolicy_SelectNextAvailable_SkipsSuspended(t *testing.T) {
	p := &ModelWeightedRoundRobinPolicy{
		suspendedModels: map[string]time.Time{
			suspensionKey("", "a"): time.Now().Add(5 * time.Minute),
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

func TestModelWeightedRoundRobinPolicy_GetPolicy_ProviderParsing(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "gpt-4", "weight": 1, "provider": 123},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})
	if err == nil || !strings.Contains(err.Error(), "'models[0].provider' must be a string") {
		t.Fatalf("expected provider type error, got %v", err)
	}

	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "gpt-4o", "weight": 3},
			map[string]interface{}{"model": "claude-sonnet-4-5-20250929", "weight": 1, "provider": "anthropic-provider"},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})
	if p.params.Models[0].Provider != "" {
		t.Fatalf("expected empty provider for first model, got %q", p.params.Models[0].Provider)
	}
	if p.params.Models[1].Provider != "anthropic-provider" {
		t.Fatalf("expected anthropic-provider, got %q", p.params.Models[1].Provider)
	}
	// The provider must survive expansion into the weighted sequence.
	for _, m := range p.weightedSequence {
		if m.Model == "claude-sonnet-4-5-20250929" && m.Provider != "anthropic-provider" {
			t.Fatalf("expected provider preserved in weighted sequence, got %q", m.Provider)
		}
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestHeaders_DefaultProvider(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models":       []interface{}{map[string]interface{}{"model": "gpt-4o", "weight": 1}},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	shared := weightedSharedContext()
	ctx := &policy.RequestHeaderContext{SharedContext: shared}
	mods := mustWeightedRequestHeaderMods(t, p.OnRequestHeaders(context.Background(), ctx, nil))

	if mods.UpstreamName != nil {
		t.Fatalf("expected no UpstreamName for default provider, got %q", *mods.UpstreamName)
	}
	if _, ok := shared.Metadata[MetadataKeyProviderRouting]; ok {
		t.Fatalf("expected selected_provider metadata to be unset for default provider")
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestHeaders_AdditionalProvider(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "claude-sonnet-4-5-20250929", "weight": 1, "provider": "anthropic-provider"},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	shared := weightedSharedContext()
	ctx := &policy.RequestHeaderContext{SharedContext: shared}
	mods := mustWeightedRequestHeaderMods(t, p.OnRequestHeaders(context.Background(), ctx, nil))

	if mods.UpstreamName == nil || *mods.UpstreamName != "anthropic-provider" {
		t.Fatalf("expected UpstreamName anthropic-provider, got %v", mods.UpstreamName)
	}
	if shared.Metadata[MetadataKeyProviderRouting] != "anthropic-provider" {
		t.Fatalf("expected selected_provider metadata anthropic-provider, got %v", shared.Metadata[MetadataKeyProviderRouting])
	}
}

func TestModelWeightedRoundRobinPolicy_IndependentSuspensionPerProvider(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "shared-model", "weight": 1, "provider": "provider-a"},
			map[string]interface{}{"model": "shared-model", "weight": 1, "provider": "provider-b"},
		},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})

	p.suspendedModels[suspensionKey("provider-a", "shared-model")] = time.Now().Add(10 * time.Minute)

	got := p.selectNextAvailableWeightedModel()
	if got == nil || got.Provider != "provider-b" {
		t.Fatalf("expected provider-b to remain available, got %+v", got)
	}
	if _, suspended := p.suspendedModels[suspensionKey("provider-b", "shared-model")]; suspended {
		t.Fatalf("provider-b/shared-model should not be suspended")
	}
}

func TestModelWeightedRoundRobinPolicy_OnResponseHeaders_SuspendsProviderModelPair(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"model": "shared-model", "weight": 1, "provider": "provider-a"},
			map[string]interface{}{"model": "shared-model", "weight": 1, "provider": "provider-b"},
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

func mustWeightedRequestHeaderMods(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	return mods
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

func weightedSharedContext() *policy.SharedContext {
	return &policy.SharedContext{
		RequestID: "req-id",
		Metadata:  map[string]interface{}{},
	}
}

func baseWeightedModels() []interface{} {
	return []interface{}{
		map[string]interface{}{"model": "gpt-4", "weight": 2},
		map[string]interface{}{"model": "gpt-35", "weight": 1},
	}
}

// TestModelWeightedRoundRobin_RejectionsDeclareFault covers the conditions this policy refuses on, and pins
// which code each takes.
func TestModelWeightedRoundRobin_RejectionsDeclareFault(t *testing.T) {
	assertFault := func(t *testing.T, action interface{}, wantCode, wantType string) {
		t.Helper()
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
		p := &ModelWeightedRoundRobinPolicy{}
		p.params.RequestModel.Location = "payload"
		p.params.RequestModel.Identifier = "$.model"
		reqCtx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{MetadataKeySelectedModel: "gpt-4"},
			},
			Body: nil,
		}
		assertFault(t, p.OnRequestBody(context.Background(), reqCtx, nil),
			policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})

	t.Run("request body is not JSON", func(t *testing.T) {
		p := &ModelWeightedRoundRobinPolicy{}
		p.params.RequestModel.Location = "payload"
		p.params.RequestModel.Identifier = "$.model"
		reqCtx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{MetadataKeySelectedModel: "gpt-4"},
			},
			Body: &policy.Body{Content: []byte("{not json"), Present: true},
		}
		assertFault(t, p.OnRequestBody(context.Background(), reqCtx, nil),
			policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})
}
