package prompttemplate

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestPromptTemplatePolicy_Mode(t *testing.T) {
	p := &PromptTemplatePolicy{}

	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}

	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestPromptTemplatePolicy_OnResponse_NoOp(t *testing.T) {
	p := &PromptTemplatePolicy{}
	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  map[string]interface{}{},
		},
	}

	action := p.OnResponse(ctx, nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}

func TestPromptTemplatePolicy_GetPolicy_MinimalSuccess(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	if len(p.params.Templates) != 1 {
		t.Fatalf("expected one template, got %d", len(p.params.Templates))
	}
	if p.params.JsonPath != "" {
		t.Fatalf("expected default jsonPath to be empty, got %q", p.params.JsonPath)
	}
	if p.params.OnMissingTemplate != OnMissingTemplateError {
		t.Fatalf("expected default onMissingTemplate=%q, got %q", OnMissingTemplateError, p.params.OnMissingTemplate)
	}
	if p.params.OnUnresolvedPlaceholder != OnUnresolvedPlaceholderKeep {
		t.Fatalf("expected default onUnresolvedPlaceholder=%q, got %q", OnUnresolvedPlaceholderKeep, p.params.OnUnresolvedPlaceholder)
	}
}

func TestPromptTemplatePolicy_GetPolicy_InvalidParams(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "missing templates",
			params:         map[string]interface{}{},
			wantErrContain: "'templates' parameter is required",
		},
		{
			name: "wrong templates type",
			params: map[string]interface{}{
				"templates": 42,
			},
			wantErrContain: "'templates' must be an array or JSON string",
		},
		{
			name: "empty templates array",
			params: map[string]interface{}{
				"templates": []interface{}{},
			},
			wantErrContain: "'templates' cannot be empty",
		},
		{
			name: "malformed templates json string",
			params: map[string]interface{}{
				"templates": `[{"name":"greet","template":"Hi [[name]]"}`,
			},
			wantErrContain: "error unmarshaling templates",
		},
		{
			name: "templates item is not object",
			params: map[string]interface{}{
				"templates": []interface{}{"bad"},
			},
			wantErrContain: "'templates[0]' must be an object",
		},
		{
			name: "empty name",
			params: map[string]interface{}{
				"templates": []interface{}{
					map[string]interface{}{
						"name":     " ",
						"template": "Hi [[name]]",
					},
				},
			},
			wantErrContain: "'templates[0].name' cannot be empty",
		},
		{
			name: "invalid name pattern",
			params: map[string]interface{}{
				"templates": []interface{}{
					map[string]interface{}{
						"name":     "bad name",
						"template": "Hi [[name]]",
					},
				},
			},
			wantErrContain: "'templates[0].name' must match ^[a-zA-Z0-9_-]+$",
		},
		{
			name: "duplicate names",
			params: map[string]interface{}{
				"templates": []interface{}{
					map[string]interface{}{
						"name":     "greet",
						"template": "Hi [[name]]",
					},
					map[string]interface{}{
						"name":     "greet",
						"template": "Hello [[name]]",
					},
				},
			},
			wantErrContain: `duplicate template name: "greet"`,
		},
		{
			name: "empty template",
			params: map[string]interface{}{
				"templates": []interface{}{
					map[string]interface{}{
						"name":     "greet",
						"template": " ",
					},
				},
			},
			wantErrContain: "'templates[0].template' cannot be empty",
		},
		{
			name: "jsonPath wrong type",
			params: map[string]interface{}{
				"templates": baseTemplatesArray(),
				"jsonPath":  true,
			},
			wantErrContain: "'jsonPath' must be a string",
		},
		{
			name: "onMissingTemplate invalid value",
			params: map[string]interface{}{
				"templates":         baseTemplatesArray(),
				"onMissingTemplate": "ignore",
			},
			wantErrContain: "'onMissingTemplate' must be one of [error,passthrough]",
		},
		{
			name: "onUnresolvedPlaceholder invalid value",
			params: map[string]interface{}{
				"templates":               baseTemplatesArray(),
				"onUnresolvedPlaceholder": "skip",
			},
			wantErrContain: "'onUnresolvedPlaceholder' must be one of [keep,empty,error]",
		},
		{
			name: "legacy config only should fail",
			params: map[string]interface{}{
				"promptTemplateConfig": `[{"name":"greet","prompt":"Hi [[name]]"}]`,
			},
			wantErrContain: "'templates' parameter is required",
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

func TestPromptTemplatePolicy_GetPolicy_TemplatesJSONStringWorks(t *testing.T) {
	params := map[string]interface{}{
		"templates": `[{"name":"greet","template":"Hi [[name]]"}]`,
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"prompt":"template://greet?name=Sam"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	if len(mods.Body) == 0 {
		t.Fatalf("expected modified body")
	}
	body := decodeJSONMap(t, mods.Body)
	if got := body["prompt"]; got != "Hi Sam" {
		t.Fatalf("unexpected prompt: got %v, want %q", got, "Hi Sam")
	}
}

func TestPromptTemplatePolicy_OnRequest_NoBodyOrEmptyBody(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	tests := []struct {
		name string
		ctx  *policy.RequestContext
	}{
		{
			name: "nil body",
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{
					RequestID: "test-request-id",
					Metadata:  map[string]interface{}{},
				},
				Body: nil,
			},
		},
		{
			name: "empty body",
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{
					RequestID: "test-request-id",
					Metadata:  map[string]interface{}{},
				},
				Body: &policy.Body{
					Content: []byte{},
					Present: false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := p.OnRequest(tt.ctx, nil)
			mods := mustRequestMods(t, action)
			if mods.Body != nil {
				t.Fatalf("expected no body modifications, got %s", string(mods.Body))
			}
		})
	}
}

func TestPromptTemplatePolicy_OnRequest_FullPayloadSingleReplacement(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	ctx := newRequestContextWithBody(`{"prompt":"template://greet?name=Ann"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	body := decodeJSONMap(t, mods.Body)
	if got := body["prompt"]; got != "Hello Ann" {
		t.Fatalf("unexpected prompt: got %v, want %q", got, "Hello Ann")
	}
}

func TestPromptTemplatePolicy_OnRequest_NoTemplateReferences_NoChanges(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	ctx := newRequestContextWithBody(`{"prompt":"plain prompt text"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	if mods.Body != nil {
		t.Fatalf("expected no body changes, got %s", string(mods.Body))
	}
}

func TestPromptTemplatePolicy_OnRequest_FullPayloadMultipleReplacements(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hello [[name]]"},
			map[string]interface{}{"name": "bye", "template": "Bye [[name]]"},
		},
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{
		"a":"template://greet?name=Ann",
		"b":"template://greet?name=Bob",
		"c":"template://bye?name=Ann"
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	if got := body["a"]; got != "Hello Ann" {
		t.Fatalf("unexpected a: got %v", got)
	}
	if got := body["b"]; got != "Hello Bob" {
		t.Fatalf("unexpected b: got %v", got)
	}
	if got := body["c"]; got != "Bye Ann" {
		t.Fatalf("unexpected c: got %v", got)
	}
}

func TestPromptTemplatePolicy_OnRequest_URLQueryDecoding(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "intro", "template": "Hello [[name]] from [[city]]"},
		},
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"prompt":"template://intro?name=John+Doe&city=New%20York"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	if got := body["prompt"]; got != "Hello John Doe from New York" {
		t.Fatalf("unexpected prompt: got %v", got)
	}
}

func TestPromptTemplatePolicy_OnRequest_EscapesQuotesAndNewlines(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{
				"name":     "multi",
				"template": "Line1 [[text]]\nLine2 \"quoted\"",
			},
		},
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"prompt":"template://multi?text=hello%20world"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	want := "Line1 hello world\nLine2 \"quoted\""
	if got := body["prompt"]; got != want {
		t.Fatalf("unexpected prompt: got %q, want %q", got, want)
	}
}

func TestPromptTemplatePolicy_OnRequest_MissingTemplate_DefaultError(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	ctx := newRequestContextWithBody(`{"prompt":"template://unknown?name=Ann"}`)
	action := p.OnRequest(ctx, nil)
	assertTemplateError(t, action, "Error resolving templates")
}

func TestPromptTemplatePolicy_OnRequest_MissingTemplate_Passthrough(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hello [[name]]"},
		},
		"onMissingTemplate": "passthrough",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{
		"a":"template://greet?name=Ann",
		"b":"template://unknown?name=Bob"
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	if got := body["a"]; got != "Hello Ann" {
		t.Fatalf("unexpected resolved value: got %v", got)
	}
	if got := body["b"]; got != "template://unknown?name=Bob" {
		t.Fatalf("expected missing template reference to passthrough, got %v", got)
	}
}

func TestPromptTemplatePolicy_OnRequest_UnresolvedPlaceholder_DefaultKeep(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hi [[name]] from [[city]]"},
		},
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"prompt":"template://greet?name=Ann"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	if got := body["prompt"]; got != "Hi Ann from [[city]]" {
		t.Fatalf("unexpected keep behavior: got %v", got)
	}
}

func TestPromptTemplatePolicy_OnRequest_UnresolvedPlaceholder_Empty(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hi [[name]] from [[city]]"},
		},
		"onUnresolvedPlaceholder": "empty",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"prompt":"template://greet?name=Ann"}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	if got := body["prompt"]; got != "Hi Ann from " {
		t.Fatalf("unexpected empty behavior: got %v", got)
	}
}

func TestPromptTemplatePolicy_OnRequest_UnresolvedPlaceholder_ErrorDeterministic(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "[[x]] [[x]] [[y]]"},
		},
		"onUnresolvedPlaceholder": "error",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"prompt":"template://greet"}`)
	action := p.OnRequest(ctx, nil)
	resp := assertTemplateError(t, action, "Error resolving templates")

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "x,y") {
		t.Fatalf("expected deterministic unresolved placeholder list in message, got %q", msg)
	}
}

func TestPromptTemplatePolicy_OnRequest_JSONPath_UpdatesOnlyTarget(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hello [[name]]"},
		},
		"jsonPath": "$.target",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{
		"target":"template://greet?name=Ann",
		"other":"template://greet?name=Bob",
		"nested":{"value":"template://greet?name=Cat"}
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	if got := body["target"]; got != "Hello Ann" {
		t.Fatalf("unexpected target value: got %v", got)
	}
	if got := body["other"]; got != "template://greet?name=Bob" {
		t.Fatalf("expected non-target field to remain unchanged, got %v", got)
	}
	nested, ok := body["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested object, got %T", body["nested"])
	}
	if got := nested["value"]; got != "template://greet?name=Cat" {
		t.Fatalf("expected nested field to remain unchanged, got %v", got)
	}
}

func TestPromptTemplatePolicy_OnRequest_JSONPath_InvalidPathReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hello [[name]]"},
		},
		"jsonPath": "$.missing.value",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"target":"template://greet?name=Ann"}`)
	action := p.OnRequest(ctx, nil)
	assertTemplateError(t, action, "Error extracting value from JSONPath")
}

func TestPromptTemplatePolicy_OnRequest_JSONPath_NonStringTargetReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hello [[name]]"},
		},
		"jsonPath": "$.target",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"target":{"value":"template://greet?name=Ann"}}`)
	action := p.OnRequest(ctx, nil)
	assertTemplateError(t, action, "Error extracting value from JSONPath")
}

func TestPromptTemplatePolicy_OnRequest_JSONPath_InvalidJSONReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{"name": "greet", "template": "Hello [[name]]"},
		},
		"jsonPath": "$.target",
	}
	p := mustGetPromptTemplatePolicy(t, params)

	ctx := newRequestContextWithBody(`{"target":"template://greet?name=Ann"`)
	action := p.OnRequest(ctx, nil)
	assertTemplateError(t, action, "Error parsing JSON payload")
}

func TestPromptTemplatePolicy_OnRequest_StressManyTemplatesAndReferences(t *testing.T) {
	templateCount := 25
	templates := make([]interface{}, 0, templateCount)
	payloadMap := make(map[string]interface{}, templateCount)

	for i := 0; i < templateCount; i++ {
		name := fmt.Sprintf("t%d", i)
		templates = append(templates, map[string]interface{}{
			"name":     name,
			"template": fmt.Sprintf("Value-%d [[v]]", i),
		})
		payloadMap[fmt.Sprintf("p%d", i)] = fmt.Sprintf("template://%s?v=%d", name, i)
	}

	payload, err := json.Marshal(payloadMap)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	p := mustGetPromptTemplatePolicy(t, map[string]interface{}{
		"templates": templates,
	})

	ctx := newRequestContextWithBody(string(payload))
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)
	body := decodeJSONMap(t, mods.Body)

	for i := 0; i < templateCount; i++ {
		key := fmt.Sprintf("p%d", i)
		want := fmt.Sprintf("Value-%d %d", i, i)
		if got := body[key]; got != want {
			t.Fatalf("unexpected resolved value for %s: got %v, want %q", key, got, want)
		}
	}
}

func TestPromptTemplatePolicy_ResolveTemplateReference_MalformedURI(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	_, _, err := p.resolveTemplateReference("template://%zz")
	if err == nil {
		t.Fatalf("expected parse error for malformed URI")
	}
	if !strings.Contains(err.Error(), "invalid template reference") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptTemplatePolicy_OnRequest_ConcurrentAccess(t *testing.T) {
	p := mustGetPromptTemplatePolicy(t, baseParams())

	const workers = 50
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()

			name := fmt.Sprintf("User%d", i)
			ctx := newRequestContextWithBody(fmt.Sprintf(`{"prompt":"template://greet?name=%s"}`, name))

			action := p.OnRequest(ctx, nil)
			mods, ok := action.(policy.UpstreamRequestModifications)
			if !ok {
				errCh <- fmt.Errorf("expected UpstreamRequestModifications, got %T", action)
				return
			}
			if len(mods.Body) == 0 {
				errCh <- fmt.Errorf("expected modified body")
				return
			}

			body := decodeJSONMapNoFail(mods.Body)
			want := "Hello " + name
			if got, _ := body["prompt"].(string); got != want {
				errCh <- fmt.Errorf("unexpected prompt: got %q, want %q", got, want)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func mustGetPromptTemplatePolicy(t *testing.T, params map[string]interface{}) *PromptTemplatePolicy {
	t.Helper()

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	policyImpl, ok := p.(*PromptTemplatePolicy)
	if !ok {
		t.Fatalf("expected *PromptTemplatePolicy, got %T", p)
	}
	return policyImpl
}

func mustRequestMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func assertTemplateError(t *testing.T, action policy.RequestAction, wantMessagePrefix string) policy.ImmediateResponse {
	t.Helper()

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if got := body["type"]; got != "PROMPT_TEMPLATE_ERROR" {
		t.Fatalf("unexpected error type: got %v, want %q", got, "PROMPT_TEMPLATE_ERROR")
	}
	msg, ok := body["message"].(string)
	if !ok {
		t.Fatalf("expected string message, got %T", body["message"])
	}
	if !strings.HasPrefix(msg, wantMessagePrefix) {
		t.Fatalf("unexpected message: got %q, want prefix %q", msg, wantMessagePrefix)
	}

	return resp
}

func decodeJSONMap(t *testing.T, payload []byte) map[string]interface{} {
	t.Helper()

	result := decodeJSONMapNoFail(payload)
	if result == nil {
		t.Fatalf("failed to decode json payload: %s", string(payload))
	}
	return result
}

func decodeJSONMapNoFail(payload []byte) map[string]interface{} {
	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		return nil
	}
	return result
}

func newRequestContextWithBody(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func baseTemplatesArray() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"name":     "greet",
			"template": "Hello [[name]]",
		},
	}
}

func baseParams() map[string]interface{} {
	return map[string]interface{}{
		"templates": baseTemplatesArray(),
	}
}
