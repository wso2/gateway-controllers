package promptdecorator

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestPromptDecoratorPolicy_Mode(t *testing.T) {
	p := &PromptDecoratorPolicy{}

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

func TestPromptDecoratorPolicy_OnResponse_NoOp(t *testing.T) {
	p := &PromptDecoratorPolicy{}
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

func TestPromptDecoratorPolicy_GetPolicy_TextConfig_Defaults(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "Be concise.",
		},
	})

	if p.params.PromptDecoratorConfig.Text == nil {
		t.Fatalf("expected text config to be set")
	}
	if got := *p.params.PromptDecoratorConfig.Text; got != "Be concise." {
		t.Fatalf("unexpected text decoration: got %q", got)
	}
	if got := p.params.JsonPath; got != defaultTextDecorationJSONPath {
		t.Fatalf("unexpected default jsonPath: got %q, want %q", got, defaultTextDecorationJSONPath)
	}
	if p.params.Append {
		t.Fatalf("expected append default false")
	}
}

func TestPromptDecoratorPolicy_GetPolicy_MessagesConfig_DefaultsAndRoleNormalization(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{
					"role":    "SYSTEM",
					"content": "You are helpful.",
				},
			},
		},
	})

	if len(p.params.PromptDecoratorConfig.Messages) != 1 {
		t.Fatalf("expected one message decoration, got %d", len(p.params.PromptDecoratorConfig.Messages))
	}
	if got := p.params.PromptDecoratorConfig.Messages[0].Role; got != "system" {
		t.Fatalf("expected normalized role 'system', got %q", got)
	}
	if got := p.params.JsonPath; got != defaultMessagesDecorationJSONPath {
		t.Fatalf("unexpected default jsonPath: got %q, want %q", got, defaultMessagesDecorationJSONPath)
	}
}

func TestPromptDecoratorPolicy_GetPolicy_ConfigFromJSONString(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": `{"text":"Use markdown."}`,
		"append":                true,
	})

	if p.params.PromptDecoratorConfig.Text == nil {
		t.Fatalf("expected text config")
	}
	if got := *p.params.PromptDecoratorConfig.Text; got != "Use markdown." {
		t.Fatalf("unexpected text config value: %q", got)
	}
	if !p.params.Append {
		t.Fatalf("expected append=true")
	}
}

func TestPromptDecoratorPolicy_GetPolicy_InvalidParams(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "missing promptDecoratorConfig",
			params:         map[string]interface{}{},
			wantErrContain: "'promptDecoratorConfig' parameter is required",
		},
		{
			name: "promptDecoratorConfig wrong type",
			params: map[string]interface{}{
				"promptDecoratorConfig": 123,
			},
			wantErrContain: "'promptDecoratorConfig' must be a JSON string or object",
		},
		{
			name: "promptDecoratorConfig malformed json string",
			params: map[string]interface{}{
				"promptDecoratorConfig": `{"text":"hello"`,
			},
			wantErrContain: "error unmarshaling promptDecoratorConfig",
		},
		{
			name: "text and messages both configured",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"text": "hello",
					"messages": []interface{}{
						map[string]interface{}{"role": "system", "content": "x"},
					},
				},
			},
			wantErrContain: "'promptDecoratorConfig' must define exactly one of 'text' or 'messages'",
		},
		{
			name: "neither text nor messages configured",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{},
			},
			wantErrContain: "'promptDecoratorConfig' must define one of 'text' or 'messages'",
		},
		{
			name: "text empty",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"text": "   ",
				},
			},
			wantErrContain: "'promptDecoratorConfig.text' must be a non-empty string",
		},
		{
			name: "messages role empty",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"messages": []interface{}{
						map[string]interface{}{"role": " ", "content": "x"},
					},
				},
			},
			wantErrContain: "'promptDecoratorConfig.messages[0].role' must be a non-empty string",
		},
		{
			name: "messages role invalid",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"messages": []interface{}{
						map[string]interface{}{"role": "moderator", "content": "x"},
					},
				},
			},
			wantErrContain: "'promptDecoratorConfig.messages[0].role' must be one of [system,user,assistant,tool]",
		},
		{
			name: "messages content empty",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"messages": []interface{}{
						map[string]interface{}{"role": "system", "content": "  "},
					},
				},
			},
			wantErrContain: "'promptDecoratorConfig.messages[0].content' must be a non-empty string",
		},
		{
			name: "jsonPath wrong type",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"text": "x",
				},
				"jsonPath": true,
			},
			wantErrContain: "'jsonPath' must be a string",
		},
		{
			name: "append wrong type",
			params: map[string]interface{}{
				"promptDecoratorConfig": map[string]interface{}{
					"text": "x",
				},
				"append": "true",
			},
			wantErrContain: "'append' must be a boolean",
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

func TestPromptDecoratorPolicy_OnRequest_TextDefaultPath_Prepend(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "Be concise.",
		},
	})

	ctx := newRequestContextWithBody(`{
		"messages":[
			{"role":"system","content":"rules"},
			{"role":"user","content":"Summarize this text"}
		]
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	messages := mustMessages(t, payload["messages"])
	last := messages[len(messages)-1]
	if got := last["content"]; got != "Be concise. Summarize this text" {
		t.Fatalf("unexpected decorated content: got %q", got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_TextDefaultPath_Append(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "in bullet points.",
		},
		"append": true,
	})

	ctx := newRequestContextWithBody(`{"messages":[{"role":"user","content":"Explain TCP"}]}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	messages := mustMessages(t, payload["messages"])
	if got := messages[0]["content"]; got != "Explain TCP in bullet points." {
		t.Fatalf("unexpected decorated content: got %q", got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_TextCustomPath(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "Use JSON output.",
		},
		"jsonPath": "$.input.prompt",
	})

	ctx := newRequestContextWithBody(`{
		"input":{"prompt":"Create a plan"},
		"messages":[{"role":"user","content":"unchanged"}]
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	input, ok := payload["input"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected input object, got %T", payload["input"])
	}
	if got := input["prompt"]; got != "Use JSON output. Create a plan" {
		t.Fatalf("unexpected prompt: got %v", got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_MessagesDefaultPath_Prepend(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{"role": "system", "content": "You are concise."},
				map[string]interface{}{"role": "assistant", "content": "Acknowledge briefly."},
			},
		},
	})

	ctx := newRequestContextWithBody(`{
		"messages":[
			{"role":"user","content":"Hello"},
			{"role":"assistant","content":"Hi"}
		]
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	messages := mustMessages(t, payload["messages"])
	if len(messages) != 4 {
		t.Fatalf("expected 4 messages after prepend, got %d", len(messages))
	}
	if got := messages[0]["role"]; got != "system" {
		t.Fatalf("unexpected first role: %v", got)
	}
	if got := messages[0]["content"]; got != "You are concise." {
		t.Fatalf("unexpected first content: %v", got)
	}
	if got := messages[2]["content"]; got != "Hello" {
		t.Fatalf("expected original messages to remain in order after prepended decorations")
	}
}

func TestPromptDecoratorPolicy_OnRequest_MessagesDefaultPath_Append(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{"role": "tool", "content": "trace-id=123"},
			},
		},
		"append": true,
	})

	ctx := newRequestContextWithBody(`{"messages":[{"role":"user","content":"hello"}]}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	messages := mustMessages(t, payload["messages"])
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages after append, got %d", len(messages))
	}
	if got := messages[1]["role"]; got != "tool" {
		t.Fatalf("unexpected appended role: %v", got)
	}
	if got := messages[1]["content"]; got != "trace-id=123" {
		t.Fatalf("unexpected appended content: %v", got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_MessagesCustomPath(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{"role": "system", "content": "Only decorate history."},
			},
		},
		"jsonPath": "$.conversation.history",
	})

	ctx := newRequestContextWithBody(`{
		"conversation":{"history":[{"role":"user","content":"hello"}]},
		"messages":[{"role":"user","content":"keep me"}]
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	conversation := payload["conversation"].(map[string]interface{})
	history := mustMessages(t, conversation["history"])
	if len(history) != 2 {
		t.Fatalf("expected history length 2, got %d", len(history))
	}
	if got := history[0]["content"]; got != "Only decorate history." {
		t.Fatalf("unexpected history decoration: %v", got)
	}
	messages := mustMessages(t, payload["messages"])
	if got := messages[0]["content"]; got != "keep me" {
		t.Fatalf("non-target array should remain unchanged, got %v", got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_EmptyBodyReturnsError(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "x",
		},
	})

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
			name: "empty body content",
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
			assertDecoratorError(t, action, "Empty request body")
		})
	}
}

func TestPromptDecoratorPolicy_OnRequest_InvalidJSONReturnsError(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "x",
		},
	})

	ctx := newRequestContextWithBody(`{"messages":[`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Error parsing JSON payload")
}

func TestPromptDecoratorPolicy_OnRequest_JSONPathNotFoundReturnsError(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "x",
		},
		"jsonPath": "$.missing.path",
	})

	ctx := newRequestContextWithBody(`{"messages":[{"role":"user","content":"hello"}]}`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Error extracting value from JSONPath")
}

func TestPromptDecoratorPolicy_OnRequest_TargetTypeMismatch_StringPathWithMessagesConfig(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{"role": "system", "content": "x"},
			},
		},
		"jsonPath": "$.messages[-1].content",
	})

	ctx := newRequestContextWithBody(`{"messages":[{"role":"user","content":"hello"}]}`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Invalid configuration for string target")
}

func TestPromptDecoratorPolicy_OnRequest_TargetTypeMismatch_ArrayPathWithTextConfig(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "x",
		},
		"jsonPath": "$.messages",
	})

	ctx := newRequestContextWithBody(`{"messages":[{"role":"user","content":"hello"}]}`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Invalid configuration for messages target")
}

func TestPromptDecoratorPolicy_OnRequest_ArrayContainsNonMapElementReturnsError(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{"role": "system", "content": "x"},
			},
		},
		"jsonPath": "$.messages",
	})

	ctx := newRequestContextWithBody(`{"messages":[1,{"role":"user","content":"hello"}]}`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Array contains non-map elements")
}

func TestPromptDecoratorPolicy_OnRequest_ExtractedValueWrongTypeReturnsError(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "x",
		},
		"jsonPath": "$.temperature",
	})

	ctx := newRequestContextWithBody(`{"temperature":0.7}`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Extracted value must be a string or an array of message objects")
}

func TestPromptDecoratorPolicy_OnRequest_JSONPathWithArrayIndex_TextTarget(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "Decorate",
		},
		"jsonPath": "$.messages[0].content",
	})

	ctx := newRequestContextWithBody(`{
		"messages":[
			{"role":"user","content":"first"},
			{"role":"assistant","content":"second"}
		]
	}`)
	action := p.OnRequest(ctx, nil)
	mods := mustRequestMods(t, action)

	payload := decodeJSONMap(t, mods.Body)
	messages := mustMessages(t, payload["messages"])
	if got := messages[0]["content"]; got != "Decorate first" {
		t.Fatalf("unexpected first message content: %v", got)
	}
	if got := messages[1]["content"]; got != "second" {
		t.Fatalf("unexpected second message content: %v", got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_JSONPathNavigationFailure(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "Decorate",
		},
		"jsonPath": "$.messages[0].content",
	})

	// ExtractValueFromJsonpath accepts this path (messages[0].content exists),
	// but update path navigation fails because messages is object, not array.
	ctx := newRequestContextWithBody(`{
		"messages":{"0":{"content":"hello"}}
	}`)
	action := p.OnRequest(ctx, nil)
	assertDecoratorError(t, action, "Error extracting value from JSONPath")
}

func TestPromptDecoratorPolicy_OnRequest_JSONPathEmptyStringUsesDefaultByConfigType(t *testing.T) {
	textPolicy := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{"text": "Prefix"},
		"jsonPath":              "",
	})
	if got := textPolicy.params.JsonPath; got != defaultTextDecorationJSONPath {
		t.Fatalf("expected text default path %q, got %q", defaultTextDecorationJSONPath, got)
	}

	messagesPolicy := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{"role": "system", "content": "x"},
			},
		},
		"jsonPath": "",
	})
	if got := messagesPolicy.params.JsonPath; got != defaultMessagesDecorationJSONPath {
		t.Fatalf("expected messages default path %q, got %q", defaultMessagesDecorationJSONPath, got)
	}
}

func TestPromptDecoratorPolicy_OnRequest_ConcurrentAccess(t *testing.T) {
	p := mustGetPromptDecoratorPolicy(t, map[string]interface{}{
		"promptDecoratorConfig": map[string]interface{}{
			"text": "Guardrail:",
		},
	})

	const workers = 50
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()

			msg := fmt.Sprintf("prompt-%d", i)
			ctx := newRequestContextWithBody(fmt.Sprintf(`{"messages":[{"role":"user","content":"%s"}]}`, msg))

			action := p.OnRequest(ctx, nil)
			mods, ok := action.(policy.UpstreamRequestModifications)
			if !ok {
				errCh <- fmt.Errorf("expected UpstreamRequestModifications, got %T", action)
				return
			}
			payload := decodeJSONMapNoFail(mods.Body)
			if payload == nil {
				errCh <- fmt.Errorf("failed to decode modified payload")
				return
			}
			messages := mustMessagesNoFail(payload["messages"])
			if messages == nil || len(messages) != 1 {
				errCh <- fmt.Errorf("invalid messages after modification")
				return
			}
			want := "Guardrail: " + msg
			if got, _ := messages[0]["content"].(string); got != want {
				errCh <- fmt.Errorf("unexpected decorated content: got %q, want %q", got, want)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func mustGetPromptDecoratorPolicy(t *testing.T, params map[string]interface{}) *PromptDecoratorPolicy {
	t.Helper()

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	policyImpl, ok := p.(*PromptDecoratorPolicy)
	if !ok {
		t.Fatalf("expected *PromptDecoratorPolicy, got %T", p)
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

func assertDecoratorError(t *testing.T, action policy.RequestAction, wantMessagePrefix string) policy.ImmediateResponse {
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
		t.Fatalf("failed to unmarshal error response body: %v", err)
	}
	if got := body["type"]; got != "PROMPT_DECORATOR_ERROR" {
		t.Fatalf("unexpected error type: got %v, want %q", got, "PROMPT_DECORATOR_ERROR")
	}
	msg, ok := body["message"].(string)
	if !ok {
		t.Fatalf("expected string error message, got %T", body["message"])
	}
	if !strings.HasPrefix(msg, wantMessagePrefix) {
		t.Fatalf("unexpected error message: got %q, want prefix %q", msg, wantMessagePrefix)
	}

	return resp
}

func decodeJSONMap(t *testing.T, payload []byte) map[string]interface{} {
	t.Helper()
	result := decodeJSONMapNoFail(payload)
	if result == nil {
		t.Fatalf("failed to decode JSON payload: %s", string(payload))
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

func mustMessages(t *testing.T, v interface{}) []map[string]interface{} {
	t.Helper()
	msgs := mustMessagesNoFail(v)
	if msgs == nil {
		t.Fatalf("expected []map[string]interface{}, got %T", v)
	}
	return msgs
}

func mustMessagesNoFail(v interface{}) []map[string]interface{} {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		msg, ok := item.(map[string]interface{})
		if !ok {
			return nil
		}
		out = append(out, msg)
	}
	return out
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
