/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package awsbedrockguardrail

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// requestPolicy is a request-only attachment backed by the given client.
func requestPolicy(client bedrockGuardrailClient, jsonPath string) *AWSBedrockGuardrailPolicy {
	return &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		hasRequestParams: true,
		requestParams:    AWSBedrockGuardrailPolicyParams{Enabled: true, JsonPath: jsonPath},
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient { return client },
	}
}

func sendRequest(p *AWSBedrockGuardrailPolicy, metadata map[string]interface{}, body string) policy.RequestAction {
	return p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: []byte(body)},
	}, map[string]interface{}{})
}

func sendResponse(p *AWSBedrockGuardrailPolicy, metadata map[string]interface{}, body string) policy.ResponseAction {
	return p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{Metadata: metadata},
		ResponseStatus: 200,
		ResponseBody:   &policy.Body{Content: []byte(body)},
	}, map[string]interface{}{})
}

func awsKeyBlockedOutput() *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{
			SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
				PiiEntities: []types.GuardrailPiiEntityFilter{{
					Action: types.GuardrailSensitiveInformationPolicyActionBlocked,
					Match:  aws.String("AKIAIOSFODNN7EXAMPLE"),
					Type:   types.GuardrailPiiEntityTypeAwsAccessKey,
				}},
			},
		}},
	}
}

// An MCP initialize or tools/list carries no tool arguments. Policies on an MCP
// proxy see every message, so a request path aimed at tool arguments must let
// these through without a guardrail call rather than reject the handshake.
func TestRequest_JSONRPCWithoutArgumentsPassesWithoutACall(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := requestPolicy(client, "$.params.arguments")

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		mod, ok := sendRequest(p, map[string]interface{}{}, body).(policy.UpstreamRequestModifications)
		if !ok || mod.Body != nil {
			t.Fatalf("%s: expected an unchanged pass, got %#v", body, mod)
		}
	}
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call for messages without tool arguments, got %d", client.calls)
	}

	// A body that is not JSON-RPC still fails extraction: it has no protocol
	// vouching that "no arguments" means "nothing to check".
	if _, ok := sendRequest(p, map[string]interface{}{}, `{"other":true}`).(policy.ImmediateResponse); !ok {
		t.Fatalf("expected a non-JSON-RPC body the path does not match to be rejected")
	}
}

// An object path checks every string inside it, in one ApplyGuardrail call with
// one content block per value.
func TestRequest_ObjectPathChecksEveryArgumentInOneCall(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := requestPolicy(client, "$.params.arguments")

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup","arguments":{"text":"Order 42 shipped.","note":"Leave it at the desk."}}}`
	if _, ok := sendRequest(p, map[string]interface{}{}, body).(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected the clean tool call to pass")
	}
	if client.calls != 1 {
		t.Fatalf("expected one ApplyGuardrail call, got %d", client.calls)
	}
	if len(client.texts) != 2 || client.texts[0] != "Leave it at the desk." || client.texts[1] != "Order 42 shipped." {
		t.Fatalf("expected both arguments as separate content blocks, got %q", client.texts)
	}
}

// A [*] path reaches every element; a violation in any of them blocks.
func TestResponse_WildcardPathIsAssessed(t *testing.T) {
	client := &countingBedrockClient{output: awsKeyBlockedOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.result.content[*].text"
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"},{"type":"text","text":"Key: AKIAIOSFODNN7EXAMPLE"}]}}`
	expectGuardrailBlock(t, 200, sendResponse(p, map[string]interface{}{}, body))
	if len(client.texts) != 2 {
		t.Fatalf("expected both content elements assessed, got %q", client.texts)
	}
}

// PII the upstream introduced is masked with its type. Before, the response phase
// assumed every reported value was a placeholder the request had put there, and
// delivered it unchanged.
func TestResponse_NewPIIIsMaskedWithItsType(t *testing.T) {
	client := &mockBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := newMockedResponsePolicy(t, client, "")

	result := sendResponse(p, map[string]interface{}{},
		`{"output":{"message":{"content":[{"text":"Contact john@example.com today."}]}}}`)
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode != nil {
		t.Fatalf("expected the masked response to pass, got %#v", result)
	}
	if got := string(mod.Body); !strings.Contains(got, "Contact {EMAIL} today.") || strings.Contains(got, "john@example.com") {
		t.Fatalf("expected the email masked as {EMAIL}, got %s", got)
	}
}

// A value the request masked and the response restored is assessed (so a block
// still applies) but not masked again: the client sent it.
func TestResponse_RestoredValueIsNotMaskedAgain(t *testing.T) {
	client := &mockBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := newMockedResponsePolicy(t, client, "")
	metadata := map[string]interface{}{
		MetadataKeyPIIEntities: map[string]string{"john@example.com": "EMAIL_0000"},
	}

	result := sendResponse(p, metadata,
		`{"output":{"message":{"content":[{"text":"I will write to EMAIL_0000."}]}}}`)
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode != nil {
		t.Fatalf("expected the response to pass, got %#v", result)
	}
	if got := string(mod.Body); !strings.Contains(got, "I will write to john@example.com.") {
		t.Fatalf("expected the restored email, got %s", got)
	}
	if text := aws.ToString(client.lastInput.Content[0].(*types.GuardrailContentBlockMemberText).Value.Text); !strings.Contains(text, "john@example.com") {
		t.Fatalf("expected the restored text to be what was assessed, got %q", text)
	}
}

// An MCP Streamable HTTP response is SSE whose events carry JSON-RPC messages.
// With only jsonPath configured, the default streamingJsonPath matched nothing in
// them and the result was delivered unassessed.
func TestResponse_MCPEventStreamIsAssessedWithJSONPath(t *testing.T) {
	client := &countingBedrockClient{output: awsKeyBlockedOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.result.content[*].text"
	})

	body := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Key: AKIAIOSFODNN7EXAMPLE\"}]}}\n\n"
	expectGuardrailBlock(t, 200, sendResponse(p, map[string]interface{}{}, body))
	if client.calls != 1 || len(client.texts) != 1 || client.texts[0] != "Key: AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("expected the tool result text to be assessed once, got calls=%d texts=%q", client.calls, client.texts)
	}
}

// Masking an MCP event stream rewrites the changed event and keeps the framing.
func TestResponse_MCPEventStreamMasksInPlace(t *testing.T) {
	client := &mockBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.result.content[*].text"
	})

	body := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Contact john@example.com\"}]}}\n\n"
	mod, ok := sendResponse(p, map[string]interface{}{}, body).(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode != nil {
		t.Fatalf("expected the masked stream to pass, got %#v", mod)
	}
	got := string(mod.Body)
	if !strings.Contains(got, "Contact {EMAIL}") || strings.Contains(got, "john@example.com") {
		t.Fatalf("expected the email masked, got %q", got)
	}
	if strings.Count(got, "event: message\n") != 2 || !strings.Contains(got, "notifications/progress") {
		t.Fatalf("expected both events and their framing kept, got %q", got)
	}
}

// An LLM token stream with no assistant text still passes on the buffered path:
// the JSON-RPC route above must not catch it. A tool-call answer is not one of
// those: its arguments are model output streamingJsonPath does not read.
func TestResponse_LLMStreamWithoutTextStillPasses(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)

	body := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":null}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3}}\n\ndata: [DONE]\n\n"
	mod, ok := sendResponse(p, map[string]interface{}{}, body).(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode != nil {
		t.Fatalf("expected a text-free token stream to pass, got %#v", mod)
	}
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call for a stream with no text, got %d", client.calls)
	}

	toolCalls := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n\ndata: [DONE]\n\n"
	mod, ok = sendResponse(p, map[string]interface{}{}, toolCalls).(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode == nil || mod.Fault == nil || mod.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("expected a tool-call stream refused with a mediation fault, got %#v", mod)
	}
}

// An ANONYMIZED finding with no matched text cannot be masked, so delivering the
// content would deliver the value AWS asked to hide.
func TestEvaluate_UnmaskableFindingBlocks(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	output := makePIIIntervenedOutput("")
	violation, _, err := p.evaluateGuardrailResponse(output, "contact someone", false, true, map[string]interface{}{})
	if err != nil || !violation {
		t.Fatalf("expected an unmaskable finding to block, got violation=%v err=%v", violation, err)
	}
}

// Two request attachments on one route share the placeholder map, so the second
// must not hand out EMAIL_0000 again for a different value.
func TestRequest_PlaceholdersContinueAcrossAttachments(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	metadata := map[string]interface{}{}

	if _, masked, _ := p.evaluateGuardrailResponse(makePIIIntervenedOutput("a@example.com"), "to a@example.com", false, true, metadata); masked != "to EMAIL_0000" {
		t.Fatalf("first attachment: got %q", masked)
	}
	if _, masked, _ := p.evaluateGuardrailResponse(makePIIIntervenedOutput("b@example.com"), "to b@example.com", false, true, metadata); masked != "to EMAIL_0001" {
		t.Fatalf("second attachment: got %q", masked)
	}
	placeholders := metadata[MetadataKeyPIIEntities].(map[string]string)
	if placeholders["a@example.com"] != "EMAIL_0000" || placeholders["b@example.com"] != "EMAIL_0001" {
		t.Fatalf("expected both values recorded for restoration, got %#v", placeholders)
	}
}

// The streaming path masks PII the model introduced as well, not only under
// redactPII.
func TestStreaming_NewPIIIsMaskedWithoutRedactPII(t *testing.T) {
	const pii = "john@example.com"
	p := streamingPolicy(&reportsPIIWhenPresentClient{pii: pii}, nil)

	var delivered string
	for _, action := range feedStream(t, p, streamCtx(), []string{
		sseEvent("Please contact "), sseEvent(pii), sseEvent(" for details."),
	}) {
		switch v := action.(type) {
		case policy.ForwardResponseChunk:
			delivered += string(v.Body)
		case policy.TerminateResponseChunk:
			t.Fatalf("expected the stream to complete, it was terminated: %s", v.Body)
		}
	}
	if strings.Contains(delivered, pii) || !strings.Contains(delivered, "{EMAIL}") {
		t.Fatalf("expected the email masked as {EMAIL} in the stream, got %q", delivered)
	}
}

// A placeholder the request put in place is restored in the stream and not
// masked again, though the restored text is what the guardrail assesses.
func TestStreaming_RestoredValueIsNotMaskedAgain(t *testing.T) {
	const pii = "john@example.com"
	p := streamingPolicy(&reportsPIIWhenPresentClient{pii: pii}, nil)
	ctx := streamCtx()
	ctx.Metadata[MetadataKeyPIIEntities] = map[string]string{pii: "EMAIL_0000"}

	var delivered string
	for _, action := range feedStream(t, p, ctx, []string{sseEvent("Writing to "), sseEvent("EMAIL_0000"), sseEvent(" now.")}) {
		if v, ok := action.(policy.ForwardResponseChunk); ok {
			delivered += string(v.Body)
		}
	}
	if !strings.Contains(delivered, pii) || strings.Contains(delivered, "{EMAIL}") {
		t.Fatalf("expected the restored email, got %q", delivered)
	}
}

// Replacements run in one pass over the original text, so a later value never
// rewrites the placeholder an earlier one inserted.
func TestApplyPIIReplacements_DoesNotRewriteInsertedPlaceholders(t *testing.T) {
	got := applyPIIReplacements("mail john@example.com, pin 0000", []piiReplacement{
		{match: "john@example.com", replacement: "EMAIL_0000"},
		{match: "0000", replacement: "PIN_0001"},
	})
	if got != "mail EMAIL_0000, pin PIN_0001" {
		t.Fatalf("expected each value replaced once, got %q", got)
	}
}

// A reported value that starts in the released frames and ends in the withheld
// one is in neither part whole, so neither rewrite would find it.
func TestReportedValueSpans_DetectsValueAcrossTheReleaseBoundary(t *testing.T) {
	p := streamingPolicy(nil, nil)
	rp := p.responseParams
	output := makePIIIntervenedOutput("john@example.com")

	if !p.reportedValueSpans(sseEvent("Mail john@exa"), sseEvent("mple.com now"), output, rp, map[string]interface{}{}) {
		t.Fatalf("expected a value split across the boundary to be detected")
	}
	if p.reportedValueSpans(sseEvent("Mail john@example.com"), sseEvent(" now"), output, rp, map[string]interface{}{}) {
		t.Fatalf("a value wholly inside the released frames is rewritten there, not a span")
	}
	if p.reportedValueSpans(sseEvent("Mail "), sseEvent("john@example.com now"), output, rp, map[string]interface{}{}) {
		t.Fatalf("a value wholly inside the retained frame is not a span")
	}
}

// A JSON-RPC message split over several data lines is still an MCP event: the
// lines are joined before it is classified, so it is not mistaken for an LLM
// token stream and passed unassessed.
func TestResponse_MultiLineJSONRPCEventIsAssessed(t *testing.T) {
	client := &countingBedrockClient{output: awsKeyBlockedOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.result.content[*].text"
	})

	body := "event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":2,\n" +
		"data: \"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Key: AKIAIOSFODNN7EXAMPLE\"}]}}\n\n"
	if !sseCarriesJSONRPC([]byte(body)) {
		t.Fatalf("expected the multi-line event to be classified as JSON-RPC")
	}
	expectGuardrailBlock(t, 200, sendResponse(p, map[string]interface{}{}, body))
	if client.calls != 1 {
		t.Fatalf("expected the tool result to be assessed once, got %d calls", client.calls)
	}
}

// --- fallbackJsonPaths ---------------------------------------------------------

// fallbackPathsAttachment builds the policy through GetPolicy with a fake Bedrock client.
func fallbackPathsAttachment(t *testing.T, flow string, flowParams map[string]interface{}, client bedrockGuardrailClient) *AWSBedrockGuardrailPolicy {
	t.Helper()
	params := baseParams()
	params[flow] = flowParams
	p := mustGetPolicy(t, params)
	p.loadAWSConfigFunc = func(context.Context, string) (aws.Config, error) { return aws.Config{}, nil }
	p.newBedrockClientFunc = func(aws.Config) bedrockGuardrailClient { return client }
	return p
}

// paths returns fallbackJsonPaths as the gateway delivers it.
func paths(p ...string) []interface{} {
	out := make([]interface{}, len(p))
	for i, s := range p {
		out[i] = s
	}
	return out
}

const (
	chatCompletionsBody  = `{"model":"m","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"hello chat"}]}`
	responsesStringBody  = `{"model":"m","input":"hello responses"}`
	responsesItemsBody   = `{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":"hello items"}]}]}`
	notOpenAIRequestBody = `{"model":"m","prompt":"legacy completions"}`
	bothFormatsBody      = `{"messages":[{"role":"user","content":"from messages"}],"input":"from input"}`
)

var openAIRequestPaths = paths(
	"$.messages[-1].content",
	"$.input[-1].content[*].text",
	"$.input",
)

func TestFallbackJSONPaths_InvalidConfigurationIsRejected(t *testing.T) {
	tests := []struct {
		name      string
		fallbacks interface{}
		want      string
	}{
		{"not an array", "$.messages[-1].content", "'fallbackJsonPaths' must be an array of strings"},
		{"non-string entry", []interface{}{"$.input", 42}, "'fallbackJsonPaths' must be an array of strings"},
		{"empty entry", paths("$.input", "  "), "'fallbackJsonPaths' entries must not be empty"},
		{"malformed entry", paths("$.input", "$.messages[-1"), "invalid 'fallbackJsonPaths' entry"},
	}
	for _, flow := range []string{"request", "response"} {
		for _, tt := range tests {
			t.Run(flow+"/"+tt.name, func(t *testing.T) {
				params := baseParams()
				params[flow] = map[string]interface{}{"enabled": true, "fallbackJsonPaths": tt.fallbacks}
				expectGetPolicyError(t, params, tt.want)
			})
		}
	}
}

func TestRequest_FallbackJSONPathsAloneAreTriedInOrder(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"chat completions hits the first path", chatCompletionsBody, []string{"hello chat"}},
		{"responses items hit the second path", responsesItemsBody, []string{"hello items"}},
		{"responses string falls through to the last path", responsesStringBody, []string{"hello responses"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &countingBedrockClient{output: makeNoInterventionOutput()}
			p := fallbackPathsAttachment(t, "request", map[string]interface{}{"fallbackJsonPaths": openAIRequestPaths}, client)

			action := sendRequest(p, map[string]interface{}{}, tt.body)
			if mod, ok := action.(policy.UpstreamRequestModifications); !ok || mod.Body != nil {
				t.Fatalf("expected the clean request to pass unchanged, got %#v", action)
			}
			if !reflect.DeepEqual(client.texts, tt.want) {
				t.Fatalf("assessed %q, want %q", client.texts, tt.want)
			}
		})
	}
}

func TestRequest_JSONPathIsTriedBeforeFallbackJSONPaths(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":          "$.messages[-1].content",
		"fallbackJsonPaths": paths("$.input"),
	}, client)

	sendRequest(p, map[string]interface{}{}, bothFormatsBody)
	if !reflect.DeepEqual(client.texts, []string{"from messages"}) {
		t.Fatalf("assessed %q, want the jsonPath match", client.texts)
	}
}

func TestRequest_FallbackJSONPathsAreTriedWhenJSONPathMisses(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"first fallback", responsesItemsBody, []string{"hello items"}},
		{"second fallback", responsesStringBody, []string{"hello responses"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &countingBedrockClient{output: makeNoInterventionOutput()}
			p := fallbackPathsAttachment(t, "request", map[string]interface{}{
				"jsonPath":          "$.messages[-1].content",
				"fallbackJsonPaths": paths("$.input[-1].content[*].text", "$.input"),
			}, client)

			sendRequest(p, map[string]interface{}{}, tt.body)
			if !reflect.DeepEqual(client.texts, tt.want) {
				t.Fatalf("assessed %q, want %q", client.texts, tt.want)
			}
		})
	}
}

// Without jsonPath, only the fallback paths are tried; the default jsonPath is not added.
func TestRequest_FallbackJSONPathsWithoutJSONPathSkipTheDefault(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"fallbackJsonPaths": paths("$.input"),
	}, client)

	sendRequest(p, map[string]interface{}{}, bothFormatsBody)
	if !reflect.DeepEqual(client.texts, []string{"from input"}) {
		t.Fatalf("assessed %q, want only the fallback match", client.texts)
	}
}

// The editor sends [] for an untouched array; jsonPath alone applies.
func TestRequest_EmptyFallbackJSONPathsKeepJSONPath(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":          "$.input",
		"fallbackJsonPaths": []interface{}{},
	}, client)

	sendRequest(p, map[string]interface{}{}, responsesStringBody)
	if !reflect.DeepEqual(client.texts, []string{"hello responses"}) {
		t.Fatalf("assessed %q, want the jsonPath match", client.texts)
	}
}

func TestRequest_FallbackJSONPathsSkipAPathThatFindsNoText(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":          "$.messages[-1].content",
		"fallbackJsonPaths": paths("$.input"),
	}, client)

	sendRequest(p, map[string]interface{}{}, `{"messages":[{"role":"user","content":"   "}],"input":"hello"}`)
	if !reflect.DeepEqual(client.texts, []string{"hello"}) {
		t.Fatalf("assessed %q, want the text the fallback reaches", client.texts)
	}
}

func TestRequest_FallbackJSONPathsLetAPayloadWithNothingToAssessPass(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":          "$.params.arguments",
		"fallbackJsonPaths": paths("$.params.input"),
	}, client)

	body := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`
	if mod, ok := sendRequest(p, map[string]interface{}{}, body).(policy.UpstreamRequestModifications); !ok || mod.Body != nil {
		t.Fatalf("expected the handshake to pass unchanged")
	}
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call, got %d", client.calls)
	}
}

func TestRequest_NoHitIsRejectedAsASingleMissIs(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":          "$.messages[-1].content",
		"fallbackJsonPaths": paths("$.input[-1].content[*].text", "$.input"),
	}, client)

	resp, ok := sendRequest(p, map[string]interface{}{}, notOpenAIRequestBody).(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected the request to be refused")
	}
	if resp.StatusCode != 422 {
		t.Fatalf("status %d, want 422", resp.StatusCode)
	}
	var body struct {
		Type    string `json:"type"`
		Message struct {
			ActionReason string `json:"actionReason"`
		} `json:"message"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Type != "AWS_BEDROCK_GUARDRAIL" || body.Message.ActionReason != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected body %s", resp.Body)
	}
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected a declared fault, got IsFault=%v Fault=%v", resp.IsFault, resp.Fault)
	}
	if resp.Fault.Code != policy.FaultCodeInvalidRequestBody || resp.Fault.Type != policy.FaultTypeValidation {
		t.Fatalf("fault %s/%s, want %s/%s", resp.Fault.Code, resp.Fault.Type, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	}
	for _, path := range []string{"$.messages[-1].content", "$.input[-1].content[*].text", "$.input"} {
		if !strings.Contains(resp.Fault.Description, path) {
			t.Fatalf("fault description %q does not name the path %q that was tried", resp.Fault.Description, path)
		}
	}
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call, got %d", client.calls)
	}
}

func TestRequest_NoHitPassesWithPassthroughOnError(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":           "$.messages[-1].content",
		"fallbackJsonPaths":  paths("$.input"),
		"passthroughOnError": true,
	}, client)

	if mod, ok := sendRequest(p, map[string]interface{}{}, notOpenAIRequestBody).(policy.UpstreamRequestModifications); !ok || mod.Body != nil {
		t.Fatalf("expected the request to pass unchanged")
	}
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call, got %d", client.calls)
	}
}

func TestRequest_FallbackJSONPathsMaskAtThePathThatHit(t *testing.T) {
	client := &mockBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := fallbackPathsAttachment(t, "request", map[string]interface{}{
		"jsonPath":          "$.messages[-1].content",
		"fallbackJsonPaths": paths("$.input"),
		"redactPII":         true,
	}, client)

	mod, ok := sendRequest(p, map[string]interface{}{}, `{"model":"m","input":"Mail john@example.com today"}`).(policy.UpstreamRequestModifications)
	if !ok || mod.Body == nil {
		t.Fatalf("expected the request to pass with a redacted body")
	}
	var got map[string]interface{}
	if err := json.Unmarshal(mod.Body, &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	want := map[string]interface{}{"model": "m", "input": "Mail ***** today"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body %s, want %v", mod.Body, want)
	}
}

func TestResponse_FallbackJSONPathsAreTriedWhenJSONPathMisses(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "$.choices[0].message.content",
		"fallbackJsonPaths": paths("$.output[*].content[*].text"),
	}, client)

	body := `{"id":"resp_1","output":[{"type":"reasoning","summary":[]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"The answer is 42."}]}]}`
	if mod, ok := sendResponse(p, map[string]interface{}{}, body).(policy.DownstreamResponseModifications); !ok || mod.StatusCode != nil {
		t.Fatalf("expected the clean response to pass")
	}
	if !reflect.DeepEqual(client.texts, []string{"The answer is 42."}) {
		t.Fatalf("assessed %q, want the Responses API output text", client.texts)
	}
}

// With fallback paths set, an empty jsonPath does not mean "assess the whole body".
func TestStreaming_FallbackJSONPathsWithAnEmptyJSONPath(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "",
		"fallbackJsonPaths": paths("$.choices[0].message.content"),
	}, client)

	feedStream(t, p, streamCtxWithType("text/event-stream"), []string{sseEvent("Hello"), sseEvent(" world"), "data: [DONE]\n\n"})
	if got := strings.Join(client.texts, ""); got != "Hello world" {
		t.Fatalf("assessed %q, want only the streamed text", got)
	}
}

func TestStreaming_JSONPathWithFallbackJSONPathsReadsEvents(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "$.choices[0].message.content",
		"fallbackJsonPaths": paths("$.output[*].content[*].text"),
	}, client)

	feedStream(t, p, streamCtxWithType("text/event-stream"), []string{sseEvent("Hello"), sseEvent(" world"), "data: [DONE]\n\n"})
	if got := strings.Join(client.texts, ""); got != "Hello world" {
		t.Fatalf("assessed %q, want only the streamed text", got)
	}
}

func TestBufferedEventStream_JSONPathWithFallbackJSONPathsReadsEvents(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "$.choices[0].message.content",
		"fallbackJsonPaths": paths("$.output[*].content[*].text"),
	}, client)

	body := sseEvent("Hello") + sseEvent(" world") + "data: [DONE]\n\n"
	action := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), map[string]interface{}{})
	if mod, ok := action.(policy.DownstreamResponseModifications); !ok || mod.StatusCode != nil {
		t.Fatalf("expected the clean stream to pass, got %#v", action)
	}
	if got := strings.Join(client.texts, ""); got != "Hello world" {
		t.Fatalf("assessed %q, want only the streamed text", got)
	}
}

func TestBufferedEventStream_FallbackJSONPathsWithAnEmptyJSONPath(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "",
		"fallbackJsonPaths": paths("$.choices[0].message.content"),
	}, client)

	body := sseEvent("Hello") + sseEvent(" world") + "data: [DONE]\n\n"
	action := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), map[string]interface{}{})
	if mod, ok := action.(policy.DownstreamResponseModifications); !ok || mod.StatusCode != nil {
		t.Fatalf("expected the clean stream to pass, got %#v", action)
	}
	if got := strings.Join(client.texts, ""); got != "Hello world" {
		t.Fatalf("assessed %q, want only the streamed text", got)
	}
}

// An MCP Streamable HTTP response whose events have different shapes: a log
// notification, then the tool result.
const (
	mcpLogEvent    = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"Looking up john@example.com\"}}\n\n"
	mcpResultEvent = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Order shipped\"}]}}\n\n"
)

func mixedMCPStreamParams(fallback string) map[string]interface{} {
	return map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "$.result.content[*].text",
		"fallbackJsonPaths": paths(fallback),
	}
}

func TestResponse_EventStreamEventsUseTheirOwnPath(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", mixedMCPStreamParams("$.params.data"), client)

	action := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", mcpLogEvent+mcpResultEvent), map[string]interface{}{})
	if mod, ok := action.(policy.DownstreamResponseModifications); !ok || mod.StatusCode != nil {
		t.Fatalf("expected the stream to pass, got %#v", action)
	}
	if want := []string{"Looking up john@example.com", "Order shipped"}; !reflect.DeepEqual(client.texts, want) {
		t.Fatalf("assessed %q, want %q", client.texts, want)
	}
}

func TestStreaming_EventStreamEventsUseTheirOwnPath(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", mixedMCPStreamParams("$.params.data"), client)

	for _, action := range feedStream(t, p, streamCtxWithType("text/event-stream"), []string{mcpLogEvent + mcpResultEvent}) {
		if action.TerminateStream() {
			t.Fatalf("expected the stream to continue, got %#v", action)
		}
	}
	if want := []string{"Looking up john@example.com", "Order shipped"}; !reflect.DeepEqual(client.texts, want) {
		t.Fatalf("assessed %q, want %q", client.texts, want)
	}
}

func TestResponse_EventStreamMasksEachEventAtItsOwnPath(t *testing.T) {
	client := &mockBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	params := mixedMCPStreamParams("$.params.data")
	params["redactPII"] = true
	p := fallbackPathsAttachment(t, "response", params, client)

	action := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", mcpLogEvent+mcpResultEvent), map[string]interface{}{})
	mod, ok := action.(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode != nil || mod.Body == nil {
		t.Fatalf("expected the stream to pass with a masked body, got %#v", action)
	}
	body := string(mod.Body)
	if !strings.Contains(body, `"data":"Looking up *****"`) || strings.Contains(body, "john@example.com") {
		t.Fatalf("expected the log event masked at params.data, got %s", body)
	}
	if !strings.Contains(body, mcpResultEvent) {
		t.Fatalf("expected the result event unchanged, got %s", body)
	}
}

func TestResponse_EventStreamEventNoPathMatchesIsMissed(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", mixedMCPStreamParams("$.params.other"), client)

	action := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", mcpLogEvent+mcpResultEvent), map[string]interface{}{})
	expectGuardrailBlock(t, 200, action)
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call, got %d", client.calls)
	}
}

func TestResponse_EventStreamEventSkipsAPathWithBlankText(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := fallbackPathsAttachment(t, "response", map[string]interface{}{
		"enabled":           true,
		"jsonPath":          "$.params.data",
		"fallbackJsonPaths": paths("$.params.logger"),
	}, client)

	event := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"   \",\"logger\":\"order lookup\"}}\n\n"
	action := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", event), map[string]interface{}{})
	if mod, ok := action.(policy.DownstreamResponseModifications); !ok || mod.StatusCode != nil {
		t.Fatalf("expected the stream to pass, got %#v", action)
	}
	if want := []string{"order lookup"}; !reflect.DeepEqual(client.texts, want) {
		t.Fatalf("assessed %q, want %q", client.texts, want)
	}
}
