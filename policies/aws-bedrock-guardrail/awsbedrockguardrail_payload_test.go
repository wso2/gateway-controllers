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

// An LLM token stream with no assistant text (a tool-call-only answer) still
// passes on the buffered path: the JSON-RPC route above must not catch it.
func TestResponse_LLMStreamWithoutTextStillPasses(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)

	body := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n\ndata: [DONE]\n\n"
	mod, ok := sendResponse(p, map[string]interface{}{}, body).(policy.DownstreamResponseModifications)
	if !ok || mod.StatusCode != nil {
		t.Fatalf("expected a text-free token stream to pass, got %#v", mod)
	}
	if client.calls != 0 {
		t.Fatalf("expected no guardrail call for a stream with no text, got %d", client.calls)
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
