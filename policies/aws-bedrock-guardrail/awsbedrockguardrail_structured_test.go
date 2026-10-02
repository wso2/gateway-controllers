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

func structuredTestPolicy(client *mockBedrockClient, params AWSBedrockGuardrailPolicyParams) *AWSBedrockGuardrailPolicy {
	params.Enabled = true
	return &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		hasRequestParams: true,
		requestParams:    params,
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient { return client },
	}
}

func piiAnonymizedOutput(matches ...string) *bedrockruntime.ApplyGuardrailOutput {
	entities := make([]types.GuardrailPiiEntityFilter, 0, len(matches))
	for _, m := range matches {
		entities = append(entities, types.GuardrailPiiEntityFilter{
			Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
			Match:  aws.String(m),
			Type:   types.GuardrailPiiEntityTypeEmail,
		})
	}
	return &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{
			SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{PiiEntities: entities},
		}},
	}
}

func requestCtx(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Content: []byte(body)},
	}
}

func sentText(t *testing.T, client *mockBedrockClient) string {
	t.Helper()
	if client.lastInput == nil {
		t.Fatalf("expected ApplyGuardrail to be called")
	}
	return aws.ToString(client.lastInput.Content[0].(*types.GuardrailContentBlockMemberText).Value.Text)
}

// Every field of an object state reaches the guardrail, where it used to be rejected as an
// extraction error.
func TestOnRequest_StructuredState_SendsEveryField(t *testing.T) {
	client := &mockBedrockClient{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}}
	p := structuredTestPolicy(client, AWSBedrockGuardrailPolicyParams{JsonPath: "$.state"})

	result := p.OnRequestBody(context.Background(), requestCtx(`{"state":{"ticket":"refund please","notes":"vip customer"},"model":"jev-latest"}`), nil)
	if mods, ok := result.(policy.UpstreamRequestModifications); !ok || mods.Body != nil {
		t.Fatalf("expected an unmodified pass, got %#v", result)
	}
	text := sentText(t, client)
	if !strings.Contains(text, "refund please") || !strings.Contains(text, "vip customer") {
		t.Fatalf("expected both fields in the guardrail input, got %q", text)
	}
	if strings.Contains(text, "jev-latest") {
		t.Fatalf("expected fields outside the JSONPath to stay out of the guardrail input, got %q", text)
	}
}

func TestOnRequest_WildcardQuestions_SendsEveryInstruction(t *testing.T) {
	client := &mockBedrockClient{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}}
	p := structuredTestPolicy(client, AWSBedrockGuardrailPolicyParams{JsonPath: "$.questions.*.instructions"})

	p.OnRequestBody(context.Background(), requestCtx(`{"questions":{"a":{"instructions":"Is it urgent?"},"b":{"instructions":"Which team?"}}}`), nil)
	text := sentText(t, client)
	if !strings.Contains(text, "Is it urgent?") || !strings.Contains(text, "Which team?") {
		t.Fatalf("expected every instruction in the guardrail input, got %q", text)
	}
}

// Masking a structured value writes placeholders into each field and stores one mapping, so the
// response is restored correctly.
func TestOnRequest_StructuredState_MasksEachField(t *testing.T) {
	client := &mockBedrockClient{output: piiAnonymizedOutput("a.user@example.com", "b.user@example.com")}
	p := structuredTestPolicy(client, AWSBedrockGuardrailPolicyParams{JsonPath: "$.state"})

	ctx := requestCtx(`{"state":{"ticket":"mail a.user@example.com","cc":["b.user@example.com"]},"model":"jev-latest"}`)
	mods, ok := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	if !ok || mods.Body == nil {
		t.Fatalf("expected a masked body")
	}
	body := string(mods.Body)
	if strings.Contains(body, "@example.com") {
		t.Fatalf("expected every email to be masked, got %s", body)
	}
	if !strings.Contains(body, `"model":"jev-latest"`) {
		t.Fatalf("expected fields outside the JSONPath to be untouched, got %s", body)
	}
	mapping, ok := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if !ok || len(mapping) != 2 || mapping["a.user@example.com"] == mapping["b.user@example.com"] {
		t.Fatalf("expected one distinct placeholder per email, got %#v", ctx.Metadata[MetadataKeyPIIEntities])
	}
	if !strings.Contains(body, mapping["a.user@example.com"]) || !strings.Contains(body, mapping["b.user@example.com"]) {
		t.Fatalf("expected the stored placeholders in the body, got %s", body)
	}
}

func TestOnRequest_StructuredState_RedactsEachField(t *testing.T) {
	client := &mockBedrockClient{output: piiAnonymizedOutput("a.user@example.com")}
	p := structuredTestPolicy(client, AWSBedrockGuardrailPolicyParams{JsonPath: "$.state", RedactPII: true})

	mods, ok := p.OnRequestBody(context.Background(), requestCtx(`{"state":{"ticket":"mail a.user@example.com","status":"open"}}`), nil).(policy.UpstreamRequestModifications)
	if !ok || mods.Body == nil {
		t.Fatalf("expected a redacted body")
	}
	body := string(mods.Body)
	if strings.Contains(body, "a.user@example.com") || !strings.Contains(body, "mail *****") {
		t.Fatalf("expected the email to be redacted in place, got %s", body)
	}
	if !strings.Contains(body, `"status":"open"`) {
		t.Fatalf("expected fields without PII to be untouched, got %s", body)
	}
}

// A path that selects no text fails closed rather than skipping the guardrail.
func TestOnRequest_StructuredState_NoTextFailsClosed(t *testing.T) {
	client := &mockBedrockClient{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}}
	p := structuredTestPolicy(client, AWSBedrockGuardrailPolicyParams{JsonPath: "$.state"})

	result := p.OnRequestBody(context.Background(), requestCtx(`{"state":{"a":null}}`), nil)
	if _, ok := result.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected an ImmediateResponse, got %T", result)
	}
	if client.lastInput != nil {
		t.Fatalf("expected no guardrail call")
	}
}
