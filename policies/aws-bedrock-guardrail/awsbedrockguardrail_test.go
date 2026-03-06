package awsbedrockguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

type mockBedrockClient struct {
	output    *bedrockruntime.ApplyGuardrailOutput
	err       error
	lastInput *bedrockruntime.ApplyGuardrailInput
}

func (m *mockBedrockClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	m.lastInput = params
	return m.output, m.err
}

func baseParams() map[string]interface{} {
	return map[string]interface{}{
		"region":           "us-east-1",
		"guardrailID":      "gr-123",
		"guardrailVersion": "DRAFT",
	}
}

func makePIIIntervenedOutput(match string) *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{
			{
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					PiiEntities: []types.GuardrailPiiEntityFilter{
						{
							Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
							Match:  aws.String(match),
							Type:   types.GuardrailPiiEntityTypeEmail,
						},
					},
					Regexes: []types.GuardrailRegexFilter{},
				},
			},
		},
	}
}

func TestGetPolicy_ValidatesRequiredAndPhaseParams(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "'region' parameter is required") {
		t.Fatalf("expected missing region error, got: %v", err)
	}

	params := baseParams()
	_, err = GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request' or 'response' parameters must be provided") {
		t.Fatalf("expected missing phase params error, got: %v", err)
	}

	params["request"] = map[string]interface{}{
		"jsonPath": 1, // invalid type
	}
	_, err = GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil || !strings.Contains(err.Error(), "invalid request parameters") {
		t.Fatalf("expected invalid request params error, got: %v", err)
	}
}

func TestGetPolicy_RequestRedactForcesResponseRedact(t *testing.T) {
	params := baseParams()
	params["request"] = map[string]interface{}{
		"redactPII": true,
	}
	params["response"] = map[string]interface{}{
		"redactPII": false,
	}

	pRaw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}

	p, ok := pRaw.(*AWSBedrockGuardrailPolicy)
	if !ok {
		t.Fatalf("unexpected policy type: %T", pRaw)
	}
	if !p.hasRequestParams || !p.hasResponseParams {
		t.Fatalf("expected both request and response params to be present")
	}
	if !p.requestParams.RedactPII {
		t.Fatalf("expected request redactPII to be true")
	}
	if !p.requestParams.Enabled {
		t.Fatalf("expected request enabled by default")
	}
	if p.requestParams.JsonPath != RequestDefaultJSONPath {
		t.Fatalf("expected request jsonPath default %q, got %q", RequestDefaultJSONPath, p.requestParams.JsonPath)
	}
	if !p.responseParams.RedactPII {
		t.Fatalf("expected response redactPII to be forced true when request redactPII is true")
	}
	if p.responseParams.JsonPath != ResponseDefaultJSONPath {
		t.Fatalf("expected response jsonPath default %q, got %q", ResponseDefaultJSONPath, p.responseParams.JsonPath)
	}
	if p.responseParams.Enabled {
		t.Fatalf("expected response disabled by default")
	}
}

func TestValidateAWSConfigParams_RoleRegionRequirement(t *testing.T) {
	params := baseParams()
	params["request"] = map[string]interface{}{"jsonPath": "$.msg"}
	params["awsRoleARN"] = "arn:aws:iam::123456789012:role/test-role"

	err := validateAWSConfigParams(params)
	if err == nil || !strings.Contains(err.Error(), "'awsRoleRegion' is required") {
		t.Fatalf("expected missing awsRoleRegion error, got: %v", err)
	}

	params["awsRoleRegion"] = ""
	err = validateAWSConfigParams(params)
	if err == nil || !strings.Contains(err.Error(), "'awsRoleRegion' cannot be empty") {
		t.Fatalf("expected empty awsRoleRegion error, got: %v", err)
	}

	params["awsRoleRegion"] = "us-east-1"
	err = validateAWSConfigParams(params)
	if err != nil {
		t.Fatalf("expected valid role config, got: %v", err)
	}
}

func TestParseRequestResponseParams_TypeValidation(t *testing.T) {
	_, err := parseRequestResponseParams(map[string]interface{}{"jsonPath": 10}, false)
	if err == nil || !strings.Contains(err.Error(), "'jsonPath' must be a string") {
		t.Fatalf("expected jsonPath type error, got: %v", err)
	}

	_, err = parseRequestResponseParams(map[string]interface{}{"redactPII": "true"}, false)
	if err == nil || !strings.Contains(err.Error(), "'redactPII' must be a boolean") {
		t.Fatalf("expected redactPII type error, got: %v", err)
	}

	_, err = parseRequestResponseParams(map[string]interface{}{"passthroughOnError": "true"}, false)
	if err == nil || !strings.Contains(err.Error(), "'passthroughOnError' must be a boolean") {
		t.Fatalf("expected passthroughOnError type error, got: %v", err)
	}

	_, err = parseRequestResponseParams(map[string]interface{}{"enabled": "true"}, false)
	if err == nil || !strings.Contains(err.Error(), "'enabled' must be a boolean") {
		t.Fatalf("expected enabled type error, got: %v", err)
	}

	_, err = parseRequestResponseParams(map[string]interface{}{"showAssessment": "true"}, false)
	if err == nil || !strings.Contains(err.Error(), "'showAssessment' must be a boolean") {
		t.Fatalf("expected showAssessment type error, got: %v", err)
	}
}

func TestEvaluateGuardrailResponse_BasicActions(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	metadata := map[string]interface{}{}

	violation, modified, err := p.evaluateGuardrailResponse(nil, "hello", false, true, metadata)
	if !violation || modified != "" || err == nil {
		t.Fatalf("expected invalid response error, got violation=%v modified=%q err=%v", violation, modified, err)
	}

	violation, modified, err = p.evaluateGuardrailResponse("bad-type", "hello", false, true, metadata)
	if !violation || err == nil {
		t.Fatalf("expected invalid output type error, got violation=%v err=%v", violation, err)
	}

	noViolationOutput := &bedrockruntime.ApplyGuardrailOutput{
		Action:      types.GuardrailActionNone,
		Assessments: []types.GuardrailAssessment{},
	}
	violation, modified, err = p.evaluateGuardrailResponse(noViolationOutput, "hello", false, true, metadata)
	if violation || modified != "" || err != nil {
		t.Fatalf("expected no violation for action NONE, got violation=%v modified=%q err=%v", violation, modified, err)
	}

	unexpectedOutput := &bedrockruntime.ApplyGuardrailOutput{
		Action:      types.GuardrailAction("UNKNOWN"),
		Assessments: []types.GuardrailAssessment{},
	}
	violation, modified, err = p.evaluateGuardrailResponse(unexpectedOutput, "hello", false, true, metadata)
	if !violation || err == nil {
		t.Fatalf("expected unexpected action error, got violation=%v err=%v", violation, err)
	}
}

func TestEvaluateGuardrailResponse_InterventionPaths(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}

	noPIIOutput := &bedrockruntime.ApplyGuardrailOutput{
		Action:      types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{},
	}
	violation, modified, err := p.evaluateGuardrailResponse(noPIIOutput, "hello", false, true, map[string]interface{}{})
	if !violation || modified != "" || err != nil {
		t.Fatalf("expected violation for non-PII intervention, got violation=%v modified=%q err=%v", violation, modified, err)
	}

	original := "contact john@example.com"
	output := makePIIIntervenedOutput("john@example.com")
	metadata := map[string]interface{}{}

	violation, modified, err = p.evaluateGuardrailResponse(output, original, true, true, metadata)
	if violation || err != nil {
		t.Fatalf("expected redact path to pass with modified content, got violation=%v err=%v", violation, err)
	}
	if !strings.Contains(modified, "*****") {
		t.Fatalf("expected redacted content, got: %q", modified)
	}

	metadata = map[string]interface{}{}
	violation, modified, err = p.evaluateGuardrailResponse(output, original, false, true, metadata)
	if violation || err != nil {
		t.Fatalf("expected masking path to pass, got violation=%v err=%v", violation, err)
	}
	if modified == original || !strings.Contains(modified, "EMAIL_0000") {
		t.Fatalf("expected masked placeholder in content, got: %q", modified)
	}

	masked, ok := metadata[MetadataKeyPIIEntities].(map[string]string)
	if !ok || masked["john@example.com"] == "" {
		t.Fatalf("expected metadata to include original->placeholder mapping, got: %#v", metadata[MetadataKeyPIIEntities])
	}

	violation, modified, err = p.evaluateGuardrailResponse(output, original, false, false, metadata)
	if violation || modified != "" || err != nil {
		t.Fatalf("expected response masking path to return no-op, got violation=%v modified=%q err=%v", violation, modified, err)
	}
}

func TestRestorePIIInResponse(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	content := "hello EMAIL_0000 and EMAIL_0001"
	mapping := map[string]string{
		"alice@example.com": "EMAIL_0000",
		"bob@example.com":   "EMAIL_0001",
	}

	restored := p.restorePIIInResponse(content, mapping)
	if restored != "hello alice@example.com and bob@example.com" {
		t.Fatalf("unexpected restored content: %q", restored)
	}
}

func TestUpdatePayloadWithMaskedContent(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}

	if got := string(p.updatePayloadWithMaskedContent([]byte(`ignored`), "a", "b", "")); got != "b" {
		t.Fatalf("expected direct replacement when jsonPath is empty, got: %q", got)
	}

	original := []byte(`{"message":"hello","nested":{"text":"hello"}}`)
	updated := p.updatePayloadWithMaskedContent(original, "hello", "*****", "$.nested.text")

	var payload map[string]interface{}
	if err := json.Unmarshal(updated, &payload); err != nil {
		t.Fatalf("failed to unmarshal updated payload: %v", err)
	}
	nested := payload["nested"].(map[string]interface{})
	if nested["text"] != "*****" {
		t.Fatalf("expected nested.text to be updated, got: %#v", nested["text"])
	}

	invalidJSON := []byte(`{"message":`)
	if got := p.updatePayloadWithMaskedContent(invalidJSON, "x", "y", "$.message"); string(got) != string(invalidJSON) {
		t.Fatalf("expected original payload on invalid JSON")
	}

	if got := p.updatePayloadWithMaskedContent(original, "hello", "*****", "$.nested.text.value"); string(got) != string(original) {
		t.Fatalf("expected original payload on invalid JSONPath")
	}
}

func TestValidatePayload_EarlyAndErrorPaths(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}

	// Response restoration path should return before any AWS call.
	metadata := map[string]interface{}{
		MetadataKeyPIIEntities: map[string]string{
			"alice@example.com": "EMAIL_0000",
		},
	}
	restored := p.validatePayload([]byte(`{"msg":"EMAIL_0000"}`), AWSBedrockGuardrailPolicyParams{
		RedactPII: false,
	}, true, metadata)
	respMod, ok := restored.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", restored)
	}
	if !strings.Contains(string(respMod.Body), "alice@example.com") {
		t.Fatalf("expected restored PII in response body, got %q", string(respMod.Body))
	}

	// JSONPath extraction error with passthrough disabled should block.
	blocked := p.validatePayload([]byte(`not-json`), AWSBedrockGuardrailPolicyParams{
		JsonPath:           "$.msg",
		PassthroughOnError: false,
		ShowAssessment:     false,
	}, false, map[string]interface{}{})
	immResp, ok := blocked.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for request block, got %T", blocked)
	}
	if immResp.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, immResp.StatusCode)
	}

	// JSONPath extraction error with passthrough enabled should continue.
	passthrough := p.validatePayload([]byte(`not-json`), AWSBedrockGuardrailPolicyParams{
		JsonPath:           "$.msg",
		PassthroughOnError: true,
	}, false, map[string]interface{}{})
	if _, ok := passthrough.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on passthrough, got %T", passthrough)
	}

	// Response block path uses UpstreamResponseModifications + status code.
	respBlocked := p.validatePayload([]byte(`not-json`), AWSBedrockGuardrailPolicyParams{
		JsonPath:           "$.msg",
		PassthroughOnError: false,
	}, true, map[string]interface{}{})
	respBlockedMod, ok := respBlocked.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications for response block, got %T", respBlocked)
	}
	if respBlockedMod.StatusCode == nil || *respBlockedMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected response status %d, got %#v", GuardrailErrorCode, respBlockedMod.StatusCode)
	}
}

func TestBuildErrorResponse_RequestAndResponse(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}

	reqResp := p.buildErrorResponse("reason", nil, false, false, nil)
	imm, ok := reqResp.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", reqResp)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}
	if ct := imm.Headers["Content-Type"]; ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	respResp := p.buildErrorResponse("reason", nil, true, false, nil)
	upResp, ok := respResp.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", respResp)
	}
	if upResp.StatusCode == nil || *upResp.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected response status %d, got %#v", GuardrailErrorCode, upResp.StatusCode)
	}
}

func TestOnRequest_NoRequestParams_ReturnsNoOp(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{
		hasRequestParams: false,
	}

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(`{"msg":"hello"}`),
		},
	}

	result := p.OnRequest(ctx, map[string]interface{}{})
	mod, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
	if mod.Body != nil {
		t.Fatalf("expected no request body modification, got %q", string(mod.Body))
	}
}

func TestOnRequest_DisabledRequestFlow_ReturnsNoOp(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled: false,
		},
	}

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(`{"msg":"hello"}`),
		},
	}

	result := p.OnRequest(ctx, map[string]interface{}{})
	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
}

func TestOnRequest_BlockAndPassthroughOnJSONPathError(t *testing.T) {
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(`not-json`),
		},
	}

	blockPolicy := &AWSBedrockGuardrailPolicy{
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled:            true,
			JsonPath:           "$.msg",
			PassthroughOnError: false,
		},
	}
	blockResult := blockPolicy.OnRequest(ctx, map[string]interface{}{})
	imm, ok := blockResult.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", blockResult)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}

	passthroughPolicy := &AWSBedrockGuardrailPolicy{
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled:            true,
			JsonPath:           "$.msg",
			PassthroughOnError: true,
		},
	}
	passthroughResult := passthroughPolicy.OnRequest(ctx, map[string]interface{}{})
	if _, ok := passthroughResult.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", passthroughResult)
	}
}

func TestOnResponse_NoResponseParams_ReturnsNoOp(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{
		hasResponseParams: false,
	}

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"msg":"hello"}`),
		},
	}

	result := p.OnResponse(ctx, map[string]interface{}{})
	mod, ok := result.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", result)
	}
	if mod.Body != nil || mod.StatusCode != nil {
		t.Fatalf("expected no response modification, got body=%q status=%v", string(mod.Body), mod.StatusCode)
	}
}

func TestOnResponse_DisabledResponseFlow_ReturnsNoOp(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{
		hasResponseParams: true,
		responseParams: AWSBedrockGuardrailPolicyParams{
			Enabled: false,
		},
	}

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"msg":"hello"}`),
		},
	}

	result := p.OnResponse(ctx, map[string]interface{}{})
	if _, ok := result.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", result)
	}
}

func TestOnResponse_RestoreAndBlockPaths(t *testing.T) {
	restorePolicy := &AWSBedrockGuardrailPolicy{
		hasResponseParams: true,
		responseParams: AWSBedrockGuardrailPolicyParams{
			Enabled:   true,
			RedactPII: false,
		},
	}

	restoreCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				MetadataKeyPIIEntities: map[string]string{
					"alice@example.com": "EMAIL_0000",
				},
			},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"msg":"EMAIL_0000"}`),
		},
	}

	restoreResult := restorePolicy.OnResponse(restoreCtx, map[string]interface{}{})
	restoreMod, ok := restoreResult.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", restoreResult)
	}
	if !strings.Contains(string(restoreMod.Body), "alice@example.com") {
		t.Fatalf("expected restored response body, got %q", string(restoreMod.Body))
	}

	blockPolicy := &AWSBedrockGuardrailPolicy{
		hasResponseParams: true,
		responseParams: AWSBedrockGuardrailPolicyParams{
			Enabled:            true,
			JsonPath:           "$.msg",
			PassthroughOnError: false,
		},
	}

	blockCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`not-json`),
		},
	}

	blockResult := blockPolicy.OnResponse(blockCtx, map[string]interface{}{})
	blockMod, ok := blockResult.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", blockResult)
	}
	if blockMod.StatusCode == nil || *blockMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected response status %d, got %#v", GuardrailErrorCode, blockMod.StatusCode)
	}
}

func TestOnRequest_WithMockedBedrockNoViolation(t *testing.T) {
	mockClient := &mockBedrockClient{
		output: &bedrockruntime.ApplyGuardrailOutput{
			Action:      types.GuardrailActionNone,
			Assessments: []types.GuardrailAssessment{},
		},
	}

	p := &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled:  true,
			JsonPath: "$.msg",
		},
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return mockClient
		},
	}

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(`{"msg":"hello from request"}`),
		},
	}

	result := p.OnRequest(ctx, map[string]interface{}{})
	mod, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
	if mod.Body != nil {
		t.Fatalf("expected no body changes, got %q", string(mod.Body))
	}
	if mockClient.lastInput == nil {
		t.Fatalf("expected mocked ApplyGuardrail to be called")
	}
	textBlock := mockClient.lastInput.Content[0].(*types.GuardrailContentBlockMemberText).Value.Text
	if aws.ToString(textBlock) != "hello from request" {
		t.Fatalf("expected extracted request text in ApplyGuardrail input, got %q", aws.ToString(textBlock))
	}
}

func TestOnRequest_WithMockedBedrockViolation(t *testing.T) {
	mockClient := &mockBedrockClient{
		output: &bedrockruntime.ApplyGuardrailOutput{
			Action:      types.GuardrailActionGuardrailIntervened,
			Assessments: []types.GuardrailAssessment{},
		},
	}

	p := &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled: true,
		},
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return mockClient
		},
	}

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(`hello`),
		},
	}

	result := p.OnRequest(ctx, map[string]interface{}{})
	imm, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}
}

func TestOnRequest_WithMockedBedrockErrorPassthrough(t *testing.T) {
	mockClient := &mockBedrockClient{
		err: errors.New("bedrock api unavailable"),
	}

	p := &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled:            true,
			PassthroughOnError: true,
		},
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return mockClient
		},
	}

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(`hello`),
		},
	}

	result := p.OnRequest(ctx, map[string]interface{}{})
	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on passthrough, got %T", result)
	}
}

func TestOnResponse_WithMockedBedrockPIIRedaction(t *testing.T) {
	mockClient := &mockBedrockClient{
		output: makePIIIntervenedOutput("john@example.com"),
	}

	p := &AWSBedrockGuardrailPolicy{
		region:            "us-east-1",
		guardrailID:       "gr-123",
		guardrailVersion:  "DRAFT",
		hasResponseParams: true,
		responseParams: AWSBedrockGuardrailPolicyParams{
			Enabled:   true,
			JsonPath:  "$.msg",
			RedactPII: true,
		},
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return mockClient
		},
	}

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(`{"msg":"john@example.com"}`),
		},
	}

	result := p.OnResponse(ctx, map[string]interface{}{})
	mod, ok := result.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", result)
	}
	if !strings.Contains(string(mod.Body), "*****") {
		t.Fatalf("expected redacted response body, got %q", string(mod.Body))
	}
	if mockClient.lastInput == nil {
		t.Fatalf("expected mocked ApplyGuardrail to be called")
	}
}
