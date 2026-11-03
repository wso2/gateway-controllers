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
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

func TestAWSBedrockGuardrailPolicy_Mode(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

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
		// awsAuth is mandatory; "system" defers to the gateway-wide credentials,
		// which is what these tests exercise unless they override it.
		"awsAuth": map[string]interface{}{"authenticationType": AuthTypeSystem},
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

	// An empty string means "not configured", so it fails the same way an
	// absent value does rather than with a distinct "cannot be empty" error.
	params["awsRoleRegion"] = ""
	err = validateAWSConfigParams(params)
	if err == nil || !strings.Contains(err.Error(), "'awsRoleRegion' is required") {
		t.Fatalf("expected empty awsRoleRegion to be treated as missing, got: %v", err)
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
	respMod, ok := restored.(policy.DownstreamResponseModifications)
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
	respBlockedMod, ok := respBlocked.(policy.DownstreamResponseModifications)
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
	upResp, ok := respResp.(policy.DownstreamResponseModifications)
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

	result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
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

	result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
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
	blockResult := blockPolicy.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
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
	passthroughResult := passthroughPolicy.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
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

	result := p.OnResponseBody(context.Background(), ctx, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
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

	result := p.OnResponseBody(context.Background(), ctx, map[string]interface{}{})
	if _, ok := result.(policy.DownstreamResponseModifications); !ok {
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

	restoreResult := restorePolicy.OnResponseBody(context.Background(), restoreCtx, map[string]interface{}{})
	restoreMod, ok := restoreResult.(policy.DownstreamResponseModifications)
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

	blockResult := blockPolicy.OnResponseBody(context.Background(), blockCtx, map[string]interface{}{})
	blockMod, ok := blockResult.(policy.DownstreamResponseModifications)
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

	result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
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

	result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
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

	result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{})
	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on passthrough, got %T", result)
	}
}

const (
	upstreamErrorBody    = `{"message":"The provided model identifier is invalid."}`
	generatedContentBody = `{"output":{"message":{"content":[{"text":"blocked content"}]}}}`
)

func newMockedResponsePolicy(t *testing.T, mockClient *mockBedrockClient, applicableStatusCodes string) *AWSBedrockGuardrailPolicy {
	t.Helper()
	responseParams := AWSBedrockGuardrailPolicyParams{
		Enabled:  true,
		JsonPath: "$.output.message.content[0].text",
	}
	if applicableStatusCodes != "" {
		ranges, err := parseStatusCodes(applicableStatusCodes)
		if err != nil {
			t.Fatalf("parseStatusCodes(%q) returned an unexpected error: %v", applicableStatusCodes, err)
		}
		responseParams.ApplicableStatusCodes = ranges
	}
	return &AWSBedrockGuardrailPolicy{
		region:            "us-east-1",
		guardrailID:       "gr-123",
		guardrailVersion:  "DRAFT",
		hasResponseParams: true,
		responseParams:    responseParams,
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return mockClient
		},
	}
}

func newIntervenedMockClient() *mockBedrockClient {
	return &mockBedrockClient{
		output: &bedrockruntime.ApplyGuardrailOutput{
			Action: types.GuardrailActionGuardrailIntervened,
		},
	}
}

func respondWith(p *AWSBedrockGuardrailPolicy, status int, body string) policy.ResponseAction {
	return p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{Metadata: map[string]interface{}{}},
		ResponseStatus: status,
		ResponseBody:   &policy.Body{Content: []byte(body)},
	}, map[string]interface{}{})
}

func expectGuardrailBlock(t *testing.T, status int, result policy.ResponseAction) {
	t.Helper()
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("status %d: expected DownstreamResponseModifications, got %T", status, result)
	}
	if mod.StatusCode == nil || *mod.StatusCode != GuardrailErrorCode {
		t.Fatalf("status %d: expected response status %d, got %#v", status, GuardrailErrorCode, mod.StatusCode)
	}
}

func TestOnResponse_EveryStatusValidatedWhenApplicableStatusCodesNotConfigured(t *testing.T) {
	mockClient := newIntervenedMockClient()
	p := newMockedResponsePolicy(t, mockClient, "")

	for _, status := range []int{400, 403, 500} {
		expectGuardrailBlock(t, status, respondWith(p, status, upstreamErrorBody))
	}
	expectGuardrailBlock(t, 200, respondWith(p, 200, generatedContentBody))
	if mockClient.lastInput == nil {
		t.Fatalf("expected ApplyGuardrail to be called for a successful response")
	}
}

func TestOnResponse_StatusOutsideConfiguredCodesPassesThrough(t *testing.T) {
	mockClient := newIntervenedMockClient()
	p := newMockedResponsePolicy(t, mockClient, "200-299")

	for _, status := range []int{400, 401, 403, 429, 500, 503} {
		result := respondWith(p, status, upstreamErrorBody)
		mod, ok := result.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("status %d: expected DownstreamResponseModifications, got %T", status, result)
		}
		if mod.StatusCode != nil || mod.Body != nil {
			t.Fatalf("status %d: expected the response to pass through unchanged, got status %v body %q", status, mod.StatusCode, string(mod.Body))
		}
	}
	if mockClient.lastInput != nil {
		t.Fatalf("expected ApplyGuardrail not to be called for statuses outside the configured codes")
	}
}

func TestOnResponse_StatusWithinConfiguredCodesIsValidated(t *testing.T) {
	for _, status := range []int{200, 204, 422} {
		mockClient := newIntervenedMockClient()
		p := newMockedResponsePolicy(t, mockClient, "200-299, 422")

		expectGuardrailBlock(t, status, respondWith(p, status, generatedContentBody))
		if mockClient.lastInput == nil {
			t.Fatalf("status %d: expected ApplyGuardrail to be called", status)
		}
	}
}

func TestOnResponse_UnknownStatusIsValidatedWhenApplicableStatusCodesConfigured(t *testing.T) {
	mockClient := newIntervenedMockClient()
	p := newMockedResponsePolicy(t, mockClient, "200-299")

	expectGuardrailBlock(t, 0, respondWith(p, 0, generatedContentBody))
	if mockClient.lastInput == nil {
		t.Fatalf("expected ApplyGuardrail to be called when the upstream status is unknown")
	}
}

func TestParseStatusCodes_Valid(t *testing.T) {
	tests := []struct {
		value string
		want  []statusCodeRange
	}{
		{"200-299", []statusCodeRange{{min: 200, max: 299}}},
		{"422", []statusCodeRange{{min: 422, max: 422}}},
		{"200-299,401,403", []statusCodeRange{{min: 200, max: 299}, {min: 401, max: 401}, {min: 403, max: 403}}},
		{" 200 - 204 , 418 ", []statusCodeRange{{min: 200, max: 204}, {min: 418, max: 418}}},
		{"100-599", []statusCodeRange{{min: 100, max: 599}}},
	}
	for _, tt := range tests {
		got, err := parseStatusCodes(tt.value)
		if err != nil {
			t.Fatalf("parseStatusCodes(%q) returned an unexpected error: %v", tt.value, err)
		}
		if len(got) != len(tt.want) {
			t.Fatalf("parseStatusCodes(%q) = %v, want %v", tt.value, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("parseStatusCodes(%q) = %v, want %v", tt.value, got, tt.want)
			}
		}
	}
}

func TestParseStatusCodes_Invalid(t *testing.T) {
	for _, value := range []string{"abc", "200-", "-200", "299-200", "99", "600", "200,,401", "200,", "200-299-300", "2OO"} {
		if _, err := parseStatusCodes(value); err == nil {
			t.Fatalf("parseStatusCodes(%q) expected an error, got none", value)
		}
	}
}

func TestParseRequestResponseParams_ApplicableStatusCodes(t *testing.T) {
	params, err := parseRequestResponseParams(map[string]interface{}{"applicableStatusCodes": "200-299,422"}, true)
	if err != nil {
		t.Fatalf("expected applicableStatusCodes to parse, got: %v", err)
	}
	want := []statusCodeRange{{min: 200, max: 299}, {min: 422, max: 422}}
	if len(params.ApplicableStatusCodes) != len(want) || params.ApplicableStatusCodes[0] != want[0] || params.ApplicableStatusCodes[1] != want[1] {
		t.Fatalf("expected status codes %v, got %v", want, params.ApplicableStatusCodes)
	}

	params, err = parseRequestResponseParams(map[string]interface{}{}, true)
	if err != nil {
		t.Fatalf("expected no error without applicableStatusCodes, got: %v", err)
	}
	if params.ApplicableStatusCodes != nil {
		t.Fatalf("expected no status codes when applicableStatusCodes is not set, got %v", params.ApplicableStatusCodes)
	}

	_, err = parseRequestResponseParams(map[string]interface{}{"applicableStatusCodes": 200}, true)
	if err == nil || !strings.Contains(err.Error(), "'applicableStatusCodes' must be a string") {
		t.Fatalf("expected applicableStatusCodes type error, got: %v", err)
	}

	_, err = parseRequestResponseParams(map[string]interface{}{"applicableStatusCodes": "299-200"}, true)
	if err == nil || !strings.Contains(err.Error(), "applicableStatusCodes") {
		t.Fatalf("expected applicableStatusCodes validation error, got: %v", err)
	}
}

func TestGetPolicy_RejectsInvalidResponseApplicableStatusCodes(t *testing.T) {
	params := baseParams()
	params["response"] = map[string]interface{}{"enabled": true, "applicableStatusCodes": "200-299,abc"}

	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil || !strings.Contains(err.Error(), "invalid response parameters") {
		t.Fatalf("expected invalid response parameters error, got: %v", err)
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

	result := p.OnResponseBody(context.Background(), ctx, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
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

// TestAWSBedrockGuardrail_InterventionDeclaresFault covers the funnel every intervention
func TestAWSBedrockGuardrail_InterventionDeclaresFault(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}

	t.Run("request phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, false, false, nil)
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse, got %T", action)
		}
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a guardrail intervention")
		}
		if resp.Fault == nil || resp.Fault.Code != policy.GuardrailCodeUnsafeContent {
			t.Fatalf("expected Error.Code=%q, got %+v", policy.GuardrailCodeUnsafeContent, resp.Fault)
		}
		if resp.Fault.Type != policy.FaultTypeGuardrail {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeGuardrail, resp.Fault.Type)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
		if resp.Fault.Guardrail == nil || resp.Fault.Guardrail.InterveningGuardrail != guardrailName {
			t.Fatalf("expected the guardrail envelope to name %q, got %+v", guardrailName, resp.Fault.Guardrail)
		}
	})

	t.Run("response phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, true, false, nil)
		mods, ok := action.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", action)
		}
		if !mods.IsFault {
			t.Fatalf("expected IsFault=true on a response-side intervention")
		}
		if mods.Fault == nil || mods.Fault.Direction != policy.DirectionResponse {
			t.Fatalf("expected Error.Direction=%q, got %+v", policy.DirectionResponse, mods.Fault)
		}
	})
}

// TestAWSBedrockGuardrail_FailClosedDeclaresFault pins the path that runs when Bedrock
// cannot be used at all: the policy fails closed and refuses the call. That is a genuine
// refusal, so it must reach the fault policies, but no guardrail produced a verdict, so it
// is declared as the policy failing its own job rather than as an intervention. The client
// still receives the same envelope as before.
func TestAWSBedrockGuardrail_FailClosedDeclaresFault(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	params := AWSBedrockGuardrailPolicyParams{RedactPII: false, JsonPath: "$.text"}

	result := p.validatePayload([]byte(`{"text":"hello"}`), params, true, map[string]interface{}{})
	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if !mods.IsFault {
		t.Fatalf("expected IsFault=true when the guardrail fails closed")
	}
	if mods.Fault == nil || mods.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("expected Error.Code=%q, got %+v", policy.FaultCodeMediationFailed, mods.Fault)
	}
	if mods.Fault.Type != policy.FaultTypeMediation {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeMediation, mods.Fault.Type)
	}
	if mods.Fault.Direction != policy.DirectionResponse {
		t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionResponse, mods.Fault.Direction)
	}
	if mods.Fault.Guardrail != nil {
		t.Fatalf("a failure to run the check is not an intervention, got Guardrail=%+v", mods.Fault.Guardrail)
	}
	if mods.StatusCode == nil || *mods.StatusCode != GuardrailErrorCode || !strings.Contains(string(mods.Body), "GUARDRAIL_INTERVENED") {
		t.Fatalf("expected the unchanged %d guardrail envelope, got %v %s", GuardrailErrorCode, mods.StatusCode, mods.Body)
	}
}

// TestAWSBedrockGuardrail_ExtractionFailureDeclaresFault pins the JSONPath extraction
// failure: an unreadable request body is the caller's, an unreadable response body leaves
// the policy unable to do its job. Neither is a guardrail verdict, and the client response
// is the same one the policy returned before the fault was declared.
func TestAWSBedrockGuardrail_ExtractionFailureDeclaresFault(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}
	params := AWSBedrockGuardrailPolicyParams{JsonPath: "$.text"}
	payload := []byte(`not-json`)
	_, extractErr := utils.ExtractStringValueFromJsonpath(payload, params.JsonPath)
	if extractErr == nil {
		t.Fatalf("expected the payload to fail extraction")
	}

	reqAction := p.validatePayload(payload, params, false, map[string]interface{}{})
	resp, ok := reqAction.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", reqAction)
	}
	want := p.buildErrorResponse("Error extracting value from JSONPath", extractErr, false, false, nil).(policy.ImmediateResponse)
	if resp.StatusCode != want.StatusCode || string(resp.Body) != string(want.Body) {
		t.Fatalf("client response changed: got %d %s, want %d %s", resp.StatusCode, resp.Body, want.StatusCode, want.Body)
	}
	if !resp.IsFault || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeInvalidRequestBody ||
		resp.Fault.Type != policy.FaultTypeValidation || resp.Fault.Direction != policy.DirectionRequest || resp.Fault.Guardrail != nil {
		t.Fatalf("expected an invalid-request-body fault, got %+v", resp.Fault)
	}

	respAction := p.validatePayload(payload, params, true, map[string]interface{}{})
	mods, ok := respAction.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", respAction)
	}
	if !mods.IsFault || mods.Fault == nil || mods.Fault.Code != policy.FaultCodeMediationFailed ||
		mods.Fault.Type != policy.FaultTypeMediation || mods.Fault.Direction != policy.DirectionResponse || mods.Fault.Guardrail != nil {
		t.Fatalf("expected a mediation fault, got %+v", mods.Fault)
	}
}

// guardrailCodeFor is the whole point of the specific codes, so its mapping and — more
// importantly — its PRECEDENCE are pinned. Bedrock can trip several policies on one call
// and a single code names one, so a change in iteration order would silently relabel
// rejections without failing anything else.
func TestAWSBedrockGuardrail_CodeNamesWhatBedrockReported(t *testing.T) {
	filter := func(t types.GuardrailContentFilterType) types.GuardrailAssessment {
		return types.GuardrailAssessment{
			ContentPolicy: &types.GuardrailContentPolicyAssessment{
				Filters: []types.GuardrailContentFilter{{Type: t}},
			},
		}
	}
	pii := types.GuardrailAssessment{
		SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
			PiiEntities: []types.GuardrailPiiEntityFilter{{}},
		},
	}
	topic := types.GuardrailAssessment{
		TopicPolicy: &types.GuardrailTopicPolicyAssessment{
			Topics: []types.GuardrailTopic{{}},
		},
	}

	for _, tc := range []struct {
		name        string
		assessments []types.GuardrailAssessment
		want        string
	}{
		{"hate", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypeHate)}, policy.GuardrailCodeHate},
		{"sexual", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypeSexual)}, policy.GuardrailCodeSexual},
		{"violence", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypeViolence)}, policy.GuardrailCodeViolence},
		{"insults map to harassment", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypeInsults)}, policy.GuardrailCodeHarassment},
		{"misconduct maps to dangerous activity", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypeMisconduct)}, policy.GuardrailCodeDangerousActivity},
		{"prompt attack", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypePromptAttack)}, policy.GuardrailCodePromptInjection},
		{"pii", []types.GuardrailAssessment{pii}, policy.GuardrailCodePII},
		{"a denied topic is intent, not content safety", []types.GuardrailAssessment{topic}, policy.GuardrailCodeSemanticMatch},
		// Precedence: PII wins over a content verdict on the same call.
		{"pii outranks a content filter", []types.GuardrailAssessment{filter(types.GuardrailContentFilterTypeHate), pii}, policy.GuardrailCodePII},
		// And a content verdict outranks a merely-configured topic.
		{"a content filter outranks a topic", []types.GuardrailAssessment{topic, filter(types.GuardrailContentFilterTypeHate)}, policy.GuardrailCodeHate},
		{"nothing recognised falls back to the group generic", nil, policy.GuardrailCodeUnsafeContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := guardrailCodeFor(&bedrockruntime.ApplyGuardrailOutput{Assessments: tc.assessments})
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}

	// A non-Bedrock output must not panic; it reaches the same fallback.
	if got := guardrailCodeFor(nil); got != policy.GuardrailCodeUnsafeContent {
		t.Fatalf("nil output: expected %q, got %q", policy.GuardrailCodeUnsafeContent, got)
	}
}
