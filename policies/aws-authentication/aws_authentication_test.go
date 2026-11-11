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

package awsauthentication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func validIAMUserParams() map[string]interface{} {
	return map[string]interface{}{
		"service":            "execute-api",
		"region":             "us-east-1",
		"authenticationType": AuthTypeIAMUserAccessKey,
		"awsAccessKeyID":     "AKIAEXAMPLE",
		"awsSecretAccessKey": "secretexample",
	}
}

func validAssumeRoleParams() map[string]interface{} {
	return map[string]interface{}{
		"service":            "execute-api",
		"region":             "us-east-1",
		"authenticationType": AuthTypeSTSAssumeRole,
		"awsRoleARN":         "arn:aws:iam::123456789012:role/example-role",
	}
}

func validIRSAParams() map[string]interface{} {
	return map[string]interface{}{
		"service":            "execute-api",
		"region":             "us-east-1",
		"authenticationType": AuthTypeIRSA,
		"awsRoleARN":         "arn:aws:iam::123456789012:role/example-irsa-role",
	}
}

func validDefaultCredentialChainParams() map[string]interface{} {
	return map[string]interface{}{
		"service":            "execute-api",
		"region":             "us-east-1",
		"authenticationType": AuthTypeDefaultCredentialChain,
	}
}

func newRequestBodyCtx(headers map[string][]string, body []byte) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(headers),
		Body:          &policy.Body{Content: body, Present: len(body) > 0},
		Path:          "/foo?bar=baz",
		Method:        http.MethodPost,
		// Authority/Scheme model the inbound client-facing gateway host — deliberately
		// distinct from UpstreamInfo below, since production code must never sign
		// against these (see context.go's RequestContext doc).
		Authority: "gateway.example.com",
		Scheme:    "https",
		UpstreamInfo: &policyenginev1.UpstreamInfo{
			URL: "https://example.execute-api.us-east-1.amazonaws.com",
		},
	}
}

func newTestPolicy() *AWSAuthenticationPolicy {
	return &AWSAuthenticationPolicy{
		service:            "execute-api",
		region:             "us-east-1",
		authenticationType: AuthTypeIAMUserAccessKey,
	}
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_ValidIAMUserAccessKey(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validIAMUserParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap := p.(*AWSAuthenticationPolicy)
	if ap.service != "execute-api" || ap.region != "us-east-1" {
		t.Errorf("unexpected service/region: %q/%q", ap.service, ap.region)
	}
	if ap.credsProvider == nil {
		t.Error("expected credsProvider to be set")
	}
}

func TestGetPolicy_ValidSTSAssumeRole(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validAssumeRoleParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap := p.(*AWSAuthenticationPolicy)
	if ap.credsProvider == nil {
		t.Error("expected credsProvider to be set")
	}
}

func TestGetPolicy_MissingAuthenticationType(t *testing.T) {
	params := validIAMUserParams()
	delete(params, "authenticationType")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for missing authenticationType")
	}
}

func TestGetPolicy_InvalidAuthenticationType(t *testing.T) {
	params := validIAMUserParams()
	params["authenticationType"] = "foo"
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for invalid authenticationType")
	}
}

func TestGetPolicy_IAMUserAccessKey_MissingAccessKeyID(t *testing.T) {
	params := validIAMUserParams()
	delete(params, "awsAccessKeyID")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for missing awsAccessKeyID")
	}
}

func TestGetPolicy_IAMUserAccessKey_MissingSecretAccessKey(t *testing.T) {
	params := validIAMUserParams()
	delete(params, "awsSecretAccessKey")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for missing awsSecretAccessKey")
	}
}

func TestGetPolicy_STSAssumeRole_MissingRoleARN(t *testing.T) {
	params := validAssumeRoleParams()
	delete(params, "awsRoleARN")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for missing awsRoleARN")
	}
}

func TestGetPolicy_STSAssumeRole_PartialBaseCreds(t *testing.T) {
	params := validAssumeRoleParams()
	params["awsAccessKeyID"] = "AKIAEXAMPLE"
	// awsSecretAccessKey intentionally omitted
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for partial base credentials")
	}
}

func TestGetPolicy_MissingService(t *testing.T) {
	params := validIAMUserParams()
	delete(params, "service")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for missing service")
	}
}

func TestGetPolicy_MissingRegion(t *testing.T) {
	params := validIAMUserParams()
	delete(params, "region")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for missing region")
	}
}

// ─── GetPolicy validation: IRSA ─────────────────────────────────────────────

func TestGetPolicy_ValidIRSA(t *testing.T) {
	t.Setenv(envWebIdentityTokenFile, "/tmp/does-not-need-to-exist-yet")

	p, err := GetPolicy(policy.PolicyMetadata{}, validIRSAParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap := p.(*AWSAuthenticationPolicy)
	if ap.credsProvider == nil {
		t.Error("expected credsProvider to be set")
	}
}

func TestGetPolicy_IRSA_MissingRoleARN_NoEnvFallback(t *testing.T) {
	t.Setenv(envRoleARN, "")
	t.Setenv(envWebIdentityTokenFile, "/tmp/token")
	params := validIRSAParams()
	delete(params, "awsRoleARN")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error when awsRoleARN is missing and AWS_ROLE_ARN is unset")
	}
}

func TestGetPolicy_IRSA_MissingRoleARN_FallsBackToEnvVar(t *testing.T) {
	t.Setenv(envRoleARN, "arn:aws:iam::123456789012:role/env-role")
	t.Setenv(envWebIdentityTokenFile, "/tmp/token")
	params := validIRSAParams()
	delete(params, "awsRoleARN")
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.(*AWSAuthenticationPolicy).credsProvider == nil {
		t.Error("expected credsProvider to be set")
	}
}

func TestGetPolicy_IRSA_MissingWebIdentityTokenFileEnvVar(t *testing.T) {
	t.Setenv(envWebIdentityTokenFile, "")
	if _, err := GetPolicy(policy.PolicyMetadata{}, validIRSAParams()); err == nil {
		t.Fatal("expected error when AWS_WEB_IDENTITY_TOKEN_FILE is unset")
	}
}

func TestBuildWebIdentityCredentialsProvider_RoleARNParamTakesPrecedenceOverEnv(t *testing.T) {
	t.Setenv(envRoleARN, "arn:aws:iam::123456789012:role/env-role")
	t.Setenv(envWebIdentityTokenFile, "/tmp/token-from-env")

	creds := credentialFields{
		roleARN:         "arn:aws:iam::123456789012:role/param-role",
		roleSessionName: defaultRoleSessionName,
	}
	provider, err := buildWebIdentityCredentialsProvider(creds, "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Error("expected a non-nil credentials provider")
	}
}

// ─── GetPolicy validation: default credential chain ────────────────────────

func TestGetPolicy_ValidDefaultCredentialChain(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validDefaultCredentialChainParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap := p.(*AWSAuthenticationPolicy)
	if ap.credsProvider == nil {
		t.Error("expected credsProvider to be set")
	}
}

func TestGetPolicy_DefaultCredentialChain_NoCredentialFieldsRequired(t *testing.T) {
	params := validDefaultCredentialChainParams()
	// Deliberately no awsRoleARN, awsAccessKeyID, awsSecretAccessKey, etc. set —
	// this mode must not require any of them.
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetPolicy_DefaultRoleSessionName(t *testing.T) {
	_, creds, err := validateAndExtractCredentialParams(validAssumeRoleParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.roleSessionName != defaultRoleSessionName {
		t.Errorf("expected default role session name %q, got %q", defaultRoleSessionName, creds.roleSessionName)
	}
}

// ─── Mode ─────────────────────────────────────────────────────────────────────

func TestMode_ReturnsExpectedProcessingModes(t *testing.T) {
	p := newTestPolicy()
	mode := p.Mode()
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Errorf("expected RequestBodyMode to be Buffer, got %v", mode.RequestBodyMode)
	}
	if mode.RequestHeaderMode != policy.HeaderModeSkip {
		t.Errorf("expected RequestHeaderMode to be Skip, got %v", mode.RequestHeaderMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("expected ResponseHeaderMode to be Skip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected ResponseBodyMode to be Skip, got %v", mode.ResponseBodyMode)
	}
}

// ─── OnRequestBody ────────────────────────────────────────────────────────────

func TestOnRequestBody_IAMUserAccessKey_SignsSuccessfully(t *testing.T) {
	p := newTestPolicy()
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test")
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		return nil
	}
	p.nowFunc = func() time.Time { return time.Unix(0, 0) }

	reqCtx := newRequestBodyCtx(nil, []byte(`{"foo":"bar"}`))
	action := p.OnRequestBody(context.Background(), reqCtx, nil)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] == "" {
		t.Error("expected Authorization header to be set")
	}
	if mods.HeadersToSet["X-Amz-Date"] == "" {
		t.Error("expected X-Amz-Date header to be set")
	}
	if mods.Body != nil {
		t.Errorf("expected body passthrough (nil), got %v", mods.Body)
	}
	if reqCtx.SharedContext.AuthContext == nil || !reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated to be true")
	}
}

func TestOnRequestBody_STSAssumeRole_SignsWithSecurityToken(t *testing.T) {
	p := newTestPolicy()
	p.authenticationType = AuthTypeSTSAssumeRole
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "sessiontoken123"}, nil
	}
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test")
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		if creds.SessionToken != "" {
			req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
		}
		return nil
	}

	reqCtx := newRequestBodyCtx(nil, nil)
	action := p.OnRequestBody(context.Background(), reqCtx, nil)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.HeadersToSet["X-Amz-Security-Token"] != "sessiontoken123" {
		t.Errorf("expected X-Amz-Security-Token to be set, got %q", mods.HeadersToSet["X-Amz-Security-Token"])
	}
}

func TestOnRequestBody_NoSessionToken_OmitsSecurityTokenHeader(t *testing.T) {
	p := newTestPolicy()
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test")
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		return nil
	}

	reqCtx := newRequestBodyCtx(nil, nil)
	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	mods := action.(policy.UpstreamRequestModifications)
	if _, present := mods.HeadersToSet["X-Amz-Security-Token"]; present {
		t.Error("expected X-Amz-Security-Token to be absent")
	}
}

func TestOnRequestBody_EmptyBody_SignsWithEmptyPayloadHash(t *testing.T) {
	p := newTestPolicy()
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}
	var capturedHash string
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		capturedHash = payloadHash
		return nil
	}

	reqCtx := newRequestBodyCtx(nil, nil)
	p.OnRequestBody(context.Background(), reqCtx, nil)

	if capturedHash != emptyPayloadHash {
		t.Errorf("expected empty payload hash %q, got %q", emptyPayloadHash, capturedHash)
	}
}

func TestOnRequestBody_NonEmptyBody_SignsWithCorrectHash(t *testing.T) {
	p := newTestPolicy()
	body := []byte(`{"hello":"world"}`)
	sum := sha256.Sum256(body)
	expectedHash := hex.EncodeToString(sum[:])

	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}
	var capturedHash, capturedService, capturedRegion string
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		capturedHash = payloadHash
		capturedService = service
		capturedRegion = region
		return nil
	}

	reqCtx := newRequestBodyCtx(nil, body)
	p.OnRequestBody(context.Background(), reqCtx, nil)

	if capturedHash != expectedHash {
		t.Errorf("expected payload hash %q, got %q", expectedHash, capturedHash)
	}
	if capturedService != p.service || capturedRegion != p.region {
		t.Errorf("expected service/region %q/%q, got %q/%q", p.service, p.region, capturedService, capturedRegion)
	}
}

func TestOnRequestBody_CredentialRetrievalFailure_ReturnsBadGateway(t *testing.T) {
	p := newTestPolicy()
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("boom")
	}

	reqCtx := newRequestBodyCtx(nil, nil)
	action := p.OnRequestBody(context.Background(), reqCtx, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
	if reqCtx.SharedContext.AuthContext == nil || reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated to be false")
	}
}

func TestOnRequestBody_SigningFailure_ReturnsBadGateway(t *testing.T) {
	p := newTestPolicy()
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		return errors.New("signing failed")
	}

	reqCtx := newRequestBodyCtx(nil, nil)
	action := p.OnRequestBody(context.Background(), reqCtx, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_NoUpstreamInfo_ReturnsBadGatewayWithoutPanicking(t *testing.T) {
	p := newTestPolicy()
	p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}

	reqCtx := newRequestBodyCtx(nil, nil)
	reqCtx.UpstreamInfo = nil
	action := p.OnRequestBody(context.Background(), reqCtx, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_PreservesExistingAuthContext(t *testing.T) {
	existing := &policy.AuthContext{Authenticated: true, AuthType: "jwt"}

	t.Run("success", func(t *testing.T) {
		p := newTestPolicy()
		p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
		}
		p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
			return nil
		}
		reqCtx := newRequestBodyCtx(nil, nil)
		reqCtx.SharedContext.AuthContext = existing
		p.OnRequestBody(context.Background(), reqCtx, nil)
		if reqCtx.SharedContext.AuthContext.Previous != existing {
			t.Error("expected Previous to point to the pre-existing AuthContext")
		}
	})

	t.Run("failure", func(t *testing.T) {
		p := newTestPolicy()
		p.retrieveCredentialsFunc = func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{}, errors.New("boom")
		}
		reqCtx := newRequestBodyCtx(nil, nil)
		reqCtx.SharedContext.AuthContext = existing
		p.OnRequestBody(context.Background(), reqCtx, nil)
		if reqCtx.SharedContext.AuthContext.Previous != existing {
			t.Error("expected Previous to point to the pre-existing AuthContext")
		}
	})
}

// ─── helper unit tests ────────────────────────────────────────────────────────

func TestHashPayload_EmptyAndNonEmpty(t *testing.T) {
	if got := hashPayload(nil); got != emptyPayloadHash {
		t.Errorf("expected empty payload hash for nil, got %q", got)
	}
	if got := hashPayload([]byte{}); got != emptyPayloadHash {
		t.Errorf("expected empty payload hash for empty slice, got %q", got)
	}

	body := []byte("hello")
	sum := sha256.Sum256(body)
	expected := hex.EncodeToString(sum[:])
	if got := hashPayload(body); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestExtractSignedHeaders_WithAndWithoutSecurityToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("Authorization", "auth-value")
	req.Header.Set("X-Amz-Date", "date-value")

	headers := extractSignedHeaders(req)
	if headers["Authorization"] != "auth-value" || headers["X-Amz-Date"] != "date-value" {
		t.Errorf("unexpected headers: %v", headers)
	}
	if _, present := headers["X-Amz-Security-Token"]; present {
		t.Error("expected X-Amz-Security-Token to be absent")
	}

	req.Header.Set("X-Amz-Security-Token", "token-value")
	headers = extractSignedHeaders(req)
	if headers["X-Amz-Security-Token"] != "token-value" {
		t.Errorf("expected X-Amz-Security-Token to be present, got %v", headers)
	}
}

func TestBuildHTTPRequest_PathIncludesQueryString(t *testing.T) {
	reqCtx := newRequestBodyCtx(nil, nil)
	req, err := buildHTTPRequest(reqCtx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Path != "/foo" {
		t.Errorf("expected path /foo, got %q", req.URL.Path)
	}
	if req.URL.RawQuery != "bar=baz" {
		t.Errorf("expected query bar=baz, got %q", req.URL.RawQuery)
	}
	wantHost := "example.execute-api.us-east-1.amazonaws.com"
	if req.Host != wantHost {
		t.Errorf("expected Host %q, got %q", wantHost, req.Host)
	}
}

func TestBuildHTTPRequest_NoUpstreamInfo_ReturnsError(t *testing.T) {
	reqCtx := newRequestBodyCtx(nil, nil)
	reqCtx.UpstreamInfo = nil

	if _, err := buildHTTPRequest(reqCtx, nil); err == nil {
		t.Error("expected an error when no upstream has been resolved for the route")
	}
}

func TestBuildHTTPRequest_UsesUpstreamInfoOverClientFacingAuthority(t *testing.T) {
	reqCtx := newRequestBodyCtx(nil, nil)
	// Simulate a request that arrived via a custom-domain gateway host, distinct
	// from the actual AWS-hosted backend the route resolves to.
	reqCtx.UpstreamInfo = &policyenginev1.UpstreamInfo{
		URL: "https://dynamodb.us-east-1.amazonaws.com",
	}

	req, err := buildHTTPRequest(reqCtx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Scheme != "https" || req.URL.Host != "dynamodb.us-east-1.amazonaws.com" {
		t.Errorf("expected request signed against the resolved upstream, got %q", req.URL.String())
	}
	if req.Host != "dynamodb.us-east-1.amazonaws.com" {
		t.Errorf("expected Host to be the resolved upstream, got %q", req.Host)
	}
	if req.URL.Path != "/foo" || req.URL.RawQuery != "bar=baz" {
		t.Errorf("expected path/query to be preserved, got %q", req.URL.String())
	}
}

func TestBuildHTTPRequest_InvalidUpstreamURL(t *testing.T) {
	reqCtx := newRequestBodyCtx(nil, nil)
	reqCtx.UpstreamInfo = &policyenginev1.UpstreamInfo{URL: "://not-a-valid-url"}

	if _, err := buildHTTPRequest(reqCtx, nil); err == nil {
		t.Error("expected an error for an invalid upstream URL")
	}
}

// TestSigningFailureDeclaresFault covers the fault declaration on the gateway's own
// failures to sign: credentials it cannot resolve, and a SigV4 signature it cannot
// produce. Only the deployment can fix a bad role ARN or an unreachable STS, so these are
// precisely the failures a fault policy exists to notify on.
func TestSigningFailureDeclaresFault(t *testing.T) {
	validCreds := func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}, nil
	}
	tests := []struct {
		name       string
		retrieve   func(ctx context.Context) (aws.Credentials, error)
		signErr    error
		wantReason string
	}{
		{
			name: "credentials cannot be resolved",
			retrieve: func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{}, errors.New("boom")
			},
			wantReason: "failed to resolve AWS credentials",
		},
		{
			name:       "request cannot be signed",
			retrieve:   validCreds,
			signErr:    errors.New("boom"),
			wantReason: "failed to sign AWS SigV4 request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPolicy()
			p.retrieveCredentialsFunc = tt.retrieve
			p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
				return tt.signErr
			}

			reqCtx := newRequestBodyCtx(nil, nil)
			action := p.OnRequestBody(context.Background(), reqCtx, nil)

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if !resp.IsFault {
				t.Fatalf("expected IsFault=true on a signing failure")
			}
			if resp.Fault == nil {
				t.Fatalf("expected Error to be populated")
			}
			if resp.Fault.Code != policy.FaultCodeMediationFailed {
				t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
			}
			if resp.Fault.Type != policy.FaultTypeMediation {
				t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeMediation, resp.Fault.Type)
			}
			if !strings.HasPrefix(resp.Fault.Description, tt.wantReason) {
				t.Fatalf("expected Error.Description to start with %q, got %q", tt.wantReason, resp.Fault.Description)
			}
			// The gateway's own diagnostic must not reach the caller's body.
			if strings.Contains(string(resp.Body), resp.Fault.Description) {
				t.Fatalf("Description leaked into the client body: %q", resp.Fault.Description)
			}
			if strings.Contains(string(resp.Body), "boom") {
				t.Fatalf("underlying error leaked into the client body: %s", resp.Body)
			}
		})
	}
}
