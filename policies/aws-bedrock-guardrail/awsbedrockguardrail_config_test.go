package awsbedrockguardrail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// phaseParams returns the minimal request-phase configuration every attachment
// needs, so credential tests can focus on the credential fields.
func phaseParams() map[string]interface{} {
	return map[string]interface{}{"jsonPath": "$.messages[-1].content"}
}

func paramsWith(overrides map[string]interface{}) map[string]interface{} {
	params := baseParams()
	params["request"] = phaseParams()
	for k, v := range overrides {
		if v == nil {
			delete(params, k)
			continue
		}
		params[k] = v
	}
	return params
}

func mustGetPolicy(t *testing.T, params map[string]interface{}) *AWSBedrockGuardrailPolicy {
	t.Helper()
	p, err := getPolicyForTest(params)
	if err != nil {
		t.Fatalf("GetPolicy returned an unexpected error: %v", err)
	}
	return p
}

func getPolicyForTest(params map[string]interface{}) (*AWSBedrockGuardrailPolicy, error) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		return nil, err
	}
	p, ok := raw.(*AWSBedrockGuardrailPolicy)
	if !ok {
		return nil, fmt.Errorf("GetPolicy returned %T, want *AWSBedrockGuardrailPolicy", raw)
	}
	return p, nil
}

func expectGetPolicyError(t *testing.T, params map[string]interface{}, wantSubstring string) {
	t.Helper()
	_, err := getPolicyForTest(params)
	if err == nil {
		t.Fatalf("expected an error containing %q, got none", wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("expected an error containing %q, got: %v", wantSubstring, err)
	}
}

// --- Guardrail identity resolution (design §5.4) ---------------------------

func TestResolveIdentity_MergedValueIsUsed(t *testing.T) {
	// The engine merges the user-level value over the system-level one before
	// the policy sees it, so a single key carries the effective value.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"region":           "eu-west-1",
		"guardrailID":      "gr-eu-strict",
		"guardrailVersion": "3",
	}))

	if p.region != "eu-west-1" || p.guardrailID != "gr-eu-strict" || p.guardrailVersion != "3" {
		t.Fatalf("unexpected identity: region=%q guardrailID=%q guardrailVersion=%q",
			p.region, p.guardrailID, p.guardrailVersion)
	}
}

func TestResolveIdentity_MissingValuesAreRejected(t *testing.T) {
	for _, key := range []string{"region", "guardrailID", "guardrailVersion"} {
		t.Run(key, func(t *testing.T) {
			expectGetPolicyError(t, paramsWith(map[string]interface{}{key: nil}),
				fmt.Sprintf("'%s' parameter is required", key))
		})
	}
}

func TestResolveIdentity_EmptyAndNonStringRejected(t *testing.T) {
	expectGetPolicyError(t, paramsWith(map[string]interface{}{"region": ""}),
		"'region' parameter is required")
	expectGetPolicyError(t, paramsWith(map[string]interface{}{"region": 42}),
		"'region' must be a string")
}

func TestResolveIdentity_DeprecatedKeysTakePrecedence(t *testing.T) {
	// The deprecated spelling wins, matching v1.1.0. This is what keeps an
	// existing attachment pointed at its own guardrail on a gateway that also
	// sets awsbedrock_guardrail_id: after the merge the canonical key carries
	// the gateway-wide value whether the author wrote one or not, so preferring
	// it would silently redirect every v1.1.0 attachment.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"guardrailID":           "gr-gateway-wide",
		"guardrailVersion":      "3",
		"localGuardrailID":      "gr-attachment-own",
		"localGuardrailVersion": "1",
	}))

	if p.guardrailID != "gr-attachment-own" {
		t.Fatalf("expected localGuardrailID to win, got %q", p.guardrailID)
	}
	if p.guardrailVersion != "1" {
		t.Fatalf("expected localGuardrailVersion to win, got %q", p.guardrailVersion)
	}
}

func TestResolveIdentity_V110AttachmentKeepsItsOwnGuardrail(t *testing.T) {
	// The regression this ordering exists to prevent: a v1.1.0 attachment on a
	// gateway with a non-empty awsbedrock_guardrail_id must keep using its own
	// guardrail, not silently switch to the gateway-wide one.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"guardrailID":           "gr-gateway-wide", // as the system level supplies it
		"guardrailVersion":      "DRAFT",
		"localGuardrailID":      "gr-tenant-a", // all a v1.1.0 attachment sets
		"localGuardrailVersion": "1",
	}))

	if p.guardrailID == "gr-gateway-wide" {
		t.Fatal("v1.1.0 attachment was silently redirected to the gateway-wide guardrail")
	}
}

func TestResolveIdentity_DeprecatedKeysUsedWhenCurrentAbsent(t *testing.T) {
	// A v1.1.0 attachment on a gateway that supplies no canonical value keeps
	// resolving to its own guardrail.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"guardrailID":           nil,
		"guardrailVersion":      nil,
		"localGuardrailID":      "gr-tenant-a",
		"localGuardrailVersion": "1",
	}))

	if p.guardrailID != "gr-tenant-a" || p.guardrailVersion != "1" {
		t.Fatalf("expected the deprecated params to be used as fallback: id=%q version=%q",
			p.guardrailID, p.guardrailVersion)
	}
}

func TestResolveIdentity_EmptyCanonicalFallsBackToDeprecated(t *testing.T) {
	// An empty system-level value must not shadow a deprecated user-level value.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"guardrailID":           "",
		"guardrailVersion":      "",
		"localGuardrailID":      "gr-tenant-a",
		"localGuardrailVersion": "1",
	}))

	if p.guardrailID != "gr-tenant-a" || p.guardrailVersion != "1" {
		t.Fatalf("empty canonical value shadowed the deprecated one: id=%q version=%q",
			p.guardrailID, p.guardrailVersion)
	}
}

func TestResolveIdentity_CanonicalKeysUsedWhenNoDeprecatedKeys(t *testing.T) {
	p := mustGetPolicy(t, paramsWith(nil))
	if p.guardrailID != "gr-123" || p.guardrailVersion != "DRAFT" {
		t.Fatalf("unexpected identity: id=%q version=%q", p.guardrailID, p.guardrailVersion)
	}
}

// --- Credential set resolution (design §5.3, §5.4) ------------------------

func TestCredentialSet_AWSAuthIsAtomic(t *testing.T) {
	// The system-level external ID must not combine with a user-level
	// role ARN: that pairing is the cross-tenant role hijack the external ID
	// exists to prevent.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsRoleARN":         "arn:aws:iam::111122223333:role/gateway-default",
		"awsRoleRegion":      "us-east-1",
		"awsRoleExternalID":  "gateway-wide-external-id",
		"awsAccessKeyID":     "AKIAGATEWAY",
		"awsSecretAccessKey": "gateway-secret",
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}))

	if p.authType != AuthTypeSTSAssumeRole {
		t.Fatalf("expected %q, got %q", AuthTypeSTSAssumeRole, p.authType)
	}
	if p.creds.roleARN != "arn:aws:iam::444455556666:role/tenant-a" {
		t.Fatalf("expected the attachment role ARN, got %q", p.creds.roleARN)
	}
	if p.creds.roleExternalID != "" {
		t.Fatalf("system-level external ID leaked into a user-level credential set: %q", p.creds.roleExternalID)
	}
	if p.creds.accessKeyID != "" || p.creds.secretAccessKey != "" {
		t.Fatalf("system-level static credentials leaked into a user-level credential set")
	}
}

func TestCredentialSet_RoleRegionDefaultsToGuardrailRegion(t *testing.T) {
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"region": "eu-west-1",
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}))

	if p.creds.roleRegion != "eu-west-1" {
		t.Fatalf("expected role region to default to the guardrail region, got %q", p.creds.roleRegion)
	}
}

func TestCredentialSet_SessionNameDefault(t *testing.T) {
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}))
	if p.creds.roleSessionName != defaultRoleSessionName {
		t.Fatalf("expected default session name %q, got %q", defaultRoleSessionName, p.creds.roleSessionName)
	}

	p = mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
			"awsRoleSessionName": "wso2-gw-support-api",
		},
	}))
	if p.creds.roleSessionName != "wso2-gw-support-api" {
		t.Fatalf("expected the configured session name, got %q", p.creds.roleSessionName)
	}
}

func TestCredentialSet_ModeValidation(t *testing.T) {
	cases := []struct {
		name    string
		awsAuth map[string]interface{}
		wantErr string
	}{
		{
			name:    "unknown authenticationType",
			awsAuth: map[string]interface{}{"authenticationType": "magic"},
			wantErr: "'awsAuth.authenticationType' must be one of",
		},
		{
			name:    "static credentials without a key",
			awsAuth: map[string]interface{}{"authenticationType": AuthTypeIAMUserAccessKey},
			wantErr: "'awsAuth.awsAccessKeyID' is required",
		},
		{
			name: "static credentials without a secret",
			awsAuth: map[string]interface{}{
				"authenticationType": AuthTypeIAMUserAccessKey,
				"awsAccessKeyID":     "AKIAEXAMPLE",
			},
			wantErr: "'awsAuth.awsSecretAccessKey' is required",
		},
		{
			name:    "assume role without an ARN",
			awsAuth: map[string]interface{}{"authenticationType": AuthTypeSTSAssumeRole},
			wantErr: "'awsAuth.awsRoleARN' is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectGetPolicyError(t, paramsWith(map[string]interface{}{"awsAuth": tc.awsAuth}), tc.wantErr)
		})
	}
}

func TestCredentialSet_AWSAuthWrongType(t *testing.T) {
	expectGetPolicyError(t, paramsWith(map[string]interface{}{"awsAuth": "sts-assume-role"}),
		"'awsAuth' must be an object")
}

func TestCredentialSet_DefaultCredentialChainNeedsNothing(t *testing.T) {
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{"authenticationType": AuthTypeDefaultCredentialChain},
	}))

	if p.authType != AuthTypeDefaultCredentialChain {
		t.Fatalf("expected %q, got %q", AuthTypeDefaultCredentialChain, p.authType)
	}
	if p.credentialsProvider != nil {
		t.Fatal("default credential chain should defer to the SDK rather than build a provider")
	}
}

func TestCredentialSet_IRSARequiresEnvironment(t *testing.T) {
	// Neither AWS_ROLE_ARN nor AWS_WEB_IDENTITY_TOKEN_FILE is set in tests, so
	// IRSA must fail loudly at deploy time rather than silently falling back to
	// another credential source.
	t.Setenv(envRoleARN, "")
	t.Setenv(envWebIdentityTokenFile, "")

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{"authenticationType": AuthTypeIRSA},
	}), "'awsAuth.awsRoleARN' is required")

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeIRSA,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}), envWebIdentityTokenFile)
}

func TestCredentialSet_IRSABuildsProvider(t *testing.T) {
	tokenFile := t.TempDir() + "/token"
	t.Setenv(envWebIdentityTokenFile, tokenFile)
	t.Setenv(envRoleARN, "arn:aws:iam::444455556666:role/from-env")

	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{"authenticationType": AuthTypeIRSA},
	}))

	if p.authType != AuthTypeIRSA {
		t.Fatalf("expected %q, got %q", AuthTypeIRSA, p.authType)
	}
	if p.credentialsProvider == nil {
		t.Fatal("expected an IRSA credentials provider to be built at init")
	}
}

// --- System-level credential path (design §5.4) ---------------------------

func TestCredentialSet_SystemModeInference(t *testing.T) {
	cases := []struct {
		name     string
		params   map[string]interface{}
		wantType string
	}{
		{
			name: "role ARN and region infer assume-role",
			params: map[string]interface{}{
				"awsRoleARN":    "arn:aws:iam::111122223333:role/gateway-default",
				"awsRoleRegion": "us-east-1",
			},
			wantType: AuthTypeSTSAssumeRole,
		},
		{
			name: "key and secret infer static credentials",
			params: map[string]interface{}{
				"awsAccessKeyID":     "AKIAEXAMPLE",
				"awsSecretAccessKey": "secret",
			},
			wantType: AuthTypeIAMUserAccessKey,
		},
		{
			name:     "nothing configured falls back to the default chain",
			params:   map[string]interface{}{},
			wantType: AuthTypeDefaultCredentialChain,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// authType is always "system" here; what varies is the provider
			// the system-level fields imply.
			p := mustGetPolicy(t, paramsWith(tc.params))
			if p.authType != AuthTypeSystem {
				t.Fatalf("expected %q, got %q", AuthTypeSystem, p.authType)
			}
			gotProvider := p.credentialsProvider != nil
			wantProvider := tc.wantType != AuthTypeDefaultCredentialChain
			if gotProvider != wantProvider {
				t.Fatalf("%s: provider built = %v, want %v", tc.name, gotProvider, wantProvider)
			}
		})
	}
}

// --- Allowlists (design §5.5) ---------------------------------------------

func TestAllowlists_RestrictEffectiveValues(t *testing.T) {
	cases := []struct {
		name    string
		params  map[string]interface{}
		wantErr string
	}{
		{
			name: "region outside allowedRegions",
			params: map[string]interface{}{
				"region":         "ap-south-1",
				"allowedRegions": []interface{}{"us-east-1", "eu-west-1"},
			},
			wantErr: "'region' value \"ap-south-1\" is not permitted",
		},
		{
			name: "guardrail ID outside allowedGuardrailIDs",
			params: map[string]interface{}{
				"allowedGuardrailIDs": []interface{}{"gr-approved"},
			},
			wantErr: "'guardrailID' value \"gr-123\" is not permitted",
		},
		{
			name: "role ARN outside allowedRoleARNs",
			params: map[string]interface{}{
				"allowedRoleARNs": []interface{}{"arn:aws:iam::444455556666:role/wso2-gw-guardrail-*"},
				"awsAuth": map[string]interface{}{
					"authenticationType": AuthTypeSTSAssumeRole,
					"awsRoleARN":         "arn:aws:iam::444455556666:role/some-other-role",
				},
			},
			wantErr: "'awsRoleARN' value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectGetPolicyError(t, paramsWith(tc.params), tc.wantErr)
		})
	}
}

func TestAllowlists_ARNPrefixMatching(t *testing.T) {
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"allowedRoleARNs": []interface{}{"arn:aws:iam::444455556666:role/wso2-gw-guardrail-*"},
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/wso2-gw-guardrail-tenant-a",
		},
	}))
	if p.creds.roleARN == "" {
		t.Fatal("expected the prefix-matched role ARN to be accepted")
	}
}

func TestAllowlists_ForbidUserLevelStaticCredentials(t *testing.T) {
	// The control that lets an operator keep every parameter attachment-level
	// while refusing attachment-level long-lived secrets.
	allowed := []interface{}{AuthTypeIRSA, AuthTypeSTSAssumeRole, AuthTypeDefaultCredentialChain}

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"allowedAuthTypes": allowed,
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeIAMUserAccessKey,
			"awsAccessKeyID":     "AKIAEXAMPLE",
			"awsSecretAccessKey": "secret",
		},
	}), "'authenticationType' value \"iam-user-access-key\" is not permitted")

	mustGetPolicy(t, paramsWith(map[string]interface{}{
		"allowedAuthTypes": allowed,
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}))
}

func TestAllowlists_EmptyMeansUnrestricted(t *testing.T) {
	mustGetPolicy(t, paramsWith(map[string]interface{}{
		"allowedRegions":      []interface{}{},
		"allowedGuardrailIDs": nil,
		"allowedAuthTypes":    []interface{}{},
	}))
}

func TestAllowlists_RejectMalformedConfiguration(t *testing.T) {
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"allowedRegions": []interface{}{"us-east-1", 7},
	}), "'allowedRegions' must be an array of strings")
}

func TestAllowlists_GatewayDefaultOutsideItsOwnAllowlistIsRejected(t *testing.T) {
	// Checking the effective value also catches an operator misconfiguration,
	// rather than only policing attachment-supplied values.
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"region":         "us-east-1",
		"allowedRegions": []interface{}{"eu-west-1"},
	}), "not permitted")
}

// --- passthroughOnError behaviour -----------------------------------------

// policyWithMockedBedrock builds a policy whose Bedrock call fails with err,
// with passthroughOnError enabled on both phases.
func policyWithMockedBedrock(err error, configErr error) *AWSBedrockGuardrailPolicy {
	mockClient := &mockBedrockClient{err: err}
	return &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		hasRequestParams: true,
		requestParams: AWSBedrockGuardrailPolicyParams{
			Enabled:            true,
			PassthroughOnError: true,
		},
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, configErr
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return mockClient
		},
	}
}

func requestContextForTest() *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Content: []byte(`hello`)},
	}
}

func TestPassthroughOnError_ToleratesAnyFailure(t *testing.T) {
	// passthroughOnError keeps pre-v1.2.0 semantics: when enabled, the request
	// proceeds whatever the guardrail call failed with. The policy draws no
	// distinction between a transient outage and a permanently broken
	// configuration, so one representative error covers the behaviour.
	p := policyWithMockedBedrock(errors.New("bedrock api unavailable"), nil)
	result := p.OnRequestBody(context.Background(), requestContextForTest(), map[string]interface{}{})
	if _, passedThrough := result.(policy.UpstreamRequestModifications); !passedThrough {
		t.Fatalf("expected passthrough with passthroughOnError enabled, got blocked (%T)", result)
	}
}

func TestPassthroughOnError_DisabledBlocks(t *testing.T) {
	p := policyWithMockedBedrock(errors.New("bedrock api unavailable"), nil)
	p.requestParams.PassthroughOnError = false
	result := p.OnRequestBody(context.Background(), requestContextForTest(), map[string]interface{}{})
	if _, passedThrough := result.(policy.UpstreamRequestModifications); passedThrough {
		t.Fatal("expected block when passthroughOnError is off, got passthrough")
	}
}

func TestPassthroughOnError_CoversCredentialResolutionFailure(t *testing.T) {
	// A failure to build the AWS config is also tolerated, matching pre-v1.2.0.
	p := policyWithMockedBedrock(nil, errors.New("failed to load AWS config: no credentials"))
	result := p.OnRequestBody(context.Background(), requestContextForTest(), map[string]interface{}{})
	if _, passedThrough := result.(policy.UpstreamRequestModifications); !passedThrough {
		t.Fatal("expected passthrough on credential resolution failure with passthroughOnError enabled")
	}
}

func TestDeriveRoleSessionName(t *testing.T) {
	cases := []struct {
		name     string
		metadata policy.PolicyMetadata
		want     string
	}{
		{"no metadata falls back", policy.PolicyMetadata{}, defaultRoleSessionName},
		{"api name only", policy.PolicyMetadata{APIName: "support-api"}, "wso2-gw-support-api"},
		{"name and version", policy.PolicyMetadata{APIName: "support-api", APIVersion: "v1.0"}, "wso2-gw-support-api-v1.0"},
		{"disallowed characters replaced", policy.PolicyMetadata{APIName: "support/api tenant"}, "wso2-gw-support-api-tenant"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveRoleSessionName(tc.metadata); got != tc.want {
				t.Fatalf("deriveRoleSessionName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveRoleSessionName_AlwaysSTSValid(t *testing.T) {
	// STS accepts only [\w+=,.@-]{2,64}; a name it rejects would fail the
	// assumption at request time rather than at deploy time.
	valid := regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	metadatas := []policy.PolicyMetadata{
		{},
		{APIName: strings.Repeat("very-long-api-name", 10), APIVersion: "v1"},
		{APIName: "!!!"},
		{APIName: "アプリ", APIVersion: "v1"},
		{APIName: "a/b\\c:d e"},
	}

	for _, md := range metadatas {
		got := deriveRoleSessionName(md)
		if !valid.MatchString(got) {
			t.Fatalf("deriveRoleSessionName(%+v) = %q, which STS would reject", md, got)
		}
	}
}

func TestRoleSessionName_DerivedByDefaultAndOverridable(t *testing.T) {
	md := policy.PolicyMetadata{APIName: "support-api", APIVersion: "v1.0"}

	raw, err := GetPolicy(md, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := raw.(*AWSBedrockGuardrailPolicy).creds.roleSessionName; got != "wso2-gw-support-api-v1.0" {
		t.Fatalf("expected a session name derived from the API, got %q", got)
	}

	raw, err = GetPolicy(md, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
			"awsRoleSessionName": "explicit-name",
		},
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := raw.(*AWSBedrockGuardrailPolicy).creds.roleSessionName; got != "explicit-name" {
		t.Fatalf("expected the explicit session name to win, got %q", got)
	}
}

// --- Credential caching (design §5.6) -------------------------------------

func TestCredentialsProvider_CachesAcrossRequests(t *testing.T) {
	// The provider is built once and wraps a credentials cache, so role
	// assumption happens on first use and on refresh rather than per request.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
		},
	}))

	if _, ok := p.credentialsProvider.(*aws.CredentialsCache); !ok {
		t.Fatalf("expected the assume-role provider to be cached, got %T", p.credentialsProvider)
	}
}

func TestCredentialsProvider_NotSharedBetweenAttachments(t *testing.T) {
	// Two attachments naming the same role with different external IDs must not
	// share credentials - one would otherwise borrow the other's identity.
	newPolicy := func(externalID string) *AWSBedrockGuardrailPolicy {
		return mustGetPolicy(t, paramsWith(map[string]interface{}{
			"awsAuth": map[string]interface{}{
				"authenticationType": AuthTypeSTSAssumeRole,
				"awsRoleARN":         "arn:aws:iam::444455556666:role/shared-arn",
				"awsRoleExternalID":  externalID,
			},
		}))
	}

	first := newPolicy("tenant-a-external-id")
	second := newPolicy("tenant-b-external-id")

	if first.credentialsProvider == second.credentialsProvider {
		t.Fatal("two attachments share one credentials provider despite different external IDs")
	}
	if first.creds.roleExternalID == second.creds.roleExternalID {
		t.Fatal("external IDs collapsed between attachments")
	}
}

// --- Client-facing error hygiene (design §6.3, S10) -----------------------

func TestErrorResponse_DoesNotLeakAWSErrorText(t *testing.T) {
	// AWS distinguishes "no such guardrail" from "exists but denied", so
	// echoing the raw message back would let a caller enumerate the guardrails
	// and roles configured in the account.
	awsErr := errors.New("operation error Bedrock Runtime: ApplyGuardrail, " +
		"https response error StatusCode: 400, RequestID: abc-123, " +
		"ResourceNotFoundException: Guardrail gr-secret-name not found in account 444455556666")

	p := &AWSBedrockGuardrailPolicy{}
	resp := p.buildErrorResponse("Error calling Amazon Bedrock Guardrails", awsErr, false, true, nil)

	imm, ok := resp.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", resp)
	}

	body := string(imm.Body)
	for _, leaked := range []string{"gr-secret-name", "444455556666", "ResourceNotFoundException", "RequestID", "abc-123"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("client response leaked %q from the AWS error: %s", leaked, body)
		}
	}
}

func TestErrorResponse_StillReportsGuardrailAssessments(t *testing.T) {
	// Withholding SDK diagnostics must not withhold genuine guardrail
	// assessment detail, which is what showAssessment is for.
	p := &AWSBedrockGuardrailPolicy{}
	resp := p.buildErrorResponse("reason", nil, false, true, makePIIIntervenedOutput("john@example.com"))

	imm, ok := resp.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", resp)
	}
	if !strings.Contains(string(imm.Body), "assessments") {
		t.Fatalf("expected guardrail assessments in the response body, got: %s", imm.Body)
	}
}

// --- Schema guard (design §5.1) -------------------------------------------

// TestSchema_UserLevelIdentityParamsDeclareNoDefault guards the rule that makes
// "omit to inherit the system-level value" true.
//
// System-level and user-level values are merged into one map before the
// policy sees them. A `default:` on a user-level property materialises it on
// every attachment, so the system-level value would never survive the merge and
// the config.toml setting would silently stop doing anything. Nothing else in
// the build catches that, hence this check.
func TestSchema_UserLevelIdentityParamsDeclareNoDefault(t *testing.T) {
	source, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatalf("cannot read policy-definition.yaml: %v", err)
	}
	lines := strings.Split(string(source), "\n")

	// Bound the scan to the user-level `parameters:` block; systemParameters
	// may legitimately carry defaults.
	start, end := -1, len(lines)
	for i, line := range lines {
		if line == "parameters:" {
			start = i
		} else if line == "systemParameters:" && start >= 0 {
			end = i
			break
		}
	}
	if start < 0 {
		t.Fatal("could not locate the parameters: block in policy-definition.yaml")
	}

	const propIndent = "    " // properties of the top-level parameters object
	for _, property := range []string{"region", "guardrailID", "guardrailVersion", "localGuardrailID", "localGuardrailVersion"} {
		t.Run(property, func(t *testing.T) {
			header := propIndent + property + ":"
			from := -1
			for i := start; i < end; i++ {
				if lines[i] == header {
					from = i + 1
					break
				}
			}
			if from < 0 {
				t.Fatalf("property %q not found in the parameters: block", property)
			}
			for i := from; i < end; i++ {
				line := lines[i]
				// Stop at the next property at the same indentation level.
				if strings.HasPrefix(line, propIndent) && !strings.HasPrefix(line, propIndent+" ") && strings.TrimSpace(line) != "" {
					break
				}
				if strings.HasPrefix(strings.TrimSpace(line), "default:") {
					t.Fatalf("%q declares a default, which would shadow the system-level value on every attachment", property)
				}
			}
		})
	}
}

func TestCredentialSet_FormatBackstop(t *testing.T) {
	// Duplicated from the schema on purpose: the schema is only enforced as
	// well as the control plane enforces it, and a malformed value slipping
	// through would fail against STS on live traffic instead of at deploy time.
	cases := []struct {
		name    string
		awsAuth map[string]interface{}
		wantErr string
	}{
		{
			name: "malformed role ARN",
			awsAuth: map[string]interface{}{
				"authenticationType": AuthTypeSTSAssumeRole,
				"awsRoleARN":         "not-an-arn",
			},
			wantErr: "not a valid IAM role ARN",
		},
		{
			name: "role ARN with a short account id",
			awsAuth: map[string]interface{}{
				"authenticationType": AuthTypeSTSAssumeRole,
				"awsRoleARN":         "arn:aws:iam::4444:role/tenant-a",
			},
			wantErr: "not a valid IAM role ARN",
		},
		{
			name: "malformed role region",
			awsAuth: map[string]interface{}{
				"authenticationType": AuthTypeSTSAssumeRole,
				"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
				"awsRoleRegion":      "Not A Region",
			},
			wantErr: "not a valid AWS region",
		},
		{
			name: "session name STS would reject",
			awsAuth: map[string]interface{}{
				"authenticationType": AuthTypeSTSAssumeRole,
				"awsRoleARN":         "arn:aws:iam::444455556666:role/tenant-a",
				"awsRoleSessionName": "has spaces and /slashes",
			},
			wantErr: "awsRoleSessionName",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectGetPolicyError(t, paramsWith(map[string]interface{}{"awsAuth": tc.awsAuth}), tc.wantErr)
		})
	}
}

// --- authenticationType "system" and mandatory awsAuth (design decision) ----

func TestAWSAuth_DefaultsToSystemWhenOmitted(t *testing.T) {
	// v1.1.0 attachments carry no credential block at all and relied on the
	// gateway-wide identity; they must keep working untouched.
	p := paramsWith(nil)
	delete(p, "awsAuth")
	got := mustGetPolicy(t, p)
	if got.authType != AuthTypeSystem {
		t.Fatalf("expected omitted awsAuth to default to %q, got %q", AuthTypeSystem, got.authType)
	}
}

func TestAWSAuth_DefaultsToSystemWhenTypeOmitted(t *testing.T) {
	got := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{},
	}))
	if got.authType != AuthTypeSystem {
		t.Fatalf("expected empty awsAuth to default to %q, got %q", AuthTypeSystem, got.authType)
	}
}

func TestAWSAuth_CredentialFieldsWithoutTypeAreIgnored(t *testing.T) {
	// No authenticationType means "system". Credential fields alongside it are
	// ignored rather than rejected, matching how the policy treated fields a
	// mode does not read before v1.2.0.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{"awsRoleARN": "arn:aws:iam::444455556666:role/tenant-a"},
	}))
	if p.authType != AuthTypeSystem {
		t.Fatalf("expected %q, got %q", AuthTypeSystem, p.authType)
	}
}

func TestAWSAuth_SystemModeUsesGatewayCredentials(t *testing.T) {
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsRoleARN":    "arn:aws:iam::111122223333:role/gateway-default",
		"awsRoleRegion": "us-east-1",
		"awsAuth":       map[string]interface{}{"authenticationType": AuthTypeSystem},
	}))

	if p.authType != AuthTypeSystem {
		t.Fatalf("expected %q, got %q", AuthTypeSystem, p.authType)
	}
	if p.creds.roleARN != "arn:aws:iam::111122223333:role/gateway-default" {
		t.Fatalf("system mode did not pick up the gateway-wide role: %q", p.creds.roleARN)
	}
	if p.credentialsProvider == nil {
		t.Fatal("expected a provider built from the gateway-wide role")
	}
}

func TestAWSAuth_SystemModeIgnoresCredentialFields(t *testing.T) {
	// The gateway-wide identity is used; anything in awsAuth is ignored. The
	// assertion that matters is that the attachment role does not leak into the
	// resolved set, so the gateway identity really is the one in play.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsRoleARN":    "arn:aws:iam::111122223333:role/gateway-default",
		"awsRoleRegion": "us-east-1",
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSystem,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/attachment-own",
			"awsAccessKeyID":     "AKIAEXAMPLE",
			"awsSecretAccessKey": "shh",
		},
	}))

	if p.authType != AuthTypeSystem {
		t.Fatalf("expected %q, got %q", AuthTypeSystem, p.authType)
	}
	if p.creds.roleARN != "arn:aws:iam::111122223333:role/gateway-default" {
		t.Fatalf("system mode should use the gateway-wide role, got %q", p.creds.roleARN)
	}
	if p.creds.accessKeyID != "" {
		t.Fatalf("attachment key leaked into the system credential set: %q", p.creds.accessKeyID)
	}
}

func TestAWSAuth_DeclaredModeNeverFallsBackToSystem(t *testing.T) {
	// A gateway-wide identity is configured and would work, but the attachment
	// declares irsa with no IRSA environment available. It must fail rather than
	// quietly running under the gateway credentials.
	t.Setenv(envRoleARN, "")
	t.Setenv(envWebIdentityTokenFile, "")

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"awsRoleARN":    "arn:aws:iam::111122223333:role/gateway-default",
		"awsRoleRegion": "us-east-1",
		"awsAuth":       map[string]interface{}{"authenticationType": AuthTypeIRSA},
	}), "awsRoleARN")
}

func TestAWSAuth_SystemIsSubjectToAllowedAuthTypes(t *testing.T) {
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"allowedAuthTypes": []interface{}{AuthTypeIRSA, AuthTypeSTSAssumeRole},
		"awsAuth":          map[string]interface{}{"authenticationType": AuthTypeSystem},
	}), "'authenticationType' value \"system\" is not permitted")
}

func TestSystemLevel_EmptyStringDefaultsAreNotErrors(t *testing.T) {
	// config.toml ships every awsbedrock_* key with an empty default, and those
	// empty values reach the policy verbatim rather than being dropped. They
	// must read as "not configured" or the documented default configuration is
	// unusable.
	p := paramsWith(map[string]interface{}{
		"awsAccessKeyID":     "",
		"awsSecretAccessKey": "",
		"awsSessionToken":    "",
		"awsRoleARN":         "",
		"awsRoleRegion":      "",
		"awsRoleExternalID":  "",
	})
	got := mustGetPolicy(t, p)
	if got.authType != AuthTypeSystem {
		t.Fatalf("expected %q, got %q", AuthTypeSystem, got.authType)
	}
	if got.credentialsProvider != nil {
		t.Fatal("empty system credentials should defer to the SDK default chain")
	}
}

func TestSystemLevel_BothRoutesValidateIdentically(t *testing.T) {
	// Omitting awsAuth and declaring authenticationType "system" are meant to be
	// equivalent. Validating in only one of them made the same gateway
	// configuration deploy or fail depending on which spelling was used.
	incomplete := func() map[string]interface{} {
		return paramsWith(map[string]interface{}{
			"awsRoleARN": "arn:aws:iam::111122223333:role/gw", // no awsRoleRegion
			"awsAuth":    nil,                                 // removed below
		})
	}

	omitted := incomplete()
	delete(omitted, "awsAuth")
	_, errOmitted := getPolicyForTest(omitted)

	explicit := incomplete()
	explicit["awsAuth"] = map[string]interface{}{"authenticationType": AuthTypeSystem}
	_, errExplicit := getPolicyForTest(explicit)

	if (errOmitted == nil) != (errExplicit == nil) {
		t.Fatalf("the two equivalent shapes disagree: omitted=%v explicit=%v", errOmitted, errExplicit)
	}
	if errOmitted == nil {
		t.Fatal("an incomplete system role config should be rejected on both routes")
	}
}

func TestAllowlist_IRSAEnvironmentRoleIsChecked(t *testing.T) {
	// The IRSA role can arrive from AWS_ROLE_ARN instead of the attachment.
	// Both routes must face the same allowlist, or an operator who sets
	// allowedRoleARNs finds it applies only to roles written out explicitly.
	envARN := "arn:aws:iam::367134611783:role/env-injected-role"
	t.Setenv(envWebIdentityTokenFile, t.TempDir()+"/token")
	t.Setenv(envRoleARN, envARN)

	restrictive := []interface{}{"arn:aws:iam::367134611783:role/permitted-only-*"}

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"allowedRoleARNs": restrictive,
		"awsAuth":         map[string]interface{}{"authenticationType": AuthTypeIRSA, "awsRoleARN": envARN},
	}), "not permitted")

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"allowedRoleARNs": restrictive,
		"awsAuth":         map[string]interface{}{"authenticationType": AuthTypeIRSA},
	}), "not permitted")
}

func TestSystemLevel_MalformedValuesAreRejected(t *testing.T) {
	// System-level fields get the same format checks as user-level ones, so a
	// typo is caught at deploy time rather than against STS on live traffic.
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"awsRoleARN":    "not-an-arn",
		"awsRoleRegion": "us-east-1",
	}), "not a valid IAM role ARN")

	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"awsRoleARN":    "arn:aws:iam::111122223333:role/gw",
		"awsRoleRegion": "Not A Region",
	}), "not a valid AWS region")
}

func TestAllowlist_RejectsWildcardThatIsNotTrailing(t *testing.T) {
	// "*" is a prefix marker, not a glob. An entry with "*" in the middle
	// matches no real value, so every deployment would be refused with a
	// message about the value rather than the configuration. Reject the entry.
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"allowedRoleARNs": []interface{}{"arn:aws:iam::*:role/team-*"},
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/team-a",
		},
	}), "'*' is only supported as the final character")

	// A trailing wildcard still works.
	mustGetPolicy(t, paramsWith(map[string]interface{}{
		"allowedRoleARNs": []interface{}{"arn:aws:iam::444455556666:role/team-*"},
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeSTSAssumeRole,
			"awsRoleARN":         "arn:aws:iam::444455556666:role/team-a",
		},
	}))
}

func TestAWSAuth_ModesThatIgnoreStaticKeysAcceptThem(t *testing.T) {
	// irsa and default-credential-chain never sign with a static key. Supplying
	// one is accepted and ignored; the provider each mode builds is unaffected.
	t.Setenv(envWebIdentityTokenFile, t.TempDir()+"/token")
	t.Setenv(envRoleARN, "arn:aws:iam::367134611783:role/irsa")

	for _, mode := range []string{AuthTypeIRSA, AuthTypeDefaultCredentialChain} {
		t.Run(mode, func(t *testing.T) {
			p := mustGetPolicy(t, paramsWith(map[string]interface{}{
				"awsAuth": map[string]interface{}{
					"authenticationType": mode,
					"awsAccessKeyID":     "AKIAEXAMPLE",
					"awsSecretAccessKey": "shh",
				},
			}))
			if p.authType != mode {
				t.Fatalf("expected %q, got %q", mode, p.authType)
			}
			// default-credential-chain defers to the SDK, so it builds none.
			if mode == AuthTypeDefaultCredentialChain && p.credentialsProvider != nil {
				t.Fatal("default-credential-chain should not build a provider")
			}
		})
	}
}

func TestAllowlist_WildcardsRejectedOnNonPrefixLists(t *testing.T) {
	// Only allowedRoleARNs treats a trailing "*" as a prefix. On the other
	// lists it is a literal that matches nothing, which would refuse every
	// deployment while pointing at the value rather than the configuration.
	for _, tc := range []struct{ list, entry string }{
		{"allowedGuardrailIDs", "gr-*"},
		{"allowedAuthTypes", "s*"},
	} {
		t.Run(tc.list, func(t *testing.T) {
			expectGetPolicyError(t, paramsWith(map[string]interface{}{
				tc.list: []interface{}{tc.entry},
			}), "does not support wildcards")
		})
	}
}

func TestAllowlist_RegionSupportsTrailingWildcard(t *testing.T) {
	// "us-east-*" is a natural way to permit a whole region family.
	mustGetPolicy(t, paramsWith(map[string]interface{}{
		"region":         "us-east-1",
		"allowedRegions": []interface{}{"us-east-*"},
	}))

	// It is still a prefix, not a glob: a different family is refused.
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"region":         "eu-west-1",
		"allowedRegions": []interface{}{"us-east-*"},
	}), "is not permitted")

	// And a non-trailing wildcard remains a configuration error.
	expectGetPolicyError(t, paramsWith(map[string]interface{}{
		"region":         "us-east-1",
		"allowedRegions": []interface{}{"us-*-1"},
	}), "'*' is only supported as the final character")
}

func TestAWSAuth_StaticKeyModeIgnoresRoleFields(t *testing.T) {
	// iam-user-access-key signs directly with the key. Role fields are accepted
	// and ignored; the provider is still a static one.
	p := mustGetPolicy(t, paramsWith(map[string]interface{}{
		"awsAuth": map[string]interface{}{
			"authenticationType": AuthTypeIAMUserAccessKey,
			"awsAccessKeyID":     "AKIAEXAMPLE",
			"awsSecretAccessKey": "shh",
			"awsRoleARN":         "arn:aws:iam::444455556666:role/never-assumed",
			"awsRoleExternalID":  "unused-external-id",
		},
	}))

	if p.authType != AuthTypeIAMUserAccessKey {
		t.Fatalf("expected %q, got %q", AuthTypeIAMUserAccessKey, p.authType)
	}
	if _, ok := p.credentialsProvider.(credentials.StaticCredentialsProvider); !ok {
		t.Fatalf("expected a static credentials provider, got %T", p.credentialsProvider)
	}
}
