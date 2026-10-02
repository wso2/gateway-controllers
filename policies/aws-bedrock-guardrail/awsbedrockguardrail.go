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
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	GuardrailErrorCode           = 422
	TextCleanRegex               = "^\"|\"$"
	MetadataKeyPIIEntities       = "awsbedrockguardrail:pii_entities"
	RequestDefaultJSONPath       = "$.messages[-1].content"
	ResponseDefaultJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = true
	ResponseFlowEnabledByDefault = false
)

// Credential-acquisition modes selectable through awsAuth.authenticationType.
const (
	// AuthTypeSystem defers to the gateway-wide credential configuration in
	// config.toml. It is the explicit way for an attachment to say "I have no
	// AWS identity of my own", replacing the pre-v1.2.0 behaviour of simply
	// omitting the credential block.
	AuthTypeSystem = "system"
	// AuthTypeIRSA obtains credentials via STS AssumeRoleWithWebIdentity using
	// the Kubernetes projected service account token (IAM Roles for Service
	// Accounts). Requires no credential material in the API definition.
	AuthTypeIRSA = "irsa"
	// AuthTypeSTSAssumeRole obtains temporary credentials via STS AssumeRole.
	AuthTypeSTSAssumeRole = "sts-assume-role"
	// AuthTypeDefaultCredentialChain resolves credentials from the AWS SDK's
	// default provider chain, with no role assumption and no configured keys.
	AuthTypeDefaultCredentialChain = "default-credential-chain"
	// AuthTypeIAMUserAccessKey uses a static, long-lived access key/secret pair.
	AuthTypeIAMUserAccessKey = "iam-user-access-key"
)

const (
	defaultRoleSessionName = "bedrock-guardrail-session"

	// Environment variables injected by the EKS Pod Identity Webhook, used by
	// AuthTypeIRSA. The token file path is never taken from a policy param.
	envRoleARN              = "AWS_ROLE_ARN"
	envWebIdentityTokenFile = "AWS_WEB_IDENTITY_TOKEN_FILE"
)

// credentialFields holds the credential configuration resolved for one policy
// attachment, from either its awsAuth object or the gateway-wide settings.
type credentialFields struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	roleARN         string
	roleRegion      string
	roleExternalID  string
	roleSessionName string
}

var textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)

type bedrockGuardrailClient interface {
	ApplyGuardrail(ctx context.Context, params *bedrockruntime.ApplyGuardrailInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error)
}

// AWSBedrockGuardrailPolicy implements AWS Bedrock Guardrail validation
type AWSBedrockGuardrailPolicy struct {
	// Static configuration from params
	region           string
	guardrailID      string
	guardrailVersion string

	// Resolved credential configuration. authType is one of the AuthType*
	// constants; creds holds only the fields that mode uses.
	authType string
	creds    credentialFields

	// credentialsProvider is built once at policy-instance creation time and
	// reused across requests. For the role-assumption modes it wraps an
	// aws.CredentialsCache, so temporary credentials are refreshed near expiry
	// rather than re-fetched from STS on every request.
	credentialsProvider aws.CredentialsProvider

	// Dynamic configuration from params
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     AWSBedrockGuardrailPolicyParams
	responseParams    AWSBedrockGuardrailPolicyParams

	// Testing hooks for AWS interactions.
	loadAWSConfigFunc    func(ctx context.Context, region string) (aws.Config, error)
	newBedrockClientFunc func(cfg aws.Config) bedrockGuardrailClient
}

type AWSBedrockGuardrailPolicyParams struct {
	Enabled            bool
	JsonPath           string
	RedactPII          bool
	PassthroughOnError bool
	ShowAssessment     bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// System-level (systemParameters, from config.toml) and user-level
	// (parameters, from the API definition) values arrive merged into this
	// single map, with user-level values having overwritten system-level ones
	// for any key both levels define.
	region, err := resolveGuardrailIdentityParam(params, "", "region")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	guardrailID, err := resolveGuardrailIdentityParam(params, "localGuardrailID", "guardrailID")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	guardrailVersion, err := resolveGuardrailIdentityParam(params, "localGuardrailVersion", "guardrailVersion")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	authType, creds, err := resolveCredentialSet(params, region, deriveRoleSessionName(metadata))
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Regions and role ARNs accept a trailing "*" as a prefix: "us-east-*" and
	// one ARN prefix per account are both natural to write. Guardrail IDs are
	// opaque strings where a prefix means nothing, and authenticationType is a
	// short enum where "s*" would silently widen to both "system" and
	// "sts-assume-role" - so those two stay exact.
	if err := checkAllowlist(params, "allowedRegions", "region", region, true); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := checkAllowlist(params, "allowedGuardrailIDs", "guardrailID", guardrailID, false); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := checkAllowlist(params, "allowedAuthTypes", "authenticationType", authType, false); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if creds.roleARN != "" {
		if err := checkAllowlist(params, "allowedRoleARNs", "awsRoleARN", creds.roleARN, true); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}

	p := &AWSBedrockGuardrailPolicy{
		region:           region,
		guardrailID:      guardrailID,
		guardrailVersion: guardrailVersion,
		authType:         authType,
		creds:            creds,
	}
	p.loadAWSConfigFunc = p.loadAWSConfig
	p.newBedrockClientFunc = func(cfg aws.Config) bedrockGuardrailClient {
		return bedrockruntime.NewFromConfig(cfg)
	}

	// Build the credentials provider once, so that role assumption does not
	// repeat on every request. A failure here is a configuration failure and
	// rejects the attachment at deploy time rather than failing open later.
	credentialsProvider, err := buildCredentialsProvider(context.Background(), authType, creds)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	p.credentialsProvider = credentialsProvider

	// Extract and parse request parameters if present
	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parseRequestResponseParams(requestParamsRaw, false)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	// Extract and parse response parameters if present
	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
		responseParams, err := parseRequestResponseParams(responseParamsRaw, true)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		p.hasResponseParams = true
		if p.hasRequestParams && p.requestParams.RedactPII {
			responseParams.RedactPII = true
		}
		p.responseParams = responseParams
	}

	// At least one of request or response must be present
	if !p.hasRequestParams && !p.hasResponseParams {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	// Credential material is deliberately absent from this line: the secret
	// access key, session token and role external ID must never be logged.
	slog.Debug("AWSBedrockGuardrail: Policy initialized",
		"region", p.region, "guardrailID", p.guardrailID, "guardrailVersion", p.guardrailVersion,
		"authenticationType", p.authType, "roleARN", p.creds.roleARN,
		"hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

// Mode returns the processing mode for the AWS Bedrock guardrail policy.
func (p *AWSBedrockGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// parseRequestResponseParams parses and validates request/response parameters from map to struct
func parseRequestResponseParams(params map[string]interface{}, isResponse bool) (AWSBedrockGuardrailPolicyParams, error) {
	result := AWSBedrockGuardrailPolicyParams{
		JsonPath: RequestDefaultJSONPath,
		Enabled:  RequestFlowEnabledByDefault,
	}
	if isResponse {
		result.JsonPath = ResponseDefaultJSONPath
		result.Enabled = ResponseFlowEnabledByDefault
	}

	// Extract optional enabled parameter
	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
	}

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional redactPII parameter
	if redactPIIRaw, ok := params["redactPII"]; ok {
		if redactPII, ok := redactPIIRaw.(bool); ok {
			result.RedactPII = redactPII
		} else {
			return result, fmt.Errorf("'redactPII' must be a boolean")
		}
	}

	// Extract optional passthroughOnError parameter
	if passthroughOnErrorRaw, ok := params["passthroughOnError"]; ok {
		if passthroughOnError, ok := passthroughOnErrorRaw.(bool); ok {
			result.PassthroughOnError = passthroughOnError
		} else {
			return result, fmt.Errorf("'passthroughOnError' must be a boolean")
		}
	}

	// Extract optional showAssessment parameter
	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		if showAssessment, ok := showAssessmentRaw.(bool); ok {
			result.ShowAssessment = showAssessment
		} else {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
	}

	return result, nil
}

// getStringParam safely extracts a string parameter
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// resolveGuardrailIdentityParam returns the effective value for one guardrail
// identity setting (region/guardrailID/guardrailVersion).
//
// User-level and system-level parameters share a key name and are merged
// upstream into a single params map, with the user-level value overwriting the
// system-level one, so canonicalKey already carries the effective value and
// needs no fallback logic of its own.
//
// legacyKey, when non-empty, names the deprecated v1.1.0 spelling of the same
// setting (localGuardrailID/localGuardrailVersion), kept for backward
// compatibility. **The deprecated key wins when both are present**, which is the
// order v1.1.0 used.
func resolveGuardrailIdentityParam(params map[string]interface{}, legacyKey, canonicalKey string) (string, error) {
	canonical, err := stringParam(params, canonicalKey)
	if err != nil {
		return "", err
	}

	var legacy string
	if legacyKey != "" {
		legacy, err = stringParam(params, legacyKey)
		if err != nil {
			return "", err
		}
	}

	if legacy != "" {
		if canonical != "" && canonical != legacy {
			slog.Debug("AWSBedrockGuardrail: deprecated parameter takes precedence; remove it to use the current one",
				"deprecatedParam", legacyKey, "deprecatedValue", legacy,
				"param", canonicalKey, "value", canonical)
		}
		return legacy, nil
	}

	if canonical != "" {
		return canonical, nil
	}

	if legacyKey != "" {
		return "", fmt.Errorf("'%s' parameter is required: set it on the policy attachment or in the gateway configuration, or supply the deprecated '%s'", canonicalKey, legacyKey)
	}
	return "", fmt.Errorf("'%s' parameter is required: set it on the policy attachment or in the gateway configuration", canonicalKey)
}

// stringParam reads an optional string parameter, returning "" when absent and
// an error when present with a non-string type.
func stringParam(params map[string]interface{}, key string) (string, error) {
	val, ok := params[key]
	if !ok || val == nil {
		return "", nil
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return str, nil
}

// resolveCredentialSet determines the AWS identity this policy attachment uses,
// choosing between the user-level awsAuth object and the system-level
// (gateway-wide) credential parameters.
//
// The credential configuration resolves atomically rather than field by field.
// When the user level supplies an awsAuth object it supplies the whole thing,
// and every system-level credential field is ignored. Per-field fallback would
// allow a user-level role ARN to pair with a system-level external ID, which is
// precisely the cross-tenant role hijack the external ID exists to prevent.
//
// With no awsAuth object, the system-level fields are read and the mode is
// inferred from which of them are populated, exactly as before this parameter
// existed. That inference now lives behind authenticationType "system"; every
// other mode states itself explicitly.
func resolveCredentialSet(params map[string]interface{}, region, defaultSessionName string) (string, credentialFields, error) {
	raw, hasAWSAuth := params["awsAuth"]
	if !hasAWSAuth {
		// Omitting the credential block means "use the system-level identity",
		// which is what every attachment authored against v1.1.0 relied on.
		return resolveSystemCredentialSet(params, region, defaultSessionName)
	}

	awsAuth, ok := raw.(map[string]interface{})
	if !ok {
		return "", credentialFields{}, fmt.Errorf("'awsAuth' must be an object")
	}

	authType, err := stringParam(awsAuth, "authenticationType")
	if err != nil {
		return "", credentialFields{}, fmt.Errorf("awsAuth: %w", err)
	}
	if authType == "" {
		// The schema defaults authenticationType to "system"; this branch covers
		// construction that bypasses schema validation and behaves the same way.
		// Any credential fields present are ignored rather than rejected, which
		// is how the policy treated fields a mode does not read before v1.2.0.
		return resolveSystemCredentialSet(params, region, defaultSessionName)
	}
	switch authType {
	case AuthTypeSystem, AuthTypeIRSA, AuthTypeSTSAssumeRole, AuthTypeDefaultCredentialChain, AuthTypeIAMUserAccessKey:
	default:
		return "", credentialFields{}, fmt.Errorf("'awsAuth.authenticationType' must be one of %q, %q, %q, %q, %q",
			AuthTypeSystem, AuthTypeIRSA, AuthTypeSTSAssumeRole, AuthTypeDefaultCredentialChain, AuthTypeIAMUserAccessKey)
	}

	// "system" is the one mode that reads gateway-wide credentials. Every other
	// mode is self-contained, so a failure in it is never masked by falling back
	// to the gateway identity.
	if authType == AuthTypeSystem {
		// Credential fields alongside "system" are ignored: the gateway-wide
		// configuration supplies the identity.
		return resolveSystemCredentialSet(params, region, defaultSessionName)
	}

	creds := credentialFields{}
	for key, field := range map[string]*string{
		"awsAccessKeyID":     &creds.accessKeyID,
		"awsSecretAccessKey": &creds.secretAccessKey,
		"awsSessionToken":    &creds.sessionToken,
		"awsRoleARN":         &creds.roleARN,
		"awsRoleRegion":      &creds.roleRegion,
		"awsRoleExternalID":  &creds.roleExternalID,
		"awsRoleSessionName": &creds.roleSessionName,
	} {
		value, err := stringParam(awsAuth, key)
		if err != nil {
			return "", credentialFields{}, fmt.Errorf("awsAuth: %w", err)
		}
		*field = value
	}

	if err := validateCredentialFields(authType, creds); err != nil {
		return "", credentialFields{}, err
	}

	if authType == AuthTypeIRSA && creds.roleARN == "" {
		creds.roleARN = strings.TrimSpace(os.Getenv(envRoleARN))
	}

	applyCredentialDefaults(&creds, region, defaultSessionName)
	return authType, creds, nil
}

// readSystemCredentialFields reads the system-level (gateway-wide) credential
// parameters. These come from config.toml via the systemParameters block, as
// opposed to the user-level parameters an API author sets on the attachment.
func readSystemCredentialFields(params map[string]interface{}, region, defaultSessionName string) (credentialFields, error) {
	creds := credentialFields{}
	for key, field := range map[string]*string{
		"awsAccessKeyID":     &creds.accessKeyID,
		"awsSecretAccessKey": &creds.secretAccessKey,
		"awsSessionToken":    &creds.sessionToken,
		"awsRoleARN":         &creds.roleARN,
		"awsRoleRegion":      &creds.roleRegion,
		"awsRoleExternalID":  &creds.roleExternalID,
	} {
		value, err := stringParam(params, key)
		if err != nil {
			return credentialFields{}, err
		}
		*field = value
	}

	if err := validateCredentialFormats(creds); err != nil {
		return credentialFields{}, err
	}

	applyCredentialDefaults(&creds, region, defaultSessionName)
	return creds, nil
}

// Format constraints mirroring the patterns in policy-definition.yaml. They
// are duplicated here deliberately: the schema is only enforced as well as the
// control plane's validator enforces it, and a malformed value that slips
// through would otherwise fail at request time - against STS, on live traffic -
// instead of being rejected when the attachment is deployed.
var (
	roleARNPattern         = regexp.MustCompile(`^arn:aws(-cn|-us-gov|-iso[a-z]?)?:iam::[0-9]{12}:role/.+$`)
	awsRegionPattern       = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	roleSessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
)

// validateCredentialFields enforces the per-mode requirements that JSON Schema
// expresses only awkwardly, as a backstop to the allOf/if/then rules in
// policy-definition.yaml, along with the field formats.
func validateCredentialFields(authType string, creds credentialFields) error {
	if err := validateCredentialFormats(creds); err != nil {
		return err
	}

	switch authType {
	case AuthTypeIAMUserAccessKey:
		if creds.accessKeyID == "" {
			return fmt.Errorf("'awsAuth.awsAccessKeyID' is required when authenticationType is %q", AuthTypeIAMUserAccessKey)
		}
		if creds.secretAccessKey == "" {
			return fmt.Errorf("'awsAuth.awsSecretAccessKey' is required when authenticationType is %q", AuthTypeIAMUserAccessKey)
		}
	case AuthTypeSTSAssumeRole:
		if creds.roleARN == "" {
			return fmt.Errorf("'awsAuth.awsRoleARN' is required when authenticationType is %q", AuthTypeSTSAssumeRole)
		}
		if creds.accessKeyID != "" && creds.secretAccessKey == "" {
			return fmt.Errorf("'awsAuth.awsSecretAccessKey' is required when 'awsAuth.awsAccessKeyID' is set")
		}
		if creds.secretAccessKey != "" && creds.accessKeyID == "" {
			return fmt.Errorf("'awsAuth.awsAccessKeyID' is required when 'awsAuth.awsSecretAccessKey' is set")
		}
	case AuthTypeIRSA:
		// awsRoleARN is intentionally not required: on EKS the Pod Identity
		// Webhook injects AWS_ROLE_ARN once the ServiceAccount carries the
		// "eks.amazonaws.com/role-arn" annotation, so the param is commonly
		// left unset. buildWebIdentityCredentialsProvider falls back to that
		// variable and fails there if neither source supplies a value.
		//
		// awsRoleExternalID is ignored here rather than rejected:
		// AssumeRoleWithWebIdentity has no external-ID parameter, so the value
		// simply goes unused, consistent with every other field a mode does not
		// read.
	case AuthTypeDefaultCredentialChain:
		// Resolution is delegated entirely to the AWS SDK's default provider
		// chain, so any key configured here would be parsed and then ignored.
	case AuthTypeSystem:
		// Handled before this point: credential fields are rejected outright and
		// the gateway-wide configuration supplies the identity.
	}
	return nil
}

// resolveSystemCredentialSet resolves the identity from the system-level
// configuration. Reached when authenticationType is "system" and when the
// user level supplies no credential block at all, which is equivalent.
func resolveSystemCredentialSet(params map[string]interface{}, region, defaultSessionName string) (string, credentialFields, error) {
	if err := validateAWSConfigParams(params); err != nil {
		return "", credentialFields{}, err
	}

	creds, err := readSystemCredentialFields(params, region, defaultSessionName)
	if err != nil {
		return "", credentialFields{}, err
	}
	return AuthTypeSystem, creds, nil
}

// validateCredentialFormats checks the field formats that both levels share.
// Applied to system-level values as well as user-level ones, so a malformed
// role ARN or region is rejected at deploy time wherever it was written rather
// than failing against STS on live traffic.
func validateCredentialFormats(creds credentialFields) error {
	if creds.roleARN != "" && !roleARNPattern.MatchString(creds.roleARN) {
		return fmt.Errorf("'awsRoleARN' is not a valid IAM role ARN: %q", creds.roleARN)
	}
	if creds.roleRegion != "" && !awsRegionPattern.MatchString(creds.roleRegion) {
		return fmt.Errorf("'awsRoleRegion' is not a valid AWS region: %q", creds.roleRegion)
	}
	if creds.roleSessionName != "" && !roleSessionNamePattern.MatchString(creds.roleSessionName) {
		return fmt.Errorf("'awsRoleSessionName' must match [\\w+=,.@-]{2,64}: %q", creds.roleSessionName)
	}
	return nil
}

// applyCredentialDefaults fills in the fields that have a derived default.
func applyCredentialDefaults(creds *credentialFields, region, defaultSessionName string) {
	if creds.roleRegion == "" {
		creds.roleRegion = region
	}
	if creds.roleSessionName == "" {
		creds.roleSessionName = defaultSessionName
	}
}

// roleSessionNameDisallowed matches every character STS rejects in a role
// session name, which permits only [\w+=,.@-].
var roleSessionNameDisallowed = regexp.MustCompile(`[^\w+=,.@-]`)

// deriveRoleSessionName builds the default STS session name for this policy
// attachment from the API it is attached to.
func deriveRoleSessionName(metadata policy.PolicyMetadata) string {
	parts := make([]string, 0, 3)
	if metadata.APIName != "" {
		parts = append(parts, metadata.APIName)
	}
	if metadata.APIVersion != "" {
		parts = append(parts, metadata.APIVersion)
	}
	if len(parts) == 0 {
		return defaultRoleSessionName
	}

	name := roleSessionNameDisallowed.ReplaceAllString("wso2-gw-"+strings.Join(parts, "-"), "-")
	if len(name) > 64 {
		name = name[:64]
	}
	name = strings.TrimRight(name, "-")
	if len(name) < 2 {
		return defaultRoleSessionName
	}
	return name
}

// checkAllowlist verifies an effective value against an operator-configured
// allowlist. An empty or absent allowlist places no restriction.
func checkAllowlist(params map[string]interface{}, allowlistKey, valueName, value string, allowPrefix bool) error {
	allowed, err := stringSliceParam(params, allowlistKey)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, entry := range allowed {
		if i := strings.Index(entry, "*"); i != -1 {
			switch {
			case !allowPrefix:
				return fmt.Errorf("'%s' entry %q is invalid: this list does not support wildcards, list each value in full", allowlistKey, entry)
			case i != len(entry)-1:
				return fmt.Errorf("'%s' entry %q is invalid: '*' is only supported as the final character, where it matches a prefix. List each value in full, or use a single trailing '*'", allowlistKey, entry)
			}
		}
	}
	for _, entry := range allowed {
		if entry == value {
			return nil
		}
		if allowPrefix && strings.HasSuffix(entry, "*") && strings.HasPrefix(value, strings.TrimSuffix(entry, "*")) {
			return nil
		}
	}
	return fmt.Errorf("'%s' value %q is not permitted by the gateway's %s configuration", valueName, value, allowlistKey)
}

// stringSliceParam reads an optional array-of-strings parameter.
func stringSliceParam(params map[string]interface{}, key string) ([]string, error) {
	val, ok := params[key]
	if !ok || val == nil {
		return nil, nil
	}
	switch typed := val.(type) {
	case []string:
		return typed, nil
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("'%s' must be an array of strings", key)
			}
			out = append(out, str)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("'%s' must be an array of strings", key)
	}
}

// validateAWSConfigParams validates AWS configuration parameters (from params)
// validateAWSConfigParams type-checks the system-level credential parameters.
func validateAWSConfigParams(params map[string]interface{}) error {
	for _, key := range []string{
		"awsAccessKeyID", "awsSecretAccessKey", "awsSessionToken",
		"awsRoleARN", "awsRoleRegion", "awsRoleExternalID",
	} {
		if raw, ok := params[key]; ok && raw != nil {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("'%s' must be a string", key)
			}
		}
	}

	// A role ARN still needs a region to assume it in, but only when one was
	// actually supplied.
	roleARN, err := stringParam(params, "awsRoleARN")
	if err != nil {
		return err
	}
	if roleARN != "" {
		roleRegion, err := stringParam(params, "awsRoleRegion")
		if err != nil {
			return err
		}
		if roleRegion == "" {
			return fmt.Errorf("'awsRoleRegion' is required when 'awsRoleARN' is specified")
		}
	}
	return nil
}

// buildCredentialsProvider constructs the AWS credentials provider once, at
// policy-instance creation time, from the resolved authentication mode.
func buildCredentialsProvider(ctx context.Context, authType string, creds credentialFields) (aws.CredentialsProvider, error) {
	slog.Debug("AWSBedrockGuardrail: building credentials provider", "authenticationType", authType)

	switch authType {
	case AuthTypeSystem:
		// The system-level fields were resolved into creds already; pick the
		// provider they imply, exactly as pre-v1.2.0 behaviour did.
		return buildSystemCredentialsProvider(ctx, creds)
	case AuthTypeIAMUserAccessKey:
		return credentials.NewStaticCredentialsProvider(creds.accessKeyID, creds.secretAccessKey, creds.sessionToken), nil
	case AuthTypeSTSAssumeRole:
		return buildAssumeRoleCredentialsProvider(ctx, creds)
	case AuthTypeIRSA:
		return buildWebIdentityCredentialsProvider(creds)
	case AuthTypeDefaultCredentialChain:
		// Resolution is delegated to the SDK's own chain when the config is
		// loaded, so there is no provider to construct here.
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported authenticationType %q", authType)
	}
}

// buildSystemCredentialsProvider constructs the provider implied by the
// system-level credential fields, preserving the pre-v1.2.0 inference: a role
// ARN with its region assumes that role, a key/secret pair signs directly, and
// anything else defers to the AWS SDK's default provider chain.
func buildSystemCredentialsProvider(ctx context.Context, creds credentialFields) (aws.CredentialsProvider, error) {
	switch {
	case creds.roleARN != "" && creds.roleRegion != "":
		return buildAssumeRoleCredentialsProvider(ctx, creds)
	case creds.accessKeyID != "" && creds.secretAccessKey != "":
		return credentials.NewStaticCredentialsProvider(creds.accessKeyID, creds.secretAccessKey, creds.sessionToken), nil
	default:
		return nil, nil
	}
}

// buildAssumeRoleCredentialsProvider builds a provider that calls AWS STS
// AssumeRole and caches the resulting temporary credentials until they are
// close to expiry, refreshing automatically thereafter.
func buildAssumeRoleCredentialsProvider(ctx context.Context, creds credentialFields) (aws.CredentialsProvider, error) {
	slog.Debug("AWSBedrockGuardrail: building STS AssumeRole credentials provider",
		"roleARN", creds.roleARN, "roleSessionName", creds.roleSessionName, "roleRegion", creds.roleRegion)

	baseCfgOpts := []func(*config.LoadOptions) error{config.WithRegion(creds.roleRegion)}
	if creds.accessKeyID != "" && creds.secretAccessKey != "" {
		baseCfgOpts = append(baseCfgOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(creds.accessKeyID, creds.secretAccessKey, creds.sessionToken)))
	}
	// else: the default AWS SDK credential chain supplies the base credentials
	// used to call sts:AssumeRole.

	baseCfg, err := config.LoadDefaultConfig(ctx, baseCfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load base AWS config for role assumption: %w", err)
	}

	stsClient := sts.NewFromConfig(baseCfg)
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, creds.roleARN, func(o *stscreds.AssumeRoleOptions) {
		if creds.roleExternalID != "" {
			o.ExternalID = aws.String(creds.roleExternalID)
		}
		o.RoleSessionName = creds.roleSessionName
	})

	return aws.NewCredentialsCache(assumeRoleProvider), nil
}

// buildWebIdentityCredentialsProvider builds a provider that calls AWS STS
// AssumeRoleWithWebIdentity using a Kubernetes projected service account token
// - the mechanism EKS calls IAM Roles for Service Accounts (IRSA) - and caches
// the resulting temporary credentials until they are close to expiry.
func buildWebIdentityCredentialsProvider(creds credentialFields) (aws.CredentialsProvider, error) {
	roleARN := creds.roleARN
	if roleARN == "" {
		roleARN = strings.TrimSpace(os.Getenv(envRoleARN))
	}
	if roleARN == "" {
		return nil, fmt.Errorf("'awsAuth.awsRoleARN' is required when authenticationType is %q and the %s environment variable is not set", AuthTypeIRSA, envRoleARN)
	}

	tokenFile := strings.TrimSpace(os.Getenv(envWebIdentityTokenFile))
	if tokenFile == "" {
		return nil, fmt.Errorf("authenticationType %q requires the %s environment variable, which is normally injected by the EKS Pod Identity Webhook", AuthTypeIRSA, envWebIdentityTokenFile)
	}

	slog.Debug("AWSBedrockGuardrail: building STS AssumeRoleWithWebIdentity (IRSA) credentials provider",
		"roleARN", roleARN, "roleSessionName", creds.roleSessionName, "webIdentityTokenFile", tokenFile)

	stsClient := sts.NewFromConfig(aws.Config{Region: creds.roleRegion})
	webIdentityProvider := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, stscreds.IdentityTokenFile(tokenFile), func(o *stscreds.WebIdentityRoleOptions) {
		o.RoleSessionName = creds.roleSessionName
	})

	return aws.NewCredentialsCache(webIdentityProvider), nil
}

// loadAWSConfig builds the AWS configuration used for ApplyGuardrail calls,
// reusing the credentials provider constructed at policy-instance creation
// time. Role assumption therefore happens on first use and on refresh, not on
// every request.
func (p *AWSBedrockGuardrailPolicy) loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if p.credentialsProvider != nil {
		opts = append(opts, config.WithCredentialsProvider(p.credentialsProvider))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return cfg, nil
}

// applyBedrockGuardrail calls AWS Bedrock Guardrail ApplyGuardrail API
func (p *AWSBedrockGuardrailPolicy) applyBedrockGuardrail(ctx context.Context, awsCfg aws.Config, guardrailID, guardrailVersion, content string) (*bedrockruntime.ApplyGuardrailOutput, error) {
	// Create Bedrock Runtime client
	newClient := p.newBedrockClientFunc
	if newClient == nil {
		newClient = func(cfg aws.Config) bedrockGuardrailClient {
			return bedrockruntime.NewFromConfig(cfg)
		}
	}
	client := newClient(awsCfg)

	// Prepare ApplyGuardrail input
	input := &bedrockruntime.ApplyGuardrailInput{
		GuardrailIdentifier: aws.String(guardrailID),
		GuardrailVersion:    aws.String(guardrailVersion),
		Source:              types.GuardrailContentSourceInput,
		Content: []types.GuardrailContentBlock{
			&types.GuardrailContentBlockMemberText{
				Value: types.GuardrailTextBlock{
					Text: aws.String(content),
				},
			},
		},
	}

	// Call ApplyGuardrail API
	output, err := client.ApplyGuardrail(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("ApplyGuardrail API call failed: %w", err)
	}

	return output, nil
}

// evaluateGuardrailResponse processes the AWS Bedrock Guardrail response
func (p *AWSBedrockGuardrailPolicy) evaluateGuardrailResponse(output interface{}, originalContent string, redactPII bool, isRequest bool, metadata map[string]interface{}) (bool, string, error) {
	if output == nil {
		return true, "", fmt.Errorf("AWS Bedrock Guardrails API returned an invalid response")
	}

	outputTyped, ok := output.(*bedrockruntime.ApplyGuardrailOutput)
	if !ok {
		return true, "", fmt.Errorf("invalid output type")
	}

	// Check if guardrail intervened
	if outputTyped.Action == types.GuardrailActionGuardrailIntervened {
		// Check if there are PII entities or sensitive information that was masked
		hasPIIMasking := false
		if len(outputTyped.Assessments) > 0 {
			for _, assessment := range outputTyped.Assessments {
				if assessment.SensitiveInformationPolicy != nil {
					if len(assessment.SensitiveInformationPolicy.PiiEntities) > 0 || len(assessment.SensitiveInformationPolicy.Regexes) > 0 {
						hasPIIMasking = true
						break
					}
				}
			}
		}

		// If PII masking was applied
		if hasPIIMasking {
			if redactPII {
				// Redaction mode: extract redacted content
				redactedContent := p.extractRedactedContent(outputTyped, originalContent)
				return false, redactedContent, nil
			} else if isRequest {
				// Masking mode: process PII entities for masking
				maskedContent, maskedPII := p.processPIIEntitiesForMasking(outputTyped, originalContent)
				if len(maskedPII) > 0 {
					metadata[MetadataKeyPIIEntities] = maskedPII
				}
				return false, maskedContent, nil
			} else {
				// Response case: PII was already masked in request, allow through
				// Restoration happens earlier in validatePayload
				return false, "", nil
			}
		}

		// Other intervention reasons - block by default (content policy, topic policy, word policy violations)
		return true, "", nil // Violation detected, block content
	}

	// Check for no intervention
	if outputTyped.Action == types.GuardrailActionNone {
		return false, "", nil // No violation, continue processing
	}

	// Unexpected response
	return true, "", fmt.Errorf("AWS Bedrock Guardrails returned unexpected response action: %s", string(outputTyped.Action))
}

// processPIIEntitiesForMasking handles PII masking when redactPII is disabled
func (p *AWSBedrockGuardrailPolicy) processPIIEntitiesForMasking(output *bedrockruntime.ApplyGuardrailOutput, originalContent string) (string, map[string]string) {
	if output == nil || len(output.Assessments) == 0 {
		return originalContent, nil
	}

	maskedPII := make(map[string]string)
	updatedContent := originalContent
	counter := 0

	// Collect all matches first, then sort by length (longest first) to avoid substring collisions
	type matchInfo struct {
		match      string
		entityType string
		isRegex    bool
	}

	var matches []matchInfo

	for _, assessment := range output.Assessments {
		if assessment.SensitiveInformationPolicy != nil {
			// Collect PII entities
			if len(assessment.SensitiveInformationPolicy.PiiEntities) > 0 {
				for _, entity := range assessment.SensitiveInformationPolicy.PiiEntities {
					if entity.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized {
						match := aws.ToString(entity.Match)
						if match != "" && maskedPII[match] == "" {
							matches = append(matches, matchInfo{
								match:      match,
								entityType: string(entity.Type),
								isRegex:    false,
							})
							maskedPII[match] = "" // Mark as seen to avoid duplicates
						}
					}
				}
			}

			// Collect regex matches
			if len(assessment.SensitiveInformationPolicy.Regexes) > 0 {
				for _, regex := range assessment.SensitiveInformationPolicy.Regexes {
					if regex.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized {
						match := aws.ToString(regex.Match)
						name := aws.ToString(regex.Name)
						if match != "" && maskedPII[match] == "" {
							matches = append(matches, matchInfo{
								match:      match,
								entityType: name,
								isRegex:    true,
							})
							maskedPII[match] = "" // Mark as seen to avoid duplicates
						}
					}
				}
			}
		}
	}

	// Sort matches by length (longest first) to prevent substring collisions
	sort.Slice(matches, func(i, j int) bool {
		return len(matches[i].match) > len(matches[j].match)
	})

	// Clear maskedPII map and rebuild with replacements
	maskedPII = make(map[string]string)

	// Process matches in order (longest first)
	for _, matchInfo := range matches {
		replacement := fmt.Sprintf("%s_%04x", matchInfo.entityType, counter)
		updatedContent = strings.ReplaceAll(updatedContent, matchInfo.match, replacement)
		maskedPII[matchInfo.match] = replacement
		counter++
	}

	return updatedContent, maskedPII
}

// extractRedactedContent extracts redacted content from guardrail outputs
func (p *AWSBedrockGuardrailPolicy) extractRedactedContent(output *bedrockruntime.ApplyGuardrailOutput, originalContent string) string {
	redactedText := originalContent
	// Replace all PII entity matches with *****
	if output != nil && len(output.Assessments) > 0 && output.Assessments[0].SensitiveInformationPolicy != nil {
		// Collect all matches first
		var matches []string

		for _, entity := range output.Assessments[0].SensitiveInformationPolicy.PiiEntities {
			match := aws.ToString(entity.Match)
			if match != "" {
				matches = append(matches, match)
			}
		}
		for _, regex := range output.Assessments[0].SensitiveInformationPolicy.Regexes {
			match := aws.ToString(regex.Match)
			if match != "" {
				matches = append(matches, match)
			}
		}

		// Sort matches by length (longest first) to prevent substring collisions
		sort.Slice(matches, func(i, j int) bool {
			return len(matches[i]) > len(matches[j])
		})

		// Process matches in order (longest first)
		for _, match := range matches {
			redactedText = strings.ReplaceAll(redactedText, match, "*****")
		}
	}
	return redactedText
}

// restorePIIInResponse handles PII restoration in responses when redactPII is disabled
func (p *AWSBedrockGuardrailPolicy) restorePIIInResponse(originalContent string, maskedPIIEntities map[string]string) string {
	if maskedPIIEntities == nil || len(maskedPIIEntities) == 0 {
		return originalContent
	}

	// Collect placeholder-original pairs and sort by placeholder length (longest first)
	// to prevent substring collisions when restoring
	type restorePair struct {
		placeholder string
		original    string
	}

	var pairs []restorePair
	for original, placeholder := range maskedPIIEntities {
		pairs = append(pairs, restorePair{
			placeholder: placeholder,
			original:    original,
		})
	}

	// Sort by placeholder length (longest first) to prevent substring collisions
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].placeholder) > len(pairs[j].placeholder)
	})

	transformedContent := originalContent
	for _, pair := range pairs {
		if strings.Contains(transformedContent, pair.placeholder) {
			transformedContent = strings.ReplaceAll(transformedContent, pair.placeholder, pair.original)
		}
	}

	return transformedContent
}

// updatePayloadWithMaskedContent updates the original payload by replacing the extracted content.
// If jsonPath is empty, it returns modifiedContent directly. Any JSON processing error (unmarshal,
// SetValueAtJSONPath, marshal) is returned rather than falling back to originalPayload, because the
// original payload still carries the content the guardrail masked or redacted.
func (p *AWSBedrockGuardrailPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) ([]byte, error) {
	if jsonPath == "" {
		return []byte(modifiedContent), nil
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(originalPayload, &jsonData); err != nil {
		return nil, fmt.Errorf("parsing payload for masked write-back: %w", err)
	}

	if err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent); err != nil {
		return nil, fmt.Errorf("writing masked value to JSONPath: %w", err)
	}

	updatedPayload, err := json.Marshal(jsonData)
	if err != nil {
		return nil, fmt.Errorf("encoding masked payload: %w", err)
	}

	return updatedPayload, nil
}

// guardrailTransform returns the per-value rewrite for a structured payload. Redaction replaces
// every match the guardrail reported with "*****"; masking replaces each original with the
// placeholder evaluateGuardrailResponse stored in metadata, so all values share one mapping and
// the response is restored correctly.
func (p *AWSBedrockGuardrailPolicy) guardrailTransform(output interface{}, redactPII bool, metadata map[string]interface{}) func(string) string {
	typed, _ := output.(*bedrockruntime.ApplyGuardrailOutput)
	if redactPII {
		return func(value string) string { return p.extractRedactedContent(typed, value) }
	}
	maskedPII, _ := metadata[MetadataKeyPIIEntities].(map[string]string)
	return func(value string) string { return applyReplacements(value, maskedPII) }
}

// buildAssessmentObject builds the assessment object
func (p *AWSBedrockGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool, output interface{}) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "AWS Bedrock Guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of AWS Bedrock Guardrail detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = []string{reason}
		} else if bedrockOutput, ok := output.(*bedrockruntime.ApplyGuardrailOutput); ok && bedrockOutput != nil {
			if len(bedrockOutput.Assessments) > 0 {
				firstAssessment := p.convertBedrockAssessmentToMap(bedrockOutput.Assessments[0])
				assessment["assessments"] = firstAssessment
			}
		}
	}

	return assessment
}

// convertBedrockAssessmentToMap converts a Bedrock assessment to a map structure
func (p *AWSBedrockGuardrailPolicy) convertBedrockAssessmentToMap(assessment types.GuardrailAssessment) map[string]interface{} {
	assessmentMap := make(map[string]interface{})

	// Handle content policy assessment
	if assessment.ContentPolicy != nil {
		contentPolicy := make(map[string]interface{})
		if len(assessment.ContentPolicy.Filters) > 0 {
			filters := make([]map[string]interface{}, 0, len(assessment.ContentPolicy.Filters))
			for _, filter := range assessment.ContentPolicy.Filters {
				filterMap := map[string]interface{}{
					"action":     string(filter.Action),
					"confidence": string(filter.Confidence),
					"type":       string(filter.Type),
				}
				filters = append(filters, filterMap)
			}
			contentPolicy["filters"] = filters
		}
		assessmentMap["contentPolicy"] = contentPolicy
	}

	// Handle topic policy assessment
	if assessment.TopicPolicy != nil {
		topicPolicy := make(map[string]interface{})
		if len(assessment.TopicPolicy.Topics) > 0 {
			topics := make([]map[string]interface{}, 0, len(assessment.TopicPolicy.Topics))
			for _, topic := range assessment.TopicPolicy.Topics {
				topicMap := map[string]interface{}{
					"action": string(topic.Action),
					"name":   aws.ToString(topic.Name),
					"type":   string(topic.Type),
				}
				topics = append(topics, topicMap)
			}
			topicPolicy["topics"] = topics
		}
		assessmentMap["topicPolicy"] = topicPolicy
	}

	// Handle word policy assessment
	if assessment.WordPolicy != nil {
		wordPolicy := make(map[string]interface{})
		if len(assessment.WordPolicy.CustomWords) > 0 {
			customWords := make([]map[string]interface{}, 0, len(assessment.WordPolicy.CustomWords))
			for _, word := range assessment.WordPolicy.CustomWords {
				wordMap := map[string]interface{}{
					"action": string(word.Action),
					"match":  aws.ToString(word.Match),
				}
				customWords = append(customWords, wordMap)
			}
			wordPolicy["customWords"] = customWords
		}
		if len(assessment.WordPolicy.ManagedWordLists) > 0 {
			managedWords := make([]map[string]interface{}, 0, len(assessment.WordPolicy.ManagedWordLists))
			for _, word := range assessment.WordPolicy.ManagedWordLists {
				wordMap := map[string]interface{}{
					"action": string(word.Action),
					"match":  aws.ToString(word.Match),
					"type":   string(word.Type),
				}
				managedWords = append(managedWords, wordMap)
			}
			wordPolicy["managedWordLists"] = managedWords
		}
		assessmentMap["wordPolicy"] = wordPolicy
	}

	// Handle sensitive information policy assessment
	if assessment.SensitiveInformationPolicy != nil {
		sipPolicy := make(map[string]interface{})
		if len(assessment.SensitiveInformationPolicy.PiiEntities) > 0 {
			piiEntities := make([]map[string]interface{}, 0, len(assessment.SensitiveInformationPolicy.PiiEntities))
			for _, entity := range assessment.SensitiveInformationPolicy.PiiEntities {
				entityMap := map[string]interface{}{
					"action": string(entity.Action),
					"match":  aws.ToString(entity.Match),
					"type":   string(entity.Type),
				}
				piiEntities = append(piiEntities, entityMap)
			}
			sipPolicy["piiEntities"] = piiEntities
		}
		if len(assessment.SensitiveInformationPolicy.Regexes) > 0 {
			regexes := make([]map[string]interface{}, 0, len(assessment.SensitiveInformationPolicy.Regexes))
			for _, regex := range assessment.SensitiveInformationPolicy.Regexes {
				regexMap := map[string]interface{}{
					"action": string(regex.Action),
					"match":  aws.ToString(regex.Match),
					"name":   aws.ToString(regex.Name),
				}
				regexes = append(regexes, regexMap)
			}
			sipPolicy["regexes"] = regexes
		}
		assessmentMap["sensitiveInformationPolicy"] = sipPolicy
	}

	return assessmentMap
}

// OnRequestBody validates request body using AWS Bedrock Guardrail.
func (p *AWSBedrockGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]interface{})
	}

	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false, reqCtx.Metadata).(policy.RequestAction)
}

// OnResponseBody validates response body using AWS Bedrock Guardrail.
func (p *AWSBedrockGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true, respCtx.Metadata).(policy.ResponseAction)
}

// validatePayload validates payload against AWS Bedrock Guardrail, returning policy actions.
func (p *AWSBedrockGuardrailPolicy) validatePayload(payload []byte, params AWSBedrockGuardrailPolicyParams, isResponse bool, metadata map[string]interface{}) interface{} {
	if !params.RedactPII && isResponse {
		if maskedPII, exists := metadata[MetadataKeyPIIEntities]; exists {
			if maskedPIIMap, ok := maskedPII.(map[string]string); ok {
				restoredContent := p.restorePIIInResponse(string(payload), maskedPIIMap)
				if restoredContent != string(payload) {
					return policy.DownstreamResponseModifications{
						Body: []byte(restoredContent),
					}
				}
			}
		}
	}

	if payload == nil {
		if isResponse {
			return policy.DownstreamResponseModifications{}
		}
		return policy.UpstreamRequestModifications{}
	}

	extractedValue, err := extractInspectableText(payload, params.JsonPath)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: JSONPath extraction error, passthrough enabled", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			if isResponse {
				return policy.DownstreamResponseModifications{}
			}
			return policy.UpstreamRequestModifications{}
		}
		slog.Debug("AWSBedrockGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, nil)
	}

	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	loadConfig := p.loadAWSConfigFunc
	if loadConfig == nil {
		loadConfig = p.loadAWSConfig
	}

	awsCfg, err := loadConfig(context.Background(), p.region)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: AWS config error, passthrough enabled", "error", err, "isResponse", isResponse)
			if isResponse {
				return policy.DownstreamResponseModifications{}
			}
			return policy.UpstreamRequestModifications{}
		}
		slog.Debug("AWSBedrockGuardrail: Error loading AWS config", "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error loading AWS config", err, isResponse, params.ShowAssessment, nil)
	}

	output, err := p.applyBedrockGuardrail(context.Background(), awsCfg, p.guardrailID, p.guardrailVersion, extractedValue)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: Guardrail API error, passthrough enabled", "error", err, "isResponse", isResponse)
			if isResponse {
				return policy.DownstreamResponseModifications{}
			}
			return policy.UpstreamRequestModifications{}
		}
		slog.Debug("AWSBedrockGuardrail: Error calling AWS Bedrock Guardrail", "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error calling AWS Bedrock Guardrail", err, isResponse, params.ShowAssessment, nil)
	}

	var outputInterface interface{} = output
	violation, modifiedContent, err := p.evaluateGuardrailResponse(outputInterface, extractedValue, params.RedactPII, !isResponse, metadata)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: Guardrail evaluation error, passthrough enabled", "error", err, "isResponse", isResponse)
			if isResponse {
				return policy.DownstreamResponseModifications{}
			}
			return policy.UpstreamRequestModifications{}
		}
		slog.Debug("AWSBedrockGuardrail: Error evaluating guardrail response", "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error evaluating guardrail response", err, isResponse, params.ShowAssessment, output)
	}

	if violation {
		slog.Debug("AWSBedrockGuardrail: Violation detected", "isResponse", isResponse)
		return p.buildErrorResponse("Violation of AWS Bedrock Guardrails detected", nil, isResponse, params.ShowAssessment, output)
	}

	if modifiedContent != "" && modifiedContent != extractedValue {
		slog.Debug("AWSBedrockGuardrail: Content modified by guardrail", "isResponse", isResponse)
		var modifiedPayload []byte
		if selectsStructuredValue(payload, params.JsonPath) {
			// The guardrail saw one joined text; apply its masking or redaction to each value.
			modifiedPayload, err = rewriteStructuredPayload(payload, params.JsonPath, p.guardrailTransform(outputInterface, params.RedactPII, metadata))
		} else {
			modifiedPayload, err = p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, params.JsonPath)
		}
		if err != nil {
			// Never fall back to the original payload: it still carries the content the
			// guardrail masked or redacted.
			slog.Debug("AWSBedrockGuardrail: Error applying guardrail modifications", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			return p.buildErrorResponse("Error applying guardrail modifications", err, isResponse, params.ShowAssessment, output)
		}
		if isResponse {
			return policy.DownstreamResponseModifications{Body: modifiedPayload}
		}
		return policy.UpstreamRequestModifications{Body: modifiedPayload}
	}

	slog.Debug("AWSBedrockGuardrail: Validation passed", "isResponse", isResponse)
	if isResponse {
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// buildErrorResponse builds a policy error response for both request and response phases.
func (p *AWSBedrockGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, output interface{}) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, output)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "AWS Bedrock Guardrail",
	}

	responseBody := map[string]interface{}{
		"type":    "AWS_BEDROCK_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"AWS_BEDROCK_GUARDRAIL","message":"Internal error"}`)
	}

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
	}
}
