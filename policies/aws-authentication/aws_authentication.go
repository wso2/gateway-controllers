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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthTypeSTSAssumeRole selects temporary credentials obtained via AWS STS AssumeRole.
	AuthTypeSTSAssumeRole = "sts-assume-role"
	// AuthTypeIAMUserAccessKey selects static, long-lived IAM user credentials.
	AuthTypeIAMUserAccessKey = "iam-user-access-key"
	// AuthTypeIRSA selects temporary credentials obtained via AWS STS
	// AssumeRoleWithWebIdentity, using a Kubernetes projected service account
	// token — the mechanism behind EKS IAM Roles for Service Accounts (IRSA).
	AuthTypeIRSA = "irsa"
	// AuthTypeDefaultCredentialChain selects credentials resolved directly
	// from the AWS SDK's default credential provider chain (environment
	// variables, shared config/credentials files, EC2 instance profile, ECS
	// task role, Lambda execution role, or an EKS Pod Identity association) —
	// no AssumeRole call and no static keys configured anywhere in policy
	// params. Use this when the gateway itself already runs under the exact
	// IAM role/permissions needed to sign requests to the target AWS
	// service, unlike sts-assume-role (which always performs an extra
	// AssumeRole hop onto a different role) or irsa (the older
	// AssumeRoleWithWebIdentity + OIDC federation mechanism specific to
	// ServiceAccount-scoped EKS workloads).
	AuthTypeDefaultCredentialChain = "default-credential-chain"

	// AuthType is the AuthContext.AuthType value recorded by this policy.
	AuthType = "aws-sigv4"

	defaultRoleSessionName = "aws-authentication-session"

	// envRoleARN and envWebIdentityTokenFile are the environment variables the
	// EKS Pod Identity Webhook injects into a pod whose ServiceAccount is
	// annotated with "eks.amazonaws.com/role-arn". They provide IRSA defaults
	// when the corresponding policy params are not set.
	envRoleARN              = "AWS_ROLE_ARN"
	envWebIdentityTokenFile = "AWS_WEB_IDENTITY_TOKEN_FILE"

	// emptyPayloadHash is the well-known SigV4 payload hash of an empty body.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// credentialFields holds the raw credential-related parameters extracted from
// policy params, independent of which authenticationType selects them.
type credentialFields struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	roleARN         string
	roleExternalID  string
	roleSessionName string
}

// AWSAuthenticationPolicy signs outbound requests to AWS-hosted backends
// using AWS Signature Version 4 (SigV4) before they are forwarded upstream.
type AWSAuthenticationPolicy struct {
	service            string
	region             string
	authenticationType string

	// credsProvider supplies (possibly cached/refreshed) AWS credentials.
	// Built once in GetPolicy and reused across requests.
	credsProvider aws.CredentialsProvider

	// signer performs the actual SigV4 signing. Stateless and reusable.
	signer *v4.Signer

	// Test seams — production code uses credsProvider.Retrieve / signer.SignHTTP /
	// time.Now directly; unit tests override these to avoid real AWS/STS network
	// calls, mirroring the loadAWSConfigFunc/newBedrockClientFunc pattern used in
	// the aws-bedrock-guardrail policy.
	retrieveCredentialsFunc func(ctx context.Context) (aws.Credentials, error)
	signFunc                func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error
	nowFunc                 func() time.Time
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("AWSAuthentication: constructing policy from params")

	service, region, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	slog.Debug("AWSAuthentication: validated service and region params", "service", service, "region", region)

	authType, creds, err := validateAndExtractCredentialParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	slog.Debug("AWSAuthentication: validated credential params", "authenticationType", authType)

	p := &AWSAuthenticationPolicy{
		service:            service,
		region:             region,
		authenticationType: authType,
		signer:             v4.NewSigner(),
		nowFunc:            time.Now,
	}

	credsProvider, err := buildCredentialsProvider(context.Background(), authType, creds, region)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AWS credentials provider: %w", err)
	}
	p.credsProvider = credsProvider
	p.retrieveCredentialsFunc = p.credsProvider.Retrieve
	p.signFunc = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
		return p.signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
	}

	slog.Debug("AWSAuthentication: policy initialized",
		"service", p.service, "region", p.region, "authenticationType", p.authenticationType)

	return p, nil
}

// Mode returns the processing mode for the AWS authentication policy.
// SigV4 signing needs the full request body to compute the payload hash, so
// the request body must be buffered; nothing else is needed.
func (p *AWSAuthenticationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent or wrong type.
// Leading/trailing whitespace is trimmed: credential values pasted from config files or
// secret stores frequently carry a stray trailing newline or space, which is invisible in
// logs but silently corrupts the SigV4 HMAC (the secret key is never echoed back by AWS,
// so a whitespace-contaminated key produces a "signature does not match" error where every
// other canonical-request element still lines up correctly).
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// getRequiredStringParam extracts a required, non-empty string parameter, trimmed per
// getStringParam.
func getRequiredStringParam(params map[string]interface{}, key string) (string, error) {
	val, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return str, nil
}

// validateAndExtractParams validates and extracts the "service" and "region" params.
func validateAndExtractParams(params map[string]interface{}) (service, region string, err error) {
	service, err = getRequiredStringParam(params, "service")
	if err != nil {
		return "", "", err
	}
	region, err = getRequiredStringParam(params, "region")
	if err != nil {
		return "", "", err
	}
	return service, region, nil
}

// validateAndExtractCredentialParams validates "authenticationType" and the
// credential fields it gates. JSON Schema's static `required` array cannot
// express "roleARN required only if authenticationType == sts-assume-role",
// so that conditional validation is enforced here.
func validateAndExtractCredentialParams(params map[string]interface{}) (authType string, creds credentialFields, err error) {
	authType, err = getRequiredStringParam(params, "authenticationType")
	if err != nil {
		return "", credentialFields{}, err
	}
	if authType != AuthTypeSTSAssumeRole && authType != AuthTypeIAMUserAccessKey && authType != AuthTypeIRSA && authType != AuthTypeDefaultCredentialChain {
		return "", credentialFields{}, fmt.Errorf("'authenticationType' must be one of %q, %q, %q, %q", AuthTypeSTSAssumeRole, AuthTypeIAMUserAccessKey, AuthTypeIRSA, AuthTypeDefaultCredentialChain)
	}

	creds = credentialFields{
		accessKeyID:     getStringParam(params, "awsAccessKeyID"),
		secretAccessKey: getStringParam(params, "awsSecretAccessKey"),
		sessionToken:    getStringParam(params, "awsSessionToken"),
		roleARN:         getStringParam(params, "awsRoleARN"),
		roleExternalID:  getStringParam(params, "awsRoleExternalID"),
		roleSessionName: getStringParam(params, "awsRoleSessionName"),
	}
	if creds.roleSessionName == "" {
		creds.roleSessionName = defaultRoleSessionName
	}

	switch authType {
	case AuthTypeIAMUserAccessKey:
		if creds.accessKeyID == "" {
			return "", credentialFields{}, fmt.Errorf("'awsAccessKeyID' is required when authenticationType is %q", AuthTypeIAMUserAccessKey)
		}
		if creds.secretAccessKey == "" {
			return "", credentialFields{}, fmt.Errorf("'awsSecretAccessKey' is required when authenticationType is %q", AuthTypeIAMUserAccessKey)
		}
	case AuthTypeSTSAssumeRole:
		if creds.roleARN == "" {
			return "", credentialFields{}, fmt.Errorf("'awsRoleARN' is required when authenticationType is %q", AuthTypeSTSAssumeRole)
		}
		if creds.accessKeyID != "" && creds.secretAccessKey == "" {
			return "", credentialFields{}, fmt.Errorf("'awsSecretAccessKey' is required when 'awsAccessKeyID' is set")
		}
		if creds.secretAccessKey != "" && creds.accessKeyID == "" {
			return "", credentialFields{}, fmt.Errorf("'awsAccessKeyID' is required when 'awsSecretAccessKey' is set")
		}
	case AuthTypeIRSA:
		// awsRoleARN is intentionally not required here: on EKS, the Pod
		// Identity Webhook injects AWS_ROLE_ARN into the pod automatically once
		// its ServiceAccount carries the "eks.amazonaws.com/role-arn"
		// annotation, so the param is commonly left unset.
		// buildWebIdentityCredentialsProvider falls back to that environment
		// variable and fails there if neither source supplies a value. The
		// web identity token file path is never taken from a param — it is
		// always read from AWS_WEB_IDENTITY_TOKEN_FILE, which the same webhook
		// injects alongside AWS_ROLE_ARN.
	case AuthTypeDefaultCredentialChain:
		// No credential fields apply: resolution is delegated entirely to
		// the AWS SDK's default credential provider chain at signing time,
		// there is no role to assume and no key/secret pair to validate.
	}
	return authType, creds, nil
}

// buildCredentialsProvider constructs the AWS credentials provider once, at
// policy-instance creation time, based on the selected authenticationType.
func buildCredentialsProvider(ctx context.Context, authType string, creds credentialFields, region string) (aws.CredentialsProvider, error) {
	slog.Debug("AWSAuthentication: building credentials provider", "authenticationType", authType, "region", region)

	switch authType {
	case AuthTypeIAMUserAccessKey:
		slog.Debug("AWSAuthentication: using static IAM user access key credentials provider")
		return credentials.NewStaticCredentialsProvider(creds.accessKeyID, creds.secretAccessKey, creds.sessionToken), nil
	case AuthTypeSTSAssumeRole:
		return buildAssumeRoleCredentialsProvider(ctx, creds, region)
	case AuthTypeIRSA:
		return buildWebIdentityCredentialsProvider(creds, region)
	case AuthTypeDefaultCredentialChain:
		return buildDefaultCredentialChainProvider(ctx, region)
	default:
		return nil, fmt.Errorf("unsupported authenticationType %q", authType)
	}
}

// buildAssumeRoleCredentialsProvider builds a credentials provider that calls
// AWS STS AssumeRole and caches the resulting temporary credentials until
// they are close to expiry, refreshing automatically thereafter.
func buildAssumeRoleCredentialsProvider(ctx context.Context, creds credentialFields, region string) (aws.CredentialsProvider, error) {
	slog.Debug("AWSAuthentication: building STS AssumeRole credentials provider",
		"roleARN", creds.roleARN, "roleSessionName", creds.roleSessionName, "region", region)

	var baseCfgOpts []func(*config.LoadOptions) error
	baseCfgOpts = append(baseCfgOpts, config.WithRegion(region))
	if creds.accessKeyID != "" && creds.secretAccessKey != "" {
		baseCfgOpts = append(baseCfgOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(creds.accessKeyID, creds.secretAccessKey, creds.sessionToken)))
	}
	// else: fall through to the default AWS SDK credential chain (env vars,
	// shared config, EC2/ECS/pod IAM role, etc.) for the base credentials used
	// to call sts:AssumeRole.

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

	slog.Debug("AWSAuthentication: STS AssumeRole credentials provider ready", "roleARN", creds.roleARN)

	return aws.NewCredentialsCache(assumeRoleProvider), nil
}

// buildWebIdentityCredentialsProvider builds a credentials provider that
// calls AWS STS AssumeRoleWithWebIdentity using a Kubernetes projected
// service account token — the mechanism EKS calls IAM Roles for Service
// Accounts (IRSA) — and caches the resulting temporary credentials until
// they are close to expiry, refreshing automatically thereafter.
//
// The awsRoleARN param takes precedence when set; if empty, this falls back
// to the AWS_ROLE_ARN environment variable that the EKS Pod Identity Webhook
// injects automatically for a ServiceAccount annotated with
// "eks.amazonaws.com/role-arn". The web identity token file path is never
// taken from a policy param — since the gateway always runs as a Kubernetes
// workload for this mode, it is always read from the AWS_WEB_IDENTITY_TOKEN_FILE
// environment variable the same webhook injects alongside AWS_ROLE_ARN. If
// either environment variable is missing, IRSA is not available in the
// current environment (e.g. the gateway is not running on a cluster with
// that trust configured) and this returns an error rather than silently
// falling back to some other credential source.
//
// AssumeRoleWithWebIdentity does not itself require caller credentials to
// invoke, so the STS client here is built from a bare region-only config
// rather than the full default credential chain used for sts-assume-role.
func buildWebIdentityCredentialsProvider(creds credentialFields, region string) (aws.CredentialsProvider, error) {
	roleARN := creds.roleARN
	if roleARN == "" {
		roleARN = strings.TrimSpace(os.Getenv(envRoleARN))
	}
	if roleARN == "" {
		return nil, fmt.Errorf("'awsRoleARN' is required when authenticationType is %q and the %s environment variable is not set", AuthTypeIRSA, envRoleARN)
	}

	tokenFile := strings.TrimSpace(os.Getenv(envWebIdentityTokenFile))
	if tokenFile == "" {
		return nil, fmt.Errorf("authenticationType %q requires the %s environment variable, which is normally injected by the EKS Pod Identity Webhook", AuthTypeIRSA, envWebIdentityTokenFile)
	}

	slog.Debug("AWSAuthentication: building STS AssumeRoleWithWebIdentity (IRSA) credentials provider",
		"roleARN", roleARN, "roleSessionName", creds.roleSessionName, "webIdentityTokenFile", tokenFile, "region", region)

	stsClient := sts.NewFromConfig(aws.Config{Region: region})
	webIdentityProvider := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, stscreds.IdentityTokenFile(tokenFile), func(o *stscreds.WebIdentityRoleOptions) {
		o.RoleSessionName = creds.roleSessionName
	})

	slog.Debug("AWSAuthentication: STS AssumeRoleWithWebIdentity (IRSA) credentials provider ready", "roleARN", roleARN)

	return aws.NewCredentialsCache(webIdentityProvider), nil
}

// buildDefaultCredentialChainProvider builds a credentials provider that
// resolves credentials directly from the AWS SDK's default credential
// provider chain — no AssumeRole/AssumeRoleWithWebIdentity call, and no
// static keys configured anywhere in policy params. This is appropriate when
// the gateway's own compute environment (EC2 instance profile, ECS task
// role, Lambda execution role, or an EKS Pod Identity association) already
// carries the exact IAM role needed to sign requests to the target service.
//
// config.LoadDefaultConfig already wraps whichever provider it resolves in
// an aws.CredentialsCache internally, so the returned provider needs no
// additional caching layer here.
func buildDefaultCredentialChainProvider(ctx context.Context, region string) (aws.CredentialsProvider, error) {
	slog.Debug("AWSAuthentication: building default AWS credential chain provider", "region", region)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load default AWS config: %w", err)
	}

	slog.Debug("AWSAuthentication: default AWS credential chain provider ready")
	return cfg.Credentials, nil
}

// OnRequestBody signs the outbound request with AWS SigV4 before it is
// forwarded to the upstream AWS-hosted backend.
func (p *AWSAuthenticationPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	slog.Debug("AWSAuthentication: signing outbound request", "method", reqCtx.Method, "path", reqCtx.Path,
		"service", p.service, "region", p.region)

	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}

	creds, err := p.retrieveCredentials(ctx)
	if err != nil {
		return p.authFailure(reqCtx.SharedContext, "failed to resolve AWS credentials", err)
	}

	signedHeaders, err := p.signRequest(ctx, reqCtx, body, creds)
	if err != nil {
		return p.authFailure(reqCtx.SharedContext, "failed to sign AWS SigV4 request", err)
	}

	p.authSuccess(reqCtx.SharedContext)

	return policy.UpstreamRequestModifications{
		HeadersToSet: signedHeaders,
	}
}

// retrieveCredentials fetches current (possibly cached/refreshed) AWS
// credentials from the provider built once in GetPolicy.
func (p *AWSAuthenticationPolicy) retrieveCredentials(ctx context.Context) (aws.Credentials, error) {
	slog.Debug("AWSAuthentication: retrieving AWS credentials", "authenticationType", p.authenticationType)

	retrieve := p.retrieveCredentialsFunc
	if retrieve == nil {
		retrieve = p.credsProvider.Retrieve
	}
	return retrieve(ctx)
}

// signRequest builds a synthetic *http.Request mirroring the proxied
// request, signs it with SigV4, and returns the headers that must be set on
// the actual upstream request.
func (p *AWSAuthenticationPolicy) signRequest(ctx context.Context, reqCtx *policy.RequestContext, body []byte, creds aws.Credentials) (map[string]string, error) {
	slog.Debug("AWSAuthentication: signing request with SigV4", "service", p.service, "region", p.region)

	req, err := buildHTTPRequest(reqCtx, body)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for signing: %w", err)
	}

	payloadHash := hashPayload(body)
	slog.Debug("AWSAuthentication: computed payload hash", "payloadHash", payloadHash)
	// SignHTTP computes the signature over the payload hash regardless of
	// whether it appears as a header, but it does not set the header itself
	// (unlike the SDK's higher-level middleware stack, which this policy
	// bypasses by calling the raw signer directly). Some AWS services (e.g.
	// S3) reject requests missing this header, so it must be set explicitly
	// before signing to be included in SignedHeaders and forwarded upstream.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	now := time.Now
	if p.nowFunc != nil {
		now = p.nowFunc
	}
	sign := p.signFunc
	if sign == nil {
		sign = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
			return p.signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
		}
	}
	if err := sign(ctx, creds, req, payloadHash, p.service, p.region, now()); err != nil {
		return nil, fmt.Errorf("SigV4 signing failed: %w", err)
	}
	slog.Debug("AWSAuthentication: SigV4 signing succeeded", "service", p.service, "region", p.region)

	return extractSignedHeaders(req), nil
}

// buildHTTPRequest constructs a minimal *http.Request carrying only the
// fields SigV4 needs to compute a valid signature: method, URL (path +
// query), Host, and body. It deliberately does not copy all inbound headers
// onto the request to be signed — only Content-Type, since blindly signing
// every inbound header risks SignatureDoesNotMatch if a header is stripped
// or rewritten between this policy and the actual upstream call.
//
// The request must be signed for the actual upstream host, not the
// client-facing gateway host the caller used — reqCtx.Scheme/Authority
// reflect the latter (see context.go's RequestContext doc) and must never be
// used here. A resolved UpstreamInfo is therefore mandatory: if the route has
// none, there is no correct host to sign for, so this returns an error
// rather than falling back to the client-facing host or an invalid request.
func buildHTTPRequest(reqCtx *policy.RequestContext, body []byte) (*http.Request, error) {
	slog.Debug("AWSAuthentication: building request to sign", "method", reqCtx.Method, "path", reqCtx.Path)
	if reqCtx.UpstreamInfo == nil || reqCtx.UpstreamInfo.URL == "" {
		return nil, fmt.Errorf("no resolved upstream URL for this route")
	}

	upstreamURL, err := url.Parse(reqCtx.UpstreamInfo.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", reqCtx.UpstreamInfo.URL, err)
	}
	scheme, authority := upstreamURL.Scheme, upstreamURL.Host
	slog.Debug("AWSAuthentication: resolved upstream host for signing", "scheme", scheme, "authority", authority)

	rawURL := strings.TrimSuffix(reqCtx.UpstreamInfo.URL, "/") + resolveUpstreamPath(reqCtx)
	slog.Debug("AWSAuthentication: signing request for upstream URL", "rawURL", rawURL)
	req, err := http.NewRequest(reqCtx.Method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = authority  // signed as the canonical "host" header
	req.ContentLength = 0 // exclude content-length from the SigV4 signature

	if reqCtx.Headers != nil {
		if ct := reqCtx.Headers.Get("content-type"); len(ct) > 0 {
			req.Header.Set("Content-Type", ct[0])
		}
	}
	return req, nil
}

// resolveUpstreamPath computes the path (and query, if present) that must be
// signed against the actual AWS backend: UpstreamInfo.BasePath followed by
// the resolved operation path.
//
// reqCtx.Path is the raw inbound ":path" (e.g. "/abc/1.0.0/chat/completions"),
// which is the gateway's APIContext + the resolved operation path.
// reqCtx.APIContext is already fully version-resolved (e.g. an API declared
// with context "/abc/$version" and version "1.0.0" reports APIContext as
// "/abc/1.0.0" — see restapi.go's Context: strings.ReplaceAll(apiData.Context,
// "$version", apiData.Version)), so the version must not be appended again
// here. SharedContext carries no field with the resolved operation path on
// its own, so it is derived here by trimming that known prefix.
func resolveUpstreamPath(reqCtx *policy.RequestContext) string {
	prefix := reqCtx.APIContext
	relativePath := strings.TrimPrefix(reqCtx.Path, prefix)

	basePath := reqCtx.UpstreamInfo.BasePath
	if basePath == "" || basePath == "/" {
		return relativePath
	}
	return strings.TrimSuffix(basePath, "/") + relativePath
}

// hashPayload returns the lowercase-hex SHA-256 of body, or the well-known
// empty-body hash when body is nil/empty.
func hashPayload(body []byte) string {
	if len(body) == 0 {
		return emptyPayloadHash
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// extractSignedHeaders reads back the headers that were signed and must be
// forwarded upstream: Authorization and X-Amz-Date (written by SignHTTP),
// X-Amz-Content-Sha256 (set in signRequest before signing so it is covered
// by the signature), and — only if session-token credentials were used —
// X-Amz-Security-Token, for use in UpstreamRequestModifications.
func extractSignedHeaders(req *http.Request) map[string]string {
	headers := map[string]string{
		"Authorization":        req.Header.Get("Authorization"),
		"X-Amz-Date":           req.Header.Get("X-Amz-Date"),
		"X-Amz-Content-Sha256": req.Header.Get("X-Amz-Content-Sha256"),
	}
	if token := req.Header.Get("X-Amz-Security-Token"); token != "" {
		headers["X-Amz-Security-Token"] = token
	}
	return headers
}

// authFailure builds a 502 Bad Gateway ImmediateResponse for gateway-side
// credential/signing failures. 502 (not 401) is deliberate: the caller's
// request was fine — it is the gateway's own AWS credentials or signing
// process that failed, a gateway-to-backend problem rather than a
// client-auth rejection.
func (p *AWSAuthenticationPolicy) authFailure(shared *policy.SharedContext, reason string, cause error) policy.RequestAction {
	slog.Error("AWSAuthentication: signing failed", "reason", reason, "error", cause,
		"service", p.service, "region", p.region, "authenticationType", p.authenticationType)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Properties: map[string]string{
			"service":            p.service,
			"region":             p.region,
			"authenticationType": p.authenticationType,
		},
		Previous: shared.AuthContext,
	}

	body, _ := json.Marshal(map[string]string{
		"error":   "Bad Gateway",
		"message": "failed to authenticate request to upstream AWS service",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeMediationFailed,
			Type:      policy.FaultTypeMediation,
			Direction: policy.DirectionRequest,
			Message:   "failed to authenticate request to upstream AWS service",
			// reason names the gateway's own configuration or signing problem, so it is
			// withheld from the client body and reaches fault policies only.
			Description: reason,
		},
	}
}

// authSuccess records a successful AWS SigV4 authentication in the shared
// AuthContext, preserving any existing chain (e.g. an earlier inbound auth
// policy) via Previous.
func (p *AWSAuthenticationPolicy) authSuccess(shared *policy.SharedContext) {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Properties: map[string]string{
			"service":            p.service,
			"region":             p.region,
			"authenticationType": p.authenticationType,
		},
		Previous: shared.AuthContext,
	}
}
