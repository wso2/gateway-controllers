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
	"strconv"
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

	// ResponseDefaultStreamingJSONPath locates the assistant text inside one SSE
	// data frame. A streamed response carries text incrementally under
	// choices[0].delta.content, so ResponseDefaultJSONPath — which addresses the
	// non-streamed choices[0].message.content — never matches on a stream. The
	// two paths cannot be collapsed into one: they address different shapes of
	// the same response.
	ResponseDefaultStreamingJSONPath = "$.choices[0].delta.content"

	// StreamingEnabledByDefault keeps the response flow buffered unless an API
	// author opts in. Buffered is what every release up to v1.3.0 did, and the
	// opt-in is what makes this version a drop-in replacement for it.
	StreamingEnabledByDefault = false

	// DefaultStreamingTextUnitChars is how many characters of assistant text are
	// batched before each ApplyGuardrail call.
	//
	// 1000 is Amazon's text unit: AWS's own guidance for streaming outputs is to
	// batch chunks "into smaller batches that are closer to a text unit, which
	// is approximately 1,000 characters", assessing as soon as the buffer
	// exceeds one unit. It is also the billing unit, so a call carrying 40
	// characters costs the same as one carrying 1000 — batching below a unit
	// buys nothing and pays the same.
	//
	// This is counted in characters of extracted text, never in bytes of the
	// wire format. One SSE event is ~150 bytes of framing around ~3 characters
	// of content, so a byte-sized window under-fills a text unit by more than an
	// order of magnitude and multiplies the bill accordingly.
	DefaultStreamingTextUnitChars = 1000

	// MinStreamingTextUnitChars floors the configured batch. Below this a batch
	// cannot fill a text unit under any framing, so it only adds calls.
	MinStreamingTextUnitChars = 100

	// streamFlushPacerBytes is how many raw bytes accumulate before the kernel
	// hands this policy a flush. It paces invocation and nothing else: whether
	// an ApplyGuardrail call happens is decided by the text-unit batch above,
	// which is measured on content this hook cannot see (see
	// NeedsMoreResponseData). Not configurable — the operator-facing control is
	// the text unit.
	streamFlushPacerBytes = 4096

	// maxHeldFlushBytes bounds the bytes withheld while their text is unassessed.
	//
	// The batch boundary is a character count, so a stream whose events carry no
	// assessable text — keep-alive comments, role deltas, usage frames — never
	// reaches it, and without this the withheld buffer grows for as long as the
	// stream runs while the client receives nothing. One text unit of SSE is
	// ~50 KB at typical framing, so this leaves room for a framing-heavy stream
	// before forcing the issue.
	//
	// Hitting it assesses whatever text has accumulated and releases, rather than
	// releasing unassessed: the guarantee is kept, at the cost of a batch billed
	// below a full text unit.
	maxHeldFlushBytes = 256 * 1024

	// maxPartialLineBytes bounds the retained incomplete line. A stream carrying
	// no line terminator at all would otherwise grow it without limit; past this
	// the fragment is dropped with a warning rather than held.
	maxPartialLineBytes = 64 * 1024

	// SSE field names. The single space after the colon is optional in the
	// specification — "data:{...}" and "data: {...}" are the same event — so
	// these are the field names and the space is handled separately. Writing
	// "data: " as a prefix would silently skip every event from an upstream
	// that omits it.
	sseDataField  = "data:"
	sseEventField = "event:"
	sseIDField    = "id:"
	sseRetryField = "retry:"
	// sseDataPrefix is only for events this policy emits itself.
	sseDataPrefix = "data: "
	sseDone       = "[DONE]"

	// metaKeySSEStream records that this stream was classified as SSE. A later
	// flush can carry only comments, "id:" or "retry:" lines and so look
	// unclassifiable on its own; without this it would be mistaken for a
	// non-SSE body and the accumulated text assessed as if it were one.
	metaKeySSEStream = "awsbedrockguardrail:stream_is_sse"

	// metaKeyPartialLine retains the trailing bytes of a flush that stopped in the
	// middle of an SSE line. A truncated "data:" payload is unparseable JSON, so
	// without this the text it carries is extracted from neither flush and is
	// never assessed. Reached when the engine force-flushes at its accumulator
	// ceiling, or whenever an upstream's writes do not align with event
	// boundaries.
	metaKeyPartialLine = "awsbedrockguardrail:partial_line"

	// metaKeyNonSSEForwarded records that a non-SSE flush was already delivered,
	// so the accumulated body must not be re-sent as a rewrite of a later chunk.
	metaKeyNonSSEForwarded = "awsbedrockguardrail:non_sse_forwarded"

	// metaKeyHeldBytes holds the flush bytes withheld from the client while the
	// text they carry is still unassessed. Only used when ValidateBeforeDeliver
	// is set; it is released verbatim once its text passes, and discarded
	// without ever being delivered if the text fails.
	metaKeyHeldBytes = "awsbedrockguardrail:held_bytes"

	// metaKeyPendingText holds assistant text seen but not yet validated: the
	// remainder carried over when a batch is trimmed back to a word or sentence
	// boundary, prepended to the next batch. AWS's guidance is that batches
	// "don't split words or sentences, and by carrying over any necessary
	// context from the previous batch" — this is that carry-over.
	metaKeyPendingText = "awsbedrockguardrail:streamed_pending_text"

	// metaKeyAccStreamedContent accumulates the assistant text already validated
	// in this stream.
	metaKeyAccStreamedContent = "awsbedrockguardrail:streamed_content"

	// metaKeyAccStreamedJSONBody accumulates a non-SSE chunked body across
	// flushes, so it can be validated whole at end of stream.
	metaKeyAccStreamedJSONBody = "awsbedrockguardrail:streamed_json_body"
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
	Enabled               bool
	JsonPath              string
	RedactPII             bool
	PassthroughOnError    bool
	ShowAssessment        bool
	ApplicableStatusCodes []statusCodeRange

	// Streaming applies to the response flow only. When false the response is
	// buffered and validated whole, exactly as in v1.3.0.
	Streaming bool

	// StreamingJsonPath addresses the assistant text inside one SSE data frame.
	// Unused when Streaming is false.
	StreamingJsonPath string

	// StreamingTextUnitChars is how many characters of assistant text are
	// batched before each ApplyGuardrail call. Unused when Streaming is false.
	StreamingTextUnitChars int
}

// statusCodeRange is an inclusive range of HTTP status codes. A single code is
// a range whose min and max are equal.
type statusCodeRange struct {
	min int
	max int
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
// Mode declares this instance's body requirements from its own configuration.
//
// Up to v1.3.0 this returned BodyModeBuffer unconditionally, which had two
// consequences an API author could not configure away. A flow the attachment
// does not use still had its body buffered, so a request-only attachment forced
// the whole response to be held; and because the kernel clears
// SupportsResponseStreaming for the entire chain as soon as any policy declares
// BUFFER, one such attachment also demoted every other policy on the route to
// buffered. Declaring SKIP for an unused flow removes both.
//
// The response flow declares STREAM only when streaming is explicitly enabled,
// so an attachment carried over from v1.3.0 keeps buffering and keeps the
// buffered path's behaviour exactly.
func (p *AWSBedrockGuardrailPolicy) Mode() policy.ProcessingMode {
	requestBodyMode := policy.BodyModeSkip
	if p.hasRequestParams && p.requestParams.Enabled {
		requestBodyMode = policy.BodyModeBuffer
	}

	responseBodyMode := policy.BodyModeSkip
	if p.hasResponseParams && p.responseParams.Enabled {
		responseBodyMode = policy.BodyModeBuffer
		if p.responseParams.Streaming {
			responseBodyMode = policy.BodyModeStream
		}
	}

	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    requestBodyMode,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   responseBodyMode,
	}
}

// parseRequestResponseParams parses and validates request/response parameters from map to struct
func parseRequestResponseParams(params map[string]interface{}, isResponse bool) (AWSBedrockGuardrailPolicyParams, error) {
	result := AWSBedrockGuardrailPolicyParams{
		JsonPath:               RequestDefaultJSONPath,
		Enabled:                RequestFlowEnabledByDefault,
		Streaming:              StreamingEnabledByDefault,
		StreamingJsonPath:      ResponseDefaultStreamingJSONPath,
		StreamingTextUnitChars: DefaultStreamingTextUnitChars,
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

	// Extract optional applicableStatusCodes parameter (response phase only)
	if applicableStatusCodesRaw, ok := params["applicableStatusCodes"]; ok && isResponse {
		applicableStatusCodes, ok := applicableStatusCodesRaw.(string)
		if !ok {
			return result, fmt.Errorf("'applicableStatusCodes' must be a string")
		}
		if strings.TrimSpace(applicableStatusCodes) != "" {
			ranges, err := parseStatusCodes(applicableStatusCodes)
			if err != nil {
				return result, fmt.Errorf("invalid 'applicableStatusCodes': %w", err)
			}
			result.ApplicableStatusCodes = ranges
		}
	}

	// The streaming parameters below configure the response flow only. Accepting
	// them on the request flow would imply the request can be validated
	// incrementally, which it cannot: a request must be validated whole before it
	// reaches the upstream, or there is nothing left to block.
	if !isResponse {
		for _, key := range []string{"streaming", "streamingJsonPath", "streamingTextUnitChars"} {
			if _, ok := params[key]; ok {
				return result, fmt.Errorf("'%s' is only valid on the response flow", key)
			}
		}
		return result, nil
	}

	// Extract optional streaming parameter
	if streamingRaw, ok := params["streaming"]; ok {
		if streaming, ok := streamingRaw.(bool); ok {
			result.Streaming = streaming
		} else {
			return result, fmt.Errorf("'streaming' must be a boolean")
		}
	}

	// Extract optional streamingJsonPath parameter
	if streamingJsonPathRaw, ok := params["streamingJsonPath"]; ok {
		streamingJsonPath, ok := streamingJsonPathRaw.(string)
		if !ok {
			return result, fmt.Errorf("'streamingJsonPath' must be a string")
		}
		if strings.TrimSpace(streamingJsonPath) == "" {
			return result, fmt.Errorf("'streamingJsonPath' must not be empty")
		}
		result.StreamingJsonPath = streamingJsonPath
	}

	// Extract optional streamingTextUnitChars parameter
	if unitRaw, ok := params["streamingTextUnitChars"]; ok {
		unit, err := extractInt(unitRaw)
		if err != nil {
			return result, fmt.Errorf("'streamingTextUnitChars' must be a number: %w", err)
		}
		if unit < MinStreamingTextUnitChars {
			return result, fmt.Errorf("'streamingTextUnitChars' must be at least %d", MinStreamingTextUnitChars)
		}
		result.StreamingTextUnitChars = unit
	}

	return result, nil
}

// extractInt accepts the numeric shapes a policy parameter can arrive as. A
// value decoded from JSON or YAML reaches a policy as float64 rather than int,
// so an int-only assertion would reject every configured window.
func extractInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float32:
		if v != float32(int(v)) {
			return 0, fmt.Errorf("value %v is not a whole number", v)
		}
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("value %v is not a whole number", v)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("unsupported numeric type %T", value)
	}
}

// parseStatusCodes parses a comma-separated list of HTTP status codes and
// inclusive ranges, such as "200-299,401,403".
func parseStatusCodes(value string) ([]statusCodeRange, error) {
	var ranges []statusCodeRange
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("empty entry in %q", value)
		}

		start, end, isRange := strings.Cut(entry, "-")
		minCode, err := parseStatusCode(start)
		if err != nil {
			return nil, err
		}
		maxCode := minCode
		if isRange {
			if maxCode, err = parseStatusCode(end); err != nil {
				return nil, err
			}
			if minCode > maxCode {
				return nil, fmt.Errorf("range %q starts after it ends", entry)
			}
		}
		ranges = append(ranges, statusCodeRange{min: minCode, max: maxCode})
	}
	return ranges, nil
}

// parseStatusCode parses a single HTTP status code between 100 and 599.
func parseStatusCode(value string) (int, error) {
	value = strings.TrimSpace(value)
	code, err := strconv.Atoi(value)
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("%q is not a status code between 100 and 599", value)
	}
	return code, nil
}

// shouldValidateStatus reports whether a response with the given upstream
// status goes through the guardrail. Every response is validated when no status
// codes are configured, and 0 means the status is unknown, so it is validated.
func (params AWSBedrockGuardrailPolicyParams) shouldValidateStatus(status int) bool {
	if len(params.ApplicableStatusCodes) == 0 || status == 0 {
		return true
	}
	for _, r := range params.ApplicableStatusCodes {
		if status >= r.min && status <= r.max {
			return true
		}
	}
	return false
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
	// Process matches longest first to prevent substring collisions
	for _, match := range redactionMatches(output) {
		redactedText = strings.ReplaceAll(redactedText, match, "*****")
	}
	return redactedText
}

// redactionMatches returns the values the guardrail reported, longest first.
//
// Shared by the redaction rewrite and the leak check that follows it: the same
// list that says what to replace is what says whether anything was missed.
func redactionMatches(output *bedrockruntime.ApplyGuardrailOutput) []string {
	if output == nil || len(output.Assessments) == 0 || output.Assessments[0].SensitiveInformationPolicy == nil {
		return nil
	}

	var matches []string
	for _, entity := range output.Assessments[0].SensitiveInformationPolicy.PiiEntities {
		if match := aws.ToString(entity.Match); match != "" {
			matches = append(matches, match)
		}
	}
	for _, regex := range output.Assessments[0].SensitiveInformationPolicy.Regexes {
		if match := aws.ToString(regex.Match); match != "" {
			matches = append(matches, match)
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return len(matches[i]) > len(matches[j])
	})
	return matches
}

// redactedFlush applies the guardrail's redactions to a flush and reports
// whether any reported value survived.
//
// Redaction is written back frame by frame, because that is the only place an
// SSE value can be replaced without re-framing the stream. A value the model
// emitted across two events — "john@" in one, "example.com" in the next — is
// therefore present in neither frame's text and is replaced in neither, so the
// rewrite alone cannot guarantee it is gone.
//
// The check closes that: the rewritten flush is re-read as a whole and tested
// against the same match list. A survivor means this flush cannot be delivered
// redacted, and the caller fails closed rather than forward the value — the one
// thing redaction mode exists to prevent.
func (p *AWSBedrockGuardrailPolicy) redactedFlush(
	flush string,
	output interface{},
	rp AWSBedrockGuardrailPolicyParams,
) (rewritten string, changed, leaked bool) {
	typed, ok := output.(*bedrockruntime.ApplyGuardrailOutput)
	if !ok {
		return flush, false, false
	}
	matches := redactionMatches(typed)
	if len(matches) == 0 {
		return flush, false, false
	}

	rewritten, changed = rewriteSSEDeltaContent(flush, rp.StreamingJsonPath, func(frameText string) string {
		return p.extractRedactedContent(typed, frameText)
	})

	joined := extractSSEDeltaContent(rewritten, rp.StreamingJsonPath)
	for _, match := range matches {
		if strings.Contains(joined, match) {
			return rewritten, changed, true
		}
	}
	return rewritten, changed, false
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

// updatePayloadWithMaskedContent updates the original payload by replacing the extracted content
// Fallback policy: If jsonPath is empty, returns modifiedContent directly. For all JSON processing
// errors (unmarshal, SetValueAtJSONPath, marshal), logs the error and returns originalPayload to
// avoid returning invalid JSON or silently losing guardrail modifications.
func (p *AWSBedrockGuardrailPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) []byte {
	if jsonPath == "" {
		return []byte(modifiedContent)
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(originalPayload, &jsonData); err != nil {
		slog.Debug("AWSBedrockGuardrail: Failed to unmarshal payload for content update", "jsonPath", jsonPath, "extractedValue", extractedValue, "error", err)
		return originalPayload
	}

	err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent)
	if err != nil {
		slog.Debug("AWSBedrockGuardrail: Failed to set value at JSONPath", "jsonPath", jsonPath, "extractedValue", extractedValue, "error", err)
		return originalPayload
	}

	updatedPayload, err := json.Marshal(jsonData)
	if err != nil {
		slog.Debug("AWSBedrockGuardrail: Failed to marshal updated payload", "jsonPath", jsonPath, "extractedValue", extractedValue, "error", err)
		return originalPayload
	}

	return updatedPayload
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
	if !p.responseParams.shouldValidateStatus(respCtx.ResponseStatus) {
		slog.Debug("AWSBedrockGuardrail: Response status not configured for validation, skipping", "status", respCtx.ResponseStatus)
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true, respCtx.Metadata).(policy.ResponseAction)
}

// ─── Streaming response path ─────────────────────────────────────────────────
//
// The response flow can validate a streamed response incrementally instead of
// holding it whole. The division of labour is the one the SDK defines: the
// kernel owns the buffer and asks NeedsMoreResponseData whether to keep
// accumulating, and this policy owns the stop condition and the verdict.
//
// What this path cannot do, by construction: once a chunk has been flushed
// downstream the response status and headers are committed, so a violation
// found mid-stream cannot become a 422. It ends the stream with a final SSE
// error event instead, which means text already delivered stays delivered.
// That is a property of streaming, not of this implementation — an API that
// must never emit unvalidated text has to stay buffered (streaming: false).

// NeedsMoreResponseData implements policy.StreamingResponsePolicy.
//
// It is the window rule, and the reason this policy cannot simply flush every
// chunk the way the locally-computed guardrails do: every validation here is a
// billed ApplyGuardrail round trip. Flushing per chunk would put an AWS call
// between every pair of tokens.
//
// Four cases:
//
//   - A unary JSON document that happens to arrive over chunked transfer
//     accumulates whole. Such a response is not incrementally consumable by a
//     client anyway, so there is no latency to protect, and holding it keeps the
//     buffered path's property that nothing unvalidated reaches the client. The
//     kernel always flushes at end of stream, so this cannot stall.
//   - Below the window, keep accumulating.
//   - At or past the window: an SSE buffer is released only on an event
//     boundary, because a flush cut through the middle of a `data:` line leaves
//     JSON that no JSONPath can read — the original failure. Anything else is
//     released as soon as the window is reached; see below for why that is safe.
//
// Note what this hook is given: the kernel passes the *raw* accumulated upstream
// bytes, before any policy has run. That is not what OnResponseBodyChunk
// receives. On a Bedrock-backed route, openai-to-bedrock-transformer sits later
// in the chain, so by reverse response ordering it runs first and rewrites each
// flush into OpenAI SSE — which is what this policy then validates. Here the
// bytes are still Amazon's binary event-stream framing.
//
// So an "is this SSE?" test cannot decide whether to hold: answering "not SSE,
// therefore accumulate" would hold every Bedrock stream to end of stream and
// defeat the whole point. Frame integrity for that format is not this policy's
// problem either — the transformer declares its own NeedsMoreResponseData for a
// partial frame, and the kernel flushes only when *no* policy wants more data,
// so releasing here can never cut a frame.
//
// The one case that must still be held is a unary JSON body, which is why the
// discriminator below is "does this look like a JSON document", not "is this
// SSE". An opaque framing with no transformer ahead of it in the chain is
// forwarded unvalidated until end of stream; that is logged by
// handleNonSSEStreamFlush.
func (p *AWSBedrockGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if !p.hasResponseParams || !p.responseParams.Enabled || !p.responseParams.Streaming {
		return false
	}
	if looksLikeJSONDocument(accumulated) {
		return true
	}
	if len(accumulated) < streamFlushPacerBytes {
		return true
	}
	if isSSEChunk(string(accumulated)) {
		return !endsAtSSEEventBoundary(accumulated)
	}
	return false
}

// looksLikeJSONDocument reports whether b opens a JSON object or array, ignoring
// leading whitespace. It is deliberately a test of the first meaningful byte
// rather than a parse: it runs on every accumulated chunk, and a partially
// received document must answer the same as a complete one.
func looksLikeJSONDocument(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// OnResponseBodyChunk implements policy.StreamingResponsePolicy. It is called
// once per flush released by NeedsMoreResponseData, never once per chunk.
func (p *AWSBedrockGuardrailPolicy) OnResponseBodyChunk(
	ctx context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled || !p.responseParams.Streaming {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil {
		return policy.ForwardResponseChunk{}
	}
	// An empty chunk mid-stream carries nothing to do. An empty chunk at end of
	// stream is different: it is the bare sentinel many streaming frameworks send
	// after the last event, and it is the last opportunity to assess the text
	// still held in pending or the body accumulated from a non-SSE response.
	// Returning early here would drop the final batch, which AWS's guidance is
	// explicit must still be assessed.
	if len(chunk.Chunk) == 0 && !chunk.EndOfStream {
		return policy.ForwardResponseChunk{}
	}
	// applicableStatusCodes applies here exactly as it does on the buffered path
	// (see OnResponseBody); the upstream status is known from the response
	// headers, which were seen before any chunk arrived.
	if !p.responseParams.shouldValidateStatus(respCtx.ResponseStatus) {
		slog.Debug("AWSBedrockGuardrail: Response status not configured for validation, skipping",
			"status", respCtx.ResponseStatus)
		return policy.ForwardResponseChunk{}
	}
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}

	chunkStr := string(chunk.Chunk)

	// Classify once per stream and remember it. A later flush can carry only
	// comments, "id:" or "retry:" lines — and the final one can be empty — so
	// judging each flush alone would route the tail of an SSE stream down the
	// non-SSE path and assess its accumulated text as a JSON body.
	sseStream, _ := respCtx.Metadata[metaKeySSEStream].(bool)
	if !sseStream && isSSEChunk(chunkStr) {
		sseStream = true
		respCtx.Metadata[metaKeySSEStream] = true
	}

	if sseStream {
		return p.handleSSEStreamFlush(chunkStr, chunk, respCtx, p.responseParams)
	}
	return p.handleNonSSEStreamFlush(chunkStr, chunk, respCtx)
}

// handleNonSSEStreamFlush validates a non-SSE body that reached this path over
// chunked transfer. NeedsMoreResponseData accumulates such a body whole, so the
// flush is normally the complete response and is validated by exactly the same
// code as the buffered path.
func (p *AWSBedrockGuardrailPolicy) handleNonSSEStreamFlush(
	chunkStr string,
	chunk *policy.StreamBody,
	respCtx *policy.ResponseStreamContext,
) policy.StreamingResponseAction {
	previous, _ := respCtx.Metadata[metaKeyAccStreamedJSONBody].(string)
	full := previous + chunkStr
	respCtx.Metadata[metaKeyAccStreamedJSONBody] = full

	if !chunk.EndOfStream {
		// Two ways to get here: the kernel force-flushed at its accumulator
		// ceiling, or the response is in a framing this policy cannot read and
		// no transformer ahead of it in the chain rewrote it into SSE. Either
		// way the bytes are on their way to the client and there is nothing to
		// decide now; the accumulated body is still validated at end of stream.
		slog.Warn("AWSBedrockGuardrail: unrecognised streaming response format flushed before end of stream, validation deferred to end of stream",
			"accumulated_bytes", len(full))
		// Remember that bytes went downstream: the accumulated body can no longer
		// be delivered as a rewrite of a later chunk without repeating them.
		respCtx.Metadata[metaKeyNonSSEForwarded] = true
		return policy.ForwardResponseChunk{}
	}

	// An empty body has nothing to assess, and handing it to validatePayload
	// would fail JSONPath extraction and reject a response that carries no
	// content at all.
	if strings.TrimSpace(full) == "" {
		return policy.ForwardResponseChunk{}
	}

	result := p.validatePayload([]byte(full), p.responseParams, true, respCtx.Metadata)
	modifications, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		return policy.ForwardResponseChunk{}
	}
	if modifications.StatusCode != nil {
		// The buffered path answers a violation with a status; this one cannot,
		// because the status went downstream with the headers. The body it built
		// is still the right thing to deliver as the stream's last event.
		return policy.TerminateResponseChunk{
			Body:              modifications.Body,
			AnalyticsMetadata: modifications.AnalyticsMetadata,
		}
	}
	if modifications.Body != nil {
		forwarded, _ := respCtx.Metadata[metaKeyNonSSEForwarded].(bool)
		if len(chunkStr) == 0 || forwarded {
			// Two reasons the rewrite cannot be delivered: the flush in hand is
			// the empty end-of-stream sentinel, so there is nothing to replace;
			// or earlier flushes already went downstream, so replacing this one
			// with the accumulated body would repeat everything sent before it.
			// Either way the assessment still ran — only the rewrite is dropped.
			slog.Debug("AWSBedrockGuardrail: response modification not delivered",
				"reason_empty_final_chunk", len(chunkStr) == 0,
				"reason_earlier_flush_forwarded", forwarded,
				"accumulated_bytes", len(full))
			return policy.ForwardResponseChunk{}
		}
		return policy.ForwardResponseChunk{Body: modifications.Body}
	}
	return policy.ForwardResponseChunk{}
}

// assessStreamBatch runs one ApplyGuardrail call for a batch. stop is true when
// the returned action must be delivered immediately — a violation, or a failure
// that passthroughOnError does not excuse.
func (p *AWSBedrockGuardrailPolicy) assessStreamBatch(
	cleaned string,
	emit string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) (action policy.StreamingResponseAction, output interface{}, modified string, stop bool) {
	output, err := p.applyGuardrailToText(cleaned)
	if err != nil {
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: streaming guardrail call failed, passthrough enabled",
				"error", err, "chunkIndex", chunk.Index)
			return p.releaseBytes(emit, nil, "", respCtx, rp), nil, "", true
		}
		slog.Debug("AWSBedrockGuardrail: streaming guardrail call failed",
			"error", err, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Error calling AWS Bedrock Guardrail", err, rp.ShowAssessment, nil),
			AnalyticsMetadata: guardrailHitAnalytics(),
		}, nil, "", true
	}

	violation, modifiedContent, err := p.evaluateGuardrailResponse(output, cleaned, rp.RedactPII, false, respCtx.Metadata)
	if err != nil {
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: streaming guardrail evaluation failed, passthrough enabled",
				"error", err, "chunkIndex", chunk.Index)
			return p.releaseBytes(emit, nil, "", respCtx, rp), nil, "", true
		}
		slog.Debug("AWSBedrockGuardrail: streaming guardrail evaluation failed",
			"error", err, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Error evaluating guardrail response", err, rp.ShowAssessment, output),
			AnalyticsMetadata: guardrailHitAnalytics(),
		}, nil, "", true
	}

	if violation {
		slog.Debug("AWSBedrockGuardrail: streaming violation detected",
			"chunkIndex", chunk.Index, "batchChars", len([]rune(cleaned)))
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Violation of AWS Bedrock Guardrails detected", nil, rp.ShowAssessment, output),
			AnalyticsMetadata: guardrailHitAnalytics(),
		}, nil, "", true
	}

	return nil, output, modifiedContent, false
}

// handleSSEStreamFlush assesses a batch before any of its bytes reach the
// client.
//
// The flush bytes are withheld — returned as an empty body, which the engine
// forwards as an empty streamed chunk — while their text accumulates. Once the
// batch passes a text unit it is assessed: if it passes, the bytes that carried
// it are released; if it fails, they are discarded and the client never receives
// them.
//
// Holding the bytes here is the only way to get that guarantee on a Bedrock
// route. The engine's own accumulator holds Amazon's binary frames, so a gate in
// NeedsMoreResponseData cannot count characters of assistant text — the text
// exists only after openai-to-bedrock-transformer has rewritten the flush, which
// happens in this callback.
//
// The cost is delivery in batch-sized steps instead of continuously. For a
// 1,000-character unit that is roughly one delivery per 1,000 characters
// generated, so time to first byte is a text unit rather than a flush;
// streamingTextUnitChars is the dial.
func (p *AWSBedrockGuardrailPolicy) handleSSEStreamFlush(
	chunkStr string,
	chunk *policy.StreamBody,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) policy.StreamingResponseAction {
	pending, _ := respCtx.Metadata[metaKeyPendingText].(string)
	held, _ := respCtx.Metadata[metaKeyHeldBytes].(string)
	newText := p.flushText(chunkStr, chunk.EndOfStream, respCtx, rp)
	unit := p.effectiveTextUnit()

	// Assess and release everything once the stream ends; there is no later
	// batch to carry into, and nothing may be left undelivered.
	if chunk.EndOfStream {
		return p.assessAndRelease(pending+newText, held+chunkStr, respCtx, rp, chunk)
	}

	// Redaction assesses every flush (unit 0), so a flush is never held past its
	// own assessment.
	if unit <= 0 {
		return p.assessAndRelease(pending+newText, held+chunkStr, respCtx, rp, chunk)
	}

	// The withheld buffer has grown as far as it may. Reached by a stream whose
	// events carry little or no assessable text, which never trips the character
	// boundary below.
	if len(held)+len(chunkStr) > maxHeldFlushBytes {
		slog.Warn("AWSBedrockGuardrail: withheld response bytes reached the limit; assessing and releasing early",
			"held_bytes", len(held), "limit", maxHeldFlushBytes, "pending_chars", len([]rune(pending)))
		return p.assessAndRelease(pending+newText, held+chunkStr, respCtx, rp, chunk)
	}

	combinedText := pending + newText
	combinedHeld := held + chunkStr

	// Past a text unit: trim the batch back to the end of a sentence, or failing
	// that a word, exactly as the immediate-delivery path does — a phrase assessed
	// as two halves can pass where the whole would not.
	//
	// The trim point generally falls inside a frame, so the bytes released are
	// the frames whose text is wholly inside the batch and the straddling frame
	// is retained. Withholding assessed text is harmless; releasing unassessed
	// text is not.
	if batch, carry := splitAtTextUnit(combinedText, unit, false); batch != "" {
		release, retain := splitHeldAtTextBoundary(combinedHeld, rp.StreamingJsonPath, len([]rune(batch)))

		action := p.assessBatchAndRelease(batch, release, respCtx, rp, chunk)
		if action.TerminateStream() {
			return action
		}
		respCtx.Metadata[metaKeyPendingText] = carry
		respCtx.Metadata[metaKeyHeldBytes] = retain
		return action
	}

	respCtx.Metadata[metaKeyPendingText] = combinedText
	respCtx.Metadata[metaKeyHeldBytes] = combinedHeld
	// Withhold: a non-nil empty body replaces the chunk, so nothing is delivered
	// for this flush. A nil body would pass the bytes straight through.
	return policy.ForwardResponseChunk{Body: []byte{}}
}

// assessAndRelease assesses everything still withheld and, if all of it passes,
// releases the bytes. On a violation the bytes are dropped and the stream ends
// with the guardrail event alone, so nothing unassessed was ever delivered.
//
// The text is assessed a unit at a time rather than in one call: a flush can
// carry several units — the testbench's mock model writes a whole stream in one
// flush, and a real upstream can coalesce — and one oversized call is both
// billed by size anyway and further from the batch size AWS recommends.
func (p *AWSBedrockGuardrailPolicy) assessAndRelease(
	batchText string,
	heldBytes string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) policy.StreamingResponseAction {
	respCtx.Metadata[metaKeyPendingText] = ""
	respCtx.Metadata[metaKeyHeldBytes] = ""

	unit := p.effectiveTextUnit()
	remaining := batchText

	var (
		lastOutput   interface{}
		lastModified string
		assessed     bool
	)

	for {
		batch, carry := splitAtTextUnit(remaining, unit, true)
		if batch == "" {
			break
		}
		remaining = carry

		cleaned := strings.TrimSpace(textCleanRegexCompiled.ReplaceAllString(batch, ""))
		if cleaned == "" {
			if carry == "" {
				break
			}
			continue
		}

		action, output, modified, stop := p.assessStreamBatch(cleaned, heldBytes, respCtx, rp, chunk)
		if stop {
			if action.TerminateStream() {
				slog.Debug("AWSBedrockGuardrail: batch failed before delivery, held bytes discarded",
					"held_bytes", len(heldBytes), "chunkIndex", chunk.Index)
				return action
			}
			// passthroughOnError: this batch was not assessed, but withholding
			// the bytes indefinitely would stall the stream, so they are
			// released.
			return p.releaseBytes(heldBytes, nil, "", respCtx, rp)
		}

		validated, _ := respCtx.Metadata[metaKeyAccStreamedContent].(string)
		respCtx.Metadata[metaKeyAccStreamedContent] = validated + batch
		lastOutput, lastModified, assessed = output, modified, true

		if carry == "" {
			break
		}
	}

	if !assessed {
		// Framing only — nothing to assess, but the bytes are still owed to the
		// client.
		return p.releaseBytes(heldBytes, nil, "", respCtx, rp)
	}
	return p.releaseBytes(heldBytes, lastOutput, lastModified, respCtx, rp)
}

// assessBatchAndRelease assesses one batch and releases the bytes it covers,
// leaving the caller to record whatever text and bytes remain withheld.
func (p *AWSBedrockGuardrailPolicy) assessBatchAndRelease(
	batchText string,
	heldBytes string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) policy.StreamingResponseAction {
	cleaned := strings.TrimSpace(textCleanRegexCompiled.ReplaceAllString(batchText, ""))
	if cleaned == "" {
		// Framing only — nothing to assess, but the bytes are still owed to the
		// client.
		return p.releaseBytes(heldBytes, nil, "", respCtx, rp)
	}

	action, output, modified, stop := p.assessStreamBatch(cleaned, heldBytes, respCtx, rp, chunk)
	if stop {
		if action.TerminateStream() {
			slog.Debug("AWSBedrockGuardrail: batch failed before delivery, held bytes discarded",
				"held_bytes", len(heldBytes), "chunkIndex", chunk.Index)
			return action
		}
		// passthroughOnError: the batch was not assessed, but withholding the
		// bytes indefinitely would stall the stream, so they are released.
		return p.releaseBytes(heldBytes, nil, "", respCtx, rp)
	}

	validated, _ := respCtx.Metadata[metaKeyAccStreamedContent].(string)
	respCtx.Metadata[metaKeyAccStreamedContent] = validated + batchText

	return p.releaseBytes(heldBytes, output, modified, respCtx, rp)
}

// releaseBytes delivers withheld bytes, applying redaction or placeholder
// restoration to them first. An empty release is still returned as an empty body
// rather than nil, so the engine does not fall back to forwarding the original
// chunk.
func (p *AWSBedrockGuardrailPolicy) releaseBytes(
	heldBytes string,
	output interface{},
	modified string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) policy.StreamingResponseAction {
	if rp.RedactPII {
		if modified != "" {
			rewritten, changed, leaked := p.redactedFlush(heldBytes, output, rp)
			if leaked {
				slog.Warn("AWSBedrockGuardrail: a reported value spans event boundaries and could not be redacted; discarding the held bytes",
					"held_bytes", len(heldBytes))
				return policy.TerminateResponseChunk{
					Body: p.buildSSEErrorEvent("Sensitive content could not be redacted in a streamed response",
						nil, rp.ShowAssessment, output),
					AnalyticsMetadata: guardrailHitAnalytics(),
				}
			}
			if changed {
				return policy.ForwardResponseChunk{Body: []byte(rewritten)}
			}
		}
		return policy.ForwardResponseChunk{Body: []byte(heldBytes)}
	}

	raw, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if exists {
		if maskedPII, ok := raw.(map[string]string); ok && len(maskedPII) > 0 {
			if rewritten, changed := rewriteSSEDeltaContent(heldBytes, rp.StreamingJsonPath, func(frameText string) string {
				return p.restorePIIInResponse(frameText, maskedPII)
			}); changed {
				return policy.ForwardResponseChunk{Body: []byte(rewritten)}
			}
		}
	}
	return policy.ForwardResponseChunk{Body: []byte(heldBytes)}
}

// effectiveTextUnit returns the batch size to validate at.
//
// Redaction mode validates every flush instead of batching. Redaction rewrites
// the frames of the flush it is holding, so a finding can only be applied to
// text that has not yet been forwarded; batching would place the finding one or
// more flushes after the frames it belongs to, which have already gone to the
// client. The cost is more ApplyGuardrail calls, which is the price of
// redacting in a stream at all.
func (p *AWSBedrockGuardrailPolicy) effectiveTextUnit() int {
	if p.responseParams.RedactPII {
		return 0
	}
	return p.responseParams.StreamingTextUnitChars
}

// splitAtTextUnit divides accumulated text into the batch to validate now and
// the remainder to carry into the next batch.
//
// Below a text unit nothing is validated yet unless the stream has ended, in
// which case the final batch is assessed whatever its size — AWS's guidance is
// explicit that the last batch must still be evaluated, and there will be no
// later batch to carry into. At or above a unit the cut happens even at end of
// stream, so a caller looping over this function assesses a long buffer as
// several unit-sized calls rather than one oversized one.
//
// Above a unit the cut is moved back to the end of the last sentence, or
// failing that the last word, so a batch never splits a phrase across two
// calls. That matters for detection, not tidiness: "my SSN is 123-" and
// "45-6789" assessed separately may each pass where the whole phrase would not.
// If neither boundary exists within a reasonable distance the text is cut at
// the unit, so a stream of boundary-free text cannot grow the carry without
// bound.
func splitAtTextUnit(text string, unit int, endOfStream bool) (batch, carry string) {
	runes := []rune(text)
	if unit <= 0 {
		return text, ""
	}
	if len(runes) < unit {
		// Below a unit: hold for more text, unless there will be none.
		if endOfStream {
			return text, ""
		}
		return "", text
	}

	cut := lastSentenceEnd(runes, unit)
	if cut <= 0 {
		cut = lastWordEnd(runes, unit)
	}
	if cut <= 0 {
		cut = unit
	}
	return string(runes[:cut]), string(runes[cut:])
}

// maxBoundarySearchRunes bounds how far back a boundary is looked for, so a
// batch is never trimmed to a small fraction of a text unit by one very long
// sentence.
const maxBoundarySearchRunes = 200

// lastSentenceEnd returns the index just past the last sentence terminator at or
// before limit, or 0 if there is none within the search distance.
func lastSentenceEnd(runes []rune, limit int) int {
	floor := limit - maxBoundarySearchRunes
	if floor < 0 {
		floor = 0
	}
	for i := limit - 1; i >= floor; i-- {
		switch runes[i] {
		case '.', '!', '?', '\n':
			return i + 1
		}
	}
	return 0
}

// lastWordEnd returns the index just past the last whitespace at or before
// limit, or 0 if there is none within the search distance.
func lastWordEnd(runes []rune, limit int) int {
	floor := limit - maxBoundarySearchRunes
	if floor < 0 {
		floor = 0
	}
	for i := limit - 1; i >= floor; i-- {
		switch runes[i] {
		case ' ', '\t', '\n', '\r':
			return i + 1
		}
	}
	return 0
}

// applyGuardrailToText runs one ApplyGuardrail call for the given text.
func (p *AWSBedrockGuardrailPolicy) applyGuardrailToText(text string) (interface{}, error) {
	loadConfig := p.loadAWSConfigFunc
	if loadConfig == nil {
		loadConfig = p.loadAWSConfig
	}
	awsCfg, err := loadConfig(context.Background(), p.region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	output, err := p.applyBedrockGuardrail(context.Background(), awsCfg, p.guardrailID, p.guardrailVersion, text)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// guardrailHitAnalytics matches the analytics the buffered path reports, so a
// stream terminated by this policy is attributed the same way as a buffered
// rejection.
func guardrailHitAnalytics() map[string]interface{} {
	return map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "AWS Bedrock Guardrail",
	}
}

// buildSSEErrorEvent renders the rejection as the stream's final event. The
// payload is the same shape the buffered path returns as a 422 body, so a
// client parsing one already understands the other.
func (p *AWSBedrockGuardrailPolicy) buildSSEErrorEvent(reason string, validationError error, showAssessment bool, output interface{}) []byte {
	assessment := p.buildAssessmentObject(reason, validationError, true, showAssessment, output)
	responseBody := map[string]interface{}{
		"type":    "AWS_BEDROCK_GUARDRAIL",
		"message": assessment,
	}
	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"AWS_BEDROCK_GUARDRAIL","message":"Internal error"}`)
	}
	return []byte(sseDataPrefix + string(bodyBytes) + "\n\n")
}

// ─── SSE helpers ─────────────────────────────────────────────────────────────

// splitHeldAtTextBoundary divides withheld bytes at the frame boundary that
// covers assessedChars of extracted text: the frames whose text is wholly inside
// the assessed batch, and the remainder to keep withholding.
//
// This is what lets a batch be trimmed to a sentence while still being able to
// release exact bytes. The trim point generally falls inside a frame, since a
// frame carries a token rather than a sentence. That frame is retained whole —
// withholding text that *has* been assessed is harmless, where releasing text
// that has not is the thing this mode exists to prevent — and its text is
// assessed again as part of the next batch, which costs nothing because the
// batch is billed by size, not by novelty.
//
// Framing is kept with the block it introduces: an "event:", "id:" or "retry:"
// line is released only once the data line it precedes is covered, so a block
// is never released with its payload still withheld. Blank separators and
// comments stand alone and are released as they are reached.
func splitHeldAtTextBoundary(held, streamingJsonPath string, assessedChars int) (release, retain string) {
	if assessedChars <= 0 {
		return "", held
	}

	var (
		chars     int
		committed int // byte offset through which everything may be released
		framing   int // byte offset where the current uncommitted framing run began
	)
	framing = -1

	for i := 0; i < len(held); {
		lineEnd := len(held)
		if j := strings.IndexByte(held[i:], '\n'); j >= 0 {
			lineEnd = i + j + 1
		}
		raw := held[i:lineEnd]
		line := strings.TrimRight(raw, "\r\n")

		switch {
		case isSSEIntroducerLine(line):
			// Introduces the data line below it; hold both or release both.
			if framing < 0 {
				framing = i
			}
		default:
			payload, _, isData := sseDataPayload(line)
			if !isData {
				// Blank separator or comment: nothing depends on it.
				if framing < 0 {
					committed = lineEnd
				}
				break
			}
			n := len([]rune(frameText(payload, streamingJsonPath)))
			if chars+n > assessedChars {
				// This frame straddles the boundary. Retain it, and the framing
				// that introduced it.
				start := committed
				if framing >= 0 {
					start = framing
				}
				return held[:start], held[start:]
			}
			chars += n
			committed = lineEnd
			framing = -1
		}
		i = lineEnd
	}

	if framing >= 0 {
		return held[:framing], held[framing:]
	}
	return held[:committed], held[committed:]
}

// isSSEIntroducerLine reports whether a line introduces the data line that
// follows it, rather than standing on its own.
func isSSEIntroducerLine(line string) bool {
	return strings.HasPrefix(line, sseEventField) ||
		strings.HasPrefix(line, sseIDField) ||
		strings.HasPrefix(line, sseRetryField)
}

// frameText returns the assistant text one data payload carries, or "" for a
// payload that carries none.
func frameText(payload, streamingJsonPath string) string {
	if t := strings.TrimSpace(payload); t == "" || t == sseDone {
		return ""
	}
	value, err := utils.ExtractStringValueFromJsonpath([]byte(payload), streamingJsonPath)
	if err != nil {
		return ""
	}
	return textCleanRegexCompiled.ReplaceAllString(value, "")
}

// splitTrailingPartialLine divides s at its last line terminator, returning the
// complete lines and the incomplete remainder. A flush with no terminator at all
// is entirely incomplete.
func splitTrailingPartialLine(s string) (complete, partial string) {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[:i+1], s[i+1:]
	}
	return "", s
}

// flushText returns the assistant text of this flush, joined to any incomplete
// line retained from the previous one, and retains this flush's own incomplete
// tail for the next.
//
// An SSE line cut in half is the problem being solved. A truncated "data:"
// payload is unparseable JSON, so without this its text is extracted from
// neither flush and never assessed. Reached when the engine force-flushes at its
// accumulator ceiling, or whenever an upstream's writes do not align with event
// boundaries.
//
// Only the text needs carrying: every byte of the flush is withheld until the
// batch covering it has been assessed, so a half-frame can never be delivered
// before the line completes. The retained fragment is what makes its text
// assessable, and the frame is whole again by the time the bytes are released.
//
// Over maxPartialLineBytes the fragment stops being retained as a fragment: a
// stream carrying no line terminator would otherwise grow it without limit. Its
// bytes are still withheld with the rest, so nothing is lost — only the chance
// to read text out of it.
func (p *AWSBedrockGuardrailPolicy) flushText(
	chunkStr string,
	endOfStream bool,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) string {
	carried, _ := respCtx.Metadata[metaKeyPartialLine].(string)
	joined := carried + chunkStr

	if endOfStream {
		delete(respCtx.Metadata, metaKeyPartialLine)
		return extractSSEDeltaContent(joined, rp.StreamingJsonPath)
	}

	complete, partial := splitTrailingPartialLine(joined)
	if len(partial) > maxPartialLineBytes {
		slog.Warn("AWSBedrockGuardrail: incomplete SSE line exceeded the retention limit, no longer retaining it",
			"partial_bytes", len(partial), "limit", maxPartialLineBytes)
		delete(respCtx.Metadata, metaKeyPartialLine)
		return extractSSEDeltaContent(joined, rp.StreamingJsonPath)
	}
	respCtx.Metadata[metaKeyPartialLine] = partial
	return extractSSEDeltaContent(complete, rp.StreamingJsonPath)
}

// isSSEChunk reports whether s looks like SSE framing.
//
// Any of the specification's field names counts, as does a comment line (one
// beginning with ":", which is how upstreams send keep-alives). Testing only
// "data:" and "event:" would misclassify a flush that happens to carry just
// comments or just "id:"/"retry:" lines, and the whole flush is scanned rather
// than its first few lines for the same reason.
func isSSEChunk(s string) bool {
	for rest := s; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		if isSSEFieldLine(line) {
			return true
		}
	}
	return false
}

// isSSEFieldLine reports whether one line is an SSE field or comment line.
func isSSEFieldLine(line string) bool {
	if strings.HasPrefix(line, ":") {
		return true // comment, e.g. ": keep-alive"
	}
	return strings.HasPrefix(line, sseDataField) ||
		strings.HasPrefix(line, sseEventField) ||
		strings.HasPrefix(line, sseIDField) ||
		strings.HasPrefix(line, sseRetryField)
}

// nextLine splits off the first line of s, dropping its terminator, and returns
// it with the remainder. Used instead of strings.Split so a scan can stop at the
// first match without splitting a whole multi-kilobyte flush.
func nextLine(s string) (line, rest string) {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSuffix(s[:i], "\r"), s[i+1:]
	}
	return strings.TrimSuffix(s, "\r"), ""
}

// sseDataPayload returns the value of a "data:" line, the exact prefix it was
// written with, and whether the line is a data line at all.
//
// Only one leading space is consumed, per the specification; any further
// whitespace belongs to the value and is preserved, so a rewritten event is
// byte-identical to the original apart from the value this policy changed.
func sseDataPayload(line string) (payload, prefix string, ok bool) {
	if !strings.HasPrefix(line, sseDataField) {
		return "", "", false
	}
	payload = line[len(sseDataField):]
	prefix = sseDataField
	if strings.HasPrefix(payload, " ") {
		payload = payload[1:]
		prefix += " "
	}
	return payload, prefix, true
}

// endsAtSSEEventBoundary reports whether s ends where one event ends, so a
// flush released here never cuts a `data:` line in half.
//
// Both terminators are accepted: matching "\n\n" alone would treat a CRLF
// stream as one event that never ends, and accumulate it to the kernel's
// ceiling instead of releasing it.
func endsAtSSEEventBoundary(s []byte) bool {
	text := string(s)
	return strings.HasSuffix(text, "\n\n") || strings.HasSuffix(text, "\r\n\r\n")
}

// extractSSEDeltaContent concatenates the assistant text carried by every
// complete data frame in s, read at streamingJsonPath.
//
// Frames with no text at that path — the opening role delta, usage frames,
// `[DONE]`, comments — contribute nothing rather than contributing their raw
// JSON. Sending framing to ApplyGuardrail would bill for it and could trip a
// guardrail on the wire format rather than on the model's words.
func extractSSEDeltaContent(s string, streamingJsonPath string) string {
	var sb strings.Builder
	for rest := s; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		payload, _, ok := sseDataPayload(line)
		if !ok {
			continue
		}
		sb.WriteString(frameText(payload, streamingJsonPath))
	}
	return sb.String()
}

// rewriteSSEDeltaContent applies transform to the text at streamingJsonPath in
// every data frame of chunkStr, returning the rewritten flush and whether
// anything changed. A frame whose payload is not JSON, carries no text at that
// path, or is unchanged by transform is passed through byte-for-byte.
func rewriteSSEDeltaContent(chunkStr string, streamingJsonPath string, transform func(string) string) (string, bool) {
	lines := strings.Split(chunkStr, "\n")
	changed := false

	for i, line := range lines {
		carriage := strings.HasSuffix(line, "\r")
		trimmed := strings.TrimSuffix(line, "\r")
		payload, prefix, ok := sseDataPayload(trimmed)
		if !ok {
			continue
		}
		if t := strings.TrimSpace(payload); t == "" || t == sseDone {
			continue
		}

		var frame map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			continue
		}
		original, err := utils.ExtractStringValueFromJsonpath([]byte(payload), streamingJsonPath)
		if err != nil {
			continue
		}
		replacement := transform(original)
		if replacement == original {
			continue
		}
		if err := utils.SetValueAtJSONPath(frame, streamingJsonPath, replacement); err != nil {
			slog.Debug("AWSBedrockGuardrail: failed to set streaming value at JSONPath",
				"jsonPath", streamingJsonPath, "error", err)
			continue
		}
		rewrittenPayload, err := json.Marshal(frame)
		if err != nil {
			slog.Debug("AWSBedrockGuardrail: failed to marshal rewritten SSE frame", "error", err)
			continue
		}

		rebuilt := prefix + string(rewrittenPayload)
		if carriage {
			rebuilt += "\r"
		}
		lines[i] = rebuilt
		changed = true
	}

	if !changed {
		return chunkStr, false
	}
	return strings.Join(lines, "\n"), true
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

	extractedValue, err := utils.ExtractStringValueFromJsonpath(payload, params.JsonPath)
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
		modifiedPayload := p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, params.JsonPath)
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
