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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

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

// guardrailCodeFor derives the specific code from what Bedrock actually reported, so a caller
// can route a PII leak differently from a hate verdict without parsing an assessment.
//
// Bedrock can trip several policies on one call, and a single code can only name one, so the
// order below is a deliberate precedence rather than an accident of iteration. It follows the
// order this policy already treats these concerns in: sensitive information is checked first
// everywhere else here too (it is the one kind that can be masked rather than blocked), so a
// rejection that involved data leaking is reported as that first.
//
// The fallback is the content-safety group's own generic (906099), not 900514: an
// intervention IS a content verdict even when the assessment names nothing this vocabulary
// covers, so a caller testing 906000 <= code < 906100 should still see it.
//
// The tradeoff, stated because it is real: 906xxx sits OUTSIDE carbon's guardrail range
// [900514, 900515), which is exactly one code wide. Carbon-compatible analytics assigns a
// fault category by range membership, so these classify as "other" rather than "guardrail"
// there. Accepted deliberately — the class is still carried by FaultDetails.Type
// ("guardrail") and by GuardrailDetails.InterveningGuardrail.
func guardrailCodeFor(output interface{}) string {
	typed, ok := output.(*bedrockruntime.ApplyGuardrailOutput)
	if !ok || typed == nil {
		return policy.GuardrailCodeUnsafeContent
	}
	// What blocked the content decides the code: a prompt attack blocked beside an
	// email the guardrail only anonymized is a prompt attack. Findings without an
	// action, or whose action is not BLOCKED, are only consulted when nothing
	// blocked, in the order they always were.
	if code := guardrailCodeMatching(typed.Assessments, true); code != "" {
		return code
	}
	if code := guardrailCodeMatching(typed.Assessments, false); code != "" {
		return code
	}
	return policy.GuardrailCodeUnsafeContent
}

// guardrailCodeMatching returns the code for the first finding, by category, in
// the assessments -- PII, then content filters, words and denied topics -- or ""
// for none. blockedOnly considers only findings whose action is BLOCKED.
func guardrailCodeMatching(assessments []types.GuardrailAssessment, blockedOnly bool) string {
	counts := func(action string) bool { return !blockedOnly || action == "BLOCKED" }
	for _, a := range assessments {
		if sip := a.SensitiveInformationPolicy; sip != nil {
			for _, e := range sip.PiiEntities {
				if counts(string(e.Action)) {
					return policy.GuardrailCodePII
				}
			}
			for _, r := range sip.Regexes {
				if counts(string(r.Action)) {
					return policy.GuardrailCodePII
				}
			}
		}
	}
	for _, a := range assessments {
		if a.ContentPolicy == nil {
			continue
		}
		for _, f := range a.ContentPolicy.Filters {
			if !counts(string(f.Action)) {
				continue
			}
			switch f.Type {
			case types.GuardrailContentFilterTypeHate:
				return policy.GuardrailCodeHate
			case types.GuardrailContentFilterTypeSexual:
				return policy.GuardrailCodeSexual
			case types.GuardrailContentFilterTypeViolence:
				return policy.GuardrailCodeViolence
			case types.GuardrailContentFilterTypeInsults:
				return policy.GuardrailCodeHarassment
			case types.GuardrailContentFilterTypeMisconduct:
				return policy.GuardrailCodeDangerousActivity
			case types.GuardrailContentFilterTypePromptAttack:
				return policy.GuardrailCodePromptInjection
			}
		}
	}
	for _, a := range assessments {
		if wp := a.WordPolicy; wp != nil {
			for _, w := range wp.CustomWords {
				if counts(string(w.Action)) {
					return policy.GuardrailCodeProfanity
				}
			}
			for _, w := range wp.ManagedWordLists {
				if counts(string(w.Action)) {
					return policy.GuardrailCodeProfanity
				}
			}
		}
	}
	for _, a := range assessments {
		// A denied topic is what the content MEANT, measured against the operator's own
		// configured policy -- the intent group rather than the content-safety one.
		if tp := a.TopicPolicy; tp != nil {
			for _, t := range tp.Topics {
				if counts(string(t.Action)) {
					return policy.GuardrailCodeSemanticMatch
				}
			}
		}
	}
	return ""
}

// guardrailName identifies this guardrail in GuardrailDetails.InterveningGuardrail.
const guardrailName = "aws-bedrock-guardrail"

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

	// maxNonSSEHeldBytes bounds the body handleNonSSEStreamFlush withholds while
	// it waits for the end of a response that is not an event stream. Above it the
	// response cannot be assessed whole: it ends with a fault, or passes through
	// under passthroughOnError.
	maxNonSSEHeldBytes = 4 * 1024 * 1024

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
	metaKeySSEStream streamStateKey = "awsbedrockguardrail:stream_is_sse"

	// metaKeyClassifyWait holds the opening flushes of a stream that is not
	// labelled text/event-stream and that so far carries only SSE fields other
	// than "data:" (a keep-alive comment, "event:", "id:" or "retry:"): they could
	// open an event stream or a plain-text body, so they are withheld until a
	// later flush decides which.
	metaKeyClassifyWait streamStateKey = "awsbedrockguardrail:classify_wait"

	// metaKeyAssessedInHeld counts assessed characters still sitting in withheld
	// frames: the batch boundary generally falls inside a frame, and that frame
	// is retained whole. Its assessed prefix is not in pending — it must not be
	// assessed or billed twice — so it has to be counted here instead, or the
	// next release boundary is short by that much and the frame lingers.
	metaKeyAssessedInHeld streamStateKey = "awsbedrockguardrail:assessed_in_held"

	// metaKeyPartialLine retains the trailing bytes of a flush that stopped in the
	// middle of an SSE line. A truncated "data:" payload is unparseable JSON, so
	// without this the text it carries is extracted from neither flush and is
	// never assessed. Reached when the engine force-flushes at its accumulator
	// ceiling, or whenever an upstream's writes do not align with event
	// boundaries.
	metaKeyPartialLine streamStateKey = "awsbedrockguardrail:partial_line"

	// metaKeyNonSSEForwarded records that a non-SSE flush was already delivered,
	// so the accumulated body must not be re-sent as a rewrite of a later chunk.
	metaKeyNonSSEForwarded streamStateKey = "awsbedrockguardrail:non_sse_forwarded"

	// metaKeyHeldBytes holds the flush bytes withheld from the client while the
	// text they carry is still unassessed. Only used when ValidateBeforeDeliver
	// is set; it is released verbatim once its text passes, and discarded
	// without ever being delivered if the text fails.
	metaKeyHeldBytes streamStateKey = "awsbedrockguardrail:held_bytes"

	// metaKeyPendingText holds assistant text seen but not yet validated: the
	// remainder carried over when a batch is trimmed back to a word or sentence
	// boundary, prepended to the next batch. AWS's guidance is that batches
	// "don't split words or sentences, and by carrying over any necessary
	// context from the previous batch" — this is that carry-over.
	metaKeyPendingText streamStateKey = "awsbedrockguardrail:streamed_pending_text"

	// metaKeyAccStreamedJSONBody accumulates a non-SSE chunked body across
	// flushes, so it can be validated whole at end of stream.
	metaKeyAccStreamedJSONBody streamStateKey = "awsbedrockguardrail:streamed_json_body"

	// metaKeyJSONRPCStream records whether an event stream carries JSON-RPC
	// messages rather than LLM token deltas (see isJSONRPCStream).
	metaKeyJSONRPCStream streamStateKey = "awsbedrockguardrail:stream_is_jsonrpc"

	// metaKeyJSONRPCBuffer withholds the bytes of a JSON-RPC event still
	// arriving, until the event is complete and can be assessed.
	metaKeyJSONRPCBuffer streamStateKey = "awsbedrockguardrail:jsonrpc_buffer"

	// metaKeyCarriedDecisions holds assessments whose rewrites apply to withheld
	// frames, until those frames are released (see carryDecisions).
	metaKeyCarriedDecisions streamStateKey = "awsbedrockguardrail:carried_decisions"

	// metaKeyStreamingPathSeen records that an event of this stream carries the
	// member streamingJsonPath starts with (see checkStreamingPath).
	metaKeyStreamingPathSeen streamStateKey = "awsbedrockguardrail:streaming_path_seen"

	// metaKeyStreamingPathWait withholds the flushes checkStreamingPath is still
	// deciding about.
	metaKeyStreamingPathWait streamStateKey = "awsbedrockguardrail:streaming_path_wait"

	// metaKeyAccStreamedLen is the size of what metaKeyAccStreamedJSONBody holds.
	metaKeyAccStreamedLen streamStateKey = "awsbedrockguardrail:streamed_json_len"
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

// streamingPathKeySegment and streamingPathIndexSegment are the dot-separated
// segments the SDK's JSONPath reader resolves: a member name, or a member name
// with one array index.
var (
	streamingPathKeySegment   = regexp.MustCompile(`^[^.\[\]\s$'"*]+$`)
	streamingPathIndexSegment = regexp.MustCompile(`^[a-zA-Z0-9_]+\[-?\d+\]$`)
)

// validateStreamingJSONPath rejects a streamingJsonPath the SDK cannot read as
// one text value. Token text is read and rewritten with the SDK's reader, which
// splits the path on "." and resolves only member names and name[n]; the
// policy's own path parser also accepts forms such as ['key'], [*] and chained
// indexes. Accepting one of those would leave the two disagreeing about what the
// path reads, so text the off-path check counts as read would never be
// extracted or assessed. A wildcard is rejected too: the SDK returns a list for
// it, which is not text, so the path would read nothing.
func validateStreamingJSONPath(path string) error {
	segments := strings.Split(path, ".")
	if segments[0] == "$" {
		segments = segments[1:]
	}
	if len(segments) == 0 {
		return fmt.Errorf("invalid 'streamingJsonPath' %q: it must select a member", path)
	}
	for _, segment := range segments {
		if streamingPathKeySegment.MatchString(segment) || streamingPathIndexSegment.MatchString(segment) {
			continue
		}
		return fmt.Errorf("invalid 'streamingJsonPath' %q: unsupported segment %q; use dotted member names with at most one array index each and no wildcard, such as $.choices[0].delta.content", path, segment)
	}
	if _, err := parseJSONPath(path); err != nil {
		return fmt.Errorf("invalid 'streamingJsonPath': %w", err)
	}
	return nil
}

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

	// stateID makes this attachment's stream-state keys its own (see stateKey).
	stateID     string
	stateIDOnce sync.Once
}

// streamStateKey names one piece of per-stream state. It is a distinct type so
// it cannot be used as a metadata key directly: every read and write has to go
// through stateKey, which makes it specific to one attachment.
type streamStateKey string

// policyInstanceSeq numbers policy instances, so each attachment gets its own
// stream-state keys.
var policyInstanceSeq atomic.Uint64

// stateKey returns the metadata key for this attachment's copy of a piece of
// stream state.
//
// The metadata map is shared by every policy on the route, and two attachments of
// this policy on one route (two guardrails, say) see the same stream. With one
// fixed key per piece of state, the second attachment read and overwrote the
// first one's withheld bytes and pending text, and the client received the
// events out of order.
func (p *AWSBedrockGuardrailPolicy) stateKey(key streamStateKey) string {
	p.stateIDOnce.Do(func() {
		p.stateID = strconv.FormatUint(policyInstanceSeq.Add(1), 10)
	})
	return string(key) + "#" + p.stateID
}

type AWSBedrockGuardrailPolicyParams struct {
	Enabled               bool
	JsonPath              string
	FallbackJsonPaths     []string
	RedactPII             bool
	PassthroughOnError    bool
	ShowAssessment        bool
	ApplicableStatusCodes []statusCodeRange

	// StreamingJsonPath addresses the assistant text inside one SSE data frame.
	// Unused when Streaming is false.
	StreamingJsonPath string

	// StreamingTextUnitChars is how many characters of assistant text are
	// batched before each ApplyGuardrail call. Unused when Streaming is false.
	StreamingTextUnitChars int
}

// extractionPaths returns the JSONPaths to try, in order: jsonPath, then the
// fallback paths. An empty jsonPath validates the whole payload, so no path
// follows it.
func (params AWSBedrockGuardrailPolicyParams) extractionPaths() []string {
	if params.JsonPath == "" || len(params.FallbackJsonPaths) == 0 {
		return []string{params.JsonPath}
	}
	return append([]string{params.JsonPath}, params.FallbackJsonPaths...)
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
// An enabled response flow declares STREAM. That is not a decision to stream:
// the engine upgrades a route only when the upstream response is actually
// chunked or text/event-stream, and falls back to the buffered OnResponseBody
// for everything else. Declaring BUFFER instead is what made a streamed
// response fail, since the buffered check cannot read SSE.
func (p *AWSBedrockGuardrailPolicy) Mode() policy.ProcessingMode {
	requestBodyMode := policy.BodyModeSkip
	if p.hasRequestParams && p.requestParams.Enabled {
		requestBodyMode = policy.BodyModeBuffer
	}

	responseBodyMode := policy.BodyModeSkip
	if p.hasResponseParams && p.responseParams.Enabled {
		responseBodyMode = policy.BodyModeStream
	}

	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    requestBodyMode,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   responseBodyMode,
	}
}

// parseFallbackJSONPaths validates fallbackJsonPaths: an array of non-empty, valid JSONPaths.
func parseFallbackJSONPaths(raw interface{}) ([]string, error) {
	var entries []interface{}
	switch v := raw.(type) {
	case []interface{}:
		entries = v
	case []string:
		for _, s := range v {
			entries = append(entries, s)
		}
	default:
		return nil, fmt.Errorf("'fallbackJsonPaths' must be an array of strings")
	}

	fallbackPaths := make([]string, 0, len(entries))
	for _, entry := range entries {
		path, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("'fallbackJsonPaths' must be an array of strings")
		}
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("'fallbackJsonPaths' entries must not be empty")
		}
		if _, err := parseJSONPath(path); err != nil {
			return nil, fmt.Errorf("invalid 'fallbackJsonPaths' entry: %w", err)
		}
		fallbackPaths = append(fallbackPaths, path)
	}
	return fallbackPaths, nil
}

// parseRequestResponseParams parses and validates request/response parameters from map to struct
func parseRequestResponseParams(params map[string]interface{}, isResponse bool) (AWSBedrockGuardrailPolicyParams, error) {
	result := AWSBedrockGuardrailPolicyParams{
		JsonPath:               RequestDefaultJSONPath,
		Enabled:                RequestFlowEnabledByDefault,
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

	// Extract optional fallbackJsonPaths parameter. They are tried in order after jsonPath.
	if fallbackRaw, ok := params["fallbackJsonPaths"]; ok {
		fallbackPaths, err := parseFallbackJSONPaths(fallbackRaw)
		if err != nil {
			return result, err
		}
		result.FallbackJsonPaths = fallbackPaths
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
		for _, key := range []string{"streamingJsonPath", "streamingTextUnitChars"} {
			if _, ok := params[key]; ok {
				return result, fmt.Errorf("'%s' is only valid on the response flow", key)
			}
		}
		return result, nil
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
		if err := validateStreamingJSONPath(streamingJsonPath); err != nil {
			return result, err
		}
		result.StreamingJsonPath = streamingJsonPath
	}

	// Extract optional streamingTextUnitChars parameter
	if unitRaw, ok := params["streamingTextUnitChars"]; ok {
		unit, err := extractInt(unitRaw)
		if err != nil {
			return result, fmt.Errorf("'streamingTextUnitChars' must be a number: %w", err)
		}
		if unit != 0 && unit < MinStreamingTextUnitChars {
			return result, fmt.Errorf("'streamingTextUnitChars' must be 0 (assess the whole response) or at least %d",
				MinStreamingTextUnitChars)
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

// guardrailSource is the ApplyGuardrail source for a check: INPUT for a request and
// OUTPUT for a response, so the guardrail applies its input or output settings.
func guardrailSource(isResponse bool) types.GuardrailContentSource {
	if isResponse {
		return types.GuardrailContentSourceOutput
	}
	return types.GuardrailContentSourceInput
}

// applyBedrockGuardrail calls AWS Bedrock Guardrail ApplyGuardrail API
//
// Each text is sent as its own content block, so a payload with several values to
// check (every MCP tool argument, say) costs one call rather than one per value.
func (p *AWSBedrockGuardrailPolicy) applyBedrockGuardrail(ctx context.Context, awsCfg aws.Config, guardrailID, guardrailVersion string, source types.GuardrailContentSource, contents ...string) (*bedrockruntime.ApplyGuardrailOutput, error) {
	// Create Bedrock Runtime client
	newClient := p.newBedrockClientFunc
	if newClient == nil {
		newClient = func(cfg aws.Config) bedrockGuardrailClient {
			return bedrockruntime.NewFromConfig(cfg)
		}
	}
	client := newClient(awsCfg)

	blocks := make([]types.GuardrailContentBlock, 0, len(contents))
	for _, content := range contents {
		blocks = append(blocks, &types.GuardrailContentBlockMemberText{
			Value: types.GuardrailTextBlock{Text: aws.String(content)},
		})
	}

	// Prepare ApplyGuardrail input
	input := &bedrockruntime.ApplyGuardrailInput{
		GuardrailIdentifier: aws.String(guardrailID),
		GuardrailVersion:    aws.String(guardrailVersion),
		Source:              source,
		Content:             blocks,
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

	if outputTyped.Action == types.GuardrailActionGuardrailIntervened {
		// A BLOCKED finding anywhere in the assessment blocks, whatever else the
		// assessment also contains.
		//
		// This used to treat the mere presence of PII entities as "masking was
		// applied" and allow the content through. Two ways that let past content
		// AWS had said to block: a prompt attack accompanied by an email address
		// reported the content filter as BLOCKED and the email as ANONYMIZED, and
		// only the email was looked at; and a PII type configured to BLOCK —
		// AWS_ACCESS_KEY, say — was masked and delivered rather than blocked,
		// because its own Action was never read.
		if hasBlockedFinding(outputTyped) {
			return true, "", nil
		}

		// An ANONYMIZED finding that carries no matched text cannot be masked, so
		// delivering the content would deliver the very value AWS asked to hide.
		if hasUnmaskableFinding(outputTyped) {
			return true, "", nil
		}

		// Nothing is blocked, so anything reported is anonymisable.
		if hasAnonymizedFinding(outputTyped) {
			masked := applyPIIReplacements(originalContent,
				p.piiReplacements(outputTyped, redactPII, isRequest, metadata, originalContent))
			if masked == originalContent {
				return false, "", nil
			}
			return false, masked, nil
		}

		// Intervened, nothing BLOCKED, nothing ANONYMIZED: an intervention this
		// policy cannot account for. Block rather than guess.
		return true, "", nil
	}

	// Check for no intervention
	if outputTyped.Action == types.GuardrailActionNone {
		return false, "", nil // No violation, continue processing
	}

	// Unexpected response
	return true, "", fmt.Errorf("AWS Bedrock Guardrails returned unexpected response action: %s", string(outputTyped.Action))
}

// hasBlockedFinding reports whether any policy in the assessment blocked.
//
// Every policy type is checked, not only the sensitive-information one: a
// content filter, a denied topic, a word filter and a contextual-grounding
// filter each carry their own BLOCKED action, and any of them is a reason the
// content must not be delivered.
func hasBlockedFinding(output *bedrockruntime.ApplyGuardrailOutput) bool {
	for _, assessment := range output.Assessments {
		if cp := assessment.ContentPolicy; cp != nil {
			for _, f := range cp.Filters {
				if f.Action == types.GuardrailContentPolicyActionBlocked {
					return true
				}
			}
		}
		if tp := assessment.TopicPolicy; tp != nil {
			for _, t := range tp.Topics {
				if t.Action == types.GuardrailTopicPolicyActionBlocked {
					return true
				}
			}
		}
		if wp := assessment.WordPolicy; wp != nil {
			for _, w := range wp.CustomWords {
				if w.Action == types.GuardrailWordPolicyActionBlocked {
					return true
				}
			}
			for _, w := range wp.ManagedWordLists {
				if w.Action == types.GuardrailWordPolicyActionBlocked {
					return true
				}
			}
		}
		if cg := assessment.ContextualGroundingPolicy; cg != nil {
			for _, f := range cg.Filters {
				if f.Action == types.GuardrailContextualGroundingPolicyActionBlocked {
					return true
				}
			}
		}
		if sip := assessment.SensitiveInformationPolicy; sip != nil {
			for _, e := range sip.PiiEntities {
				if e.Action == types.GuardrailSensitiveInformationPolicyActionBlocked {
					return true
				}
			}
			for _, r := range sip.Regexes {
				if r.Action == types.GuardrailSensitiveInformationPolicyActionBlocked {
					return true
				}
			}
		}
	}
	return false
}

// hasAnonymizedFinding reports whether the assessment reported a value to mask
// or redact. Only ANONYMIZED counts: a finding with any other action is not
// something this policy can resolve by rewriting the text.
func hasAnonymizedFinding(output *bedrockruntime.ApplyGuardrailOutput) bool {
	for _, assessment := range output.Assessments {
		sip := assessment.SensitiveInformationPolicy
		if sip == nil {
			continue
		}
		for _, e := range sip.PiiEntities {
			if e.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized {
				return true
			}
		}
		for _, r := range sip.Regexes {
			if r.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized {
				return true
			}
		}
	}
	return false
}

// hasUnmaskableFinding reports whether an ANONYMIZED finding carries no matched
// text. The policy masks by replacing the reported value, so without one there is
// nothing to replace and the value would be delivered as it is.
func hasUnmaskableFinding(output *bedrockruntime.ApplyGuardrailOutput) bool {
	for _, assessment := range output.Assessments {
		sip := assessment.SensitiveInformationPolicy
		if sip == nil {
			continue
		}
		for _, e := range sip.PiiEntities {
			if e.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized && aws.ToString(e.Match) == "" {
				return true
			}
		}
		for _, r := range sip.Regexes {
			if r.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized && aws.ToString(r.Match) == "" {
				return true
			}
		}
	}
	return false
}

// piiReplacement replaces one value the guardrail reported.
type piiReplacement struct {
	match       string
	replacement string
}

// applyPIIReplacements applies the replacements to one piece of text in a single
// pass over the original, so text one replacement inserts (EMAIL_0000) is never
// matched by another (0000). Where two values start at the same position, the
// earlier replacement wins, which piiReplacements orders longest first.
func applyPIIReplacements(content string, replacements []piiReplacement) string {
	if len(replacements) == 0 {
		return content
	}
	pairs := make([]string, 0, 2*len(replacements))
	for _, r := range replacements {
		if r.match == "" {
			continue
		}
		pairs = append(pairs, r.match, r.replacement)
	}
	return strings.NewReplacer(pairs...).Replace(content)
}

// piiReplacements lists the values to replace in content that passed with
// ANONYMIZED findings, longest first so a value containing another is replaced
// whole:
//
//   - redactPII: every reported value becomes "*****".
//   - request: each ANONYMIZED value becomes a placeholder such as EMAIL_0000,
//     recorded in metadata so the response can restore it.
//   - response: each ANONYMIZED value becomes its type in braces, such as
//     {EMAIL}. That value came from the upstream (an LLM answer, an MCP tool
//     result), so there is nothing to restore it to. A value the request phase
//     masked and the response phase restored is left alone: the client sent it.
//
// partOfRequestValue reports whether a value the guardrail reported in a
// response is the client's own value, put back from a request placeholder, so it
// must not be masked again.
//
// An exact request value is. So is part of one -- Bedrock can draw a restored
// value's boundary differently in the response ("John" of "John Smith") -- but
// only when every occurrence of it in text sits inside a request value of the
// same type of entity -- one value or several ("Taylor" of both "Taylor Lee" and
// "Taylor Kim"). A match found anywhere else is new content (a different "John",
// or a PIN that happens to appear in an address) and is masked.
func partOfRequestValue(match, entityType, text string, restored map[string]string) bool {
	if _, exact := restored[match]; exact {
		return true
	}
	var originals []string
	for original, placeholder := range restored {
		if original != match && strings.Contains(original, match) && placeholderEntityType(placeholder) == entityType {
			originals = append(originals, original)
		}
	}
	return len(originals) > 0 && occursOnlyWithin(text, match, originals)
}

// placeholderEntityType returns the entity type a request placeholder was minted
// for: "NAME" for "NAME_0000".
func placeholderEntityType(placeholder string) string {
	if i := strings.LastIndex(placeholder, "_"); i > 0 {
		return placeholder[:i]
	}
	return ""
}

// occursOnlyWithin reports whether match occurs in text, and only inside
// occurrences of the originals.
func occursOnlyWithin(text, match string, originals []string) bool {
	if !strings.Contains(text, match) {
		return false
	}
	type span struct{ start, end int }
	var within []span
	for _, original := range originals {
		for from := 0; ; {
			i := strings.Index(text[from:], original)
			if i < 0 {
				break
			}
			within = append(within, span{from + i, from + i + len(original)})
			from += i + 1
		}
	}
	for from := 0; ; {
		i := strings.Index(text[from:], match)
		if i < 0 {
			return true
		}
		start, end := from+i, from+i+len(match)
		inside := false
		for _, w := range within {
			if start >= w.start && end <= w.end {
				inside = true
				break
			}
		}
		if !inside {
			return false
		}
		from = start + 1
	}
}

func (p *AWSBedrockGuardrailPolicy) piiReplacements(output *bedrockruntime.ApplyGuardrailOutput, redactPII, isRequest bool, metadata map[string]interface{}, text string) []piiReplacement {
	if output == nil {
		return nil
	}
	if redactPII {
		matches := redactionMatches(output)
		replacements := make([]piiReplacement, 0, len(matches))
		for _, m := range matches {
			replacements = append(replacements, piiReplacement{match: m, replacement: "*****"})
		}
		return replacements
	}

	restored, _ := metadata[MetadataKeyPIIEntities].(map[string]string)

	type found struct{ match, entityType string }
	seen := make(map[string]bool)
	var matches []found
	add := func(match, entityType string) {
		if match == "" || seen[match] {
			return
		}
		seen[match] = true
		matches = append(matches, found{match, entityType})
	}
	for _, assessment := range output.Assessments {
		sip := assessment.SensitiveInformationPolicy
		if sip == nil {
			continue
		}
		for _, e := range sip.PiiEntities {
			if e.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized {
				add(aws.ToString(e.Match), string(e.Type))
			}
		}
		for _, r := range sip.Regexes {
			if r.Action == types.GuardrailSensitiveInformationPolicyActionAnonymized {
				add(aws.ToString(r.Match), aws.ToString(r.Name))
			}
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return len(matches[i].match) > len(matches[j].match)
	})

	replacements := make([]piiReplacement, 0, len(matches))
	if isRequest {
		if restored == nil {
			restored = make(map[string]string)
		}
		// Continue the numbering of any earlier attachment on the same request, so
		// two attachments never hand out the same placeholder for different values.
		counter := len(restored)
		for _, m := range matches {
			placeholder, ok := restored[m.match]
			if !ok {
				placeholder = fmt.Sprintf("%s_%04x", m.entityType, counter)
				counter++
				restored[m.match] = placeholder
			}
			replacements = append(replacements, piiReplacement{match: m.match, replacement: placeholder})
		}
		if len(restored) > 0 && metadata != nil {
			metadata[MetadataKeyPIIEntities] = restored
		}
		return replacements
	}

	for _, m := range matches {
		if partOfRequestValue(m.match, m.entityType, text, restored) {
			continue
		}
		replacements = append(replacements, piiReplacement{match: m.match, replacement: "{" + m.entityType + "}"})
	}
	return replacements
}

// redactionMatches returns the values the guardrail reported, longest first.
//
// Shared by the redaction rewrite and the leak check that follows it: the same
// list that says what to replace is what says whether anything was missed.
func redactionMatches(output *bedrockruntime.ApplyGuardrailOutput) []string {
	if output == nil {
		return nil
	}

	// Every assessment, not just the first. Bedrock reports one per policy it
	// evaluated, and the sensitive-information findings can sit in any of them --
	// hasAnonymizedFinding and the redaction collection both walk them all, so a
	// value reported in a later assessment was redacted but then missing from the
	// list the leak check tests against.
	var matches []string
	for _, assessment := range output.Assessments {
		sip := assessment.SensitiveInformationPolicy
		if sip == nil {
			continue
		}
		for _, entity := range sip.PiiEntities {
			if match := aws.ToString(entity.Match); match != "" {
				matches = append(matches, match)
			}
		}
		for _, regex := range sip.Regexes {
			if match := aws.ToString(regex.Match); match != "" {
				matches = append(matches, match)
			}
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
// A model emits a value over several token events -- "support" in one,
// "@acme" in the next, ".com" in a third -- so the values are found in the
// flush's text read as a whole, and each one is written back across the frames
// that carry it (rewriteAcrossFrames). Rewriting one frame at a time found the
// value in no frame, and the stream was ended instead of masked.
//
// The check is the safety net: the rewritten flush is re-read as a whole and
// tested against the same match list. A survivor means this flush cannot be
// delivered redacted, and the caller fails closed rather than forward the value
// — the one thing redaction mode exists to prevent.
func (p *AWSBedrockGuardrailPolicy) redactedFlush(
	flush string,
	output interface{},
	rp AWSBedrockGuardrailPolicyParams,
	metadata map[string]interface{},
) (rewritten string, changed, leaked bool) {
	rewrites := p.responseRewrites(output, rp, metadata, extractSSEDeltaContent(flush, rp.StreamingJsonPath))
	if len(rewrites) == 0 {
		return flush, false, false
	}

	rewritten, changed = rewriteAcrossFrames(flush, rp.StreamingJsonPath, rewrites)

	joined := extractSSEDeltaContent(rewritten, rp.StreamingJsonPath)
	for _, r := range rewrites {
		if strings.Contains(joined, r.match) {
			return rewritten, changed, true
		}
	}
	return rewritten, changed, false
}

// responseRewrites is what a response assessment asks to be replaced before the
// text reaches the client: every reported value under redactPII, otherwise each
// ANONYMIZED value the upstream introduced (see piiReplacements). Nothing when the
// assessment passed clean.
func (p *AWSBedrockGuardrailPolicy) responseRewrites(
	output interface{},
	rp AWSBedrockGuardrailPolicyParams,
	metadata map[string]interface{},
	text string,
) []piiReplacement {
	typed, ok := output.(*bedrockruntime.ApplyGuardrailOutput)
	if !ok || typed == nil || typed.Action != types.GuardrailActionGuardrailIntervened {
		return nil
	}
	if !rp.RedactPII && !hasAnonymizedFinding(typed) {
		return nil
	}
	return p.piiReplacements(typed, rp.RedactPII, false, metadata, text)
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

// restorePayload puts the request's placeholders back into a whole response body.
//
// The placeholder bytes are replaced in place, so the body keeps its layout, key
// order and escaping exactly as the upstream wrote them -- including a
// placeholder the upstream used as an object key. Inside JSON (a JSON document,
// or the data of an event-stream event that is JSON) the original value is
// written JSON-escaped, so a value containing a quote, a backslash or a newline
// leaves the document valid. Any other body gets the value as it is.
func (p *AWSBedrockGuardrailPolicy) restorePayload(payload []byte, maskedPIIEntities map[string]string) ([]byte, bool) {
	if len(maskedPIIEntities) == 0 || !containsPlaceholder(string(payload), maskedPIIEntities) {
		return payload, false
	}
	plain := func(s string) string { return p.restorePIIInResponse(s, maskedPIIEntities) }
	escaped := func(s string) string { return p.restorePIIInResponse(s, jsonEscapedOriginals(maskedPIIEntities)) }

	var restored string
	switch {
	case json.Valid(payload):
		restored = escaped(string(payload))
	case looksLikeEventStream(payload):
		lines := strings.Split(string(payload), "\n")
		for i, line := range lines {
			if data, _, isData := sseDataPayload(strings.TrimSuffix(line, "\r")); isData && json.Valid([]byte(data)) {
				lines[i] = escaped(line)
			} else {
				lines[i] = plain(line)
			}
		}
		restored = strings.Join(lines, "\n")
	default:
		restored = plain(string(payload))
	}
	return []byte(restored), restored != string(payload)
}

// containsPlaceholder reports whether s contains any of the request's
// placeholders, so a body with none is left byte-for-byte as it is.
func containsPlaceholder(s string, maskedPIIEntities map[string]string) bool {
	for _, placeholder := range maskedPIIEntities {
		if placeholder != "" && strings.Contains(s, placeholder) {
			return true
		}
	}
	return false
}

// jsonEscapedOriginals returns the request's original-to-placeholder mapping with
// each original value escaped for use inside a JSON string.
func jsonEscapedOriginals(maskedPIIEntities map[string]string) map[string]string {
	escaped := make(map[string]string, len(maskedPIIEntities))
	for original, placeholder := range maskedPIIEntities {
		encoded, err := encodeJSON(original)
		if err != nil || len(encoded) < 2 {
			escaped[original] = placeholder
			continue
		}
		escaped[string(encoded[1:len(encoded)-1])] = placeholder
	}
	return escaped
}

// buildGuardrailErrorResponse describes the intervention for the gateway: the code and
// class that decide its analytics category, which side was refused, and the guardrail
// envelope this policy already publishes in its response body.
//
// Direction is per phase, not per policy: a request-side hit and a response-side hit are
// operationally different events that share a status code, and only this policy knows
// which it made.
func (p *AWSBedrockGuardrailPolicy) buildGuardrailErrorResponse(reason string, validationError error, isResponse, showAssessment bool, output interface{}) *policy.FaultDetails {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, output)

	direction := policy.DirectionRequest
	if isResponse {
		direction = policy.DirectionResponse
	}

	actionReason, _ := assessment["actionReason"].(string)

	guardrail := &policy.GuardrailDetails{
		InterveningGuardrail: guardrailName,
		Action:               policy.GuardrailActionIntervened,
		ActionReason:         actionReason,
	}
	// Assessments carries the content the guardrail existed to stop, so it is populated
	// only where the operator already opted in through showAssessment — the same gate the
	// published response envelope uses.
	if raw, ok := assessment["assessments"]; ok {
		guardrail.Assessments = map[string]any{"assessments": raw}
	}

	return &policy.FaultDetails{
		Code:      guardrailCodeFor(output),
		Type:      policy.FaultTypeGuardrail,
		Direction: direction,
		Message:   "AWS Bedrock guardrail intervened",
		// reason is the detail of what was blocked. Description is withheld from the
		// response body by every renderer and reaches fault policies only, which is why
		// the detail belongs here rather than in Message.
		Description: reason,
		Guardrail:   guardrail,
	}
}

// extractionFault describes a rejection made because the value at jsonPath could not be
// read, so no check ran and there is no guardrail verdict to report. On a request the
// payload is the caller's, so it is an invalid request body; on a response it is the
// upstream's, and the policy could not do its job.
func extractionFault(reason string, err error, isResponse bool) *policy.FaultDetails {
	if isResponse {
		return &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionResponse,
			Message:     "The response body could not be read for the guardrail check",
			Description: reason + ": " + err.Error(),
		}
	}
	return &policy.FaultDetails{
		Code:        policy.FaultCodeInvalidRequestBody,
		Type:        policy.FaultTypeValidation,
		Direction:   policy.DirectionRequest,
		Message:     "The request body could not be read for the guardrail check",
		Description: reason + ": " + err.Error(),
	}
}

// checkFailureFault describes a rejection made because the policy could not run its check
// at all, so there is no guardrail verdict to report: the policy failed its own job.
// Description carries the reason only: the service's error text can name the account's
// resources, so it stays in the debug log.
func checkFailureFault(reason string, isResponse bool) *policy.FaultDetails {
	direction := policy.DirectionRequest
	if isResponse {
		direction = policy.DirectionResponse
	}
	return &policy.FaultDetails{
		Code:        policy.FaultCodeMediationFailed,
		Type:        policy.FaultTypeMediation,
		Direction:   direction,
		Message:     "The guardrail check could not be completed",
		Description: reason,
	}
}

// withFault replaces the fault an error response declares, leaving its status, headers
// and body exactly as they are.
func withFault(action interface{}, fault *policy.FaultDetails) interface{} {
	switch a := action.(type) {
	case policy.ImmediateResponse:
		a.Fault = fault
		return a
	case policy.DownstreamResponseModifications:
		a.Fault = fault
		return a
	}
	return action
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
	return p.validatePayloadAs(content, p.responseParams, true, respCtx.Metadata,
		responseMediaType(respCtx.ResponseHeaders)).(policy.ResponseAction)
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
// SSE". Anything else that reaches OnResponseBodyChunk as a non-SSE body (plain
// text, or an opaque framing with no transformer ahead of it in the chain) is
// withheld there by handleNonSSEStreamFlush until end of stream.
func (p *AWSBedrockGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return false
	}
	if looksLikeJSONDocument(accumulated) {
		return true
	}
	if len(accumulated) < streamFlushPacerBytes {
		return true
	}
	if looksLikeEventStream(accumulated) {
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
	if !p.hasResponseParams || !p.responseParams.Enabled {
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
	//
	// The Content-Type and the first flush with content decide (see
	// isEventStreamResponse). A flush with nothing but whitespace is not evidence
	// either way, so it is not recorded.
	//
	// An unlabelled stream whose opening flushes carry only SSE fields other than
	// "data:" (a keep-alive, say) is not decided yet: those flushes are withheld
	// and handed, with the flush that decides, to the reader it selects. Deciding
	// on them alone would read a token stream as one body, held until the end of
	// the stream and refused past maxNonSSEHeldBytes.
	sseStream, classified := respCtx.Metadata[p.stateKey(metaKeySSEStream)].(bool)
	prepended := false
	if !classified {
		mediaType := responseMediaType(respCtx.ResponseHeaders)
		if wait, ok := respCtx.Metadata[p.stateKey(metaKeyClassifyWait)].(string); ok {
			delete(respCtx.Metadata, p.stateKey(metaKeyClassifyWait))
			chunkStr = wait + chunkStr
			prepended = true
		}
		body := []byte(chunkStr)
		sseStream = isEventStreamResponse(mediaType, body)
		if !sseStream && !chunk.EndOfStream && sniffedMediaType(mediaType) &&
			looksLikeEventStream(body) && len(chunkStr) <= maxHeldFlushBytes {
			respCtx.Metadata[p.stateKey(metaKeyClassifyWait)] = chunkStr
			return policy.ForwardResponseChunk{Body: []byte{}}
		}
		if strings.TrimSpace(chunkStr) != "" {
			respCtx.Metadata[p.stateKey(metaKeySSEStream)] = sseStream
		}
	}
	if prepended {
		// A reader that forwards "unchanged" means the bytes it was given, which
		// include the withheld opening flushes, not this flush alone.
		action := p.dispatchResponseChunk(chunkStr, sseStream, chunk, respCtx)
		if forward, ok := action.(policy.ForwardResponseChunk); ok && forward.Body == nil {
			forward.Body = []byte(chunkStr)
			return forward
		}
		return action
	}
	return p.dispatchResponseChunk(chunkStr, sseStream, chunk, respCtx)
}

// dispatchResponseChunk hands a flush to the reader for the stream's format.
func (p *AWSBedrockGuardrailPolicy) dispatchResponseChunk(chunkStr string, sseStream bool, chunk *policy.StreamBody, respCtx *policy.ResponseStreamContext) policy.StreamingResponseAction {

	// An empty jsonPath assesses the whole payload as text, an event stream
	// included, so the body is withheld and assessed whole as any other
	// non-event-stream body is; reading it as events would apply
	// streamingJsonPath to a configuration that asked for the whole body.
	if sseStream && p.responseParams.JsonPath != "" {
		if p.isJSONRPCStream(chunkStr, respCtx) {
			return p.handleJSONRPCStreamFlush(chunkStr, chunk, respCtx)
		}
		return p.handleSSEStreamFlush(chunkStr, chunk, respCtx, p.responseParams)
	}
	return p.handleNonSSEStreamFlush(chunkStr, chunk, respCtx)
}

// isJSONRPCStream reports whether this event stream carries JSON-RPC messages (an
// MCP Streamable HTTP or A2A response) rather than LLM token deltas, and
// remembers the answer once it is known.
//
// Its events are read with jsonPath, as the buffered path reads them;
// streamingJsonPath addresses a token delta, which such a stream does not carry.
func (p *AWSBedrockGuardrailPolicy) isJSONRPCStream(chunkStr string, respCtx *policy.ResponseStreamContext) bool {
	if isRPC, known := respCtx.Metadata[p.stateKey(metaKeyJSONRPCStream)].(bool); known {
		return isRPC
	}
	// The first JSON-RPC message may arrive over several flushes, so the bytes the
	// token path is withholding are looked at too: those it has read and holds
	// until assessed, then those checkStreamingPath holds unread, in that order.
	held, _ := respCtx.Metadata[p.stateKey(metaKeyHeldBytes)].(string)
	waiting, _ := respCtx.Metadata[p.stateKey(metaKeyStreamingPathWait)].(string)
	withheld := held + waiting
	buffered := withheld + chunkStr
	if extractSSEDeltaContent(buffered, p.responseParams.StreamingJsonPath) != "" {
		// Token deltas: this is an LLM stream, and its text is read with
		// streamingJsonPath as before -- even if a JSON-RPC message appears beside
		// it. Reading such a stream with jsonPath would leave the deltas unassessed.
		respCtx.Metadata[p.stateKey(metaKeyJSONRPCStream)] = false
		return false
	}
	if !sseCarriesJSONRPC([]byte(buffered)) {
		return false
	}
	respCtx.Metadata[p.stateKey(metaKeyJSONRPCStream)] = true
	// Hand over whatever the token path was withholding, so no byte is lost or
	// delivered twice.
	respCtx.Metadata[p.stateKey(metaKeyJSONRPCBuffer)] = withheld
	respCtx.Metadata[p.stateKey(metaKeyHeldBytes)] = ""
	delete(respCtx.Metadata, p.stateKey(metaKeyStreamingPathWait))
	respCtx.Metadata[p.stateKey(metaKeyPendingText)] = ""
	respCtx.Metadata[p.stateKey(metaKeyAssessedInHeld)] = 0
	delete(respCtx.Metadata, p.stateKey(metaKeyPartialLine))
	return true
}

// handleJSONRPCStreamFlush assesses a JSON-RPC event stream one complete event
// at a time, with the same extraction the buffered path uses (jsonPath against
// each event's data). Bytes of an event still arriving are withheld until it
// completes, so nothing is delivered before its message has been assessed.
func (p *AWSBedrockGuardrailPolicy) handleJSONRPCStreamFlush(
	chunkStr string,
	chunk *policy.StreamBody,
	respCtx *policy.ResponseStreamContext,
) policy.StreamingResponseAction {
	rp := p.responseParams
	previous, _ := respCtx.Metadata[p.stateKey(metaKeyJSONRPCBuffer)].(string)
	buffered := previous + chunkStr

	complete, rest := buffered, ""
	if !chunk.EndOfStream {
		complete, rest = splitAtLastEventEnd(buffered)
	}
	if len(rest) > maxHeldFlushBytes {
		// One message larger than the withheld-bytes limit: it cannot be held to
		// completion, and releasing it would deliver it unassessed.
		delete(respCtx.Metadata, p.stateKey(metaKeyJSONRPCBuffer))
		if !rp.PassthroughOnError {
			return p.unassessableEnd(true)
		}
		slog.Debug("AWSBedrockGuardrail: JSON-RPC event exceeded the withheld-bytes limit, passthrough enabled",
			"held_bytes", len(rest))
		// Only the oversized event passes unassessed. The complete events before
		// it in this flush are assessed as usual, and their verdict stands.
		if strings.TrimSpace(complete) == "" {
			return policy.ForwardResponseChunk{Body: []byte(buffered)}
		}
		action := p.assessJSONRPCEvents(complete, respCtx)
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			return action
		}
		return policy.ForwardResponseChunk{Body: append(forward.Body, rest...)}
	}
	respCtx.Metadata[p.stateKey(metaKeyJSONRPCBuffer)] = rest
	return p.assessJSONRPCEvents(complete, respCtx)
}

// assessJSONRPCEvents assesses the complete events of a JSON-RPC event stream
// flush. A forward it returns always carries a non-nil body: the events as they
// are to be delivered, or nothing while none is complete.
func (p *AWSBedrockGuardrailPolicy) assessJSONRPCEvents(complete string, respCtx *policy.ResponseStreamContext) policy.StreamingResponseAction {
	rp := p.responseParams
	if strings.TrimSpace(complete) == "" {
		// Nothing complete yet: withhold (a non-nil empty body delivers nothing).
		return policy.ForwardResponseChunk{Body: []byte(complete)}
	}
	if !rp.PassthroughOnError && extractSSEDeltaContent(complete, rp.StreamingJsonPath) != "" {
		// Token deltas after the stream was read as JSON-RPC: jsonPath does not
		// address them, so they would be delivered unassessed.
		slog.Warn("AWSBedrockGuardrail: JSON-RPC event stream also carries token deltas; they cannot be assessed")
		return p.unassessableEnd(true)
	}
	if !sseHasJSONEvent(complete) {
		// Keep-alives, comments or a "[DONE]" marker: no message to assess. A line
		// that cannot be read at all is still refused; an event the stream never
		// finished is not, since an SSE client discards it.
		if !rp.PassthroughOnError && unreadableEventStream(complete) {
			return p.unassessableEnd(true)
		}
		return policy.ForwardResponseChunk{Body: []byte(complete)}
	}

	result := p.validatePayloadAs([]byte(complete), rp, true, respCtx.Metadata, jsonRPCEventStream)
	modifications, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		return policy.ForwardResponseChunk{Body: []byte(complete)}
	}
	if modifications.StatusCode != nil {
		// The status already went downstream with the headers, so the verdict the
		// buffered path answers with a 422 ends the stream as its last event.
		return policy.TerminateResponseChunk{
			Body:              []byte(sseDataPrefix + string(modifications.Body) + "\n\n"),
			AnalyticsMetadata: modifications.AnalyticsMetadata,
			IsFault:           true,
			Fault:             modifications.Fault,
		}
	}
	if modifications.Body != nil {
		return policy.ForwardResponseChunk{Body: modifications.Body}
	}
	return policy.ForwardResponseChunk{Body: []byte(complete)}
}

// splitAtLastEventEnd divides s after its last complete event (the blank line
// that ends it), returning the complete events and the event still arriving.
func splitAtLastEventEnd(s string) (complete, rest string) {
	end := lastEventEnd(s)
	if end < 0 {
		return "", s
	}
	return s[:end], s[end:]
}

// lastEventEnd returns the offset just after the last blank line in s -- a line
// terminator directly after another -- or -1 when there is none. Terminators are
// CRLF, LF or CR, in any mix, as the SSE specification allows and the JSON-RPC
// reader accepts. A CR that is the last byte of s may be the first half of a
// CRLF still arriving: right after text it does not end the line yet, but right
// after another terminator it completes a blank line either way (an LF that
// follows only finishes that CRLF, and reads as one more blank line).
func lastEventEnd(s string) int {
	end := -1
	afterTerminator := false
	for i := 0; i < len(s); {
		width := 0
		switch {
		case s[i] == '\r' && i+1 == len(s):
			if afterTerminator {
				return len(s)
			}
			return end
		case s[i] == '\r' && s[i+1] == '\n':
			width = 2
		case s[i] == '\r' || s[i] == '\n':
			width = 1
		}
		if width == 0 {
			afterTerminator = false
			i++
			continue
		}
		i += width
		if afterTerminator {
			end = i
		}
		afterTerminator = true
	}
	return end
}

// sseHasJSONEvent reports whether any event of an SSE body carries JSON data.
func sseHasJSONEvent(s string) bool {
	for _, event := range splitEvents([]byte(s)) {
		data, ok := eventData(event.lines)
		if !ok {
			continue
		}
		if _, err := decodeJSON([]byte(data)); err == nil {
			return true
		}
	}
	return false
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
	if forwarded, _ := respCtx.Metadata[p.stateKey(metaKeyNonSSEForwarded)].(bool); forwarded {
		// passthroughOnError released this body unassessed when it outgrew the
		// limit; the rest of it passes the same way, and nothing more is kept.
		return p.forwardRestored(chunkStr, respCtx)
	}
	// The flushes are kept as a list and joined once, rather than re-copying the
	// whole body on every flush.
	parts, _ := respCtx.Metadata[p.stateKey(metaKeyAccStreamedJSONBody)].([]interface{})
	size, _ := respCtx.Metadata[p.stateKey(metaKeyAccStreamedLen)].(int)
	parts = append(parts, chunkStr)
	size += len(chunkStr)
	respCtx.Metadata[p.stateKey(metaKeyAccStreamedJSONBody)] = parts
	respCtx.Metadata[p.stateKey(metaKeyAccStreamedLen)] = size

	if !chunk.EndOfStream {
		// The kernel force-flushed at its accumulator ceiling, or the body is
		// plain text, which it does not hold whole. Either way it is withheld here
		// and assessed whole at end of stream, as a buffered response is, so none
		// of it is delivered before it has been assessed and restored.
		if size <= maxNonSSEHeldBytes {
			return policy.ForwardResponseChunk{Body: []byte{}}
		}
		if !p.responseParams.PassthroughOnError {
			slog.Warn("AWSBedrockGuardrail: response too large to withhold until assessed; ending the stream",
				"accumulated_bytes", size, "limit", maxNonSSEHeldBytes)
			p.dropAccumulated(respCtx)
			return p.unassessableEnd(p.classifiedAsEventStream(respCtx))
		}
		slog.Warn("AWSBedrockGuardrail: response too large to withhold until assessed, passthrough enabled; releasing it unassessed",
			"accumulated_bytes", size, "limit", maxNonSSEHeldBytes)
		respCtx.Metadata[p.stateKey(metaKeyNonSSEForwarded)] = true
		p.dropAccumulated(respCtx)
		released := p.forwardRestored(joinParts(parts, size), respCtx)
		if released.Body == nil {
			released.Body = []byte(joinParts(parts, size))
		}
		return released
	}
	p.dropAccumulated(respCtx)
	full := joinParts(parts, size)

	// Nothing has been delivered yet: whatever is returned now replaces the whole
	// response.
	deliverAll := policy.ForwardResponseChunk{Body: []byte(full)}

	// An empty body has nothing to assess, and handing it to validatePayload
	// would fail JSONPath extraction and reject a response that carries no
	// content at all.
	if strings.TrimSpace(full) == "" {
		return deliverAll
	}

	result := p.validatePayloadAs([]byte(full), p.responseParams, true, respCtx.Metadata,
		responseMediaType(respCtx.ResponseHeaders))
	modifications, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		return deliverAll
	}
	if modifications.StatusCode != nil {
		// The buffered path answers a violation with a status; this one cannot,
		// because the status went downstream with the headers. The body it built
		// is still the right thing to deliver as the stream's last event -- framed
		// as an SSE event when the response is an event stream assessed whole (an
		// empty jsonPath), or an SSE client would discard it and see a clean end.
		body := modifications.Body
		if p.classifiedAsEventStream(respCtx) {
			body = []byte(sseDataPrefix + string(body) + "\n\n")
		}
		return policy.TerminateResponseChunk{
			Body:              body,
			AnalyticsMetadata: modifications.AnalyticsMetadata,
			// The status that would have carried this verdict went downstream with
			// the headers, so IsFault is the only thing left marking the stream as
			// having ended in a failure rather than a clean close. validatePayload
			// already built the fault for the buffered action it returned; carry
			// that one rather than rebuild it, so both paths report identically.
			IsFault: true,
			Fault:   modifications.Fault,
		}
	}
	if modifications.Body != nil {
		return policy.ForwardResponseChunk{Body: modifications.Body}
	}
	return deliverAll
}

// classifiedAsEventStream reports whether OnResponseBodyChunk classified this
// response as Server-Sent Events.
func (p *AWSBedrockGuardrailPolicy) classifiedAsEventStream(respCtx *policy.ResponseStreamContext) bool {
	sse, _ := respCtx.Metadata[p.stateKey(metaKeySSEStream)].(bool)
	return sse
}

// assessStreamBatch runs one ApplyGuardrail call for a batch. stop is true when
// the returned action must be delivered immediately — a violation, or a failure
// that passthroughOnError does not excuse.
func (p *AWSBedrockGuardrailPolicy) assessStreamBatch(
	cleaned string,
	_ string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) (action policy.StreamingResponseAction, output interface{}, modified string, stop bool) {
	output, err := p.applyGuardrailToText(cleaned)
	if err != nil {
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: streaming guardrail call failed, passthrough enabled",
				"error", err, "chunkIndex", chunk.Index)
			// The caller releases the bytes, with every decision that still applies
			// to them; releasing here would consume decisions carried for withheld
			// frames, and they would then be missing from that release.
			return policy.ForwardResponseChunk{}, nil, "", true
		}
		slog.Debug("AWSBedrockGuardrail: streaming guardrail call failed",
			"error", err, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Error calling AWS Bedrock Guardrail", err, rp.ShowAssessment, nil),
			AnalyticsMetadata: guardrailHitAnalytics(),
			IsFault:           true,
			// The policy failed its own job, so there is no guardrail verdict to
			// report — the same distinction the buffered path draws.
			Fault: checkFailureFault("Error calling AWS Bedrock Guardrail", true),
		}, nil, "", true
	}

	violation, modifiedContent, err := p.evaluateGuardrailResponse(output, cleaned, rp.RedactPII, false, respCtx.Metadata)
	if err != nil {
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: streaming guardrail evaluation failed, passthrough enabled",
				"error", err, "chunkIndex", chunk.Index)
			// The caller releases the bytes, with every decision that still applies
			// to them; releasing here would consume decisions carried for withheld
			// frames, and they would then be missing from that release.
			return policy.ForwardResponseChunk{}, nil, "", true
		}
		slog.Debug("AWSBedrockGuardrail: streaming guardrail evaluation failed",
			"error", err, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Error evaluating guardrail response", err, rp.ShowAssessment, output),
			AnalyticsMetadata: guardrailHitAnalytics(),
			IsFault:           true,
			Fault:             checkFailureFault("Error evaluating guardrail response", true),
		}, nil, "", true
	}

	if violation {
		slog.Debug("AWSBedrockGuardrail: streaming violation detected",
			"chunkIndex", chunk.Index, "batchChars", len([]rune(cleaned)))
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Violation of AWS Bedrock Guardrails detected", nil, rp.ShowAssessment, output),
			AnalyticsMetadata: guardrailHitAnalytics(),
			IsFault:           true,
			// A real guardrail verdict, so it carries the code derived from what
			// Bedrock reported — the mid-stream equivalent of the buffered 422.
			Fault: p.buildGuardrailErrorResponse("Violation of AWS Bedrock Guardrails detected",
				nil, true, rp.ShowAssessment, output),
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
	// Put masked values back before anything reads this flush, so the text
	// assessed below is the text the client will receive. validatePayload does
	// the same on the buffered path, restoring the payload before extracting
	// from it. Restoring at delivery instead left the guardrail assessing
	// "EMAIL_0000" while the client got the address back.
	//
	// It has to happen here rather than later because the boundary accounting
	// counts characters: a placeholder and the value it stands for are different
	// lengths, so assessing one and splitting the frames on the other puts the
	// release point in the wrong place.
	chunkStr = p.restoreFlushFrames(chunkStr, respCtx, rp)

	chunkStr, pathDecision := p.checkStreamingPath(chunkStr, chunk.EndOfStream, respCtx, rp)
	switch pathDecision {
	case streamingPathRefuse:
		return p.unassessableEnd(true)
	case streamingPathWait:
		return policy.ForwardResponseChunk{Body: []byte{}}
	}
	pending, _ := respCtx.Metadata[p.stateKey(metaKeyPendingText)].(string)
	held, _ := respCtx.Metadata[p.stateKey(metaKeyHeldBytes)].(string)
	newText, unassessable := p.flushText(chunkStr, chunk.EndOfStream, respCtx, rp)
	if unassessable {
		// A single data line too large to retain: its text can never be read, so
		// delivering its bytes would release content no assessment has seen.
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: unassessable line, passthrough enabled", "chunkIndex", chunk.Index)
			// Everything withheld is being delivered now, so the state it came
			// from has to go with it: a later flush reading a stale metaKeyHeldBytes
			// would send the same events a second time, and a stale pending text or
			// assessed-character count would put the next boundary walk in the
			// wrong place. flushText has already dropped the line's own fragment.
			//
			// The text that can be read -- the events withheld so far and the
			// complete events of this flush -- is still assessed before anything is
			// released, as passthroughOnError promises: only the oversized line goes
			// out unread. assessAndRelease resets that state and releases the
			// oversized fragment with the batch.
			return p.assessAndRelease(pending+newText, held+chunkStr, respCtx, rp, chunk)
		}
		return p.unassessableEnd(true)
	}
	unit := p.effectiveTextUnit()

	// Assess and release everything once the stream ends; there is no later
	// batch to carry into, and nothing may be left undelivered.
	if chunk.EndOfStream {
		return p.assessAndRelease(pending+newText, held+chunkStr, respCtx, rp, chunk)
	}

	// The withheld buffer has grown as far as it may. Reached by a stream whose
	// events carry little or no assessable text, which never trips the character
	// boundary below.
	combinedText := pending + newText
	combinedHeld := held + chunkStr

	if len(combinedHeld) > maxHeldFlushBytes {
		slog.Warn("AWSBedrockGuardrail: withheld response bytes reached the limit; assessing and releasing early",
			"held_bytes", len(held), "limit", maxHeldFlushBytes, "pending_chars", len([]rune(pending)))
		// The release is still trimmed to a word boundary, as a unit batch is: a
		// value cut by the release would be assessed in two halves, neither of
		// which matches. Events carrying logprobs reach this limit after about a
		// thousand characters of text, so the cut is not a rare edge. Only the
		// frames carrying the trailing word stay withheld; when there is no
		// boundary to cut at, or the frames after it are too large to keep,
		// everything is released as before.
		if batch, carry := splitAtWordBoundary(combinedText); batch != "" {
			assessedInHeld, _ := respCtx.Metadata[p.stateKey(metaKeyAssessedInHeld)].(int)
			boundary := assessedInHeld + len([]rune(batch))
			if release, retain, covered := splitHeldAtTextBoundary(combinedHeld, rp.StreamingJsonPath, boundary); release != "" && len(retain) <= maxCapRetainBytes {
				return p.releaseBatch(batch, carry, release, retain, boundary-covered, respCtx, rp, chunk)
			}
		}
		return p.assessAndRelease(combinedText, combinedHeld, respCtx, rp, chunk)
	}

	// Past a text unit: trim the batch back to the end of a sentence, or failing
	// that a word, exactly as the immediate-delivery path does — a phrase assessed
	// as two halves can pass where the whole would not.
	//
	// The trim point generally falls inside a frame, so the bytes released are
	// the frames whose text is wholly inside the batch and the straddling frame
	// is retained. Withholding assessed text is harmless; releasing unassessed
	// text is not.
	if batch, carry := splitAtTextUnit(combinedText, unit, false); batch != "" {
		// Assessed characters already sitting in withheld frames count toward the
		// boundary: they are not in the batch, but the frames carrying them are
		// in held, so the walk has to account for them to reach the same point.
		assessedInHeld, _ := respCtx.Metadata[p.stateKey(metaKeyAssessedInHeld)].(int)
		boundary := assessedInHeld + len([]rune(batch))

		release, retain, covered := splitHeldAtTextBoundary(combinedHeld, rp.StreamingJsonPath, boundary)
		return p.releaseBatch(batch, carry, release, retain, boundary-covered, respCtx, rp, chunk)
	}

	respCtx.Metadata[p.stateKey(metaKeyPendingText)] = combinedText
	respCtx.Metadata[p.stateKey(metaKeyHeldBytes)] = combinedHeld
	// Withhold: a non-nil empty body replaces the chunk, so nothing is delivered
	// for this flush. A nil body would pass the bytes straight through.
	return policy.ForwardResponseChunk{Body: []byte{}}
}

// releaseBatch assesses batch, releases the frames that carry it, and records
// the text and bytes that stay withheld for the next flush.
func (p *AWSBedrockGuardrailPolicy) releaseBatch(
	batch, carry, release, retain string,
	assessedInRetained int,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) policy.StreamingResponseAction {
	action := p.assessBatchAndRelease(batch, release, retain, assessedInRetained, respCtx, rp, chunk)
	if action.TerminateStream() {
		return action
	}
	respCtx.Metadata[p.stateKey(metaKeyPendingText)] = carry
	respCtx.Metadata[p.stateKey(metaKeyHeldBytes)] = retain
	respCtx.Metadata[p.stateKey(metaKeyAssessedInHeld)] = assessedInRetained
	return action
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
	// A trailing incomplete line's text is not in batchText — flushText could not
	// read it — so its bytes must not be released here either. Mid-stream it
	// stays withheld for the flush that completes it; at end of stream there is
	// no such flush, and flushText has already joined it into the final text.
	release := heldBytes
	retain := ""
	if !chunk.EndOfStream {
		release, retain = splitTrailingPartialLine(heldBytes)
		// flushText stops retaining a fragment past maxPartialLineBytes and reads
		// its text into the batch instead, so beyond that limit these bytes have
		// been assessed and withholding them protects nothing. It also defeats the
		// cap this function was called to enforce: a stream carrying no line
		// terminator has no complete lines to release, so the whole buffer would be
		// retained and grow again by every later flush. Bounding retention at the
		// same limit flushText uses keeps the two in agreement.
		if len(retain) > maxPartialLineBytes {
			slog.Warn("AWSBedrockGuardrail: incomplete line exceeded the retention limit; releasing it with the batch",
				"retained_bytes", len(retain), "limit", maxPartialLineBytes)
			release, retain = heldBytes, ""
		}
	}

	respCtx.Metadata[p.stateKey(metaKeyPendingText)] = ""
	respCtx.Metadata[p.stateKey(metaKeyHeldBytes)] = retain
	respCtx.Metadata[p.stateKey(metaKeyAssessedInHeld)] = 0

	// The configured batch decides when to assess and deliver; it does not decide
	// how much goes into one request. Every call carries at most one text unit,
	// which is the size AWS recommends and which costs exactly the same as
	// sending the batch whole — input is billed per text unit either way, so
	// splitting is free. Letting the batch size through instead sent one
	// oversized request: measured at 55,199 characters for a very large
	// configured batch, because the withheld-bytes limit bounds the buffer and
	// not the request. That is the long-context case AWS's guidance says to
	// chunk.
	stopAction, decisions, lastOutput, lastModified, assessed := p.assessTextInUnits(
		batchText, release, respCtx, rp, chunk)
	if stopAction != nil {
		if stopAction.TerminateStream() {
			slog.Debug("AWSBedrockGuardrail: batch failed before delivery, held bytes discarded",
				"held_bytes", len(release), "chunkIndex", chunk.Index)
			return stopAction
		}
		// passthroughOnError: this batch was not assessed, but withholding the
		// bytes indefinitely would stall the stream, so they are released.
		return p.releaseBytes(release, nil, "", respCtx, rp)
	}
	if !assessed {
		// Framing only -- nothing to assess, but the bytes are still owed to the
		// client.
		return p.releaseBytes(release, nil, "", respCtx, rp)
	}

	return p.releaseWithDecisions(release, decisions, lastOutput, lastModified, respCtx, rp)
}

// assessTextInUnits assesses text one AWS text unit at a time.
//
// The configured batch decides when to assess and deliver; it does not decide
// how much goes into one request. Every call carries at most one text unit,
// which is the size AWS recommends and which costs exactly the same as sending
// the batch whole -- input is billed per text unit either way, so splitting is
// free. Letting the batch size through instead sent one oversized request:
// measured at 55,199 characters for a very large configured batch, because the
// withheld-bytes limit bounds the buffer and not the request. That is the
// long-context case AWS's guidance says to chunk.
//
// stopAction is non-nil when the caller must return immediately: a violation,
// or a failure passthroughOnError does not excuse.
func (p *AWSBedrockGuardrailPolicy) assessTextInUnits(
	text string,
	heldBytes string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) (stopAction policy.StreamingResponseAction, decisions []interface{}, lastOutput interface{}, lastModified string, assessed bool) {
	remaining := text
	for {
		unitText, carry := splitAtTextUnit(remaining, DefaultStreamingTextUnitChars, true)
		if unitText == "" {
			break
		}
		remaining = carry

		cleaned := strings.TrimSpace(textCleanRegexCompiled.ReplaceAllString(unitText, ""))
		if cleaned == "" {
			if carry == "" {
				break
			}
			continue
		}

		action, output, modified, stop := p.assessStreamBatch(cleaned, heldBytes, respCtx, rp, chunk)
		if stop {
			if action.TerminateStream() {
				return action, nil, nil, "", false
			}
			// passthroughOnError excused this unit's failure, so the rest of the
			// release goes out as it is. The rewrites of the units already assessed
			// still apply to the bytes they describe.
			slog.Debug("AWSBedrockGuardrail: a unit could not be assessed, passthrough enabled; keeping earlier units' rewrites",
				"assessed_units", len(decisions), "chunkIndex", chunk.Index)
			break
		}
		lastOutput, lastModified, assessed = output, modified, true
		// Every unit describes bytes in the same release, so every unit's rewrite
		// decision applies to them. Keeping only the last drops the earlier ones.
		if modified != "" {
			decisions = append(decisions, output)
		}
		if carry == "" {
			break
		}
	}
	return nil, decisions, lastOutput, lastModified, assessed
}

// releaseWithDecisions folds every unit's redaction into the bytes before they
// go out. releaseBytes applies one decision, which is correct when there is
// only one; across several units a value reported in the first is delivered in
// the clear whenever the last reports nothing.
func (p *AWSBedrockGuardrailPolicy) releaseWithDecisions(
	heldBytes string,
	decisions []interface{},
	lastOutput interface{},
	lastModified string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) policy.StreamingResponseAction {
	decisions = append(p.takeCarriedDecisions(respCtx, heldBytes), decisions...)
	if len(decisions) == 0 {
		return p.releaseBytes(heldBytes, lastOutput, lastModified, respCtx, rp)
	}
	rewritten := heldBytes
	for _, decision := range decisions {
		out, stop := p.rewriteHeld(rewritten, decision, rp, respCtx.Metadata)
		if stop != nil {
			return *stop
		}
		rewritten = out
	}
	return policy.ForwardResponseChunk{Body: []byte(p.restoreHeld(rewritten, respCtx, rp))}
}

// rewriteHeld applies one assessment's replacements -- redaction, or masking of
// PII the upstream introduced -- to withheld bytes. A reported value it cannot
// rewrite in place (one spanning event boundaries) stops the stream instead: the
// bytes are discarded rather than delivered with the value in them.
func (p *AWSBedrockGuardrailPolicy) rewriteHeld(
	heldBytes string,
	output interface{},
	rp AWSBedrockGuardrailPolicyParams,
	metadata map[string]interface{},
) (string, *policy.TerminateResponseChunk) {
	rewritten, changed, leaked := p.redactedFlush(heldBytes, output, rp, metadata)
	if leaked {
		slog.Warn("AWSBedrockGuardrail: a reported value spans event boundaries and could not be redacted; discarding the held bytes",
			"held_bytes", len(heldBytes))
		return "", &policy.TerminateResponseChunk{
			// No assessment in the body, whatever showAssessment says: it would
			// carry the very value that could not be masked.
			Body: p.buildSSEErrorEvent("Sensitive content could not be redacted in a streamed response",
				errRedactionFailed, false, nil),
			AnalyticsMetadata: guardrailHitAnalytics(),
			IsFault:           true,
			// The guardrail asked for the value to be masked, which is not a block;
			// what failed is this policy delivering it masked, so it is a mediation
			// fault rather than a guardrail violation.
			Fault: checkFailureFault("Sensitive content could not be redacted in a streamed response", true),
		}
	}
	if changed {
		return rewritten, nil
	}
	return heldBytes, nil
}

// restoreHeld puts the request phase's placeholders back into withheld bytes.
// Under redactPII nothing was masked to be restored.
func (p *AWSBedrockGuardrailPolicy) restoreHeld(
	heldBytes string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) string {
	if rp.RedactPII {
		return heldBytes
	}
	maskedPII, ok := respCtx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if !ok || len(maskedPII) == 0 {
		return heldBytes
	}
	if rewritten, changed := rewriteSSEDeltaContent(heldBytes, rp.StreamingJsonPath, func(frameText string) string {
		return p.restorePIIInResponse(frameText, maskedPII)
	}); changed {
		return rewritten
	}
	return heldBytes
}

// errRedactionFailed marks the error body sent when a reported value could not
// be masked in place. It makes the body give that reason rather than call the
// response a violation, and showAssessment is never honoured there: the
// assessment names the value that could not be masked.
var errRedactionFailed = errors.New("sensitive content could not be redacted")

// assessBatchAndRelease assesses one batch and releases the bytes it covers,
// leaving the caller to record whatever text and bytes remain withheld.
func (p *AWSBedrockGuardrailPolicy) assessBatchAndRelease(
	batchText string,
	heldBytes string,
	retainedBytes string,
	assessedInRetained int,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
	chunk *policy.StreamBody,
) policy.StreamingResponseAction {
	// Every AWS call carries at most one text unit, whatever batch the
	// attachment configured -- the same rule assessAndRelease follows. Sending
	// the batch whole put a configured 8,000-character batch into one request.
	stopAction, decisions, lastOutput, lastModified, assessed := p.assessTextInUnits(
		batchText, heldBytes, respCtx, rp, chunk)
	if stopAction != nil {
		if stopAction.TerminateStream() {
			slog.Debug("AWSBedrockGuardrail: batch failed before delivery, held bytes discarded",
				"held_bytes", len(heldBytes), "chunkIndex", chunk.Index)
			return stopAction
		}
		// passthroughOnError: the batch was not assessed, but withholding the
		// bytes indefinitely would stall the stream, so they are released.
		return p.releaseBytes(heldBytes, nil, "", respCtx, rp)
	}
	if !assessed {
		// Framing only -- nothing to assess, but the bytes are still owed to the
		// client.
		return p.releaseBytes(heldBytes, nil, "", respCtx, rp)
	}

	// The batch boundary generally falls inside a frame, and that frame stays
	// withheld. Its assessed prefix is covered by THESE decisions, but it will be
	// delivered under a later batch's -- and that batch never sees this text, so a
	// redaction reported here would simply be dropped and the value delivered in
	// the clear. Fail closed, exactly as releaseBytes does when a reported value
	// cannot be redacted in place. The same applies to a value that starts in the
	// released frames and ends in the withheld one: neither part contains it
	// whole, so neither rewrite would find it.
	//
	// A value wholly inside the withheld frame's assessed prefix is the exception:
	// those bytes have not been delivered, so this batch's rewrite is carried
	// forward and applied when they are (carryDecisions). Ending the stream there
	// cut off any response whose batch ended in the middle of a token event --
	// which a sentence boundary normally does.
	var carry []interface{}
	if retainedBytes != "" {
		for _, decision := range decisions {
			if !p.reportedValueSpans(heldBytes, retainedBytes, decision, rp, respCtx.Metadata) {
				if p.reportedValueRemains(retainedBytes, assessedInRetained, decision, rp, respCtx.Metadata) {
					carry = append(carry, decision)
				}
				continue
			}
			slog.Warn("AWSBedrockGuardrail: a reported value sits in a withheld frame this batch cannot rewrite; discarding the held bytes",
				"retained_bytes", len(retainedBytes), "chunkIndex", chunk.Index)
			return policy.TerminateResponseChunk{
				// No assessment in the body: it would carry the value that could
				// not be masked.
				Body: p.buildSSEErrorEvent("Sensitive content could not be redacted in a streamed response",
					errRedactionFailed, false, nil),
				AnalyticsMetadata: guardrailHitAnalytics(),
				IsFault:           true,
				Fault:             checkFailureFault("Sensitive content could not be redacted in a streamed response", true),
			}
		}
	}

	action := p.releaseWithDecisions(heldBytes, decisions, lastOutput, lastModified, respCtx, rp)
	if !action.TerminateStream() {
		p.carryDecisions(respCtx, carry)
	}
	return action
}

// carryDecisions keeps rewrites for withheld frames whose assessed text carries
// a reported value, to be applied when those frames are released.
func (p *AWSBedrockGuardrailPolicy) carryDecisions(respCtx *policy.ResponseStreamContext, decisions []interface{}) {
	if len(decisions) == 0 {
		return
	}
	carried, _ := respCtx.Metadata[p.stateKey(metaKeyCarriedDecisions)].([]interface{})
	respCtx.Metadata[p.stateKey(metaKeyCarriedDecisions)] = append(carried, decisions...)
}

// takeCarriedDecisions returns the rewrites carried for withheld frames, once the
// bytes being released include text -- the withheld frames come first in any
// later release, so that release is the one that delivers them.
func (p *AWSBedrockGuardrailPolicy) takeCarriedDecisions(respCtx *policy.ResponseStreamContext, release string) []interface{} {
	carried, _ := respCtx.Metadata[p.stateKey(metaKeyCarriedDecisions)].([]interface{})
	if len(carried) == 0 || extractSSEDeltaContent(release, p.responseParams.StreamingJsonPath) == "" {
		return nil
	}
	delete(respCtx.Metadata, p.stateKey(metaKeyCarriedDecisions))
	return carried
}

// reportedValueRemains reports whether a value this assessment marked for
// redaction starts within the first assessedChars characters of the given
// frames' assistant text: the part of the withheld frames this batch assessed,
// which no later batch will see.
//
// An occurrence after that point is unassessed text the next batch carries, so
// that batch reports it and rewrites it when it releases these frames. Testing
// the whole retained region ended the stream whenever a model repeated a value
// after the batch boundary, although it would have been masked.
func (p *AWSBedrockGuardrailPolicy) reportedValueRemains(
	frames string,
	assessedChars int,
	output interface{},
	rp AWSBedrockGuardrailPolicyParams,
	metadata map[string]interface{},
) bool {
	if assessedChars <= 0 {
		return false
	}
	joined := extractSSEDeltaContent(frames, rp.StreamingJsonPath)
	rewrites := p.responseRewrites(output, rp, metadata, joined)
	if len(rewrites) == 0 {
		return false
	}
	// The assessed prefix, in bytes: the boundary is counted in characters.
	prefix := len(joined)
	if runes := []rune(joined); assessedChars < len(runes) {
		prefix = len(string(runes[:assessedChars]))
	}
	for _, r := range rewrites {
		if r.match == "" {
			continue
		}
		if idx := strings.Index(joined, r.match); idx >= 0 && idx < prefix {
			return true
		}
	}
	return false
}

// reportedValueSpans reports whether a value this assessment marked for
// replacement starts in the released frames and ends in the retained ones.
func (p *AWSBedrockGuardrailPolicy) reportedValueSpans(
	released, retained string,
	output interface{},
	rp AWSBedrockGuardrailPolicyParams,
	metadata map[string]interface{},
) bool {
	if released == "" || retained == "" {
		return false
	}
	head := extractSSEDeltaContent(released, rp.StreamingJsonPath)
	joined := head + extractSSEDeltaContent(retained, rp.StreamingJsonPath)
	rewrites := p.responseRewrites(output, rp, metadata, joined)
	if len(rewrites) == 0 {
		return false
	}
	boundary := len(head)
	for _, r := range rewrites {
		if r.match == "" {
			continue
		}
		// Only an occurrence starting inside the last len(match)-1 bytes of the
		// released text can cross the boundary.
		from := boundary - len(r.match) + 1
		if from < 0 {
			from = 0
		}
		for i := from; i < boundary; {
			idx := strings.Index(joined[i:], r.match)
			if idx < 0 || i+idx >= boundary {
				break
			}
			if i+idx+len(r.match) > boundary {
				return true
			}
			i += idx + 1
		}
	}
	return false
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
	for _, carried := range p.takeCarriedDecisions(respCtx, heldBytes) {
		rewritten, stop := p.rewriteHeld(heldBytes, carried, rp, respCtx.Metadata)
		if stop != nil {
			return *stop
		}
		heldBytes = rewritten
	}
	if modified != "" {
		rewritten, stop := p.rewriteHeld(heldBytes, output, rp, respCtx.Metadata)
		if stop != nil {
			return *stop
		}
		heldBytes = rewritten
	}
	return policy.ForwardResponseChunk{Body: []byte(p.restoreHeld(heldBytes, respCtx, rp))}
}

// restoreFlushFrames puts masked values back into a flush's frames before the
// flush is accumulated, assessed or split.
//
// releaseBytes still restores at delivery, which is not redundant: a placeholder
// split across two flushes is in neither frame here and only becomes whole
// later. That case is the documented limitation -- such a value reaches the
// client without having been assessed -- and is unchanged by this.
func (p *AWSBedrockGuardrailPolicy) restoreFlushFrames(
	chunkStr string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) string {
	if rp.RedactPII {
		return chunkStr
	}
	raw, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return chunkStr
	}
	maskedPII, ok := raw.(map[string]string)
	if !ok || len(maskedPII) == 0 {
		return chunkStr
	}
	rewritten, changed := rewriteSSEDeltaContent(chunkStr, rp.StreamingJsonPath, func(frameText string) string {
		return p.restorePIIInResponse(frameText, maskedPII)
	})
	if !changed {
		return chunkStr
	}
	return rewritten
}

// effectiveTextUnit returns the batch size to assess at.
//
// Redaction used to be a special case here, assessing every flush rather than
// batching: it rewrites the frames of the flush in hand, so a finding deferred
// to a later batch would arrive after those frames had been forwarded. That
// reason is gone — no flush is forwarded until the batch covering it has been
// assessed — and keeping the special case made redaction *worse*: a value split
// across two flushes was in neither flush's text, so neither assessment
// reported it and it was delivered unredacted. Batching joins the text first.
func (p *AWSBedrockGuardrailPolicy) effectiveTextUnit() int {
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

	// Zero: assess the whole response, so nothing is assessed until the stream
	// ends. streamingTextUnitChars: 0 asks for this.
	if unit <= 0 {
		if endOfStream {
			return text, ""
		}
		return "", text
	}

	if len(runes) < unit {
		// Below a unit: hold for more text, unless there will be none.
		if endOfStream {
			return text, ""
		}
		return "", text
	}

	cut := lastSentenceEnd(runes, unit, endOfStream)
	if cut <= 0 {
		cut = lastWordEnd(runes, unit)
	}
	if cut <= 0 {
		cut = unit
	}
	return string(runes[:cut]), string(runes[cut:])
}

// splitAtWordBoundary cuts text after its last sentence or word end, for a
// release forced by the withheld-bytes limit rather than by a text unit. batch
// is empty when no boundary lies within maxBoundarySearchRunes of the end.
func splitAtWordBoundary(text string) (batch, carry string) {
	runes := []rune(text)
	cut := lastSentenceEnd(runes, len(runes), false)
	if cut <= 0 {
		cut = lastWordEnd(runes, len(runes))
	}
	if cut <= 0 {
		return "", text
	}
	return string(runes[:cut]), string(runes[cut:])
}

// maxCapRetainBytes bounds what a release forced by maxHeldFlushBytes may keep
// withheld: the frames carrying the trailing partial word. Past it the release
// takes everything, so the buffer cannot stay near its limit.
const maxCapRetainBytes = maxHeldFlushBytes / 4

// maxBoundarySearchRunes bounds how far back a boundary is looked for, so a
// batch is never trimmed to a small fraction of a text unit by one very long
// sentence.
const maxBoundarySearchRunes = 200

// lastSentenceEnd returns the index just past the last sentence terminator at or
// before limit, or 0 if there is none within the search distance.
//
// A terminator only counts when whitespace follows it, or when it ends the text
// available. Accepting any "." split the values this policy exists to catch:
// with the batch boundary landing inside one, "john@example.com" was cut into
// "john@example." and "com", and "192.168.1.1" into "192.168." and "1.1".
// Neither half matches a PII rule, so neither assessment reported anything and
// the value was released unchanged — the trimming meant to stop a phrase being
// split was creating the split instead.
//
// A terminator followed by a closing quote or bracket is not accepted either.
// That costs a little precision — the batch then ends at a word boundary rather
// than a sentence — and a word boundary never cuts a value in half, which is
// what matters here.
func lastSentenceEnd(runes []rune, limit int, endOfStream bool) int {
	floor := limit - maxBoundarySearchRunes
	if floor < 0 {
		floor = 0
	}
	for i := limit - 1; i >= floor; i-- {
		switch runes[i] {
		case '.', '!', '?':
			if i+1 < len(runes) {
				if isSpaceRune(runes[i+1]) {
					return i + 1
				}
				continue
			}
			// Nothing follows it in the text available. Mid-stream that is not
			// evidence of a sentence end -- the very next flush may continue the
			// token, which is how "john@example." and "com" became two batches.
			// Only once the stream has ended does end-of-text mean end-of-sentence.
			if endOfStream {
				return i + 1
			}
		case '\n':
			return i + 1
		}
	}
	return 0
}

// isSpaceRune reports whether r is one of the space characters that separate
// words here. Kept explicit rather than unicode.IsSpace so the set is the same
// one lastWordEnd splits on.
func isSpaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return false
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

// applyGuardrailToText runs one ApplyGuardrail call for the given text of a
// streamed response.
func (p *AWSBedrockGuardrailPolicy) applyGuardrailToText(text string) (interface{}, error) {
	loadConfig := p.loadAWSConfigFunc
	if loadConfig == nil {
		loadConfig = p.loadAWSConfig
	}
	awsCfg, err := loadConfig(context.Background(), p.region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	output, err := p.applyBedrockGuardrail(context.Background(), awsCfg, p.guardrailID, p.guardrailVersion, types.GuardrailContentSourceOutput, text)
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
//
// coveredChars reports how much of the assessed text the released frames
// actually carried. The remainder is assessed text still sitting in a retained
// frame, which the caller must add to the next boundary or that frame lingers
// one round longer than it needs to.
func splitHeldAtTextBoundary(held, streamingJsonPath string, assessedChars int) (release, retain string, coveredChars int) {
	if assessedChars <= 0 {
		return "", held, 0
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

		// A line with no terminator is still arriving. Its payload is truncated,
		// so its text could not be read and therefore cannot have been assessed:
		// reading zero characters out of it must not be mistaken for carrying
		// none. Retain it and everything after it.
		if !strings.HasSuffix(raw, "\n") {
			start := committed
			if framing >= 0 {
				start = framing
			}
			return held[:start], held[start:], chars
		}

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
				return held[:start], held[start:], chars
			}
			chars += n
			committed = lineEnd
			framing = -1
		}
		i = lineEnd
	}

	if framing >= 0 {
		return held[:framing], held[framing:], chars
	}
	return held[:committed], held[committed:], chars
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
	if err != nil || value == "" {
		return ""
	}
	if frameReadsAnotherChoice(payload, streamingJsonPath) {
		return ""
	}
	return textCleanRegexCompiled.ReplaceAllString(value, "")
}

// frameReadsAnotherChoice is readsAnotherChoice for one data payload.
func frameReadsAnotherChoice(payload, streamingJsonPath string) bool {
	tokens, err := parseJSONPath(streamingJsonPath)
	if err != nil {
		return false
	}
	doc, err := decodeJSON([]byte(payload))
	return err == nil && readsAnotherChoice(doc, tokens)
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
// Over maxPartialLineBytes the fragment stops being retained, because a stream
// carrying no line terminator would otherwise grow it without limit. Dropping it
// loses the only thing that would have made the line readable: its "data:"
// prefix and opening brace stay in this flush while the rest arrives in the
// next, so neither half parses and the line's text is never assessed -- while
// its bytes are released with everything else. unassessable reports that, and
// the caller fails closed rather than delivering text no assessment has seen.
func (p *AWSBedrockGuardrailPolicy) flushText(
	chunkStr string,
	endOfStream bool,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) (text string, unassessable bool) {
	carried, _ := respCtx.Metadata[p.stateKey(metaKeyPartialLine)].(string)
	joined := carried + chunkStr

	if endOfStream {
		delete(respCtx.Metadata, p.stateKey(metaKeyPartialLine))
		return extractSSEDeltaContent(joined, rp.StreamingJsonPath), refusesUnreadableBody(joined, rp)
	}

	complete, partial := splitTrailingPartialLine(joined)
	if refusesUnreadable(complete, rp) {
		// Text outside any event, or a data payload that is not JSON: delivering
		// these bytes would release text no assessment has read.
		slog.Warn("AWSBedrockGuardrail: SSE response carries a line that cannot be read, or output streamingJsonPath does not read; its text cannot be assessed")
		delete(respCtx.Metadata, p.stateKey(metaKeyPartialLine))
		return extractSSEDeltaContent(complete, rp.StreamingJsonPath), true
	}
	if len(partial) > maxPartialLineBytes {
		slog.Warn("AWSBedrockGuardrail: incomplete SSE line exceeded the retention limit; its text cannot be assessed",
			"partial_bytes", len(partial), "limit", maxPartialLineBytes)
		delete(respCtx.Metadata, p.stateKey(metaKeyPartialLine))
		return extractSSEDeltaContent(joined, rp.StreamingJsonPath), true
	}
	respCtx.Metadata[p.stateKey(metaKeyPartialLine)] = partial
	return extractSSEDeltaContent(complete, rp.StreamingJsonPath), false
}

// joinParts joins the flushes handleNonSSEStreamFlush accumulated.
func joinParts(parts []interface{}, size int) string {
	var sb strings.Builder
	sb.Grow(size)
	for _, part := range parts {
		if s, ok := part.(string); ok {
			sb.WriteString(s)
		}
	}
	return sb.String()
}

// dropAccumulated forgets the body handleNonSSEStreamFlush accumulated.
func (p *AWSBedrockGuardrailPolicy) dropAccumulated(respCtx *policy.ResponseStreamContext) {
	delete(respCtx.Metadata, p.stateKey(metaKeyAccStreamedJSONBody))
	delete(respCtx.Metadata, p.stateKey(metaKeyAccStreamedLen))
}

// forwardRestored forwards bytes released without an assessment, with the
// request's placeholders put back, as every other delivered response has them.
// It returns a nil body (forward unchanged) when there is nothing to restore.
func (p *AWSBedrockGuardrailPolicy) forwardRestored(s string, respCtx *policy.ResponseStreamContext) policy.ForwardResponseChunk {
	if p.responseParams.RedactPII {
		return policy.ForwardResponseChunk{}
	}
	masked, _ := respCtx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if len(masked) == 0 || !containsPlaceholder(s, masked) {
		return policy.ForwardResponseChunk{}
	}
	// The body cannot be parsed whole here, so its Content-Type decides: inside a
	// JSON document a restored value is escaped, or a quote or backslash in it
	// would break the JSON the client receives.
	if isJSONMediaType(responseMediaType(respCtx.ResponseHeaders)) {
		masked = jsonEscapedOriginals(masked)
	}
	if restored := p.restorePIIInResponse(s, masked); restored != s {
		return policy.ForwardResponseChunk{Body: []byte(restored)}
	}
	return policy.ForwardResponseChunk{}
}

// isJSONMediaType reports whether a media type names a JSON document:
// application/json, or any +json type.
func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// jsonRPCEventStream is the media type handleJSONRPCStreamFlush passes to
// validatePayloadAs: an event stream known to carry JSON-RPC messages.
const jsonRPCEventStream = "text/event-stream; jsonrpc"

// streamingPathKey returns the member name streamingJsonPath starts with --
// "choices" for "$.choices[0].delta.content" -- or "" when it starts otherwise.
func streamingPathKey(path string) string {
	if m := streamingPathKeyPattern.FindStringSubmatch(path); m != nil {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}
	return ""
}

var streamingPathKeyPattern = regexp.MustCompile(`^\$(?:\.([A-Za-z0-9_-]+)|\[['"]([^'"]+)['"]\])`)

// streamingPathMatches reports, for the complete data lines of an event stream,
// whether any event carries the member streamingJsonPath starts with, and whether
// any does not. A provider's error event is neither.
func streamingPathMatches(s, key string) (matched, unmatched bool) {
	complete, _ := splitTrailingPartialLine(s)
	for rest := complete; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		payload, _, ok := sseDataPayload(line)
		if !ok {
			continue
		}
		if t := strings.TrimSpace(payload); t == "" || t == sseDone {
			continue
		}
		var doc interface{}
		if json.Unmarshal([]byte(payload), &doc) != nil {
			continue // unreadable lines are refused separately
		}
		if obj, isObject := doc.(map[string]interface{}); isObject {
			if _, has := obj[key]; has {
				matched = true
				continue
			}
			if _, isError := obj["error"]; isError {
				continue
			}
		}
		unmatched = true
	}
	return matched, unmatched
}

// streamingPathDecision is what checkStreamingPath decided for a flush.
type streamingPathDecision int

const (
	streamingPathProceed streamingPathDecision = iota // assess the (possibly longer) flush as usual
	streamingPathWait                                 // withhold it: no event has shown the path yet
	streamingPathRefuse                               // end the stream: the path describes no event
)

// checkStreamingPath makes sure streamingJsonPath describes this token stream
// before any of it is delivered.
//
// Until an event carrying the member streamingJsonPath starts with has been
// seen, flushes whose JSON events lack it are withheld: some formats open with
// such events (Anthropic's message_start, say) before the first one that does.
// When one arrives, everything withheld is handed on with it. If the stream
// ends, or the withheld bytes reach maxHeldFlushBytes, without one, the path
// does not describe this stream (a provider's own format under the default, say),
// so none of its text could be read: it ends rather than being delivered as if it
// carried none. Flushes with no JSON event at all, and passthroughOnError, are
// not affected.
func (p *AWSBedrockGuardrailPolicy) checkStreamingPath(
	chunkStr string,
	endOfStream bool,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) (string, streamingPathDecision) {
	key := streamingPathKey(rp.StreamingJsonPath)
	if key == "" || rp.PassthroughOnError {
		return chunkStr, streamingPathProceed
	}
	if seen, _ := respCtx.Metadata[p.stateKey(metaKeyStreamingPathSeen)].(bool); seen {
		return chunkStr, streamingPathProceed
	}
	waiting, _ := respCtx.Metadata[p.stateKey(metaKeyStreamingPathWait)].(string)
	buffered := waiting + chunkStr
	carried, _ := respCtx.Metadata[p.stateKey(metaKeyPartialLine)].(string)
	matched, unmatched := streamingPathMatches(carried+buffered, key)
	if endOfStream {
		// The last line counts too, terminated or not.
		m, u := streamingPathMatches(carried+buffered+"\n", key)
		matched, unmatched = matched || m, unmatched || u
	}
	switch {
	case matched:
		respCtx.Metadata[p.stateKey(metaKeyStreamingPathSeen)] = true
		delete(respCtx.Metadata, p.stateKey(metaKeyStreamingPathWait))
		return buffered, streamingPathProceed
	case !unmatched && waiting == "":
		return chunkStr, streamingPathProceed
	case endOfStream || len(buffered) > maxHeldFlushBytes:
		delete(respCtx.Metadata, p.stateKey(metaKeyStreamingPathWait))
		if !unmatched {
			return buffered, streamingPathProceed
		}
		slog.Warn("AWSBedrockGuardrail: streamingJsonPath matches no event of the response; its text cannot be assessed",
			"streamingJsonPath", rp.StreamingJsonPath)
		return "", streamingPathRefuse
	default:
		respCtx.Metadata[p.stateKey(metaKeyStreamingPathWait)] = buffered
		return "", streamingPathWait
	}
}

// errUnassessable is the reason given to the client when response content could
// not be read to be assessed: no guardrail ran, so it is not reported as a
// violation.
var errUnassessable = errors.New("response content could not be assessed")

// unassessableEnd ends a response whose content could not be assessed, with a
// mediation fault and a reason that says so -- as an SSE event when the response
// is an event stream, as the guardrail error JSON otherwise.
func (p *AWSBedrockGuardrailPolicy) unassessableEnd(eventStream bool) policy.TerminateResponseChunk {
	const reason = "Response content could not be assessed"
	var body []byte
	if eventStream {
		body = p.buildSSEErrorEvent(reason, errUnassessable, p.responseParams.ShowAssessment, nil)
	} else if errResp, ok := p.buildErrorResponse(reason, errUnassessable, true, p.responseParams.ShowAssessment, nil).(policy.DownstreamResponseModifications); ok {
		body = errResp.Body
	}
	return policy.TerminateResponseChunk{
		Body:              body,
		AnalyticsMetadata: guardrailHitAnalytics(),
		IsFault:           true,
		Fault:             checkFailureFault(reason, true),
	}
}

// amazonEventStreamMediaType is the binary framing Bedrock streams in. A
// translating policy later in the chain (openai-to-bedrock-transformer) rewrites
// both the body and this Content-Type into SSE, but a body that still carries it
// may be either, so it is sniffed like a response with no Content-Type.
const amazonEventStreamMediaType = "application/vnd.amazon.eventstream"

// responseMediaType returns the response's media type, lower-cased and without
// parameters, or "" when there is no Content-Type.
func responseMediaType(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	values := headers.Get("content-type")
	if len(values) == 0 {
		return ""
	}
	mediaType, _, _ := strings.Cut(values[0], ";")
	return strings.ToLower(strings.TrimSpace(mediaType))
}

// isEventStreamResponse reports whether a response body is Server-Sent Events.
//
// A text/event-stream Content-Type is SSE, unless the body is plainly a JSON
// document (its first non-blank character opens an object or array): that is
// read with jsonPath, as it always was. A response with no Content-Type, or one
// an event stream is commonly mislabelled as (sniffedMediaType), is an event
// stream only when its first non-blank line is an SSE field or comment and it
// carries a data line, so an event stream labelled application/json is still read
// as one. Any other type is not sniffed.
//
// Only the first line is sniffed: a plain-text answer can contain a line that
// starts "id:" or "data:" and is still plain text.
func isEventStreamResponse(mediaType string, body []byte) bool {
	if mediaType == "text/event-stream" {
		return !looksLikeJSONDocument(body)
	}
	if !sniffedMediaType(mediaType) {
		return false
	}
	return looksLikeEventStream(body) && hasSSEDataLine(body)
}

// sniffedMediaType reports whether a response labelled mediaType may still be an
// event stream: no Content-Type, or one an event stream is commonly sent under
// by mistake. Any other type (application/yaml, text/html, ...) is taken at its
// word and read with jsonPath, as it always was.
func sniffedMediaType(mediaType string) bool {
	switch mediaType {
	case "", "application/json", "text/plain", "application/octet-stream", amazonEventStreamMediaType:
		return true
	}
	return false
}

// hasSSEDataLine reports whether any line of body is a "data:" field. A body
// that is not labelled text/event-stream is read as an event stream only when it
// carries one: text that merely opens with "id: 42" or ":)" is still text, and
// is read with jsonPath like any other non-event-stream body.
func hasSSEDataLine(body []byte) bool {
	for rest := string(body); rest != ""; {
		var line string
		line, rest = nextLine(rest)
		if strings.HasPrefix(strings.TrimPrefix(line, byteOrderMark), sseDataField) {
			return true
		}
	}
	return false
}

// byteOrderMark may open an event stream; the SSE specification strips it.
const byteOrderMark = "\uFEFF"

// unreadableSSELine reports whether any line of an SSE body carries text this
// policy cannot read: text outside any event, or a data line whose payload is
// neither JSON nor "[DONE]".
//
// Either would reach the client without its text having been assessed. A data
// payload that is not JSON cannot be read at streamingJsonPath -- and that
// includes an event whose JSON the upstream split over several data lines, each
// of which is a fragment on its own.
//
// A leading byte order mark is stripped, and blank lines, comments and the other
// fields the SSE specification defines ("event", "id", "retry", with or without
// a colon) are ignored. Any other line is treated as text outside any event:
// the specification has a client ignore an unknown field, but a client that is
// not an EventSource shows it, so a line such as "SSN: 123-45-6789" is refused
// rather than delivered unread.
func unreadableSSELine(s string) bool {
	for rest := s; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		line = strings.TrimPrefix(line, byteOrderMark)
		if strings.Contains(line, "\r") {
			return true // a bare carriage return ends lines this reader does not split on
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, ":") {
			continue
		}
		name, value, hasColon := strings.Cut(line, ":")
		if !isSSEFieldName(name) {
			return true // text outside any event
		}
		if name != "data" || !hasColon {
			continue
		}
		payload := strings.TrimPrefix(value, " ")
		if t := strings.TrimSpace(payload); t != "" && t != sseDone && !json.Valid([]byte(payload)) {
			return true
		}
	}
	return false
}

// isSSEFieldName reports whether s names one of the fields the SSE
// specification defines: what a line carries before its colon, or the whole of a
// line with none.
func isSSEFieldName(s string) bool {
	switch s {
	case "data", "event", "id", "retry":
		return true
	}
	return false
}

// unreadableSSEBody is unreadableSSELine for a body that has ended. Its last
// line, when it has no terminator, is an event the stream never finished; an SSE
// client discards it, so a field cut off there is not refused. Text that is not
// a field at all still is, and so is a bare carriage return.
func unreadableSSEBody(s string) bool {
	complete, partial := splitTrailingPartialLine(s)
	if unreadableSSELine(complete) {
		return true
	}
	return strings.Contains(partial, "\r") || unreadablePartialLine(partial)
}

// unreadablePartialLine reports whether an unterminated last line carries text
// that cannot be read. A field cut off there is not: a field other than data, or
// a data line that is empty or whose JSON was cut short (it opens an object or
// array). Prose, or a data line carrying anything else, is.
func unreadablePartialLine(partial string) bool {
	partial = strings.TrimPrefix(strings.TrimSuffix(partial, "\r"), byteOrderMark)
	if strings.TrimSpace(partial) == "" || strings.HasPrefix(partial, ":") {
		return false
	}
	name, value, _ := strings.Cut(partial, ":")
	if !isSSEFieldName(name) {
		return true
	}
	if name != "data" {
		return false
	}
	value = strings.TrimSpace(value)
	return value != "" && !strings.HasPrefix(value, "{") && !strings.HasPrefix(value, "[") && value != sseDone
}

// unreadableEventStream is the readability check for an event stream of JSON-RPC
// messages, read event by event as extractEventStream reads it: line endings may
// be CRLF or CR, an event's data lines are joined, and the joined data must be
// JSON, "[DONE]" or empty. Text outside any field is unreadable too. Without this,
// a data payload that is not JSON was skipped by the extraction and delivered.
func unreadableEventStream(s string) bool {
	complete, partial := splitTrailingPartialLine(normalizeLineEndings([]byte(s)))
	for _, event := range splitEvents([]byte(complete)) {
		for _, line := range event.lines {
			line = strings.TrimPrefix(line, byteOrderMark)
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, ":") {
				continue
			}
			if name, _, _ := strings.Cut(line, ":"); !isSSEFieldName(name) {
				return true
			}
		}
		if data, ok := eventData(event.lines); ok {
			if t := strings.TrimSpace(data); t != "" && t != sseDone && !json.Valid([]byte(data)) {
				return true
			}
		}
	}
	return unreadablePartialLine(partial)
}

// refusesUnreadableBody is refusesUnreadable for a body that has ended.
func refusesUnreadableBody(s string, rp AWSBedrockGuardrailPolicyParams) bool {
	// An unfinished last line is an event an SSE client discards, so only the
	// complete lines are checked for output the path does not read.
	complete, _ := splitTrailingPartialLine(s)
	return !rp.PassthroughOnError && (unreadableSSEBody(s) || missedStreamedOutput(complete, rp.StreamingJsonPath))
}

// refusesUnreadable reports whether an unreadable line (unreadableSSELine), or an
// event with model output streamingJsonPath does not read (missedStreamedOutput),
// ends the response. With passthroughOnError it does not: such a line was
// delivered as it was before this check existed, and the readable text around it
// is still assessed as usual.
func refusesUnreadable(s string, rp AWSBedrockGuardrailPolicyParams) bool {
	return !rp.PassthroughOnError && (unreadableSSELine(s) || missedStreamedOutput(s, rp.StreamingJsonPath))
}

// streamedOutputKeys name the members of a streamed event that carry model
// output: text, a refusal, reasoning, an audio response's transcript, or a tool
// call and its arguments. Any non-blank string beneath one of them is output.
// An audio delta's data is not: it is encoded audio, which the guardrail cannot
// read, and its transcript is the text of the same audio.
var streamedOutputKeys = map[string]bool{
	"content":           true,
	"text":              true,
	"transcript":        true,
	"refusal":           true,
	"reasoning":         true,
	"reasoning_content": true,
	"thinking":          true,
	"tool_calls":        true,
	"function_call":     true,
	"arguments":         true,
	"partial_json":      true,
}

// streamedMetadataKeys name members whose strings describe output rather than
// carry it, so nothing beneath them counts as output: log probabilities repeat
// the tokens of the text the path reads (logprobs.content[].token), and a role
// names who wrote the text (Gemini's content.role beside content.parts).
//
// Log probabilities also carry top_logprobs, alternative tokens the model did
// not choose. They are single tokens, not text, and are not assessed. When a
// value is masked, the log probabilities of the event that carried it are
// removed (dropLogprobs), since their tokens would deliver the value itself.
var streamedMetadataKeys = map[string]bool{
	logprobsKey: true,
	"role":      true,
}

const logprobsKey = "logprobs"

// dropLogprobs removes every log probabilities member beneath v. A masked value
// is written into the text the path reads; the same value is also in the tokens
// of the log probabilities beside it, so they go with it.
func dropLogprobs(v interface{}) {
	switch node := v.(type) {
	case map[string]interface{}:
		delete(node, logprobsKey)
		for _, child := range node {
			dropLogprobs(child)
		}
	case []interface{}:
		for _, child := range node {
			dropLogprobs(child)
		}
	}
}

// choiceArrayKeys name the arrays whose elements are a response's alternative
// answers, each naming its own position in an "index" member: OpenAI's choices
// and Gemini's candidates. An "index" member of an element of any other array is
// the provider's own data, not a choice's identity.
var choiceArrayKeys = map[string]bool{
	"choices":    true,
	"candidates": true,
}

// readsAnotherChoice reports whether streamingJsonPath, followed through doc,
// passes an element of a choice array (choiceArrayKeys) whose own "index" member
// names another position. An OpenAI stream with n>1 sends each choice in its own
// event at choices[0], told apart only by that member, so $.choices[0] reads
// every choice; joining them would interleave their tokens and split each
// choice's phrases. Only the choice the path names is read.
func readsAnotherChoice(doc interface{}, tokens []pathToken) bool {
	node := doc
	arrayKey := ""
	for _, token := range tokens {
		switch token.kind {
		case tokenKey:
			object, ok := node.(map[string]interface{})
			if !ok {
				return false
			}
			node = object[token.key]
			arrayKey = token.key
		case tokenIndex:
			array, ok := node.([]interface{})
			if !ok || token.index < 0 || token.index >= len(array) {
				return false
			}
			node = array[token.index]
			if choiceArrayKeys[arrayKey] && choiceIndexDiffers(node, token.index) {
				return true
			}
			arrayKey = ""
		default:
			return false
		}
	}
	return false
}

// choiceIndexDiffers reports whether element is an object whose "index" member
// is a number other than position.
func choiceIndexDiffers(element interface{}, position int) bool {
	object, ok := element.(map[string]interface{})
	if !ok {
		return false
	}
	n, ok := object["index"].(json.Number)
	return ok && n.String() != strconv.Itoa(position)
}

// missedStreamedOutput reports whether a data line of s carries model output that
// streamingJsonPath does not read, so it would be delivered unassessed: a
// tool-call delta beside or instead of delta.content, a legacy completion's
// choices[].text under the chat path, or a member of another shape where the
// path expects an array.
//
// An event without the member the path starts with reads nothing, so any output
// in it counts (a provider's own event beside the chat deltas, say). In an event
// with that member, only what the path does not lead to counts: the members
// beside it, other array elements, everything beneath a wildcard (the SDK reads
// no text through one), and a value of another shape where the path goes on.
// An event's id, model, role, finish reason or usage are not output, and events
// with no text at all -- the opening role delta, the finishing delta, a usage
// frame with no choices, an error -- carry none.
func missedStreamedOutput(s, streamingJsonPath string) bool {
	tokens, err := parseJSONPath(streamingJsonPath)
	if err != nil || len(tokens) == 0 || tokens[0].kind != tokenKey {
		return false
	}
	for rest := s; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		payload, _, ok := sseDataPayload(strings.TrimSuffix(line, "\r"))
		if !ok {
			continue
		}
		if t := strings.TrimSpace(payload); t == "" || t == sseDone {
			continue
		}
		doc, err := decodeJSON([]byte(payload))
		if err != nil {
			continue // unreadable lines are refused separately
		}
		event, isObject := doc.(map[string]interface{})
		if !isObject {
			continue
		}
		if _, has := event[tokens[0].key]; !has {
			if carriesStreamedOutput(doc, false) {
				return true
			}
			continue
		}
		if outputOffPath(doc, tokens, false, "") {
			return true
		}
	}
	return false
}

// outputOffPath reports whether node carries model output anywhere the remaining
// path tokens do not lead to text; output says node is beneath an output member,
// and arrayKey names the member node is the value of ("" for an array element or
// the event itself).
func outputOffPath(node interface{}, tokens []pathToken, output bool, arrayKey string) bool {
	if len(tokens) == 0 {
		switch node.(type) {
		case string, json.Number, bool, nil:
			return false // the text the path reads (or no text at all)
		}
		return carriesStreamedOutput(node, true) // an object or array: not read as text
	}
	token := tokens[0]
	switch token.kind {
	case tokenKey:
		object, ok := node.(map[string]interface{})
		if !ok {
			return carriesStreamedOutput(node, output) // another shape: the path reads nothing
		}
		for key, child := range object {
			if key != token.key && !streamedMetadataKeys[key] && carriesStreamedOutput(child, output || streamedOutputKeys[key]) {
				return true
			}
		}
		child, has := object[token.key]
		return has && outputOffPath(child, tokens[1:], output || streamedOutputKeys[token.key], token.key)
	case tokenWildcard:
		// The SDK reads a wildcard as a list, which is not text: nothing beneath
		// it is read.
		return carriesStreamedOutput(node, output)
	default:
		array, ok := node.([]interface{})
		if !ok {
			return carriesStreamedOutput(node, output)
		}
		index := token.index
		if index < 0 {
			index += len(array)
		}
		for i, element := range array {
			if i == index && !(choiceArrayKeys[arrayKey] && choiceIndexDiffers(element, index)) {
				if outputOffPath(element, tokens[1:], output, "") {
					return true
				}
			} else if carriesStreamedOutput(element, output) {
				return true // another choice the path does not read
			}
		}
		return false
	}
}

// carriesStreamedOutput reports whether v holds a non-blank string beneath one of
// streamedOutputKeys; output says v itself is beneath one.
func carriesStreamedOutput(v interface{}, output bool) bool {
	switch node := v.(type) {
	case string:
		return output && strings.TrimSpace(node) != ""
	case map[string]interface{}:
		for key, child := range node {
			if !streamedMetadataKeys[key] && carriesStreamedOutput(child, output || streamedOutputKeys[key]) {
				return true
			}
		}
	case []interface{}:
		for _, child := range node {
			if carriesStreamedOutput(child, output) {
				return true
			}
		}
	}
	return false
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
	// A byte order mark opening the stream is kept in the prefix, so the line is
	// still read as data and a rewrite writes it back unchanged.
	bom := ""
	if strings.HasPrefix(line, byteOrderMark) {
		bom, line = byteOrderMark, line[len(byteOrderMark):]
	}
	if !strings.HasPrefix(line, sseDataField) {
		return "", "", false
	}
	payload = line[len(sseDataField):]
	prefix = bom + sseDataField
	if strings.HasPrefix(payload, " ") {
		payload = payload[1:]
		prefix += " "
	}
	return payload, prefix, true
}

// endsAtSSEEventBoundary reports whether s ends where one event ends, so a
// flush released here never cuts a `data:` line in half.
//
// Every terminator is accepted, in any mix (see lastEventEnd): matching "\n\n"
// alone would treat a CRLF or CR stream as one event that never ends, and
// accumulate it to the kernel's ceiling instead of releasing it.
func endsAtSSEEventBoundary(s []byte) bool {
	return len(s) > 0 && lastEventEnd(string(s)) == len(s)
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

// replacementSpan is one occurrence of a value to replace, as byte offsets into a
// text.
type replacementSpan struct {
	start, end  int
	replacement string
}

// findReplacementSpans returns the occurrences applyPIIReplacements would
// replace in text, in order and without overlaps: the leftmost occurrence of any
// value wins, and where two values start at the same position the earlier
// replacement does (piiReplacements orders them longest first).
func findReplacementSpans(text string, replacements []piiReplacement) []replacementSpan {
	next := make([]int, len(replacements))
	for i, r := range replacements {
		next[i] = -1
		if r.match != "" {
			next[i] = strings.Index(text, r.match)
		}
	}
	var spans []replacementSpan
	pos := 0
	for {
		best := -1
		for i, at := range next {
			if at >= 0 && (best < 0 || at < next[best]) {
				best = i
			}
		}
		if best < 0 {
			return spans
		}
		r := replacements[best]
		start := next[best]
		spans = append(spans, replacementSpan{start: start, end: start + len(r.match), replacement: r.replacement})
		pos = start + len(r.match)
		// Occurrences overlapping the one just taken are skipped.
		for i, at := range next {
			if at >= 0 && at < pos {
				next[i] = -1
				if idx := strings.Index(text[pos:], replacements[i].match); idx >= 0 {
					next[i] = pos + idx
				}
			}
		}
	}
}

// sseTextFrame is one data line of a flush whose payload carries text at
// streamingJsonPath.
type sseTextFrame struct {
	line     int
	prefix   string
	carriage bool
	frame    map[string]interface{}
	value    string
	start    int // offset of value in the flush's joined text
}

// rewriteAcrossFrames replaces values in a flush's text read as a whole, then
// writes the result back frame by frame: each replacement goes into the frame
// where its value starts, and the rest of the value is removed from the frames
// after it. Frames are kept -- one emptied of text still carries its event -- so
// the stream keeps its shape and only the text changes. A frame whose text does
// not change is passed through byte-for-byte.
func rewriteAcrossFrames(chunkStr, streamingJsonPath string, replacements []piiReplacement) (string, bool) {
	if len(replacements) == 0 {
		return chunkStr, false
	}
	lines := strings.Split(chunkStr, "\n")
	tokens, _ := parseJSONPath(streamingJsonPath)
	var (
		frames []sseTextFrame
		joined strings.Builder
	)
	for i, line := range lines {
		carriage := strings.HasSuffix(line, "\r")
		payload, prefix, ok := sseDataPayload(strings.TrimSuffix(line, "\r"))
		if !ok {
			continue
		}
		if t := strings.TrimSpace(payload); t == "" || t == sseDone {
			continue
		}
		frame, ok := decodeFrame(payload)
		if !ok {
			continue
		}
		value, err := utils.ExtractStringValueFromJsonpath([]byte(payload), streamingJsonPath)
		if err != nil || value == "" || readsAnotherChoice(frame, tokens) {
			continue // the same frames frameText reads, so the offsets agree
		}
		frames = append(frames, sseTextFrame{line: i, prefix: prefix, carriage: carriage,
			frame: frame, value: value, start: joined.Len()})
		joined.WriteString(value)
	}

	text := joined.String()
	spans := findReplacementSpans(text, replacements)
	if len(spans) == 0 {
		return chunkStr, false
	}

	changed := false
	first := 0 // first span that can still reach the current frame
	for _, f := range frames {
		start, end := f.start, f.start+len(f.value)
		for first < len(spans) && spans[first].end <= start {
			first++
		}
		var b strings.Builder
		cursor := start
		for _, sp := range spans[first:] {
			if sp.start >= end {
				break
			}
			if sp.start > cursor {
				b.WriteString(text[cursor:sp.start])
			}
			if sp.start >= start {
				// The value starts in this frame, so its replacement goes here.
				b.WriteString(sp.replacement)
			}
			if sp.end > cursor {
				cursor = sp.end
			}
		}
		if cursor < end {
			b.WriteString(text[cursor:end])
		}
		replacement := b.String()
		if replacement == f.value {
			continue
		}
		dropLogprobs(f.frame)
		if err := utils.SetValueAtJSONPath(f.frame, streamingJsonPath, replacement); err != nil {
			slog.Debug("AWSBedrockGuardrail: failed to set streaming value at JSONPath",
				"jsonPath", streamingJsonPath, "error", err)
			continue
		}
		encoded, err := encodeJSON(f.frame)
		if err != nil {
			slog.Debug("AWSBedrockGuardrail: failed to marshal rewritten SSE frame", "error", err)
			continue
		}
		rebuilt := f.prefix + string(encoded)
		if f.carriage {
			rebuilt += "\r"
		}
		lines[f.line] = rebuilt
		changed = true
	}
	if !changed {
		return chunkStr, false
	}
	return strings.Join(lines, "\n"), true
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

		frame, ok := decodeFrame(payload)
		if !ok {
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
		rewrittenPayload, err := encodeJSON(frame)
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

// decodeFrame decodes one data payload as a JSON object. Numbers are kept as
// written (decodeJSON), so re-encoding a rewritten frame does not round an
// integer above 2^53 -- an "id" of 9007199254740993 came back as ...992.
func decodeFrame(payload string) (map[string]interface{}, bool) {
	doc, err := decodeJSON([]byte(payload))
	if err != nil {
		return nil, false
	}
	frame, ok := doc.(map[string]interface{})
	return frame, ok
}

// validatePayload validates payload against AWS Bedrock Guardrail, returning policy actions.
// A response body's type is sniffed; validatePayloadAs takes it from the response's
// Content-Type instead.
func (p *AWSBedrockGuardrailPolicy) validatePayload(payload []byte, params AWSBedrockGuardrailPolicyParams, isResponse bool, metadata map[string]interface{}) interface{} {
	return p.validatePayloadAs(payload, params, isResponse, metadata, "")
}

// validatePayloadAs is validatePayload for a body whose media type is known (""
// when it is not); see isEventStreamResponse.
func (p *AWSBedrockGuardrailPolicy) validatePayloadAs(payload []byte, params AWSBedrockGuardrailPolicyParams, isResponse bool, metadata map[string]interface{}, mediaType string) interface{} {
	// Putting a masked value back used to return here, so the restored response
	// was delivered without ever being assessed — the guardrail saw nothing of a
	// response whose own request had masked something. The restoration now
	// happens in place and the assessment continues on the restored text, which
	// is what the client will receive.
	restored := false
	if !params.RedactPII && isResponse {
		if maskedPII, exists := metadata[MetadataKeyPIIEntities]; exists {
			if maskedPIIMap, ok := maskedPII.(map[string]string); ok {
				if restoredContent, changed := p.restorePayload(payload, maskedPIIMap); changed {
					payload = restoredContent
					restored = true
				}
			}
		}
	}

	if payload == nil {
		return noModification(isResponse, nil)
	}

	// A streamed LLM body can reach this buffered path: the engine demotes the
	// whole chain to buffered as soon as any policy declares BUFFER, and then an
	// SSE body arrives here whole. jsonPath addresses a non-streamed shape and
	// cannot match it, which answered 422 for a response the upstream had
	// returned 200 for. Read it as SSE instead — the same extraction the
	// streaming path uses, over the whole body.
	//
	// An MCP Streamable HTTP response is SSE too, but each of its events carries a
	// whole JSON-RPC message that jsonPath does address. Those take the general
	// extraction below, which applies jsonPath to every event; read with
	// streamingJsonPath they matched nothing and passed unassessed.
	//
	// Whether the body is SSE comes from the Content-Type or its first line, not
	// from an SSE-looking line somewhere in it (see isEventStreamResponse).
	// The JSON-RPC stream path validates one batch of events at a time, and a
	// batch may hold no JSON-RPC message of its own; it is read with jsonPath all
	// the same, as the whole stream is.
	//
	// An empty jsonPath means "assess the whole payload", for an event stream as
	// for anything else, so such a body is assessed whole as text (see
	// extractPayload) and is never read as events.
	forceJSONRPC := mediaType == jsonRPCEventStream
	if forceJSONRPC {
		mediaType = "text/event-stream"
	}
	eventStream := isResponse && params.JsonPath != "" && isEventStreamResponse(mediaType, payload)
	if eventStream {
		if !forceJSONRPC && !sseCarriesJSONRPC(payload) {
			return p.validateStreamedBody(payload, params, metadata, restored)
		}
		// A JSON-RPC event stream: an event whose data is not JSON would be
		// skipped by the extraction below and delivered without being read.
		if !params.PassthroughOnError && unreadableEventStream(string(payload)) {
			err := errors.New("the event stream has text outside any event, or a data payload that is not JSON")
			return p.passOrBlock("Error extracting value from JSONPath", err, params, true, nil,
				extractionFault("Error extracting value from JSONPath", err, true), payload, restored)
		}
	}

	// An event stream is read as one even when it opens with a line that is not an
	// SSE field: re-sniffing it here would reject what the checks above accepted
	// (with passthroughOnError, deliver it unassessed).
	extracted, err := extractFirstHit(payload, params.extractionPaths(), eventStream)
	if err == nil && extracted.missed != nil {
		if !params.PassthroughOnError {
			err = extracted.missed
		} else {
			// Only the content the path missed passes unassessed; the events it
			// does match are assessed as usual.
			slog.Debug("AWSBedrockGuardrail: some content has no value at jsonPath, passthrough enabled; assessing the rest",
				"error", extracted.missed)
		}
	}
	if err != nil {
		return p.passOrBlock("Error extracting value from JSONPath", err, params, isResponse, nil,
			extractionFault("Error extracting value from JSONPath", err, isResponse), payload, restored)
	}

	contents := make([]string, 0, len(extracted.segments))
	for _, segment := range extracted.segments {
		if text := strings.TrimSpace(textCleanRegexCompiled.ReplaceAllString(segment.value, "")); text != "" {
			contents = append(contents, text)
		}
	}
	if len(contents) == 0 {
		// Nothing to assess: an MCP initialize or tools/list, say, or a JSON-RPC
		// notification. Deliver whatever restoration did.
		slog.Debug("AWSBedrockGuardrail: no text to validate", "paths", params.extractionPaths(), "isResponse", isResponse)
		return noModification(isResponse, restoredBody(payload, restored))
	}

	output, stop := p.assessContents(contents, params, isResponse, payload, restored)
	if stop != nil {
		return stop
	}

	violation, replacements, err := p.decide(output, params, isResponse, metadata, strings.Join(contents, "\n"))
	if err != nil {
		return p.passOrBlock("Error evaluating guardrail response", err, params, isResponse, output,
			checkFailureFault("Error evaluating guardrail response", isResponse), payload, restored)
	}
	if violation {
		slog.Debug("AWSBedrockGuardrail: Violation detected", "isResponse", isResponse)
		return p.buildErrorResponse("Violation of AWS Bedrock Guardrails detected", nil, isResponse, params.ShowAssessment, output)
	}

	changed := false
	for _, segment := range extracted.segments {
		if masked := applyPIIReplacements(segment.value, replacements); masked != segment.value {
			segment.set(masked)
			changed = true
		}
	}
	if !changed {
		slog.Debug("AWSBedrockGuardrail: Validation passed", "isResponse", isResponse)
		return noModification(isResponse, restoredBody(payload, restored))
	}
	if isResponse && extracted.stripLogprobs != nil {
		// The masked value is also in the tokens of the response's log
		// probabilities.
		extracted.stripLogprobs()
	}

	modifiedPayload, err := extracted.rebuild()
	if err != nil {
		// Never forward the unmasked payload when masking was required.
		slog.Debug("AWSBedrockGuardrail: failed to rebuild masked payload", "error", err, "isResponse", isResponse)
		// The guardrail's verdict allowed the content; what failed is this policy
		// writing the masks back, so the fault is a mediation one.
		return withFault(p.buildErrorResponse("Error updating payload with masked content", err, isResponse, params.ShowAssessment, output),
			checkFailureFault("Error updating payload with masked content", isResponse))
	}
	slog.Debug("AWSBedrockGuardrail: Content modified by guardrail", "isResponse", isResponse)
	return noModification(isResponse, modifiedPayload)
}

// validateStreamedBody assesses an LLM event stream that arrived whole on the
// buffered path, reading assistant text with streamingJsonPath.
func (p *AWSBedrockGuardrailPolicy) validateStreamedBody(payload []byte, params AWSBedrockGuardrailPolicyParams, metadata map[string]interface{}, restored bool) interface{} {
	if refusesUnreadableBody(string(payload), params) {
		// Text this reader cannot extract would be delivered unassessed; finding no
		// frames in it is not the same as it carrying no text. With
		// passthroughOnError the readable text is still assessed below.
		err := errors.New("the event stream has text outside any event, a data payload that is not JSON, or output streamingJsonPath does not read")
		return p.passOrBlock("Error extracting value from JSONPath", err, params, true, nil,
			extractionFault("Error extracting value from JSONPath", err, true), payload, restored)
	}
	if key := streamingPathKey(params.StreamingJsonPath); key != "" && !params.PassthroughOnError {
		if matched, unmatched := streamingPathMatches(string(payload), key); !matched && unmatched {
			err := errors.New("streamingJsonPath matches no event of the event stream")
			return p.passOrBlock("Error extracting value from JSONPath", err, params, true, nil,
				extractionFault("Error extracting value from JSONPath", err, true), payload, restored)
		}
	}
	extractedValue := strings.TrimSpace(textCleanRegexCompiled.ReplaceAllString(
		extractSSEDeltaContent(string(payload), params.StreamingJsonPath), ""))
	if extractedValue == "" {
		// Framing only — nothing to assess. Deliver whatever restoration did.
		return noModification(true, restoredBody(payload, restored))
	}

	output, stop := p.assessContents([]string{extractedValue}, params, true, payload, restored)
	if stop != nil {
		return stop
	}
	violation, replacements, err := p.decide(output, params, true, metadata, extractedValue)
	if err != nil {
		return p.passOrBlock("Error evaluating guardrail response", err, params, true, output,
			checkFailureFault("Error evaluating guardrail response", true), payload, restored)
	}
	if violation {
		return p.buildErrorResponse("Violation of AWS Bedrock Guardrails detected", nil, true, params.ShowAssessment, output)
	}
	if len(replacements) == 0 || applyPIIReplacements(extractedValue, replacements) == extractedValue {
		return noModification(true, restoredBody(payload, restored))
	}

	// A value spanning several events is written back across them; one that still
	// survives is a failure rather than something to deliver.
	rewritten, _, leaked := p.redactedFlush(string(payload), output, params, metadata)
	if leaked {
		slog.Debug("AWSBedrockGuardrail: redaction could not be applied across events")
		// No assessment in the body: it would carry the value that could not be
		// masked.
		return withFault(p.buildErrorResponse("Sensitive content could not be redacted in a streamed response",
			errRedactionFailed, true, false, nil),
			checkFailureFault("Sensitive content could not be redacted in a streamed response", true))
	}
	return noModification(true, []byte(rewritten))
}

// assessContents calls ApplyGuardrail on every text in one request. A failure to
// reach or configure AWS returns the action to take instead of an assessment.
func (p *AWSBedrockGuardrailPolicy) assessContents(contents []string, params AWSBedrockGuardrailPolicyParams, isResponse bool, payload []byte, restored bool) (*bedrockruntime.ApplyGuardrailOutput, interface{}) {
	loadConfig := p.loadAWSConfigFunc
	if loadConfig == nil {
		loadConfig = p.loadAWSConfig
	}
	awsCfg, err := loadConfig(context.Background(), p.region)
	if err != nil {
		return nil, p.passOrBlock("Error loading AWS config", err, params, isResponse, nil,
			checkFailureFault("Error loading AWS config", isResponse), payload, restored)
	}
	output, err := p.applyBedrockGuardrail(context.Background(), awsCfg, p.guardrailID, p.guardrailVersion, guardrailSource(isResponse), contents...)
	if err != nil {
		return nil, p.passOrBlock("Error calling AWS Bedrock Guardrail", err, params, isResponse, nil,
			checkFailureFault("Error calling AWS Bedrock Guardrail", isResponse), payload, restored)
	}
	return output, nil
}

// decide turns an assessment into a verdict and, when the content may pass, the
// replacements to make in it (see evaluateGuardrailResponse for the rules).
func (p *AWSBedrockGuardrailPolicy) decide(output *bedrockruntime.ApplyGuardrailOutput, params AWSBedrockGuardrailPolicyParams, isResponse bool, metadata map[string]interface{}, text string) (bool, []piiReplacement, error) {
	violation, _, err := p.evaluateGuardrailResponse(output, "", params.RedactPII, !isResponse, metadata)
	if err != nil || violation {
		return violation, nil, err
	}
	if output.Action != types.GuardrailActionGuardrailIntervened {
		return false, nil, nil
	}
	return false, p.piiReplacements(output, params.RedactPII, !isResponse, metadata, text), nil
}

// passOrBlock answers a check that could not run: passes the payload when
// passthroughOnError is set, and blocks it otherwise. The fault says why the check
// could not run (there is no guardrail verdict), so it replaces the verdict fault
// buildErrorResponse declares.
func (p *AWSBedrockGuardrailPolicy) passOrBlock(reason string, err error, params AWSBedrockGuardrailPolicyParams, isResponse bool, output interface{}, fault *policy.FaultDetails, payload []byte, restored bool) interface{} {
	if params.PassthroughOnError {
		slog.Debug("AWSBedrockGuardrail: "+reason+", passthrough enabled", "error", err, "isResponse", isResponse)
		// Restoration already happened in place, so passing through without the
		// body would send the placeholder to the client.
		return noModification(isResponse, restoredBody(payload, restored))
	}
	slog.Debug("AWSBedrockGuardrail: "+reason, "error", err, "isResponse", isResponse)
	return withFault(p.buildErrorResponse(reason, err, isResponse, params.ShowAssessment, output), fault)
}

// noModification passes the payload on, replacing its body when body is set.
func noModification(isResponse bool, body []byte) interface{} {
	if isResponse {
		return policy.DownstreamResponseModifications{Body: body}
	}
	return policy.UpstreamRequestModifications{Body: body}
}

func restoredBody(payload []byte, restored bool) []byte {
	if restored {
		return payload
	}
	return nil
}

// sseCarriesJSONRPC reports whether any event of an SSE body is a JSON-RPC
// message — an MCP Streamable HTTP response rather than an LLM token stream.
// An event's data lines are joined first, as the SSE specification does, so a
// message split over several data lines is still recognised.
func sseCarriesJSONRPC(payload []byte) bool {
	for _, event := range splitEvents(payload) {
		data, ok := eventData(event.lines)
		if !ok {
			continue
		}
		if doc, err := decodeJSON([]byte(data)); err == nil && isJSONRPCMessage(doc) {
			return true
		}
	}
	return false
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

	errorResponse := p.buildGuardrailErrorResponse(reason, validationError, isResponse, showAssessment, output)

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
			IsFault:           true,
			Fault:             errorResponse,
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
		IsFault:           true,
		Fault:             errorResponse,
	}
}
