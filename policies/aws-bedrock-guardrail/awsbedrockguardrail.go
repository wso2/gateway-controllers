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

	// ResponseDefaultStreamingJSONPath locates the assistant text inside one SSE
	// data frame. A streamed response carries text incrementally under
	// choices[0].delta.content, so ResponseDefaultJSONPath — which addresses the
	// non-streamed choices[0].message.content — never matches on a stream. The
	// two paths cannot be collapsed into one: they address different shapes of
	// the same response.
	ResponseDefaultStreamingJSONPath = "$.choices[0].delta.content"

	// StreamingEnabledByDefault keeps the response flow buffered unless an API
	// author opts in. Buffered is what every release up to v1.1.0 did, and the
	// opt-in is what makes this version a drop-in replacement for it.
	StreamingEnabledByDefault = false

	// DefaultStreamingWindowBytes is how much of the response is accumulated
	// before each ApplyGuardrail call. Unlike the guardrails that compute their
	// verdict locally, every validation here is a billed AWS round trip, so
	// validating per chunk would add a round trip between every pair of tokens
	// and bill one call per token. The window trades detection granularity for
	// cost and time-to-next-token; see the policy definition for the tradeoff.
	DefaultStreamingWindowBytes = 2048

	// MinStreamingWindowBytes floors the configured window. A window below this
	// approaches per-chunk validation, which is the cost blow-up the window
	// exists to prevent.
	MinStreamingWindowBytes = 256

	sseDataPrefix  = "data: "
	sseEventPrefix = "event:"
	sseDone        = "[DONE]"

	// metaKeyAccStreamedContent accumulates the assistant text already validated
	// in this stream, so the final window can be recognised as such.
	metaKeyAccStreamedContent = "awsbedrockguardrail:streamed_content"

	// metaKeyAccStreamedJSONBody accumulates a non-SSE chunked body across
	// flushes, so it can be validated whole at end of stream.
	metaKeyAccStreamedJSONBody = "awsbedrockguardrail:streamed_json_body"
)

var textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)

type bedrockGuardrailClient interface {
	ApplyGuardrail(ctx context.Context, params *bedrockruntime.ApplyGuardrailInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error)
}

// AWSBedrockGuardrailPolicy implements AWS Bedrock Guardrail validation
type AWSBedrockGuardrailPolicy struct {
	// Static configuration from params
	region             string
	guardrailID        string
	guardrailVersion   string
	awsAccessKeyID     string
	awsSecretAccessKey string
	awsSessionToken    string
	awsRoleARN         string
	awsRoleRegion      string
	awsRoleExternalID  string

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

	// Streaming applies to the response flow only. When false the response is
	// buffered and validated whole, exactly as in v1.1.0.
	Streaming bool

	// StreamingJsonPath addresses the assistant text inside one SSE data frame.
	// Unused when Streaming is false.
	StreamingJsonPath string

	// StreamingWindowBytes is how many bytes of the response accumulate before
	// each ApplyGuardrail call. Unused when Streaming is false.
	StreamingWindowBytes int
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// Validate and extract static configuration from params
	if err := validateAWSConfigParams(params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// guardrailID/guardrailVersion can each be set directly on this policy
	// attachment (localGuardrailID/localGuardrailVersion), or left unset to
	// use the gateway-wide systemParameters value of the same setting.
	guardrailID, err := resolveGuardrailParam(params, "localGuardrailID", "guardrailID")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	guardrailVersion, err := resolveGuardrailParam(params, "localGuardrailVersion", "guardrailVersion")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	p := &AWSBedrockGuardrailPolicy{
		region:           getStringParam(params, "region"),
		guardrailID:      guardrailID,
		guardrailVersion: guardrailVersion,
	}
	p.loadAWSConfigFunc = p.loadAWSConfig
	p.newBedrockClientFunc = func(cfg aws.Config) bedrockGuardrailClient {
		return bedrockruntime.NewFromConfig(cfg)
	}

	// Optional AWS credentials
	if val, ok := params["awsAccessKeyID"]; ok {
		if str, ok := val.(string); ok {
			p.awsAccessKeyID = str
		}
	}
	if val, ok := params["awsSecretAccessKey"]; ok {
		if str, ok := val.(string); ok {
			p.awsSecretAccessKey = str
		}
	}
	if val, ok := params["awsSessionToken"]; ok {
		if str, ok := val.(string); ok {
			p.awsSessionToken = str
		}
	}
	if val, ok := params["awsRoleARN"]; ok {
		if str, ok := val.(string); ok {
			p.awsRoleARN = str
		}
	}
	if val, ok := params["awsRoleRegion"]; ok {
		if str, ok := val.(string); ok {
			p.awsRoleRegion = str
		}
	}
	if val, ok := params["awsRoleExternalID"]; ok {
		if str, ok := val.(string); ok {
			p.awsRoleExternalID = str
		}
	}

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

	slog.Debug("AWSBedrockGuardrail: Policy initialized", "region", p.region, "guardrailID", p.guardrailID, "guardrailVersion", p.guardrailVersion, "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

// Mode returns the processing mode for the AWS Bedrock guardrail policy.
// Mode declares this instance's body requirements from its own configuration.
//
// Up to v1.1.0 this returned BodyModeBuffer unconditionally, which had two
// consequences an API author could not configure away. A flow the attachment
// does not use still had its body buffered, so a request-only attachment forced
// the whole response to be held; and because the kernel clears
// SupportsResponseStreaming for the entire chain as soon as any policy declares
// BUFFER, one such attachment also demoted every other policy on the route to
// buffered. Declaring SKIP for an unused flow removes both.
//
// The response flow declares STREAM only when streaming is explicitly enabled,
// so an attachment carried over from v1.1.0 keeps buffering and keeps the
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
		JsonPath:             RequestDefaultJSONPath,
		Enabled:              RequestFlowEnabledByDefault,
		Streaming:            StreamingEnabledByDefault,
		StreamingJsonPath:    ResponseDefaultStreamingJSONPath,
		StreamingWindowBytes: DefaultStreamingWindowBytes,
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

	// The streaming parameters below configure the response flow only. Accepting
	// them on the request flow would imply the request can be validated
	// incrementally, which it cannot: a request must be validated whole before it
	// reaches the upstream, or there is nothing left to block.
	if !isResponse {
		for _, key := range []string{"streaming", "streamingJsonPath", "streamingWindowBytes"} {
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

	// Extract optional streamingWindowBytes parameter
	if windowRaw, ok := params["streamingWindowBytes"]; ok {
		window, err := extractInt(windowRaw)
		if err != nil {
			return result, fmt.Errorf("'streamingWindowBytes' must be a number: %w", err)
		}
		if window < MinStreamingWindowBytes {
			return result, fmt.Errorf("'streamingWindowBytes' must be at least %d", MinStreamingWindowBytes)
		}
		result.StreamingWindowBytes = window
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

// getStringParam safely extracts a string parameter
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// resolveGuardrailParam returns the value for a guardrail identity setting
// (guardrailID/guardrailVersion) that can be supplied directly on this policy
// attachment (attachmentKey, from "parameters") or via the gateway-wide
// systemParameters value of the same setting (systemKey, resolved from
// config.toml into the same flat params map). At least one must resolve to a
// non-empty string.
func resolveGuardrailParam(params map[string]interface{}, attachmentKey, systemKey string) (string, error) {
	if val, ok := params[attachmentKey]; ok {
		str, ok := val.(string)
		if !ok {
			return "", fmt.Errorf("'%s' must be a string", attachmentKey)
		}
		if str == "" {
			return "", fmt.Errorf("'%s' cannot be empty", attachmentKey)
		}
		return str, nil
	}
	if val, ok := params[systemKey]; ok {
		str, ok := val.(string)
		if !ok {
			return "", fmt.Errorf("'%s' must be a string", systemKey)
		}
		if str == "" {
			return "", fmt.Errorf("'%s' cannot be empty", systemKey)
		}
		return str, nil
	}
	return "", fmt.Errorf("one of '%s' or '%s' parameter is required", attachmentKey, systemKey)
}

// validateAWSConfigParams validates AWS configuration parameters (from params)
func validateAWSConfigParams(params map[string]interface{}) error {
	// Validate region (required)
	regionRaw, ok := params["region"]
	if !ok {
		return fmt.Errorf("'region' parameter is required")
	}
	region, ok := regionRaw.(string)
	if !ok {
		return fmt.Errorf("'region' must be a string")
	}
	if region == "" {
		return fmt.Errorf("'region' cannot be empty")
	}

	// Validate optional AWS credential parameters
	if awsAccessKeyIDRaw, ok := params["awsAccessKeyID"]; ok {
		awsAccessKeyID, ok := awsAccessKeyIDRaw.(string)
		if !ok {
			return fmt.Errorf("'awsAccessKeyID' must be a string")
		}
		if awsAccessKeyID == "" {
			return fmt.Errorf("'awsAccessKeyID' cannot be empty")
		}
	}

	if awsSecretAccessKeyRaw, ok := params["awsSecretAccessKey"]; ok {
		awsSecretAccessKey, ok := awsSecretAccessKeyRaw.(string)
		if !ok {
			return fmt.Errorf("'awsSecretAccessKey' must be a string")
		}
		if awsSecretAccessKey == "" {
			return fmt.Errorf("'awsSecretAccessKey' cannot be empty")
		}
	}

	if awsSessionTokenRaw, ok := params["awsSessionToken"]; ok {
		_, ok := awsSessionTokenRaw.(string)
		if !ok {
			return fmt.Errorf("'awsSessionToken' must be a string")
		}
	}

	if awsRoleARNRaw, ok := params["awsRoleARN"]; ok {
		awsRoleARN, ok := awsRoleARNRaw.(string)
		if !ok {
			return fmt.Errorf("'awsRoleARN' must be a string")
		}

		// If role ARN is provided, validate role region
		if awsRoleARN != "" {
			// If role ARN is provided and not empty, validate role region
			awsRoleRegionRaw, ok := params["awsRoleRegion"]
			if !ok {
				return fmt.Errorf("'awsRoleRegion' is required when 'awsRoleARN' is specified")
			}

			awsRoleRegion, ok := awsRoleRegionRaw.(string)
			if !ok {
				return fmt.Errorf("'awsRoleRegion' must be a string")
			}

			if awsRoleRegion == "" {
				return fmt.Errorf("'awsRoleRegion' cannot be empty when 'awsRoleARN' is specified")
			}
		}
	}

	if awsRoleExternalIDRaw, ok := params["awsRoleExternalID"]; ok {
		_, ok := awsRoleExternalIDRaw.(string)
		if !ok {
			return fmt.Errorf("'awsRoleExternalID' must be a string")
		}
	}

	return nil
}

// loadAWSConfig creates AWS configuration with custom credentials and role assumption
func (p *AWSBedrockGuardrailPolicy) loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	// Use AWS credentials from policy instance (params)
	accessKeyID := p.awsAccessKeyID
	secretAccessKey := p.awsSecretAccessKey
	sessionToken := p.awsSessionToken
	roleARN := p.awsRoleARN
	roleRegion := p.awsRoleRegion
	roleExternalID := p.awsRoleExternalID

	// Check if role-based authentication should be used
	if roleARN != "" && roleRegion != "" {
		return p.loadAWSConfigWithAssumeRole(ctx, accessKeyID, secretAccessKey, sessionToken, roleARN, roleRegion, roleExternalID, region)
	} else if accessKeyID != "" && secretAccessKey != "" {
		return p.loadAWSConfigWithStaticCredentials(ctx, accessKeyID, secretAccessKey, sessionToken, region)
	} else {
		// Use default credential chain
		return config.LoadDefaultConfig(ctx, config.WithRegion(region))
	}
}

// loadAWSConfigWithStaticCredentials creates AWS config with static credentials
func (p *AWSBedrockGuardrailPolicy) loadAWSConfigWithStaticCredentials(ctx context.Context, accessKeyID, secretAccessKey, sessionToken, region string) (aws.Config, error) {
	var credsProvider aws.CredentialsProvider
	if sessionToken != "" {
		credsProvider = credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
	} else {
		credsProvider = credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credsProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config with static credentials: %w", err)
	}

	return cfg, nil
}

// loadAWSConfigWithAssumeRole creates AWS config with role assumption
func (p *AWSBedrockGuardrailPolicy) loadAWSConfigWithAssumeRole(ctx context.Context, accessKeyID, secretAccessKey, sessionToken, roleARN, roleRegion, roleExternalID, region string) (aws.Config, error) {
	// Create base config for role assumption
	var baseCfg aws.Config
	var err error

	if accessKeyID != "" && secretAccessKey != "" {
		var baseCredsProvider aws.CredentialsProvider
		if sessionToken != "" {
			baseCredsProvider = credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
		} else {
			baseCredsProvider = credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
		}

		baseCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(roleRegion),
			config.WithCredentialsProvider(baseCredsProvider),
		)
	} else {
		baseCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(roleRegion))
	}

	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load base AWS config for role assumption: %w", err)
	}

	// Create STS client for role assumption
	stsClient := sts.NewFromConfig(baseCfg)

	// Create assume role credentials provider
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		if roleExternalID != "" {
			o.ExternalID = aws.String(roleExternalID)
		}
		o.RoleSessionName = "bedrock-guardrail-session"
	})

	// Load final config with assumed role credentials for the target region
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(assumeRoleProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config with assume role: %w", err)
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
			assessment["assessments"] = []string{validationError.Error()}
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
// Three cases:
//
//   - A body that is not SSE (plain JSON over chunked transfer) accumulates
//     whole. Such a response is not incrementally consumable by a client
//     anyway, so there is no latency to protect, and holding it keeps the
//     buffered path's property that nothing reaches the client until it has
//     been validated. The kernel always flushes at end of stream, so this
//     cannot stall.
//   - Below the window, keep accumulating.
//   - At or past the window, release — but only on an SSE event boundary. A
//     flush cut through the middle of a `data:` line leaves JSON that no
//     JSONPath can read, which is what produces the "Error extracting value
//     from JSONPath" failure this path exists to avoid.
func (p *AWSBedrockGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if !p.hasResponseParams || !p.responseParams.Enabled || !p.responseParams.Streaming {
		return false
	}
	if !isSSEChunk(string(accumulated)) {
		return true
	}
	if len(accumulated) < p.responseParams.StreamingWindowBytes {
		return true
	}
	return !endsAtSSEEventBoundary(accumulated)
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
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}

	chunkStr := string(chunk.Chunk)
	if !isSSEChunk(chunkStr) {
		return p.handleNonSSEStreamFlush(chunkStr, chunk, respCtx)
	}
	return p.handleSSEStreamFlush(chunkStr, chunk, respCtx)
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
		// Only reachable when the kernel force-flushed at its accumulator
		// ceiling. The body is already past any size this policy should be
		// validating as one payload, and it is on its way to the client, so
		// there is nothing to decide here.
		slog.Warn("AWSBedrockGuardrail: non-SSE response flushed before end of stream, validation deferred",
			"accumulated_bytes", len(full))
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
		return policy.ForwardResponseChunk{Body: modifications.Body}
	}
	return policy.ForwardResponseChunk{}
}

// handleSSEStreamFlush validates one window of a streamed response.
func (p *AWSBedrockGuardrailPolicy) handleSSEStreamFlush(
	chunkStr string,
	chunk *policy.StreamBody,
	respCtx *policy.ResponseStreamContext,
) policy.StreamingResponseAction {
	rp := p.responseParams

	windowText := extractSSEDeltaContent(chunkStr, rp.StreamingJsonPath)
	if strings.TrimSpace(windowText) == "" {
		// A flush carrying only framing — the opening role delta, a keep-alive
		// comment, usage, [DONE]. There is nothing to validate, but a masked
		// placeholder may still need restoring before it reaches the client.
		return p.forwardWithPIIRestored(chunkStr, respCtx, rp)
	}

	cleaned := strings.TrimSpace(textCleanRegexCompiled.ReplaceAllString(windowText, ""))

	output, err := p.applyGuardrailToText(cleaned)
	if err != nil {
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: streaming guardrail call failed, passthrough enabled",
				"error", err, "chunkIndex", chunk.Index)
			return p.forwardWithPIIRestored(chunkStr, respCtx, rp)
		}
		slog.Debug("AWSBedrockGuardrail: streaming guardrail call failed",
			"error", err, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Error calling AWS Bedrock Guardrail", err, rp.ShowAssessment, nil),
			AnalyticsMetadata: guardrailHitAnalytics(),
		}
	}

	violation, modifiedContent, err := p.evaluateGuardrailResponse(output, cleaned, rp.RedactPII, false, respCtx.Metadata)
	if err != nil {
		if rp.PassthroughOnError {
			slog.Debug("AWSBedrockGuardrail: streaming guardrail evaluation failed, passthrough enabled",
				"error", err, "chunkIndex", chunk.Index)
			return p.forwardWithPIIRestored(chunkStr, respCtx, rp)
		}
		slog.Debug("AWSBedrockGuardrail: streaming guardrail evaluation failed",
			"error", err, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Error evaluating guardrail response", err, rp.ShowAssessment, output),
			AnalyticsMetadata: guardrailHitAnalytics(),
		}
	}

	if violation {
		slog.Debug("AWSBedrockGuardrail: streaming violation detected",
			"chunkIndex", chunk.Index, "windowBytes", len(chunkStr))
		return policy.TerminateResponseChunk{
			Body:              p.buildSSEErrorEvent("Violation of AWS Bedrock Guardrails detected", nil, rp.ShowAssessment, output),
			AnalyticsMetadata: guardrailHitAnalytics(),
		}
	}

	// Record what has been validated so far. Nothing in this file reads it back
	// to make a decision; it is here so the accumulated text is available for
	// debugging a stream and for any end-of-stream check added later.
	previous, _ := respCtx.Metadata[metaKeyAccStreamedContent].(string)
	respCtx.Metadata[metaKeyAccStreamedContent] = previous + windowText

	if rp.RedactPII && modifiedContent != "" && modifiedContent != cleaned {
		if typed, ok := output.(*bedrockruntime.ApplyGuardrailOutput); ok {
			rewritten, changed := rewriteSSEDeltaContent(chunkStr, rp.StreamingJsonPath, func(frameText string) string {
				return p.extractRedactedContent(typed, frameText)
			})
			if changed {
				return policy.ForwardResponseChunk{Body: []byte(rewritten)}
			}
		}
	}

	return p.forwardWithPIIRestored(chunkStr, respCtx, rp)
}

// forwardWithPIIRestored forwards a flush, first putting back any value this
// request's own request flow masked on the way to the upstream. The buffered
// path does this at the top of validatePayload; a streamed response needs it
// per flush, frame by frame, because there is no single payload to rewrite.
//
// Limitation worth knowing: a placeholder is restored only where it appears
// whole inside one frame's text. An upstream that splits `EMAIL_0000` across
// two SSE events leaves each half unmatched and the client sees the
// placeholder. Masked output reaching the client is visible rather than silent,
// and it is no worse than the buffered path, which cannot read an SSE body at
// all — but it is not a guarantee, and an API that needs one should keep the
// response flow buffered.
func (p *AWSBedrockGuardrailPolicy) forwardWithPIIRestored(
	chunkStr string,
	respCtx *policy.ResponseStreamContext,
	rp AWSBedrockGuardrailPolicyParams,
) policy.StreamingResponseAction {
	if rp.RedactPII {
		return policy.ForwardResponseChunk{}
	}
	raw, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.ForwardResponseChunk{}
	}
	maskedPII, ok := raw.(map[string]string)
	if !ok || len(maskedPII) == 0 {
		return policy.ForwardResponseChunk{}
	}

	rewritten, changed := rewriteSSEDeltaContent(chunkStr, rp.StreamingJsonPath, func(frameText string) string {
		return p.restorePIIInResponse(frameText, maskedPII)
	})
	if !changed {
		return policy.ForwardResponseChunk{}
	}
	return policy.ForwardResponseChunk{Body: []byte(rewritten)}
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

// isSSEChunk reports whether s looks like SSE framing.
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
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
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, sseDataPrefix) {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, sseDataPrefix))
		if payload == "" || payload == sseDone {
			continue
		}
		text, err := utils.ExtractStringValueFromJsonpath([]byte(payload), streamingJsonPath)
		if err != nil {
			continue
		}
		sb.WriteString(textCleanRegexCompiled.ReplaceAllString(text, ""))
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
		trimmed := strings.TrimRight(line, "\r")
		if !strings.HasPrefix(trimmed, sseDataPrefix) {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, sseDataPrefix))
		if payload == "" || payload == sseDone {
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

		rebuilt := sseDataPrefix + string(rewrittenPayload)
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
