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

package mistralmoderation

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultEndpoint = "https://api.mistral.ai"
	defaultModel    = "mistral-moderation-2603"
	// apiKeyEnvVar is read when the apiKey system parameter is empty, so the key can live in
	// the policy engine's environment instead of config.toml.
	apiKeyEnvVar = "MISTRAL_API_KEY"
	// endpointEnvVar overrides the Mistral base URL, for an egress proxy or a private
	// deployment. It is deliberately not a policy parameter: the gateway lets an API
	// definition override any system parameter, and an API developer who could choose the
	// endpoint could have the administrator's key sent to a host of their own.
	endpointEnvVar = "MISTRAL_MODERATION_ENDPOINT"

	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second

	// disabledThreshold switches a category off.
	disabledThreshold = -1

	// moderationModeText sends the text at jsonPath to POST /v1/moderations.
	moderationModeText = "text"
	// moderationModeConversation sends the chat messages to POST /v1/chat/moderations, which
	// classifies the last message in the context of the ones before it.
	moderationModeConversation = "conversation"

	defaultMessagesPath = "$.messages"

	// defaultStreamingJSONPath locates the reply text in one event of an OpenAI-style
	// streamed (stream: true) response.
	defaultStreamingJSONPath = "$.choices[0].delta.content"
)

// systemConfig is the gateway administrator's configuration.
type systemConfig struct {
	apiKey   string
	endpoint string
	model    string
}

// phaseParams is the API developer's configuration for one phase (request or response).
type phaseParams struct {
	// Enabled turns moderation of the phase on or off without removing its configuration.
	Enabled        bool
	ModerationMode string
	// MessagesPath locates the chat messages in the request body (conversation mode only).
	MessagesPath string
	JSONPath     string
	// StreamingJSONPath locates the reply text in each event of a streamed response, which is
	// reassembled into the complete reply before it is moderated (response only).
	StreamingJSONPath  string
	PassthroughOnError bool
	ShowAssessment     bool
	Timeout            time.Duration
	// Thresholds holds only enabled categories.
	Thresholds map[string]float64
}

// parseSystemConfig reads the gateway-level parameters. The key is never logged or echoed in
// an error.
func parseSystemConfig(params map[string]interface{}) (systemConfig, error) {
	apiKey, err := optionalString(params, "apiKey")
	if err != nil {
		return systemConfig{}, err
	}
	if strings.TrimSpace(apiKey) == "" {
		apiKey = os.Getenv(apiKeyEnvVar)
	}
	if strings.TrimSpace(apiKey) == "" {
		return systemConfig{}, fmt.Errorf("the Mistral API key is not configured: set 'api_key' under [policy_configurations.mistral_moderation_v1] in config.toml or the %s environment variable", apiKeyEnvVar)
	}

	endpoint := strings.TrimSpace(os.Getenv(endpointEnvVar))
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return systemConfig{}, fmt.Errorf("the %s environment variable must be an absolute http or https URL", endpointEnvVar)
	}

	model, err := optionalString(params, "model")
	if err != nil {
		return systemConfig{}, err
	}
	if strings.TrimSpace(model) == "" {
		model = defaultModel
	}

	return systemConfig{apiKey: strings.TrimSpace(apiKey), endpoint: endpoint, model: model}, nil
}

// parsePhaseParams parses and validates one phase's parameters.
func parsePhaseParams(params map[string]interface{}, defaultJSONPath string) (phaseParams, error) {
	result := phaseParams{
		Enabled:           true,
		ModerationMode:    moderationModeText,
		MessagesPath:      defaultMessagesPath,
		JSONPath:          defaultJSONPath,
		StreamingJSONPath: defaultStreamingJSONPath,
		Timeout:           defaultTimeout,
	}

	if raw, ok := params["enabled"]; ok {
		v, ok := boolParam(raw)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = v
	}

	if raw, ok := params["moderationMode"]; ok {
		mode, ok := raw.(string)
		if !ok || (mode != moderationModeText && mode != moderationModeConversation) {
			return result, fmt.Errorf("'moderationMode' must be %q or %q", moderationModeText, moderationModeConversation)
		}
		result.ModerationMode = mode
	}

	if raw, ok := params["messagesPath"]; ok {
		messagesPath, ok := raw.(string)
		if !ok || strings.TrimSpace(messagesPath) == "" {
			return result, fmt.Errorf("'messagesPath' must be a non-empty string")
		}
		result.MessagesPath = messagesPath
	}

	if raw, ok := params["jsonPath"]; ok {
		jsonPath, ok := raw.(string)
		if !ok {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
		result.JSONPath = jsonPath
	}

	if raw, ok := params["streamingJsonPath"]; ok {
		streamingJSONPath, ok := raw.(string)
		if !ok || strings.TrimSpace(streamingJSONPath) == "" {
			return result, fmt.Errorf("'streamingJsonPath' must be a non-empty string")
		}
		result.StreamingJSONPath = normalizeWildcards(streamingJSONPath)
	}

	if raw, ok := params["passthroughOnError"]; ok {
		v, ok := boolParam(raw)
		if !ok {
			return result, fmt.Errorf("'passthroughOnError' must be a boolean")
		}
		result.PassthroughOnError = v
	}

	if raw, ok := params["showAssessment"]; ok {
		v, ok := boolParam(raw)
		if !ok {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
		result.ShowAssessment = v
	}

	if raw, ok := params["timeout"]; ok {
		s, ok := raw.(string)
		if !ok {
			return result, fmt.Errorf("'timeout' must be a duration string (e.g. \"5s\")")
		}
		timeout, err := time.ParseDuration(s)
		if err != nil {
			return result, fmt.Errorf("'timeout' is not a valid duration: %w", err)
		}
		if timeout <= 0 || timeout > maxTimeout {
			return result, fmt.Errorf("'timeout' must be greater than 0 and at most %s", maxTimeout)
		}
		result.Timeout = timeout
	}

	thresholds, err := parseCategoryThresholds(params["categoryThresholds"])
	if err != nil {
		return result, err
	}
	result.Thresholds = thresholds

	return result, nil
}

// parseCategoryThresholds starts from defaultCategoryThresholds and applies the configured
// values on top. A value of -1 disables a category; any other value must be within 0 and 1.
// A category neither defaulted nor configured is not evaluated.
func parseCategoryThresholds(raw interface{}) (map[string]float64, error) {
	thresholds := make(map[string]float64, len(supportedCategories))
	for category, threshold := range defaultCategoryThresholds {
		thresholds[category] = threshold
	}
	if raw == nil {
		return thresholds, nil
	}

	configured, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("'categoryThresholds' must be an object")
	}
	for category, value := range configured {
		if !isSupportedCategory(category) {
			return nil, fmt.Errorf("'categoryThresholds' has unknown category %q; supported categories are %s",
				category, strings.Join(supportedCategories, ", "))
		}
		threshold, err := extractFloat(value)
		if err != nil {
			return nil, fmt.Errorf("'categoryThresholds.%s' must be a number: %w", category, err)
		}
		if threshold == disabledThreshold {
			delete(thresholds, category)
			continue
		}
		if threshold < 0 || threshold > 1 {
			return nil, fmt.Errorf("'categoryThresholds.%s' must be between 0 and 1, or -1 to disable the category", category)
		}
		thresholds[category] = threshold
	}
	return thresholds, nil
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return s, nil
}

// extractFloat accepts the numeric forms a parameter can arrive in: a JSON number, a Go
// integer, or a numeric string (gateways from 1.2.0 convert those).
func extractFloat(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	case nil:
		return 0, fmt.Errorf("value is required")
	default:
		return 0, fmt.Errorf("cannot convert %T to number", value)
	}
}

// boolParam reads a boolean parameter. The gateway's schema check accepts the strings "true" and
// "false" for a boolean, so they are read as booleans too.
func boolParam(raw interface{}) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		switch v {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}
