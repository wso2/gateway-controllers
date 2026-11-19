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
 */

package semanticcache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	jevSystemOnePath       = "/v1/systemone"
	jevDefaultBaseURL      = "https://api.typesafe.ai"
	jevDefaultModel        = "jev-latest"
	jevDefaultTimeout      = 5 * time.Second
	jevMaxTimeout          = 30 * time.Second
	jevRetryBackoff        = 250 * time.Millisecond
	jevOverloadedStatus    = 529
	jevMaxResponseBytes    = 1 << 20
	jevResponseJSONPath    = "$.choices[0].message.content"
	jevMetadataDecisionKey = "semantic-cache:jev-check"
	jevMetadataUsageKey    = "semantic-cache:jev-usage"

	jevQuestionNoul  = "noul"
	jevQuestionScore = "score"

	jevDecisionStore = "store"
	jevDecisionSkip  = "skip"
)

type jevQuestion struct {
	Key          string
	Type         string
	Instructions string
	// Criteria holds the ordered scale levels for score.
	Criteria  []string
	Threshold float64
}

type jevCacheCheckConfig struct {
	Enabled   bool
	Questions []jevQuestion
	Timeout   time.Duration
	APIKey    string
	BaseURL   string
	Model     string
}

type jevDecision struct {
	Decision string
	Fired    []map[string]interface{}
	Error    string
}

type jevUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func defaultJevCacheQuestions() []jevQuestion {
	// Keep these questions in sync with the default shown in policy-definition.yaml.
	// TestDefaultJevCacheQuestionsMatchPolicyDefinition guards against drift.
	return []jevQuestion{
		{Key: "time_sensitive", Type: jevQuestionNoul, Instructions: "Does the answer in `response` depend on the current date or time, or on live information such as news, prices, weather, or stock levels?", Threshold: 0.7},
		{Key: "needs_context", Type: jevQuestionNoul, Instructions: "Does `request` only make sense together with earlier messages in the conversation, for example a follow-up like 'tell me more' or 'what about the second one'?", Threshold: 0.7},
		{Key: "unhelpful_response", Type: jevQuestionNoul, Instructions: "Is `response` a refusal, an error, or a reply saying the request couldn't be completed?", Threshold: 0.7},
		{Key: "sensitive_data", Type: jevQuestionNoul, Instructions: "Do `request` or `response` contain secrets, credentials, or personal data such as passwords, card numbers, or ID numbers?", Threshold: 0.7},
	}
}

func parseJevCacheCheck(params map[string]interface{}) (jevCacheCheckConfig, error) {
	cfg := jevCacheCheckConfig{Timeout: jevDefaultTimeout, BaseURL: jevDefaultBaseURL, Model: jevDefaultModel}
	raw, exists := params["jevCacheCheck"]
	if !exists || raw == nil {
		return cfg, nil
	}
	check, ok := raw.(map[string]interface{})
	if !ok {
		return cfg, fmt.Errorf("'jevCacheCheck' must be an object")
	}
	if enabledRaw, ok := check["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return cfg, fmt.Errorf("'jevCacheCheck.enabled' must be a boolean")
		}
		cfg.Enabled = enabled
	}
	if !cfg.Enabled {
		return cfg, nil
	}

	apiKey, _ := params["jevApiKey"].(string)
	if strings.TrimSpace(apiKey) == "" {
		return cfg, fmt.Errorf("'jevApiKey' is required when 'jevCacheCheck.enabled' is true")
	}
	cfg.APIKey = apiKey
	if baseURL, ok := params["jevBaseURL"].(string); ok && strings.TrimSpace(baseURL) != "" {
		cfg.BaseURL = strings.TrimRight(baseURL, "/")
	}
	if model, ok := params["jevModel"].(string); ok && strings.TrimSpace(model) != "" {
		cfg.Model = model
	}
	if timeoutRaw, ok := check["timeout"]; ok {
		timeoutString, ok := timeoutRaw.(string)
		if !ok {
			return cfg, fmt.Errorf("'jevCacheCheck.timeout' must be a duration string")
		}
		timeout, err := time.ParseDuration(timeoutString)
		if err != nil || timeout <= 0 || timeout > jevMaxTimeout {
			return cfg, fmt.Errorf("'jevCacheCheck.timeout' must be greater than 0 and at most %s", jevMaxTimeout)
		}
		cfg.Timeout = timeout
	}

	questionsRaw, ok := check["questions"]
	if !ok {
		cfg.Questions = defaultJevCacheQuestions()
		return cfg, nil
	}
	questionList, ok := questionsRaw.([]interface{})
	if !ok {
		return cfg, fmt.Errorf("'jevCacheCheck.questions' must be an array")
	}
	if len(questionList) == 0 {
		cfg.Questions = defaultJevCacheQuestions()
		return cfg, nil
	}

	seen := make(map[string]bool, len(questionList))
	for i, rawQuestion := range questionList {
		questionMap, ok := rawQuestion.(map[string]interface{})
		if !ok {
			return cfg, fmt.Errorf("'jevCacheCheck.questions[%d]' must be an object", i)
		}
		question, err := parseJevQuestion(questionMap, i)
		if err != nil {
			return cfg, err
		}
		if seen[question.Key] {
			return cfg, fmt.Errorf("'jevCacheCheck.questions[%d].key' %q is duplicated", i, question.Key)
		}
		seen[question.Key] = true
		cfg.Questions = append(cfg.Questions, question)
	}
	return cfg, nil
}

func parseJevQuestion(raw map[string]interface{}, index int) (jevQuestion, error) {
	prefix := fmt.Sprintf("jevCacheCheck.questions[%d]", index)
	question := jevQuestion{}
	question.Key, _ = raw["key"].(string)
	if question.Key == "" {
		return question, fmt.Errorf("'%s.key' is required", prefix)
	}
	question.Type, _ = raw["type"].(string)
	if question.Type != jevQuestionNoul && question.Type != jevQuestionScore {
		return question, fmt.Errorf("'%s.type' must be 'noul' or 'score'", prefix)
	}
	question.Instructions, _ = raw["instructions"].(string)
	if strings.TrimSpace(question.Instructions) == "" {
		return question, fmt.Errorf("'%s.instructions' is required", prefix)
	}
	threshold, err := extractFloat64(raw["threshold"])
	if err != nil {
		return question, fmt.Errorf("'%s.threshold' must be a number", prefix)
	}
	question.Threshold = threshold

	switch question.Type {
	case jevQuestionNoul:
		if threshold <= 0 || threshold > 1 {
			return question, fmt.Errorf("'%s.threshold' must be in (0, 1] for noul", prefix)
		}
	case jevQuestionScore:
		question.Criteria, err = jevStringList(raw["criteria"], prefix+".criteria")
		if err != nil || len(question.Criteria) < 2 || len(question.Criteria) > 10 {
			return question, fmt.Errorf("'%s.criteria' must contain 2 to 10 strings for score", prefix)
		}
		if threshold <= 0 || threshold > float64(len(question.Criteria)-1) {
			return question, fmt.Errorf("'%s.threshold' must be in (0, %d] for score", prefix, len(question.Criteria)-1)
		}
	}
	return question, nil
}

func jevStringList(raw interface{}, field string) ([]string, error) {
	values, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' must be an array", field)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("'%s' entries must be non-empty strings", field)
		}
		result = append(result, text)
	}
	return result, nil
}

func responseText(response map[string]interface{}) (string, error) {
	payload, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return utils.ExtractStringValueFromJsonpath(payload, jevResponseJSONPath)
}

func (p *SemanticCachePolicy) recordJevDecision(shared *policy.SharedContext, decision jevDecision, usage *jevUsage) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	value := map[string]interface{}{"decision": decision.Decision}
	if len(decision.Fired) > 0 {
		value["firedQuestions"] = decision.Fired
	}
	if decision.Error != "" {
		value["error"] = decision.Error
	}
	shared.Metadata[jevMetadataDecisionKey] = value
	if usage != nil {
		shared.Metadata[jevMetadataUsageKey] = map[string]interface{}{
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens,
		}
	}
}

type jevClient struct {
	url        string
	apiKey     string
	model      string
	timeout    time.Duration
	httpClient *http.Client
}

func newJevClient(config jevCacheCheckConfig) *jevClient {
	return &jevClient{
		url:        strings.TrimRight(config.BaseURL, "/") + jevSystemOnePath,
		apiKey:     config.APIKey,
		model:      config.Model,
		timeout:    config.Timeout,
		httpClient: newPolicyHTTPClient(0, true),
	}
}

type jevState struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type jevQuestionPayload struct {
	Type         string      `json:"type"`
	Instructions string      `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type jevRequest struct {
	State     jevState                      `json:"state"`
	Model     string                        `json:"model"`
	Questions map[string]jevQuestionPayload `json:"questions"`
}

func (client *jevClient) shouldStore(ctx context.Context, requestText, responseText string, questions []jevQuestion) (jevDecision, *jevUsage, error) {
	payloadQuestions := make(map[string]jevQuestionPayload, len(questions))
	for _, question := range questions {
		payload := jevQuestionPayload{Type: question.Type, Instructions: question.Instructions}
		if question.Type == jevQuestionScore {
			payload.Criteria = question.Criteria
		}
		payloadQuestions[question.Key] = payload
	}
	body, err := json.Marshal(jevRequest{State: jevState{Request: requestText, Response: responseText}, Model: client.model, Questions: payloadQuestions})
	if err != nil {
		return jevDecision{}, nil, fmt.Errorf("failed to serialize the Jev request")
	}

	callCtx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	status, responseBody, err := client.post(callCtx, body)
	if err == nil && (status == http.StatusTooManyRequests || status == jevOverloadedStatus) {
		timer := time.NewTimer(jevRetryBackoff)
		select {
		case <-callCtx.Done():
			timer.Stop()
			return jevDecision{}, nil, fmt.Errorf("the Jev request timed out")
		case <-timer.C:
		}
		status, responseBody, err = client.post(callCtx, body)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || callCtx.Err() != nil {
			return jevDecision{}, nil, fmt.Errorf("the Jev request timed out")
		}
		return jevDecision{}, nil, fmt.Errorf("the Jev request failed")
	}
	if status < 200 || status > 299 {
		return jevDecision{}, nil, fmt.Errorf("the Jev API returned status %d", status)
	}

	answers, usage, err := decodeJevAnswers(responseBody, questions)
	if err != nil {
		return jevDecision{}, usage, err
	}
	decision := jevDecision{Decision: jevDecisionStore}
	for _, question := range questions {
		value, detail, err := jevBlockingValue(question, answers[question.Key])
		if err != nil {
			return jevDecision{}, usage, fmt.Errorf("answer for question %q is invalid: %w", question.Key, err)
		}
		if value >= question.Threshold {
			detail["question"] = question.Key
			detail["type"] = question.Type
			detail["threshold"] = question.Threshold
			decision.Fired = append(decision.Fired, detail)
		}
	}
	if len(decision.Fired) > 0 {
		decision.Decision = jevDecisionSkip
	}
	return decision, usage, nil
}

func (client *jevClient) post(ctx context.Context, payload []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+client.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, jevMaxResponseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > jevMaxResponseBytes {
		return 0, nil, fmt.Errorf("the Jev response is too large")
	}
	return response.StatusCode, body, nil
}

func decodeJevAnswers(body []byte, questions []jevQuestion) (map[string]json.RawMessage, *jevUsage, error) {
	var response struct {
		Answers map[string]json.RawMessage `json:"answers"`
		Usage   *jevUsage                  `json:"usage"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil, fmt.Errorf("the Jev response is not valid JSON")
	}
	if response.Answers == nil {
		return nil, response.Usage, fmt.Errorf("the Jev response has no answers")
	}
	if response.Usage != nil && (response.Usage.InputTokens < 0 || response.Usage.OutputTokens < 0) {
		return nil, response.Usage, fmt.Errorf("the Jev response has invalid token usage")
	}
	expected := make(map[string]bool, len(questions))
	for _, question := range questions {
		expected[question.Key] = true
		if _, ok := response.Answers[question.Key]; !ok {
			return nil, response.Usage, fmt.Errorf("the Jev response has no answer for question %q", question.Key)
		}
	}
	for key := range response.Answers {
		if !expected[key] {
			return nil, response.Usage, fmt.Errorf("the Jev response contains an unknown answer %q", key)
		}
	}
	return response.Answers, response.Usage, nil
}

func jevBlockingValue(question jevQuestion, raw json.RawMessage) (float64, map[string]interface{}, error) {
	detail := make(map[string]interface{})
	switch question.Type {
	case jevQuestionNoul:
		var answer struct {
			Type string   `json:"type"`
			Noul *float64 `json:"noul"`
		}
		if err := json.Unmarshal(raw, &answer); err != nil || answer.Type != jevQuestionNoul || answer.Noul == nil || !validProbability(*answer.Noul) {
			return 0, nil, fmt.Errorf("expected a noul probability")
		}
		detail["value"] = *answer.Noul
		return *answer.Noul, detail, nil
	case jevQuestionScore:
		var answer struct {
			Type  string   `json:"type"`
			Score *float64 `json:"score"`
		}
		if err := json.Unmarshal(raw, &answer); err != nil || answer.Type != jevQuestionScore || answer.Score == nil || !finite(*answer.Score) || *answer.Score < 0 || *answer.Score > float64(len(question.Criteria)-1) {
			return 0, nil, fmt.Errorf("expected a score within the configured scale")
		}
		detail["value"] = *answer.Score
		return *answer.Score, detail, nil
	default:
		return 0, nil, fmt.Errorf("unsupported question type")
	}
}

func finite(value float64) bool           { return !math.IsNaN(value) && !math.IsInf(value, 0) }
func validProbability(value float64) bool { return finite(value) && value >= 0 && value <= 1 }
