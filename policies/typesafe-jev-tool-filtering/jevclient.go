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

package typesafejevtoolfiltering

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	systemOnePath       = "/v1/systemone"
	questionTypeNoul    = "noul"
	questionIDPrefix    = "tool_"
	statusJevOverloaded = 529
	retryBackoff        = 250 * time.Millisecond

	questionInstructionsFormat = "Would `tools[%d]` be materially useful for completing `prompt`?"
	criterionTrue              = "The tool can directly complete a necessary part of the request."
	criterionFalse             = "The tool does not contribute to completing the request."
)

// jevState is the structured state Jev reasons over: the user's prompt and
// the normalized tool metadata, in the order the questions reference.
type jevState struct {
	Prompt string           `json:"prompt"`
	Tools  []normalizedTool `json:"tools"`
}

type jevQuestionCriteria struct {
	True  string `json:"true,omitempty"`
	False string `json:"false,omitempty"`
}

type jevQuestionPayload struct {
	Type         string               `json:"type"`
	Instructions string               `json:"instructions"`
	Criteria     *jevQuestionCriteria `json:"criteria,omitempty"`
}

// jevSystemOneRequest carries object state, unlike the plain-text state the
// typesafe-jev-guardrail policy sends.
type jevSystemOneRequest struct {
	State     any                           `json:"state"`
	Model     string                        `json:"model"`
	Questions map[string]jevQuestionPayload `json:"questions"`
}

// jevUsage is TypeSafe's token accounting for one System One evaluation.
type jevUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// questionID is the stable identifier for the tool at position index of the
// state's tools array. Positions, not descriptions, identify tools: two tools
// may legitimately carry identical descriptions.
func questionID(index int) string {
	return fmt.Sprintf("%s%d", questionIDPrefix, index)
}

// buildQuestions creates one Noul question per normalized tool. Noul rather
// than Choice: several tools can independently be useful for one prompt, so
// the judgements must be independent rather than mutually exclusive.
func buildQuestions(toolCount int) (map[string]jevQuestionPayload, []string) {
	questions := make(map[string]jevQuestionPayload, toolCount)
	ids := make([]string, 0, toolCount)

	for index := 0; index < toolCount; index++ {
		id := questionID(index)
		ids = append(ids, id)
		questions[id] = jevQuestionPayload{
			Type:         questionTypeNoul,
			Instructions: fmt.Sprintf(questionInstructionsFormat, index),
			Criteria: &jevQuestionCriteria{
				True:  criterionTrue,
				False: criterionFalse,
			},
		}
	}

	return questions, ids
}

// jevClient is shared by every concurrent request handled by one policy
// instance. It holds configuration and a connection-pooling HTTP client, both
// safe for concurrent use; no per-request state lives on it.
type jevClient struct {
	url              string
	apiKey           string
	model            string
	timeout          time.Duration
	maxResponseBytes int
	httpClient       *http.Client
}

func newJevClient(sys systemConfig, timeout time.Duration) *jevClient {
	return &jevClient{
		url:              sys.BaseURL + systemOnePath,
		apiKey:           sys.APIKey,
		model:            sys.Model,
		timeout:          timeout,
		maxResponseBytes: sys.MaxResponseBytes,
		httpClient:// Never follow a redirect: doing so would hand the bearer token
		// to wherever the redirect points. The 3xx is returned as-is and
		// refused below as an unexpected status.
		newPolicyHTTPClient(0, true),
	}
}

// evaluate asks Jev one Noul question per tool and returns the relevance
// probabilities in questionIDs order. Every error it returns is safe to log:
// none of them contain the API key, the prompt, or tool definitions.
func (c *jevClient) evaluate(ctx context.Context, state jevState, questions map[string]jevQuestionPayload, questionIDs []string) ([]float64, *jevUsage, error) {
	payload, err := json.Marshal(jevSystemOneRequest{
		State:     state,
		Model:     c.model,
		Questions: questions,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize the Jev request")
	}

	// The deadline is derived from the gateway's context, so a cancelled or
	// expiring request cancels the provider call with it.
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	status, body, err := c.postSystemOne(ctx, callCtx, payload)
	if err == nil && (status == http.StatusTooManyRequests || status == statusJevOverloaded) {
		timer := time.NewTimer(retryBackoff)
		select {
		case <-callCtx.Done():
			timer.Stop()
			return nil, nil, transportError(ctx, callCtx, callCtx.Err())
		case <-timer.C:
		}
		status, body, err = c.postSystemOne(ctx, callCtx, payload)
	}
	if err != nil {
		return nil, nil, err
	}

	// Every non-2xx status is a provider error. A 429 or 529 reaches this
	// branch only after the single bounded retry also failed.
	if status < 200 || status > 299 {
		return nil, nil, fmt.Errorf("the Jev API returned status %d", status)
	}

	return parseJevResponse(body, questionIDs)
}

// postSystemOne performs one bounded HTTP attempt. Its errors never include
// the bearer token, prompt, or tool definitions.
func (c *jevClient) postSystemOne(parentCtx, callCtx context.Context, payload []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to build the Jev request")
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return 0, nil, transportError(parentCtx, callCtx, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxResponseBytes)+1))
	if err != nil {
		return 0, nil, transportError(parentCtx, callCtx, err)
	}
	if len(body) > c.maxResponseBytes {
		return 0, nil, fmt.Errorf("the Jev response is larger than %d bytes", c.maxResponseBytes)
	}
	return response.StatusCode, body, nil
}

// transportError describes a failed call without echoing the request, the
// response, or the credential the request carried.
func transportError(parentCtx, callCtx context.Context, err error) error {
	if parentCtx.Err() != nil {
		return fmt.Errorf("the Jev request was cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) || callCtx.Err() != nil {
		return fmt.Errorf("the Jev request timed out")
	}
	return fmt.Errorf("the Jev request failed")
}

// parseJevScores validates the whole response before returning any score.
// It is all-or-nothing on purpose: a partial or malformed response must never
// yield a partially filtered request, and a missing score must never be read
// as a confident zero.
func parseJevScores(body []byte, questionIDs []string) ([]float64, error) {
	scores, _, err := parseJevResponse(body, questionIDs)
	return scores, err
}

// parseJevResponse validates all requested answers before returning scores and
// extracts optional token usage for request metadata.
func parseJevResponse(body []byte, questionIDs []string) ([]float64, *jevUsage, error) {
	var envelope struct {
		Answers *json.RawMessage `json:"answers"`
		Usage   *jevUsage        `json:"usage"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, fmt.Errorf("the Jev response is not valid JSON")
	}
	if envelope.Answers == nil {
		return nil, nil, fmt.Errorf("the Jev response has no 'answers' field")
	}
	if envelope.Usage != nil && (envelope.Usage.InputTokens < 0 || envelope.Usage.OutputTokens < 0) {
		return nil, nil, fmt.Errorf("the Jev response has invalid token usage")
	}

	answers, err := decodeAnswerObject(*envelope.Answers)
	if err != nil {
		return nil, nil, err
	}

	requested := make(map[string]bool, len(questionIDs))
	for _, id := range questionIDs {
		requested[id] = true
	}
	for id := range answers {
		if !requested[id] {
			return nil, nil, fmt.Errorf("the Jev response contains an answer for unknown question %q", id)
		}
	}

	scores := make([]float64, 0, len(questionIDs))
	for _, id := range questionIDs {
		raw, ok := answers[id]
		if !ok {
			return nil, nil, fmt.Errorf("the Jev response has no answer for question %q", id)
		}
		score, err := decodeNoulAnswer(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("answer for question %q is invalid: %w", id, err)
		}
		scores = append(scores, score)
	}

	return scores, envelope.Usage, nil
}

// decodeAnswerObject reads the answers object key by key so a duplicate
// question id is rejected. Plain json.Unmarshal would silently keep the last
// occurrence and hide the contradiction.
func decodeAnswerObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))

	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("the Jev response 'answers' field is not an object")
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("the Jev response 'answers' field is not an object")
	}

	answers := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("the Jev response 'answers' field is malformed")
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("the Jev response 'answers' field is malformed")
		}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("the Jev response 'answers' field is malformed")
		}
		if _, exists := answers[key]; exists {
			return nil, fmt.Errorf("the Jev response contains duplicate answers for question %q", key)
		}
		answers[key] = value
	}

	return answers, nil
}

// decodeNoulAnswer requires the "noul" field to actually be present: a
// pointer distinguishes "absent" from "present and 0", so a malformed answer
// is never read as a confident "not relevant".
func decodeNoulAnswer(raw json.RawMessage) (float64, error) {
	var answer struct {
		Type string   `json:"type"`
		Noul *float64 `json:"noul"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return 0, fmt.Errorf("it is not a valid answer object")
	}
	if answer.Type != questionTypeNoul {
		return 0, fmt.Errorf("expected type %q but got %q", questionTypeNoul, answer.Type)
	}
	if answer.Noul == nil {
		return 0, fmt.Errorf("it is missing the 'noul' field")
	}

	score := *answer.Noul
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0, fmt.Errorf("its 'noul' value is not a finite number")
	}
	if score < 0 || score > 1 {
		return 0, fmt.Errorf("its 'noul' value %g is outside the range 0 to 1", score)
	}

	return score, nil
}
