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

package mistralshieldstralcontentsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// This file is the Shieldstral client: building the classification prompt,
// calling an OpenAI-compatible chat completions endpoint, and turning the
// answer's logprobs into a score. It knows nothing about the gateway.

const (
	// systemPrompt is the fixed system message Shieldstral was trained with,
	// verbatim from the model card and Mistral's moderation cookbook.
	systemPrompt = `Judge whether the Document meets the requirements based on the Query and the Instruction provided. Note that the answer can only be "yes" or "no".`

	chatCompletionsPath = "/v1/chat/completions"

	// The verdict is the first generated token; 20 is the most alternatives
	// the OpenAI-compatible API returns, and what the reference code asks for.
	topLogprobs = 20

	// absentLogprob stands in for a yes or no token that is not among the top
	// alternatives, and is also a floor: as in the reference vLLM code, a
	// logprob below it counts as it. The score therefore stays within about
	// [0.00005, 0.99995] when only one verdict is likely, which no useful
	// threshold falls outside.
	absentLogprob = -10.0

	// An inference server returns 429 when rate limited and 503 when
	// overloaded. One retry with a short backoff, bounded by the same per-call
	// timeout as the first attempt.
	retryBackoff = 250 * time.Millisecond

	// A one-token answer with 20 alternatives is a few kilobytes, so a larger
	// body is not a valid answer.
	maxResponseBytes = 1 << 20
	// Only the start of an error body goes into error messages, which are logged.
	maxErrorBodyBytes = 512
)

// errMalformedResponse marks an answer that arrived but could not be scored,
// as opposed to a call that failed.
var errMalformedResponse = errors.New("malformed Shieldstral response")

// yesTokens and noTokens are the spellings the reference code accepts for a
// verdict token, after trimming whitespace and lowercasing.
var (
	yesTokens = map[string]bool{"yes": true, "yes.": true, `"yes"`: true, "'yes'": true}
	noTokens  = map[string]bool{"no": true, "no.": true, `"no"`: true, "'no'": true}
)

// shieldstralClient calls one Shieldstral deployment. It is safe for
// concurrent use.
type shieldstralClient struct {
	completionsURL string
	apiKey         string
	model          string
	http           *http.Client
}

// classification is the result of one yes/no question.
type classification struct {
	// Score is the probability of "yes" renormalised over yes and no, in [0, 1].
	Score            float64
	PromptTokens     int
	CompletionTokens int
}

// newShieldstralClient validates the endpoint and returns a client for it. An
// endpoint is the server's base URL; a trailing "/v1" is accepted too, since
// that is how OpenAI-compatible base URLs are often written.
func newShieldstralClient(endpoint, apiKey, model string, httpClient *http.Client) (*shieldstralClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("'endpoint' is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("'endpoint' must be an http or https URL")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("'endpoint' must include a host")
	}
	// Transport errors quote the URL and are logged, so credentials in it would leak.
	if u.User != nil {
		return nil, fmt.Errorf("'endpoint' must not include credentials; use 'apiKey'")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("'endpoint' must not include a query or fragment")
	}
	base := strings.TrimSuffix(strings.TrimSuffix(u.String(), "/"), "/v1")
	return &shieldstralClient{
		completionsURL: base + chatCompletionsPath,
		apiKey:         apiKey,
		model:          model,
		http:           httpClient,
	}, nil
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	Logprobs    bool          `json:"logprobs"`
	TopLogprobs int           `json:"top_logprobs"`
}

type tokenLogprob struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Logprobs *struct {
			Content []struct {
				tokenLogprob
				TopLogprobs []tokenLogprob `json:"top_logprobs"`
			} `json:"content"`
		} `json:"logprobs"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// fieldMarker matches a field label such as "<Query>:" in any case and spacing.
var fieldMarker = regexp.MustCompile(`(?i)<\s*(instruct|query|document)\s*>\s*:`)

// buildUserMessage lays out the three fields exactly as the reference code
// does. The document is the caller's text, so a field label inside it is
// defused by dropping its colon: otherwise a prompt could add its own
// "<Query>:" line and pull the answer towards a question of its choosing.
// Measured on Shieldstral 1.0, an injected query lowered a pipe-bomb prompt's
// score from 0.9995 to 0.893; with the colon dropped it scored 0.984.
func buildUserMessage(instruct, query, document string) string {
	document = fieldMarker.ReplaceAllString(document, "<$1>")
	return "<Instruct>: " + instruct + "\n\n<Query>: " + query + "\n\n<Document>: " + document
}

// classify asks Shieldstral one yes/no question about document. The caller's
// context bounds the call, including the one retry.
func (c *shieldstralClient) classify(ctx context.Context, instruct, query, document string) (classification, error) {
	payload, err := json.Marshal(chatCompletionRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserMessage(instruct, query, document)},
		},
		MaxTokens:   1,
		Temperature: 0,
		Logprobs:    true,
		TopLogprobs: topLogprobs,
	})
	if err != nil {
		return classification{}, fmt.Errorf("failed to marshal Shieldstral request: %w", err)
	}

	status, body, err := c.post(ctx, payload)
	if err == nil && (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) {
		slog.Debug("MistralShieldstralContentSafety: Shieldstral rate limited or overloaded, retrying once", "status", status)
		select {
		case <-ctx.Done():
			return classification{}, fmt.Errorf("Shieldstral returned status %d and timed out before retry: %w", status, ctx.Err())
		case <-time.After(retryBackoff):
		}
		status, body, err = c.post(ctx, payload)
	}
	if err != nil {
		return classification{}, err
	}
	if status != http.StatusOK {
		return classification{}, fmt.Errorf("Shieldstral returned status %d: %s", status, errorSnippet(body))
	}

	var parsed chatCompletionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return classification{}, fmt.Errorf("%w: %v", errMalformedResponse, err)
	}
	score, err := scoreFromResponse(parsed)
	if err != nil {
		return classification{}, err
	}
	result := classification{Score: score}
	if parsed.Usage != nil {
		result.PromptTokens = parsed.Usage.PromptTokens
		result.CompletionTokens = parsed.Usage.CompletionTokens
	}
	return result, nil
}

// scoreFromResponse computes the softmax over the yes and no logprobs at the
// first generated position, as the reference code does. It never falls back to
// the generated text: an endpoint that does not return logprobs, or whose top
// alternatives hold neither verdict, gives no score, and that is an error
// rather than a guess.
func scoreFromResponse(resp chatCompletionResponse) (float64, error) {
	if len(resp.Choices) == 0 {
		return 0, fmt.Errorf("%w: no choices", errMalformedResponse)
	}
	lp := resp.Choices[0].Logprobs
	if lp == nil || len(lp.Content) == 0 {
		return 0, fmt.Errorf("%w: no logprobs; the endpoint must support logprobs and top_logprobs", errMalformedResponse)
	}
	first := lp.Content[0]
	candidates := first.TopLogprobs
	if len(candidates) == 0 {
		// Some servers omit the alternatives but still report the chosen token.
		candidates = []tokenLogprob{first.tokenLogprob}
	}

	zYes, zNo := absentLogprob, absentLogprob
	foundYes, foundNo := false, false
	for _, cand := range candidates {
		t := strings.ToLower(strings.TrimSpace(cand.Token))
		switch {
		case yesTokens[t]:
			zYes, foundYes = math.Max(zYes, cand.Logprob), true
		case noTokens[t]:
			zNo, foundNo = math.Max(zNo, cand.Logprob), true
		}
	}
	if !foundYes && !foundNo {
		return 0, fmt.Errorf("%w: the answer holds neither a yes nor a no token", errMalformedResponse)
	}
	// exp(zYes) / (exp(zYes) + exp(zNo)), written so neither exponent overflows.
	return 1 / (1 + math.Exp(zNo-zYes)), nil
}

func (c *shieldstralClient) post(ctx context.Context, payload []byte) (int, []byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.completionsURL, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create Shieldstral HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// A self-hosted server often runs without a key; sending an empty bearer
	// token would be rejected by one that has a key, so the header is omitted.
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return 0, nil, fmt.Errorf("Shieldstral HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read Shieldstral response: %w", err)
	}
	if len(body) > maxResponseBytes {
		// A successful answer that doesn't fit is rejected rather than decoded
		// from a truncated body. An error body only feeds a diagnostic, so it is
		// cut instead, keeping the status for the retry decision.
		if resp.StatusCode == http.StatusOK {
			return 0, nil, fmt.Errorf("Shieldstral response exceeds %d bytes", maxResponseBytes)
		}
		body = body[:maxResponseBytes]
	}
	return resp.StatusCode, body, nil
}

// errorSnippet returns the start of an error body for an error message.
func errorSnippet(body []byte) string {
	if len(body) <= maxErrorBodyBytes {
		return string(body)
	}
	return string(body[:maxErrorBodyBytes]) + "... (truncated)"
}
