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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	moderationPath     = "/v1/moderations"
	chatModerationPath = "/v1/chat/moderations"
	// maxResponseBytes bounds how much of a Mistral answer is read. A moderation answer for
	// one input is well under 2 KB; anything near this size is not a moderation answer.
	maxResponseBytes = 1 << 20
	// maxErrorSnippetBytes bounds how much of an error body reaches the debug log.
	maxErrorSnippetBytes = 256
)

// serviceErrorKind classifies why a moderation call produced no verdict. The kind, not the
// raw error, is what reaches the client and the fault description: the raw error can carry
// the endpoint's host name and the service's own error text.
type serviceErrorKind string

const (
	errKindUnauthorized     serviceErrorKind = "unauthorized"
	errKindRateLimited      serviceErrorKind = "rate_limited"
	errKindServerError      serviceErrorKind = "server_error"
	errKindUnexpectedStatus serviceErrorKind = "unexpected_status"
	errKindTimeout          serviceErrorKind = "timeout"
	errKindCanceled         serviceErrorKind = "canceled"
	errKindNetwork          serviceErrorKind = "network"
	errKindInvalidResponse  serviceErrorKind = "invalid_response"
)

// serviceError is a failed moderation call. Error() is for the debug log only; ClientMessage()
// is the client-safe summary.
type serviceError struct {
	Kind       serviceErrorKind
	StatusCode int
	Err        error
}

func (e *serviceError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("Mistral moderation API error (%s, HTTP %d): %v", e.Kind, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("Mistral moderation API error (%s): %v", e.Kind, e.Err)
}

func (e *serviceError) Unwrap() error { return e.Err }

// ClientMessage summarises the failure without the endpoint, the key or the service's text.
func (e *serviceError) ClientMessage() string {
	switch e.Kind {
	case errKindUnauthorized:
		return fmt.Sprintf("Mistral moderation API rejected the gateway credentials (HTTP %d)", e.StatusCode)
	case errKindRateLimited:
		return "Mistral moderation API rate limit exceeded (HTTP 429)"
	case errKindServerError:
		return fmt.Sprintf("Mistral moderation API is unavailable (HTTP %d)", e.StatusCode)
	case errKindUnexpectedStatus:
		return fmt.Sprintf("Mistral moderation API returned an unexpected status (HTTP %d)", e.StatusCode)
	case errKindTimeout:
		return "Mistral moderation API request timed out"
	case errKindCanceled:
		return "Mistral moderation API request was canceled"
	case errKindNetwork:
		return "Mistral moderation API could not be reached"
	default:
		return "Mistral moderation API returned an invalid response"
	}
}

// moderationRequest is the body of POST /v1/moderations (text mode). input also accepts an
// array of strings; the policy always sends one string, so results holds exactly one entry.
type moderationRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

// chatMessage is one message of a conversation sent to POST /v1/chat/moderations. Mistral
// accepts the roles system, user, assistant and tool, with text content.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatModerationRequest is the body of POST /v1/chat/moderations. input also accepts a list of
// conversations; the policy always sends one, so results holds exactly one entry, which
// classifies the conversation's last message in the context of the ones before it.
type chatModerationRequest struct {
	Model string        `json:"model"`
	Input []chatMessage `json:"input"`
}

// moderationResponse is the part of the /v1/moderations answer the policy reads.
type moderationResponse struct {
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Results []moderationResult `json:"results"`
}

// moderationResult is the verdict for one input. Categories holds Mistral's own boolean
// classification at its internal thresholds; CategoryScores holds the scores (0 to 1) that
// the policy compares with the operator's thresholds.
type moderationResult struct {
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

// moderationClient calls the Mistral moderation endpoint. It holds no per-request state and
// is safe for concurrent use.
type moderationClient struct {
	endpoint string
	apiKey   string
	model    string
	// httpClient overrides the HTTP client, for tests. nil uses the policy engine's shared
	// outbound client.
	httpClient *http.Client
}

func newModerationClient(endpoint, apiKey, model string) *moderationClient {
	return &moderationClient{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		apiKey:   apiKey,
		model:    model,
	}
}

func (c *moderationClient) client() *http.Client {
	if c.httpClient != nil {
		return c.httpClient
	}
	if shared := utils.SharedHTTPClient(); shared != nil {
		return shared
	}
	return fallbackHTTPClient()
}

// moderate sends text to POST /v1/moderations and returns its verdict.
func (c *moderationClient) moderate(ctx context.Context, text string, timeout time.Duration) (*moderationResult, error) {
	return c.post(ctx, moderationPath, moderationRequest{Model: c.model, Input: text}, timeout)
}

// moderateChat sends a conversation to POST /v1/chat/moderations and returns the verdict for
// its last message.
func (c *moderationClient) moderateChat(ctx context.Context, messages []chatMessage, timeout time.Duration) (*moderationResult, error) {
	return c.post(ctx, chatModerationPath, chatModerationRequest{Model: c.model, Input: messages}, timeout)
}

// post sends one moderation request and decodes the verdict. Both endpoints answer with the
// same shape. The call is bounded by timeout and by ctx, and is not retried: a retry would add
// latency to every request the gateway is holding, and passthroughOnError already decides
// what a failed check means.
func (c *moderationClient) post(ctx context.Context, path string, body interface{}, timeout time.Duration) (*moderationResult, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, &serviceError{Kind: errKindInvalidResponse, Err: fmt.Errorf("failed to marshal request: %w", err)}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return nil, &serviceError{Kind: errKindNetwork, Err: fmt.Errorf("failed to create request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, classifyTransportError(ctx, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, classifyTransportError(ctx, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, respBody)
	}
	if len(respBody) > maxResponseBytes {
		return nil, &serviceError{Kind: errKindInvalidResponse, Err: fmt.Errorf("response exceeds %d bytes", maxResponseBytes)}
	}

	var parsed moderationResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, &serviceError{Kind: errKindInvalidResponse, Err: fmt.Errorf("failed to decode response: %w", err)}
	}
	if len(parsed.Results) == 0 {
		return nil, &serviceError{Kind: errKindInvalidResponse, Err: errors.New("response has no results")}
	}
	result := parsed.Results[0]
	// A missing category_scores must not decode as "every score is zero".
	if result.CategoryScores == nil {
		return nil, &serviceError{Kind: errKindInvalidResponse, Err: errors.New("response has no category_scores")}
	}
	return &result, nil
}

func statusError(status int, body []byte) *serviceError {
	err := fmt.Errorf("response body: %s", errorSnippet(body))
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &serviceError{Kind: errKindUnauthorized, StatusCode: status, Err: err}
	case status == http.StatusTooManyRequests:
		return &serviceError{Kind: errKindRateLimited, StatusCode: status, Err: err}
	case status >= 500:
		return &serviceError{Kind: errKindServerError, StatusCode: status, Err: err}
	default:
		return &serviceError{Kind: errKindUnexpectedStatus, StatusCode: status, Err: err}
	}
}

// classifyTransportError tells a timeout (the policy's own deadline or a dial/read timeout)
// apart from a caller that went away and from a plain network failure.
func classifyTransportError(ctx context.Context, err error) *serviceError {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &serviceError{Kind: errKindTimeout, Err: err}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &serviceError{Kind: errKindTimeout, Err: err}
	}
	if errors.Is(err, context.Canceled) {
		return &serviceError{Kind: errKindCanceled, Err: err}
	}
	return &serviceError{Kind: errKindNetwork, Err: err}
}

// errorSnippet returns the start of an error body for the debug log.
func errorSnippet(body []byte) string {
	if len(body) <= maxErrorSnippetBytes {
		return string(body)
	}
	return string(body[:maxErrorSnippetBytes]) + "... (truncated)"
}

var (
	fallbackClientOnce sync.Once
	fallbackClient     *http.Client
)

// fallbackHTTPClient is used only when utils.SharedHTTPClient() has not been installed (a
// gateway that predates it, or a call before the engine finishes startup). It has bounded
// dial and TLS timeouts, honours no environment proxy and follows no redirect, so the
// Authorization header never travels to a host other than the configured endpoint. Each call
// is still bounded by the per-phase timeout through its context.
func fallbackHTTPClient() *http.Client {
	fallbackClientOnce.Do(func() {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		fallbackClient = &http.Client{
			Transport: &http.Transport{
				Proxy:               nil,
				DialContext:         dialer.DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return fallbackClient
}
