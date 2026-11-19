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

package nvidiaswitchyardrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// maxDecisionBytes bounds the Switchyard response; a decision is a few hundred bytes.
	maxDecisionBytes = 64 << 10

	// sessionIDHeader is the header switchyard-server reads the session ID from.
	sessionIDHeader = "x-switchyard-session-id"

	// idleConnTimeout keeps connections to switchyard-server open across quiet
	// periods. A new connection repeats the DNS lookup, which can take over
	// 100 ms inside a container and eat most of a short decision timeout.
	idleConnTimeout = 5 * time.Minute
)

// switchyardHTTPClient is shared by every policy instance, so routes and
// redeployments reuse the same warm connections.
var switchyardHTTPClient = newSwitchyardHTTPClient()

func newSwitchyardHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.IdleConnTimeout = idleConnTimeout
	return &http.Client{Transport: transport}
}

var (
	// errProfileNotFound means switchyard-server has no route named after the
	// configured profile.
	errProfileNotFound = errors.New("switchyard-server has no route for the configured profile")
	// errInvalidDecision means the server answered 200 with a body that is not
	// a usable decision.
	errInvalidDecision = errors.New("switchyard-server returned an unusable decision")
)

// decisionRequest is the body of switchyard-server's POST /v1/decision. The
// request's model names the server route, which this policy calls a profile.
type decisionRequest struct {
	InputFormat string          `json:"input_format"`
	Request     json.RawMessage `json:"request"`
}

// decisionResponse is switchyard-server's answer. Targets are the server's
// target table names; profiles name them "efficient" and "capable".
type decisionResponse struct {
	Selected  decisionTarget   `json:"selected"`
	Fallbacks []decisionTarget `json:"fallbacks"`
}

type decisionTarget struct {
	Target string `json:"target"`
}

type switchyardClient struct {
	endpoint   string
	apiKey     string
	timeout    time.Duration
	httpClient *http.Client
}

// decide asks switchyard-server for a decision, sending headers with it. Any
// transport error, non-200 status or undecodable body is returned as an error
// so the caller applies the fallback.
func (c *switchyardClient) decide(ctx context.Context, inputFormat string, request []byte, headers map[string]string) (decisionResponse, error) {
	var d decisionResponse
	body, err := json.Marshal(decisionRequest{InputFormat: inputFormat, Request: request})
	if err != nil {
		return d, fmt.Errorf("encode decision request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return d, fmt.Errorf("create decision request: %w", err)
	}
	for name, value := range headers {
		httpReq.Header.Set(name, value)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// switchyard-server does not authenticate callers; the key is for a proxy
	// placed in front of it.
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return d, fmt.Errorf("decision request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxDecisionBytes))
		if resp.StatusCode == http.StatusNotFound && isUnknownRoute(raw) {
			return d, errProfileNotFound
		}
		return d, fmt.Errorf("switchyard-server returned status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDecisionBytes)).Decode(&d); err != nil {
		return d, fmt.Errorf("%w: %v", errInvalidDecision, err)
	}
	if d.Selected.Target == "" {
		return d, fmt.Errorf("%w: no selected target", errInvalidDecision)
	}
	return d, nil
}

// isUnknownRoute reports whether a 404 body is switchyard-server's answer for a
// profile it has no route for. Any other 404, such as a wrong endpoint path, is
// a server problem rather than a missing profile.
func isUnknownRoute(body []byte) bool {
	var reply struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	return json.Unmarshal(body, &reply) == nil && reply.Error.Code == "model_not_found"
}
