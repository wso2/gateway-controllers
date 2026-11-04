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

// Package opapolicy implements a request policy that validates requests
// against an Open Policy Agent (OPA) server.
package opapolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultMaxOpenConnections = 500
	defaultConnectionTimeout  = 30 // seconds
	maxOPAResponseSize        = 1024 * 1024

	// Keys of the OPA input document.
	inputKey                = "input"
	requestOriginKey        = "requestOrigin"
	requestMethodKey        = "requestMethod"
	requestPathKey          = "requestPath"
	requestTransportHdrsKey = "transportHeaders"
	electedResourceKey      = "electedResource"
	apiContextKey           = "apiContext"

	resultKey = "result"

	contentTypeJSON = "application/json"
)

// OPAPolicy validates a request against an OPA policy engine.
type OPAPolicy struct {
	// requestURL is the full OPA data API URL: {serverUrl}/{policy}[/{rule}].
	requestURL         string
	accessKey          string
	rule               string
	sendAccessToken    bool
	additionalProps    []string
	client             *http.Client
	policyName         string
	maxResponseSizeCap int64
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	serverURL, err := requiredString(params, "serverUrl")
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(serverURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("'serverUrl' must be a valid http or https URL")
	}

	policyName, err := requiredString(params, "policy")
	if err != nil {
		return nil, err
	}

	rule, err := requiredString(params, "rule")
	if err != nil {
		return nil, err
	}

	accessKey, err := optionalString(params, "accessKey")
	if err != nil {
		return nil, err
	}

	sendAccessToken, err := optionalBool(params, "sendAccessToken", false)
	if err != nil {
		return nil, err
	}

	additional, err := optionalStringList(params, "additionalProperties")
	if err != nil {
		return nil, err
	}

	maxConns, err := optionalInt(params, "maxOpenConnections", defaultMaxOpenConnections, 1, 999)
	if err != nil {
		return nil, err
	}
	timeoutSecs, err := optionalInt(params, "connectionTimeout", defaultConnectionTimeout, 1, 999)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = maxConns
	transport.MaxIdleConnsPerHost = maxConns
	transport.MaxIdleConns = maxConns

	return &OPAPolicy{
		requestURL:         buildRequestURL(serverURL, policyName, rule),
		accessKey:          accessKey,
		rule:               rule,
		sendAccessToken:    sendAccessToken,
		additionalProps:    additional,
		policyName:         policyName,
		maxResponseSizeCap: maxOPAResponseSize,
		client: &http.Client{
			Timeout:   time.Duration(timeoutSecs) * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Mode returns the processing mode: only the request headers are needed.
func (p *OPAPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders queries OPA and allows or blocks the request.
func (p *OPAPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	payload, err := p.buildInput(reqCtx)
	if err != nil {
		slog.Error("OPA: failed to build request payload", "policy", p.policyName, "error", err)
		return internalError(fmt.Sprintf("failed to build the OPA input: %v", err))
	}

	respBody, err := p.callOPA(ctx, payload)
	if err != nil {
		slog.Error("OPA: validation request failed", "policy", p.policyName, "rule", p.rule, "error", err)
		return internalError(fmt.Sprintf("OPA validation request failed: %v", err))
	}

	allowed, err := p.handleResponse(respBody)
	if err != nil {
		slog.Error("OPA: invalid validation response", "policy", p.policyName, "rule", p.rule, "error", err)
		return internalError(fmt.Sprintf("invalid OPA validation response: %v", err))
	}

	if !allowed {
		slog.Debug("OPA: request denied", "policy", p.policyName, "rule", p.rule, "requestId", requestID(reqCtx))
		return forbidden(fmt.Sprintf("OPA policy %q rule %q denied the request", p.policyName, p.rule))
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// buildInput builds the OPA input document: {"input": {...}}.
func (p *OPAPolicy) buildInput(reqCtx *policy.RequestHeaderContext) ([]byte, error) {
	headers := flattenHeaders(reqCtx.Headers)

	input := map[string]interface{}{
		requestOriginKey:        requestOrigin(headers),
		requestMethodKey:        reqCtx.Method,
		requestPathKey:          reqCtx.Path,
		requestTransportHdrsKey: headers,
	}

	if sc := reqCtx.SharedContext; sc != nil {
		input[electedResourceKey] = sc.OperationPath
		input[apiContextKey] = p.buildAPIContext(sc, headers)

		for _, key := range p.additionalProps {
			if v, ok := sc.Metadata[key]; ok && v != nil {
				input[key] = v
			}
		}
	}

	return json.Marshal(map[string]interface{}{inputKey: input})
}

func (p *OPAPolicy) buildAPIContext(sc *policy.SharedContext, headers map[string]string) map[string]interface{} {
	apiCtx := map[string]interface{}{
		"apiId":      sc.APIId,
		"apiName":    sc.APIName,
		"apiVersion": sc.APIVersion,
		"context":    sc.APIContext,
	}

	if auth := sc.AuthContext; auth != nil {
		apiCtx["isAuthenticated"] = auth.Authenticated
		apiCtx["isAuthorized"] = auth.Authorized
		apiCtx["authType"] = auth.AuthType
		apiCtx["username"] = auth.Subject
		apiCtx["issuer"] = auth.Issuer
		apiCtx["consumerKey"] = auth.CredentialID
		if len(auth.Audience) > 0 {
			apiCtx["audience"] = auth.Audience
		}
		if len(auth.Scopes) > 0 {
			scopes := make([]string, 0, len(auth.Scopes))
			for s, granted := range auth.Scopes {
				if granted {
					scopes = append(scopes, s)
				}
			}
			sort.Strings(scopes)
			apiCtx["scopes"] = scopes
		}
		if len(auth.Properties) > 0 {
			apiCtx["properties"] = auth.Properties
		}
	} else {
		apiCtx["isAuthenticated"] = false
	}

	if p.sendAccessToken {
		if token := bearerToken(headers["authorization"]); token != "" {
			apiCtx["accessToken"] = token
		}
	}
	return apiCtx
}

func (p *OPAPolicy) callOPA(ctx context.Context, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating OPA request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Accept", contentTypeJSON)
	if p.accessKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.accessKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling OPA server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, p.maxResponseSizeCap+1))
	if err != nil {
		return nil, fmt.Errorf("reading OPA response: %w", err)
	}
	if int64(len(body)) > p.maxResponseSizeCap {
		return nil, fmt.Errorf("OPA response exceeds %d bytes", p.maxResponseSizeCap)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA server returned status %d", resp.StatusCode)
	}
	return body, nil
}

// handleResponse extracts the boolean decision from the OPA response, which
// is {"result": <bool>} for the configured rule. An undefined decision ({}) is
// an error
func (p *OPAPolicy) handleResponse(body []byte) (bool, error) {
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("parsing OPA response: %w", err)
	}
	result, ok := resp[resultKey]
	if !ok {
		return false, fmt.Errorf("empty result received for the OPA policy %q for rule %q", p.policyName, p.rule)
	}
	if string(result) == "null" {
		return false, fmt.Errorf("the field %q is null: invalid decision for the OPA policy %q for rule %q", resultKey, p.policyName, p.rule)
	}

	var allowed bool
	if err := json.Unmarshal(result, &allowed); err != nil {
		return false, fmt.Errorf("the field %q is not a boolean: %w", resultKey, err)
	}
	return allowed, nil
}

func buildRequestURL(serverURL, policyName, rule string) string {
	return strings.TrimRight(serverURL, "/") + "/" + strings.Trim(policyName, "/") + "/" + strings.Trim(rule, "/")
}

func flattenHeaders(h *policy.Headers) map[string]string {
	out := map[string]string{}
	if h == nil {
		return out
	}
	h.Iterate(func(name string, values []string) {
		if strings.HasPrefix(name, ":") || len(values) == 0 {
			return
		}
		out[strings.ToLower(name)] = strings.Join(values, ",")
	})
	return out
}

// requestOrigin resolves the client IP from the forwarding headers.
func requestOrigin(headers map[string]string) string {
	if xff := headers["x-forwarded-for"]; xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return headers["x-envoy-external-address"]
}

func bearerToken(authorization string) string {
	const prefix = "bearer "
	if len(authorization) > len(prefix) && strings.EqualFold(authorization[:len(prefix)], prefix) {
		return strings.TrimSpace(authorization[len(prefix):])
	}
	return ""
}

func requestID(reqCtx *policy.RequestHeaderContext) string {
	if reqCtx.SharedContext == nil {
		return ""
	}
	return reqCtx.SharedContext.RequestID
}

// forbidden rejects a request OPA denied: the caller is identified but not
// permitted, an authorization failure. reason names the policy and rule and
// goes in Description, which reaches fault policies and analytics, never the
// client.
func forbidden(reason string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{
		"error":   "Forbidden",
		"message": "The request was rejected by the OPA policy validation",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusForbidden,
		Headers:    map[string]string{"content-type": contentTypeJSON},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeAuthForbidden,
			Type:        policy.FaultTypeAuthorization,
			Direction:   policy.DirectionRequest,
			Message:     "The request was rejected by the OPA policy validation",
			Description: reason,
		},
	}
}

// internalError refuses the request when no decision could be obtained from
// OPA. That is the policy failing to do its job, not a decision about the
// caller, so the fault is policy.FaultCodeMediationFailed. reason carries the
// underlying error, which can name the OPA server, so it goes in Description
// and never reaches the client.
func internalError(reason string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{
		"error":   "Internal Server Error",
		"message": "Unable to validate the request with the OPA policy engine",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusInternalServerError,
		Headers:    map[string]string{"content-type": contentTypeJSON},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionRequest,
			Message:     "Unable to validate the request with the OPA policy engine",
			Description: reason,
		},
	}
}

// ---- parameter helpers ----

func requiredString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	s, ok := raw.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("'%s' must be a non-empty string", key)
	}
	return strings.TrimSpace(s), nil
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

func optionalBool(params map[string]interface{}, key string, def bool) (bool, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return def, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
	return b, nil
}

func optionalInt(params map[string]interface{}, key string, def, min, max int) (int, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return def, nil
	}
	var n int
	switch v := raw.(type) {
	case int:
		n = v
	case int64:
		n = int(v)
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("'%s' must be an integer", key)
		}
		n = int(v)
	default:
		return 0, fmt.Errorf("'%s' must be an integer", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("'%s' must be between %d and %d", key, min, max)
	}
	return n, nil
}

func optionalStringList(params map[string]interface{}, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("'%s' must be an array of strings", key)
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("'%s' must be an array of strings", key)
	}
}
