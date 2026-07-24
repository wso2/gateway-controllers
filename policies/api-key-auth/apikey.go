/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	store "github.com/wso2/api-platform/common/apikey"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	AuthType = "apikey"

	applicationIDMetadataKey   = "x-wso2-application-id"
	applicationNameMetadataKey = "x-wso2-application-name"
)

// APIKeyPolicy implements API Key Authentication
type APIKeyPolicy struct {
}

var ins = &APIKeyPolicy{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

func (p *APIKeyPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// resolveValidatedAPIKey validates the provided API key against external store/service and returns the resolved key
// returns nil if the key is invalid, or an error if there was an issue during validation
func (p *APIKeyPolicy) resolveValidatedAPIKey(apiId, apiOperation, operationMethod, apiKey, issuer string) (*store.APIKey, error) {
	apiKeyStore := store.GetAPIkeyStoreInstance()
	resolvedKey, err := apiKeyStore.ResolveValidatedAPIKey(apiId, apiOperation, operationMethod, apiKey, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve API key via the policy engine")
	}
	return resolvedKey, nil
}

// extractQueryParam extracts the first value of the given query parameter from the request path
func extractQueryParam(path, param string) string {
	// Parse the URL-encoded path
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return ""
	}

	// Split the path into components
	parts := strings.Split(decodedPath, "?")
	if len(parts) != 2 {
		return ""
	}

	// Parse the query string
	queryString := parts[1]
	values, err := url.ParseQuery(queryString)
	if err != nil {
		return ""
	}

	// Get the first value of the specified parameter
	if value, ok := values[param]; ok && len(value) > 0 {
		return value[0]
	}

	return ""
}

// ─── v2alpha.RequestHeaderPolicy ─────────────────────────────────────────────

// OnRequestHeaders implements v1alpha2.RequestHeaderPolicy.
// It performs API key authentication in the request-header phase, allowing the
// kernel to short-circuit before any body buffering occurs.
func (p *APIKeyPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if errResp := p.authenticate(reqCtx.SharedContext, getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers), reqCtx.Path, reqCtx.Method, params); errResp != nil {
		return *errResp
	}

	keyName, _ := params["key"].(string)
	location, _ := params["in"].(string)
	analyticsMetadata := map[string]interface{}{}
	if reqCtx.SharedContext != nil && reqCtx.SharedContext.AuthContext != nil {
		analyticsMetadata[applicationNameMetadataKey] = reqCtx.SharedContext.AuthContext.Properties["ApplicationName"]
		analyticsMetadata[applicationIDMetadataKey] = reqCtx.SharedContext.AuthContext.Properties["ApplicationID"]
	}

	mods := policy.UpstreamRequestHeaderModifications{
		AnalyticsMetadata: analyticsMetadata,
	}
	if location == "header" {
		mods.HeadersToRemove = []string{http.CanonicalHeaderKey(keyName)}
	} else if location == "query" {
		mods.QueryParametersToRemove = []string{keyName}
	}
	return mods
}

// authenticate is the shared core logic for OnRequestHeaders.
// It extracts and validates the API key, sets SharedContext.AuthContext, and returns
// nil on success or an *ImmediateResponse on failure.
func (p *APIKeyPolicy) authenticate(
	shared *policy.SharedContext,
	headers *policy.Headers,
	path, method string,
	params map[string]interface{},
) *policy.ImmediateResponse {
	slog.Debug("API Key Auth Policy: authenticate started",
		"path", path,
		"method", method,
		"apiId", shared.APIId,
		"apiName", shared.APIName,
		"apiVersion", shared.APIVersion,
	)

	keyName, ok := params["key"].(string)
	if !ok || keyName == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'key' configuration")
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing or invalid 'key' configuration")
	}

	location, ok := params["in"].(string)
	if !ok || location == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'in' configuration")
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	var valuePrefix string
	if valuePrefixRaw, ok := params["valuePrefix"]; ok {
		if vp, ok := valuePrefixRaw.(string); ok {
			valuePrefix = vp
		}
	}

	issuer, _ := params["issuer"].(string)

	slog.Debug("API Key Auth Policy: Configuration loaded",
		"keyName", keyName, "location", location, "valuePrefix", valuePrefix)

	var providedKey string
	switch location {
	case "header":
		if vals := headers.Get(http.CanonicalHeaderKey(keyName)); len(vals) > 0 {
			providedKey = vals[0]
			slog.Debug("API Key Auth Policy: Found API key in header",
				"headerName", keyName, "keyLength", len(providedKey))
		}
	case "query":
		providedKey = extractQueryParam(path, keyName)
		if providedKey != "" {
			slog.Debug("API Key Auth Policy: Found API key in query parameter",
				"paramName", keyName, "keyLength", len(providedKey))
		}
	default:
		slog.Debug("API Key Auth Policy: Unsupported location", "location", location)
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	if valuePrefix != "" {
		originalLength := len(providedKey)
		providedKey = stripPrefix(providedKey, valuePrefix)
		slog.Debug("API Key Auth Policy: Processed value prefix",
			"prefix", valuePrefix,
			"originalLength", originalLength,
			"processedLength", len(providedKey),
		)
	}

	if providedKey == "" {
		slog.Debug("API Key Auth Policy: No API key found or API key is malformed", "location", location, "keyName", keyName)
		return p.failAuth(shared, 401, "json", "Valid API key required", "missing or malformed API key")
	}

	apiId := shared.APIId
	apiName := shared.APIName
	apiVersion := shared.APIVersion
	apiOperation := shared.OperationPath
	operationMethod := method

	if apiId == "" || apiName == "" || apiVersion == "" || apiOperation == "" || operationMethod == "" {
		slog.Debug("API Key Auth Policy: Missing API details for validation",
			"apiId", apiId, "apiName", apiName, "apiVersion", apiVersion,
			"apiOperation", apiOperation, "operationMethod", operationMethod)
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing API details for validation")
	}

	slog.Debug("API Key Auth Policy: Starting validation",
		"apiId", apiId, "apiName", apiName, "apiVersion", apiVersion,
		"apiOperation", apiOperation, "operationMethod", operationMethod,
		"keyLength", len(providedKey))

	resolvedKey, err := p.resolveValidatedAPIKey(apiId, apiOperation, operationMethod, providedKey, issuer)
	if err != nil {
		slog.Debug("API Key Auth Policy: Validation error", "error", err)
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"error validating API key")
	}
	if resolvedKey == nil {
		slog.Debug("API Key Auth Policy: Invalid API key")
		return p.failAuth(shared, 401, "json", "Valid API key required", "invalid API key")
	}

	slog.Debug("API Key Auth Policy: Authentication successful")
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
		Properties: map[string]string{
			"ApplicationName": resolvedKey.ApplicationName,
			"ApplicationID":   resolvedKey.ApplicationID,
		},
		TokenId: generateTokenID(providedKey),
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[applicationIDMetadataKey] = resolvedKey.ApplicationID
	return nil
}

// failAuth sets the auth context to unauthenticated and returns a policy.ImmediateResponse.
func (p *APIKeyPolicy) failAuth(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage, reason string) *policy.ImmediateResponse {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}
	v1resp := p.buildErrorResponse(statusCode, errorFormat, errorMessage, reason)
	return &policy.ImmediateResponse{
		StatusCode: v1resp.StatusCode,
		Headers:    v1resp.Headers,
		Body:       v1resp.Body,
	}
}

// stripPrefix removes the specified prefix from the value (case-insensitive)
// Returns the value with prefix removed, or empty string if prefix doesn't match
func stripPrefix(value, prefix string) string {
	// Do exact case-insensitive prefix matching
	if len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
		return value[len(prefix):]
	}
	return ""
}

func generateTokenID(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// buildErrorResponse constructs the ImmediateResponse body and headers for an auth failure.
func (p *APIKeyPolicy) buildErrorResponse(statusCode int, errorFormat, errorMessage, reason string) policy.ImmediateResponse {
	headers := map[string]string{"content-type": "application/json"}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	default: // json
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	slog.Debug("API Key Auth Policy: Returning immediate response",
		"statusCode", statusCode,
		"contentType", headers["content-type"],
		"bodyLength", len(body),
		"reason", reason,
	)

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}
