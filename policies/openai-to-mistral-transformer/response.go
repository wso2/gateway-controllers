/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package openaitomistral

import (
	"encoding/json"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// mistralErrorBody covers both shapes Mistral returns on failure: a flat
// {"message": "..."} envelope and the OpenAI-style {"error": {...}} envelope.
type mistralErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
	Error   struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

func translateResponse(respBody []byte, status int, requestModel string) policy.ResponseAction {
	if status >= 200 && status < 300 {
		return translateSuccessResponse(respBody, requestModel)
	}
	return translateErrorResponse(respBody, status)
}

// translateSuccessResponse leaves Mistral's OpenAI-shaped body alone but
// backfills the "model" field with the model that actually served the request
// when the upstream omitted it, so clients always see a non-empty model.
func translateSuccessResponse(respBody []byte, requestModel string) policy.ResponseAction {
	var payload map[string]interface{}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return policy.DownstreamResponseModifications{}
	}

	if m, _ := payload["model"].(string); strings.TrimSpace(m) == "" && requestModel != "" {
		payload["model"] = requestModel
	}

	newBody, err := json.Marshal(payload)
	if err != nil {
		return policy.DownstreamResponseModifications{}
	}

	return policy.DownstreamResponseModifications{
		Body: newBody,
		HeadersToSet: map[string]string{
			"content-type":   "application/json",
			"content-length": fmt.Sprintf("%d", len(newBody)),
		},
	}
}

// translateErrorResponse rewrites Mistral error envelopes into the OpenAI
// error envelope so clients see a single error shape regardless of upstream.
func translateErrorResponse(respBody []byte, status int) policy.ResponseAction {
	errType := mapStatusToOpenAIErrorType(status)
	errMessage := string(respBody)
	errCode := fmt.Sprintf("%d", status)

	var parsed mistralErrorBody
	if err := json.Unmarshal(respBody, &parsed); err == nil {
		switch {
		case parsed.Error.Message != "":
			errMessage = parsed.Error.Message
			if parsed.Error.Type != "" {
				errType = parsed.Error.Type
			}
			if parsed.Error.Code != "" {
				errCode = parsed.Error.Code
			}
		case parsed.Message != "":
			errMessage = parsed.Message
			if parsed.Type != "" {
				errType = parsed.Type
			}
			if parsed.Code != "" {
				errCode = parsed.Code
			}
		}
	}

	openaiErr := map[string]interface{}{
		"error": map[string]interface{}{
			"type":    errType,
			"message": errMessage,
			"code":    errCode,
		},
	}

	newBody, err := json.Marshal(openaiErr)
	if err != nil {
		return errResponse(500, "failed to translate Mistral error: "+err.Error(),
			policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation)
	}

	return policy.DownstreamResponseModifications{
		Body: newBody,
		HeadersToSet: map[string]string{
			"content-type":   "application/json",
			"content-length": fmt.Sprintf("%d", len(newBody)),
		},
	}
}

func mapStatusToOpenAIErrorType(status int) string {
	switch {
	case status == 400:
		return "invalid_request_error"
	case status == 401:
		return "authentication_error"
	case status == 403:
		return "permission_error"
	case status == 404:
		return "not_found_error"
	case status == 413:
		return "request_too_large"
	case status == 422:
		return "invalid_request_error"
	case status == 429:
		return "rate_limit_error"
	case status >= 500:
		return "server_error"
	default:
		return "api_error"
	}
}

// looksLikeSSE reports whether the body opens as a Server-Sent Events stream.
//
// It accepts every line type the SSE grammar allows at the start of a stream,
// not only "event:" and "data:". A provider may open with a comment line
// (": ping", commonly used as a keep-alive) or with an "id:" or "retry:", and
// reading one of those as a JSON document would route a live stream into the
// buffered translator — which holds it until the upstream closes and so undoes
// the incremental delivery this policy exists to preserve. No JSON document can
// begin with any of these, so widening the test costs nothing.
func looksLikeSSE(body []byte) bool {
	trimmed := strings.TrimLeft(string(body), " \r\n\t\uFEFF")
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, ":") {
		return true
	}
	for _, field := range []string{"event:", "data:", "id:", "retry:"} {
		if strings.HasPrefix(trimmed, field) {
			return true
		}
	}
	return false
}

// openAIErrorBody renders an OpenAI error envelope. The streaming path uses it
// where the buffered path would return an ImmediateResponse: once the status and
// headers are committed, the body is the only part of the reply still open, so
// the envelope has to carry the failure on its own.
func openAIErrorBody(errType, message, code string) []byte {
	body, err := json.Marshal(map[string]interface{}{
		"error": map[string]interface{}{
			"type":    errType,
			"message": message,
			"code":    code,
		},
	})
	if err != nil {
		// Unreachable for a map of plain strings, but a nil body here would be
		// read as "no change" and let the untranslated bytes through.
		return []byte(`{"error":{"type":"server_error",` +
			`"message":"The upstream response could not be translated.",` +
			`"code":"response_translation_failed"}}`)
	}
	return body
}
