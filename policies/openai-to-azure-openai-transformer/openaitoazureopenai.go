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

// Package openaitoazureopenai rewrites an OpenAI Chat Completions request path
// into the Azure OpenAI form
// /openai/deployments/{deployment}/{pathSuffix}?api-version=<apiVersion>.
// The body passes through unchanged; Azure already emits OpenAI-shaped
// responses, so response translation is intentionally not implemented.
package openaitoazureopenai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	PolicyName                  = "openai-to-azure-openai-transformer"
	DefaultPathSuffix           = "/chat/completions"
	MetadataKeySelectedProvider = "selected_provider"
)

type PolicyParams struct {
	APIVersion string
	Model      string
	PathSuffix string
	// ProviderID is the upstream provider this translator targets. It is both the
	// upstream cluster the request is routed to and the key matched
	// (case-insensitive) against SharedContext.Metadata["selected_provider"]
	// in multi-provider mode.
	ProviderID string
}

type TranslatorPolicy struct {
	params PolicyParams
}

func GetPolicy(_ policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid params: %w", PolicyName, err)
	}
	return &TranslatorPolicy{params: parsed}, nil
}

// Mode buffers the request body even though we don't modify it — the
// deployment id may have to be read from the body's "model" field when the
// operator hasn't pinned one.
func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func (p *TranslatorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if !p.shouldRun(reqCtx) {
		return policy.UpstreamRequestModifications{}
	}

	deployment, err := p.resolveDeployment(reqCtx)
	if err != nil {
		return errResponse(400, err.Error(),
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
	}

	newPath := buildAzurePath(deployment, p.params.PathSuffix, p.params.APIVersion)
	slog.Debug(PolicyName+": rewriting request path",
		"providerId", p.params.ProviderID, "deployment", deployment, "path", newPath)

	mods := policy.UpstreamRequestModifications{Path: &newPath}
	if p.params.ProviderID != "" {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// shouldRun reports whether the request should be rewritten. When no upstream
// router (e.g. llm-header-router) has published a selected provider into the
// metadata, the proxy is in single-provider mode and the translator always
// runs. When a provider has been selected, the translator runs only if that
// selection matches its own "providerId".
func (p *TranslatorPolicy) shouldRun(reqCtx *policy.RequestContext) bool {
	selected := selectedProvider(reqCtx)
	if selected == "" {
		// Single-provider mode: no router selected a provider, so run.
		return true
	}
	return strings.EqualFold(selected, p.params.ProviderID)
}

func selectedProvider(reqCtx *policy.RequestContext) string {
	if reqCtx == nil || reqCtx.SharedContext == nil || reqCtx.Metadata == nil {
		return ""
	}
	raw, ok := reqCtx.Metadata[MetadataKeySelectedProvider]
	if !ok {
		return ""
	}
	v, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// resolveDeployment returns the Azure deployment id that will serve this
// request. The model named in the request payload takes priority; the
// configured model is a fallback, used only when the payload names none. A
// payload model that is absent, null or an empty string counts as none; a
// whitespace-only one is malformed and is rejected even when a fallback exists.
//
// This policy has no response phase, so it records no effective model: nothing
// downstream of it reports one.
func (p *TranslatorPolicy) resolveDeployment(reqCtx *policy.RequestContext) (string, error) {
	raw, present := readModelFromBody(reqCtx)
	if present && raw != nil {
		model, isString := raw.(string)
		if !isString {
			return "", fmt.Errorf("request field 'model' must be a string")
		}
		if trimmed := strings.TrimSpace(model); trimmed != "" {
			return trimmed, nil
		} else if model != "" {
			return "", fmt.Errorf("request field 'model' must not be blank")
		}
	}

	if p.params.Model != "" {
		return p.params.Model, nil
	}
	return "", fmt.Errorf("'model' is required in the request body (or as a policy parameter) " +
		"to derive the Azure deployment id.")
}

// readModelFromBody returns the raw "model" value and whether the payload
// carried one at all, so a non-string can be rejected rather than coerced. An
// absent or unparseable body simply names no model.
func readModelFromBody(reqCtx *policy.RequestContext) (interface{}, bool) {
	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return nil, false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return nil, false
	}
	raw, present := payload["model"]
	return raw, present
}

// buildAzurePath escapes the deployment as a single path segment and the
// apiVersion as a query value. The deployment may originate from the request
// body's "model" field, so it is untrusted and must not be able to inject
// additional path segments or query parameters. pathSuffix is operator-supplied
// configuration and is inserted verbatim.
func buildAzurePath(deployment, pathSuffix, apiVersion string) string {
	return fmt.Sprintf("/openai/deployments/%s%s?api-version=%s",
		url.PathEscape(deployment), pathSuffix, url.QueryEscape(apiVersion))
}

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{PathSuffix: DefaultPathSuffix}

	apiVersion, err := optionalString(params, "apiVersion")
	if err != nil {
		return result, err
	}
	if apiVersion == "" {
		return result, fmt.Errorf("'apiVersion' is required")
	}
	result.APIVersion = apiVersion

	if v, err := optionalString(params, "model"); err != nil {
		return result, err
	} else {
		result.Model = v
	}

	if v, err := optionalString(params, "pathSuffix"); err != nil {
		return result, err
	} else if v != "" {
		// PathSuffix must start with '/' so buildAzurePath can concatenate
		// without inspecting the operator-supplied string.
		if !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		result.PathSuffix = v
	}

	if v, err := optionalString(params, "providerId"); err != nil {
		return result, err
	} else {
		result.ProviderID = v
	}

	return result, nil
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(v), nil
}

// errResponse refuses the exchange and describes why.
//
// direction states which side was refused: DirectionRequest when the caller's payload could
// not be read or converted, DirectionResponse when the provider's could not be translated
// back. Those are operationally different events that share nothing but this function, and
// only the caller knows which it is — which is why it is a parameter rather than inferred
// from the status.
func errResponse(statusCode int, message, code, direction, errorType string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      code,
			Type:      errorType,
			Direction: direction,
			// message already goes to the client as the body's error text.
			Message: message,
		},
	}
}
