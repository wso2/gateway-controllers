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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package contextbasedrouting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	metadataInputTokens      = "context_based_routing.input_tokens"
	metadataSelectedModel    = "context_based_routing.selected_model"
	metadataSelectedProvider = "context_based_routing.selected_provider"
	metadataSelectedRoute    = "context_based_routing.selected_route"
	metadataProviderRouting  = "selected_provider"
)

type ContextBasedRoutingPolicy struct {
	config config
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return &ContextBasedRoutingPolicy{config: parsed}, nil
}

func (p *ContextBasedRoutingPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func (p *ContextBasedRoutingPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return badRequest("request body must contain a JSON object")
	}

	var decoded interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &decoded); err != nil {
		return badRequest("request body contains malformed JSON")
	}
	payload, ok := decoded.(map[string]interface{})
	if !ok || payload == nil {
		return badRequest("request body must be a JSON object")
	}

	inputTokens, estimateErr := estimateInputTokens(payload, p.config.CharsPerToken, p.config.InputJSONPaths)
	if estimateErr != nil {
		if p.config.Fallback == nil {
			return policy.UpstreamRequestModifications{}
		}
		return p.applyTarget(reqCtx, payload, *p.config.Fallback, "fallback")
	}
	reqCtx.Metadata[metadataInputTokens] = inputTokens

	for i, route := range p.config.Routes {
		if rangeMatches(route, inputTokens) {
			name := route.Name
			if name == "" {
				name = fmt.Sprintf("route-%d", i+1)
			}
			return p.applyTarget(reqCtx, payload, route.Target, name)
		}
	}

	if p.config.Fallback != nil {
		return p.applyTarget(reqCtx, payload, *p.config.Fallback, "fallback")
	}
	return policy.UpstreamRequestModifications{}
}

func rangeMatches(route tokenRange, tokens int64) bool {
	if route.MinTokens != nil && tokens < *route.MinTokens {
		return false
	}
	if route.MaxTokens != nil && tokens >= *route.MaxTokens {
		return false
	}
	return true
}

func (p *ContextBasedRoutingPolicy) applyTarget(
	reqCtx *policy.RequestContext,
	payload map[string]interface{},
	selected target,
	routeName string,
) policy.RequestAction {
	mods := policy.UpstreamRequestModifications{}
	identifier := p.config.RequestModel.Identifier

	switch p.config.RequestModel.Location {
	case "payload":
		if err := utils.SetValueAtJSONPath(payload, identifier, selected.Model); err != nil {
			return badRequest(fmt.Sprintf("model location '%s' is missing or invalid", identifier))
		}
		updated, err := json.Marshal(payload)
		if err != nil {
			return policy.ImmediateResponse{
				StatusCode: 500,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(`{"error":"failed to prepare routed request"}`),
			}
		}
		mods.Body = updated
	case "header":
		mods.HeadersToSet = map[string]string{identifier: selected.Model}
	case "queryParam":
		path, ok := rewriteQueryParameter(reqCtx.Path, identifier, selected.Model)
		if !ok {
			return badRequest(fmt.Sprintf("request path could not be rewritten for model query parameter '%s'", identifier))
		}
		mods.Path = &path
	case "pathParam":
		path, ok := rewritePathParameter(reqCtx.Path, p.config.RequestModel.PathExpression, p.config.RequestModel.PathModelGroup, selected.Model)
		if !ok {
			return badRequest(fmt.Sprintf("model path expression '%s' did not match the request", identifier))
		}
		mods.Path = &path
	}

	if selected.Provider != "" {
		providerName := selected.Provider
		mods.UpstreamName = &providerName
		reqCtx.Metadata[metadataProviderRouting] = providerName
	}
	reqCtx.Metadata[metadataSelectedModel] = selected.Model
	reqCtx.Metadata[metadataSelectedProvider] = selected.Provider
	reqCtx.Metadata[metadataSelectedRoute] = routeName
	return mods
}

func badRequest(message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return policy.ImmediateResponse{
		StatusCode: 400,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

func rewriteQueryParameter(rawPath, name, model string) (string, bool) {
	parsed, err := url.ParseRequestURI(rawPath)
	if err != nil {
		return rawPath, false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return rawPath, false
	}
	query.Set(name, model)
	parsed.RawQuery = query.Encode()
	return parsed.RequestURI(), true
}

func rewritePathParameter(rawPath string, expression *regexp.Regexp, modelGroup int, model string) (string, bool) {
	original, indices := modelFromPath(rawPath, expression, modelGroup)
	if original == "" || indices == nil {
		return rawPath, false
	}
	parts := strings.SplitN(rawPath, "?", 2)
	updated := parts[0][:indices[0]] + model + parts[0][indices[1]:]
	if len(parts) == 2 {
		updated += "?" + parts[1]
	}
	return updated, true
}

func modelFromPath(rawPath string, expression *regexp.Regexp, modelGroup int) (string, []int) {
	if expression == nil {
		return "", nil
	}
	parts := strings.SplitN(rawPath, "?", 2)
	indices := expression.FindStringSubmatchIndex(parts[0])
	indexOffset := modelGroup * 2
	if len(indices) <= indexOffset+1 || indices[indexOffset] < 0 || indices[indexOffset+1] < 0 {
		return "", nil
	}
	start, end := indices[indexOffset], indices[indexOffset+1]
	return parts[0][start:end], []int{start, end}
}
