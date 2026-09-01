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

// Package costbasedrouting routes LLM requests through independently budgeted
// model targets. A configured client-requested model is preferred while its
// budget remains; otherwise the first available ordered route is selected. When
// every budget is exhausted, the configured behaviour either uses the default
// target or rejects the request with HTTP 429.
package costbasedrouting

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	// Policy-internal metadata. These names are namespaced so they cannot
	// collide with the other model-routing policies in the same chain.
	metadataSelectedModel    = "cost_based_routing.selected_model"
	metadataSelectedProvider = "cost_based_routing.selected_provider"
	metadataSelectedTier     = "cost_based_routing.selected_tier"
	metadataSelectedRoute    = "cost_based_routing.selected_route"
	metadataTrackPrimaryCost = "cost_based_routing.track_primary_cost"
	metadataBudgetKey        = "cost_based_routing.budget_key"
	metadataBudgetIndex      = "cost_based_routing.budget_index"
	metadataCostCharged      = "cost_based_routing.cost_charged"

	// metadataProviderRouting is the engine-level contract key read by the
	// conditional provider-authentication and protocol-transformer policies.
	metadataProviderRouting = "selected_provider"

	// Cost metadata published by the llm-cost system policy.
	metadataLLMCost         = "x-llm-cost"
	metadataLLMCostStatus   = "x-llm-cost-status"
	llmCostStatusCalculated = "calculated"

	tierPrimary  = "primary"
	tierFallback = "fallback"
	tierDefault  = "default"
)

type routeBudget struct {
	store     *budgetStore
	namespace string
}

type routingSelection struct {
	target      target
	routeName   string
	budgetIndex int
	budgetKey   string
	budgetState budgetState
	available   int64
}

// CostBasedRoutingPolicy prefers a matching client-requested LLM target, then
// selects the first ordered fallback whose recorded spending still fits inside
// its configured budgets.
type CostBasedRoutingPolicy struct {
	metadata policy.PolicyMetadata
	config   config
	budgets  []routeBudget

	// Legacy test/back-compat aliases for the first budgeted route.
	budget          *budgetStore
	budgetNamespace string
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	budgets := make([]routeBudget, len(parsed.Routes))
	for i, route := range parsed.Routes {
		store, err := newBudgetStore(parsed, route, metadata)
		if err != nil {
			return nil, err
		}
		budgets[i] = routeBudget{
			store:     store,
			namespace: budgetNamespaceFor(metadata, parsed, route),
		}
	}
	result := &CostBasedRoutingPolicy{
		metadata: metadata,
		config:   parsed,
		budgets:  budgets,
	}
	if len(budgets) > 0 {
		result.budget = budgets[0].store
		result.budgetNamespace = budgets[0].namespace
	}
	return result, nil
}

// Mode requests the phases the policy needs. The request body is buffered only
// when the model lives in the payload. The response body is streamed so that
// cost accounting works for both streamed and buffered LLM responses.
func (p *CostBasedRoutingPolicy) Mode() policy.ProcessingMode {
	requestBodyMode := policy.BodyModeSkip
	if p.config.RequestModel.Location == "payload" {
		requestBodyMode = policy.BodyModeBuffer
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    requestBodyMode,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// OnRequestHeaders reads the client-requested model when it is available in a
// header, query parameter, or path parameter and performs the routing decision.
// Payload-based matching is deferred to OnRequestBody because the body is not
// available in this phase. With requested-model matching disabled, payload
// requests retain the historical header-phase selection behaviour.
func (p *CostBasedRoutingPolicy) OnRequestHeaders(
	ctx context.Context,
	reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{},
) policy.RequestHeaderAction {
	if reqCtx.SharedContext.Metadata == nil {
		reqCtx.SharedContext.Metadata = make(map[string]interface{})
	}

	if p.config.RespectRequestedModel && p.config.RequestModel.Location == "payload" {
		return policy.UpstreamRequestHeaderModifications{}
	}

	requestedModel := ""
	if p.config.RespectRequestedModel {
		requestedModel = requestedModelFromHeaders(reqCtx, p.config.RequestModel)
	}
	selection, failure := p.selectTarget(ctx, reqCtx.Metadata, requestedModel)
	if failure != nil {
		return *failure
	}
	p.recordAndLogSelection(reqCtx.Metadata, selection, requestedModel)

	mods := policy.UpstreamRequestHeaderModifications{}
	applyProviderRouting(reqCtx.Metadata, selection.target, func(name *string) { mods.UpstreamName = name })

	identifier := p.config.RequestModel.Identifier
	switch p.config.RequestModel.Location {
	case "payload":
		// The payload is rewritten in OnRequestBody using the target chosen here.
	case "header":
		mods.HeadersToSet = map[string]string{identifier: selection.target.Model}
	case "queryParam":
		path, ok := rewriteQueryParameter(reqCtx.Path, identifier, selection.target.Model)
		if !ok {
			return badRequest(fmt.Sprintf("request path could not be rewritten for model query parameter '%s'", identifier))
		}
		mods.Path = &path
	case "pathParam":
		path, ok := rewritePathParameter(reqCtx.Path, p.config.RequestModel.PathExpression,
			p.config.RequestModel.PathModelGroup, selection.target.Model)
		if !ok {
			return badRequest(fmt.Sprintf("model path expression '%s' did not match the request", identifier))
		}
		mods.Path = &path
	}

	return mods
}

// OnRequestBody reads the requested model and performs requested-model-first
// selection for payload configurations, then rewrites both the model and the
// upstream provider. When matching is disabled, it applies the target selected
// in the header phase.
func (p *CostBasedRoutingPolicy) OnRequestBody(
	ctx context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if p.config.RequestModel.Location != "payload" {
		return policy.UpstreamRequestModifications{}
	}

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

	identifier := p.config.RequestModel.Identifier
	model, _ := reqCtx.Metadata[metadataSelectedModel].(string)
	selectedProvider := ""
	if p.config.RespectRequestedModel {
		requestedModel := requestedModelFromPayload(payload, identifier)
		selection, failure := p.selectTarget(ctx, reqCtx.Metadata, requestedModel)
		if failure != nil {
			return *failure
		}
		p.recordAndLogSelection(reqCtx.Metadata, selection, requestedModel)
		model = selection.target.Model
		selectedProvider = selection.target.Provider
	}
	if model == "" {
		slog.Error("CostBasedRouting: no target was selected for payload request",
			"route", p.metadata.RouteName)
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error":"cost-based routing target was not selected"}`),
		}
	}
	if err := utils.SetValueAtJSONPath(payload, identifier, model); err != nil {
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

	mods := policy.UpstreamRequestModifications{Body: updated}
	if p.config.RespectRequestedModel {
		applyProviderRouting(reqCtx.Metadata, target{Model: model, Provider: selectedProvider}, func(name *string) { mods.UpstreamName = name })
	}
	return mods
}

// selectTarget tries the route matching the client's requested model first.
// If it is absent or exhausted, routes are checked from the top in configured
// order. A previously checked requested route is skipped on the fallback pass.
func (p *CostBasedRoutingPolicy) selectTarget(ctx context.Context, metadata map[string]interface{}, requestedModel string) (routingSelection, *policy.ImmediateResponse) {
	requestedIndex := -1
	if p.config.RespectRequestedModel && requestedModel != "" {
		for i, route := range p.config.Routes {
			if route.Target.Model == requestedModel {
				requestedIndex = i
				break
			}
		}
	}

	indices := make([]int, 0, len(p.config.Routes)+1)
	if requestedIndex >= 0 {
		indices = append(indices, requestedIndex)
	}
	for i := range p.config.Routes {
		if i != requestedIndex {
			indices = append(indices, i)
		}
	}

	selection := routingSelection{routeName: tierDefault, budgetIndex: -1, budgetState: budgetExhausted}
	for _, i := range indices {
		route := p.config.Routes[i]
		budget := p.routeBudgetAt(i)
		key := budgetKey(budget.namespace, p.config.ConsumerBased, metadata)
		state, available, err := budget.store.Query(ctx, key)
		selection.available = available
		if err != nil {
			if !budget.store.failOpen {
				slog.Error("CostBasedRouting: budget storage unavailable and failure mode is closed",
					"route", p.metadata.RouteName, "costRoute", route.Name, "backend", budget.store.backend, "error", err)
				failure := serviceUnavailable("budget state is unavailable")
				return routingSelection{}, &failure
			}
			slog.Warn("CostBasedRouting: budget storage unavailable, continuing on configured route",
				"route", p.metadata.RouteName, "costRoute", route.Name, "backend", budget.store.backend, "error", err)
			selection.target = route.Target
			selection.routeName = route.Name
			selection.budgetIndex = i
			selection.budgetKey = key
			selection.budgetState = budgetUnknown
			return selection, nil
		}
		if state == budgetAvailable {
			selection.target = route.Target
			selection.routeName = route.Name
			selection.budgetIndex = i
			selection.budgetKey = key
			selection.budgetState = state
			return selection, nil
		}
	}
	if p.config.OnExhausted == onExhaustedReject {
		failure := budgetExhaustedResponse()
		return routingSelection{}, &failure
	}

	if p.config.Default != nil {
		selection.target = *p.config.Default
		if p.config.LegacyDefaultTier {
			selection.routeName = tierFallback
		}
	}
	return selection, nil
}

func (p *CostBasedRoutingPolicy) recordAndLogSelection(metadata map[string]interface{}, selection routingSelection, requestedModel string) {
	slog.Debug("CostBasedRouting: selected target",
		"route", p.metadata.RouteName,
		"requestedModel", requestedModel,
		"costRoute", selection.routeName,
		"budgetState", selection.budgetState.String(),
		"availableScaledUnits", selection.available,
		"consumerBased", p.config.ConsumerBased)
	p.recordSelection(metadata, selection.target, selection.routeName, selection.routeName,
		selection.budgetKey, selection.budgetIndex, selection.budgetIndex >= 0)
}

func requestedModelFromHeaders(reqCtx *policy.RequestHeaderContext, cfg requestModelConfig) string {
	switch cfg.Location {
	case "header":
		values := reqCtx.Headers.Get(cfg.Identifier)
		if len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	case "queryParam":
		parsed, err := url.ParseRequestURI(reqCtx.Path)
		if err == nil {
			return strings.TrimSpace(parsed.Query().Get(cfg.Identifier))
		}
	case "pathParam":
		model, _ := modelFromPath(reqCtx.Path, cfg.PathExpression, cfg.PathModelGroup)
		return strings.TrimSpace(model)
	}
	return ""
}

func requestedModelFromPayload(payload map[string]interface{}, identifier string) string {
	value, err := utils.ExtractValueFromJsonpath(payload, identifier)
	if err != nil {
		return ""
	}
	model, _ := value.(string)
	return strings.TrimSpace(model)
}

// OnResponseHeaders preserves the upstream response as-is. The policy exposes
// no budget headers: the remaining budget is not yet final at this point,
// because this request's own cost is only known once its body completes.
func (p *CostBasedRoutingPolicy) OnResponseHeaders(
	_ context.Context,
	_ *policy.ResponseHeaderContext,
	_ map[string]interface{},
) policy.ResponseHeaderAction {
	return policy.DownstreamResponseHeaderModifications{}
}

// OnResponseBodyChunk forwards every chunk unchanged and charges the selected
// route budget once, at end of stream, after llm-cost publishes the actual cost.
func (p *CostBasedRoutingPolicy) OnResponseBodyChunk(
	ctx context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if chunk != nil && chunk.EndOfStream {
		p.chargeOnce(ctx, respCtx.Metadata)
	}
	return policy.ForwardResponseChunk{}
}

// NeedsMoreResponseData reports false: the cost is read from metadata that
// llm-cost publishes, so this policy never accumulates response bytes itself.
func (p *CostBasedRoutingPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody is the buffered fallback used when the chain cannot stream.
// It charges through the same once-only path as the streaming hook.
func (p *CostBasedRoutingPolicy) OnResponseBody(
	ctx context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	p.chargeOnce(ctx, respCtx.Metadata)
	return policy.DownstreamResponseModifications{}
}

// recordSelection publishes the routing decision for the later phases and for
// diagnostics. trackCost is the single switch that decides whether the response
// cost reaches one of the configured route budgets.
func (p *CostBasedRoutingPolicy) recordSelection(metadata map[string]interface{}, selected target, routeName, tier, key string, budgetIndex int, trackCost bool) {
	metadata[metadataSelectedModel] = selected.Model
	metadata[metadataSelectedProvider] = selected.Provider
	metadata[metadataSelectedTier] = tier
	metadata[metadataSelectedRoute] = routeName
	metadata[metadataTrackPrimaryCost] = trackCost
	if trackCost {
		metadata[metadataBudgetKey] = key
		metadata[metadataBudgetIndex] = budgetIndex
	} else {
		delete(metadata, metadataBudgetKey)
		delete(metadata, metadataBudgetIndex)
	}
}

func (p *CostBasedRoutingPolicy) routeBudgetAt(index int) routeBudget {
	budget := p.budgets[index]
	if index == 0 && p.budget != nil {
		budget.store = p.budget
		if p.budgetNamespace != "" {
			budget.namespace = p.budgetNamespace
		}
	}
	return budget
}

// applyProviderRouting points the request at the target's named upstream and
// publishes the engine's selected_provider contract key. A target without a
// provider must use the LLM proxy's default provider, so no upstream name is
// set and any selected_provider left behind by an earlier policy is removed —
// stale routing metadata would otherwise select the wrong provider.
func applyProviderRouting(metadata map[string]interface{}, selected target, setUpstream func(*string)) {
	if selected.Provider == "" {
		delete(metadata, metadataProviderRouting)
		return
	}
	provider := selected.Provider
	setUpstream(&provider)
	metadata[metadataProviderRouting] = provider
}

// chargeOnce records this request's cost against the selected route budget at
// most once. It is a no-op for default requests, and it deliberately skips the
// charge whenever the cost is absent, unusable, or was not calculated: a
// pricing gap must never be able to exhaust a budget.
func (p *CostBasedRoutingPolicy) chargeOnce(ctx context.Context, metadata map[string]interface{}) {
	if metadata == nil {
		return
	}
	if charged, _ := metadata[metadataCostCharged].(bool); charged {
		return
	}

	track, _ := metadata[metadataTrackPrimaryCost].(bool)
	if !track {
		// Default requests still have their cost calculated for analytics; it
		// simply never reaches a route budget.
		return
	}

	// Claim the charge before attempting it so that the streaming and buffered
	// hooks can never both deduct for the same response.
	metadata[metadataCostCharged] = true

	key, _ := metadata[metadataBudgetKey].(string)
	if key == "" {
		slog.Warn("CostBasedRouting: budget key missing, skipping cost accounting",
			"route", p.metadata.RouteName)
		return
	}
	budgetIndex, ok := metadata[metadataBudgetIndex].(int)
	if !ok || budgetIndex < 0 || budgetIndex >= len(p.budgets) {
		slog.Warn("CostBasedRouting: budget route missing, skipping cost accounting",
			"route", p.metadata.RouteName)
		return
	}
	budget := p.routeBudgetAt(budgetIndex)

	cost, status, ok := parseReportedCost(metadata)
	if !ok {
		slog.Warn("CostBasedRouting: no usable LLM cost was reported, budget not charged",
			"route", p.metadata.RouteName,
			"costStatus", status,
			"costPresent", metadata[metadataLLMCost] != nil,
			"hint", "attach the llm-cost policy after this policy on the same path")
		return
	}
	if cost == 0 {
		slog.Debug("CostBasedRouting: reported cost is zero, budget not charged",
			"route", p.metadata.RouteName)
		return
	}

	scaled, ok := scaleCost(cost, p.config.CostScaleFactor)
	if !ok || scaled <= 0 {
		slog.Warn("CostBasedRouting: reported cost could not be scaled, budget not charged",
			"route", p.metadata.RouteName, "costScaleFactor", p.config.CostScaleFactor)
		return
	}

	if err := budget.store.Charge(ctx, key, scaled); err != nil {
		slog.Error("CostBasedRouting: failed to charge the route budget",
			"route", p.metadata.RouteName, "costRoute", metadata[metadataSelectedRoute], "backend", budget.store.backend, "error", err)
		return
	}

	slog.Debug("CostBasedRouting: charged the route budget",
		"route", p.metadata.RouteName, "costRoute", metadata[metadataSelectedRoute], "scaledUnits", scaled)
}

func badRequest(message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return policy.ImmediateResponse{
		StatusCode: 400,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

func serviceUnavailable(message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return policy.ImmediateResponse{
		StatusCode: 503,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

func budgetExhaustedResponse() policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{
		"error": "all configured route budgets are exhausted",
		"code":  "cost_based_routing_budget_exhausted",
	})
	return policy.ImmediateResponse{
		StatusCode: 429,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

// rewriteQueryParameter replaces (or adds) the model query parameter while
// preserving the path, the other parameters, and correct URL escaping.
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

// rewritePathParameter replaces only the captured model segment, preserving the
// rest of the path and the query string.
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
