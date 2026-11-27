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

// Package modelaccesscontrol checks the model a client requests against an allow or
// deny rule, and redirects a denied model to an administrator-approved fallback when
// a mapping names one.
//
// The decision order for every request is: extract the requested model, apply the
// access rule to it, and only when the rule denies it look up a fallback mapping. A
// permitted model is forwarded unchanged; a mapped model is rewritten (and routed to
// the mapping's provider, if it names one); anything else is rejected before the
// upstream call. Every check runs before the request is modified, so a rejection
// never leaves a partly rewritten request behind. Responses are never modified.
package modelaccesscontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Shared metadata keys. selected_provider is the gateway's routing contract: the
// controller gates provider credentials and transformers on it.
const (
	MetadataSelectedProvider = "selected_provider"
	MetadataRequestedModel   = "model_access_control.requested_model"
	MetadataEffectiveModel   = "model_access_control.effective_model"
	MetadataDecision         = "model_access_control.decision"
	MetadataMappingMatched   = "model_access_control.mapping_matched"
)

// Analytics metadata keys.
const (
	analyticsDecision       = "model_access_decision"
	analyticsRequestedModel = "requested_model"
	analyticsEffectiveModel = "effective_model"
	analyticsMappingMatched = "mapping_matched"
)

// Decisions recorded in metadata and analytics.
const (
	decisionPermitted = "permitted"
	decisionMapped    = "mapped"
	decisionDenied    = "denied"
	decisionSkipped   = "skipped"
	decisionError     = "error"
)

// Statuses follow what OpenAI and Anthropic return themselves: 404 for a model the
// caller cannot use (unknown and restricted look the same, so the response does not
// confirm that a restricted model exists), 400 for a request without a usable model.
const (
	statusModelNotFound = 404
	statusInvalidModel  = 400
	statusRoutingError  = 500
)

// Client-facing bodies. None of them names the requested model, a fallback, a
// provider or a listed model, so a caller cannot enumerate the configuration.
var (
	bodyModelNotFound = []byte(`{"error":{"message":"The model does not exist or you do not have access to it.","type":"invalid_request_error","param":"model","code":"model_not_found"}}`)
	bodyInvalidModel  = []byte(`{"error":{"message":"The request must specify exactly one valid model.","type":"invalid_request_error","param":"model","code":"invalid_model"}}`)
	bodyRoutingError  = []byte(`{"error":{"message":"The request could not be routed.","type":"server_error","code":"routing_error"}}`)
)

// maxLoggedModelLength bounds client-supplied model names in logs and analytics.
const maxLoggedModelLength = 128

// maxModelLength bounds the requested model before any pattern runs on it. Real model
// IDs, Bedrock ARNs included, are far shorter; a longer value is rejected as invalid.
const maxModelLength = 1024

// Policy is immutable after GetPolicy; every per-request value lives in the request
// context, so one instance serves concurrent requests.
type Policy struct {
	cfg *config
}

var (
	_ policy.Policy              = (*Policy)(nil)
	_ policy.RequestHeaderPolicy = (*Policy)(nil)
	_ policy.RequestPolicy       = (*Policy)(nil)
)

// GetPolicy parses, validates and compiles the configuration, so a bad configuration
// fails the deployment rather than the first request.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]any) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		slog.Error("model-access-control: invalid configuration",
			"apiId", metadata.APIId, "route", metadata.RouteName, "error", err)
		return nil, fmt.Errorf("model-access-control: %w", err)
	}
	return &Policy{cfg: cfg}, nil
}

// Mode buffers the request body only when the model is in the payload; every other
// location is read from the request headers. The response is never processed.
func (p *Policy) Mode() policy.ProcessingMode {
	mode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if p.cfg.requestModel.kind == locationPayload {
		mode.RequestBodyMode = policy.BodyModeBuffer
	} else {
		mode.RequestHeaderMode = policy.HeaderModeProcess
	}
	return mode
}

// outcome is the result of evaluating one request, computed before anything in the
// request changes.
type outcome struct {
	requested string // trimmed client-requested model
	effective string // model to forward
	provider  string // provider a mapping selected, empty when none
	mapped    bool
}

func (o outcome) decision() string {
	if o.mapped {
		return decisionMapped
	}
	return decisionPermitted
}

// requestFacts are the per-request values the decision reads and writes.
type requestFacts struct {
	meta      map[string]any
	apiID     string
	operation string
}

func factsFrom(shared *policy.SharedContext) requestFacts {
	if shared == nil {
		return requestFacts{}
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]any{}
	}
	return requestFacts{meta: shared.Metadata, apiID: shared.APIId, operation: shared.OperationPath}
}

// evaluate applies the access rule and, on denial, the fallback mapping. It returns
// a response to send instead of forwarding, or nil with the outcome to apply.
func (p *Policy) evaluate(facts requestFacts, rawRequested string) (outcome, *policy.ImmediateResponse) {
	requested := strings.TrimSpace(rawRequested)
	out := outcome{requested: requested, effective: rawRequested}

	if len(requested) > maxModelLength {
		return out, p.invalidModel(facts, fmt.Sprintf("the requested model is longer than %d bytes", maxModelLength))
	}
	// No model name holds a control character or invalid UTF-8 (which a JSON decoder
	// turns into U+FFFD). Such a name is not on any list, so a deny rule would let it
	// through, while an upstream that strips or truncates it could read a denied model.
	if hasControl(requested) || !utf8.ValidString(requested) || strings.ContainsRune(requested, utf8.RuneError) {
		return out, p.invalidModel(facts, "the requested model contains control characters or invalid UTF-8")
	}

	if p.cfg.access.permits(requested) {
		p.record(facts, out, decisionPermitted)
		return out, nil
	}

	result := p.cfg.mapping.resolve(requested)
	if result.unusable {
		p.record(facts, out, decisionError)
		slog.Error("model-access-control: mapping pattern expanded to an unusable model",
			"apiId", facts.apiID, "operation", facts.operation, "requestedModel", bound(requested))
		return out, p.routingError(out, "a mapping pattern expanded to a blank or invalid model name")
	}
	if !result.matched {
		p.record(facts, out, decisionDenied)
		slog.Info("model-access-control: requested model denied",
			"apiId", facts.apiID, "operation", facts.operation,
			"requestedModel", bound(requested), "mode", string(p.cfg.access.mode))
		return out, p.denied(out, fmt.Sprintf("model %q is denied by the access rule (mode %s) and no fallback mapping matched",
			bound(requested), p.cfg.access.mode))
	}

	// A fixed target is an administrator-approved destination. A target built from
	// capture groups is partly chosen by the client, so it must pass the access rule
	// too; otherwise "legacy-(.*)" -> "$1" would forward any model the client names.
	if result.dynamic && !p.cfg.access.permits(result.target.model) {
		p.record(facts, out, decisionDenied)
		slog.Info("model-access-control: fallback target built from the requested model is not permitted",
			"apiId", facts.apiID, "operation", facts.operation,
			"requestedModel", bound(requested), "fallbackModel", bound(result.target.model))
		return out, p.denied(out, fmt.Sprintf("model %q is denied by the access rule and its fallback %q, built from capture groups, is not permitted either",
			bound(requested), bound(result.target.model)))
	}

	out.effective, out.provider, out.mapped = result.target.model, result.target.provider, true
	if existing, conflict := providerConflict(facts.meta, out.provider); conflict {
		p.record(facts, out, decisionError)
		slog.Error("model-access-control: an earlier policy selected a different provider",
			"apiId", facts.apiID, "operation", facts.operation,
			"mappedProvider", out.provider, "selectedProvider", existing)
		return out, p.routingError(out, "an earlier policy selected a provider that conflicts with the fallback mapping")
	}

	p.record(facts, out, decisionMapped)
	return out, nil
}

// providerConflict reports whether an earlier policy already selected a provider
// that differs from the mapping's. A mapping without a provider targets the proxy's
// primary provider, so any earlier selection conflicts with it: forwarding would send
// the fallback model to a provider it was not configured for.
func providerConflict(meta map[string]any, provider string) (string, bool) {
	raw, ok := meta[MetadataSelectedProvider]
	if !ok || raw == nil {
		return "", false
	}
	existing, ok := raw.(string)
	if !ok || strings.TrimSpace(existing) == "" {
		return fmt.Sprint(raw), true
	}
	return existing, provider == "" || existing != provider
}

// publishRoute writes selected_provider for a mapping that names a provider. It runs
// in the same step that sets UpstreamName, so the router, the provider credentials
// and the transformers all see the same provider.
func publishRoute(facts requestFacts, out outcome) *string {
	if out.provider == "" {
		return nil
	}
	provider := out.provider
	if facts.meta != nil {
		facts.meta[MetadataSelectedProvider] = provider
	}
	return &provider
}

// missing handles a request whose model cannot be established. skippable is true only
// for a request that cannot carry an inference model; ambiguity is never skippable.
func (p *Policy) missing(facts requestFacts, skippable bool, reason error) *policy.ImmediateResponse {
	if p.cfg.access.onMissingModel == missingModelSkip && skippable && !errors.Is(reason, errAmbiguousModel) {
		p.record(facts, outcome{}, decisionSkipped)
		return nil
	}
	description := "the request does not carry a model"
	if reason != nil {
		description = reason.Error()
	}
	return p.invalidModel(facts, description)
}

// invalidModel rejects a request whose model is missing, unreadable, ambiguous or
// too long with 400 invalid_model.
func (p *Policy) invalidModel(facts requestFacts, description string) *policy.ImmediateResponse {
	p.record(facts, outcome{}, decisionDenied)
	slog.Info("model-access-control: request rejected without a usable model",
		"apiId", facts.apiID, "operation", facts.operation, "reason", description)
	return &policy.ImmediateResponse{
		StatusCode:        statusInvalidModel,
		Headers:           jsonHeaders(),
		Body:              bodyInvalidModel,
		AnalyticsMetadata: analytics(outcome{}, decisionDenied),
		IsFault:           true,
		Fault: &policy.FaultDetails{
			Code:        p.missingModelFaultCode(),
			Type:        policy.FaultTypeValidation,
			Direction:   policy.DirectionRequest,
			Message:     "The request does not specify a usable model.",
			Description: description,
		},
	}
}

// missingModelFaultCode names the part of the request that should have carried the model.
func (p *Policy) missingModelFaultCode() string {
	switch p.cfg.requestModel.kind {
	case locationHeader:
		return policy.FaultCodeInvalidRequestHeader
	case locationQuery, locationPath:
		return policy.FaultCodeInvalidRequestURI
	default:
		return policy.FaultCodeInvalidRequestBody
	}
}

func (p *Policy) denied(out outcome, description string) *policy.ImmediateResponse {
	return &policy.ImmediateResponse{
		StatusCode:        statusModelNotFound,
		Headers:           jsonHeaders(),
		Body:              bodyModelNotFound,
		AnalyticsMetadata: analytics(out, decisionDenied),
		IsFault:           true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeAuthForbidden,
			Type:        policy.FaultTypeAuthorization,
			Direction:   policy.DirectionRequest,
			Message:     "The requested model is not permitted.",
			Description: description,
		},
	}
}

func (p *Policy) routingError(out outcome, description string) *policy.ImmediateResponse {
	return &policy.ImmediateResponse{
		StatusCode:        statusRoutingError,
		Headers:           jsonHeaders(),
		Body:              bodyRoutingError,
		AnalyticsMetadata: analytics(out, decisionError),
		IsFault:           true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionRequest,
			Message:     "The request could not be routed.",
			Description: description,
		},
	}
}

// record publishes the per-request result for later policies.
func (p *Policy) record(facts requestFacts, out outcome, decision string) {
	if facts.meta == nil {
		return
	}
	facts.meta[MetadataRequestedModel] = out.requested
	facts.meta[MetadataEffectiveModel] = strings.TrimSpace(out.effective)
	facts.meta[MetadataDecision] = decision
	facts.meta[MetadataMappingMatched] = out.mapped
}

func analytics(out outcome, decision string) map[string]any {
	return map[string]any{
		analyticsDecision:       decision,
		analyticsRequestedModel: bound(out.requested),
		analyticsEffectiveModel: bound(strings.TrimSpace(out.effective)),
		analyticsMappingMatched: out.mapped,
	}
}

// jsonHeaders returns a new map for every response; the kernel owns what it is given.
func jsonHeaders() map[string]string {
	return map[string]string{"content-type": "application/json"}
}

// bound truncates a client-supplied model name for logs and analytics.
func bound(model string) string {
	if len(model) <= maxLoggedModelLength {
		return model
	}
	cut := maxLoggedModelLength
	for cut > 0 && !utf8.ValidString(model[:cut]) {
		cut--
	}
	return model[:cut] + "...(truncated)"
}

// OnRequestHeaders handles the header, queryParam and pathParam locations.
func (p *Policy) OnRequestHeaders(_ context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]any) policy.RequestHeaderAction {
	if p.cfg.requestModel.kind == locationPayload {
		return policy.UpstreamRequestHeaderModifications{}
	}
	facts := factsFrom(reqCtx.SharedContext)

	requested, found, err := p.cfg.requestModel.extractFromRequestLine(reqCtx.Headers, reqCtx.Path)
	if err != nil || !found {
		// A model location that cannot be read is never skipped, as in the body phase:
		// an upstream may still read a model from it.
		if immediate := p.missing(facts, err == nil && mayCarryNoModel(reqCtx.Method, reqCtx.Headers), err); immediate != nil {
			return *immediate
		}
		return policy.UpstreamRequestHeaderModifications{}
	}

	out, immediate := p.evaluate(facts, requested)
	if immediate != nil {
		return *immediate
	}

	mods := policy.UpstreamRequestHeaderModifications{AnalyticsMetadata: analytics(out, out.decision())}
	if out.mapped && out.effective != requested {
		headers, path, err := p.cfg.requestModel.rewriteRequestLine(reqCtx.Path, out.effective)
		if err != nil {
			return *p.rewriteFailed(facts, out, err)
		}
		mods.HeadersToSet, mods.Path = headers, path
	}
	mods.UpstreamName = publishRoute(facts, out)
	return mods
}

// OnRequestBody handles the payload location. A JSON body is read at the JSONPath; a
// form or multipart body is read from the field of the same name, so endpoints that
// upload files are checked too.
func (p *Policy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]any) policy.RequestAction {
	if p.cfg.requestModel.kind != locationPayload {
		return policy.UpstreamRequestModifications{}
	}
	facts := factsFrom(reqCtx.SharedContext)
	skippable := mayCarryNoModel(reqCtx.Method, reqCtx.Headers)

	if reqCtx.Body == nil || !reqCtx.Body.Present || len(bytes.TrimSpace(reqCtx.Body.Content)) == 0 {
		return p.passOrReject(p.missing(facts, skippable, nil))
	}
	content := reqCtx.Body.Content

	// The body decides how it is read, not the Content-Type a client chose: anything
	// that looks like JSON is read as JSON, so labelling a JSON body as a form or as
	// binary cannot hide its model from this policy while an upstream reads it.
	if !looksLikeJSON(content) {
		kind, boundary, err := requestForm(reqCtx.Headers)
		if err != nil {
			return p.passOrReject(p.missing(facts, false, err))
		}
		if kind != formNone {
			return p.onFormBody(facts, kind, boundary, content, skippable)
		}
		// Neither JSON nor a form. A text body is not skipped: a lenient upstream
		// could still find a model in it that this policy cannot read.
		return p.passOrReject(p.missing(facts, skippable && !isTextBody(reqCtx.Headers), errMalformedModel))
	}

	payload, err := p.cfg.requestModel.decodePayload(content)
	if err != nil {
		// A body that looks like JSON but does not parse strictly (a BOM, a trailing
		// comma, trailing data) may still parse upstream, so it is never skipped.
		return p.passOrReject(p.missing(facts, false, err))
	}
	requested, found := p.cfg.requestModel.extractFromPayload(payload)
	if !found {
		// A body that parses as JSON is treated as JSON whatever its content type says.
		// A model that is present but not a string is unreadable, not absent, so it is
		// never skipped, whatever the method.
		skip := isBodylessMethod(reqCtx.Method) && !p.cfg.requestModel.hasUnusableModel(payload)
		return p.passOrReject(p.missing(facts, skip, nil))
	}

	return p.applyBody(facts, requested, func(model string) ([]byte, error) {
		// The rewrite re-encodes the body from a map, which would silently drop one
		// value of a repeated member, so such a body is refused instead.
		if err := checkNoRepeatedMembers(content); err != nil {
			return nil, err
		}
		return p.cfg.requestModel.rewritePayload(payload, model)
	})
}

// onFormBody checks the model field of a URL-encoded or multipart body. A form
// without the field (a file upload, for example) is a request without a model.
func (p *Policy) onFormBody(facts requestFacts, kind formKind, boundary string, content []byte, skippable bool) policy.RequestAction {
	key := p.cfg.requestModel.formKey()
	if key == "" {
		return p.passOrReject(p.missing(facts, false, errMalformedModel))
	}
	requested, found, err := extractFromForm(kind, boundary, content, key)
	if err != nil {
		return p.passOrReject(p.missing(facts, false, err))
	}
	if !found {
		return p.passOrReject(p.missing(facts, skippable, nil))
	}
	return p.applyBody(facts, requested, func(model string) ([]byte, error) {
		return rewriteForm(kind, boundary, content, key, model)
	})
}

// applyBody evaluates the requested model and builds the body modifications. An
// unchanged model keeps the client's bytes exactly; Body nil passes them through.
func (p *Policy) applyBody(facts requestFacts, requested string, rewrite func(string) ([]byte, error)) policy.RequestAction {
	out, immediate := p.evaluate(facts, requested)
	if immediate != nil {
		return *immediate
	}
	mods := policy.UpstreamRequestModifications{AnalyticsMetadata: analytics(out, out.decision())}
	if out.mapped && out.effective != requested {
		body, err := rewrite(out.effective)
		if err != nil {
			return *p.rewriteFailed(facts, out, err)
		}
		mods.Body = body
	}
	mods.UpstreamName = publishRoute(facts, out)
	return mods
}

// passOrReject returns the rejection, or forwards the request unchanged when there is
// none (a skipped request).
func (p *Policy) passOrReject(immediate *policy.ImmediateResponse) policy.RequestAction {
	if immediate != nil {
		return *immediate
	}
	return policy.UpstreamRequestModifications{}
}

// rewriteFailed rejects a request whose model could not be replaced. It runs before
// selected_provider is written, so nothing of the failed route is left behind.
func (p *Policy) rewriteFailed(facts requestFacts, out outcome, err error) *policy.ImmediateResponse {
	p.record(facts, out, decisionError)
	slog.Error("model-access-control: failed to rewrite the request model",
		"apiId", facts.apiID, "operation", facts.operation,
		"location", string(p.cfg.requestModel.kind), "error", err)
	return p.routingError(out, "the fallback model could not be written to the request: "+err.Error())
}

// mayCarryNoModel reports whether a request is one onMissingModel: skip may forward:
// a method that carries no inference body, or a body that is not JSON. A JSON request
// without a model is never skipped, so skip cannot become a bypass. The body phase
// narrows this further for text bodies and bodies that parse as JSON.
func mayCarryNoModel(method string, headers *policy.Headers) bool {
	if isBodylessMethod(method) {
		return true
	}
	mediaType := singleMediaType(headers)
	return mediaType != "" && mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")
}

func isBodylessMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "DELETE", "OPTIONS":
		return true
	}
	return false
}

// looksLikeJSON reports whether the body's first character opens a JSON object or
// array, skipping whitespace, NUL bytes and UTF-8, UTF-16 or UTF-32 byte order marks.
// Parsers such as Python's json.loads detect UTF-16 and UTF-32 by those bytes, so a
// body in either encoding counts as JSON here; it then fails the strict decode and is
// rejected instead of skipped.
func looksLikeJSON(body []byte) bool {
	for i := 0; i < len(body); i++ {
		switch {
		case body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n' || body[i] == 0:
		case bytes.HasPrefix(body[i:], utf8BOM):
			i += len(utf8BOM) - 1
		case bytes.HasPrefix(body[i:], []byte{0xfe, 0xff}) || bytes.HasPrefix(body[i:], []byte{0xff, 0xfe}):
			i++
		default:
			return body[i] == '{' || body[i] == '['
		}
	}
	return false
}

var utf8BOM = []byte("\xef\xbb\xbf")

// isTextBody reports a text/* content type.
func isTextBody(headers *policy.Headers) bool {
	return strings.HasPrefix(singleMediaType(headers), "text/")
}

// singleMediaType returns the lower-cased media type of a single Content-Type header,
// or "" when there is none or more than one.
func singleMediaType(headers *policy.Headers) string {
	values := headers.Get("content-type")
	if len(values) != 1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(strings.SplitN(values[0], ";", 2)[0]))
}
