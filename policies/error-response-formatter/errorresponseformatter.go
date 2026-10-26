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

// Package errorresponseformatter renders a gateway error into a shape an operator defines.
//
// It authors a body, and the gateway formats an error only when nothing else authored one, so
// the built-in formatter stands down with no flag and no ordering requirement.
//
// Two ways to describe a shape:
//
//   - `template` — a structured object rendered as JSON. A leaf that is exactly ${Status}
//     becomes a JSON number; a string template could only produce "401".
//   - `stringTemplate` — raw text, for output that is not an object: XML, SOAP, plain text,
//     where attributes, namespaces and stable element order all matter.
//
// Substituted values are escaped for the output syntax, so a message containing "</fault>"
// cannot break out of its element.

package errorresponseformatter

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Parameter names.
const (
	paramPreset         = "preset"
	paramTemplate       = "template"
	paramStringTemplate = "stringTemplate"
	paramContentType    = "contentType"
	paramEscape         = "escape"
	paramHeadersToSet   = "headersToSet"
	paramHeadersToAdd   = "headersToAppend"
	paramHeadersRemove  = "headersToRemove"
	paramStatusCode     = "statusCode"
)

// The statuses statusCode may set. Below 200 is excluded because a 1xx is not a final response;
// 2xx and 3xx are allowed, because some protocols carry an error inside one — JSON-RPC over HTTP
// conventionally answers 200 with an error object.
const (
	minStatusCode = 200
	maxStatusCode = 599
)

// Content types.
const (
	contentTypeJSON    = "application/json"
	contentTypeTextXML = "text/xml"             // SOAP 1.1
	contentTypeSOAP12  = "application/soap+xml" // SOAP 1.2
)

// escapeMode is how substituted values are made safe for the output syntax.
type escapeMode string

const (
	// escapeAuto derives the mode from contentType. The default, and correct for every
	// content type the presets use.
	escapeAuto escapeMode = "auto"
	escapeXML  escapeMode = "xml"
	escapeJSON escapeMode = "json"
	escapeNone escapeMode = "none"
)

// Preset names. A preset exists wherever the target shape is exact and a near-miss is rejected
// as firmly as garbage — an OpenAI client, a JSON-RPC client, a SOAP stack.
const (
	presetOpenAI    = "openai"
	presetCanonical = "canonical"
	presetJSONRPC   = "jsonrpc"
	presetSOAP11    = "soap11"
	presetSOAP12    = "soap12"
)

// placeholderRe matches ${Field}.
var placeholderRe = regexp.MustCompile(`\$\{([A-Za-z0-9]+)\}`)

// typedFields are placeholders that keep their natural JSON type when a structured leaf is
// exactly the placeholder — a number stays a number, and an absent JSON-RPC id stays null
// rather than becoming the string "null".
var typedFields = map[string]bool{"Status": true, "JsonRpcCode": true, "JsonRpcID": true}

// ErrorFormatterPolicy renders the error into the configured shape. Immutable after
// construction, so the shared instance is safe across concurrent requests.
type ErrorFormatterPolicy struct {
	template       map[string]interface{} // JSON output; nil when stringTemplate is used
	stringTemplate string                 // text output; empty when template is used
	contentType    string
	escape         escapeMode

	// Header mutations applied alongside the body. Placeholders are expanded in values, so a
	// header can carry the failure's own detail — x-error-code: ${Code} being the case that
	// comes up, since a client that wants to branch without parsing the body needs it there.
	//
	// Names are NOT expanded. A header name built from the failure would let one error
	// produce a header another does not, and a caller cannot write against a header set that
	// varies per response.
	headersToSet    []headerEntry
	headersToAppend []headerEntry
	headersToRemove []string

	// statusCode replaces the response status when non-zero. 0 keeps the status the failure
	// already has.
	statusCode int
}

// headerEntry is one configured header mutation, before placeholders are expanded.
type headerEntry struct {
	Name  string
	Value string
}

// Compile-time proof that this satisfies the fault-path contract.
//
// Worth stating why: OnFault is dispatched ONLY for entries in spec.faultPolicies. A policy
// implementing it but declared under spec.policies deploys and never runs; a policy declared as
// a fault entry WITHOUT it is dropped at chain build. This assertion catches the second.
var _ policy.FaultPolicy = (*ErrorFormatterPolicy)(nil)

// GetPolicy validates the configuration when the gateway builds the API's policy chain. A
// configuration it refuses leaves this policy out of the fault chain, and the gateway logs why.
//
// Everything checkable is checked here rather than per request: this policy runs when a request
// is already failing, and discovering a bad template there would replace a usable error with a
// worse one.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	preset := stringParam(params, paramPreset, "")
	rawTemplate, hasTemplate := params[paramTemplate]
	stringTemplate := stringParam(params, paramStringTemplate, "")

	set := 0
	for _, on := range []bool{preset != "", hasTemplate, stringTemplate != ""} {
		if on {
			set++
		}
	}
	if set > 1 {
		return nil, fmt.Errorf("set only one of %s, %s or %s", paramPreset, paramTemplate, paramStringTemplate)
	}

	p := &ErrorFormatterPolicy{
		contentType: stringParam(params, paramContentType, ""),
		escape:      escapeMode(stringParam(params, paramEscape, string(escapeAuto))),
	}

	var err error
	if p.headersToSet, err = headerEntries(params, paramHeadersToSet); err != nil {
		return nil, err
	}
	if p.headersToAppend, err = headerEntries(params, paramHeadersToAdd); err != nil {
		return nil, err
	}
	if p.headersToRemove, err = stringListParam(params, paramHeadersRemove); err != nil {
		return nil, err
	}
	if err = validateHeaderNames(p.headersToSet, p.headersToAppend, p.headersToRemove); err != nil {
		return nil, err
	}
	if p.statusCode, err = statusCodeParam(params); err != nil {
		return nil, err
	}

	switch {
	case preset != "":
		sh, ok := presetShape(preset)
		if !ok {
			return nil, fmt.Errorf("unknown %s %q (known: %s)", paramPreset, preset, strings.Join(presetNames(), ", "))
		}
		p.template, p.stringTemplate = sh.template, sh.stringTemplate
		// An explicit contentType still wins: a preset's default is a default, not a lock.
		if p.contentType == "" {
			p.contentType = sh.contentType
		}
	case hasTemplate:
		tmpl, ok := rawTemplate.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s must be an object; use %s for XML, SOAP or plain text",
				paramTemplate, paramStringTemplate)
		}
		p.template = tmpl
	case stringTemplate != "":
		p.stringTemplate = stringTemplate
	default:
		// No configuration at all is the canonical shape rather than an error: the policy is
		// then a plain "give me one consistent error body", which is a reasonable thing to want.
		sh, _ := presetShape(presetCanonical)
		p.template, p.contentType = sh.template, orDefault(p.contentType, sh.contentType)
	}

	if p.contentType == "" {
		p.contentType = contentTypeJSON
	}
	switch p.escape {
	case escapeAuto, escapeXML, escapeJSON, escapeNone:
	default:
		return nil, fmt.Errorf("unknown %s %q (known: auto, xml, json, none)", paramEscape, p.escape)
	}
	return p, p.validate()
}

// GetPolicyV2 is an alias for GetPolicy, for the Builder-generated plugin registry.
func GetPolicyV2(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	return GetPolicy(metadata, params)
}

// validate rejects what cannot be rendered, before the policy is ever used.
func (p *ErrorFormatterPolicy) validate() error {
	var texts []string
	if p.stringTemplate != "" {
		texts = append(texts, p.stringTemplate)
	}
	collectStrings(p.template, &texts)
	// Header values are templates too, so an unknown placeholder in one has to be caught up
	// front like any other — otherwise it reaches a client verbatim as "${Coed}".
	for _, e := range p.headersToSet {
		texts = append(texts, e.Value)
	}
	for _, e := range p.headersToAppend {
		texts = append(texts, e.Value)
	}

	seen := map[string]bool{}
	var unknown []string
	known := view{}.fields()
	for _, t := range texts {
		if strings.Contains(t, "{{") {
			return fmt.Errorf("{{...}} is reserved by the gateway's spec templating and never reaches this policy; use ${Field}")
		}
		for _, m := range placeholderRe.FindAllStringSubmatch(t, -1) {
			if _, ok := known[m[1]]; !ok && !seen[m[1]] {
				seen[m[1]] = true
				unknown = append(unknown, m[1])
			}
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown placeholder(s) %s (known: %s)",
			strings.Join(unknown, ", "), strings.Join(knownFields(), ", "))
	}

	// A structured template must survive encoding. Checked once here so a request-time marshal
	// cannot be the first time an unencodable value is discovered.
	if p.template != nil {
		if _, err := json.Marshal(renderMap(p.template, view{Status: 500}, escapeNone)); err != nil {
			return fmt.Errorf("%s cannot be encoded as JSON: %w", paramTemplate, err)
		}
	}
	return nil
}

// Mode skips every normal phase. This policy exists only on the fault path, and declaring a
// phase it does not use would make the engine buffer bodies for successful traffic.
func (p *ErrorFormatterPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnFault renders the body, and replaces the status when statusCode is set.
//
// Returns modifications rather than an ImmediateResponse: an immediate response ends the fault
// chain, and reformatting a body is not a reason to stop an operator's other handlers running.
func (p *ErrorFormatterPolicy) OnFault(
	ctx context.Context,
	faultCtx *policy.FaultContext,
	_ map[string]interface{},
) *policy.FaultResponse {
	// nil is "changed nothing" in the new contract, which is exactly what the degraded paths
	// below want: leaving the error untouched authors no body, so the gateway's own protocol
	// formatter still gets its turn. Previously this returned an empty modification, which
	// meant the same thing but made the caller inspect it to find out.
	if faultCtx == nil {
		return nil
	}

	// The view is built from the status the client will RECEIVE, so ${Status} and everything
	// derived from it — the OpenAI type, the JSON-RPC and SOAP codes — agree with the new status
	// rather than describing one the client never sees.
	status := faultCtx.ResponseStatus
	if p.statusCode != 0 {
		status = p.statusCode
	}
	v := viewOf(faultCtx, status)

	var body []byte
	if p.template != nil {
		// encoding/json escapes string values itself, so no manual escaping here — doing both
		// would double-escape.
		encoded, err := json.Marshal(renderMap(p.template, v, escapeNone))
		if err != nil {
			// Unreachable: validate() already marshalled this shape. Leaving the response
			// untouched authors no body, so the gateway's own formatter still gets its turn —
			// degrading to the protocol default beats emitting a broken document.
			slog.ErrorContext(ctx, "[error-response-formatter] encoding failed; leaving the error unchanged", "error", err)
			return nil
		}
		body = encoded
	} else {
		body = []byte(expand(p.stringTemplate, v, p.effectiveEscape()))
	}

	// Header values carry placeholders too, expanded with escaping OFF. A header value is
	// not part of the body's syntax, so XML- or JSON-escaping it would put &quot; on the wire
	// where the operator wrote a quote. What DOES have to be stripped is anything that could
	// end the header — see sanitizeHeaderValue.
	headersToSet := map[string]string{"content-type": p.contentType}
	for _, e := range p.headersToSet {
		headersToSet[e.Name] = sanitizeHeaderValue(expand(e.Value, v, escapeNone))
	}
	var headersToAppend map[string][]string
	if len(p.headersToAppend) > 0 {
		headersToAppend = make(map[string][]string, len(p.headersToAppend))
		for _, e := range p.headersToAppend {
			// Repeated names accumulate rather than overwrite: that is what appending means,
			// and the array shape exists so an operator can express it without nesting.
			headersToAppend[e.Name] = append(headersToAppend[e.Name],
				sanitizeHeaderValue(expand(e.Value, v, escapeNone)))
		}
	}

	slog.DebugContext(ctx, "[error-response-formatter] authored an error body",
		"bytes", len(body), "contentType", p.contentType, "escape", p.effectiveEscape(),
		"code", v.Code, "status", status, "headersSet", len(headersToSet)-1,
		"headersAppended", len(headersToAppend), "headersRemoved", len(p.headersToRemove))

	fr := &policy.FaultResponse{
		Body:            body,
		HeadersToSet:    headersToSet,
		HeadersToAppend: headersToAppend,
		HeadersToRemove: p.headersToRemove,
	}
	if p.statusCode != 0 {
		// A copy, so no response holds a pointer into the shared policy instance.
		code := p.statusCode
		fr.StatusCode = &code
	}
	return fr
}

// sanitizeHeaderValue strips what cannot appear in a header value.
//
// CR and LF are the reason this exists: a Message or Description reaching a header value is
// content the gateway did not author — for a guardrail rejection it is the blocked content
// itself — and a newline in it would end the header and begin whatever followed. That is
// response splitting, and the escaping modes this policy already has do not prevent it,
// because they are about a BODY's syntax rather than the header framing around it.
//
// Replaced with a space rather than dropped, so words either side do not run together and a
// value that was mangled still reads as mangled instead of looking deliberate.
func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return ' '
		}
		return r
	}, v)
}

// effectiveEscape resolves escapeAuto against the content type.
//
// Derived rather than asked for, because the right answer is a property of the syntax being
// produced and an operator should not have to state it twice.
func (p *ErrorFormatterPolicy) effectiveEscape() escapeMode {
	if p.escape != escapeAuto {
		return p.escape
	}
	ct := strings.ToLower(p.contentType)
	switch {
	case strings.Contains(ct, "xml"): // covers application/xml, text/xml, application/soap+xml
		return escapeXML
	case strings.Contains(ct, "json"):
		return escapeJSON
	default:
		return escapeNone
	}
}

// ─── rendering ───────────────────────────────────────────────────────────────

// renderMap walks a structured template, substituting placeholders in string leaves.
//
// A leaf that is EXACTLY one numeric placeholder keeps its natural type. A leaf that renders
// empty is DROPPED — a sparse error is normal (a router failure, or a policy that has not
// adopted the error type), and a caller distinguishing "no code" from `"code":""` is better
// served by absence.
func renderMap(tmpl map[string]interface{}, v view, esc escapeMode) map[string]interface{} {
	out := make(map[string]interface{}, len(tmpl))
	for k, raw := range tmpl {
		if rendered, keep := renderValue(raw, v, esc); keep {
			out[k] = rendered
		}
	}
	return out
}

func renderValue(raw interface{}, v view, esc escapeMode) (interface{}, bool) {
	switch val := raw.(type) {
	case string:
		return renderLeaf(val, v, esc)
	case map[string]interface{}:
		nested := renderMap(val, v, esc)
		// An object whose every leaf dropped is itself dropped, so a sparse error cannot leave
		// {"error":{}} behind.
		return nested, len(nested) > 0
	case []interface{}:
		out := make([]interface{}, 0, len(val))
		for _, item := range val {
			if rendered, keep := renderValue(item, v, esc); keep {
				out = append(out, rendered)
			}
		}
		return out, len(out) > 0
	default:
		// Numbers, booleans and nulls are literals the operator wrote; pass them through.
		return raw, true
	}
}

// renderLeaf substitutes a single string leaf.
func renderLeaf(leaf string, v view, esc escapeMode) (interface{}, bool) {
	fields := v.fields()

	// Exactly one placeholder and nothing else: keep the value's natural type.
	if m := placeholderRe.FindStringSubmatch(leaf); m != nil && m[0] == leaf {
		if typedFields[m[1]] {
			return v.typed(m[1]), true
		}
		s := fields[m[1]]
		return s, s != ""
	}

	rendered := expand(leaf, v, esc)
	// A leaf that CONTAINED placeholders but rendered to nothing is dropped; a literal with no
	// placeholders is kept even if empty, because the operator wrote it deliberately.
	if rendered == "" && placeholderRe.MatchString(leaf) {
		return "", false
	}
	return rendered, true
}

// expand substitutes every ${Field}, escaping each value for the output syntax.
//
// The escaping is the point. Without it a message containing "</fault>" breaks out of its
// element — a broken document and an injection primitive in one.
func expand(tmpl string, v view, esc escapeMode) string {
	fields := v.fields()
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		name := placeholderRe.FindStringSubmatch(match)[1]
		val, ok := fields[name]
		if !ok {
			return match
		}
		return escapeFor(val, esc)
	})
}

// escapeFor makes a substituted value safe inside the given syntax.
func escapeFor(s string, esc escapeMode) string {
	switch esc {
	case escapeXML:
		var buf bytes.Buffer
		// EscapeText handles < > & ' " and the control characters XML forbids.
		if err := xml.EscapeText(&buf, []byte(s)); err != nil {
			return "" // unreachable for a bytes.Buffer; empty beats a broken document
		}
		return buf.String()
	case escapeJSON:
		b, err := json.Marshal(s)
		if err != nil || len(b) < 2 {
			return ""
		}
		return string(b[1 : len(b)-1]) // strip the quotes json.Marshal adds
	default:
		return s
	}
}

// ─── the view ────────────────────────────────────────────────────────────────

// view is what a template may reference.
type view struct {
	Code        string
	Type        string
	Direction   string
	Message     string
	Description string
	Policy      string
	PolicyPhase string
	Status      int
	RequestID   string
	// Source is which actor produced the failure — "gateway", "backend", "router", "noRoute"
	// or "unknown". Worth having in a template because it is the one thing a status cannot
	// say: a backend's 503 and the router's own 503 are the same number and mean opposite
	// things, and an operator's house envelope frequently wants to state which.
	Source string
	// Protocol-derived values, so a template does not have to encode a status mapping.
	OpenAIType  string
	JsonRpcCode int
	Soap11Code  string
	Soap12Code  string
	// JsonRpcID is the JSON-RPC request id, and is nil unless the failing policy supplied one.
	// Typed any because the protocol permits a string, a number, or null.
	JsonRpcID any
}

// fields flattens the view into the placeholder table. Numeric fields appear as strings here
// for text interpolation; renderLeaf keeps the number when a structured leaf is exactly the
// placeholder.
func (v view) fields() map[string]string {
	return map[string]string{
		"Code":        v.Code,
		"Type":        v.Type,
		"Direction":   v.Direction,
		"Message":     v.Message,
		"Description": v.Description,
		"Policy":      v.Policy,
		"PolicyPhase": v.PolicyPhase,
		"Source":      v.Source,
		"Status":      strconv.Itoa(v.Status),
		"RequestID":   v.RequestID,
		"OpenAIType":  v.OpenAIType,
		"JsonRpcCode": strconv.Itoa(v.JsonRpcCode),
		"JsonRpcID":   jsonRPCIDText(v.JsonRpcID),
		"Soap11Code":  v.Soap11Code,
		"Soap12Code":  v.Soap12Code,
	}
}

// jsonRPCIDText renders the id for TEXT interpolation, where everything is a string.
//
// An absent id becomes empty rather than "<nil>", so a leaf that mentions it drops out under
// the same rule as every other empty placeholder. A structured leaf that is exactly
// ${JsonRpcID} takes the typed path instead and keeps null.
func jsonRPCIDText(id any) string {
	if id == nil {
		return ""
	}
	if s, ok := id.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", id)
}

// typed returns a field in its natural JSON type.
func (v view) typed(name string) any {
	switch name {
	case "JsonRpcCode":
		return v.JsonRpcCode
	case "JsonRpcID":
		return v.JsonRpcID
	default:
		return v.Status
	}
}

// knownFields lists placeholder names, for the validation error message.
func knownFields() []string {
	out := make([]string, 0, 16)
	for k := range (view{}).fields() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// viewOf flattens the error context into template data, for the status the response will be
// sent with.
func viewOf(faultCtx *policy.FaultContext, status int) view {
	clientFault := status >= 400 && status < 500

	v := view{
		Status:      status,
		Policy:      faultCtx.Policy,
		PolicyPhase: faultCtx.PolicyPhase,
		Source:      faultCtx.Source,
		OpenAIType:  openAIErrorType(status),
		JsonRpcCode: jsonRPCCode(status),
		// SOAP 1.1 says Client/Server; 1.2 renamed them Sender/Receiver. Both carry the
		// conventional namespace prefix used by the matching preset.
		Soap11Code: pick(clientFault, "soapenv:Client", "soapenv:Server"),
		Soap12Code: pick(clientFault, "env:Sender", "env:Receiver"),
		// Message always has a value: a body whose only human-readable field is empty is worse
		// for a caller than a generic sentence.
		Message: "An unexpected error occurred.",
	}
	if faultCtx.SharedContext != nil {
		v.RequestID = faultCtx.SharedContext.RequestID
	}
	if e := faultCtx.Fault; e != nil {
		v.Code = e.Code
		v.Type = e.Type
		v.Direction = e.Direction
		if e.Message != "" {
			v.Message = e.Message
		}
		// Description is NOT defaulted. For a guardrail rejection it is the content the
		// guardrail blocked, so an absent value must stay absent rather than be filled in with
		// something that reads like detail.
		v.Description = e.Description
		if e.Policy != "" {
			v.Policy = e.Policy
		}
		// JSON-RPC detail overrides the status-derived code and supplies the id. A policy
		// that parsed the request knows both; the status mapping below can only guess the
		// code and cannot know the id at all.
		if e.JSONRPC != nil {
			if e.JSONRPC.Code != nil {
				v.JsonRpcCode = *e.JSONRPC.Code
			}
			v.JsonRpcID = e.JSONRPC.ID
		}
	}
	return v
}

// openAIErrorType maps a status onto OpenAI's error-type vocabulary.
//
// Mirrors mapStatusToOpenAIErrorType in the openai-to-* transformer policies. Duplicated
// rather than shared because those live in another repository.
func openAIErrorType(status int) string {
	switch {
	case status == 400, status == 422:
		return "invalid_request_error"
	case status == 401:
		return "authentication_error"
	case status == 403:
		return "permission_error"
	case status == 404:
		return "not_found_error"
	case status == 413:
		return "request_too_large"
	case status == 429:
		return "rate_limit_error"
	case status >= 500:
		return "server_error"
	default:
		return "api_error"
	}
}

// jsonRPCCode maps a status onto JSON-RPC 2.0's reserved server range.
//
// Gateway errors are server-side failures, so they map onto the reserved codes rather than
// inventing values that could collide with an application's own. Matches what the engine's own
// JSON-RPC renderer does — including in being only a FALLBACK: a policy that stated its own
// code in FaultDetails.JSONRPC overrides this, because -32602 and -32700 are not reachable
// from a status.
func jsonRPCCode(status int) int {
	if status >= 400 && status < 500 {
		return -32600 // invalid request
	}
	return -32603 // internal error
}

// ─── presets ─────────────────────────────────────────────────────────────────

// shape is a preset's rendered form plus the content type it implies.
type shape struct {
	template       map[string]interface{}
	stringTemplate string
	contentType    string
}

func presetNames() []string {
	return []string{presetOpenAI, presetCanonical, presetJSONRPC, presetSOAP11, presetSOAP12}
}

// presetShape returns a built-in shape.
//
// The SOAP presets matter most: SOAP 1.1 and 1.2 faults are declared in the engine's renderer
// set but NOT registered, so the gateway cannot produce one at all. These are the only way to
// get a conformant fault today.
func presetShape(name string) (shape, bool) {
	switch name {
	case presetOpenAI:
		// `type` uses OpenAI's own vocabulary rather than the gateway's class names, because a
		// client matching "authentication_error" will not recognise "authentication". `param`
		// is omitted: OpenAI sends null when it does not apply, and an absent key is
		// equivalent for every client library.
		return shape{template: map[string]interface{}{
			"error": map[string]interface{}{
				"message": "${Message}",
				"type":    "${OpenAIType}",
				"code":    "${Code}",
			},
		}, contentType: contentTypeJSON}, true

	case presetCanonical:
		return shape{template: map[string]interface{}{
			"code":    "${Code}",
			"type":    "${Type}",
			"message": "${Message}",
		}, contentType: contentTypeJSON}, true

	case presetJSONRPC:
		// id echoes the failing policy's request id, and renders as null when there is none —
		// the id lives in the request BODY, and most errors are produced before any body is
		// read. JSON-RPC explicitly permits null for a request whose id could not be
		// determined; guessing one would correlate the error to the wrong call.
		return shape{template: map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "${JsonRpcID}",
			"error": map[string]interface{}{
				"code":    "${JsonRpcCode}",
				"message": "${Message}",
			},
		}, contentType: contentTypeJSON}, true

	case presetSOAP11:
		// SOAP 1.1: fault children are UNqualified (faultcode/faultstring/detail), and the
		// media type is text/xml. Getting either wrong makes a SOAP stack reject the envelope.
		return shape{stringTemplate: `<?xml version="1.0" encoding="UTF-8"?>` +
			`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soapenv:Body><soapenv:Fault>` +
			`<faultcode>${Soap11Code}</faultcode>` +
			`<faultstring>${Message}</faultstring>` +
			`<detail><errorcode>${Code}</errorcode></detail>` +
			`</soapenv:Fault></soapenv:Body></soapenv:Envelope>`,
			contentType: contentTypeTextXML}, true

	case presetSOAP12:
		// SOAP 1.2: children ARE namespace-qualified, Code/Reason replace
		// faultcode/faultstring, Reason carries an xml:lang Text, and the media type is
		// application/soap+xml.
		return shape{stringTemplate: `<?xml version="1.0" encoding="UTF-8"?>` +
			`<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">` +
			`<env:Body><env:Fault>` +
			`<env:Code><env:Value>${Soap12Code}</env:Value></env:Code>` +
			`<env:Reason><env:Text xml:lang="en">${Message}</env:Text></env:Reason>` +
			`<env:Detail><errorcode>${Code}</errorcode></env:Detail>` +
			`</env:Fault></env:Body></env:Envelope>`,
			contentType: contentTypeSOAP12}, true

	default:
		return shape{}, false
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// collectStrings gathers every string leaf in a structured template, for validation.
func collectStrings(v interface{}, out *[]string) {
	switch val := v.(type) {
	case string:
		*out = append(*out, val)
	case map[string]interface{}:
		for _, item := range val {
			collectStrings(item, out)
		}
	case []interface{}:
		for _, item := range val {
			collectStrings(item, out)
		}
	}
}

// stringParam reads a string parameter, falling back to def when absent or the wrong type.
// headerEntries reads the array-of-{name, value} shape every other header-writing policy in
// this catalogue uses (respond, set-headers), rather than a YAML mapping.
//
// A mapping would read better here — HeadersToSet is a map on the wire — but consistency wins:
// the management UI renders these definitions, and one policy spelling headers differently
// from the two beside it is a worse cost than the extra nesting.
//
// The array also expresses appending several values under one name without a nested list,
// which is exactly what headersToAppend needs.
func headerEntries(params map[string]interface{}, key string) ([]headerEntry, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be a list of {name, value} entries", key)
	}
	out := make([]headerEntry, 0, len(list))
	for i, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object with name and value", key, i)
		}
		name, ok := entry["name"].(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("%s[%d].name must be a non-empty string", key, i)
		}
		value, ok := scalarText(entry["value"])
		if !ok {
			return nil, fmt.Errorf("%s[%d].value must be a string, number or boolean", key, i)
		}
		out = append(out, headerEntry{Name: name, Value: value})
	}
	return out, nil
}

// stringListParam reads a []string parameter, accepting a bare scalar as a one-element list —
// removing a single header is the common case and requiring a list for it is friction with no
// upside.
func stringListParam(params map[string]interface{}, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, nil
	}
	if text, isScalar := scalarText(raw); isScalar {
		return []string{text}, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be a string or a list of strings", key)
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		text, isScalar := scalarText(item)
		if !isScalar {
			return nil, fmt.Errorf("%s[%d] must be a string, number or boolean", key, i)
		}
		out = append(out, text)
	}
	return out, nil
}

// scalarText renders a YAML scalar as text. Numbers and booleans are accepted because an
// operator writing `value: 30` means the string "30" and would be surprised to have it
// rejected.
func scalarText(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		// %v rather than FormatFloat: YAML gives every plain number as float64, so 30 must
		// render as "30" and not "30.000000".
		return fmt.Sprintf("%v", t), true
	default:
		return "", false
	}
}

// validateHeaderNames rejects a header name that cannot be sent, and the one overlap that is
// a contradiction rather than a preference.
//
// Setting and removing the same header is not resolved silently: the two mutations reach the
// gateway in one FaultResponse and which wins is the translator's business, not something an
// operator should have to know. Refusing it up front costs nothing and a wrong guess in
// production costs a header a client was waiting for.
func validateHeaderNames(set, appended []headerEntry, removed []string) error {
	written := make([]string, 0, len(set)+len(appended))
	for _, e := range append(append([]headerEntry{}, set...), appended...) {
		written = append(written, e.Name)
	}

	for _, name := range append(append([]string{}, written...), removed...) {
		if name == "" {
			return fmt.Errorf("a header name must not be empty")
		}
		if strings.ContainsAny(name, " \t\r\n:") {
			return fmt.Errorf("header name %q contains a character that cannot appear in one", name)
		}
		// The gateway's own content-type comes from contentType/preset, so accepting it here
		// too would give one header two sources and no stated precedence.
		if strings.EqualFold(name, "content-type") {
			return fmt.Errorf("set the response content type with %s, not as a header", paramContentType)
		}
	}

	lower := make(map[string]bool, len(removed))
	for _, name := range removed {
		lower[strings.ToLower(name)] = true
	}
	for _, name := range written {
		if lower[strings.ToLower(name)] {
			return fmt.Errorf("header %q is both written and removed; drop it from one of %s/%s/%s",
				name, paramHeadersToSet, paramHeadersToAdd, paramHeadersRemove)
		}
	}
	return nil
}

// statusCodeParam reads statusCode. Absent is 0, which keeps the failure's own status.
//
// Validated here rather than left to the engine, because a status outside the range would
// otherwise be found only when a request is already failing.
func statusCodeParam(params map[string]interface{}) (int, error) {
	raw, ok := params[paramStatusCode]
	if !ok || raw == nil {
		return 0, nil
	}
	var code int
	switch v := raw.(type) {
	case int:
		code = v
	case int64:
		code = int(v)
	case float64:
		// YAML and JSON give every number as float64; 401.5 is not a status.
		if v != float64(int(v)) {
			return 0, fmt.Errorf("%s must be a whole number, got %v", paramStatusCode, v)
		}
		code = int(v)
	default:
		return 0, fmt.Errorf("%s must be a number, got %T", paramStatusCode, raw)
	}
	if code < minStatusCode || code > maxStatusCode {
		return 0, fmt.Errorf("%s must be between %d and %d, got %d",
			paramStatusCode, minStatusCode, maxStatusCode, code)
	}
	return code, nil
}

func stringParam(params map[string]interface{}, key, def string) string {
	if raw, ok := params[key]; ok {
		if s, ok := raw.(string); ok && s != "" {
			return s
		}
	}
	return def
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func pick(cond bool, whenTrue, whenFalse string) string {
	if cond {
		return whenTrue
	}
	return whenFalse
}
