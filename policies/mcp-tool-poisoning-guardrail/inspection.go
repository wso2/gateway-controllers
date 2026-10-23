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

package mcptoolpoisoningguardrail

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ──────────────────────────────────────────────────────────────────────────
// Tool metadata extraction: walking a tools/list entry and deciding, for every
// string it contains, whether it is inspectable text and whether it is prose
// worth a model call.
// ──────────────────────────────────────────────────────────────────────────

// Every string reachable inside a tool entry is inspected. An upstream chooses
// the keys of its own tool metadata, so deciding what to inspect from an
// allowlist of known key names would let it evade the guardrail by renaming a
// field or by inventing one: a _meta extension key, a parameter `default`, an
// `enum` value and a parameter name all reach the agent exactly like a
// description does. The tables below narrow only what is worth a *model call*;
// the static detectors run over every collected string regardless.

// nodeKind describes what a node inside a tool entry is. It decides whether the
// node's keys are keywords or names the upstream invented, and — crucially —
// whether the JSON Schema exemptions below apply to them at all. A keyword only
// means what the vocabulary says where the vocabulary is in force.
type nodeKind int

const (
	// kindMetadata is upstream-shaped data: _meta, annotations, any vendor
	// extension subtree, and JSON Schema instance data. Every key here is a
	// name the upstream invented and every string is prose an agent may read,
	// so nothing in it is exempt from anything.
	kindMetadata nodeKind = iota
	// kindToolRoot is the tool entry itself, whose keys are MCP tool keywords.
	kindToolRoot
	// kindSchema is a JSON Schema object, whose keys are schema keywords. This
	// is the only position in which the exemptions below apply.
	kindSchema
	// kindSchemaNames maps names the upstream invented to schemas: the value of
	// properties, $defs and friends.
	kindSchemaNames
	// kindDependentRequiredNames maps a declared parameter name to the list of
	// other parameter names it requires: the value of dependentRequired, whose
	// only legal value shape is that list.
	kindDependentRequiredNames
	// kindDependenciesNames is the same position for the legacy dependencies
	// keyword, which accepts either that list or a schema.
	kindDependenciesNames
	// kindSchemaList is an array whose entries are each supposed to be a schema:
	// the value of allOf and friends. Each entry is shape-checked in its own
	// right, so an entry that is not a schema gets no keyword exemptions.
	kindSchemaList
)

// toolKeywords are the keys MCP itself defines on a tool entry. Any other key
// at the root of a tool is a name the upstream invented.
var toolKeywords = map[string]struct{}{
	"_meta":        {},
	"annotations":  {},
	"description":  {},
	"icons":        {},
	"inputschema":  {},
	"name":         {},
	"outputschema": {},
	"title":        {},
}

// schemaKeywords is the JSON Schema vocabulary. Inside a schema these key names
// are the specification's, not the upstream's, so they are not collected as
// text. A keyword missing from this table is merely collected and scanned,
// which is the safe direction for the table to drift in.
var schemaKeywords = map[string]struct{}{
	"$anchor": {}, "$comment": {}, "$defs": {}, "$dynamicanchor": {},
	"$dynamicref": {}, "$id": {}, "$ref": {}, "$schema": {}, "$vocabulary": {},
	"additionalitems": {}, "additionalproperties": {}, "allof": {}, "anyof": {},
	"const": {}, "contains": {}, "contentencoding": {}, "contentmediatype": {},
	"contentschema": {}, "default": {}, "definitions": {}, "dependencies": {},
	"dependentrequired": {}, "dependentschemas": {}, "deprecated": {},
	"description": {}, "else": {}, "enum": {}, "examples": {},
	"exclusivemaximum": {}, "exclusiveminimum": {}, "format": {}, "if": {},
	"items": {}, "maxcontains": {}, "maximum": {}, "maxitems": {},
	"maxlength": {}, "maxproperties": {}, "mincontains": {}, "minimum": {},
	"minitems": {}, "minlength": {}, "minproperties": {}, "multipleof": {},
	"not": {}, "oneof": {}, "pattern": {}, "patternproperties": {},
	"prefixitems": {}, "properties": {}, "propertynames": {}, "readonly": {},
	"required": {}, "then": {}, "title": {}, "type": {},
	"unevaluateditems": {}, "unevaluatedproperties": {}, "uniqueitems": {},
	"writeonly": {},
}

// identifierKeys are schema keywords whose string value is a machine token
// rather than prose aimed at an agent.
//
// Their values are still collected and scanned by the static detectors, so a
// bidi override or an injection phrase hidden in a `type` is still a finding.
// They are not sent to the classifier: the model is trained on tool
// descriptions and scores bare tokens unreliably.
//
// This exemption applies ONLY in kindSchema. A key named `type` inside _meta,
// inside a vendor extension, or inside instance data is just a key an upstream
// chose, and its value is classified like any other prose.
var identifierKeys = map[string]struct{}{
	"$anchor":          {},
	"$dynamicanchor":   {},
	"$dynamicref":      {},
	"$id":              {},
	"$ref":             {},
	"$schema":          {},
	"$vocabulary":      {},
	"contentencoding":  {},
	"contentmediatype": {},
	"format":           {},
	"pattern":          {},
	"required":         {},
	"type":             {},
}

// nameDeclaringKeys are the schema keywords whose immediate child keys are names
// the upstream invented — parameter names, definition names — and whose values
// are schemas.
var nameDeclaringKeys = map[string]struct{}{
	"$defs":             {},
	"definitions":       {},
	"dependentschemas":  {},
	"patternproperties": {},
	"properties":        {},
}

// isSchemaObject reports whether a value is shaped like a JSON Schema: the
// object form, or the boolean form that is `true`/`false` as a whole schema.
//
// Shape is checked before any keyword exemption is granted, because the
// exemptions are what an upstream would want to reach. Inside a schema a key
// named `type` is an exempt machine token, so prose parked under `type` in a
// position where the vocabulary forbids an object — `dependentRequired`, or a
// `properties` entry holding an array — would keep that prose away from the
// classifier. Such a value is not a schema, whatever key it arrived under, so
// it is treated as the upstream-shaped data it is.
func isSchemaObject(value any) bool {
	switch value.(type) {
	case map[string]any, bool:
		return true
	default:
		return false
	}
}

func isList(value any) bool {
	_, ok := value.([]any)
	return ok
}

// dependentNameContext derives the rules for the value of one declared name
// under dependentRequired or the legacy dependencies.
//
// An array is a list of parameter names: collected and statically scanned, but
// never classified. `dependentRequired: {"api_key": ["account_id"]}` names two
// ordinary parameters on both sides, and this model scores credential-shaped
// identifiers high, so classifying them would filter a schema for the crime of
// declaring a dependency.
//
// allowSchema is true only for the legacy keyword, which genuinely accepts a
// schema in this position. dependentRequired does not, so an object there is
// malformed — and malformed data earns no schema exemptions.
func dependentNameContext(value any, allowSchema bool) walkContext {
	if _, isNames := value.([]any); isNames {
		return walkContext{kind: kindMetadata, classify: false}
	}
	if allowSchema && isSchemaObject(value) {
		return walkContext{kind: kindSchema, classify: true}
	}
	return walkContext{kind: kindMetadata, classify: true}
}

// instanceDataKeys are the schema keywords whose values are example or default
// *instances* rather than schema.
var instanceDataKeys = map[string]struct{}{
	"const":    {},
	"default":  {},
	"enum":     {},
	"examples": {},
}

// schemaValueKeys are the schema keywords whose value is a single schema, and
// schemaListKeys those whose value is an array of schemas. Following them is
// what keeps the schema vocabulary in force at the right depth — and, just as
// importantly, what lets it lapse everywhere else.
//
// The two are kept apart because the shapes are not interchangeable. `not` takes
// one schema, so an array there is malformed; `allOf` takes a list, so an object
// there is malformed. Accepting either shape for both would reopen the exemption
// to anything that wraps prose in the container the keyword does not want.
var schemaValueKeys = map[string]struct{}{
	"additionalitems":       {},
	"additionalproperties":  {},
	"contains":              {},
	"contentschema":         {},
	"else":                  {},
	"if":                    {},
	"not":                   {},
	"propertynames":         {},
	"then":                  {},
	"unevaluateditems":      {},
	"unevaluatedproperties": {},
}

var schemaListKeys = map[string]struct{}{
	"allof":       {},
	"anyof":       {},
	"oneof":       {},
	"prefixitems": {},
}

// itemsKey is the one keyword that legitimately takes either shape: a single
// schema, or the tuple form that drafts through 2019-09 allow. It is handled on
// its own rather than by loosening the two tables above.
const itemsKey = "items"

func has(table map[string]struct{}, key string) bool {
	_, found := table[key]
	return found
}

// Field classes: the semantic position a piece of text came from, recorded for
// calibration and observability. They are descriptive only — no enforcement
// decision reads one, so a misclassified field is a reporting inaccuracy and
// never a security hole. Anything the walk cannot place stays classUnknown and
// is inspected exactly like everything else.
const (
	classDescription          = "description"
	classTitle                = "title"
	classParameterDescription = "parameterDescription"
	className                 = "name"
	classDefault              = "default"
	classConst                = "const"
	classEnum                 = "enum"
	classExamples             = "examples"
	classVendorExtension      = "vendorExtension"
	classMetadata             = "metadata"
	classSchemaKeyword        = "schemaKeyword"
	classUnknown              = "unknown"
)

// keyFieldSuffix marks a field id that refers to an object *key* rather than to
// the value stored under it. It cannot occur in a rendered JSON path, so a key
// field id is never confused with a value field id.
const keyFieldSuffix = "#key"

// plainKeyPattern matches keys that can be rendered with dot notation in a
// field id without becoming ambiguous.
var plainKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_$-]+$`)

// maxIDSegmentBytes caps one upstream-supplied segment of an identifier — a
// tool name or an object key. Identifiers travel into logs and into the
// assessment attached to a block response, so an upstream that returns a
// megabyte-long property name must not be able to amplify through them.
//
// This is a cap on *labels*, not on inspected text: the metadata a tool field
// carries is never shortened, it is dropped and the tool recorded as degraded.
// MCP tool names are bounded at 256 characters, so real names are unaffected.
//
// Because it truncates, a field id is a display value only. Two distinct fields
// can render to the same id, so nothing that decides an outcome — in particular
// the mapping from a classifier result back to the field it scored — may be
// keyed on one.
const maxIDSegmentBytes = 256

// truncationMarker is appended to a shortened identifier segment.
const truncationMarker = "…(truncated)"

// truncateIDSegment shortens an over-long identifier segment, marking that it
// was shortened so a truncated id is never mistaken for a real one. The cut is
// made on a character boundary so the label stays valid text; anything that is
// not valid UTF-8 at that point (a split character, a lone surrogate) is
// dropped from the label.
func truncateIDSegment(value string) string {
	if len(value) <= maxIDSegmentBytes {
		return value
	}
	return strings.ToValidUTF8(value[:maxIDSegmentBytes], "") + truncationMarker
}

// asciiLower lowercases a key only when it is entirely ASCII. Keywords are
// ASCII, and strings.ToLower is Unicode-aware: it folds "İnputSchema" (U+0130)
// into the inputschema keyword and would grant it schema exemptions.
func asciiLower(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] >= utf8.RuneSelf {
			return key
		}
	}
	return strings.ToLower(key)
}

// toolField is one piece of inspectable text together with the id that ties it
// back to its location in the upstream response.
type toolField struct {
	// FieldID is the path of this text inside the tools/list result, for
	// example `tools[0].inputSchema.properties.path.description`, with the
	// keyFieldSuffix appended when the text is an object key rather than a
	// value. It is a human-readable label for logs and findings: it is
	// truncated per segment and is therefore not guaranteed unique.
	FieldID string
	// Text is the string exactly as decoded, lone surrogates included (see
	// decodeJSON). Its length is the UTF-8 size every byte limit counts; the
	// static detectors and the classifier see validText(Text).
	Text string
	// Class is the semantic position this text came from, for analytics only.
	Class string
	// Classify is false for identifier-like fields — the tool name, JSON Schema
	// structural keywords, declared parameter names. They are still scanned by
	// the static detectors but are not worth a model call.
	Classify bool
}

// extractedTool is one entry of result.tools together with everything the
// guardrail needs to decide on it.
type extractedTool struct {
	Index int
	// ID is the tool name when present, otherwise a positional `#<index>`
	// placeholder so findings stay attributable.
	ID     string
	Name   string
	Raw    any
	Fields []toolField

	// Degraded records that some of this tool's textual metadata could not be
	// inspected (resource limits, or an entry that is not a valid tool object).
	// A degraded tool is never treated as safe.
	Degraded bool
	Reasons  []string
}

// extraction is the result of walking one tools/list result.
type extraction struct {
	Tools []extractedTool
	// Degraded is true when any tool was not fully inspected.
	Degraded   bool
	TotalBytes int
}

// extractTools walks result.tools and collects every string a client could put
// in front of an agent — the tool's own description and title, everything
// nested inside inputSchema, outputSchema, annotations and _meta, declared
// parameter names, and schema instance data such as default, const and enum —
// staying inside the configured resource limits.
//
// Text is never truncated: a field that does not fit is dropped and its tool is
// marked degraded, so the caller can refuse to report a partially inspected
// tool as safe.
func extractTools(tools []any, limits SystemParams) extraction {
	result := extraction{Tools: make([]extractedTool, 0, len(tools))}
	budget := limits.MaxTotalBytes

	for index, raw := range tools {
		tool := extractedTool{Index: index, Raw: raw}

		if index >= limits.MaxTools {
			tool.ID = fmt.Sprintf("#%d", index)
			if entry, ok := raw.(map[string]any); ok {
				if name, ok := entry["name"].(string); ok && strings.TrimSpace(name) != "" {
					tool.ID = truncateIDSegment(name)
					tool.Name = name
				}
			}
			tool.degrade(fmt.Sprintf("tool count limit of %d reached", limits.MaxTools))
			result.Tools = append(result.Tools, tool)
			continue
		}

		entry, ok := raw.(map[string]any)
		if !ok {
			tool.ID = fmt.Sprintf("#%d", index)
			tool.degrade("tool entry is not a JSON object")
			result.Tools = append(result.Tools, tool)
			continue
		}

		name, hasName := entry["name"].(string)
		if !hasName || strings.TrimSpace(name) == "" {
			tool.ID = fmt.Sprintf("#%d", index)
			tool.degrade("tool entry has no name")
		} else {
			tool.ID = truncateIDSegment(name)
			tool.Name = name
		}

		walker := &fieldWalker{
			limits:    limits,
			budget:    &budget,
			toolIndex: index,
			tool:      &tool,
		}
		walker.walk(entry, fmt.Sprintf("tools[%d]", index), 0, walkContext{kind: kindToolRoot, classify: true, class: classUnknown})

		result.Tools = append(result.Tools, tool)
	}

	for _, tool := range result.Tools {
		for _, field := range tool.Fields {
			result.TotalBytes += len(field.Text)
		}
		if tool.Degraded {
			result.Degraded = true
		}
	}

	return result
}

// degrade marks the tool as not fully inspected, recording a de-duplicated
// reason. Reasons never contain tool metadata text.
func (t *extractedTool) degrade(reason string) {
	t.Degraded = true
	for _, existing := range t.Reasons {
		if existing == reason {
			return
		}
	}
	t.Reasons = append(t.Reasons, reason)
}

type fieldWalker struct {
	limits    SystemParams
	budget    *int
	toolIndex int
	tool      *extractedTool
}

// walkContext carries the position-dependent rules that decide how a key and a
// string leaf are treated. It is recomputed for every key, so an exemption that
// belongs to a schema keyword cannot leak into data nested underneath it.
type walkContext struct {
	kind nodeKind
	// classify reports whether a string reached from here is prose worth a
	// model call, as opposed to a machine token. Only arrays inherit it, since
	// an array's entries share their key with each other.
	classify bool
	// class is the semantic field class a string leaf here belongs to.
	class string
	// inParameter reports that this schema describes a declared parameter, so
	// its `description` is a parameter description rather than the tool's.
	inParameter bool
}

// collectsKey reports whether an object key is itself inspectable text.
//
// A key is inspected unless it is a keyword recognised in the position it
// appears in. Everything else is a name the upstream invented — a parameter
// name, a vendor _meta key, a key inside a default or an enum — and an agent is
// shown those next to the descriptions.
func collectsKey(kind nodeKind, lowerKey string) bool {
	switch kind {
	case kindToolRoot:
		return !has(toolKeywords, lowerKey)
	case kindSchema:
		return !has(schemaKeywords, lowerKey)
	default:
		// kindSchemaNames and kindMetadata: every key is the upstream's.
		return true
	}
}

// childContext derives the rules for the value stored under one key.
//
// The value is inspected, not just the key. A keyword grants schema treatment —
// and with it the exemptions that keep machine tokens away from the classifier —
// only when what it holds is actually shaped like the thing the specification
// says goes there. An upstream is free to send a shape the vocabulary forbids;
// it must not be able to reach an exemption by doing so.
func childContext(ctx walkContext, lowerKey string, value any) walkContext {
	child := walkContext{kind: kindMetadata, classify: true}

	switch ctx.kind {
	case kindToolRoot:
		switch lowerKey {
		case "inputschema", "outputschema":
			if isSchemaObject(value) {
				child.kind = kindSchema
			}
		case "name":
			// The tool's identifier. Scanned statically — that is where an
			// invisible-character homoglyph would hide — but not classified.
			child.classify = false
			child.class = className
		case "description":
			child.class = classDescription
		case "title":
			child.class = classTitle
		case "_meta", "annotations":
			child.class = classMetadata
		}

	case kindSchemaNames:
		// lowerKey is a declared name, not a keyword, so the keyword tables must
		// not be consulted for it. What it holds should be a schema.
		if isSchemaObject(value) {
			child.kind = kindSchema
			// Its `description` describes a declared parameter.
			child.inParameter = true
		}

	case kindDependentRequiredNames:
		// dependentRequired accepts only a list of parameter names here.
		child = dependentNameContext(value, false)

	case kindDependenciesNames:
		// The legacy keyword accepts that list or a schema.
		child = dependentNameContext(value, true)

	case kindSchema:
		// Only here does a JSON Schema keyword mean what the vocabulary says.
		if has(identifierKeys, lowerKey) {
			child.classify = false
		}
		switch lowerKey {
		case "description":
			child.class = classParameterDescription
			if !ctx.inParameter {
				child.class = classDescription
			}
		case "title":
			child.class = classTitle
		}
		if has(identifierKeys, lowerKey) {
			child.class = classSchemaKeyword
		}

		switch {
		case has(instanceDataKeys, lowerKey):
			// default/const/enum/examples hold instances, not schema: below this
			// point any key name is possible and the vocabulary lapses.
			child.kind = kindMetadata
			switch lowerKey {
			case "default":
				child.class = classDefault
			case "const":
				child.class = classConst
			case "enum":
				child.class = classEnum
			case "examples":
				child.class = classExamples
			}
		case lowerKey == "dependentrequired":
			if _, isNamesMap := value.(map[string]any); isNamesMap {
				child.kind = kindDependentRequiredNames
			}
		case lowerKey == "dependencies":
			if _, isNamesMap := value.(map[string]any); isNamesMap {
				child.kind = kindDependenciesNames
			}
		case has(nameDeclaringKeys, lowerKey):
			if _, isNamesMap := value.(map[string]any); isNamesMap {
				child.kind = kindSchemaNames
			}
		case lowerKey == itemsKey:
			// Either a single schema or the historical tuple form.
			switch {
			case isSchemaObject(value):
				child.kind = kindSchema
			case isList(value):
				child.kind = kindSchemaList
			}
		case has(schemaValueKeys, lowerKey):
			// One schema. An array here is not one.
			if isSchemaObject(value) {
				child.kind = kindSchema
			}
		case has(schemaListKeys, lowerKey):
			// A list of schemas. An object here is not one.
			if isList(value) {
				child.kind = kindSchemaList
			}
		default:
			// An unrecognised key inside a schema is a vendor extension, whose
			// contents are the upstream's data rather than schema.
			child.kind = kindMetadata
			if child.class == "" {
				child.class = classVendorExtension
			}
		}

	case kindMetadata:
		// Inside _meta, annotations or a vendor subtree the class of the parent
		// carries down; there are no keywords here to reclassify by.
		child.class = ctx.class
		// Outside a schema no key name carries keyword meaning, so nothing here
		// is exempt from classification.
	}

	return child
}

// elementContext derives the rules for one entry of an array.
//
// Entries normally inherit their key's rules, because they share that key with
// each other: the strings under `required` stay identifiers, those under `enum`
// stay prose. A list of schemas is the exception — every entry is its own schema
// position, so each has to be shaped like a schema on its own to be treated as
// one. An entry that is not gets no keyword exemptions, which is what stops a
// poisoned object nested one array deeper than the vocabulary allows.
func elementContext(ctx walkContext, item any) walkContext {
	if ctx.kind != kindSchemaList {
		return ctx
	}
	if isSchemaObject(item) {
		return walkContext{kind: kindSchema, classify: true, class: ctx.class}
	}
	return walkContext{kind: kindMetadata, classify: true, class: ctx.class}
}

func (w *fieldWalker) walk(node any, path string, depth int, ctx walkContext) {
	if depth > w.limits.MaxNestingDepth {
		w.tool.degrade(fmt.Sprintf("nesting depth limit of %d exceeded", w.limits.MaxNestingDepth))
		return
	}

	switch typed := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			lowerKey := asciiLower(key)
			childPath := path + renderKey(key)

			if collectsKey(ctx.kind, lowerKey) {
				// The key itself is a name the upstream invented.
				// Keys are scanned statically, not classified: a key is an
				// identifier, and identifiers such as `api_key` or `password`
				// are ordinary in honest catalogues while this model scores
				// bare identifiers unreliably.
				w.addField(childPath+keyFieldSuffix, key, false, className)
			}

			child := childContext(ctx, lowerKey, typed[key])
			if text, ok := typed[key].(string); ok {
				w.addField(childPath, text, child.classify, child.class)
				continue
			}
			w.walk(typed[key], childPath, depth+1, child)
		}
	case []any:
		for i, item := range typed {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			child := elementContext(ctx, item)
			if text, ok := item.(string); ok {
				w.addField(childPath, text, child.classify, child.class)
				continue
			}
			w.walk(item, childPath, depth+1, child)
		}
	}
}

func (w *fieldWalker) addField(fieldID, text string, classify bool, class string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	if len(w.tool.Fields) >= w.limits.MaxFieldsPerTool {
		w.tool.degrade(fmt.Sprintf("field count limit of %d reached", w.limits.MaxFieldsPerTool))
		return
	}
	if len(text) > w.limits.MaxFieldBytes {
		// Deliberately not truncated: a shortened field would be classified as
		// if it were the whole text and reported as fully inspected.
		w.tool.degrade(fmt.Sprintf("field exceeds the %d byte limit", w.limits.MaxFieldBytes))
		return
	}
	if len(text) > *w.budget {
		w.tool.degrade(fmt.Sprintf("total inspection budget of %d bytes exhausted", w.limits.MaxTotalBytes))
		return
	}

	*w.budget -= len(text)
	if class == "" {
		class = classUnknown
	}
	w.tool.Fields = append(w.tool.Fields, toolField{
		FieldID:  fieldID,
		Text:     text,
		Class:    class,
		Classify: classify,
	})
}

// renderKey renders an object key as a field-id segment, quoting keys that
// would otherwise make the path ambiguous. Quoted keys are ASCII-escaped JSON
// strings, so a label never carries a raw control or bidirectional character
// into a log line. The result is a display label: it is truncated, so it is
// not a unique identifier for the field.
func renderKey(key string) string {
	key = truncateIDSegment(key)
	if plainKeyPattern.MatchString(key) {
		return "." + key
	}
	return "[" + asciiQuote(key) + "]"
}

// ──────────────────────────────────────────────────────────────────────────
// Static detectors: the gateway-local, model-free inspection pass. Deterministic
// and cheap, and the only signal left when the classifier is unavailable.
// ──────────────────────────────────────────────────────────────────────────

// staticFinding is one deterministic, model-free detection. It never carries
// the matched text — only where it was found and what matched — so findings can
// be logged and returned without leaking tool metadata.
type staticFinding struct {
	FieldID  string `json:"field"`
	Detector string `json:"detector"`
	Severity string `json:"severity"`
}

// injectionPattern is an explicit prompt-injection signature.
//
// Every pattern requires a directive aimed at the agent. Bare URLs, and bare
// mentions of credentials or secret-bearing files, are NOT signatures on their
// own: legitimate tools document endpoints they call and credentials they need,
// and flagging those would make the guardrail unusable.
type injectionPattern struct {
	id       string
	severity string
	pattern  *regexp.Regexp
}

// compileDetector compiles one case-insensitive injection pattern.
//
// Unicode behaviour is pinned rather than inherited, because an attacker who
// can make the detectors disagree with the published behaviour has a bypass:
//
//   - \b is RE2's ASCII word boundary, so a letter such as "é" glued to
//     "ignore" does not hide the word, and \s is exactly [\t\n\f\r ].
//   - (?i) folds the Kelvin sign (U+212A) to k and the long s (U+017F) to s.
//   - RE2 does NOT fold the dotted capital I (U+0130) or the dotless small i
//     (U+0131) to i; the reference implementation's case folding did. Every
//     literal i in a pattern is therefore widened to [iİı], so "ıgnore all
//     previous instructions" is still an instruction override. The widening
//     changes nothing else: İ and ı are not ASCII word characters, so word
//     boundaries around them are unaffected.
//
// Every pattern is written in lower case with a leading (?is) flag group, no
// character classes containing i, and no escapes other than \b, \s, \. and
// \[ \], which is what lets this rewrite be a plain scan.
func compileDetector(pattern string) *regexp.Regexp {
	flags, body, ok := strings.Cut(pattern, ")")
	if !ok || flags != "(?is" {
		panic("detector pattern must start with (?is): " + pattern)
	}
	var builder strings.Builder
	builder.WriteString("(?is)")
	for i := 0; i < len(body); i++ {
		switch c := body[i]; c {
		case '\\':
			// Copy the escape and its operand untouched.
			builder.WriteByte(c)
			if i+1 < len(body) {
				i++
				builder.WriteByte(body[i])
			}
		case 'i':
			builder.WriteString("[iİı]")
		default:
			builder.WriteByte(c)
		}
	}
	return regexp.MustCompile(builder.String())
}

var injectionPatterns = []injectionPattern{
	{
		// "ignore all previous instructions", "disregard the above rules"
		id:       "injection.instruction_override",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)\b(ignore|disregard|forget|override|bypass)\b.{0,40}?\b(previous|prior|earlier|above|preceding|system|original)\b.{0,25}?\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b`),
	},
	{
		// The `<IMPORTANT>` / `<SYSTEM>` pseudo-tag blocks used by the public
		// MCP tool-poisoning proofs of concept to fence hidden instructions.
		id:       "injection.hidden_instruction_tag",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)<\s*/?\s*(important|system|secret|hidden|internal|confidential|instructions?)\s*>|\[\[\s*(important|system|secret|hidden|internal)\s*\]\]`),
	},
	{
		// "do not tell the user", "without informing the user", "hide this from the user"
		id:       "injection.concealment",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)(\b(do\s*not|don't|never|must\s+not)\b.{0,40}?\b(tell|inform|mention|reveal|disclose|show|display|notify|explain)\b.{0,30}?\b(the\s+)?(user|human|operator|caller|client)\b)` +
				`|(\bwithout\s+(telling|informing|notifying|alerting|asking)\s+(the\s+)?(user|human|operator|caller)\b)` +
				`|(\b(hide|conceal|suppress)\b.{0,30}?\bfrom\s+(the\s+)?(user|human|operator|caller)\b)`),
	},
	{
		// "reveal the system prompt", "send the conversation history"
		id:       "injection.system_prompt_exfiltration",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)\b(reveal|print|output|dump|repeat|send|forward|leak|disclose|return|summarize|echo)\b.{0,40}?\b(system\s+prompt|system\s+message|system\s+instructions|initial\s+instructions|hidden\s+instructions|conversation\s+history|chat\s+history)\b`),
	},
	{
		// An imperative directed at secret-bearing files. The verb is required:
		// a tool that merely documents "reads files under ~/.ssh" with no
		// imperative aimed at the agent does not match.
		id:       "injection.sensitive_file_access",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)\b(read|open|cat|load|fetch|retrieve|access|send|upload|post|transmit|exfiltrate|forward|include|attach|copy|append)\b.{0,60}?` +
				`(~/\.ssh|/\.ssh/|\bid_rsa\b|\bid_ed25519\b|/etc/(passwd|shadow)|~/\.aws/credentials|\.aws/credentials|(^|[\s"'` + "`" + `/])\.env\b|credentials\.json|\.kube/config|\.npmrc|\.git-credentials|\.docker/config\.json)`),
	},
	{
		// "send the api key to https://…" — verb, secret, and destination all
		// required, so documenting that a tool "requires an API key" is fine.
		id:       "injection.secret_transmission",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)\b(send|post|upload|transmit|forward|exfiltrate|report|email|mail|leak|deliver)\b.{0,60}?` +
				`\b(api[_\s-]?keys?|apikeys?|access[_\s-]?tokens?|bearer\s+tokens?|passwords?|passphrases?|secrets?|credentials?|private\s+keys?|session\s+cookies?|auth\s+tokens?)\b.{0,60}?` +
				`\b(to|at|via|through|into|towards?)\b`),
	},
	{
		// Read-sensitive-state-then-ship-it-off command chains, e.g.
		// "run gcore … && curl --upload-file … http://…".
		id:       "injection.data_exfiltration_command",
		severity: SeverityHigh,
		pattern: compileDetector(
			`(?is)\b(gcore|tcpdump|cat|dd|tar|zip|base64|env|printenv|history)\b.{0,90}?\b(curl|wget|nc|netcat|scp|rsync)\b.{0,90}?(--upload-file|--data|-T\s|-d\s|https?://)`),
	},
	{
		// "the agent must first call …", "you are required to run … before"
		// — an instruction about the agent's behaviour rather than about what
		// the tool does. Medium: legitimate tools occasionally phrase
		// prerequisites this way.
		id:       "injection.agent_directive",
		severity: SeverityMedium,
		pattern: compileDetector(
			`(?is)\b(you|the\s+(agent|assistant|model|ai|llm))\b.{0,30}?\b(must|should\s+always|shall|are\s+required\s+to|is\s+required\s+to|need\s+to|have\s+to|has\s+to)\b.{0,60}?` +
				`\b(first|before|prior\s+to|always|instead|silently)\b`),
	},
}

// hiddenCharClass describes one class of invisible or control characters.
type hiddenCharClass struct {
	id       string
	severity string
	contains func(r rune) bool
}

// hiddenCharClasses are ordered so the most specific class wins for a rune.
//
// Zero-width joiner (U+200D) and zero-width non-joiner (U+200C) are excluded:
// they are load-bearing in emoji sequences and in Persian/Arabic/Indic text.
// Left-to-right and right-to-left marks (U+200E/U+200F) are excluded for the
// same reason — only the embedding/override/isolate controls that enable
// Trojan-Source style reordering are treated as findings.
var hiddenCharClasses = []hiddenCharClass{
	{
		id:       "hidden.bidi_control",
		severity: SeverityHigh,
		contains: func(r rune) bool {
			return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
		},
	},
	{
		id:       "hidden.tag_characters",
		severity: SeverityHigh,
		contains: func(r rune) bool {
			return r >= 0xE0000 && r <= 0xE007F
		},
	},
	{
		id:       "hidden.zero_width",
		severity: SeverityMedium,
		contains: func(r rune) bool {
			return r == 0x200B || (r >= 0x2060 && r <= 0x2064) || r == 0xFEFF
		},
	},
	{
		id:       "hidden.private_use",
		severity: SeverityMedium,
		contains: func(r rune) bool {
			return (r >= 0xE000 && r <= 0xF8FF) ||
				(r >= 0xF0000 && r <= 0xFFFFD) ||
				(r >= 0x100000 && r <= 0x10FFFD)
		},
	},
	{
		id:       "hidden.control_character",
		severity: SeverityMedium,
		contains: func(r rune) bool {
			if r == '\t' || r == '\n' || r == '\r' {
				return false
			}
			return r < 0x20 || (r >= 0x7F && r <= 0x9F)
		},
	},
	{
		id:       "hidden.format_character",
		severity: SeverityMedium,
		contains: func(r rune) bool {
			if _, allowed := allowedFormatRunes[r]; allowed {
				return false
			}
			// Remaining Cf runes: soft hyphen, Mongolian vowel separator,
			// interlinear annotation marks, and similar.
			return isFormatCharacter(r)
		},
	},
}

// formatCharacterRanges is Unicode general category Cf. It is pinned here
// rather than read from unicode.Cf so that a Go toolchain upgrade to a newer
// Unicode version cannot silently change what the detector reports; the table
// is identical to unicode.Cf in Go's Unicode 15.0 tables and to the reference
// implementation's pinned table.
var formatCharacterRanges = [][2]rune{
	{0x00AD, 0x00AD}, {0x0600, 0x0605}, {0x061C, 0x061C}, {0x06DD, 0x06DD}, {0x070F, 0x070F},
	{0x0890, 0x0891}, {0x08E2, 0x08E2}, {0x180E, 0x180E}, {0x200B, 0x200F}, {0x202A, 0x202E},
	{0x2060, 0x2064}, {0x2066, 0x206F}, {0xFEFF, 0xFEFF}, {0xFFF9, 0xFFFB}, {0x110BD, 0x110BD},
	{0x110CD, 0x110CD}, {0x13430, 0x1343F}, {0x1BCA0, 0x1BCA3}, {0x1D173, 0x1D17A},
	{0xE0001, 0xE0001}, {0xE0020, 0xE007F},
}

func isFormatCharacter(r rune) bool {
	for _, bounds := range formatCharacterRanges {
		if r >= bounds[0] && r <= bounds[1] {
			return true
		}
	}
	return false
}

// allowedFormatRunes are Cf runes with load-bearing uses in ordinary text:
// the zero-width non-joiner and joiner (Persian, Arabic, Indic scripts and
// emoji sequences) and the left-to-right and right-to-left marks (bidirectional
// text that is not being reordered).
var allowedFormatRunes = map[rune]struct{}{
	0x200C: {},
	0x200D: {},
	0x200E: {},
	0x200F: {},
}

// ansiEscapePattern matches CSI/OSC terminal escape sequences, which render as
// nothing (or as cursor moves) in a terminal-hosted agent.
var ansiEscapePattern = regexp.MustCompile("\x1b[\\[\\]()#;?]*[0-9;]*[A-Za-z]")

// scanField runs every enabled static detector over one field and returns the
// findings, de-duplicated by detector and sorted for deterministic output.
func scanField(field toolField, config StaticDetectorConfig) []staticFinding {
	if !config.Enabled {
		return nil
	}

	detected := make(map[string]string)
	// A lone surrogate is scanned as the single U+FFFD it is sent as, not as
	// three invalid bytes, so pattern windows count it as one character.
	text := validText(field.Text)

	if config.HiddenCharacters {
		if ansiEscapePattern.MatchString(text) {
			detected["hidden.ansi_escape"] = SeverityHigh
		}
		for _, r := range text {
			for _, class := range hiddenCharClasses {
				if class.contains(r) {
					detected[class.id] = class.severity
					break
				}
			}
		}
	}

	if config.InjectionPatterns {
		for _, pattern := range injectionPatterns {
			if pattern.pattern.MatchString(text) {
				detected[pattern.id] = pattern.severity
			}
		}
	}

	if len(detected) == 0 {
		return nil
	}

	findings := make([]staticFinding, 0, len(detected))
	for detector, severity := range detected {
		findings = append(findings, staticFinding{
			FieldID:  field.FieldID,
			Detector: detector,
			Severity: severity,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Detector < findings[j].Detector
	})
	return findings
}

// ──────────────────────────────────────────────────────────────────────────
// Inspection decisions: running both passes over one tools/list result and
// aggregating them into a per-tool verdict.
// ──────────────────────────────────────────────────────────────────────────

// Finding sources, reported in causes, observations and analytics.
const (
	causeClassifier = "classifier"
	causeStatic     = "staticDetector"
	causeDegraded   = "inspectionIncomplete"
)

// toolDecision is the guardrail's verdict for one tool entry.
//
// Detection and enforcement are deliberately separate fields. A model score
// reaching the threshold is a *detection*; whether that detection can remove or
// block a tool depends on classifierAction. Collapsing the two into one boolean
// is what would let an advisory model finding silently enforce.
type toolDecision struct {
	Index int    `json:"index"`
	Tool  string `json:"tool"`

	// Classified reports whether a model score was obtained for this tool.
	// It is false when the classifier failed and static fallback was used, and
	// when the tool carried no classifiable text.
	Classified bool `json:"classified"`
	// Score is the highest Tool Poisoning probability across the tool's fields.
	// Only meaningful when Classified is true.
	Score float64 `json:"score,omitempty"`
	// ScoreField is the field id that produced Score, and ScoreFieldClass the
	// semantic class of that field. Neither carries the inspected text.
	ScoreField      string `json:"scoreField,omitempty"`
	ScoreFieldClass string `json:"scoreFieldClass,omitempty"`

	// ModelDetected reports that Score reached classifierThreshold. It says
	// nothing about enforcement.
	ModelDetected bool `json:"modelDetected"`
	// ModelEnforced reports that the detection counts towards the policy
	// action, which requires classifierAction=enforce.
	ModelEnforced bool `json:"modelEnforced"`

	Findings []staticFinding `json:"findings,omitempty"`
	// StaticViolation reports that a static finding reached the configured
	// severity. Static findings always enforce.
	StaticViolation bool `json:"staticViolation"`

	// Degraded reports that this tool's metadata was not fully inspected.
	// A degraded tool is never reported as safe, and always enforces.
	Degraded bool     `json:"degraded"`
	Reasons  []string `json:"reasons,omitempty"`

	// Violation is the enforceable verdict: what Action acts on.
	Violation bool `json:"violation"`
	// Causes lists why this tool is enforceable; Observed lists findings that
	// were recorded but deliberately did not enforce.
	Causes   []string `json:"causes,omitempty"`
	Observed []string `json:"observed,omitempty"`
}

// reportable reports whether this decision has anything worth recording, which
// includes advisory model detections that did not enforce.
func (d toolDecision) reportable() bool {
	return d.Violation || d.ModelDetected || len(d.Findings) > 0
}

// inspectionOutcome is the guardrail's verdict for one tools/list result.
type inspectionOutcome struct {
	Decisions []toolDecision
	Model     string
	Revision  string
	LatencyMs int64

	// ClassifierDegraded is true when the classifier failed and the verdict
	// rests on static detectors alone.
	ClassifierDegraded bool
	// ExtractionDegraded is true when resource limits stopped the guardrail
	// from inspecting all tool metadata.
	ExtractionDegraded bool

	// ViolationCount counts enforceable violations — what Action acts on.
	ViolationCount int
	// ModelDetections counts tools the model flagged, enforced or not, and
	// AdvisoryDetections the subset that deliberately did not enforce.
	ModelDetections    int
	AdvisoryDetections int
	InspectedTools     int
}

// Degraded reports whether any part of this inspection was incomplete.
func (o inspectionOutcome) Degraded() bool {
	return o.ClassifierDegraded || o.ExtractionDegraded
}

// violatingIndexes returns the set of result.tools indexes that violate the policy.
func (o inspectionOutcome) violatingIndexes() map[int]struct{} {
	indexes := make(map[int]struct{}, o.ViolationCount)
	for _, decision := range o.Decisions {
		if decision.Violation {
			indexes[decision.Index] = struct{}{}
		}
	}
	return indexes
}

// violations returns only the enforceable decisions.
func (o inspectionOutcome) violations() []toolDecision {
	violating := make([]toolDecision, 0, o.ViolationCount)
	for _, decision := range o.Decisions {
		if decision.Violation {
			violating = append(violating, decision)
		}
	}
	return violating
}

// reported returns every decision worth recording, which includes advisory
// model detections that did not enforce. Those must stay visible in logs and in
// the assessment, or flag mode would hide what the model found.
func (o inspectionOutcome) reported() []toolDecision {
	out := make([]toolDecision, 0, len(o.Decisions))
	for _, decision := range o.Decisions {
		if decision.reportable() {
			out = append(out, decision)
		}
	}
	return out
}

// toJSON renders a finding for an assessment: where it was found and what
// matched, never the matched text.
func (f staticFinding) toJSON() orderedObject {
	return orderedObject{{"field", f.FieldID}, {"detector", f.Detector}, {"severity", f.Severity}}
}

// toJSON renders a decision for an assessment. Ids, classes, scores and
// detector ids only — never the inspected text.
func (d toolDecision) toJSON() orderedObject {
	data := orderedObject{{"index", d.Index}, {"tool", d.Tool}, {"classified", d.Classified}}
	if d.Score != 0 {
		data = append(data, jsonMember{"score", d.Score})
	}
	if d.ScoreField != "" {
		data = append(data, jsonMember{"scoreField", d.ScoreField})
	}
	if d.ScoreFieldClass != "" {
		data = append(data, jsonMember{"scoreFieldClass", d.ScoreFieldClass})
	}
	data = append(data, jsonMember{"modelDetected", d.ModelDetected}, jsonMember{"modelEnforced", d.ModelEnforced})
	if len(d.Findings) > 0 {
		findings := make([]any, 0, len(d.Findings))
		for _, finding := range d.Findings {
			findings = append(findings, finding.toJSON())
		}
		data = append(data, jsonMember{"findings", findings})
	}
	data = append(data, jsonMember{"staticViolation", d.StaticViolation}, jsonMember{"degraded", d.Degraded})
	if len(d.Reasons) > 0 {
		data = append(data, jsonMember{"reasons", d.Reasons})
	}
	data = append(data, jsonMember{"violation", d.Violation})
	if len(d.Causes) > 0 {
		data = append(data, jsonMember{"causes", d.Causes})
	}
	if len(d.Observed) > 0 {
		data = append(data, jsonMember{"observed", d.Observed})
	}
	return data
}

// planInspection runs the static pass and builds the de-duplicated classifier
// items.
//
// Wire ids are compact and generated here ("f0", "f1", ...) rather than being
// the field path. A field path is built from upstream-supplied object keys, so
// using it on the wire would let an upstream shape — and inflate — the ids the
// classifier has to accept. Findings still carry the readable field path.
//
// The map back from a score is keyed on the exact inspected text, never on the
// field id: field ids truncate each upstream-supplied segment, so two fields
// whose paths differ only past the truncation point render to the same id.
// Keying on the id would let one such field overwrite the other's wire id and
// hand both the wrong score — including handing a poisoned field a benign one.
// Keying on the text is exact, and it also means repeated text (the `"string"`
// under every parameter's `type`, a description shared by two tools) costs a
// single classifier item.
func planInspection(extracted extraction, static StaticDetectorConfig) ([][]staticFinding, []classifyItem, map[string]string) {
	findingsByTool := make([][]staticFinding, len(extracted.Tools))
	items := make([]classifyItem, 0, len(extracted.Tools))
	wireIDs := make(map[string]string, len(extracted.Tools))
	for i, tool := range extracted.Tools {
		for _, field := range tool.Fields {
			findingsByTool[i] = append(findingsByTool[i], scanField(field, static)...)
			if !field.Classify {
				continue
			}
			if _, queued := wireIDs[field.Text]; queued {
				continue
			}
			wireID := "f" + strconv.Itoa(len(items))
			wireIDs[field.Text] = wireID
			// A lone surrogate cannot be sent as UTF-8; it is sent as U+FFFD.
			items = append(items, classifyItem{ID: wireID, Text: validText(field.Text)})
		}
	}
	return findingsByTool, items, wireIDs
}

// decide turns extraction, static findings and scores into per-tool verdicts.
// scores is nil when classification failed and the static detectors are
// standing in for the model.
func decide(extracted extraction, findingsByTool [][]staticFinding, wireIDs map[string]string, scores map[string]float64, params PolicyParams, outcome inspectionOutcome) inspectionOutcome {
	for i, tool := range extracted.Tools {
		decision := toolDecision{
			Index:    tool.Index,
			Tool:     tool.ID,
			Findings: findingsByTool[i],
			Degraded: tool.Degraded,
			Reasons:  append([]string(nil), tool.Reasons...),
		}

		if scores != nil {
			for _, field := range tool.Fields {
				if !field.Classify {
					continue
				}
				score, ok := scores[wireIDs[field.Text]]
				if !ok {
					continue
				}
				// Field scores aggregate by maximum: one poisoned parameter
				// description is enough to poison the tool. Strictly greater,
				// so the first field wins a tie.
				if !decision.Classified || score > decision.Score {
					decision.Score = score
					decision.ScoreField = field.FieldID
					decision.ScoreFieldClass = field.Class
				}
				decision.Classified = true
			}
		}

		// Detection: did the model flag this tool? reachesThreshold refuses a
		// non-finite score or threshold, so NaN can never pass or fail silently.
		decision.ModelDetected = decision.Classified && reachesThreshold(decision.Score, params.ClassifierThreshold)
		// Enforcement: may that detection act? Only on an explicit opt-in.
		// Measured against the bundled model, honest tool metadata scored above
		// poisoned metadata, so a model score alone removing a tool would
		// filter honest catalogues.
		decision.ModelEnforced = decision.ModelDetected && params.ClassifierAction == ClassifierEnforce

		// Static findings are evaluated independently of the score, and always
		// enforce: a benign-looking score never cancels a static finding.
		for _, finding := range decision.Findings {
			if meetsSeverity(finding.Severity, params.Static.MinSeverity) {
				decision.StaticViolation = true
				break
			}
		}

		if decision.ModelEnforced {
			decision.Causes = append(decision.Causes, causeClassifier)
		} else if decision.ModelDetected {
			// Recorded, deliberately not acted on.
			decision.Observed = append(decision.Observed, causeClassifier)
		}
		if decision.StaticViolation {
			decision.Causes = append(decision.Causes, causeStatic)
		}
		if decision.Degraded {
			decision.Causes = append(decision.Causes, causeDegraded)
		}

		decision.Violation = decision.ModelEnforced || decision.StaticViolation || decision.Degraded

		if decision.Violation {
			outcome.ViolationCount++
		}
		if decision.ModelDetected {
			outcome.ModelDetections++
			if !decision.ModelEnforced {
				outcome.AdvisoryDetections++
			}
		}
		outcome.Decisions = append(outcome.Decisions, decision)
	}
	return outcome
}

// reachesThreshold is the one comparison that turns a model score into a
// detection.
//
// Both operands were already validated where they entered the policy —
// parsePolicyParams refuses a non-finite threshold and parseClassifierResponse
// a non-finite or out-of-range score — and that duplication is intentional.
// Every ordered comparison against NaN is false, so a NaN that slipped past
// either check would make `score >= threshold` silently false for every tool:
// classifier enforcement disabled with no error anywhere. Checking again at the
// comparison keeps that failure impossible even if a future change to the
// parsing path reintroduces a NaN; a non-finite operand counts as a detection
// rather than as a pass.
func reachesThreshold(score, threshold float64) bool {
	if math.IsNaN(score) || math.IsInf(score, 0) || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return true
	}
	return score >= threshold
}

// inspect extracts the inspectable metadata of every tool, runs the static
// detectors, classifies the text, and decides which tools violate the policy.
// ctx carries the classification deadline.
//
// A non-nil error means the verdict could not be established and the response
// must not be delivered: either classification failed under
// onClassifierError=block, or static fallback was requested but the static pass
// could not stand in for it.
func (p *McpToolPoisoningGuardrailPolicy) inspect(ctx context.Context, tools []any) (inspectionOutcome, error) {
	extracted := extractTools(tools, p.system)
	outcome := inspectionOutcome{
		Decisions:          make([]toolDecision, 0, len(extracted.Tools)),
		ExtractionDegraded: extracted.Degraded,
		InspectedTools:     len(extracted.Tools),
	}

	// Static pass first: its findings must survive a classifier failure, and
	// they are what onClassifierError=useStaticDetectors falls back to.
	findingsByTool, items, wireIDs := planInspection(extracted, p.params.Static)

	scores := map[string]float64{}
	if len(items) > 0 {
		result, err := p.classifier.classify(ctx, items)
		outcome.LatencyMs = result.Latency.Milliseconds()
		if err != nil {
			slog.Warn("MCP Tool Poisoning Guardrail Policy: Classification failed",
				"error", err.Error(),
				"items", len(items),
				"onClassifierError", p.params.OnClassifierError)

			if p.params.OnClassifierError != OnErrorUseStaticDetectors {
				return inspectionOutcome{}, fmt.Errorf("tool metadata classification failed: %w", err)
			}
			// Static fallback only stands in for the model when the static pass
			// actually ran and could have found something. With static
			// detection off, or on with every scanner disabled, there is
			// nothing left to base a verdict on. GetPolicy rejects that
			// combination, so this is the defence in depth for a policy built
			// some other way.
			if !p.params.Static.canDetect() {
				return inspectionOutcome{}, fmt.Errorf("tool metadata classification failed and no static detector is enabled: %w", err)
			}
			scores = nil
			outcome.ClassifierDegraded = true
		} else {
			scores = result.Scores
			outcome.Model = result.Model
			outcome.Revision = result.Revision
		}
	}

	return decide(extracted, findingsByTool, wireIDs, scores, p.params, outcome), nil
}

// logSafe renders an upstream-derived value for a log line as ASCII-escaped
// JSON, so tool names, field ids and model identity reported by the classifier
// cannot inject line breaks, control or bidirectional characters into logs
// whatever handler the gateway configures. A string is rendered without its
// surrounding quotes; the handler quotes it if it needs to. The result is
// capped at maxLogValueBytes: a client chooses its JSON-RPC id and an upstream
// its field paths, and neither may make a log line arbitrarily long.
func logSafe(value any) string {
	rendered := renderLogValue(value)
	if len(rendered) > maxLogValueBytes {
		// The rendering is ASCII, so any cut is on a character boundary.
		return rendered[:maxLogValueBytes] + "...(truncated)"
	}
	return rendered
}

// maxLogValueBytes bounds one upstream- or client-derived value in a log line.
const maxLogValueBytes = 2048

func renderLogValue(value any) string {
	var builder strings.Builder
	switch typed := value.(type) {
	case string:
		quoted := asciiQuote(typed)
		return quoted[1 : len(quoted)-1]
	case []string:
		builder.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				builder.WriteByte(',')
			}
			appendJSONString(&builder, item, true)
		}
		builder.WriteByte(']')
	case []staticFinding:
		builder.WriteByte('[')
		for index, finding := range typed {
			if index > 0 {
				builder.WriteByte(',')
			}
			encoded, _ := encodeJSON(finding.toJSON())
			appendASCII(&builder, encoded)
		}
		builder.WriteByte(']')
	default:
		encoded, _ := encodeJSON(value)
		appendASCII(&builder, encoded)
	}
	return builder.String()
}

// appendASCII writes already-encoded JSON with every non-ASCII character
// escaped. JSON escapes are valid anywhere a character is, so the result is the
// same JSON value.
func appendASCII(builder *strings.Builder, encoded string) {
	for _, r := range encoded {
		switch {
		case r < 0x7F:
			builder.WriteRune(r)
		case r >= 0x10000:
			r -= 0x10000
			writeUnicodeEscape(builder, 0xD800+(r>>10))
			writeUnicodeEscape(builder, 0xDC00+(r&0x3FF))
		default:
			writeUnicodeEscape(builder, r)
		}
	}
}

// logOutcome records the verdict. Tool ids, field ids, detector ids and scores
// are recorded; the tool metadata text itself never is.
func (p *McpToolPoisoningGuardrailPolicy) logOutcome(outcome inspectionOutcome, applied string) {
	slog.Info("MCP Tool Poisoning Guardrail Policy: tools/list inspected",
		"action", p.params.Action,
		"classifierAction", p.params.ClassifierAction,
		"applied", applied,
		"inspectedTools", outcome.InspectedTools,
		"violations", outcome.ViolationCount,
		"modelDetections", outcome.ModelDetections,
		"advisoryDetections", outcome.AdvisoryDetections,
		"model", logSafe(outcome.Model),
		"modelRevision", logSafe(outcome.Revision),
		"classifierLatencyMs", outcome.LatencyMs,
		"degraded", outcome.Degraded())

	// Advisory model detections are logged at the same detail as enforceable
	// ones. Under the default classifierAction they are the only record that
	// the model flagged anything, and they are what an operator calibrates from.
	for _, decision := range outcome.reported() {
		message := "MCP Tool Poisoning Guardrail Policy: tool violates policy"
		if !decision.Violation {
			message = "MCP Tool Poisoning Guardrail Policy: model finding recorded, not enforced"
		}
		slog.Warn(message,
			"tool", logSafe(decision.Tool),
			"index", decision.Index,
			"classified", decision.Classified,
			"score", decision.Score,
			"scoreField", logSafe(decision.ScoreField),
			"scoreFieldClass", decision.ScoreFieldClass,
			"threshold", p.params.ClassifierThreshold,
			"classifierAction", p.params.ClassifierAction,
			"modelDetected", decision.ModelDetected,
			"modelEnforced", decision.ModelEnforced,
			"staticViolation", decision.StaticViolation,
			"enforceable", decision.Violation,
			"causes", logSafe(decision.Causes),
			"observed", logSafe(decision.Observed),
			"findings", logSafe(decision.Findings),
			"degraded", decision.Degraded,
			"reasons", logSafe(decision.Reasons))
	}
}

// assessment renders the structured findings attached to a block response when
// showAssessment is enabled: ids, classes, severities and scores only.
func (p *McpToolPoisoningGuardrailPolicy) assessment(outcome inspectionOutcome, reason string) orderedObject {
	data := orderedObject{
		{"interveningGuardrail", policyDisplayName},
		{"actionReason", reason},
		{"action", p.params.Action},
		{"classifierAction", p.params.ClassifierAction},
		{"classifierThreshold", p.params.ClassifierThreshold},
		{"degradedInspection", outcome.Degraded()},
	}
	if outcome.Model != "" {
		data = append(data, jsonMember{"model", outcome.Model}, jsonMember{"modelRevision", outcome.Revision})
	}
	if violations := outcome.violations(); len(violations) > 0 {
		rendered := make([]any, 0, len(violations))
		for _, decision := range violations {
			rendered = append(rendered, decision.toJSON())
		}
		data = append(data, jsonMember{"violations", rendered})
	}
	// Model findings that did not enforce are reported separately, so the
	// assessment never implies an advisory score removed anything.
	var observed []any
	for _, decision := range outcome.Decisions {
		if decision.ModelDetected && !decision.ModelEnforced {
			observed = append(observed, decision.toJSON())
		}
	}
	if len(observed) > 0 {
		data = append(data, jsonMember{"observedModelFindings", observed})
	}
	return data
}
