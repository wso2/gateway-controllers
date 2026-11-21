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

package awsbedrockguardrail

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// textSegment is one text value taken from a payload for the guardrail to check.
// set writes a new value back into the parsed payload, for masking.
type textSegment struct {
	value string
	set   func(string)
	// loc is where the value sits in the decoded document; the zero value for
	// a segment that is not a member or element (the whole payload).
	loc slotLocation
}

// slotLocation identifies a member or array element of a decoded document: the
// map or array holding it, and its key or index.
type slotLocation struct {
	container uintptr
	key       string
	index     int
}

// extractedPayload holds the text segments found in a payload and rebuilds the
// payload after any segment has been changed.
type extractedPayload struct {
	segments []*textSegment
	rebuild  func() ([]byte, error)
	// stripLogprobs removes the log probabilities of every document whose text
	// was changed, before rebuild encodes it: a JSON body, or each changed event
	// of an event stream. nil for a body that is not JSON.
	stripLogprobs func()
	// missed is the extraction error for content some events carry that the path
	// does not reach, while other events' segments were found. The caller faults
	// on it, or, with passthroughOnError, lets only that content pass and still
	// assesses the segments.
	missed error
}

// extractPayload finds the text the guardrail must check.
//
//   - An empty jsonPath checks the whole body as one piece of text.
//   - A JSON body is resolved with jsonPath. When the path points at an object
//     or an array, every string inside it is checked (e.g. "$.params.arguments"
//     covers every MCP tool argument).
//   - A Server-Sent Events body (e.g. an MCP Streamable HTTP response) is split
//     into events, and jsonPath is resolved against the JSON in each event's data.
//   - A single JSON-RPC message the path does not apply to yields no segments
//     only when it carries no content to check: an MCP initialize, ping, list
//     or notification, or the result of one (see carriesNoContent). Any other
//     message the path misses, such as a tools/call whose arguments have a
//     different shape, is an extraction error, as it was before JSON-RPC
//     support: passing it would deliver its content unassessed.
func extractPayload(payload []byte, jsonPath string) (*extractedPayload, error) {
	return extractPayloadAs(payload, jsonPath, looksLikeEventStream(payload))
}

// extractPayloadAs is extractPayload for a body whose format the caller has
// already established: eventStream says the body is a Server-Sent Events stream
// (from its Content-Type, say), so it is read as one even when its first line
// is not an SSE field, as the caller's own readability checks read it.
func extractPayloadAs(payload []byte, jsonPath string, eventStream bool) (*extractedPayload, error) {
	if jsonPath == "" {
		segment := &textSegment{value: string(payload)}
		segment.set = func(v string) { segment.value = v }
		return &extractedPayload{
			segments: []*textSegment{segment},
			rebuild:  func() ([]byte, error) { return []byte(segment.value), nil },
		}, nil
	}

	tokens, err := parseJSONPath(jsonPath)
	if err != nil {
		return nil, err
	}

	doc, jsonErr := decodeJSON(payload)
	if jsonErr == nil {
		root := &doc
		segments, err := resolveTextSegments(root, tokens, nil)
		if isJSONRPCMessage(doc) && (err == nil || errors.Is(err, errNoValue)) {
			if extra := structuredContentSegments(root, tokens, segments, nil); len(extra) > 0 {
				if err != nil {
					segments, err = nil, nil // the result's text is all in structuredContent
				}
				segments = append(segments, extra...)
			}
		}
		if errors.Is(err, errNoValue) && isJSONRPCMessage(doc) {
			if carriesNoContent(doc) {
				return unchangedPayload(payload), nil
			}
			if isJSONRPCError(doc) {
				segments, err = resolveErrorText(root, nil)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%w (jsonPath %q)", err, jsonPath)
		}
		return &extractedPayload{
			segments:      segments,
			rebuild:       func() ([]byte, error) { return encodeJSON(*root) },
			stripLogprobs: func() { dropLogprobs(*root) },
		}, nil
	}

	if eventStream {
		return extractEventStream(payload, jsonPath, tokens)
	}

	return nil, fmt.Errorf("payload is neither JSON nor a Server-Sent Events stream: %w", jsonErr)
}

// structuredContentSegments returns the text of an MCP tool result's
// structuredContent that the primary selection does not already hold, when
// jsonPath reads the result: it is the same result in another form, and would
// otherwise reach the client unassessed. It is assessed even when jsonPath
// matches nothing, as for a tool result whose content list is empty. A path
// whose first member is a wildcard reads the result too. Values the primary
// selection already holds are left out by location, not by text, so equal text
// in two fields is still assessed in both, and none is assessed twice. A path
// into structuredContent itself is the operator's own choice of what to read.
func structuredContentSegments(root *interface{}, tokens []pathToken, primary []*textSegment, onChange func()) []*textSegment {
	if len(tokens) == 0 {
		return nil
	}
	switch {
	case tokens[0].kind == tokenKey && tokens[0].key == "result":
	case tokens[0].kind == tokenWildcard:
	default:
		return nil
	}
	if len(tokens) > 1 && tokens[1].kind == tokenKey && tokens[1].key == structuredContentMember {
		return nil
	}
	message, _ := (*root).(map[string]interface{})
	result, _ := message["result"].(map[string]interface{})
	if _, has := result[structuredContentMember]; !has {
		return nil
	}
	extra, err := resolveTextSegments(root, structuredContentPath, onChange)
	if err != nil {
		return nil // no text in it
	}
	covered := make(map[slotLocation]bool, len(primary))
	for _, segment := range primary {
		if segment.loc != (slotLocation{}) {
			covered[segment.loc] = true
		}
	}
	var missing []*textSegment
	for _, segment := range extra {
		if !covered[segment.loc] {
			missing = append(missing, segment)
		}
	}
	return missing
}

const structuredContentMember = "structuredContent"

var structuredContentPath = mustParseJSONPath("$.result.structuredContent")

// errNoValue is returned when jsonPath matches nothing in a document.
var errNoValue = errors.New("no value found at jsonPath")

// isJSONRPCMessage reports whether doc is one JSON-RPC 2.0 message. A batch
// (a JSON array) is not one, so a batch the path does not match is still an
// error rather than passing unchecked.
func isJSONRPCMessage(doc interface{}) bool {
	m, ok := doc.(map[string]interface{})
	if !ok {
		return false
	}
	version, ok := m["jsonrpc"].(string)
	return ok && version == "2.0"
}

// contentFreeMethods are the JSON-RPC (MCP) methods whose requests carry no
// content for a guardrail: session setup, keep-alives and listings.
var contentFreeMethods = map[string]bool{
	"initialize":               true,
	"ping":                     true,
	"tools/list":               true,
	"prompts/list":             true,
	"resources/list":           true,
	"resources/templates/list": true,
	"roots/list":               true,
	"logging/setLevel":         true,
	"resources/subscribe":      true,
	"resources/unsubscribe":    true,
}

// contentFreeResultMembers are the members of a JSON-RPC result that mark it as
// the answer to a content-free method: an initialize result or a listing.
var contentFreeResultMembers = map[string]bool{
	"protocolVersion":   true,
	"capabilities":      true,
	"serverInfo":        true,
	"instructions":      true,
	"tools":             true,
	"prompts":           true,
	"resources":         true,
	"resourceTemplates": true,
	"roots":             true,
	"nextCursor":        true,
	"_meta":             true,
}

// carriesNoContent reports whether a JSON-RPC message carries nothing a
// guardrail needs to check, so a jsonPath that does not apply to it may let it
// through:
//   - a request or notification of a content-free method (see
//     contentFreeMethods), or any notification except notifications/message,
//     which carries log data, and a notifications/progress with a message;
//   - a result made only of initialize or listing members, or an empty one.
//
// Anything else, a tools/call or a tool result say, is content the path was
// meant to reach. An error response is not content-free either: its message
// and data are server text that reaches the client, so when the path does not
// apply to it they are assessed instead (see resolveErrorText).
func carriesNoContent(doc interface{}) bool {
	m, ok := doc.(map[string]interface{})
	if !ok {
		return false
	}
	if method, ok := m["method"].(string); ok {
		if contentFreeMethods[method] {
			return true
		}
		if method == "notifications/progress" {
			// A progress update may carry a human-readable message; only a bare
			// counter is content-free.
			params, _ := m["params"].(map[string]interface{})
			message, _ := params["message"].(string)
			return strings.TrimSpace(message) == ""
		}
		return strings.HasPrefix(method, "notifications/") && method != "notifications/message"
	}
	result, ok := m["result"].(map[string]interface{})
	if !ok {
		return false
	}
	for member := range result {
		if !contentFreeResultMembers[member] {
			return false
		}
	}
	return true
}

// isJSONRPCError reports whether a JSON-RPC message is an error response.
func isJSONRPCError(doc interface{}) bool {
	m, ok := doc.(map[string]interface{})
	if !ok {
		return false
	}
	_, isErr := m["error"].(map[string]interface{})
	return isErr
}

// errorTextPath selects the error object of a JSON-RPC error response, so every
// string in it (the message, and anything in data) is assessed.
var errorTextPath = mustParseJSONPath("$.error")

// mustParseJSONPath parses a path fixed in the code. A path that fails to parse,
// or parses to no tokens, would select the whole message (nil tokens resolve to
// the root), so it stops the policy from loading instead.
func mustParseJSONPath(path string) []pathToken {
	tokens, err := parseJSONPath(path)
	if err != nil || len(tokens) == 0 {
		panic(fmt.Sprintf("awsbedrockguardrail: invalid built-in jsonPath %q: %v", path, err))
	}
	return tokens
}

// resolveErrorText selects the text of a JSON-RPC error response that jsonPath
// does not apply to. An error with no text at all has nothing to assess.
func resolveErrorText(root *interface{}, onChange func()) ([]*textSegment, error) {
	segments, err := resolveTextSegments(root, errorTextPath, onChange)
	if errors.Is(err, errNoValue) {
		return nil, nil
	}
	return segments, err
}

// unchangedPayload is a payload with nothing to check.
func unchangedPayload(payload []byte) *extractedPayload {
	return &extractedPayload{rebuild: func() ([]byte, error) { return payload, nil }}
}

func decodeJSON(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc interface{}
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	// Reject trailing content, such as a second JSON value or a stray '}'.
	// (Decoder.More would accept a trailing '}' or ']'.)
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected content after JSON value")
	}
	return doc, nil
}

func encodeJSON(doc interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// payloadEvent is one event of a Server-Sent Events stream.
type payloadEvent struct {
	lines []string
	doc   interface{}
	dirty bool
}

// looksLikeEventStream reports whether the first non-empty line of the body is
// a Server-Sent Events field or comment.
func looksLikeEventStream(payload []byte) bool {
	// A byte order mark may open the stream; the SSE specification strips it.
	for _, line := range strings.Split(strings.TrimPrefix(normalizeLineEndings(payload), "\uFEFF"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		for _, prefix := range []string{"data:", "event:", "id:", "retry:", ":"} {
			if strings.HasPrefix(line, prefix) {
				return true
			}
		}
		return false
	}
	return false
}

// normalizeLineEndings turns the CRLF and CR line endings that Server-Sent
// Events allow into LF.
func normalizeLineEndings(payload []byte) string {
	return strings.ReplaceAll(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\r", "\n")
}

// splitEvents splits a Server-Sent Events body into its events at blank lines.
func splitEvents(payload []byte) []*payloadEvent {
	var events []*payloadEvent
	current := &payloadEvent{}
	for _, line := range strings.Split(normalizeLineEndings(payload), "\n") {
		if line == "" {
			if len(current.lines) > 0 {
				events = append(events, current)
				current = &payloadEvent{}
			}
			continue
		}
		current.lines = append(current.lines, line)
	}
	if len(current.lines) > 0 {
		events = append(events, current)
	}
	return events
}

func extractEventStream(payload []byte, jsonPath string, tokens []pathToken) (*extractedPayload, error) {
	events := splitEvents(payload)

	var segments []*textSegment
	matched := false
	allJSONRPC := true
	sawJSONRPC := false
	contentMissed := false
	for _, event := range events {
		data, ok := eventData(event.lines)
		if !ok {
			continue
		}
		doc, err := decodeJSON([]byte(data))
		if err != nil {
			// Not JSON (e.g. a "[DONE]" marker); nothing to check in this event.
			continue
		}
		isRPC := isJSONRPCMessage(doc)
		if isRPC {
			sawJSONRPC = true
		} else {
			allJSONRPC = false
		}
		event.doc = doc
		ev := event
		eventSegments, err := resolveTextSegments(&event.doc, tokens, func() { ev.dirty = true })
		if isRPC && (err == nil || errors.Is(err, errNoValue)) {
			if extra := structuredContentSegments(&event.doc, tokens, eventSegments, func() { ev.dirty = true }); len(extra) > 0 {
				if err != nil {
					eventSegments, err = nil, nil
				}
				eventSegments = append(eventSegments, extra...)
			}
		}
		if errors.Is(err, errNoValue) && isRPC && isJSONRPCError(doc) {
			// An error response the path does not apply to: its own text is
			// assessed instead.
			eventSegments, err = resolveErrorText(&event.doc, func() { ev.dirty = true })
		}
		if err != nil {
			// The path does not apply to this event (e.g. a progress notification).
			// Content it missed would be delivered unassessed: a JSON-RPC message
			// with content, such as a tool result of another shape; other JSON with
			// text, even beside events the path does match; or a value the path
			// selects that is not text (null, say), as extractPayload treats it.
			switch {
			case !errors.Is(err, errNoValue):
				contentMissed = true
			case isRPC:
				contentMissed = contentMissed || !carriesNoContent(doc)
			default:
				contentMissed = contentMissed || carriesText(doc)
			}
			continue
		}
		matched = true
		segments = append(segments, eventSegments...)
	}
	var missed error
	if contentMissed {
		missed = fmt.Errorf("an event in the Server-Sent Events stream carries content with no text at jsonPath %q", jsonPath)
		if !matched {
			return nil, missed
		}
	}
	if !matched && allJSONRPC && sawJSONRPC {
		// Only content-free JSON-RPC messages the path does not apply to, e.g. a
		// stream of MCP progress notifications or an initialize result. A stream
		// with no JSON event at all is not one: it has nothing to vouch for it, so
		// it is an error.
		return unchangedPayload(payload), nil
	}
	if !matched {
		return nil, fmt.Errorf("no event in the Server-Sent Events stream has a value at jsonPath %q", jsonPath)
	}

	rebuild := func() ([]byte, error) {
		var out strings.Builder
		for _, event := range events {
			lines := event.lines
			if event.dirty {
				encoded, err := encodeJSON(event.doc)
				if err != nil {
					return nil, err
				}
				lines = replaceEventData(event.lines, string(encoded))
			}
			out.WriteString(strings.Join(lines, "\n"))
			out.WriteString("\n\n")
		}
		return []byte(out.String()), nil
	}

	stripLogprobs := func() {
		for _, event := range events {
			if event.dirty {
				dropLogprobs(event.doc)
			}
		}
	}

	return &extractedPayload{segments: segments, rebuild: rebuild, stripLogprobs: stripLogprobs, missed: missed}, nil
}

// carriesText reports whether a JSON value holds any non-blank string.
func carriesText(v interface{}) bool {
	switch node := v.(type) {
	case string:
		return strings.TrimSpace(node) != ""
	case map[string]interface{}:
		for _, child := range node {
			if carriesText(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range node {
			if carriesText(child) {
				return true
			}
		}
	}
	return false
}

// eventData joins an event's data lines, as the SSE specification does.
func eventData(lines []string) (string, bool) {
	var data []string
	for _, line := range lines {
		if value, ok := dataLineValue(line); ok {
			data = append(data, value)
		}
	}
	if len(data) == 0 {
		return "", false
	}
	return strings.Join(data, "\n"), true
}

func dataLineValue(line string) (string, bool) {
	// A byte order mark may open the stream; the SSE specification strips it.
	line = strings.TrimPrefix(line, "\uFEFF")
	if !strings.HasPrefix(line, "data:") {
		return "", false
	}
	return strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "), true
}

// replaceEventData puts the new data in place of the first data line and drops
// the remaining data lines; other fields keep their position.
func replaceEventData(lines []string, data string) []string {
	out := make([]string, 0, len(lines))
	written := false
	for _, line := range lines {
		if _, ok := dataLineValue(line); ok {
			if !written {
				out = append(out, "data: "+data)
				written = true
			}
			continue
		}
		out = append(out, line)
	}
	return out
}

type pathTokenKind int

const (
	tokenKey pathTokenKind = iota
	tokenIndex
	tokenWildcard
)

type pathToken struct {
	kind  pathTokenKind
	key   string
	index int
}

// parseJSONPath parses the JSONPath subset the policy supports: $, .key, .*,
// [n] (negative counts from the end), [*] and ['key'].
func parseJSONPath(path string) ([]pathToken, error) {
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "$")

	var tokens []pathToken
	readKey := func(start int) (string, int) {
		end := start
		for end < len(p) && p[end] != '.' && p[end] != '[' {
			end++
		}
		return p[start:end], end
	}

	for i := 0; i < len(p); {
		switch p[i] {
		case '.':
			i++
			if i < len(p) && p[i] == '*' {
				tokens = append(tokens, pathToken{kind: tokenWildcard})
				i++
				continue
			}
			key, next := readKey(i)
			if key == "" {
				return nil, fmt.Errorf("invalid jsonPath %q: empty key", path)
			}
			tokens = append(tokens, pathToken{kind: tokenKey, key: key})
			i = next
		case '[':
			end := strings.IndexByte(p[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("invalid jsonPath %q: missing ']'", path)
			}
			inner := strings.TrimSpace(p[i+1 : i+end])
			switch {
			case inner == "*":
				tokens = append(tokens, pathToken{kind: tokenWildcard})
			case len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0]:
				tokens = append(tokens, pathToken{kind: tokenKey, key: inner[1 : len(inner)-1]})
			default:
				index, err := strconv.Atoi(inner)
				if err != nil {
					return nil, fmt.Errorf("invalid jsonPath %q: bad array index %q", path, inner)
				}
				tokens = append(tokens, pathToken{kind: tokenIndex, index: index})
			}
			i += end + 1
		default:
			// A path without a leading "$." starts with a bare key.
			key, next := readKey(i)
			tokens = append(tokens, pathToken{kind: tokenKey, key: key})
			i = next
		}
	}
	return tokens, nil
}

// slot is a location in a decoded JSON document that can be read and written.
type slot struct {
	get func() interface{}
	set func(interface{})
	// fromWildcard marks an element a wildcard selected, whose shape may differ
	// from its siblings' (see resolveTextSegments).
	fromWildcard bool
	loc          slotLocation
}

// descendantSlots returns the members named key anywhere beneath node.
func descendantSlots(node interface{}, key string) []slot {
	var found []slot
	switch v := node.(type) {
	case map[string]interface{}:
		for _, k := range sortedKeys(v) {
			if k == key {
				found = append(found, mapSlot(v, k))
				continue
			}
			found = append(found, descendantSlots(v[k], key)...)
		}
	case []interface{}:
		for i := range v {
			found = append(found, descendantSlots(v[i], key)...)
		}
	}
	return found
}

func mapSlot(m map[string]interface{}, key string) slot {
	return slot{
		get: func() interface{} { return m[key] },
		set: func(v interface{}) { m[key] = v },
		loc: slotLocation{container: reflect.ValueOf(m).Pointer(), key: key, index: -1},
	}
}

func arraySlot(arr []interface{}, index int) slot {
	return slot{
		get: func() interface{} { return arr[index] },
		set: func(v interface{}) { arr[index] = v },
		loc: slotLocation{container: reflect.ValueOf(arr).Pointer(), index: index},
	}
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// resolveTextSegments resolves the path against the document and returns every
// string found at, or inside, the matched values. onChange runs whenever a
// segment is written back. It fails only when the path matches nothing, or
// when it matches only values that are not text (true, false, null).
func resolveTextSegments(root *interface{}, tokens []pathToken, onChange func()) ([]*textSegment, error) {
	slots := []slot{{
		get: func() interface{} { return *root },
		set: func(v interface{}) { *root = v },
	}}

	for _, token := range tokens {
		var next []slot
		for _, s := range slots {
			switch node := s.get().(type) {
			case map[string]interface{}:
				switch token.kind {
				case tokenKey:
					if _, ok := node[token.key]; ok {
						next = append(next, mapSlot(node, token.key))
					} else if s.fromWildcard {
						// An element of another shape than its siblings, such as an MCP
						// resource item ({"resource":{"text":...}}) beside text items
						// under $.result.content[*].text: its members of that name,
						// however deep, are read too, rather than its text passing
						// unassessed. An element with none (an image) has no such text.
						next = append(next, descendantSlots(node, token.key)...)
					}
				case tokenWildcard:
					for _, k := range sortedKeys(node) {
						sl := mapSlot(node, k)
						sl.fromWildcard = true
						next = append(next, sl)
					}
				}
			case []interface{}:
				switch token.kind {
				case tokenIndex:
					index := token.index
					if index < 0 {
						index += len(node)
					}
					if index >= 0 && index < len(node) {
						next = append(next, arraySlot(node, index))
					}
				case tokenWildcard:
					for i := range node {
						sl := arraySlot(node, i)
						sl.fromWildcard = true
						next = append(next, sl)
					}
				}
			}
		}
		slots = next
		if len(slots) == 0 {
			return nil, errNoValue
		}
	}

	var segments []*textSegment
	nonText := 0
	newSegment := func(value string, s slot) {
		segments = append(segments, &textSegment{
			value: value,
			loc:   s.loc,
			set: func(v string) {
				s.set(v)
				if onChange != nil {
					onChange()
				}
			},
		})
	}

	var collect func(s slot)
	collect = func(s slot) {
		switch v := s.get().(type) {
		case string:
			newSegment(v, s)
		case map[string]interface{}:
			for _, k := range sortedKeys(v) {
				collect(mapSlot(v, k))
			}
		case []interface{}:
			for i := range v {
				collect(arraySlot(v, i))
			}
		}
	}

	for _, s := range slots {
		switch v := s.get().(type) {
		case json.Number:
			// A number selected directly is checked as text, as before.
			newSegment(v.String(), s)
		case string, map[string]interface{}, []interface{}:
			collect(s)
		default:
			nonText++
		}
	}

	if nonText == len(slots) {
		return nil, errors.New("value at jsonPath is not a string or number")
	}
	return segments, nil
}
