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
	"sort"
	"strconv"
	"strings"
)

// textSegment is one text value taken from a payload for the guardrail to check.
// set writes a new value back into the parsed payload, for masking.
type textSegment struct {
	value string
	set   func(string)
}

// extractedPayload holds the text segments found in a payload and rebuilds the
// payload after any segment has been changed.
type extractedPayload struct {
	segments []*textSegment
	rebuild  func() ([]byte, error)
}

// extractPayload finds the text the guardrail must check.
//
//   - An empty jsonPath checks the whole body as one piece of text.
//   - A JSON body is resolved with jsonPath. When the path points at an object
//     or an array, every string inside it is checked (e.g. "$.params.arguments"
//     covers every MCP tool argument).
//   - A Server-Sent Events body (e.g. an MCP Streamable HTTP response) is split
//     into events, and jsonPath is resolved against the JSON in each event's data.
func extractPayload(payload []byte, jsonPath string) (*extractedPayload, error) {
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
		if err != nil {
			return nil, fmt.Errorf("%w (jsonPath %q)", err, jsonPath)
		}
		return &extractedPayload{
			segments: segments,
			rebuild:  func() ([]byte, error) { return encodeJSON(*root) },
		}, nil
	}

	if looksLikeEventStream(payload) {
		return extractEventStream(payload, jsonPath, tokens)
	}

	return nil, fmt.Errorf("payload is neither JSON nor a Server-Sent Events stream: %w", jsonErr)
}

func decodeJSON(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc interface{}
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	// Reject trailing content such as a second JSON value.
	if decoder.More() {
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

// sseEvent is one event of a Server-Sent Events stream.
type sseEvent struct {
	lines []string
	doc   interface{}
	dirty bool
}

// looksLikeEventStream reports whether the first non-empty line of the body is
// a Server-Sent Events field or comment.
func looksLikeEventStream(payload []byte) bool {
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimRight(line, "\r")
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

func extractEventStream(payload []byte, jsonPath string, tokens []pathToken) (*extractedPayload, error) {
	normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")

	var events []*sseEvent
	current := &sseEvent{}
	for _, line := range strings.Split(normalized, "\n") {
		if line == "" {
			if len(current.lines) > 0 {
				events = append(events, current)
				current = &sseEvent{}
			}
			continue
		}
		current.lines = append(current.lines, line)
	}
	if len(current.lines) > 0 {
		events = append(events, current)
	}

	var segments []*textSegment
	matched := false
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
		event.doc = doc
		ev := event
		eventSegments, err := resolveTextSegments(&event.doc, tokens, func() { ev.dirty = true })
		if err != nil {
			// The path does not apply to this event (e.g. a progress notification).
			continue
		}
		matched = true
		segments = append(segments, eventSegments...)
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

	return &extractedPayload{segments: segments, rebuild: rebuild}, nil
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
}

func mapSlot(m map[string]interface{}, key string) slot {
	return slot{
		get: func() interface{} { return m[key] },
		set: func(v interface{}) { m[key] = v },
	}
}

func arraySlot(arr []interface{}, index int) slot {
	return slot{
		get: func() interface{} { return arr[index] },
		set: func(v interface{}) { arr[index] = v },
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
					}
				case tokenWildcard:
					for _, k := range sortedKeys(node) {
						next = append(next, mapSlot(node, k))
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
						next = append(next, arraySlot(node, i))
					}
				}
			}
		}
		slots = next
		if len(slots) == 0 {
			return nil, errors.New("no value found at jsonPath")
		}
	}

	var segments []*textSegment
	nonText := 0
	newSegment := func(value string, s slot) {
		segments = append(segments, &textSegment{
			value: value,
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
