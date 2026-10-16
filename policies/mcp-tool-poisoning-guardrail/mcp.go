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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	mcpPathSegment   = "/mcp"
	mcpSessionHeader = "mcp-session-id"

	// methodToolsList is the only MCP method this policy inspects. Every other
	// method is passed through untouched.
	methodToolsList = "tools/list"

	// resultToolsKey is the key holding the tool array inside a tools/list result.
	resultToolsKey = "tools"

	// maxJSONDepth bounds how deeply a decoded document may nest. It is a
	// parser guard, not an inspection limit (that is maxNestingDepth): a body
	// nested beyond it is malformed rather than walked.
	maxJSONDepth = 1000
)

// errMalformedJSON marks a body that is not the single well-formed JSON
// document expected. Messages wrapping it never quote the document.
var errMalformedJSON = errors.New("malformed JSON")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errMalformedJSON, fmt.Sprintf(format, args...))
}

// ──────────────────────────────────────────────────────────────────────────
// Strict JSON decoding.
//
// encoding/json is deliberately not used for anything this policy inspects. It
// keeps the last of two duplicate keys, silently replaces invalid UTF-8, and
// cannot say where in the input a value came from. Each of those is a gap
// between what the guardrail inspects and what a client is shown:
//
//   - A client that keeps the first of two duplicate keys would be shown a value
//     this policy never inspected, so duplicate keys are refused in responses.
//   - A body that is not valid UTF-8 is not JSON, and repairing it would mean
//     inspecting a document the upstream never sent.
//   - Filtering rebuilds result.tools from the upstream's own bytes, which needs
//     the byte span of every tool entry.
//
// Strings are decoded to WTF-8: a lone surrogate escape (\ud800) is kept as its
// three-byte generalised UTF-8 form rather than collapsed to U+FFFD. That keeps
// "\ud800" and "\ud801" distinct — as distinct object keys, and as distinct
// JSON-RPC ids — exactly as JSON defines them. Text handed to the static
// detectors or the classifier goes through validText first.
// ──────────────────────────────────────────────────────────────────────────

// span is a half-open byte range [start, end) in the decoded input.
type span struct {
	start int
	end   int
}

// jsonLayout records where result.tools and each of its entries sit in the
// decoded input, so a filtered response can be rebuilt from the upstream's own
// bytes.
type jsonLayout struct {
	hasTools    bool
	tools       span
	toolEntries []span
}

// Positions whose spans are captured.
type valueRole int

const (
	roleOther valueRole = iota
	roleRoot
	roleResult
	roleTools
)

type jsonDecoder struct {
	data            string
	pos             int
	allowDuplicates bool
	layout          jsonLayout
}

// decodeJSON decodes exactly one JSON value, preserving number literals as
// json.Number. The whole input must be that one value plus JSON whitespace: a
// body such as `{...}]` is rejected rather than having its prefix inspected.
func decodeJSON(data string, allowDuplicates bool) (any, jsonLayout, error) {
	if !utf8.ValidString(data) {
		return nil, jsonLayout{}, malformed("body is not valid UTF-8")
	}
	decoder := &jsonDecoder{data: data, allowDuplicates: allowDuplicates}
	decoder.skipWhitespace()
	if decoder.pos == len(data) {
		return nil, jsonLayout{}, malformed("body is empty")
	}
	value, err := decoder.value(0, roleRoot)
	if err != nil {
		return nil, jsonLayout{}, err
	}
	decoder.skipWhitespace()
	if decoder.pos != len(data) {
		return nil, jsonLayout{}, malformed("unexpected trailing content after the payload")
	}
	return value, decoder.layout, nil
}

// decodeJSONObject decodes a body that must be exactly one JSON object.
func decodeJSONObject(data string, allowDuplicates bool) (map[string]any, jsonLayout, error) {
	value, layout, err := decodeJSON(data, allowDuplicates)
	if err != nil {
		return nil, jsonLayout{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, jsonLayout{}, malformed("payload is not a JSON object")
	}
	return object, layout, nil
}

func (d *jsonDecoder) skipWhitespace() {
	for d.pos < len(d.data) {
		switch d.data[d.pos] {
		case ' ', '\t', '\n', '\r':
			d.pos++
		default:
			return
		}
	}
}

func (d *jsonDecoder) syntaxError(what string) error {
	return malformed("invalid JSON: %s at offset %d", what, d.pos)
}

func (d *jsonDecoder) value(depth int, role valueRole) (any, error) {
	if d.pos >= len(d.data) {
		return nil, d.syntaxError("unexpected end of input")
	}
	switch c := d.data[d.pos]; {
	case c == '{':
		return d.object(depth+1, role)
	case c == '[':
		return d.array(depth+1, role)
	case c == '"':
		return d.string()
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	case strings.HasPrefix(d.data[d.pos:], "true"):
		d.pos += 4
		return true, nil
	case strings.HasPrefix(d.data[d.pos:], "false"):
		d.pos += 5
		return false, nil
	case strings.HasPrefix(d.data[d.pos:], "null"):
		d.pos += 4
		return nil, nil
	default:
		// NaN, Infinity and -Infinity land here: none of them is JSON.
		return nil, d.syntaxError("unexpected character")
	}
}

func (d *jsonDecoder) object(depth int, role valueRole) (any, error) {
	if depth > maxJSONDepth {
		return nil, malformed("document nested more than %d levels deep", maxJSONDepth)
	}
	d.pos++ // {
	object := make(map[string]any)
	d.skipWhitespace()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		return object, nil
	}
	for {
		d.skipWhitespace()
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return nil, d.syntaxError("expected an object key")
		}
		key, err := d.string()
		if err != nil {
			return nil, err
		}
		d.skipWhitespace()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, d.syntaxError("expected ':'")
		}
		d.pos++
		d.skipWhitespace()

		childRole := roleOther
		switch {
		case role == roleRoot && key == "result":
			childRole = roleResult
		case role == roleResult && key == resultToolsKey:
			childRole = roleTools
		}
		value, err := d.value(depth, childRole)
		if err != nil {
			return nil, err
		}

		if _, duplicate := object[key]; duplicate && !d.allowDuplicates {
			// A client that keeps the first of two duplicate keys would be
			// shown a value this policy never inspected. Refusing the document
			// closes that gap instead of guessing which one the client reads.
			return nil, malformed("duplicate object key")
		}
		object[key] = value

		d.skipWhitespace()
		if d.pos >= len(d.data) {
			return nil, d.syntaxError("unterminated object")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
		case '}':
			d.pos++
			return object, nil
		default:
			return nil, d.syntaxError("expected ',' or '}'")
		}
	}
}

func (d *jsonDecoder) array(depth int, role valueRole) (any, error) {
	if depth > maxJSONDepth {
		return nil, malformed("document nested more than %d levels deep", maxJSONDepth)
	}
	arrayStart := d.pos
	d.pos++ // [
	items := make([]any, 0)
	var entries []span
	d.skipWhitespace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
	} else {
		for {
			d.skipWhitespace()
			start := d.pos
			value, err := d.value(depth, roleOther)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
			if role == roleTools {
				entries = append(entries, span{start: start, end: d.pos})
			}
			d.skipWhitespace()
			if d.pos >= len(d.data) {
				return nil, d.syntaxError("unterminated array")
			}
			if d.data[d.pos] == ',' {
				d.pos++
				continue
			}
			if d.data[d.pos] == ']' {
				d.pos++
				break
			}
			return nil, d.syntaxError("expected ',' or ']'")
		}
	}
	if role == roleTools {
		d.layout.hasTools = true
		d.layout.tools = span{start: arrayStart, end: d.pos}
		d.layout.toolEntries = entries
	}
	return items, nil
}

func (d *jsonDecoder) number() (any, error) {
	start := d.pos
	if d.data[d.pos] == '-' {
		d.pos++
	}
	switch {
	case d.pos < len(d.data) && d.data[d.pos] == '0':
		d.pos++
	case d.pos < len(d.data) && d.data[d.pos] >= '1' && d.data[d.pos] <= '9':
		d.digits()
	default:
		return nil, d.syntaxError("invalid number")
	}
	if d.pos < len(d.data) && d.data[d.pos] == '.' {
		d.pos++
		if !d.digits() {
			return nil, d.syntaxError("invalid number")
		}
	}
	if d.pos < len(d.data) && (d.data[d.pos] == 'e' || d.data[d.pos] == 'E') {
		d.pos++
		if d.pos < len(d.data) && (d.data[d.pos] == '+' || d.data[d.pos] == '-') {
			d.pos++
		}
		if !d.digits() {
			return nil, d.syntaxError("invalid number")
		}
	}
	// Kept as the literal: ids and unrelated fields are echoed to the client,
	// and a float round trip would rewrite 0.10 as 0.1 or overflow 1e400.
	return json.Number(d.data[start:d.pos]), nil
}

func (d *jsonDecoder) digits() bool {
	start := d.pos
	for d.pos < len(d.data) && d.data[d.pos] >= '0' && d.data[d.pos] <= '9' {
		d.pos++
	}
	return d.pos > start
}

func (d *jsonDecoder) string() (string, error) {
	d.pos++ // opening quote
	var builder strings.Builder
	chunkStart := d.pos
	for {
		if d.pos >= len(d.data) {
			return "", d.syntaxError("unterminated string")
		}
		c := d.data[d.pos]
		switch {
		case c == '"':
			if builder.Len() == 0 {
				value := d.data[chunkStart:d.pos]
				d.pos++
				return value, nil
			}
			builder.WriteString(d.data[chunkStart:d.pos])
			d.pos++
			return builder.String(), nil
		case c < 0x20:
			return "", d.syntaxError("invalid control character in string")
		case c == '\\':
			builder.WriteString(d.data[chunkStart:d.pos])
			if err := d.escape(&builder); err != nil {
				return "", err
			}
			chunkStart = d.pos
		default:
			d.pos++
		}
	}
}

func (d *jsonDecoder) escape(builder *strings.Builder) error {
	d.pos++ // backslash
	if d.pos >= len(d.data) {
		return d.syntaxError("unterminated escape")
	}
	c := d.data[d.pos]
	d.pos++
	switch c {
	case '"', '\\', '/':
		builder.WriteByte(c)
	case 'b':
		builder.WriteByte('\b')
	case 'f':
		builder.WriteByte('\f')
	case 'n':
		builder.WriteByte('\n')
	case 'r':
		builder.WriteByte('\r')
	case 't':
		builder.WriteByte('\t')
	case 'u':
		code, ok := d.hex4()
		if !ok {
			return d.syntaxError("invalid \\uXXXX escape")
		}
		if code >= 0xD800 && code <= 0xDBFF && strings.HasPrefix(d.data[d.pos:], `\u`) {
			// A high surrogate followed by a low one is one astral character.
			saved := d.pos
			d.pos += 2
			if low, ok := d.hex4(); ok && low >= 0xDC00 && low <= 0xDFFF {
				builder.WriteRune(0x10000 + (code-0xD800)<<10 + (low - 0xDC00))
				return nil
			}
			d.pos = saved
		}
		if code >= 0xD800 && code <= 0xDFFF {
			appendWTF8Surrogate(builder, code)
			return nil
		}
		builder.WriteRune(code)
	default:
		return d.syntaxError("invalid escape")
	}
	return nil
}

func (d *jsonDecoder) hex4() (rune, bool) {
	if d.pos+4 > len(d.data) {
		return 0, false
	}
	var value rune
	for _, c := range []byte(d.data[d.pos : d.pos+4]) {
		switch {
		case c >= '0' && c <= '9':
			value = value<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			value = value<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			value = value<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	d.pos += 4
	return value, true
}

// appendWTF8Surrogate writes a lone surrogate code point in its three-byte
// generalised UTF-8 form, which is not valid UTF-8 and so can never be confused
// with real text.
func appendWTF8Surrogate(builder *strings.Builder, code rune) {
	builder.WriteByte(byte(0xE0 | code>>12))
	builder.WriteByte(byte(0x80 | (code>>6)&0x3F))
	builder.WriteByte(byte(0x80 | code&0x3F))
}

// wtf8SurrogateAt reports the lone surrogate encoded at s[i:], if any.
func wtf8SurrogateAt(s string, i int) (rune, bool) {
	if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
		return 0xD000 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F), true
	}
	return 0, false
}

// validText replaces every lone surrogate with U+FFFD, one replacement per
// surrogate. This is the text the static detectors and the classifier see.
func validText(s string) string {
	if !strings.Contains(s, "\xED") {
		return s
	}
	var builder strings.Builder
	builder.Grow(len(s))
	for i := 0; i < len(s); {
		if _, ok := wtf8SurrogateAt(s, i); ok {
			builder.WriteRune(utf8.RuneError)
			i += 3
			continue
		}
		builder.WriteByte(s[i])
		i++
	}
	return builder.String()
}

// ──────────────────────────────────────────────────────────────────────────
// JSON encoding.
//
// Everything this policy writes — JSON-RPC errors, assessments, canonical ids —
// goes through this encoder rather than encoding/json, so that it can write a
// lone surrogate back as the escape it arrived as, keep object members in the
// order they were built, and leave <, > and & unescaped.
// ──────────────────────────────────────────────────────────────────────────

// orderedObject is a JSON object whose members are written in order.
type orderedObject []jsonMember

type jsonMember struct {
	key   string
	value any
}

// rawJSON is an already-encoded JSON value written verbatim.
type rawJSON string

// encodeJSON writes value compactly. Maps are written with sorted keys, which
// is the canonical form used to compare JSON-RPC ids.
func encodeJSON(value any) (string, error) {
	var builder strings.Builder
	if err := appendJSON(&builder, value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func appendJSON(builder *strings.Builder, value any) error {
	switch typed := value.(type) {
	case nil:
		builder.WriteString("null")
	case bool:
		if typed {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
	case string:
		appendJSONString(builder, typed, false)
	case json.Number:
		builder.WriteString(string(typed))
	case rawJSON:
		builder.WriteString(string(typed))
	case int:
		builder.WriteString(strconv.Itoa(typed))
	case int64:
		builder.WriteString(strconv.FormatInt(typed, 10))
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			// A non-finite number must never be written as JSON.
			return fmt.Errorf("cannot encode a non-finite number as JSON")
		}
		builder.WriteString(formatFloat(typed))
	case orderedObject:
		builder.WriteByte('{')
		for index, member := range typed {
			if index > 0 {
				builder.WriteByte(',')
			}
			appendJSONString(builder, member.key, false)
			builder.WriteByte(':')
			if err := appendJSON(builder, member.value); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		// Byte order of (WTF-8) keys is code point order.
		sort.Strings(keys)
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteByte(',')
			}
			appendJSONString(builder, key, false)
			builder.WriteByte(':')
			if err := appendJSON(builder, typed[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	case []any:
		builder.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := appendJSON(builder, item); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
	case []string:
		builder.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				builder.WriteByte(',')
			}
			appendJSONString(builder, item, false)
		}
		builder.WriteByte(']')
	default:
		return fmt.Errorf("cannot encode %T as JSON", value)
	}
	return nil
}

// appendJSONString writes s as a JSON string. Text is written as UTF-8 with
// only the mandatory escapes; asciiOnly escapes everything outside printable
// ASCII instead, which is also forced for a string holding a lone surrogate so
// that the surrogate is written back as the escape it arrived as.
func appendJSONString(builder *strings.Builder, s string, asciiOnly bool) {
	if !asciiOnly && strings.Contains(s, "\xED") {
		for i := 0; i < len(s); i++ {
			if _, ok := wtf8SurrogateAt(s, i); ok {
				asciiOnly = true
				break
			}
		}
	}
	builder.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				builder.WriteString(`\"`)
			case '\\':
				builder.WriteString(`\\`)
			case '\n':
				builder.WriteString(`\n`)
			case '\r':
				builder.WriteString(`\r`)
			case '\t':
				builder.WriteString(`\t`)
			case '\b':
				builder.WriteString(`\b`)
			case '\f':
				builder.WriteString(`\f`)
			default:
				if c < 0x20 || (asciiOnly && c == 0x7F) {
					writeUnicodeEscape(builder, rune(c))
				} else {
					builder.WriteByte(c)
				}
			}
			i++
			continue
		}
		if code, ok := wtf8SurrogateAt(s, i); ok {
			writeUnicodeEscape(builder, code)
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Unreachable for decoded input, which is validated; never
			// written out as invalid UTF-8.
			writeUnicodeEscape(builder, utf8.RuneError)
		case !asciiOnly:
			builder.WriteString(s[i : i+size])
		case r >= 0x10000:
			r -= 0x10000
			writeUnicodeEscape(builder, 0xD800+(r>>10))
			writeUnicodeEscape(builder, 0xDC00+(r&0x3FF))
		default:
			writeUnicodeEscape(builder, r)
		}
		i += size
	}
	builder.WriteByte('"')
}

func writeUnicodeEscape(builder *strings.Builder, code rune) {
	const hexDigits = "0123456789abcdef"
	builder.WriteString(`\u`)
	builder.WriteByte(hexDigits[(code>>12)&0xF])
	builder.WriteByte(hexDigits[(code>>8)&0xF])
	builder.WriteByte(hexDigits[(code>>4)&0xF])
	builder.WriteByte(hexDigits[code&0xF])
}

// formatFloat renders a float the way the reference implementation's
// assessments did: the shortest round-tripping digits, in fixed notation for
// exponents from -4 to 15 (always with a fractional part) and in scientific
// notation with a two-digit exponent otherwise — 0.6, 1.0, 1e-05, 1e+16.
func formatFloat(value float64) string {
	if value == 0 {
		if math.Signbit(value) {
			return "-0.0"
		}
		return "0.0"
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	sign := ""
	if scientific[0] == '-' {
		sign = "-"
		scientific = scientific[1:]
	}
	mantissa, exponentText, _ := strings.Cut(scientific, "e")
	exponent, _ := strconv.Atoi(exponentText)
	digits := strings.Replace(mantissa, ".", "", 1)

	if exponent >= -4 && exponent < 16 {
		if exponent >= 0 {
			if len(digits) <= exponent+1 {
				return sign + digits + strings.Repeat("0", exponent+1-len(digits)) + ".0"
			}
			return sign + digits[:exponent+1] + "." + digits[exponent+1:]
		}
		return sign + "0." + strings.Repeat("0", -exponent-1) + digits
	}

	formatted := digits[:1]
	if len(digits) > 1 {
		formatted += "." + digits[1:]
	}
	exponentSign := "+"
	if exponent < 0 {
		exponentSign = "-"
		exponent = -exponent
	}
	return fmt.Sprintf("%s%se%s%02d", sign, formatted, exponentSign, exponent)
}

// asciiQuote renders s as an ASCII-only JSON string. Used for labels built from
// upstream text, so a label can never carry a raw control or bidirectional
// character into a log line.
func asciiQuote(s string) string {
	var builder strings.Builder
	appendJSONString(&builder, s, true)
	return builder.String()
}

// ──────────────────────────────────────────────────────────────────────────
// Server-sent events
// ──────────────────────────────────────────────────────────────────────────

// sseEvent is one parsed server-sent event.
//
// fields keeps every non-data line verbatim (event:, id:, retry:, comments) so a
// rebuilt event keeps its framing. raw is the exact source text of the event
// including its terminating blank line, so events this policy does not rewrite
// are written back byte for byte.
type sseEvent struct {
	fields  []string
	data    string
	hasData bool
	raw     string
	newline string
}

// parseEventStream splits an SSE payload into events.
//
// Lines are split on LF and a trailing CR is dropped, so LF and CRLF framing
// are both understood. `data:` lines are joined with LF and lose one optional
// leading space. A payload that is not valid UTF-8 is not an event stream.
//
// A bare CR is also a line terminator in the SSE grammar, but rebuilding a
// stream that mixes all three terminators byte for byte is not worth the
// surface: a CR inside what this parser reads as one line would be a line
// boundary to the client, so the client would see `data:` fields this policy
// never inspected. Such a stream is refused rather than parsed.
func parseEventStream(body string) ([]sseEvent, error) {
	if !utf8.ValidString(body) {
		return nil, malformed("body is not valid UTF-8")
	}

	events := make([]sseEvent, 0)
	current := sseEvent{}
	var rawParts []string
	var dataLines []string
	newline := ""

	flush := func() {
		switch {
		case len(current.fields) > 0 || len(dataLines) > 0:
			current.data = strings.Join(dataLines, "\n")
			current.hasData = len(dataLines) > 0
			current.raw = strings.Join(rawParts, "")
			current.newline = newline
			if current.newline == "" {
				current.newline = "\n"
			}
			events = append(events, current)
		case len(rawParts) > 0 && len(events) > 0:
			// Blank lines between events stay with the previous event, so they
			// survive a rebuild unchanged.
			events[len(events)-1].raw += strings.Join(rawParts, "")
		}
		current = sseEvent{}
		rawParts = nil
		dataLines = nil
		newline = ""
	}

	pieces := strings.Split(body, "\n")
	last := len(pieces) - 1
	for index, piece := range pieces {
		// Only a CR that terminates the piece is CRLF framing. Any other CR
		// splits the line for the client but not for this parser.
		if strings.Contains(strings.TrimSuffix(piece, "\r"), "\r") {
			return nil, malformed("event stream uses a bare CR line terminator")
		}
		if index < last {
			rawParts = append(rawParts, piece+"\n")
		} else if piece != "" {
			rawParts = append(rawParts, piece)
		}
		line := strings.TrimSuffix(piece, "\r")
		if newline == "" && index < last {
			newline = "\n"
			if strings.HasSuffix(piece, "\r") {
				newline = "\r\n"
			}
		}
		if line == "" {
			flush()
			continue
		}
		if value, isData := strings.CutPrefix(line, "data:"); isData {
			dataLines = append(dataLines, strings.TrimPrefix(value, " "))
			continue
		}
		current.fields = append(current.fields, line)
	}
	flush()

	return events, nil
}

// buildEvent renders one event with new data, keeping its other lines and its
// line ending.
func buildEvent(event sseEvent, data string) string {
	newline := event.newline
	if newline == "" {
		newline = "\n"
	}
	lines := append([]string(nil), event.fields...)
	for _, line := range strings.Split(data, "\n") {
		lines = append(lines, "data: "+line)
	}
	return strings.Join(lines, newline) + newline + newline
}

// buildEventStream renders events built by this policy, such as an error.
func buildEventStream(events []sseEvent) string {
	var builder strings.Builder
	for _, event := range events {
		builder.WriteString(buildEvent(event, event.data))
	}
	return builder.String()
}

// ──────────────────────────────────────────────────────────────────────────
// JSON-RPC
// ──────────────────────────────────────────────────────────────────────────

// encodeJSONRPCID renders a payload's JSON-RPC id into a comparable, storable
// form. ok is false when the payload has no id member at all, which makes it a
// notification: no response comes back, so there is nothing to inspect.
//
// An explicit `"id": null` is NOT a notification. MCP forbids null ids, but a
// client that sends one still gets a response carrying tool metadata, so it is
// correlated like any other id rather than let through uninspected.
//
// The encoding is canonical JSON with number literals preserved and object keys
// sorted, so an int64 id, a string id and a null id stay distinct and compare
// exactly, and the stored form can be echoed back verbatim in an error.
func encodeJSONRPCID(payload map[string]any) (string, bool) {
	id, present := payload["id"]
	if !present {
		return "", false
	}
	encoded, err := encodeJSON(id)
	if err != nil {
		return "", false
	}
	return encoded, true
}

// matchesJSONRPCID reports whether a response payload answers the recorded id.
func matchesJSONRPCID(payload map[string]any, encodedRequestID string) bool {
	encoded, ok := encodeJSONRPCID(payload)
	return ok && encoded == encodedRequestID
}

// requestIDForEcho restores a stored id so it can be echoed back in an error.
// The stored form is already canonical JSON; anything that does not decode is
// echoed as null.
func requestIDForEcho(encoded string) rawJSON {
	if _, _, err := decodeJSON(encoded, false); err != nil {
		return "null"
	}
	return rawJSON(encoded)
}

// isJSONRPCError reports whether the payload is an upstream JSON-RPC error
// response. Upstream errors are forwarded to the client untouched.
func isJSONRPCError(payload map[string]any) bool {
	value, ok := payload["error"]
	return ok && value != nil
}

// buildJSONRPCError renders a JSON-RPC error response. data is omitted when nil.
func buildJSONRPCError(code int, message string, requestID rawJSON, data any) string {
	errorObject := orderedObject{{"code", code}, {"message", message}}
	if data != nil {
		errorObject = append(errorObject, jsonMember{"data", data})
	}
	body, err := encodeJSON(orderedObject{
		{"jsonrpc", "2.0"},
		{"id", requestID},
		{"error", errorObject},
	})
	if err != nil {
		return `{"jsonrpc":"2.0","id":` + string(requestID) + `,"error":{"code":-32603,"message":"Unexpected error"}}`
	}
	return body
}

// parseRequestPayload extracts the JSON-RPC payload of a request, handling SSE
// framing. It returns a map for a single request or a []any for a batch.
//
// Request parsing keeps the last of any duplicate keys: a malformed request is
// the client's own business, and the response side is where duplicate keys are
// refused.
func parseRequestPayload(body []byte, sse bool) (any, error) {
	if !sse {
		value, _, err := decodeJSON(string(body), true)
		if err != nil {
			return nil, err
		}
		switch value.(type) {
		case map[string]any, []any:
			return value, nil
		}
		return nil, malformed("request is not a JSON object or batch")
	}

	events, err := parseEventStream(string(body))
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if strings.TrimSpace(event.data) == "" {
			continue
		}
		value, _, err := decodeJSON(event.data, true)
		if err != nil {
			continue
		}
		switch value.(type) {
		case map[string]any, []any:
			return value, nil
		}
	}
	return nil, malformed("no JSON payload found in event stream")
}

// isToolsListRequest reports whether a decoded JSON-RPC entry calls tools/list.
func isToolsListRequest(payload any) bool {
	entry, ok := payload.(map[string]any)
	if !ok {
		return false
	}
	method, _ := entry["method"].(string)
	return method == methodToolsList
}

// ──────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ──────────────────────────────────────────────────────────────────────────

// isMcpPostRequest reports whether the request targets the MCP endpoint.
// Segment-exact match: only "/mcp" itself or a subpath under "/mcp/", never a
// substring such as "/resource/mcp". Mirrors the mcp-acl-list policy.
func isMcpPostRequest(method, path string) bool {
	if !strings.EqualFold(method, "POST") {
		return false
	}
	cleanPath := strings.TrimSpace(path)
	if idx := strings.Index(cleanPath, "?"); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	return cleanPath == mcpPathSegment || strings.HasPrefix(cleanPath, mcpPathSegment+"/")
}

// isEventStream reports whether headers declare an SSE payload.
func isEventStream(headers *policy.Headers) bool {
	for _, value := range headers.Get("content-type") {
		if strings.Contains(strings.ToLower(value), "text/event-stream") {
			return true
		}
	}
	return false
}

// getSessionID returns the MCP session id header value, or an empty string.
func getSessionID(headers *policy.Headers) string {
	if values := headers.Get(mcpSessionHeader); len(values) > 0 {
		return values[0]
	}
	return ""
}

// buildErrorResponse builds the immediate response returned when the guardrail
// refuses to deliver a tools/list result. The upstream framing (JSON or SSE)
// and the MCP session id are preserved so the client sees a well-formed MCP
// response on the transport it negotiated.
func buildErrorResponse(sse bool, sessionID string, code int, message string, requestID rawJSON, data any, analytics map[string]any) policy.ImmediateResponse {
	body := buildJSONRPCError(code, message, requestID, data)

	contentType := "application/json"
	if sse {
		contentType = "text/event-stream"
		body = buildEventStream([]sseEvent{{data: body}})
	}

	headers := map[string]string{"Content-Type": contentType}
	if sessionID != "" {
		headers[mcpSessionHeader] = sessionID
	}

	copied := make(map[string]any, len(analytics))
	for key, value := range analytics {
		copied[key] = value
	}
	return policy.ImmediateResponse{
		StatusCode:        200,
		Headers:           headers,
		Body:              []byte(body),
		AnalyticsMetadata: copied,
	}
}
