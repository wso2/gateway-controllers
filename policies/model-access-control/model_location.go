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

package modelaccesscontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

type locationKind string

const (
	locationPayload locationKind = "payload"
	locationHeader  locationKind = "header"
	locationQuery   locationKind = "queryParam"
	locationPath    locationKind = "pathParam"
)

// modelLocation says where the request carries the model. The gateway controller
// injects it from the LLM provider template; the API operator never sets it.
type modelLocation struct {
	kind       locationKind
	identifier string
	// segments is the parsed payload JSONPath.
	segments []pathSegment
	// pathRegex is the compiled pathParam expression, and pathGroup the submatch that
	// holds the model (0 is the whole match, accepted only when nothing is rewritten).
	pathRegex *regexp.Regexp
	pathGroup int
}

// pathSegment is one step of a payload JSONPath: an object key, optionally followed
// by an array index ("messages[0]").
type pathSegment struct {
	key      string
	hasIndex bool
	index    int
}

// errAmbiguousModel is a model given more than once: two headers, two query values or
// two JSON keys. An upstream could read a different one than the policy did, so the
// request is rejected whatever onMissingModel says.
var errAmbiguousModel = errors.New("the model is given more than once")

// errMalformedModel is a model location the policy cannot read: undecodable escapes
// or an unparseable body.
var errMalformedModel = errors.New("the model location cannot be read")

var jsonPathSegment = regexp.MustCompile(`^([A-Za-z0-9_-]+)(?:\[(\d+)\])?$`)

func parseModelLocation(raw any, rewrites bool) (modelLocation, error) {
	if raw == nil {
		return modelLocation{}, fmt.Errorf("'requestModel' is required; the gateway controller injects it from the LLM provider template")
	}
	entry, ok := raw.(map[string]any)
	if !ok {
		return modelLocation{}, fmt.Errorf("'requestModel' must be an object")
	}
	location, ok := entry["location"].(string)
	if !ok {
		return modelLocation{}, fmt.Errorf("'requestModel.location' is required and must be a string")
	}
	identifier, err := nonBlankString(entry["identifier"], "requestModel.identifier")
	if err != nil {
		return modelLocation{}, err
	}

	loc := modelLocation{kind: locationKind(location), identifier: identifier}
	switch loc.kind {
	case locationPayload:
		segments, err := parseJSONPath(identifier)
		if err != nil {
			return modelLocation{}, fmt.Errorf("'requestModel.identifier' %w", err)
		}
		loc.segments = segments
	case locationHeader:
		if !validHeaderName(identifier) {
			return modelLocation{}, fmt.Errorf("'requestModel.identifier' must be a valid header name, got %q", identifier)
		}
		loc.identifier = strings.ToLower(identifier)
	case locationQuery:
		if hasControl(identifier) || strings.ContainsAny(identifier, "&=#?") {
			return modelLocation{}, fmt.Errorf("'requestModel.identifier' must be a query parameter name, got %q", identifier)
		}
	case locationPath:
		re, err := regexp.Compile(identifier)
		if err != nil {
			return modelLocation{}, fmt.Errorf("'requestModel.identifier' is not a valid RE2 expression: %w", err)
		}
		// Rewriting replaces exactly one capture group, so it can never touch the
		// prefix or suffix the expression also matches.
		if rewrites && re.NumSubexp() < 1 {
			return modelLocation{}, fmt.Errorf("'requestModel.identifier' must have a capture group for the model when 'fallback' is set")
		}
		loc.pathRegex = re
		if re.NumSubexp() > 0 {
			loc.pathGroup = 1
		}
	default:
		return modelLocation{}, fmt.Errorf("'requestModel.location' must be one of payload, header, queryParam or pathParam, got %q", location)
	}
	return loc, nil
}

// parseJSONPath accepts the dotted subset of JSONPath the SDK helpers implement
// ("$.model", "$.request.model", "$.items[0].model"), without wildcards and without
// the document root on its own, so a rewrite can always address the value.
func parseJSONPath(identifier string) ([]pathSegment, error) {
	path := strings.TrimPrefix(identifier, "$")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return nil, fmt.Errorf("must address a field, not the document root")
	}
	parts := strings.Split(path, ".")
	segments := make([]pathSegment, 0, len(parts))
	for _, part := range parts {
		match := jsonPathSegment.FindStringSubmatch(part)
		if match == nil {
			return nil, fmt.Errorf("must be a dotted JSONPath such as $.model, got %q", identifier)
		}
		seg := pathSegment{key: match[1]}
		// The SDK reads "key[0]" as an array index only when the key has no '-', and
		// as a literal key otherwise, so such a path could not be read or rewritten.
		if match[2] != "" && strings.Contains(match[1], "-") {
			return nil, fmt.Errorf("cannot index an array behind a key that contains '-', got %q", identifier)
		}
		if match[2] != "" {
			index, err := strconv.Atoi(match[2])
			if err != nil {
				return nil, fmt.Errorf("has an invalid array index in %q", identifier)
			}
			seg.hasIndex, seg.index = true, index
		}
		segments = append(segments, seg)
	}
	return segments, nil
}

func validHeaderName(name string) bool {
	if name == "" || strings.HasPrefix(name, ":") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),/:;<=>?@[\]{}`, c) >= 0 {
			return false
		}
	}
	return true
}

// ─── Header, query and path ──────────────────────────────────────────────────

// extractFromRequestLine reads the model from a header, the query string or the path.
// found is false when the location holds no model.
func (l modelLocation) extractFromRequestLine(headers *policy.Headers, rawPath string) (model string, found bool, err error) {
	switch l.kind {
	case locationHeader:
		values := headers.Get(l.identifier)
		if len(values) == 0 {
			return "", false, nil
		}
		// A comma is how HTTP joins repeated headers, and a proxy in front may have
		// joined two model headers into one value. No model name holds one.
		if len(values) > 1 || strings.Contains(values[0], ",") {
			return "", false, errAmbiguousModel
		}
		return values[0], strings.TrimSpace(values[0]) != "", nil
	case locationQuery:
		match, err := findQueryValue(rawPath, l.identifier)
		if err != nil {
			return "", false, err
		}
		if match.count == 0 {
			return "", false, nil
		}
		if match.count > 1 {
			return "", false, errAmbiguousModel
		}
		return match.decoded, strings.TrimSpace(match.decoded) != "", nil
	case locationPath:
		model, _, _, ok, err := l.matchPath(rawPath)
		if err != nil {
			return "", false, err
		}
		return model, ok && strings.TrimSpace(model) != "", nil
	default:
		return "", false, nil
	}
}

// rewriteRequestLine builds the modifications that replace the model in a header,
// the query string or the path. Only the bytes of the model change.
func (l modelLocation) rewriteRequestLine(rawPath, model string) (headers map[string]string, path *string, err error) {
	switch l.kind {
	case locationHeader:
		// The header is read back as one model only when it holds no comma, the
		// separator of repeated header values.
		if strings.Contains(model, ",") {
			return nil, nil, fmt.Errorf("the fallback model cannot be written into a header: it contains a comma")
		}
		return map[string]string{l.identifier: model}, nil, nil
	case locationQuery:
		match, err := findQueryValue(rawPath, l.identifier)
		if err != nil {
			return nil, nil, err
		}
		if match.count != 1 {
			return nil, nil, errAmbiguousModel
		}
		updated := rawPath[:match.start] + url.QueryEscape(model) + rawPath[match.end:]
		return nil, &updated, nil
	case locationPath:
		updated, err := l.rewritePath(rawPath, model)
		if err != nil {
			return nil, nil, err
		}
		return nil, &updated, nil
	default:
		return nil, nil, fmt.Errorf("location %q is not rewritten in the header phase", l.kind)
	}
}

// matchPath returns the model and the byte range it occupies in the raw (escaped)
// path, which excludes the query string.
//
// The expression runs on the path with every escape decoded except %2F and %25, so
// an encoded separator inside a model ID (an inference-profile ARN carries one) stays
// part of the match instead of ending it. The captured text is then decoded once,
// which is what the upstream reads. A kept escape right after the match means the
// expression could not read the whole model, so the request is rejected rather than
// checked against a prefix of it.
func (l modelLocation) matchPath(rawPath string) (model string, start, end int, found bool, err error) {
	if l.pathRegex == nil {
		return "", 0, 0, false, nil
	}
	pathOnly, _ := splitQuery(rawPath)
	decoded, offsets, err := decodePath(pathOnly)
	if err != nil {
		return "", 0, 0, false, err
	}
	// An upstream that reads the path after resolving dot segments, or after decoding
	// it in full, would see another model than the expression matched here.
	if hasDotSegment(decoded) {
		return "", 0, 0, false, errMalformedModel
	}
	full, err := url.PathUnescape(pathOnly)
	if err != nil || hasDotSegment(full) {
		return "", 0, 0, false, errMalformedModel
	}
	// Two matches are two models; an upstream may read the other one, also after
	// decoding encoded slashes.
	if len(l.pathRegex.FindAllStringIndex(decoded, 2)) > 1 || len(l.pathRegex.FindAllStringIndex(full, 2)) > 1 {
		return "", 0, 0, false, errAmbiguousModel
	}
	idx := l.pathRegex.FindStringSubmatchIndex(decoded)
	group := l.pathGroup * 2
	if len(idx) <= group+1 || idx[group] < 0 {
		// The expression matches only once encoded slashes are decoded: the model
		// is hidden from this policy but not from an upstream that decodes them.
		if full != decoded && l.pathRegex.MatchString(full) {
			return "", 0, 0, false, errMalformedModel
		}
		return "", 0, 0, false, nil
	}
	from, to := idx[group], idx[group+1]
	if touchesKeptEscape(decoded, from, to) {
		return "", 0, 0, false, errMalformedModel
	}
	model, err = url.PathUnescape(decoded[from:to])
	if err != nil {
		return "", 0, 0, false, errMalformedModel
	}
	return model, offsets[from], offsets[to], model != "", nil
}

// touchesKeptEscape reports whether the match [from, to) starts or ends inside a
// kept escape, or has one directly before or after it. Every '%' in a path from
// decodePath starts a kept escape, so in each of these cases the upstream would read
// a longer or different model than the expression matched.
func touchesKeptEscape(decoded string, from, to int) bool {
	for _, pos := range []int{from, to} {
		if (pos >= 1 && decoded[pos-1] == '%') || (pos >= 2 && decoded[pos-2] == '%') {
			return true
		}
	}
	return (from >= 3 && decoded[from-3] == '%') || (to < len(decoded) && decoded[to] == '%')
}

// hasDotSegment reports a "." or ".." path segment, which a server resolves before
// routing.
func hasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func (l modelLocation) rewritePath(rawPath, model string) (string, error) {
	if l.pathGroup == 0 {
		return "", fmt.Errorf("the path expression has no capture group to rewrite")
	}
	// PathEscape keeps dots, so these would become dot segments the upstream resolves.
	if model == "." || model == ".." {
		return "", fmt.Errorf("the model %q cannot be written as a path segment", model)
	}
	_, start, end, found, err := l.matchPath(rawPath)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("the path expression no longer matches the request path")
	}
	return rawPath[:start] + url.PathEscape(model) + rawPath[end:], nil
}

// decodePath percent-decodes a path except for %2F and %25, which stay escaped so a
// decoded slash or percent sign can never be mistaken for a separator or a new
// escape. It also returns, for every byte boundary of the result, the matching
// boundary in the raw string, so a rewrite replaces only the model's raw bytes.
func decodePath(raw string) (string, []int, error) {
	var decoded strings.Builder
	offsets := make([]int, 0, len(raw)+1)
	for i := 0; i < len(raw); {
		if raw[i] == '%' {
			if i+2 >= len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return "", nil, errMalformedModel
			}
			c := unhex(raw[i+1])<<4 | unhex(raw[i+2])
			if c == '/' || c == '%' {
				for k := 0; k < 3; k++ {
					offsets = append(offsets, i+k)
					decoded.WriteByte(raw[i+k])
				}
				i += 3
				continue
			}
			offsets = append(offsets, i)
			decoded.WriteByte(c)
			i += 3
			continue
		}
		offsets = append(offsets, i)
		decoded.WriteByte(raw[i])
		i++
	}
	offsets = append(offsets, len(raw))
	return decoded.String(), offsets, nil
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func splitQuery(path string) (pathOnly, query string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i], path[i+1:]
	}
	return path, ""
}

type queryValue struct {
	decoded    string
	start, end int
	count      int
}

// findQueryValue finds every occurrence of key in the raw query string, decoding keys
// and values once. It keeps the byte range of the first value, so a rewrite can
// replace it without reordering parameters or re-encoding the others; an upstream
// may sign the raw query.
func findQueryValue(rawPath, key string) (queryValue, error) {
	q := strings.IndexByte(rawPath, '?')
	if q < 0 {
		return queryValue{}, nil
	}
	return scanQuery(rawPath, q+1, key)
}

// scanQuery scans the &-separated key=value pairs of raw from offset start. Byte
// ranges in the result are offsets into raw.
func scanQuery(raw string, start int, key string) (queryValue, error) {
	var result queryValue
	for cursor := start; cursor <= len(raw); {
		end := strings.IndexByte(raw[cursor:], '&')
		if end < 0 {
			end = len(raw)
		} else {
			end += cursor
		}
		segment := raw[cursor:end]
		rawKey, valueOffset := segment, len(segment)
		if eq := strings.IndexByte(segment, '='); eq >= 0 {
			rawKey, valueOffset = segment[:eq], eq+1
		}
		decodedKey, err := url.QueryUnescape(rawKey)
		if err != nil {
			return queryValue{}, errMalformedModel
		}
		if decodedKey == key {
			valueStart := cursor + valueOffset
			value, err := url.QueryUnescape(raw[valueStart:end])
			if err != nil {
				return queryValue{}, errMalformedModel
			}
			result.count++
			if result.count == 1 {
				result.decoded, result.start, result.end = value, valueStart, end
			}
		}
		if end == len(raw) {
			break
		}
		cursor = end + 1
	}
	// Parsers differ on the details: some split on ';' too, some compare keys ignoring
	// case or surrounding spaces, some read "model[]" as "model". If any of them would
	// find a model this scan did not, the model is ambiguous.
	if lenientKeyCount(raw[start:], key) != result.count {
		return queryValue{}, errAmbiguousModel
	}
	return result, nil
}

// lenientKeyCount counts the pairs of a query string or form body whose key any common
// parser could read as key.
func lenientKeyCount(raw, key string) int {
	count := 0
	for _, segment := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		name, _, _ := strings.Cut(segment, "=")
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		// The whole key is compared first, ignoring case and surrounding spaces, so a
		// configured key that holds a '[' still matches its own variants.
		if strings.EqualFold(strings.TrimSpace(name), key) {
			count++
			continue
		}
		if open := strings.IndexByte(name, '['); open >= 0 {
			name = name[:open]
		}
		if strings.EqualFold(strings.TrimSpace(name), key) {
			count++
		}
	}
	return count
}

// ─── Form bodies ─────────────────────────────────────────────────────────────

type formKind int

const (
	formNone formKind = iota
	formURLEncoded
	formMultipart
)

// requestForm reports whether the body is a form, which is how endpoints such as
// /audio/transcriptions and /images/edits carry the model, and returns the multipart
// boundary. A form content type that cannot be parsed is errMalformedModel.
func requestForm(headers *policy.Headers) (formKind, string, error) {
	values := headers.Get("content-type")
	if len(values) != 1 {
		return formNone, "", nil
	}
	lower := strings.ToLower(strings.TrimSpace(values[0]))
	isURLEncoded := strings.HasPrefix(lower, "application/x-www-form-urlencoded")
	isMultipart := strings.HasPrefix(lower, "multipart/")
	if !isURLEncoded && !isMultipart {
		return formNone, "", nil
	}
	mediaType, params, err := mime.ParseMediaType(values[0])
	if err != nil {
		return formNone, "", errMalformedModel
	}
	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return formURLEncoded, "", nil
	case strings.HasPrefix(mediaType, "multipart/"):
		if params["boundary"] == "" {
			return formNone, "", errMalformedModel
		}
		return formMultipart, params["boundary"], nil
	}
	return formNone, "", nil
}

// formKey is the form field that carries the model: the JSONPath's single top-level
// key ("$.model" -> "model"). A nested path has no form equivalent.
func (l modelLocation) formKey() string {
	if len(l.segments) != 1 || l.segments[0].hasIndex {
		return ""
	}
	return l.segments[0].key
}

// extractFromForm reads the model field of a form body. A field given more than once
// is errAmbiguousModel; a body that cannot be parsed is errMalformedModel.
func extractFromForm(kind formKind, boundary string, body []byte, key string) (string, bool, error) {
	switch kind {
	case formURLEncoded:
		match, err := scanQuery(string(body), 0, key)
		if err != nil {
			return "", false, err
		}
		if match.count > 1 {
			return "", false, errAmbiguousModel
		}
		return match.decoded, match.count == 1 && strings.TrimSpace(match.decoded) != "", nil
	case formMultipart:
		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		var model string
		count, parts := 0, 0
		for {
			// Raw parts: the value is read as sent, as an upstream reads it.
			part, err := reader.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", false, errMalformedModel
			}
			parts++
			name, err := partName(part)
			if err != nil {
				return "", false, err
			}
			if name != key {
				// Form binders such as ASP.NET's match field names ignoring case.
				if strings.EqualFold(strings.TrimSpace(name), key) {
					return "", false, errAmbiguousModel
				}
				continue
			}
			if len(part.Header.Values("Content-Transfer-Encoding")) > 0 {
				return "", false, errMalformedModel
			}
			count++
			if count > 1 {
				return "", false, errAmbiguousModel
			}
			// One byte over the limit is enough for evaluate to reject it as too long.
			value, err := io.ReadAll(io.LimitReader(part, maxModelLength+1))
			if err != nil || len(value) > maxModelLength {
				// A truncated value must not be trimmed and checked: the upstream reads
				// the whole field.
				return "", false, errMalformedModel
			}
			model = string(value)
		}
		// A form with no part at all is not a form any client sends.
		if parts == 0 {
			return "", false, errMalformedModel
		}
		return model, count == 1 && strings.TrimSpace(model) != "", nil
	}
	return "", false, nil
}

// rfc2231Name matches an extended name parameter (name*=charset”value).
var rfc2231Name = regexp.MustCompile(`(?i)(^|;)\s*name\*`)

// partName returns the form field name of a multipart part. Parsers disagree on a
// part with more than one Content-Disposition header, a repeated or malformed
// parameter, or an RFC 2231 encoded name: one may see "model" where another sees
// nothing. Any of these is errMalformedModel, so the policy and the upstream always
// agree on which part carries the model.
func partName(part *multipart.Part) (string, error) {
	values := part.Header.Values("Content-Disposition")
	if len(values) == 0 {
		return "", nil
	}
	if len(values) > 1 || rfc2231Name.MatchString(values[0]) {
		return "", errMalformedModel
	}
	disposition, params, err := mime.ParseMediaType(values[0])
	if err != nil || disposition != "form-data" {
		return "", errMalformedModel
	}
	return params["name"], nil
}

// rewriteForm replaces the model field of a form body. A URL-encoded body changes
// only the value's bytes; a multipart body is written again with the same boundary,
// every other part copied byte for byte.
func rewriteForm(kind formKind, boundary string, body []byte, key, model string) ([]byte, error) {
	switch kind {
	case formURLEncoded:
		raw := string(body)
		match, err := scanQuery(raw, 0, key)
		if err != nil {
			return nil, err
		}
		if match.count != 1 {
			return nil, errAmbiguousModel
		}
		return []byte(raw[:match.start] + url.QueryEscape(model) + raw[match.end:]), nil
	case formMultipart:
		// A value holding the boundary would read as a delimiter, ending the model
		// part or the whole form early. A capture fallback lets the client choose it.
		if strings.Contains(model, "--"+boundary) {
			return nil, fmt.Errorf("the model contains the multipart boundary")
		}
		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		if err := writer.SetBoundary(boundary); err != nil {
			return nil, err
		}
		for {
			part, err := reader.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, errMalformedModel
			}
			header := textproto.MIMEHeader{}
			for name, values := range part.Header {
				header[name] = append([]string(nil), values...)
			}
			name, err := partName(part)
			if err != nil {
				return nil, err
			}
			isModel := name == key
			out, err := writer.CreatePart(header)
			if err != nil {
				return nil, err
			}
			if isModel {
				_, err = io.WriteString(out, model)
			} else {
				_, err = io.Copy(out, part)
			}
			if err != nil {
				return nil, errMalformedModel
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("the body is not a form")
}

// ─── Payload ─────────────────────────────────────────────────────────────────

// decodePayload decodes a JSON object request body strictly: numbers keep their
// exact text, trailing data is an error, and a key repeated along the model's
// JSONPath, exactly or differing only in case, is errAmbiguousModel, because Go
// keeps the last value while an upstream may read the first.
func (l modelLocation) decodePayload(body []byte) (map[string]any, error) {
	if err := checkDuplicateKeysOnPath(body, l.segments); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil || payload == nil {
		return nil, errMalformedModel
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errMalformedModel
	}
	return payload, nil
}

// extractFromPayload returns the model at the JSONPath. A value that is absent, not
// a string or blank is not found.
func (l modelLocation) extractFromPayload(payload map[string]any) (string, bool) {
	value, err := utils.ExtractValueFromJsonpath(payload, l.identifier)
	if err != nil {
		return "", false
	}
	model, ok := value.(string)
	return model, ok && strings.TrimSpace(model) != ""
}

// hasUnusableModel reports whether the JSONPath holds a value that is neither a
// string nor null, such as a number, an array or an object.
func (l modelLocation) hasUnusableModel(payload map[string]any) bool {
	value, err := utils.ExtractValueFromJsonpath(payload, l.identifier)
	if err != nil || value == nil {
		return false
	}
	_, isString := value.(string)
	return !isString
}

// rewritePayload sets the model at the JSONPath and re-encodes the body without
// HTML escaping, so text the client sent is not rewritten as < and the like.
func (l modelLocation) rewritePayload(payload map[string]any, model string) ([]byte, error) {
	if err := utils.SetValueAtJSONPath(payload, l.identifier, model); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// errRepeatedMember is a body with a repeated object member off the model's path. A
// fallback rewrite decodes the body into a map, which keeps only one of the values.
var errRepeatedMember = errors.New("the body repeats an object member, which a rewrite cannot preserve")

// checkNoRepeatedMembers fails when any object in the body has the same key twice.
func checkNoRepeatedMembers(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	// keys holds the members seen in each open object; nil marks an open array.
	var keys []map[string]struct{}
	expectKey := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errMalformedModel
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				keys = append(keys, map[string]struct{}{})
			case '[':
				keys = append(keys, nil)
			default:
				keys = keys[:len(keys)-1]
			}
		case string:
			if expectKey {
				top := keys[len(keys)-1]
				if _, seen := top[t]; seen {
					return errRepeatedMember
				}
				top[t] = struct{}{}
			}
		}
		// The next token is a key when the innermost open value is an object and the
		// token just read was not itself a key.
		inObject := len(keys) > 0 && keys[len(keys)-1] != nil
		if _, isDelim := tok.(json.Delim); isDelim {
			expectKey = inObject && (tok == json.Delim('{') || tok == json.Delim('}') || tok == json.Delim(']'))
		} else {
			expectKey = inObject && !expectKey
		}
	}
}

// checkDuplicateKeysOnPath walks the JSON tokens and fails when an object on the
// model's JSONPath has the same key twice. Values off the path are skipped whole.
func checkDuplicateKeysOnPath(body []byte, segments []pathSegment) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return walkValue(dec, segments)
}

// walkValue consumes one JSON value. remaining is the part of the model's path that
// starts at this value; nil means the value is off the path.
func walkValue(dec *json.Decoder, remaining []pathSegment) error {
	tok, err := dec.Token()
	if err != nil {
		return errMalformedModel
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		var seen map[string]struct{}
		foldMatches := 0
		// Only an object-key step applies to an object; an index step expects an array.
		if len(remaining) > 0 && remaining[0].key != "" {
			seen = map[string]struct{}{}
		}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errMalformedModel
			}
			key, _ := keyTok.(string)
			var child []pathSegment
			if seen != nil {
				if _, dup := seen[key]; dup {
					return errAmbiguousModel
				}
				seen[key] = struct{}{}
				// Go decodes JSON into a struct ignoring key case, and the last match
				// wins, so a later policy or upstream could read "MODEL" where this
				// policy read "model". Two keys on the path that differ only in case
				// are ambiguous.
				if strings.EqualFold(key, remaining[0].key) {
					foldMatches++
					if foldMatches > 1 {
						return errAmbiguousModel
					}
				}
				if key == remaining[0].key {
					child = descend(remaining)
				}
			}
			if child == nil {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return errMalformedModel
				}
				continue
			}
			if err := walkValue(dec, child); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			var child []pathSegment
			if len(remaining) > 0 && remaining[0].key == "" && remaining[0].index == i {
				child = remaining[1:]
				if len(child) == 0 {
					child = nil
				}
			}
			if child == nil {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return errMalformedModel
				}
				continue
			}
			if err := walkValue(dec, child); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return errMalformedModel
	}
	return nil
}

// descend returns the path below the object key remaining[0].key: an index step when
// the segment has one, the next segment otherwise, or nil at the end of the path.
func descend(remaining []pathSegment) []pathSegment {
	if remaining[0].hasIndex {
		step := []pathSegment{{index: remaining[0].index}}
		return append(step, remaining[1:]...)
	}
	if len(remaining) == 1 {
		return nil
	}
	return remaining[1:]
}
