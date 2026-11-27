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

package mistralshieldstralcontentsafety

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// This file extracts the text to screen from a request or response body. It
// follows typesafe-jev-content-safety's extraction exactly, so both policies
// read the same JSONPath configuration the same way.

// extractText returns the text to screen from a request or response body.
//
// A buffered response to a "stream": true request arrives as the complete
// SSE event stream rather than a single JSON document, so it is reassembled
// from each event's streamingJsonPath fragment before screening.
func extractText(payload []byte, params phaseParams, isResponse bool) (string, error) {
	if isResponse && isSSE(payload) {
		return extractSSEText(payload, params.StreamingJSONPath)
	}
	if params.JSONPath == "" {
		return string(payload), nil
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return "", err
	}
	value, err := utils.ExtractValueFromJsonpath(jsonData, params.JSONPath)
	if err != nil {
		return "", err
	}
	if strings.Contains(params.JSONPath, "*") {
		return textFromMatches(value)
	}
	return textFromValue(value)
}

// normalizeWildcards rewrites "[*]" as ".*", the form the SDK's JSONPath
// helper understands, so "$.messages[*].content" and "$.messages.*.content"
// select the same messages.
func normalizeWildcards(path string) string {
	return strings.ReplaceAll(path, "[*]", ".*")
}

// textFromMatches joins the text of every value a wildcard path selected, one
// per message, in order. Each value is read like a single message's content,
// so a null value (a tool-call-only assistant message) contributes nothing and
// a content-part array contributes its text parts. The newest messages are kept
// whole and the oldest dropped once the text passes maxScreenedTextBytes, so a
// long conversation stays within Shieldstral's context window; the newest message is
// always kept, even when it alone passes the limit.
func textFromMatches(value interface{}) (string, error) {
	matches, ok := value.([]interface{})
	if !ok {
		return textFromValue(value)
	}
	// No match at all means the path after the wildcard doesn't fit the body (for
	// example a misspelled key), which must not pass as nothing to screen.
	if len(matches) == 0 {
		return "", fmt.Errorf("wildcard JSONPath matched no values")
	}
	texts := make([]string, 0, len(matches))
	for i, match := range matches {
		text, err := textFromValue(match)
		if err != nil {
			return "", fmt.Errorf("match %d: %w", i, err)
		}
		if strings.TrimSpace(text) != "" {
			texts = append(texts, text)
		}
	}

	const separator = "\n\n"
	start, size := len(texts), 0
	for i := len(texts) - 1; i >= 0; i-- {
		next := len(texts[i])
		if i < len(texts)-1 {
			next += len(separator)
		}
		if start < len(texts) && size+next > maxScreenedTextBytes {
			break
		}
		start, size = i, size+next
	}
	if start > 0 {
		slog.Debug("MistralShieldstralContentSafety: Screened text over the size limit, dropping the oldest messages",
			"dropped", start, "kept", len(texts)-start, "limitBytes", maxScreenedTextBytes)
	}
	return strings.Join(texts[start:], separator), nil
}

// textFromValue converts a JSONPath result to screenable text. A null value
// (e.g. a tool-call-only reply with "content": null) has nothing to screen.
// An array is treated as OpenAI-style multimodal content parts: text parts
// are joined and non-text parts (images, audio) are skipped, since they
// can't be screened as text and would only consume Shieldstral's context window.
func textFromValue(value interface{}) (string, error) {
	switch v := value.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case []interface{}:
		return textFromContentParts(v)
	default:
		return "", fmt.Errorf("value at JSONPath is not a string, number, or content-part array")
	}
}

func textFromContentParts(parts []interface{}) (string, error) {
	var texts []string
	for i, item := range parts {
		switch part := item.(type) {
		case string:
			texts = append(texts, part)
		case map[string]interface{}:
			if text, ok := part["text"].(string); ok {
				texts = append(texts, text)
				continue
			}
			// A typed non-text part (image_url, input_audio, ...) is skipped.
			// An untyped object means the JSONPath points at something other
			// than content parts (e.g. the whole messages array), which must
			// not silently screen as empty.
			if _, typed := part["type"].(string); !typed {
				return "", fmt.Errorf("array element %d at JSONPath is not a content part", i)
			}
		default:
			return "", fmt.Errorf("array element %d at JSONPath is not a content part", i)
		}
	}
	return strings.Join(texts, "\n"), nil
}

// isSSE reports whether payload looks like a server-sent event stream.
func isSSE(payload []byte) bool {
	trimmed := bytes.TrimLeft(payload, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("data:")) || bytes.HasPrefix(trimmed, []byte("event:"))
}

// extractSSEText concatenates the streamingJsonPath fragment of every SSE
// data event. Events where the path doesn't resolve (role-only deltas, finish
// events, usage events) contribute nothing, and a resolved null (the content
// of a tool-call-only reply) counts as resolved but adds no text. If events were
// parsed but the path resolved in none of them, the stream isn't in the shape
// the path expects (for example a different provider's format), so it is an
// extraction error rather than a reply with nothing to screen.
func extractSSEText(payload []byte, streamingJSONPath string) (string, error) {
	var sb strings.Builder
	parsed, resolved := 0, 0
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		parsed++
		value, err := utils.ExtractValueFromJsonpath(event, streamingJSONPath)
		if err != nil {
			continue
		}
		resolved++
		if text, ok := value.(string); ok {
			sb.WriteString(text)
		}
	}
	if parsed > 0 && resolved == 0 {
		return "", fmt.Errorf("streamingJsonPath %q matched none of the %d stream events", streamingJSONPath, parsed)
	}
	return sb.String(), nil
}
