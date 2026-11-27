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

package mistralmoderation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// extractText returns the text to moderate from a request or response body. An empty
// jsonPath moderates the whole body as text.
func extractText(payload []byte, jsonPath string) (string, error) {
	if jsonPath == "" {
		return string(payload), nil
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return "", fmt.Errorf("body is not a JSON object: %w", err)
	}
	path := normalizeWildcards(jsonPath)
	value, err := utils.ExtractValueFromJsonpath(jsonData, path)
	if err != nil {
		return "", err
	}
	if strings.Contains(path, "*") {
		return textFromMatches(value)
	}
	return textFromValue(value)
}

// extractReply returns the reply text of a response. A response to a "stream": true request
// arrives buffered as the complete server-sent event stream rather than one JSON document, so
// its reply is reassembled from each event's streamingJsonPath fragment. An empty jsonPath
// moderates the whole body as text, an event stream included.
func extractReply(payload []byte, params phaseParams) (string, error) {
	if params.JSONPath != "" && isSSE(payload) {
		return extractSSEText(payload, params.StreamingJSONPath)
	}
	return extractText(payload, params.JSONPath)
}

// isSSE reports whether payload looks like a server-sent event stream.
func isSSE(payload []byte) bool {
	trimmed := bytes.TrimLeft(payload, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("data:")) || bytes.HasPrefix(trimmed, []byte("event:")) ||
		bytes.HasPrefix(trimmed, []byte(":"))
}

// extractSSEText concatenates the streamingJsonPath fragment of every data event. Events
// where the path does not resolve (the opening role delta, the finishing delta, a usage
// frame) contribute nothing, and a resolved null (a tool-call-only reply) counts as resolved
// but adds no text. If events were parsed but the path resolved in none of them, the stream is
// not in the shape the path expects (for example another provider's format), so it is an
// extraction error rather than a reply with nothing to moderate.
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
	if parsed == 0 {
		return "", fmt.Errorf("event stream has no JSON data events")
	}
	if resolved == 0 {
		return "", fmt.Errorf("streamingJsonPath %q matched none of the %d stream events", streamingJSONPath, parsed)
	}
	return sb.String(), nil
}

// normalizeWildcards rewrites "[*]" as ".*", the form the SDK's JSONPath helper understands,
// so "$.messages[*].content" and "$.messages.*.content" select the same messages.
func normalizeWildcards(path string) string {
	return strings.ReplaceAll(path, "[*]", ".*")
}

// textFromMatches joins the text of every value a wildcard path selected, one per message, in
// order, so a whole conversation is moderated in one call.
func textFromMatches(value interface{}) (string, error) {
	matches, ok := value.([]interface{})
	if !ok {
		return textFromValue(value)
	}
	// No match at all means the path after the wildcard does not fit the body (for example a
	// misspelled key), which must not pass as nothing to moderate.
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
	return strings.Join(texts, "\n\n"), nil
}

// textFromValue converts a JSONPath result to text. A null value (an assistant message with
// only tool calls) has nothing to moderate. An array is read as content parts (OpenAI and
// Anthropic content blocks, Gemini parts, Bedrock Converse content blocks): the text of every
// part is joined and parts without text (images, audio, tool calls) are skipped.
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
			// A part without text (an image, a Gemini functionCall, a Bedrock toolUse) is
			// skipped. An object shaped like a message means the path points at the messages
			// array instead of one message's content, which must not moderate as empty.
			_, hasRole := part["role"]
			_, hasContent := part["content"]
			if hasRole || hasContent {
				return "", fmt.Errorf("array element %d at JSONPath is a message, not a content part", i)
			}
		default:
			return "", fmt.Errorf("array element %d at JSONPath is not a content part", i)
		}
	}
	return strings.Join(texts, "\n"), nil
}

// extractConversation reads the chat messages at messagesPath and converts them to the
// messages /v1/chat/moderations accepts: a supported role and plain-text content. Content
// parts become their joined text. A message whose role Mistral does not accept, or whose
// content has no text (an assistant turn with only tool calls), is left out. lastHasText
// reports whether the conversation's final message, the one Mistral classifies, is kept: when
// it is not, an earlier message would be classified in its place.
func extractConversation(payload []byte, messagesPath string) (messages []chatMessage, lastHasText bool, err error) {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return nil, false, fmt.Errorf("body is not a JSON object: %w", err)
	}
	value, err := utils.ExtractValueFromJsonpath(jsonData, messagesPath)
	if err != nil {
		return nil, false, err
	}
	raw, ok := value.([]interface{})
	if !ok {
		return nil, false, fmt.Errorf("value at messagesPath is not an array of messages")
	}
	if len(raw) == 0 {
		return nil, false, fmt.Errorf("messages array at messagesPath is empty")
	}

	sawContent := false
	for i, item := range raw {
		msg, ok := item.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("message %d at messagesPath is not an object", i)
		}
		roleRaw, _ := msg["role"].(string)
		// OpenAI, Anthropic, Bedrock Converse and Mistral carry a message's text in content;
		// Gemini carries it in parts.
		content, hasContent := msg["content"]
		if !hasContent {
			content, hasContent = msg["parts"]
		}
		sawContent = sawContent || hasContent
		text, err := textFromValue(content)
		if err != nil {
			return nil, false, fmt.Errorf("message %d: %w", i, err)
		}
		hasText := strings.TrimSpace(text) != ""
		role, supported := chatRole(roleRaw)
		if i == len(raw)-1 {
			lastHasText = hasText && supported
		}
		if !supported || !hasText {
			continue
		}
		messages = append(messages, chatMessage{Role: role, Content: text})
	}
	// No message with a content (or parts) member means messagesPath points at an array of
	// some other shape. That must fail the check rather than pass as nothing to classify.
	if !sawContent {
		return nil, false, fmt.Errorf("no message at messagesPath has a content or parts member")
	}
	return messages, lastHasText, nil
}

// chatRole maps a provider's role onto one Mistral's chat moderation accepts. developer is
// OpenAI's newer name for system, function its older name for tool, and model Gemini's name
// for assistant.
func chatRole(role string) (string, bool) {
	switch role {
	case "system", "user", "assistant", "tool":
		return role, true
	case "developer":
		return "system", true
	case "function":
		return "tool", true
	case "model":
		return "assistant", true
	default:
		return "", false
	}
}

// hasClassifiableTurn reports whether the conversation has a message other than system ones;
// Mistral rejects a conversation of system messages alone.
func hasClassifiableTurn(messages []chatMessage) bool {
	for _, m := range messages {
		if m.Role != "system" {
			return true
		}
	}
	return false
}
