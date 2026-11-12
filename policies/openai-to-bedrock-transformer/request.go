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

package openaitobedrock

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// translateRequest converts an OpenAI Chat Completions payload into a Bedrock
// Converse request body. The model lives in the URL path, not the body, so it
// is deliberately omitted here. It returns an error, meant for the client as a
// 400, when the payload carries content Converse cannot represent.
func translateRequest(payload map[string]interface{}) (policy.UpstreamRequestModifications, error) {
	converse := map[string]interface{}{}

	if messages, ok := payload["messages"].([]interface{}); ok {
		system, converseMessages, err := convertMessages(messages)
		if err != nil {
			return policy.UpstreamRequestModifications{}, err
		}
		if len(system) > 0 {
			converse["system"] = system
		}
		if len(converseMessages) > 0 {
			converse["messages"] = converseMessages
		}
	}

	if inference := buildInferenceConfig(payload); len(inference) > 0 {
		converse["inferenceConfig"] = inference
	}

	if toolConfig := buildToolConfig(payload); toolConfig != nil {
		converse["toolConfig"] = toolConfig
	}

	newBody, err := json.Marshal(converse)
	if err != nil {
		return policy.UpstreamRequestModifications{
			Body: []byte(fmt.Sprintf(`{"error":{"message":"failed to marshal Bedrock body: %s"}}`, err.Error())),
		}, nil
	}

	return policy.UpstreamRequestModifications{
		Body:            newBody,
		HeadersToSet:    map[string]string{"content-type": "application/json"},
		HeadersToRemove: []string{"content-length"},
	}, nil
}

// convertMessages splits OpenAI messages into Converse system blocks and the
// role/content message list. Consecutive tool messages collapse into a single
// user message of toolResult blocks, matching how Converse groups tool output.
func convertMessages(messages []interface{}) ([]map[string]interface{}, []map[string]interface{}, error) {
	var system []map[string]interface{}
	var converseMessages []map[string]interface{}
	names := documentNames{}

	for i := 0; i < len(messages); i++ {
		message, ok := messages[i].(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := message["role"].(string)

		switch role {
		case "system", "developer":
			if text := extractText(message["content"]); text != "" {
				system = append(system, map[string]interface{}{"text": text})
			}
		case "user":
			content, err := convertUserContent(message["content"], names)
			if err != nil {
				return nil, nil, err
			}
			converseMessages = append(converseMessages, map[string]interface{}{
				"role":    "user",
				"content": content,
			})
		case "assistant":
			converseMessages = append(converseMessages, map[string]interface{}{
				"role":    "assistant",
				"content": convertAssistantContent(message),
			})
		case "tool":
			var toolResults []interface{}
			for i < len(messages) {
				toolMessage, ok := messages[i].(map[string]interface{})
				if !ok {
					break
				}
				if r, _ := toolMessage["role"].(string); r != "tool" {
					break
				}
				toolCallID, _ := toolMessage["tool_call_id"].(string)
				toolResults = append(toolResults, map[string]interface{}{
					"toolResult": map[string]interface{}{
						"toolUseId": toolCallID,
						"content":   []interface{}{map[string]interface{}{"text": extractText(toolMessage["content"])}},
					},
				})
				i++
			}
			i-- // outer loop will re-increment
			converseMessages = append(converseMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})
		}
	}

	return system, converseMessages, nil
}

func extractText(content interface{}) string {
	switch typed := content.(type) {
	case string:
		return typed
	case []interface{}:
		var parts []string
		for _, part := range typed {
			block, ok := part.(map[string]interface{})
			if !ok || block["type"] != "text" {
				continue
			}
			if text, ok := block["text"].(string); ok {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "")
	}
	return ""
}

func convertUserContent(content interface{}, names documentNames) ([]interface{}, error) {
	switch typed := content.(type) {
	case string:
		return []interface{}{map[string]interface{}{"text": typed}}, nil
	case []interface{}:
		var blocks []interface{}
		hasDocument, hasText := false, false
		for _, part := range typed {
			block, ok := part.(map[string]interface{})
			if !ok {
				continue
			}
			switch block["type"] {
			case "text":
				if text, ok := block["text"].(string); ok {
					blocks = append(blocks, map[string]interface{}{"text": text})
					hasText = hasText || strings.TrimSpace(text) != ""
				}
			case "image_url":
				if image := convertImage(block); image != nil {
					blocks = append(blocks, image)
				}
			case "file":
				document, err := convertDocument(block, names)
				if err != nil {
					return nil, err
				}
				blocks = append(blocks, document)
				hasDocument = true
			}
		}
		// Converse rejects a message that carries a document without text.
		if hasDocument && !hasText {
			return nil, errors.New("a user message with a file must also include a non-empty text part; Bedrock requires text alongside documents")
		}
		if len(blocks) > 0 {
			return blocks, nil
		}
	}
	return []interface{}{map[string]interface{}{"text": ""}}, nil
}

func convertAssistantContent(message map[string]interface{}) []interface{} {
	var blocks []interface{}
	if text := extractText(message["content"]); text != "" {
		blocks = append(blocks, map[string]interface{}{"text": text})
	}

	toolCalls, _ := message["tool_calls"].([]interface{})
	for _, raw := range toolCalls {
		toolCall, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := toolCall["id"].(string)
		fn, _ := toolCall["function"].(map[string]interface{})
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		argsString, _ := fn["arguments"].(string)

		var input interface{} = map[string]interface{}{}
		if argsString != "" {
			if err := json.Unmarshal([]byte(argsString), &input); err != nil {
				input = map[string]interface{}{}
			}
		}
		blocks = append(blocks, map[string]interface{}{
			"toolUse": map[string]interface{}{
				"toolUseId": id,
				"name":      name,
				"input":     input,
			},
		})
	}

	if len(blocks) == 0 {
		blocks = append(blocks, map[string]interface{}{"text": ""})
	}
	return blocks
}

// convertImage maps an OpenAI image_url block to a Converse image block. Only
// base64 data URIs are supported; remote URLs are dropped since the Converse
// image source expects inline bytes.
func convertImage(block map[string]interface{}) map[string]interface{} {
	imageObject, ok := block["image_url"].(map[string]interface{})
	if !ok {
		return nil
	}
	url, ok := imageObject["url"].(string)
	if !ok || !strings.HasPrefix(url, "data:") {
		return nil
	}
	parts := strings.SplitN(url, ",", 2)
	if len(parts) != 2 {
		return nil
	}
	meta := strings.TrimPrefix(parts[0], "data:")
	mediaType := strings.SplitN(meta, ";", 2)[0]
	format := strings.TrimPrefix(mediaType, "image/")
	if format == "" {
		return nil
	}
	return map[string]interface{}{
		"image": map[string]interface{}{
			"format": format,
			"source": map[string]interface{}{"bytes": parts[1]},
		},
	}
}

// documentFormats maps media types to the formats a Converse document block
// accepts.
var documentFormats = map[string]string{
	"application/pdf":    "pdf",
	"text/csv":           "csv",
	"application/msword": "doc",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
	"application/vnd.ms-excel": "xls",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
	"text/html":       "html",
	"text/plain":      "txt",
	"text/markdown":   "md",
	"text/x-markdown": "md",
}

// documentExtensions are the file extensions accepted when the media type
// does not name a supported format, e.g. application/octet-stream.
var documentExtensions = map[string]string{
	"pdf": "pdf", "csv": "csv", "doc": "doc", "docx": "docx", "xls": "xls",
	"xlsx": "xlsx", "html": "html", "htm": "html", "txt": "txt", "md": "md",
	"markdown": "md",
}

// documentNameDisallowed matches what a Converse document name may not
// contain; it allows only alphanumerics, single spaces, hyphens, parentheses
// and square brackets.
var documentNameDisallowed = regexp.MustCompile(`[^A-Za-z0-9\-()\[\] ]+`)

// maxDocumentNameLength is the longest name Converse accepts for a document.
const maxDocumentNameLength = 200

// documentNames tracks the document names already used in a request, since
// Converse rejects a request whose documents share a name.
type documentNames map[string]bool

// unique returns name, or name with a "-N" suffix when it is already taken,
// truncating the base so the result stays within maxDocumentNameLength.
func (n documentNames) unique(name string) string {
	candidate := truncateDocumentName(name, maxDocumentNameLength)
	for i := 2; n[candidate]; i++ {
		suffix := fmt.Sprintf("-%d", i)
		candidate = truncateDocumentName(name, maxDocumentNameLength-len(suffix)) + suffix
	}
	n[candidate] = true
	return candidate
}

// truncateDocumentName cuts a sanitised (ASCII-only) name to at most limit
// characters without leaving a trailing space, falling back to "document".
func truncateDocumentName(name string, limit int) string {
	if len(name) > limit {
		name = strings.TrimRight(name[:limit], " ")
	}
	if name == "" {
		return "document"
	}
	return name
}

// convertDocument maps an OpenAI file block to a Converse document block. The
// file must be sent inline as a base64 data URI in file_data; a file_id cannot
// be resolved because Bedrock has no access to OpenAI-hosted files.
func convertDocument(block map[string]interface{}, names documentNames) (map[string]interface{}, error) {
	file, ok := block["file"].(map[string]interface{})
	if !ok {
		return nil, errors.New("file content part is missing its file object")
	}
	filename, _ := file["filename"].(string)
	data, _ := file["file_data"].(string)
	if data == "" {
		if fileID, _ := file["file_id"].(string); fileID != "" {
			return nil, errors.New("file_id is not supported for Bedrock; send the file inline as a base64 data URI in file_data")
		}
		return nil, errors.New("file content part requires file_data")
	}

	if !strings.HasPrefix(data, "data:") {
		return nil, errors.New("file_data must be a base64 data URI (data:<media type>;base64,<data>)")
	}
	parts := strings.SplitN(strings.TrimPrefix(data, "data:"), ",", 2)
	if len(parts) != 2 {
		return nil, errors.New("file_data must be a base64 data URI (data:<media type>;base64,<data>)")
	}
	meta := strings.Split(parts[0], ";")
	if !strings.EqualFold(strings.TrimSpace(meta[len(meta)-1]), "base64") {
		return nil, errors.New("file_data must be base64 encoded (data:<media type>;base64,<data>)")
	}
	if err := validateBase64(parts[1]); err != nil {
		return nil, err
	}
	mediaType := strings.ToLower(strings.TrimSpace(meta[0]))

	format, ok := documentFormats[mediaType]
	if !ok {
		extension := strings.ToLower(strings.TrimPrefix(path.Ext(filename), "."))
		if format, ok = documentExtensions[extension]; !ok {
			return nil, fmt.Errorf("unsupported file type %q; Bedrock documents accept pdf, csv, doc, docx, xls, xlsx, html, txt and md", describeFileType(mediaType, filename))
		}
	}

	return map[string]interface{}{
		"document": map[string]interface{}{
			"format": format,
			"name":   names.unique(documentName(filename)),
			"source": map[string]interface{}{"bytes": parts[1]},
		},
	}, nil
}

// validateBase64 checks that data is non-empty, standard padded base64, the
// encoding Converse expects in source.bytes. Whitespace is rejected rather
// than stripped because the encoded data is forwarded unchanged.
func validateBase64(data string) error {
	if data == "" {
		return errors.New("file_data contains no data")
	}
	if strings.ContainsAny(data, " \t\r\n") {
		return errors.New("file_data must be base64 without whitespace or line breaks")
	}
	if _, err := base64.StdEncoding.DecodeString(data); err != nil {
		return errors.New("file_data is not valid base64")
	}
	return nil
}

// documentName derives a Converse-safe document name from a filename.
func documentName(filename string) string {
	base := strings.TrimSuffix(path.Base(filename), path.Ext(filename))
	name := documentNameDisallowed.ReplaceAllString(base, " ")
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "document"
	}
	return name
}

func describeFileType(mediaType, filename string) string {
	if mediaType != "" {
		return mediaType
	}
	return filename
}

func buildInferenceConfig(payload map[string]interface{}) map[string]interface{} {
	inference := map[string]interface{}{}

	if v, ok := payload["max_completion_tokens"]; ok {
		inference["maxTokens"] = v
	} else if v, ok := payload["max_tokens"]; ok {
		inference["maxTokens"] = v
	}

	if v, ok := payload["temperature"]; ok {
		inference["temperature"] = v
	}
	if v, ok := payload["top_p"]; ok {
		inference["topP"] = v
	}
	if stop, ok := payload["stop"]; ok && stop != nil {
		switch s := stop.(type) {
		case string:
			inference["stopSequences"] = []string{s}
		case []interface{}:
			inference["stopSequences"] = s
		}
	}
	return inference
}

// buildToolConfig maps OpenAI tools/tool_choice to a Converse toolConfig.
// Returns nil when no tools apply (or tool_choice is "none"), in which case the
// caller omits toolConfig entirely.
func buildToolConfig(payload map[string]interface{}) map[string]interface{} {
	tools, ok := payload["tools"].([]interface{})
	if !ok || len(tools) == 0 {
		return nil
	}

	// "none" means the model may not call tools — drop the whole toolConfig.
	if choice, ok := payload["tool_choice"].(string); ok && choice == "none" {
		return nil
	}

	var converseTools []interface{}
	for _, raw := range tools {
		tool, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		fn, ok := tool["function"].(map[string]interface{})
		if !ok {
			continue
		}
		spec := map[string]interface{}{"name": fn["name"]}
		if description, ok := fn["description"]; ok {
			spec["description"] = description
		}
		schema := fn["parameters"]
		if schema == nil {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		spec["inputSchema"] = map[string]interface{}{"json": schema}
		converseTools = append(converseTools, map[string]interface{}{"toolSpec": spec})
	}
	if len(converseTools) == 0 {
		return nil
	}

	toolConfig := map[string]interface{}{"tools": converseTools}
	if toolChoice := convertToolChoice(payload["tool_choice"]); toolChoice != nil {
		toolConfig["toolChoice"] = toolChoice
	}
	return toolConfig
}

func convertToolChoice(toolChoice interface{}) map[string]interface{} {
	switch choice := toolChoice.(type) {
	case string:
		switch choice {
		case "required":
			return map[string]interface{}{"any": map[string]interface{}{}}
		case "auto":
			return map[string]interface{}{"auto": map[string]interface{}{}}
		}
	case map[string]interface{}:
		if fn, ok := choice["function"].(map[string]interface{}); ok {
			if name, ok := fn["name"].(string); ok {
				return map[string]interface{}{"tool": map[string]interface{}{"name": name}}
			}
		}
	}
	return nil
}
