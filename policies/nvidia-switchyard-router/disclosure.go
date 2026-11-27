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

package nvidiaswitchyardrouter

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Prompt disclosure levels: how much of the conversation switchyard-server
// sees. Redacted turns keep their role and position, and their text is
// replaced by its length, so message counts still reach the router.
const (
	// disclosureNone sends roles and sizes only, for profiles such as random
	// that read nothing.
	disclosureNone = "none"
	// disclosureToolActivity keeps tool calls and tool results, which is what
	// the Stage router scores, and redacts all prose.
	disclosureToolActivity = "tool_activity"
	// disclosureTaskAndToolActivity also keeps the opening user request and the
	// latest user message, which is what a Stage judge reads.
	disclosureTaskAndToolActivity = "task_and_tool_activity"
	// disclosureFull sends the request unchanged.
	disclosureFull = "full"
)

// decisionFields are the top-level request fields kept when the prompt is
// redacted: the conversation and size limits. System prompts, instructions,
// tool definitions and other settings are dropped.
var decisionFields = []string{"messages", "input", "max_tokens", "max_completion_tokens", "max_output_tokens", "stream"}

// redactRequest returns the parts of request that the disclosure level
// allows switchyard-server to see. It changes request in place.
func redactRequest(inputFormat string, request map[string]interface{}, level string) map[string]interface{} {
	out := map[string]interface{}{}
	for _, field := range decisionFields {
		if value, ok := request[field]; ok {
			out[field] = value
		}
	}

	keepTask := level == disclosureTaskAndToolActivity
	keepTools := level != disclosureNone
	switch inputFormat {
	case "openai_responses":
		switch input := out["input"].(type) {
		case string:
			if !keepTask {
				out["input"] = redacted(input)
			}
		case []interface{}:
			out["input"] = redactConversation(input, keepTask, keepTools, isResponsesTask, redactResponsesItem)
		}
	case "anthropic_messages":
		if messages, ok := out["messages"].([]interface{}); ok {
			out["messages"] = redactConversation(messages, keepTask, keepTools, isAnthropicTask, redactAnthropicMessage)
		}
	default:
		if messages, ok := out["messages"].([]interface{}); ok {
			out["messages"] = redactConversation(messages, keepTask, keepTools, isChatTask, redactChatMessage)
		}
	}
	return out
}

// redactConversation redacts every turn except, with keepTask, the opening
// and latest user requests. redact returns false to drop a turn.
func redactConversation(
	items []interface{},
	keepTask, keepTools bool,
	isTask func(map[string]interface{}) bool,
	redact func(item map[string]interface{}, keepTools bool) (map[string]interface{}, bool),
) []interface{} {
	first, last := -1, -1
	if keepTask {
		for i, item := range items {
			if m, ok := item.(map[string]interface{}); ok && isTask(m) {
				if first < 0 {
					first = i
				}
				last = i
			}
		}
	}

	out := make([]interface{}, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if i == first || i == last {
			out = append(out, m)
			continue
		}
		if r, keep := redact(m, keepTools); keep {
			out = append(out, r)
		}
	}
	return out
}

// redacted stands in for content: its length, without its text.
func redacted(values ...interface{}) string {
	return fmt.Sprintf("[redacted %d chars]", contentSize(values...))
}

func contentSize(values ...interface{}) int {
	n := 0
	for _, v := range values {
		switch c := v.(type) {
		case nil:
		case string:
			n += utf8.RuneCountInString(c)
		case map[string]interface{}:
			if text, ok := c["text"].(string); ok {
				n += utf8.RuneCountInString(text)
			} else if b, err := json.Marshal(c); err == nil {
				n += len(b)
			}
		default:
			if text := contentText(c); text != "" {
				n += utf8.RuneCountInString(text)
			} else if b, err := json.Marshal(c); err == nil {
				n += len(b)
			}
		}
	}
	return n
}

// --- OpenAI Chat Completions ---

func isChatTask(m map[string]interface{}) bool {
	return m["role"] == "user"
}

// redactChatMessage keeps tool messages and assistant tool calls when
// keepTools is set. Otherwise every turn becomes plain text, and tool results
// become user turns, as they are in the other formats.
func redactChatMessage(m map[string]interface{}, keepTools bool) (map[string]interface{}, bool) {
	role, _ := m["role"].(string)
	switch {
	case role == "tool" && keepTools:
		return m, true
	case role == "tool":
		return map[string]interface{}{"role": "user", "content": redacted(m["content"])}, true
	case m["tool_calls"] != nil && keepTools:
		out := map[string]interface{}{"role": role, "tool_calls": m["tool_calls"]}
		if contentSize(m["content"]) > 0 {
			out["content"] = redacted(m["content"])
		}
		return out, true
	default:
		return map[string]interface{}{"role": role, "content": redacted(m["content"], m["tool_calls"])}, true
	}
}

// --- Anthropic Messages ---

func isAnthropicToolBlock(block interface{}) bool {
	m, ok := block.(map[string]interface{})
	if !ok {
		return false
	}
	t, _ := m["type"].(string)
	return t == "tool_use" || t == "tool_result" || strings.HasSuffix(t, "_tool_use") || strings.HasSuffix(t, "_tool_result")
}

// isAnthropicTask is a user message with content of its own; tool results
// also travel as user messages.
func isAnthropicTask(m map[string]interface{}) bool {
	if m["role"] != "user" {
		return false
	}
	switch content := m["content"].(type) {
	case string:
		return true
	case []interface{}:
		for _, block := range content {
			if !isAnthropicToolBlock(block) {
				return true
			}
		}
	}
	return false
}

// redactAnthropicMessage keeps tool blocks in place when keepTools is set and
// replaces every other block with a text block holding its size.
func redactAnthropicMessage(m map[string]interface{}, keepTools bool) (map[string]interface{}, bool) {
	out := map[string]interface{}{"role": m["role"]}
	blocks, isList := m["content"].([]interface{})
	if !keepTools || !isList {
		out["content"] = redacted(m["content"])
		return out, true
	}
	content := make([]interface{}, 0, len(blocks))
	for _, block := range blocks {
		if isAnthropicToolBlock(block) {
			content = append(content, block)
		} else {
			content = append(content, map[string]interface{}{"type": "text", "text": redacted(block)})
		}
	}
	out["content"] = content
	return out, true
}

// --- OpenAI Responses ---

func isResponsesMessage(m map[string]interface{}) bool {
	t, _ := m["type"].(string)
	return t == "message" || (t == "" && m["role"] != nil)
}

func isResponsesTask(m map[string]interface{}) bool {
	return isResponsesMessage(m) && m["role"] == "user"
}

// redactResponsesItem redacts message items, drops reasoning, and keeps tool
// call and output items when keepTools is set. Without it, calls become
// assistant turns and outputs become user turns.
func redactResponsesItem(m map[string]interface{}, keepTools bool) (map[string]interface{}, bool) {
	t, _ := m["type"].(string)
	switch {
	case isResponsesMessage(m):
		out := map[string]interface{}{"role": m["role"], "content": redacted(m["content"])}
		if t != "" {
			out["type"] = t
		}
		return out, true
	case t == "reasoning":
		return nil, false
	case keepTools:
		return m, true
	case strings.HasSuffix(t, "_output"):
		return map[string]interface{}{"role": "user", "content": redacted(m["output"])}, true
	default:
		return map[string]interface{}{"role": "assistant", "content": redacted(m["arguments"], m["input"])}, true
	}
}
