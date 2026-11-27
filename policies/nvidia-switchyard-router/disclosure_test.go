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
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Each conversation carries one marker per kind of content, so a test can
// check which kinds reach switchyard-server.
const (
	chatConversation = `{"model":"m","temperature":0.2,"tools":[{"type":"function","function":{"name":"TOOLDEF"}}],"messages":[
		{"role":"system","content":"SYSTEM"},
		{"role":"user","content":"TASK"},
		{"role":"assistant","content":"PROSE","tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":"{\"command\":\"CALL\"}"}}]},
		{"role":"tool","tool_call_id":"c1","content":"RESULT"},
		{"role":"user","content":"MIDDLE"},
		{"role":"assistant","content":"REPLY"},
		{"role":"user","content":[{"type":"text","text":"LATEST"}]}]}`

	anthropicConversation = `{"model":"m","max_tokens":1024,"system":"SYSTEM","messages":[
		{"role":"user","content":"TASK"},
		{"role":"assistant","content":[{"type":"thinking","thinking":"THOUGHT"},{"type":"text","text":"PROSE"},{"type":"tool_use","id":"t1","name":"bash","input":{"command":"CALL"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"RESULT"}]},
		{"role":"user","content":"MIDDLE"},
		{"role":"assistant","content":"REPLY"},
		{"role":"user","content":[{"type":"text","text":"LATEST"}]}]}`

	responsesConversation = `{"model":"m","instructions":"SYSTEM","input":[
		{"role":"user","content":"TASK"},
		{"type":"reasoning","summary":[{"type":"summary_text","text":"THOUGHT"}]},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"PROSE"}]},
		{"type":"function_call","call_id":"f1","name":"bash","arguments":"{\"command\":\"CALL\"}"},
		{"type":"function_call_output","call_id":"f1","output":"RESULT"},
		{"role":"user","content":"MIDDLE"},
		{"type":"message","role":"assistant","content":"REPLY"},
		{"type":"message","role":"user","content":[{"type":"input_text","text":"LATEST"}]}]}`
)

var allMarkers = []string{"SYSTEM", "TOOLDEF", "THOUGHT", "TASK", "PROSE", "CALL", "RESULT", "MIDDLE", "REPLY", "LATEST"}

func TestPromptDisclosure(t *testing.T) {
	for _, tc := range []struct {
		level string
		sent  []string
	}{
		{"none", nil},
		{"tool_activity", []string{"CALL", "RESULT"}},
		{"task_and_tool_activity", []string{"TASK", "CALL", "RESULT", "LATEST"}},
	} {
		for _, conv := range []struct{ path, body string }{
			{"/chat/completions", chatConversation},
			{"/v1/messages", anthropicConversation},
			{"/v1/responses", responsesConversation},
		} {
			t.Run(tc.level+conv.path, func(t *testing.T) {
				srv, rec := server(t, 200, selected("efficient", "capable"))
				params := testParams(srv.URL)
				params["promptDisclosure"] = tc.level
				p := newPolicy(t, params)
				reqCtx := requestContext(conv.body, nil)
				reqCtx.Path = conv.path

				mods := routed(t, p.OnRequestBody(context.Background(), reqCtx, nil))

				sent := string(rec.body.Request)
				for _, marker := range allMarkers {
					want := contains(tc.sent, marker)
					if strings.Contains(sent, marker) != want {
						t.Errorf("%s sent = %v, want %v", marker, !want, want)
					}
				}
				if !strings.Contains(sent, "[redacted ") {
					t.Errorf("no redaction markers in %s", sent)
				}
				if strings.Contains(sent, "temperature") {
					t.Errorf("generation settings sent: %s", sent)
				}
				// The routed request is the caller's, unredacted.
				if !strings.Contains(string(mods.Body), "MIDDLE") || !strings.Contains(string(mods.Body), "SYSTEM") {
					t.Errorf("routed request was redacted: %s", mods.Body)
				}
			})
		}
	}
}

func TestPromptDisclosureKeepsTurnsAndRoles(t *testing.T) {
	request, err := decodePayload([]byte(chatConversation))
	if err != nil {
		t.Fatal(err)
	}
	got := redactRequest("openai_chat", request, disclosureToolActivity)
	messages := got["messages"].([]interface{})
	var roles []string
	for _, m := range messages {
		roles = append(roles, m.(map[string]interface{})["role"].(string))
	}
	if want := "system user assistant tool user assistant user"; strings.Join(roles, " ") != want {
		t.Fatalf("roles = %v, want %s", roles, want)
	}
	if messages[1].(map[string]interface{})["content"] != "[redacted 4 chars]" {
		t.Fatalf("user turn = %v", messages[1])
	}
	if got["model"] != nil || got["tools"] != nil {
		t.Fatalf("unexpected fields kept: %v", got)
	}

	// Without tools, tool results become user turns and calls lose their arguments.
	request, _ = decodePayload([]byte(chatConversation))
	none := redactRequest("openai_chat", request, disclosureNone)
	b, _ := json.Marshal(none)
	if strings.Contains(string(b), "tool_calls") || strings.Contains(string(b), `"tool"`) {
		t.Fatalf("tool structure kept at none: %s", b)
	}
}

func TestPromptDisclosureFullSendsRequestUnchanged(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["promptDisclosure"] = "full"
	p := newPolicy(t, params)
	p.OnRequestBody(context.Background(), requestContext(chatConversation, nil), nil)
	for _, marker := range allMarkers {
		if marker != "THOUGHT" && !strings.Contains(string(rec.body.Request), marker) {
			t.Errorf("%s missing from a full disclosure", marker)
		}
	}
}

func TestResponsesStringInput(t *testing.T) {
	for level, want := range map[string]string{
		disclosureTaskAndToolActivity: "fix the build",
		disclosureToolActivity:        "[redacted 13 chars]",
	} {
		request, _ := decodePayload([]byte(`{"model":"m","input":"fix the build"}`))
		if got := redactRequest("openai_responses", request, level)["input"]; got != want {
			t.Errorf("%s: input = %v, want %q", level, got, want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
