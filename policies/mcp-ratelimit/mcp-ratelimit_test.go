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

package mcpratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── parseEntries ────────────────────────────────────────────────────────────

func TestParseEntries(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]any
		wantErr     string
		wantCount   int
		wantEntries []limitEntry // section + name only, compared positionally
	}{
		{
			name: "tools entry with explicit name",
			params: map[string]any{
				"tools": []any{
					map[string]any{
						"name":   "toolA",
						"limits": []any{map[string]any{"limit": float64(5), "duration": "1m"}},
					},
				},
			},
			wantCount:   1,
			wantEntries: []limitEntry{{section: sectionTools, name: "toolA"}},
		},
		{
			name: "missing name defaults to wildcard",
			params: map[string]any{
				"tools": []any{
					map[string]any{
						"limits": []any{map[string]any{"limit": float64(5), "duration": "1m"}},
					},
				},
			},
			wantCount:   1,
			wantEntries: []limitEntry{{section: sectionTools, name: "*"}},
		},
		{
			name: "blank name defaults to wildcard",
			params: map[string]any{
				"resources": []any{
					map[string]any{
						"name":   "   ",
						"limits": []any{map[string]any{"limit": float64(1), "duration": "1s"}},
					},
				},
			},
			wantCount:   1,
			wantEntries: []limitEntry{{section: sectionResources, name: "*"}},
		},
		{
			name: "all four sections parsed",
			params: map[string]any{
				"tools":     []any{map[string]any{"name": "t", "limits": []any{map[string]any{"limit": float64(1), "duration": "1s"}}}},
				"resources": []any{map[string]any{"name": "r", "limits": []any{map[string]any{"limit": float64(1), "duration": "1s"}}}},
				"prompts":   []any{map[string]any{"name": "p", "limits": []any{map[string]any{"limit": float64(1), "duration": "1s"}}}},
				"methods":   []any{map[string]any{"name": "tools/list", "limits": []any{map[string]any{"limit": float64(1), "duration": "1s"}}}},
			},
			wantCount: 4,
			wantEntries: []limitEntry{
				{section: sectionTools, name: "t"},
				{section: sectionResources, name: "r"},
				{section: sectionPrompts, name: "p"},
				{section: sectionMethods, name: "tools/list"},
			},
		},
		{
			name:      "no sections returns empty",
			params:    map[string]any{},
			wantCount: 0,
		},
		{
			name: "section not an array",
			params: map[string]any{
				"tools": "nope",
			},
			wantErr: "tools must be an array",
		},
		{
			name: "entry not an object",
			params: map[string]any{
				"tools": []any{"nope"},
			},
			wantErr: "tools[0] must be an object",
		},
		{
			name: "missing limits",
			params: map[string]any{
				"tools": []any{map[string]any{"name": "toolA"}},
			},
			wantErr: "tools[0].limits must be a non-empty array",
		},
		{
			name: "empty limits array",
			params: map[string]any{
				"tools": []any{map[string]any{"name": "toolA", "limits": []any{}}},
			},
			wantErr: "tools[0].limits must be a non-empty array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseEntries(tt.params)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(entries) != tt.wantCount {
				t.Fatalf("expected %d entries, got %d", tt.wantCount, len(entries))
			}
			for i, want := range tt.wantEntries {
				if entries[i].section != want.section || entries[i].name != want.name {
					t.Fatalf("entry[%d] = {%s,%s}, want {%s,%s}",
						i, entries[i].section, entries[i].name, want.section, want.name)
				}
			}
		})
	}
}

func TestParseEntries_KeyExtractionPassthrough(t *testing.T) {
	ke := []any{map[string]any{"type": "header", "key": "x-user"}}
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":          "toolA",
				"limits":        []any{map[string]any{"limit": float64(5), "duration": "1m"}},
				"keyExtraction": ke,
			},
		},
	}
	entries, err := parseEntries(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || len(entries[0].keyExtractionRaw) != 1 {
		t.Fatalf("expected key extraction to be carried through, got %+v", entries)
	}
}

func TestGetPolicy(t *testing.T) {
	t.Run("returns error when no section configured", func(t *testing.T) {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{})
		if err == nil || !strings.Contains(err.Error(), "at least one of tools, resources, prompts, or methods") {
			t.Fatalf("expected at-least-one-section error, got %v", err)
		}
	})

	t.Run("propagates parse error", func(t *testing.T) {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{"tools": "bad"})
		if err == nil || !strings.Contains(err.Error(), "tools must be an array") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("captures global config", func(t *testing.T) {
		params := map[string]any{
			"tools": []any{
				map[string]any{"name": "toolA", "limits": []any{map[string]any{"limit": float64(5), "duration": "1m"}}},
			},
			"keyExtraction":       []any{map[string]any{"type": "ip"}},
			"onRateLimitExceeded": map[string]any{"statusCode": float64(503)},
			"algorithm":           "gcra",
			"backend":             "memory",
			"unrelated":           "ignored",
		}
		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r"}, params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mp := p.(*McpRateLimitPolicy)
		if len(mp.entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(mp.entries))
		}
		if len(mp.globalKeyExtraction) != 1 {
			t.Fatalf("expected global key extraction captured")
		}
		if mp.onRateLimitExceeded == nil {
			t.Fatalf("expected onRateLimitExceeded captured")
		}
		if _, ok := mp.systemParams["algorithm"]; !ok {
			t.Fatalf("expected algorithm captured in systemParams")
		}
		if _, ok := mp.systemParams["backend"]; !ok {
			t.Fatalf("expected backend captured in systemParams")
		}
		if _, ok := mp.systemParams["unrelated"]; ok {
			t.Fatalf("expected unrelated key to be excluded from systemParams")
		}
	})
}

func TestMode(t *testing.T) {
	p := &McpRateLimitPolicy{}
	mode := p.Mode()
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Fatalf("expected request body to be buffered, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeProcess {
		t.Fatalf("expected response headers to be processed, got %v", mode.ResponseHeaderMode)
	}
}

func TestIdentifyCapability(t *testing.T) {
	tests := []struct {
		name        string
		payload     map[string]any
		wantMethod  string
		wantCapType string
		wantCapName string
	}{
		{
			name:        "tools/call resolves tool name",
			payload:     map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}},
			wantMethod:  "tools/call",
			wantCapType: "tool",
			wantCapName: "toolA",
		},
		{
			name:        "tools/list has no capability name",
			payload:     map[string]any{"method": "tools/list"},
			wantMethod:  "tools/list",
			wantCapType: "tool",
			wantCapName: "",
		},
		{
			name:        "resources/read resolves uri",
			payload:     map[string]any{"method": "resources/read", "params": map[string]any{"uri": "file:///a"}},
			wantMethod:  "resources/read",
			wantCapType: "resource",
			wantCapName: "file:///a",
		},
		{
			name:        "prompts/get resolves prompt name",
			payload:     map[string]any{"method": "prompts/get", "params": map[string]any{"name": "promptA"}},
			wantMethod:  "prompts/get",
			wantCapType: "prompt",
			wantCapName: "promptA",
		},
		{
			name:        "unstructured method",
			payload:     map[string]any{"method": "ping"},
			wantMethod:  "ping",
			wantCapType: "",
			wantCapName: "",
		},
		{
			name:        "missing method",
			payload:     map[string]any{"id": "1"},
			wantMethod:  "",
			wantCapType: "",
			wantCapName: "",
		},
	}

	p := &McpRateLimitPolicy{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			reqCtx := newRequestCtx(t, "POST", nil, body)
			method, capType, capName, _, err := p.identifyCapability(reqCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if method != tt.wantMethod || capType != tt.wantCapType || capName != tt.wantCapName {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)",
					method, capType, capName, tt.wantMethod, tt.wantCapType, tt.wantCapName)
			}
		})
	}
}

func TestIdentifyCapability_InvalidJSON(t *testing.T) {
	p := &McpRateLimitPolicy{}
	reqCtx := newRequestCtx(t, "POST", nil, []byte("{not-json"))
	if _, _, _, _, err := p.identifyCapability(reqCtx); err == nil {
		t.Fatalf("expected error for malformed body")
	}
}

func TestIdentifyCapability_AmbiguousMembers(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "case variant method shadows protected method",
			body: `{"method":"tools/call","Method":"ping","params":{"name":"toolA"}}`,
		},
		{
			name: "duplicate method shadows protected method",
			body: `{"method":"tools/call","method":"ping","params":{"name":"toolA"}}`,
		},
		{
			name: "case variant params shadows protected capability",
			body: `{"method":"tools/call","params":{"name":"toolA"},"Params":{"name":"toolB"}}`,
		},
		{
			name: "case variant name shadows protected capability",
			body: `{"method":"tools/call","params":{"name":"toolA","Name":"toolB"}}`,
		},
		{
			name: "duplicate uri shadows protected capability",
			body: `{"method":"resources/read","params":{"uri":"file:///a","uri":"file:///b"}}`,
		},
		{
			name: "Unicode case-folded params shadows protected capability",
			body: `{"method":"tools/call","params":{"name":"toolA"},"param\u017f":{"name":"toolB"}}`,
		},
	}

	p := &McpRateLimitPolicy{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqCtx := newRequestCtx(t, "POST", nil, []byte(tt.body))
			if _, _, _, _, err := p.identifyCapability(reqCtx); !isAmbiguousMemberError(err) {
				t.Fatalf("expected ambiguous-member error, got %v", err)
			}
		})
	}
}

func TestIdentifyCapability_ExtensionMethodParametersUntouched(t *testing.T) {
	p := &McpRateLimitPolicy{}
	body := []byte(`{"method":"vendor/run","params":{"Name":"case-sensitive","URI":"custom"}}`)
	reqCtx := newRequestCtx(t, "POST", nil, body)

	method, capType, capName, _, err := p.identifyCapability(reqCtx)
	if err != nil {
		t.Fatalf("expected extension method parameters to pass through, got %v", err)
	}
	if method != "vendor/run" || capType != "" || capName != "" {
		t.Fatalf("got (%q,%q,%q), want (vendor/run,\"\",\"\")", method, capType, capName)
	}
}

func TestIdentifyCapability_EventStream(t *testing.T) {
	p := &McpRateLimitPolicy{}
	payload, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
	body := []byte("event: message\ndata: " + string(payload) + "\n\n")
	reqCtx := newRequestCtx(t, "POST", map[string][]string{"content-type": {"text/event-stream"}}, body)

	method, capType, capName, _, err := p.identifyCapability(reqCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if method != "tools/call" || capType != "tool" || capName != "toolA" {
		t.Fatalf("event-stream parse failed: got (%q,%q,%q)", method, capType, capName)
	}
}

func TestIdentifyCapability_AmbiguousEventStream(t *testing.T) {
	p := &McpRateLimitPolicy{}
	payload := `{"method":"tools/call","Method":"ping","params":{"name":"toolA"}}`
	body := []byte("event: message\ndata: " + payload + "\n\n")
	reqCtx := newRequestCtx(t, "POST", map[string][]string{"content-type": {"text/event-stream"}}, body)

	if _, _, _, _, err := p.identifyCapability(reqCtx); !isAmbiguousMemberError(err) {
		t.Fatalf("expected ambiguous-member error, got %v", err)
	}
}

func TestIdentifyCapability_EmptyEventStream(t *testing.T) {
	p := &McpRateLimitPolicy{}
	reqCtx := newRequestCtx(t, "POST", map[string][]string{"content-type": {"text/event-stream"}}, []byte("event: ping\n\n"))
	if _, _, _, _, err := p.identifyCapability(reqCtx); err == nil {
		t.Fatalf("expected error for event stream with no data payload")
	}
}

// ─── findMatches ─────────────────────────────────────────────────────────────

func TestFindMatches(t *testing.T) {
	p := &McpRateLimitPolicy{
		entries: []limitEntry{
			{section: sectionTools, name: "toolA"},     // 0 exact
			{section: sectionTools, name: "*"},         // 1 wildcard
			{section: sectionMethods, name: "ping"},    // 2
			{section: sectionResources, name: "*"},     // 3
			{section: sectionPrompts, name: "promptA"}, // 4
		},
	}

	t.Run("exact tool ordered before wildcard", func(t *testing.T) {
		matches := p.findMatches("tools/call", "tool", "toolA")
		if len(matches) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(matches))
		}
		if matches[0].entryIdx != 0 || matches[1].entryIdx != 1 {
			t.Fatalf("expected exact (0) before wildcard (1), got %d then %d", matches[0].entryIdx, matches[1].entryIdx)
		}
		if matches[0].capabilityID != "toolA" || matches[1].capabilityID != "toolA" {
			t.Fatalf("expected capabilityID toolA on both matches, got %+v", matches)
		}
	})

	t.Run("non-configured tool matches only wildcard", func(t *testing.T) {
		matches := p.findMatches("tools/call", "tool", "toolB")
		if len(matches) != 1 || matches[0].entryIdx != 1 {
			t.Fatalf("expected only wildcard match, got %+v", matches)
		}
	})

	t.Run("method exact match", func(t *testing.T) {
		matches := p.findMatches("ping", "", "")
		if len(matches) != 1 || matches[0].entryIdx != 2 || matches[0].capabilityID != "ping" {
			t.Fatalf("expected method match, got %+v", matches)
		}
	})

	t.Run("resource wildcard uses uri as capability id", func(t *testing.T) {
		matches := p.findMatches("resources/read", "resource", "file:///x")
		if len(matches) != 1 || matches[0].capabilityID != "file:///x" {
			t.Fatalf("expected resource uri capability id, got %+v", matches)
		}
	})

	t.Run("tool section ignored when capability name empty", func(t *testing.T) {
		matches := p.findMatches("tools/list", "tool", "")
		if len(matches) != 0 {
			t.Fatalf("expected no matches for tools/list (no name), got %+v", matches)
		}
	})

	t.Run("no match for unconfigured method", func(t *testing.T) {
		if matches := p.findMatches("logging/setLevel", "", ""); len(matches) != 0 {
			t.Fatalf("expected no matches, got %+v", matches)
		}
	})
}

// ─── small helpers ───────────────────────────────────────────────────────────

func TestIsPostRequest(t *testing.T) {
	if !isPostRequest("POST") || !isPostRequest("post") {
		t.Fatalf("expected POST in any case to be accepted")
	}
	if isPostRequest("GET") {
		t.Fatalf("expected GET to be rejected")
	}
}

func TestIsEventStream(t *testing.T) {
	if !isEventStream(policy.NewHeaders(map[string][]string{"Content-Type": {"text/event-stream; charset=utf-8"}})) {
		t.Fatalf("expected event-stream content type to be detected")
	}
	if isEventStream(policy.NewHeaders(map[string][]string{"content-type": {"application/json"}})) {
		t.Fatalf("expected json content type not to be event stream")
	}
	if isEventStream(nil) {
		t.Fatalf("expected nil headers not to be event stream")
	}
}

func TestGetSessionID(t *testing.T) {
	h := policy.NewHeaders(map[string][]string{mcpSessionHeader: {"sess-1"}})
	if got := getSessionID(h); got != "sess-1" {
		t.Fatalf("expected sess-1, got %q", got)
	}
	if got := getSessionID(policy.NewHeaders(map[string][]string{})); got != "" {
		t.Fatalf("expected empty session id, got %q", got)
	}
	if got := getSessionID(nil); got != "" {
		t.Fatalf("expected empty session id for nil headers, got %q", got)
	}
}

func TestExtractFirstSseJSON(t *testing.T) {
	body := []byte("event: message\ndata: {\"a\":1}\n\nevent: message\ndata: {\"b\":2}\n\n")
	got := extractFirstSseJSON(body)
	if string(got) != `{"a":1}` {
		t.Fatalf("expected first data payload, got %q", string(got))
	}

	multi := []byte("data: {\"a\":\ndata: 1}\n\n")
	if got := extractFirstSseJSON(multi); string(got) != "{\"a\":\n1}" {
		t.Fatalf("expected multi-line data joined, got %q", string(got))
	}

	if got := extractFirstSseJSON([]byte("event: ping\n\n")); got != nil {
		t.Fatalf("expected nil for stream with no data, got %q", string(got))
	}
}

func TestDelegateKey(t *testing.T) {
	if got := delegateKey(3, "toolA"); got != "3:toolA" {
		t.Fatalf("expected 3:toolA, got %q", got)
	}
}

func TestHasUserDefinedBody(t *testing.T) {
	cases := []struct {
		name string
		ore  map[string]any
		want bool
	}{
		{"nil", nil, false},
		{"empty body", map[string]any{"body": ""}, false},
		{"no body key", map[string]any{"statusCode": float64(503)}, false},
		{"with body", map[string]any{"body": "blocked"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &McpRateLimitPolicy{onRateLimitExceeded: c.ore}
			if got := p.hasUserDefinedBody(); got != c.want {
				t.Fatalf("hasUserDefinedBody() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBuildJsonRpcErrorBody(t *testing.T) {
	t.Run("json envelope with id", func(t *testing.T) {
		body, ct := buildJsonRpcErrorBody(json.RawMessage(`"req-1"`), -32700, "bad", false)
		if ct != "application/json" {
			t.Fatalf("expected application/json, got %q", ct)
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if parsed["id"] != "req-1" {
			t.Fatalf("expected id req-1, got %v", parsed["id"])
		}
		errObj := parsed["error"].(map[string]any)
		if errObj["code"] != float64(-32700) || errObj["message"] != "bad" {
			t.Fatalf("unexpected error object: %+v", errObj)
		}
	})

	t.Run("defaults id to null when missing", func(t *testing.T) {
		body, _ := buildJsonRpcErrorBody(nil, -32000, "rate", false)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		if parsed["id"] != nil {
			t.Fatalf("expected null id, got %v", parsed["id"])
		}
	})

	t.Run("sse envelope", func(t *testing.T) {
		body, ct := buildJsonRpcErrorBody(json.RawMessage(`1`), -32000, "rate", true)
		if ct != "text/event-stream" {
			t.Fatalf("expected text/event-stream, got %q", ct)
		}
		if !strings.HasPrefix(string(body), "data: ") || !strings.HasSuffix(string(body), "\n\n") {
			t.Fatalf("expected SSE-wrapped body, got %q", string(body))
		}
	})
}

func TestBuildJsonRpcRateLimitedBody(t *testing.T) {
	body, ct := buildJsonRpcRateLimitedBody(json.RawMessage(`1`), false)
	if ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	errObj := parsed["error"].(map[string]any)
	if errObj["code"] != float64(jsonRpcErrCodeRateLimited) {
		t.Fatalf("expected rate-limit code %d, got %v", jsonRpcErrCodeRateLimited, errObj["code"])
	}
}

// ─── OnRequestBody / OnResponseHeaders (integration with real delegate) ──────

func TestOnRequestBody_NonMcpMethodPassesThrough(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
	reqCtx := newRequestCtx(t, "GET", nil, body)

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through for non-POST, got %T", action)
	}
}

func TestOnRequestBody_EmptyBodyPassesThrough(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	reqCtx := newRequestCtx(t, "POST", nil, nil)
	reqCtx.Body = &policy.Body{Content: nil, Present: false}

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through for empty body, got %T", action)
	}
}

func TestOnRequestBody_NoMatchPassesThroughButSetsMetadata(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	// Request a different tool — no rule matches.
	body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolB"}})
	reqCtx := newRequestCtx(t, "POST", nil, body)

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through, got %T", action)
	}
	if reqCtx.Metadata[metadataMcpMethod] != "tools/call" {
		t.Fatalf("expected mcp.method metadata to be set, got %v", reqCtx.Metadata[metadataMcpMethod])
	}
	if reqCtx.Metadata[metadataMcpCapabilityName] != "toolB" {
		t.Fatalf("expected mcp.name metadata to be set, got %v", reqCtx.Metadata[metadataMcpCapabilityName])
	}
}

func TestOnRequestBody_InvalidBodyReturnsJsonRpcError(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	reqCtx := newRequestCtx(t, "POST", nil, []byte("{bad-json"))

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d", resp.StatusCode)
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("expected JSON-RPC error body: %v", err)
	}
	errObj := parsed["error"].(map[string]any)
	if errObj["code"] != float64(-32700) {
		t.Fatalf("expected parse-error code -32700, got %v", errObj["code"])
	}
}

func TestOnRequestBody_AmbiguousMemberReturnsInvalidRequest(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	body := []byte(`{"method":"tools/call","Method":"ping","params":{"name":"toolA"}}`)
	reqCtx := newRequestCtx(t, "POST", nil, body)

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d", resp.StatusCode)
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("expected JSON-RPC error body: %v", err)
	}
	errObj := parsed["error"].(map[string]any)
	if errObj["code"] != float64(-32600) {
		t.Fatalf("expected invalid-request code -32600, got %v", errObj["code"])
	}
}

func TestOnRequestBody_AllowsUnderLimit(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
	reqCtx := newRequestCtx(t, "POST", nil, body)

	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatalf("expected request under the limit to be allowed, got ImmediateResponse")
	}
	invoked, _ := reqCtx.SharedContext.Metadata[metadataInvokedDelegates].([]string)
	if len(invoked) != 1 {
		t.Fatalf("expected one invoked delegate recorded, got %v", invoked)
	}
}

func TestOnRequestBody_BlocksOverLimit(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1) // limit of 1
	makeBody := func() []byte {
		b, _ := json.Marshal(map[string]any{"id": "1", "method": "tools/call", "params": map[string]any{"name": "toolA"}})
		return b
	}

	// First request consumes the single token.
	first := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, makeBody()), nil)
	if _, ok := first.(policy.ImmediateResponse); ok {
		t.Fatalf("expected first request to be allowed")
	}

	// Second request exceeds the limit.
	second := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, makeBody()), nil)
	resp, ok := second.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on limit breach, got %T", second)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("expected json content type, got %q", resp.Headers["content-type"])
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("expected JSON-RPC error body: %v", err)
	}
	if parsed["id"] != "1" {
		t.Fatalf("expected request id 1 echoed, got %v", parsed["id"])
	}
	errObj := parsed["error"].(map[string]any)
	if errObj["code"] != float64(jsonRpcErrCodeRateLimited) {
		t.Fatalf("expected rate-limit code, got %v", errObj["code"])
	}
}

func TestOnRequestBody_PerCapabilityBuckets(t *testing.T) {
	// Wildcard tool rule with limit of 1 — each distinct tool gets its own bucket.
	p := newWildcardToolPolicy(t, 1)
	call := func(tool string) policy.RequestAction {
		b, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": tool}})
		return p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, b), nil)
	}

	if _, ok := call("toolA").(policy.ImmediateResponse); ok {
		t.Fatalf("first toolA call should be allowed")
	}
	if _, ok := call("toolA").(policy.ImmediateResponse); !ok {
		t.Fatalf("second toolA call should be blocked")
	}
	// A different tool must still be allowed despite toolA being exhausted.
	if _, ok := call("toolB").(policy.ImmediateResponse); ok {
		t.Fatalf("first toolB call should be allowed (separate bucket)")
	}
}

func TestOnRequestBody_BlocksOverLimitSSE(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	makeBody := func() []byte {
		payload, _ := json.Marshal(map[string]any{"id": "sse-7", "method": "tools/call", "params": map[string]any{"name": "toolA"}})
		return []byte("event: message\ndata: " + string(payload) + "\n\n")
	}
	headers := map[string][]string{
		"content-type":   {"text/event-stream"},
		mcpSessionHeader: {"session-xyz"},
	}

	p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", headers, makeBody()), nil)
	second := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", headers, makeBody()), nil)

	resp, ok := second.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", second)
	}
	if resp.Headers["content-type"] != "text/event-stream" {
		t.Fatalf("expected event-stream response, got %q", resp.Headers["content-type"])
	}
	if resp.Headers[mcpSessionHeader] != "session-xyz" {
		t.Fatalf("expected session id propagated, got %q", resp.Headers[mcpSessionHeader])
	}
	payload := extractFirstSseJSON(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("expected JSON-RPC payload inside SSE body: %v", err)
	}
	if parsed["id"] != "sse-7" {
		t.Fatalf("expected id sse-7, got %v", parsed["id"])
	}
}

func TestOnRequestBody_CustomBodyReturnedUnchanged(t *testing.T) {
	params := map[string]any{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"tools": []any{
			map[string]any{"name": "toolA", "limits": []any{map[string]any{"limit": float64(1), "duration": "1m"}}},
		},
		"onRateLimitExceeded": map[string]any{
			"statusCode": float64(503),
			"body":       "custom-blocked",
		},
	}
	p := newPolicy(t, params)
	makeBody := func() []byte {
		b, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
		return b
	}

	p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, makeBody()), nil)
	second := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, makeBody()), nil)

	resp, ok := second.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", second)
	}
	// User-defined body must be passed through untouched (not rewritten to JSON-RPC).
	if string(resp.Body) != "custom-blocked" {
		t.Fatalf("expected custom body returned unchanged, got %q", string(resp.Body))
	}
	if resp.StatusCode != 503 {
		t.Fatalf("expected custom status 503, got %d", resp.StatusCode)
	}
}

func TestOnResponseHeaders_NoInvokedDelegates(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	respCtx := newResponseHeaderCtx(t, nil)
	action := p.OnResponseHeaders(context.Background(), respCtx, nil)
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	if len(mods.HeadersToSet) != 0 {
		t.Fatalf("expected no headers set when nothing was invoked, got %v", mods.HeadersToSet)
	}
}

func TestOnResponseHeaders_ForwardsDelegateHeaders(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	shared := &policy.SharedContext{RequestID: "rid", Metadata: make(map[string]any)}

	// Drive a request so a delegate is created and recorded as invoked.
	body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
	reqCtx := &policy.RequestContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(nil),
		Body:          &policy.Body{Content: body, Present: true},
		Method:        "POST",
	}
	p.OnRequestBody(context.Background(), reqCtx, nil)

	// Response phase reuses the same SharedContext (so invoked delegates carry over).
	respCtx := &policy.ResponseHeaderContext{
		SharedContext:   shared,
		RequestHeaders:  policy.NewHeaders(nil),
		ResponseHeaders: policy.NewHeaders(nil),
		ResponseStatus:  200,
	}
	action := p.OnResponseHeaders(context.Background(), respCtx, nil)
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	if len(mods.HeadersToSet) == 0 {
		t.Fatalf("expected delegate rate-limit headers to be forwarded, got none")
	}
}

// uniqueRoute keeps each policy's rate-limit buckets isolated from other tests,
// since advanced-ratelimit caches memory limiters in a process-global cache keyed
// (in part) by route name.
func uniqueRoute(t *testing.T) policy.PolicyMetadata {
	t.Helper()
	return policy.PolicyMetadata{RouteName: t.Name()}
}

func newPolicy(t *testing.T, params map[string]any) *McpRateLimitPolicy {
	t.Helper()
	p, err := GetPolicy(uniqueRoute(t), params)
	if err != nil {
		t.Fatalf("failed to build policy: %v", err)
	}
	return p.(*McpRateLimitPolicy)
}

func newToolPolicy(t *testing.T, name string, limit int) *McpRateLimitPolicy {
	t.Helper()
	return newPolicy(t, map[string]any{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"tools": []any{
			map[string]any{
				"name":   name,
				"limits": []any{map[string]any{"limit": float64(limit), "duration": "1m"}},
			},
		},
	})
}

func newWildcardToolPolicy(t *testing.T, limit int) *McpRateLimitPolicy {
	t.Helper()
	return newPolicy(t, map[string]any{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"tools": []any{
			map[string]any{
				"name":   "*",
				"limits": []any{map[string]any{"limit": float64(limit), "duration": "1m"}},
			},
		},
	})
}

func newRequestCtx(t *testing.T, method string, headers map[string][]string, body []byte) *policy.RequestContext {
	t.Helper()
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers: policy.NewHeaders(headers),
		Body:    &policy.Body{Content: body, Present: body != nil},
		Method:  method,
		Path:    "/mcp",
		Scheme:  "http",
	}
}

func newResponseHeaderCtx(t *testing.T, metadata map[string]any) *policy.ResponseHeaderContext {
	t.Helper()
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  metadata,
		},
		RequestHeaders:  policy.NewHeaders(nil),
		ResponseHeaders: policy.NewHeaders(nil),
		ResponseStatus:  200,
	}
}

// ─── resolver-bearing routes ─────────────────────────────────────────────────
//
// Everything above builds contexts with no resolver, so those tests are the gateway-without-a-
// resolver path and must keep passing untouched. What follows covers the route that carries one,
// where the capability arrives in the mirrored headers or the resolver's attributes.

const modernVersion = "2026-07-28"

// newHeaderCtx builds a header-phase context on a route whose resolver ran.
//
// mcp.body.present is set for every caller: the resolver publishes it for any body it
// received, so a fixture that omits it models a state the engine cannot produce. Use
// newHeaderCtxNoBody for the one case that legitimately publishes nothing.
// newHeaderCtxNoResolver is the same request on a route that carries no resolver, which is what
// makes the header phase stand aside.
func newHeaderCtxNoResolver(t *testing.T, method string, headers map[string][]string, attrs map[string]string) *policy.RequestHeaderContext {
	t.Helper()
	c := newHeaderCtx(t, method, headers, attrs)
	c.APIKind, c.ResolvedOperation = "", ""
	delete(c.Metadata, metadataBodyResolved)
	return c
}

// newResolvedRequestCtx is a body-phase context on a route whose resolver already ran.
func newResolvedRequestCtx(t *testing.T, method string, headers map[string][]string, body []byte) *policy.RequestContext {
	t.Helper()
	c := newRequestCtx(t, method, headers, body)
	c.APIKind, c.ResolvedOperation = policy.APIKindMCP, "mcp"
	c.Metadata = map[string]any{metadataBodyResolved: true}
	return c
}

func newHeaderCtx(t *testing.T, method string, headers map[string][]string, attrs map[string]string) *policy.RequestHeaderContext {
	t.Helper()
	withBody := map[string]string{attrBodyPresent: "true"}
	for k, v := range attrs {
		withBody[k] = v
	}
	return newHeaderCtxRaw(t, method, headers, withBody)
}

// newHeaderCtxNoBody models a request that reached the resolver carrying no body.
func newHeaderCtxNoBody(t *testing.T, method string, headers map[string][]string) *policy.RequestHeaderContext {
	t.Helper()
	return newHeaderCtxRaw(t, method, headers, nil)
}

func newHeaderCtxRaw(t *testing.T, method string, headers map[string][]string, attrs map[string]string) *policy.RequestHeaderContext {
	t.Helper()
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:            "test-request-id",
			Metadata:             map[string]any{metadataBodyResolved: true},
			OperationPath:        "/mcp",
			APIKind:              policy.APIKindMCP,
			ResolvedOperation:    "mcp",
			ResolutionAttributes: policy.NewResolutionAttributes(attrs),
		},
		Headers: policy.NewHeaders(headers),
		Method:  method,
		Path:    "/mcp",
		Scheme:  "http",
	}
}

// legacyAttrs is what the resolver publishes for a body naming this operation.
func legacyAttrs(method, name string) map[string]string {
	attrs := map[string]string{attrBodyMethod: method, attrBodyJSONRPCID: "1"}
	if name != "" {
		attrs[attrBodyCapabilityName] = name
	}
	return attrs
}

// modernHeaders is what a 2026-07-28 client mirrors alongside its body.
func modernHeaders(method, name string) map[string][]string {
	headers := map[string][]string{headerProtocolVersion: {modernVersion}, headerMcpMethod: {method}}
	if name != "" {
		headers[headerMcpName] = []string{name}
	}
	return headers
}

func TestMode_AsksForBothRequestPhases(t *testing.T) {
	m := newToolPolicy(t, "toolA", 5).Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeBuffer {
		t.Fatalf("request modes = %v/%v, want Process/Buffer: which phase decides is settled per request", m.RequestHeaderMode, m.RequestBodyMode)
	}
	// The delegates replay here whichever phase invoked them.
	if m.ResponseHeaderMode != policy.HeaderModeProcess {
		t.Fatalf("ResponseHeaderMode = %v, want Process", m.ResponseHeaderMode)
	}
}

func TestOnRequestHeaders_LimitsFromResolverAttributes(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	attrs := legacyAttrs("tools/call", "toolA")

	if action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil); action != nil {
		t.Fatalf("expected the first request to be allowed, got %T", action)
	}

	action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on limit breach, got %T", action)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_LimitsFromMirroredHeaders(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	headers := modernHeaders("tools/call", "toolA")

	// No body attributes at all: a modern request is identified from its headers alone.
	if action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", headers, nil), nil); action != nil {
		t.Fatalf("expected the first request to be allowed, got %T", action)
	}
	if action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", headers, nil), nil); action == nil {
		t.Fatalf("expected the second request to be limited")
	}
}

// Both eras must land in the same bucket: a re-bucketing here would silently reset every counter
// on upgrade, with nothing failing to show it.
func TestOnRequestHeaders_BothErasReachTheSameDelegate(t *testing.T) {
	keysOf := func(p *McpRateLimitPolicy) []string {
		var keys []string
		p.delegates.Range(func(k, _ any) bool {
			keys = append(keys, k.(string))
			return true
		})
		return keys
	}

	viaAttributes := newToolPolicy(t, "toolA", 5)
	viaAttributes.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA")), nil)

	viaHeaders := newToolPolicy(t, "toolA", 5)
	viaHeaders.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", modernHeaders("tools/call", "toolA"), nil), nil)

	viaBody := newToolPolicy(t, "toolA", 5)
	body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
	viaBody.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, body), nil)

	attrKeys, headerKeys, bodyKeys := keysOf(viaAttributes), keysOf(viaHeaders), keysOf(viaBody)
	if len(bodyKeys) != 1 {
		t.Fatalf("expected exactly one delegate, got %v", bodyKeys)
	}
	if !slices.Equal(attrKeys, bodyKeys) || !slices.Equal(headerKeys, bodyKeys) {
		t.Fatalf("delegate keys diverge: attributes=%v headers=%v body=%v", attrKeys, headerKeys, bodyKeys)
	}
}

func TestOnRequestHeaders_RejectsUnreadableBody(t *testing.T) {
	tests := []struct {
		reason      string
		wantCode    int
		wantMessage string
	}{
		{reasonSyntaxError, jsonRpcErrCodeParseError, "Request body is not valid JSON"},
		{reasonInvalidMemberType, jsonRpcErrCodeInvalidRequest, "Request body has a member of the wrong type"},
		{reasonNotAnObject, jsonRpcErrCodeInvalidRequest, "Request body is not a single JSON-RPC request object"},
		{reasonAmbiguous, jsonRpcErrCodeInvalidRequest, "Ambiguous MCP request: body names a member more than once"},
		{"a reason this build does not know", jsonRpcErrCodeInvalidRequest, "Invalid MCP request body"},
	}
	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			p := newToolPolicy(t, "toolA", 5)
			reqCtx := newHeaderCtx(t, "POST", nil, map[string]string{attrBodyUnusable: tc.reason})

			action := p.OnRequestHeaders(context.Background(), reqCtx, nil)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected a rejection, got %T", action)
			}
			if resp.StatusCode != 400 {
				t.Fatalf("expected status 400, got %d", resp.StatusCode)
			}
			var parsed map[string]any
			if err := json.Unmarshal(resp.Body, &parsed); err != nil {
				t.Fatalf("expected a JSON-RPC error body: %v", err)
			}
			errObj := parsed["error"].(map[string]any)
			if errObj["code"] != float64(tc.wantCode) {
				t.Fatalf("expected code %d, got %v", tc.wantCode, errObj["code"])
			}
			if errObj["message"] != tc.wantMessage {
				t.Fatalf("expected message %q, got %v", tc.wantMessage, errObj["message"])
			}
			// No facts are published alongside a reason, so there is no id to echo.
			if parsed["id"] != nil {
				t.Fatalf("expected a null id, got %v", parsed["id"])
			}
		})
	}
}

// A body that read fine but named no operation forwards. This policy restricts, so an
// unidentified request must not be counted against a bucket that is not its own — the case being
// a legacy client POSTing a JSON-RPC response, which carries an id and a result and no method.
//
// The rule is measured against `methods: ["*"]`, the one config that would otherwise catch it: a
// tools rule needs a capability type, which an empty method yields none of, so it would appear to
// pass whether or not the guard is there.
func TestOnRequestHeaders_ForwardsWhenNoOperationIsNamed(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		attrs   map[string]string
	}{
		{"legacy response POST: an id and no method", nil, map[string]string{attrBodyJSONRPCID: "1"}},
		{"nothing published at all", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newWildcardMethodResolverPolicy(t, 1)
			// Two requests against a limit of one: if either were counted the second would block.
			for i := range 2 {
				reqCtx := newHeaderCtx(t, "POST", tc.headers, tc.attrs)
				if action := p.OnRequestHeaders(context.Background(), reqCtx, nil); action != nil {
					t.Fatalf("request %d: expected it to be forwarded, got %T", i+1, action)
				}
				// Nothing was identified, so no capability metadata may be published either —
				// a downstream policy reading an empty mcp.method would be reading a guess.
				if _, published := reqCtx.Metadata[metadataMcpMethod]; published {
					t.Fatalf("request %d: expected no capability metadata, got %v", i+1, reqCtx.Metadata)
				}
			}
		})
	}
}

// The forward above is legacy-only: 2026-07-28 requires Mcp-Method, and forwarding a request
// without it would let a client go uncounted by withholding one header.
func TestOnRequestHeaders_ModernWithoutMcpMethodIsRejected(t *testing.T) {
	p := newWildcardMethodResolverPolicy(t, 1)
	reqCtx := newHeaderCtx(t, "POST", map[string][]string{headerProtocolVersion: {modernVersion}}, nil)
	resp, ok := p.OnRequestHeaders(context.Background(), reqCtx, nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 400 {
		t.Fatalf("expected a 400 rejection, got %#v", resp)
	}
	var env struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil || env.Error.Code != jsonRpcErrCodeHeaderMismatch {
		t.Fatalf("error code = %d (%v), want %d; body %s", env.Error.Code, err, jsonRpcErrCodeHeaderMismatch, resp.Body)
	}
	assertMirroredHeaderFault(t, resp,
		`{"error":{"code":-32020,"message":"Mcp-Method header is required"},"id":null,"jsonrpc":"2.0"}`)
}

// assertMirroredHeaderFault checks a missing or undecodable mirrored header is declared as an
// invalid-header validation fault, and that declaring it leaves the client's 400 as it was.
func assertMirroredHeaderFault(t *testing.T, resp policy.ImmediateResponse, wantBody string) {
	t.Helper()
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected a fault, got IsFault %v Fault %+v", resp.IsFault, resp.Fault)
	}
	if f := resp.Fault; f.Code != policy.FaultCodeInvalidRequestHeader || f.Type != policy.FaultTypeValidation || f.Direction != policy.DirectionRequest {
		t.Fatalf("fault = %s/%s/%s, want %s/%s/%s", f.Code, f.Type, f.Direction,
			policy.FaultCodeInvalidRequestHeader, policy.FaultTypeValidation, policy.DirectionRequest)
	}
	if resp.StatusCode != 400 || string(resp.Body) != wantBody || resp.Headers["content-type"] != "application/json" {
		t.Fatalf("client response changed: %d %v %s", resp.StatusCode, resp.Headers, resp.Body)
	}
}

func newWildcardMethodResolverPolicy(t *testing.T, limit int) *McpRateLimitPolicy {
	t.Helper()
	return newPolicy(t, map[string]any{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"methods": []any{
			map[string]any{
				"name":   "*",
				"limits": []any{map[string]any{"limit": float64(limit), "duration": "1m"}},
			},
		},
	})
}

func newWildcardResolverToolPolicy(t *testing.T, limit int) *McpRateLimitPolicy {
	t.Helper()
	return newPolicy(t, map[string]any{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"tools": []any{
			map[string]any{
				"name":   "*",
				"limits": []any{map[string]any{"limit": float64(limit), "duration": "1m"}},
			},
		},
	})
}

// A tools/call must mirror Mcp-Name; a withheld or undecodable one is rejected rather than going
// uncounted under an empty name that matches no tools rule.
func TestOnRequestHeaders_ModernWithoutRequiredMcpNameIsRejected(t *testing.T) {
	body := map[string]string{
		attrBodyMethod:         "tools/call",
		attrBodyCapabilityName: "toolA",
	}
	modern := func(name string) map[string][]string {
		h := map[string][]string{headerProtocolVersion: {modernVersion}, headerMcpMethod: {"tools/call"}}
		if name != "" {
			h[headerMcpName] = []string{name}
		}
		return h
	}

	for _, tc := range []struct {
		name    string
		headers map[string][]string
	}{
		{"Mcp-Name withheld", modern("")},
		{"Mcp-Name will not decode", modern("=?base64?not-valid-base64!?=")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newWildcardResolverToolPolicy(t, 100)
			resp, ok := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", tc.headers, body), nil).(policy.ImmediateResponse)
			if !ok || resp.StatusCode != 400 {
				t.Fatalf("expected a 400 rejection, got %#v", resp)
			}
			var env struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(resp.Body, &env); err != nil || env.Error.Code != jsonRpcErrCodeHeaderMismatch {
				t.Fatalf("error code = %d (%v), want %d; body %s", env.Error.Code, err, jsonRpcErrCodeHeaderMismatch, resp.Body)
			}
			assertMirroredHeaderFault(t, resp,
				`{"error":{"code":-32020,"message":"Mcp-Name header is required for tools/call"},"id":null,"jsonrpc":"2.0"}`)
		})
	}
}

// Intended behaviour, not an omission. The resolver publishes a name whenever params.name or
// params.uri is present, so resources/subscribe carries its URI — but taking it would make an
// exact-URI rule start matching requests that only a wildcard rule reaches today, and findMatches
// enforces every match, so that can only add rejections. Both paths narrow identically.
func TestCapabilityFrom_TakesTheNameOnlyForTheThreeMethodsThatNameOne(t *testing.T) {
	tests := []struct {
		method      string
		name        string
		wantType    string
		wantCapName string
	}{
		{"tools/call", "toolA", "tool", "toolA"},
		{"tools/list", "toolA", "tool", ""},
		{"resources/read", "file:///logs", "resource", "file:///logs"},
		{"resources/subscribe", "file:///logs", "resource", ""},
		{"prompts/get", "promptA", "prompt", "promptA"},
		{"prompts/list", "promptA", "prompt", ""},
		{"ping", "", "", ""},
		{"server/discover", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			capType, capName := capabilityFrom(tc.method, tc.name)
			if capType != tc.wantType || capName != tc.wantCapName {
				t.Fatalf("got (%q,%q), want (%q,%q)", capType, capName, tc.wantType, tc.wantCapName)
			}
		})
	}
}

// The end-to-end half of the narrowing: an exact-URI rule stays out of resources/subscribe.
func TestOnRequestHeaders_SubscribeUriDoesNotMatchAnExactRule(t *testing.T) {
	p := newPolicy(t, map[string]any{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"resources": []any{
			map[string]any{
				"name":   "file:///logs",
				"limits": []any{map[string]any{"limit": float64(1), "duration": "1m"}},
			},
		},
	})
	attrs := legacyAttrs("resources/subscribe", "file:///logs")
	for i := range 2 {
		if action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil); action != nil {
			t.Fatalf("request %d: expected subscribe to stay ungoverned by an exact-URI rule, got %T", i+1, action)
		}
	}
}

// The rejection echoes the id as the JSON token the client sent, so its correlation matches. The
// resolver publishes the token verbatim — 7 for a number, "7" with its quotes for a string.
func TestOnRequestHeaders_RateLimitErrorEchoesTheIDType(t *testing.T) {
	tests := []struct {
		name   string
		attr   string
		wantID any
	}{
		{"number", `7`, float64(7)},
		{"a string that looks numeric", `"7"`, "7"},
		{"a plain string", `"req-7"`, "req-7"},
		{"an empty string is still a string", `""`, ""},
		{"absent", "", nil},
		// The kernel drops an attribute value over 256 chars rather than truncating it, and a
		// string id costs two more for its quotes — so a very long one simply never arrives.
		// A null id beats one that was silently altered.
		{"dropped by the kernel's length bound", "", nil},
		// Defensive; see TestMcpFacts_RequestIDIsValidJSONOrEmpty for why the guard exists,
		// since the envelope reaches null either way.
		{"a half token", `{"a":`, nil},
		{"not JSON at all", "not-json", nil},
		{"two tokens", "7 8", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newToolPolicy(t, "toolA", 1)
			attrs := map[string]string{attrBodyMethod: "tools/call", attrBodyCapabilityName: "toolA"}
			if tc.attr != "" {
				attrs[attrBodyJSONRPCID] = tc.attr
			}

			p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil)
			action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected the second request to be limited, got %T", action)
			}
			var parsed map[string]any
			if err := json.Unmarshal(resp.Body, &parsed); err != nil {
				t.Fatalf("expected a JSON-RPC error body: %v", err)
			}
			if parsed["id"] != tc.wantID {
				t.Fatalf("expected id %#v, got %#v", tc.wantID, parsed["id"])
			}
		})
	}
}

// Each hook belongs to exactly one kind of route. The executor already gates on Mode(), so these
// guards are unreachable in production — they stop a direct call in a test deciding twice, or
// deciding without facts.
func TestHooksDeferToTheOtherPhase(t *testing.T) {
	t.Run("header phase does nothing without a resolver", func(t *testing.T) {
		p := newToolPolicy(t, "toolA", 1)
		attrs := legacyAttrs("tools/call", "toolA")
		for i := range 2 {
			if action := p.OnRequestHeaders(context.Background(), newHeaderCtxNoResolver(t, "POST", nil, attrs), nil); action != nil {
				t.Fatalf("request %d: expected the header phase to defer, got %T", i+1, action)
			}
		}
		// Prove the stand-in still detects what it claims to: the same input on a resolver
		// route does limit, so the skip above is the guard and not an inert fixture.
		resolver := newToolPolicy(t, "toolA", 1)
		resolver.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil)
		if action := resolver.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, attrs), nil); action == nil {
			t.Fatalf("control: expected a resolver route to limit the same request")
		}
	})

	t.Run("body phase does nothing on a resolver route", func(t *testing.T) {
		p := newToolPolicy(t, "toolA", 1)
		body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "toolA"}})
		for i := range 2 {
			action := p.OnRequestBody(context.Background(), newResolvedRequestCtx(t, "POST", nil, body), nil)
			if _, blocked := action.(policy.ImmediateResponse); blocked {
				t.Fatalf("request %d: expected the body phase to defer", i+1)
			}
		}
		// Control: the same body on a resolver-less route is limited.
		legacy := newToolPolicy(t, "toolA", 1)
		legacy.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, body), nil)
		action := legacy.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, body), nil)
		if _, blocked := action.(policy.ImmediateResponse); !blocked {
			t.Fatalf("control: expected a resolver-less route to limit the same request")
		}
	})
}

func TestOnRequestHeaders_PublishesCapabilityMetadata(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)
	reqCtx := newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA"))

	p.OnRequestHeaders(context.Background(), reqCtx, nil)

	for key, want := range map[string]string{
		metadataMcpMethod:         "tools/call",
		metadataMcpCapabilityType: "tool",
		metadataMcpCapabilityName: "toolA",
	} {
		if got, _ := reqCtx.Metadata[key].(string); got != want {
			t.Fatalf("metadata %q: got %q, want %q", key, got, want)
		}
	}
	// The response phase replays these, so the write has to survive the hook move.
	if invoked, _ := reqCtx.Metadata[metadataInvokedDelegates].([]string); len(invoked) != 1 {
		t.Fatalf("expected one invoked delegate recorded, got %v", reqCtx.Metadata[metadataInvokedDelegates])
	}
}

func TestOnRequestHeaders_SkipsNonPost(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	attrs := legacyAttrs("tools/call", "toolA")
	for _, method := range []string{"GET", "DELETE"} {
		for range 2 {
			if action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, method, nil, attrs), nil); action != nil {
				t.Fatalf("%s: expected it to be forwarded, got %T", method, action)
			}
		}
	}
}

// The route is matched segment-exactly on the API-definition path, so a path that merely ends in
// "/mcp" is not the MCP endpoint. Matches the MCP authorization and access-control policies.
func TestOnRequestHeaders_SkipsNonMcpPaths(t *testing.T) {
	for _, path := range []string{"/resource/mcp", "/mcpx", "/"} {
		t.Run(path, func(t *testing.T) {
			p := newToolPolicy(t, "toolA", 1)
			for i := range 2 {
				reqCtx := newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA"))
				reqCtx.OperationPath = path
				if action := p.OnRequestHeaders(context.Background(), reqCtx, nil); action != nil {
					t.Fatalf("request %d: expected %q to be forwarded, got %T", i+1, path, action)
				}
			}
		})
	}

	// An empty OperationPath falls back to the downstream request path, so a real POST /mcp is
	// still limited rather than silently skipped.
	t.Run("empty operation path falls back to the request path", func(t *testing.T) {
		p := newToolPolicy(t, "toolA", 1)
		limited := false
		for range 2 {
			reqCtx := newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA"))
			reqCtx.OperationPath = ""
			if action := p.OnRequestHeaders(context.Background(), reqCtx, nil); action != nil {
				limited = true
			}
		}
		if !limited {
			t.Fatal("expected the downstream /mcp path to be recognised and limited")
		}
	})

	// A subpath under /mcp is the endpoint, and is limited.
	p := newToolPolicy(t, "toolA", 1)
	for _, path := range []string{"/mcp", "/mcp/v1"} {
		reqCtx := newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA"))
		reqCtx.OperationPath = path
		p.OnRequestHeaders(context.Background(), reqCtx, nil)
	}
	reqCtx := newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA"))
	if action := p.OnRequestHeaders(context.Background(), reqCtx, nil); action == nil {
		t.Fatalf("expected /mcp and /mcp/v1 to share the bucket and breach the limit")
	}
}

// Both request paths render an unreadable body through handleUnusableBody, so the same bytes get
// the same error whether the resolver read them or this policy parsed them itself.
func TestUnreadableBodyRendersIdenticallyOnBothPaths(t *testing.T) {
	tests := []struct {
		name   string
		body   []byte
		reason string
	}{
		{"broken JSON", []byte(`{"method":`), reasonSyntaxError},
		{"a member named twice", []byte(`{"method":"tools/call","method":"tools/list"}`), reasonAmbiguous},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viaBody := newToolPolicy(t, "toolA", 5).
				OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, tc.body), nil)
			bodyResp, ok := viaBody.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected the body parse to reject, got %T", viaBody)
			}

			viaResolver := newToolPolicy(t, "toolA", 5).
				OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", nil, map[string]string{attrBodyUnusable: tc.reason}), nil)
			resolverResp, ok := viaResolver.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected the resolver path to reject, got %T", viaResolver)
			}

			if bodyResp.StatusCode != resolverResp.StatusCode || string(bodyResp.Body) != string(resolverResp.Body) {
				t.Fatalf("the two paths disagree:\n  body     %d %s\n  resolver %d %s",
					bodyResp.StatusCode, bodyResp.Body, resolverResp.StatusCode, resolverResp.Body)
			}
		})
	}
}

// A modern request carries its id in a body this policy does not read, so the rejection renders
// null rather than taking the one value a modern request would owe to the body.
func TestOnRequestHeaders_ModernRateLimitErrorHasANullID(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	headers := modernHeaders("tools/call", "toolA")
	attrs := map[string]string{attrBodyJSONRPCID: `7`}

	p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", headers, attrs), nil)
	action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", headers, attrs), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected the second request to be limited, got %T", action)
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("expected a JSON-RPC error body: %v", err)
	}
	if parsed["id"] != nil {
		t.Errorf("id = %v, want null: a modern request's id is not read from the body", parsed["id"])
	}
}

// facts.RequestID is always valid JSON or empty. The envelope reaches `"id":null` for a mangled
// attribute either way — without the guard by failing json.Marshal and falling back — so the
// guard is only observable here. It keeps a bad id from failing the whole envelope rather than
// just the id, and matches the MCP Spec Validation policy's jsonRPCID.
func TestMcpFacts_RequestIDIsValidJSONOrEmpty(t *testing.T) {
	tests := []struct {
		attr string
		want string
	}{
		{`7`, `7`},
		{`"7"`, `"7"`},
		{`""`, `""`},
		{`null`, `null`},
		{`{"a":`, ""},
		{"not-json", ""},
		{"7 8", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.attr, func(t *testing.T) {
			shared := &policy.SharedContext{
				ResolutionAttributes: policy.NewResolutionAttributes(map[string]string{attrBodyJSONRPCID: tc.attr}),
			}
			got := mcpFacts(policy.NewHeaders(nil), shared).RequestID
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if len(got) > 0 && !json.Valid(got) {
				t.Fatalf("RequestID must be valid JSON when set, got %q", got)
			}
		})
	}
}

// Every context embeds *SharedContext, so a nil one panics on any Metadata access.
func TestNilSharedContextDoesNotPanic(t *testing.T) {
	p := newToolPolicy(t, "toolA", 5)

	headerCtx := newHeaderCtx(t, "POST", nil, legacyAttrs("tools/call", "toolA"))
	headerCtx.SharedContext = nil
	if action := p.OnRequestHeaders(context.Background(), headerCtx, nil); action != nil {
		t.Fatalf("expected a request with no shared context to be forwarded, got %T", action)
	}

	respCtx := newResponseHeaderCtx(t, nil)
	respCtx.SharedContext = nil
	if mods, ok := p.OnResponseHeaders(context.Background(), respCtx, nil).(policy.DownstreamResponseHeaderModifications); !ok || len(mods.HeadersToSet) != 0 {
		t.Fatalf("expected no header modifications, got %#v", mods)
	}

	bodyCtx := newRequestCtx(t, "POST", nil, []byte(`{"method":"tools/call","params":{"name":"toolA"}}`))
	bodyCtx.SharedContext = nil
	legacy := newToolPolicy(t, "toolA", 5)
	if _, blocked := legacy.OnRequestBody(context.Background(), bodyCtx, nil).(policy.ImmediateResponse); blocked {
		t.Fatalf("expected a request with no shared context to be forwarded")
	}
}

// A modern request is limited on Mcp-Method and Mcp-Name, so the body verdict says nothing about
// it and the rules apply as usual. Rejecting that body is mcp-spec-validation's job.
func TestOnRequestHeaders_ModernUnusableBodyStillLimitsOnTheHeaders(t *testing.T) {
	for _, reason := range []string{reasonSyntaxError, reasonInvalidMemberType, reasonNotAnObject, reasonAmbiguous} {
		t.Run(reason, func(t *testing.T) {
			p := newToolPolicy(t, "toolA", 1)
			headers := modernHeaders("tools/call", "toolA")
			attrs := map[string]string{attrBodyUnusable: reason}

			if action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", headers, attrs), nil); action != nil {
				t.Fatalf("the first request must pass, got %T", action)
			}
			action := p.OnRequestHeaders(context.Background(), newHeaderCtx(t, "POST", headers, attrs), nil)
			if resp, ok := action.(policy.ImmediateResponse); !ok || resp.StatusCode != 429 {
				t.Fatalf("expected the second request to be limited, got %#v", action)
			}
		})
	}
}

func TestDecodeRequestID(t *testing.T) {
	// The id is whatever the client sent, and the gateway re-emits it verbatim. A string must
	// stay a string and a number a number: a client matching on the value it sent would not
	// recognise the other spelling.
	if got := decodeRequestID(json.RawMessage(`"req-1"`)); got != "req-1" {
		t.Fatalf("expected string id req-1, got %#v", got)
	}
	if got := decodeRequestID(json.RawMessage(`1`)); got != json.Number("1") {
		t.Fatalf("expected numeric id 1, got %#v", got)
	}
	// An integer beyond float64 precision must not be rounded.
	if got := decodeRequestID(json.RawMessage(`9007199254740993`)); got != json.Number("9007199254740993") {
		t.Fatalf("expected numeric id 9007199254740993, got %#v", got)
	}
	// Absent, explicit null, and unparseable all collapse to nil, which the gateway renders
	// as the null JSON-RPC requires for an id it could not determine.
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`{bad`)} {
		if got := decodeRequestID(raw); got != nil {
			t.Fatalf("expected nil id for %q, got %#v", raw, got)
		}
	}
}

// assertDescribedJSONRPC checks the described error and the fallback body beside it.
//
// The description is what the gateway's renderer reads, and supplies what a status alone
// cannot: the specific code and the id. The body is the same failure in the shape this
// policy has always written, for a gateway with no renderer — assertFallbackBodyAgrees
// checks the two cannot drift apart.
func assertDescribedJSONRPC(t *testing.T, resp policy.ImmediateResponse, wantCode int, wantID any) {
	t.Helper()
	if resp.Fault == nil || resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.Code == nil {
		t.Fatalf("expected a described JSON-RPC code, got %+v", resp.Fault)
	}
	if *resp.Fault.JSONRPC.Code != wantCode {
		t.Fatalf("expected code %d, got %d", wantCode, *resp.Fault.JSONRPC.Code)
	}
	if resp.Fault.JSONRPC.ID != wantID {
		t.Fatalf("expected id %v, got %v", wantID, resp.Fault.JSONRPC.ID)
	}
	assertFallbackBodyAgrees(t, resp)
}

// TestRateLimitedResponsePropagatesDelegateFault covers the rewrite this policy performs on
// the delegate's throttle response. Only the body and headers are replaced with a JSON-RPC
// envelope, so the delegate's own fault declaration must survive — a field-by-field copy
// would silently drop it, and the throttle would never reach the fault policies.
func TestRateLimitedResponsePropagatesDelegateFault(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	makeBody := func() []byte {
		b, _ := json.Marshal(map[string]any{"id": "1", "method": "tools/call", "params": map[string]any{"name": "toolA"}})
		return b
	}

	p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, makeBody()), nil)
	second := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, makeBody()), nil)

	resp, ok := second.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on limit breach, got %T", second)
	}
	if !resp.IsFault {
		t.Fatalf("expected the delegate's IsFault to survive the JSON-RPC rewrite")
	}
	if resp.Fault == nil {
		t.Fatalf("expected the delegate's Fault to survive the JSON-RPC rewrite")
	}
	if resp.Fault.Type != "throttling" {
		t.Fatalf("expected Error.Type=%q, got %q", "throttling", resp.Fault.Type)
	}
	if resp.Fault.Code != policy.FaultCodeThrottledAPI {
		t.Fatalf("expected Error.Code %q, got %q", policy.FaultCodeThrottledAPI, resp.Fault.Code)
	}
	assertDescribedJSONRPC(t, resp, jsonRpcErrCodeRateLimited, "1")
}

// A large numeric id reaches the description exactly as the client sent it.
func TestRateLimitedResponseKeepsLargeNumericID(t *testing.T) {
	p := newToolPolicy(t, "toolA", 1)
	body := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call","params":{"name":"toolA"}}`)

	p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, body), nil)
	resp, ok := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, body), nil).(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on limit breach")
	}
	if !strings.Contains(string(resp.Body), `"id":9007199254740993`) {
		t.Fatalf("expected the raw id in the body, got %s", resp.Body)
	}
	assertDescribedJSONRPC(t, resp, jsonRpcErrCodeRateLimited, json.Number("9007199254740993"))
}

// TestMalformedRequestDeclaresFault covers this policy's own rejection: a body it cannot
// parse as MCP. Nothing was throttled, so the code must come from the reserved user block
func TestMalformedRequestDeclaresFault(t *testing.T) {
	p := newToolPolicy(t, "toolA", 10)

	action := p.OnRequestBody(context.Background(), newRequestCtx(t, "POST", nil, []byte("{not json")), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on a malformed request")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated")
	}
	if resp.Fault.Code != policy.FaultCodeInvalidRequestBody {
		t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeInvalidRequestBody, resp.Fault.Code)
	}
	if resp.Fault.Type != policy.FaultTypeValidation {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeValidation, resp.Fault.Type)
	}
	assertDescribedJSONRPC(t, resp, jsonRpcErrCodeParseError, nil)
}

// assertFallbackBodyAgrees checks the legacy JSON-RPC body that travels alongside the
// description.
//
// Both are always sent. The description is what a gateway with an error renderer uses; the
// body is what a gateway without one sends, so a policy upgraded on its own still answers a
// rejection the way it always has. Asserting they AGREE — rather than restating the literals
// a second time — is what catches the failure that matters: one of the two drifting, so the
// answer a caller gets depends on which gateway happens to be running.
func assertFallbackBodyAgrees(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	if len(resp.Body) == 0 {
		t.Fatal("Expected a fallback body alongside the description, got none")
	}

	raw := resp.Body
	wantType := "application/json"
	if after, found := strings.CutPrefix(string(raw), "data: "); found {
		// SSE framing: the envelope is the event's data member.
		raw = []byte(strings.TrimSuffix(after, "\n\n"))
		wantType = "text/event-stream"
	}
	if got := resp.Headers["Content-Type"] + resp.Headers["content-type"]; got != wantType {
		t.Fatalf("Expected Content-Type %q for the fallback body, got %q", wantType, got)
	}

	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&envelope); err != nil {
		t.Fatalf("Fallback body is not a JSON-RPC envelope: %v (%q)", err, raw)
	}
	if envelope.JSONRPC != "2.0" {
		t.Fatalf("Expected jsonrpc 2.0 in the fallback body, got %q", envelope.JSONRPC)
	}
	if resp.Fault == nil || resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.Code == nil {
		t.Fatalf("Expected a described JSON-RPC error to compare against, got %+v", resp.Fault)
	}
	if envelope.Error.Code != *resp.Fault.JSONRPC.Code {
		t.Fatalf("Fallback body code %d disagrees with the described code %d",
			envelope.Error.Code, *resp.Fault.JSONRPC.Code)
	}
	if envelope.Error.Message != resp.Fault.Message {
		t.Fatalf("Fallback body message %q disagrees with the described message %q",
			envelope.Error.Message, resp.Fault.Message)
	}
	if !sameJSONRPCID(envelope.ID, resp.Fault.JSONRPC.ID) {
		t.Fatalf("Fallback body id %v disagrees with the described id %v",
			envelope.ID, resp.Fault.JSONRPC.ID)
	}
}

// sameJSONRPCID compares two decoded JSON-RPC ids through their JSON encoding rather than
// with ==, so the comparison does not depend on how each side decoded a number.
func sameJSONRPCID(fromBody, described any) bool {
	a, errA := json.Marshal(fromBody)
	b, errB := json.Marshal(described)
	return errA == nil && errB == nil && string(a) == string(b)
}
