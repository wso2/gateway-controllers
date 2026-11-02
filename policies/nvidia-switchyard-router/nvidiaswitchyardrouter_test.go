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
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func testParams(endpoint string) map[string]interface{} {
	return map[string]interface{}{
		"modelPool": []interface{}{
			map[string]interface{}{"provider": "openai-provider", "model": "gpt-4o-mini", "tier": "efficient"},
			map[string]interface{}{"provider": "bedrock-provider", "model": "nova-lite", "tier": "efficient"},
			map[string]interface{}{"provider": "anthropic-provider", "model": "claude-sonnet-5-5", "tier": "capable"},
			map[string]interface{}{"provider": "openai-provider", "model": "gpt-4.1", "tier": "capable"},
		},
		"profile":            "coding-agents",
		"fallback":           map[string]interface{}{"mode": "model", "provider": "openai-provider", "model": "gpt-4o-mini"},
		"switchyardEndpoint": endpoint,
		"requestModel":       map[string]interface{}{"location": "payload", "identifier": "$.model"},
	}
}

func newPolicy(t *testing.T, params map[string]interface{}) *SwitchyardRouterPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*SwitchyardRouterPolicy)
}

// selected is a switchyard-server /v1/decision response choosing target.
func selected(target, fallback string) string {
	return `{"selected":{"target":"` + target + `","model":"` + target +
		`","llm_client":{"format":"openai_chat","base_url":"http://127.0.0.1:9/"},"extra_body":{}},` +
		`"fallbacks":[{"target":"` + fallback + `","model":"` + fallback +
		`","llm_client":{"format":"openai_chat","base_url":"http://127.0.0.1:9/"},"extra_body":{}}]}`
}

type recorded struct {
	body    decisionRequest
	headers http.Header
	calls   int
}

// server starts a fake switchyard-server that records the last request and
// replies with the given status and body.
func server(t *testing.T, status int, reply string) (*httptest.Server, *recorded) {
	t.Helper()
	rec := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.calls++
		rec.headers = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&rec.body); err != nil {
			t.Errorf("decode decision request: %v", err)
		}
		w.WriteHeader(status)
		w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func requestContext(body string, headers map[string][]string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(headers),
		Body:          &policy.Body{Content: []byte(body)},
		Path:          "/chat/completions",
	}
}

const chatBody = `{"model":"anything","seed":12345678901234567890,"messages":[{"role":"user","content":"fix the test"}]}`

func routed(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func upstreamAndModel(t *testing.T, mods policy.UpstreamRequestModifications) (string, string) {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("routed body is not JSON: %v", err)
	}
	upstream := ""
	if mods.UpstreamName != nil {
		upstream = *mods.UpstreamName
	}
	model, _ := body["model"].(string)
	return upstream, model
}

func TestRoutesToSelectedTier(t *testing.T) {
	srv, rec := server(t, 200, selected("capable", "efficient"))
	p := newPolicy(t, testParams(srv.URL))
	reqCtx := requestContext(chatBody, map[string][]string{"x-switchyard-session-id": {" run-42 "}})

	mods := routed(t, p.OnRequestBody(context.Background(), reqCtx, nil))

	upstream, model := upstreamAndModel(t, mods)
	if upstream != "anthropic-provider" || model != "claude-sonnet-5-5" {
		t.Fatalf("routed to %s/%s", upstream, model)
	}
	if reqCtx.Metadata["selected_provider"] != "anthropic-provider" {
		t.Fatalf("selected_provider metadata = %v", reqCtx.Metadata["selected_provider"])
	}
	if !strings.Contains(string(mods.Body), "12345678901234567890") {
		t.Fatalf("large number was not preserved: %s", mods.Body)
	}
	wantAnalytics := map[string]any{"switchyard_tier": "capable", "switchyard_profile": "coding-agents", "switchyard_outcome": "routed"}
	if !reflect.DeepEqual(mods.AnalyticsMetadata, wantAnalytics) {
		t.Fatalf("analytics = %v", mods.AnalyticsMetadata)
	}

	if rec.body.InputFormat != "openai_chat" {
		t.Fatalf("input_format = %q", rec.body.InputFormat)
	}
	var sent map[string]interface{}
	if err := json.Unmarshal(rec.body.Request, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["model"] != "coding-agents" {
		t.Fatalf("decision request model = %v, want the profile", sent["model"])
	}
	if !strings.Contains(string(rec.body.Request), `"fix the test"`) {
		t.Fatalf("conversation not sent: %s", rec.body.Request)
	}
	if got := rec.headers.Get("x-switchyard-session-id"); got != "run-42" {
		t.Fatalf("session header = %q", got)
	}
	if got := rec.headers.Get("Authorization"); got != "" {
		t.Fatalf("authorization sent without a key: %q", got)
	}
}

func TestEfficientTierUsesFirstPooledModel(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, testParams(srv.URL))
	upstream, model := upstreamAndModel(t, routed(t, p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil)))
	if upstream != "openai-provider" || model != "gpt-4o-mini" {
		t.Fatalf("routed to %s/%s", upstream, model)
	}
}

func TestOptionalKeyAndCustomSessionHeader(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["switchyardApiKey"] = "proxy-key"
	params["sessionHeader"] = "X-Agent-Run"
	p := newPolicy(t, params)

	p.OnRequestBody(context.Background(), requestContext(chatBody, map[string][]string{"x-agent-run": {"r-7"}}), nil)

	if rec.headers.Get("Authorization") != "Bearer proxy-key" {
		t.Fatalf("authorization = %q", rec.headers.Get("Authorization"))
	}
	if rec.headers.Get("x-switchyard-session-id") != "r-7" {
		t.Fatalf("session header = %q", rec.headers.Get("x-switchyard-session-id"))
	}
}

func TestNoSessionHeaderWhenClientSendsNone(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, testParams(srv.URL))
	p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil)
	if _, set := rec.headers["X-Switchyard-Session-Id"]; set {
		t.Fatal("session header sent without a session ID")
	}
}

func TestFallsBackWhenDecisionUnusable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		reply  string
		reason string
	}{
		{"server error", 502, `{"error":{"message":"boom"}}`, reasonUnavailable},
		{"unknown profile", 404, `{"error":{"message":"No route registered for model coding-agents","code":"model_not_found"}}`, reasonProfileNotFound},
		{"wrong endpoint path", 404, `404 page not found`, reasonUnavailable},
		{"not json", 200, `not json`, reasonInvalidDecision},
		{"no selected target", 200, `{"fallbacks":[]}`, reasonInvalidDecision},
		{"target is not a tier", 200, selected("strong", "weak"), reasonInvalidDecision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := server(t, tc.status, tc.reply)

			p := newPolicy(t, testParams(srv.URL))
			mods := routed(t, p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil))
			upstream, model := upstreamAndModel(t, mods)
			if upstream != "openai-provider" || model != "gpt-4o-mini" {
				t.Fatalf("fallback routed to %s/%s", upstream, model)
			}
			if mods.AnalyticsMetadata["switchyard_outcome"] != "fallback" || mods.AnalyticsMetadata["switchyard_error"] != tc.reason {
				t.Fatalf("analytics = %v, want reason %s", mods.AnalyticsMetadata, tc.reason)
			}

			params := testParams(srv.URL)
			params["fallback"] = map[string]interface{}{"mode": "error"}
			p = newPolicy(t, params)
			resp, ok := p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil).(policy.ImmediateResponse)
			if !ok || resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(resp.Body), codeDecisionFailed) {
				t.Fatalf("expected 503 %s, got %+v", codeDecisionFailed, resp)
			}
			if resp.AnalyticsMetadata["switchyard_outcome"] != "rejected" || resp.AnalyticsMetadata["switchyard_error"] != tc.reason {
				t.Fatalf("503 analytics = %v", resp.AnalyticsMetadata)
			}
		})
	}
}

func TestFallsBackOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	params := testParams(srv.URL)
	params["switchyardTimeout"] = "50ms"
	p := newPolicy(t, params)

	start := time.Now()
	mods := routed(t, p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout not applied, took %s", elapsed)
	}
	upstream, model := upstreamAndModel(t, mods)
	if upstream != "openai-provider" || model != "gpt-4o-mini" || mods.AnalyticsMetadata["switchyard_error"] != reasonTimeout {
		t.Fatalf("fallback routed to %s/%s, analytics %v", upstream, model, mods.AnalyticsMetadata)
	}
}

func TestPassesThroughBodiesItCannotRoute(t *testing.T) {
	srv, rec := server(t, 200, selected("capable", "efficient"))
	p := newPolicy(t, testParams(srv.URL))

	for _, body := range []string{"", "not json", "[1,2]", "null"} {
		mods := routed(t, p.OnRequestBody(context.Background(), requestContext(body, nil), nil))
		if mods.Body != nil || mods.UpstreamName != nil {
			t.Fatalf("body %q was modified: %+v", body, mods)
		}
	}
	if rec.calls != 0 {
		t.Fatalf("switchyard-server called %d times for unroutable bodies", rec.calls)
	}
}

func TestPrimaryProviderEntryKeepsUpstream(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["modelPool"] = []interface{}{
		map[string]interface{}{"model": "gpt-4o-mini", "tier": "efficient"},
		map[string]interface{}{"provider": "anthropic-provider", "model": "claude-sonnet-5-5", "tier": "capable"},
	}
	params["fallback"] = map[string]interface{}{"mode": "model", "model": "gpt-4o-mini"}
	p := newPolicy(t, params)
	reqCtx := requestContext(chatBody, nil)

	upstream, model := upstreamAndModel(t, routed(t, p.OnRequestBody(context.Background(), reqCtx, nil)))
	if upstream != "" || model != "gpt-4o-mini" {
		t.Fatalf("routed to %q/%s", upstream, model)
	}
	if _, set := reqCtx.Metadata["selected_provider"]; set {
		t.Fatal("selected_provider set for the primary provider")
	}
}

func TestInputFormatFromPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
		ok   bool
	}{
		{"/chat/completions", "openai_chat", true},
		{"/openai/v1/chat/completions/", "openai_chat", true},
		{"/v1/chat/completions?api-version=2024-10-21", "openai_chat", true},
		{"/v1/responses", "openai_responses", true},
		{"/v1/messages", "anthropic_messages", true},
		{"/v1/embeddings", "", false},
		{"", "", false},
	} {
		got, ok := inputFormatForPath(tc.path)
		if got != tc.want || ok != tc.ok {
			t.Errorf("inputFormatForPath(%q) = %q, %v; want %q, %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestUnknownPathUsesFallbackWithoutServer(t *testing.T) {
	srv, rec := server(t, 200, selected("capable", "efficient"))
	p := newPolicy(t, testParams(srv.URL))
	reqCtx := requestContext(chatBody, nil)
	reqCtx.Path = "/v1/embeddings"

	mods := routed(t, p.OnRequestBody(context.Background(), reqCtx, nil))
	upstream, model := upstreamAndModel(t, mods)
	if upstream != "openai-provider" || model != "gpt-4o-mini" || rec.calls != 0 || mods.AnalyticsMetadata["switchyard_error"] != reasonUnknownFormat {
		t.Fatalf("routed to %s/%s with %d server calls, analytics %v", upstream, model, rec.calls, mods.AnalyticsMetadata)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(map[string]interface{})
		wantErr string
	}{
		{"missing pool", func(p map[string]interface{}) { delete(p, "modelPool") }, "'modelPool' parameter is required"},
		{"no capable model", func(p map[string]interface{}) {
			p["modelPool"] = []interface{}{map[string]interface{}{"model": "a", "tier": "efficient"}}
			delete(p, "fallback")
		}, "at least one capable model"},
		{"bad tier", func(p map[string]interface{}) {
			p["modelPool"].([]interface{})[0].(map[string]interface{})["tier"] = "premium"
		}, "'modelPool[0].tier'"},
		{"missing model", func(p map[string]interface{}) {
			delete(p["modelPool"].([]interface{})[1].(map[string]interface{}), "model")
		}, "'modelPool[1].model'"},
		{"provider not a string", func(p map[string]interface{}) {
			p["modelPool"].([]interface{})[0].(map[string]interface{})["provider"] = 42
		}, "'modelPool[0].provider'"},
		{"duplicate entry", func(p map[string]interface{}) {
			p["modelPool"] = append(p["modelPool"].([]interface{}),
				map[string]interface{}{"provider": " openai-provider ", "model": "gpt-4.1", "tier": "efficient"})
		}, "repeats provider"},
		{"missing profile", func(p map[string]interface{}) { delete(p, "profile") }, "'profile' parameter is required"},
		{"blank profile", func(p map[string]interface{}) { p["profile"] = " " }, "'profile' parameter is required"},
		{"fallback outside pool", func(p map[string]interface{}) {
			p["fallback"] = map[string]interface{}{"mode": "model", "provider": "openai-provider", "model": "gpt-5"}
		}, "'fallback' must name a model in 'modelPool'"},
		{"fallback without model", func(p map[string]interface{}) {
			p["fallback"] = map[string]interface{}{"mode": "model"}
		}, "'fallback.model' is required"},
		{"bad fallback mode", func(p map[string]interface{}) {
			p["fallback"] = map[string]interface{}{"mode": "retry"}
		}, "'fallback.mode'"},
		{"empty session header", func(p map[string]interface{}) { p["sessionHeader"] = " " }, "'sessionHeader'"},
		{"bad mode", func(p map[string]interface{}) { p["mode"] = "shadow" }, "'mode'"},
		{"sessionFromPrompt not a bool", func(p map[string]interface{}) { p["sessionFromPrompt"] = "yes" }, "'sessionFromPrompt'"},
		{"bad promptDisclosure", func(p map[string]interface{}) { p["promptDisclosure"] = "latest_user_prompt" }, "'promptDisclosure'"},
		{"promptDisclosure not a string", func(p map[string]interface{}) { p["promptDisclosure"] = 1 }, "'promptDisclosure'"},
		{"responseHeaders not a bool", func(p map[string]interface{}) { p["responseHeaders"] = "no" }, "'responseHeaders'"},
		{"missing endpoint", func(p map[string]interface{}) { delete(p, "switchyardEndpoint") }, "'switchyardEndpoint'"},
		{"api key not a string", func(p map[string]interface{}) { p["switchyardApiKey"] = 7 }, "'switchyardApiKey'"},
		{"timeout too long", func(p map[string]interface{}) { p["switchyardTimeout"] = "30s" }, "'switchyardTimeout'"},
		{"timeout not a duration", func(p map[string]interface{}) { p["switchyardTimeout"] = "soon" }, "'switchyardTimeout'"},
		{"header location", func(p map[string]interface{}) {
			p["requestModel"] = map[string]interface{}{"location": "header", "identifier": "x-model"}
		}, "'requestModel.location' must be 'payload'"},
		{"missing requestModel", func(p map[string]interface{}) { delete(p, "requestModel") }, "'requestModel' configuration is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := testParams("http://switchyard.invalid")
			tc.mutate(params)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	params := testParams("http://switchyard.invalid")
	delete(params, "fallback")
	params["switchyardTimeout"] = ""
	params["switchyardApiKey"] = ""
	p := newPolicy(t, params)

	if p.fallbackMode != fallbackModeError || p.fallback != nil {
		t.Fatalf("fallback = %s %+v", p.fallbackMode, p.fallback)
	}
	if p.client.timeout != defaultSwitchyardTimeout || p.client.apiKey != "" {
		t.Fatalf("timeout=%s apiKey=%q", p.client.timeout, p.client.apiKey)
	}
	if p.sessionHeader != defaultSessionHeader || p.sessionFromPrompt {
		t.Fatalf("sessionHeader=%q sessionFromPrompt=%v", p.sessionHeader, p.sessionFromPrompt)
	}
	if p.mode != modeEnforce || p.client.timeout != time.Second {
		t.Fatalf("mode=%q timeout=%s", p.mode, p.client.timeout)
	}
	if p.disclosure != disclosureTaskAndToolActivity || !p.responseHeaders {
		t.Fatalf("promptDisclosure=%q responseHeaders=%v", p.disclosure, p.responseHeaders)
	}
}

func TestObserveOnlyRecordsWithoutRouting(t *testing.T) {
	srv, rec := server(t, 200, selected("capable", "efficient"))
	params := testParams(srv.URL)
	params["mode"] = "observe_only"
	p := newPolicy(t, params)
	reqCtx := requestContext(chatBody, nil)

	mods := routed(t, p.OnRequestBody(context.Background(), reqCtx, nil))

	if rec.calls != 1 {
		t.Fatalf("switchyard-server called %d times", rec.calls)
	}
	if mods.Body != nil || mods.UpstreamName != nil {
		t.Fatalf("observe-only changed the request: %+v", mods)
	}
	if _, set := reqCtx.Metadata["selected_provider"]; set {
		t.Fatal("observe-only set selected_provider")
	}
	want := map[string]any{
		"switchyard_tier":              "capable",
		"switchyard_outcome":           "observed",
		"switchyard_observed_model":    "claude-sonnet-5-5",
		"switchyard_observed_provider": "anthropic-provider",
		"switchyard_profile":           "coding-agents",
		"switchyard_mode":              "observe_only",
	}
	if !reflect.DeepEqual(mods.AnalyticsMetadata, want) {
		t.Fatalf("analytics = %v", mods.AnalyticsMetadata)
	}
}

func TestObserveOnlyNeverRejects(t *testing.T) {
	srv, _ := server(t, 502, `{"error":{"message":"boom"}}`)
	params := testParams(srv.URL)
	params["mode"] = "observe_only"
	params["fallback"] = map[string]interface{}{"mode": "error"}
	p := newPolicy(t, params)

	for _, path := range []string{"/chat/completions", "/v1/embeddings"} {
		reqCtx := requestContext(chatBody, nil)
		reqCtx.Path = path
		mods := routed(t, p.OnRequestBody(context.Background(), reqCtx, nil))
		if mods.Body != nil || mods.UpstreamName != nil {
			t.Fatalf("%s: observe-only changed the request: %+v", path, mods)
		}
		if mods.AnalyticsMetadata["switchyard_outcome"] != "decision_failed" || mods.AnalyticsMetadata["switchyard_error"] == "" {
			t.Fatalf("%s: analytics = %v", path, mods.AnalyticsMetadata)
		}
	}
}

func TestSessionFromPrompt(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["sessionFromPrompt"] = true
	p := newPolicy(t, params)

	send := func(body string, headers map[string][]string, path string) string {
		reqCtx := requestContext(body, headers)
		reqCtx.Path = path
		p.OnRequestBody(context.Background(), reqCtx, nil)
		return rec.headers.Get("x-switchyard-session-id")
	}

	turn1 := `{"model":"m","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"fix the build"}]}`
	turn2 := `{"model":"m","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"fix the build"},` +
		`{"role":"assistant","content":"ok"},{"role":"user","content":"now run the tests"}]}`
	other := `{"model":"m","messages":[{"role":"user","content":"write a poem"}]}`

	first := send(turn1, nil, "/chat/completions")
	if !strings.HasPrefix(first, "prompt-") {
		t.Fatalf("derived session = %q", first)
	}
	if got := send(turn2, nil, "/chat/completions"); got != first {
		t.Fatalf("later turn session %q differs from %q", got, first)
	}
	if got := send(other, nil, "/chat/completions"); got == first || got == "" {
		t.Fatalf("different conversation session = %q", got)
	}
	if got := send(turn1, map[string][]string{"x-switchyard-session-id": {"run-9"}}, "/chat/completions"); got != "run-9" {
		t.Fatalf("header should win, got %q", got)
	}

	parts := `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"fix the build"}]}]}`
	if got := send(parts, nil, "/v1/messages"); !strings.HasPrefix(got, "prompt-") {
		t.Fatalf("anthropic parts session = %q", got)
	}
	responses := `{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":"fix the build"}]}]}`
	if got := send(responses, nil, "/v1/responses"); !strings.HasPrefix(got, "prompt-") {
		t.Fatalf("responses session = %q", got)
	}
	if got := send(`{"model":"m","input":"fix the build"}`, nil, "/v1/responses"); !strings.HasPrefix(got, "prompt-") {
		t.Fatalf("responses string input session = %q", got)
	}
	if got := send(`{"model":"m","messages":[{"role":"system","content":"only system"}]}`, nil, "/chat/completions"); got != "" {
		t.Fatalf("no user message should give no session, got %q", got)
	}
}

func TestSessionFromPromptOffByDefault(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, testParams(srv.URL))
	p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil)
	if got := rec.headers.Get("x-switchyard-session-id"); got != "" {
		t.Fatalf("session derived without sessionFromPrompt: %q", got)
	}
}

func TestForwardsHarnessHeaders(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["sessionFromPrompt"] = true
	p := newPolicy(t, params)

	p.OnRequestBody(context.Background(), requestContext(chatBody, map[string][]string{
		"x-claude-code-session-id": {"cc-1"},
		"x-claude-code-agent-id":   {"agent-2"},
		"user-agent":               {"claude-cli/2.1.150"},
		"authorization":            {"Bearer client-secret"},
	}), nil)

	for name, want := range map[string]string{
		"x-claude-code-session-id": "cc-1",
		"x-claude-code-agent-id":   "agent-2",
		"user-agent":               "claude-cli/2.1.150",
		"x-switchyard-session-id":  "",
		"authorization":            "",
	} {
		if got := rec.headers.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestHarnessSessionSkipsPromptSession(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["sessionFromPrompt"] = true
	p := newPolicy(t, params)

	for _, headers := range []map[string][]string{
		{"session-id": {"s-1"}},
		{"x-session-id": {"s-1"}},
		{"x-codex-turn-metadata": {`{"session_id":"s-1","turn_id":"t"}`}},
	} {
		p.OnRequestBody(context.Background(), requestContext(chatBody, headers), nil)
		if got := rec.headers.Get("x-switchyard-session-id"); got != "" {
			t.Errorf("%v: derived session %q despite a harness session", headers, got)
		}
	}

	p.OnRequestBody(context.Background(), requestContext(chatBody, map[string][]string{
		"x-codex-turn-metadata": {`{"turn_id":"t"}`},
	}), nil)
	if got := rec.headers.Get("x-switchyard-session-id"); !strings.HasPrefix(got, "prompt-") {
		t.Errorf("codex metadata without a session ID should get a derived one, got %q", got)
	}
}

func TestConfiguredSessionHeaderWins(t *testing.T) {
	srv, rec := server(t, 200, selected("efficient", "capable"))
	params := testParams(srv.URL)
	params["sessionHeader"] = "x-agent-run"
	p := newPolicy(t, params)

	p.OnRequestBody(context.Background(), requestContext(chatBody, map[string][]string{
		"x-agent-run":             {"run-1"},
		"x-switchyard-session-id": {"other"},
	}), nil)
	if got := rec.headers.Get("x-switchyard-session-id"); got != "run-1" {
		t.Fatalf("session = %q", got)
	}
}

// responseHeaders runs the response phase for a request routed by p.
func responseHeaders(t *testing.T, p *SwitchyardRouterPolicy, reqCtx *policy.RequestContext) map[string]string {
	t.Helper()
	action := p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: reqCtx.SharedContext}, nil)
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	return mods.HeadersToSet
}

func TestResponseHeaders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		reply  string
		mode   string
		want   map[string]string
	}{
		{"routed", 200, selected("capable", "efficient"), "enforce",
			map[string]string{headerTier: "capable", headerOutcome: "routed"}},
		{"fallback", 502, "", "enforce",
			map[string]string{headerTier: "efficient", headerOutcome: "fallback", headerError: "unavailable"}},
		{"observed", 200, selected("capable", "efficient"), "observe_only",
			map[string]string{headerTier: "capable", headerOutcome: "observed"}},
		{"observe failure", 404, `{"error":{"code":"model_not_found"}}`, "observe_only",
			map[string]string{headerOutcome: "decision_failed", headerError: "profile_not_found"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := server(t, tc.status, tc.reply)
			params := testParams(srv.URL)
			params["mode"] = tc.mode
			p := newPolicy(t, params)
			if p.Mode().ResponseHeaderMode != policy.HeaderModeProcess {
				t.Fatal("response headers are not processed")
			}
			reqCtx := requestContext(chatBody, nil)
			p.OnRequestBody(context.Background(), reqCtx, nil)
			if got := responseHeaders(t, p, reqCtx); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("headers = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRejectionCarriesResponseHeaders(t *testing.T) {
	srv, _ := server(t, 502, "")
	params := testParams(srv.URL)
	params["fallback"] = map[string]interface{}{"mode": "error"}
	p := newPolicy(t, params)

	resp := p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil).(policy.ImmediateResponse)
	if resp.Headers[headerOutcome] != "rejected" || resp.Headers[headerError] != "unavailable" || resp.Headers["content-type"] != "application/json" {
		t.Fatalf("headers = %v", resp.Headers)
	}
}

func TestResponseHeadersCanBeTurnedOff(t *testing.T) {
	srv, _ := server(t, 502, "")
	params := testParams(srv.URL)
	params["responseHeaders"] = false
	params["fallback"] = map[string]interface{}{"mode": "error"}
	p := newPolicy(t, params)

	if p.Mode().ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatal("response headers processed while turned off")
	}
	reqCtx := requestContext(chatBody, nil)
	resp := p.OnRequestBody(context.Background(), reqCtx, nil).(policy.ImmediateResponse)
	if _, set := resp.Headers[headerOutcome]; set {
		t.Fatalf("headers = %v", resp.Headers)
	}
	if got := responseHeaders(t, p, reqCtx); len(got) != 0 {
		t.Fatalf("headers = %v", got)
	}
}

func TestPoliciesShareLongLivedConnections(t *testing.T) {
	a := newPolicy(t, testParams("http://switchyard-server:4000/v1/decision"))
	b := newPolicy(t, testParams("http://switchyard-server:4000/v1/decision"))

	if a.client.httpClient != b.client.httpClient {
		t.Fatal("policy instances do not share an HTTP client")
	}
	transport, ok := a.client.httpClient.Transport.(*http.Transport)
	if !ok || transport.IdleConnTimeout != idleConnTimeout {
		t.Fatalf("transport = %#v", a.client.httpClient.Transport)
	}
}
