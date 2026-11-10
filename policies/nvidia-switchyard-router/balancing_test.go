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
	"fmt"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// balancedParams has three efficient models weighted 3:1:1.
func balancedParams(endpoint, balancing string) map[string]interface{} {
	params := testParams(endpoint)
	params["modelPool"] = []interface{}{
		map[string]interface{}{"provider": "openai-provider", "model": "gpt-4o-mini", "tier": "efficient", "weight": 3},
		map[string]interface{}{"provider": "bedrock-provider", "model": "nova-lite", "tier": "efficient"},
		map[string]interface{}{"provider": "gemini-provider", "model": "gemini-flash", "tier": "efficient", "weight": json.Number("1")},
		map[string]interface{}{"provider": "anthropic-provider", "model": "claude-sonnet-5-5", "tier": "capable"},
	}
	params["tierBalancing"] = balancing
	return params
}

// models routes n requests and counts the models they went to. session
// gives request i its session header, or none when it returns "".
func models(t *testing.T, p *SwitchyardRouterPolicy, n int, session func(i int) string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		var headers map[string][]string
		if id := session(i); id != "" {
			headers = map[string][]string{"x-switchyard-session-id": {id}}
		}
		_, model := upstreamAndModel(t, routed(t, p.OnRequestBody(context.Background(), requestContext(chatBody, headers), nil)))
		counts[model]++
	}
	return counts
}

func noSession(int) string { return "" }

func TestFirstBalancingUsesFirstModel(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	for _, balancing := range []string{"", "first"} {
		params := balancedParams(srv.URL, balancing)
		if balancing == "" {
			delete(params, "tierBalancing")
		}
		p := newPolicy(t, params)
		if got := models(t, p, 10, noSession); got["gpt-4o-mini"] != 10 {
			t.Fatalf("%q: models = %v", balancing, got)
		}
	}
}

func TestRoundRobinFollowsWeights(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, balancedParams(srv.URL, "round_robin"))

	got := models(t, p, 50, noSession)
	if got["gpt-4o-mini"] != 30 || got["nova-lite"] != 10 || got["gemini-flash"] != 10 {
		t.Fatalf("models = %v, want 30/10/10", got)
	}
}

func TestRoundRobinSwitchesUpstreamWithModel(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, balancedParams(srv.URL, "round_robin"))
	want := map[string]string{"gpt-4o-mini": "openai-provider", "nova-lite": "bedrock-provider", "gemini-flash": "gemini-provider"}
	for i := 0; i < 5; i++ {
		upstream, model := upstreamAndModel(t, routed(t, p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil)))
		if want[model] != upstream {
			t.Fatalf("model %s sent to %s", model, upstream)
		}
	}
}

func TestSessionAffinityKeepsSessionsOnOneModel(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, balancedParams(srv.URL, "session_affinity"))

	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("run-%d", i)
		if got := models(t, p, 5, func(int) string { return id }); len(got) != 1 {
			t.Fatalf("session %s spread over %v", id, got)
		}
	}

	spread := models(t, p, 600, func(i int) string { return fmt.Sprintf("session-%d", i) })
	if spread["gpt-4o-mini"] < 300 || spread["nova-lite"] < 60 || spread["gemini-flash"] < 60 {
		t.Fatalf("sessions not spread by weight: %v", spread)
	}

	if got := models(t, p, 50, noSession); got["gpt-4o-mini"] != 30 {
		t.Fatalf("requests without a session should rotate, got %v", got)
	}
}

func TestSessionAffinityUsesHarnessSession(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, balancedParams(srv.URL, "session_affinity"))

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		reqCtx := requestContext(chatBody, map[string][]string{"x-claude-code-session-id": {"cc-1"}})
		_, model := upstreamAndModel(t, routed(t, p.OnRequestBody(context.Background(), reqCtx, nil)))
		seen[model] = true
	}
	if len(seen) != 1 {
		t.Fatalf("one Claude Code session went to %v", seen)
	}
}

func TestBalancingIsSafeConcurrently(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	p := newPolicy(t, balancedParams(srv.URL, "round_robin"))
	tier := p.tiers[tierEfficient]

	var mu sync.Mutex
	counts := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			model := tier.pick(p.balancing, "").Model
			mu.Lock()
			counts[model]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts["gpt-4o-mini"] != 300 || counts["nova-lite"] != 100 || counts["gemini-flash"] != 100 {
		t.Fatalf("concurrent picks = %v", counts)
	}
}

func TestObserveOnlyReportsBalancedModel(t *testing.T) {
	srv, _ := server(t, 200, selected("efficient", "capable"))
	params := balancedParams(srv.URL, "round_robin")
	params["mode"] = "observe_only"
	p := newPolicy(t, params)

	observed := map[string]int{}
	for i := 0; i < 5; i++ {
		mods := routed(t, p.OnRequestBody(context.Background(), requestContext(chatBody, nil), nil))
		observed[mods.AnalyticsMetadata["switchyard_observed_model"].(string)]++
	}
	if observed["gpt-4o-mini"] != 3 || observed["nova-lite"] != 1 || observed["gemini-flash"] != 1 {
		t.Fatalf("observed models = %v", observed)
	}
}

func TestInvalidBalancingConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(map[string]interface{})
		wantErr string
	}{
		{"unknown balancing", func(p map[string]interface{}) { p["tierBalancing"] = "least_latency" }, "'tierBalancing'"},
		{"balancing not a string", func(p map[string]interface{}) { p["tierBalancing"] = true }, "'tierBalancing'"},
		{"zero weight", func(p map[string]interface{}) { setWeight(p, 0) }, "'modelPool[0].weight'"},
		{"weight too large", func(p map[string]interface{}) { setWeight(p, 101) }, "'modelPool[0].weight'"},
		{"fractional weight", func(p map[string]interface{}) { setWeight(p, 1.5) }, "'modelPool[0].weight'"},
		{"weight not a number", func(p map[string]interface{}) { setWeight(p, "2") }, "'modelPool[0].weight'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := balancedParams("http://switchyard.invalid", "round_robin")
			tc.mutate(params)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	params := balancedParams("http://switchyard.invalid", "round_robin")
	setWeight(params, float64(4))
	if p := newPolicy(t, params); p.tiers[tierEfficient].models[0].Weight != 4 {
		t.Fatalf("float weight not accepted: %+v", p.tiers[tierEfficient].models[0])
	}
}

func setWeight(params map[string]interface{}, weight interface{}) {
	params["modelPool"].([]interface{})[0].(map[string]interface{})["weight"] = weight
}
