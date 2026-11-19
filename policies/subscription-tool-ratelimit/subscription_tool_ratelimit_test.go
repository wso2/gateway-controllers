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

package subscriptiontoolratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func toolConditions(count int, onExceed string) string {
	return fmt.Sprintf(`[
		{"id":"requests","type":"request-count","params":{"limits":[{"count":1000,"timeUnit":"MINUTE"}]}},
		{"id":"tool-calls","type":"tool-call-count","params":{"limits":[{"count":%d,"timeAmount":1,"timeUnit":"HOUR"}],"onExceed":"%s"}}
	]`, count, onExceed)
}

func newPolicy(t *testing.T) *SubscriptionToolRateLimitPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "mcp-route", APIName: t.Name()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*SubscriptionToolRateLimitPolicy)
}

func shared(t *testing.T, subID, conditions string) *policy.SharedContext {
	md := map[string]interface{}{}
	if subID != "" {
		md[metadataKeySubscriptionID] = subID
		md[metadataKeyPlanID] = "plan-1"
		md[metadataKeyPlanConditions] = conditions
	}
	return &policy.SharedContext{APIId: "api-1", APIName: t.Name(), OperationPath: "/mcp", Metadata: md}
}

// bodyRequest is an MCP POST on a gateway without the MCP resolver.
func bodyRequest(t *testing.T, subID, conditions, body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: shared(t, subID, conditions),
		Headers:       policy.NewHeaders(map[string][]string{"mcp-session-id": {"sess-1"}}),
		Body:          &policy.Body{Content: []byte(body), Present: true, EndOfStream: true},
		Path:          "/mcp",
		Method:        "POST",
	}
}

// modernRequest is an MCP 2026-07-28 POST on a gateway with the resolver.
func modernRequest(t *testing.T, subID, conditions, method string) *policy.RequestHeaderContext {
	sc := shared(t, subID, conditions)
	sc.APIKind = policy.APIKindMCP
	sc.Metadata[metadataBodyResolved] = true
	return &policy.RequestHeaderContext{
		SharedContext: sc,
		Headers: policy.NewHeaders(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {method},
			headerMcpName:         {"get_weather"},
		}),
		Path:   "/mcp",
		Method: "POST",
	}
}

// legacyRequest is an older MCP POST whose body the resolver read.
func legacyRequest(t *testing.T, subID, conditions, method string) *policy.RequestHeaderContext {
	sc := shared(t, subID, conditions)
	sc.APIKind = policy.APIKindMCP
	sc.Metadata[metadataBodyResolved] = true
	sc.ResolutionAttributes = policy.NewResolutionAttributes(map[string]string{
		attrBodyMethod:    method,
		attrBodyJSONRPCID: "7",
	})
	return &policy.RequestHeaderContext{
		SharedContext: sc,
		Headers:       policy.NewHeaders(nil),
		Path:          "/mcp",
		Method:        "POST",
	}
}

const toolCall = `{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"get_weather"}}`

func blocked(action interface{}) (policy.ImmediateResponse, bool) {
	resp, ok := action.(policy.ImmediateResponse)
	return resp, ok
}

func TestBodyPathCountsToolCalls(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(2, "reject")
	for i := 1; i <= 2; i++ {
		if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)); isBlocked {
			t.Fatalf("call %d should pass", i)
		}
	}
	resp, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil))
	if !isBlocked || resp.StatusCode != 429 {
		t.Fatalf("expected a 429, got %#v", resp)
	}
	var body struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("body is not JSON: %s", resp.Body)
	}
	if body.JSONRPC != "2.0" || string(body.ID) != `"call-1"` || body.Error.Code != -32000 ||
		body.Error.Message != "Subscription quota exceeded: 2 tool calls per 1 hour" {
		t.Fatalf("unexpected JSON-RPC body %s", resp.Body)
	}
	if resp.Fault == nil || resp.Fault.Code != policy.FaultCodeThrottledSubscription || resp.Fault.Type != policy.FaultTypeThrottling ||
		resp.Fault.Message != "Subscription plan tool call limit exceeded" || resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.ID != "call-1" {
		t.Fatalf("unexpected fault %#v", resp.Fault)
	}
	if resp.Headers["X-RateLimit-Limit"] != "2" || resp.Headers["RateLimit-Policy"] != "2;w=3600" ||
		resp.Headers["Retry-After"] == "" || resp.Headers[mcpSessionHeader] != "sess-1" {
		t.Fatalf("unexpected headers %v", resp.Headers)
	}
}

func TestOnlyToolsCallIsCounted(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{}}`,
		`not json`,
		`[{"jsonrpc":"2.0","id":4,"method":"ping"}]`,
	} {
		for i := 0; i < 3; i++ {
			if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, body), nil)); isBlocked {
				t.Fatalf("%s must not be counted", body)
			}
		}
	}
	// The one allowed tool call is still available.
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)); isBlocked {
		t.Fatalf("first tool call should pass")
	}
}

func TestNonMcpRequestIsNotCounted(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	for i := 0; i < 3; i++ {
		req := bodyRequest(t, "sub-1", conds, toolCall)
		req.OperationPath = "/other"
		req.Path = "/other"
		if _, isBlocked := blocked(p.OnRequestBody(context.Background(), req, nil)); isBlocked {
			t.Fatalf("a non-MCP path must not be counted")
		}
		get := bodyRequest(t, "sub-1", conds, toolCall)
		get.Method = "GET"
		if _, isBlocked := blocked(p.OnRequestBody(context.Background(), get, nil)); isBlocked {
			t.Fatalf("a GET must not be counted")
		}
	}
}

func TestDuplicateMethodMemberCannotDodgeTheLimit(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping","params":{"name":"x"}}`
	p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, body), nil)
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, body), nil)); !isBlocked {
		t.Fatalf("expected the second call to be limited")
	}
}

func TestModernHeadersCountToolCalls(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	if _, isBlocked := blocked(p.OnRequestHeaders(context.Background(), modernRequest(t, "sub-1", conds, "tools/call"), nil)); isBlocked {
		t.Fatalf("first call should pass")
	}
	resp, isBlocked := blocked(p.OnRequestHeaders(context.Background(), modernRequest(t, "sub-1", conds, "tools/call"), nil))
	if !isBlocked {
		t.Fatalf("second call should be limited")
	}
	if resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.ID != nil {
		t.Fatalf("a modern request has no id to echo, got %#v", resp.Fault.JSONRPC)
	}
	// Other methods are not counted.
	if _, isBlocked := blocked(p.OnRequestHeaders(context.Background(), modernRequest(t, "sub-1", conds, "tools/list"), nil)); isBlocked {
		t.Fatalf("tools/list must not be limited")
	}
	// The resolver decided at the header phase; the body phase does nothing.
	req := bodyRequest(t, "sub-1", conds, toolCall)
	req.APIKind = policy.APIKindMCP
	req.Metadata[metadataBodyResolved] = true
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), req, nil)); isBlocked {
		t.Fatalf("body phase must not count again")
	}
}

func TestLegacyResolverFactsCountToolCalls(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	p.OnRequestHeaders(context.Background(), legacyRequest(t, "sub-1", conds, "tools/call"), nil)
	resp, isBlocked := blocked(p.OnRequestHeaders(context.Background(), legacyRequest(t, "sub-1", conds, "tools/call"), nil))
	if !isBlocked {
		t.Fatalf("second call should be limited")
	}
	if !json.Valid(resp.Body) || resp.Fault.JSONRPC == nil || fmt.Sprint(resp.Fault.JSONRPC.ID) != "7" {
		t.Fatalf("expected the id from the resolver, got %s / %#v", resp.Body, resp.Fault.JSONRPC)
	}
}

func TestToolHeaderPhaseWithoutResolverDefersToBody(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	req := modernRequest(t, "sub-1", conds, "tools/call")
	delete(req.Metadata, metadataBodyResolved)
	for i := 0; i < 3; i++ {
		if action := p.OnRequestHeaders(context.Background(), req, nil); action != nil {
			t.Fatalf("header phase must defer to the body without a resolver, got %#v", action)
		}
	}
}

func TestToolOnExceedAllow(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "allow")
	for i := 0; i < 4; i++ {
		if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)); isBlocked {
			t.Fatalf("onExceed allow must not block")
		}
	}
}

func TestToolPassThroughWithoutMetadataOrCondition(t *testing.T) {
	p := newPolicy(t)
	noTools := `[{"id":"requests","type":"request-count","params":{"limits":[{"count":1,"timeUnit":"MINUTE"}]}}]`
	for i := 0; i < 3; i++ {
		if action := p.OnRequestBody(context.Background(), bodyRequest(t, "", "", toolCall), nil); action != nil {
			t.Fatalf("missing metadata must pass through, got %#v", action)
		}
		if action := p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", noTools, toolCall), nil); action != nil {
			t.Fatalf("a plan without tool-call-count must pass through, got %#v", action)
		}
	}
}

func TestToolCountersPerSubscription(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)); !isBlocked {
		t.Fatalf("sub-1 should be limited")
	}
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-2", conds, toolCall), nil)); isBlocked {
		t.Fatalf("sub-2 has its own counter")
	}
}

func TestToolPlanChangeAppliesNewLimits(t *testing.T) {
	p := newPolicy(t)
	p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", toolConditions(1, "reject"), toolCall), nil)
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", toolConditions(1, "reject"), toolCall), nil)); !isBlocked {
		t.Fatalf("should be limited under the old plan")
	}
	if _, isBlocked := blocked(p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", toolConditions(5, "reject"), toolCall), nil)); isBlocked {
		t.Fatalf("the new plan's limit applies")
	}
}
