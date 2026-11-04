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

package mcpauthz

import (
	"context"
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// unresolved strips the resolver marks from a header context, modelling a route without one.
func unresolved(c *policy.RequestHeaderContext) *policy.RequestHeaderContext {
	c.APIKind, c.ResolvedOperation = "", ""
	delete(c.Metadata, metadataBodyResolved)
	return c
}

// resolved marks a body-phase context as belonging to a route whose resolver already ran.
func resolved(c *policy.RequestContext) *policy.RequestContext {
	c.APIKind, c.ResolvedOperation = policy.APIKindMCP, "mcp"
	c.Metadata = map[string]any{metadataBodyResolved: true}
	return c
}

// resolvedRequest builds a header-phase POST /mcp on a resolver-bearing route. attrs is what
// the resolver published; headers is what the client sent.
// resolvedRequest builds a header-phase POST /mcp on a route whose resolver ran.
//
// mcp.body.present is set for every caller: the resolver publishes it for any body it received,
// so a fixture that omits it models a state the engine cannot produce.
func resolvedRequest(headers map[string][]string, attrs map[string]string, authCtx *policy.AuthContext) *policy.RequestHeaderContext {
	withBody := map[string]string{attrBodyPresent: "true"}
	for k, v := range attrs {
		withBody[k] = v
	}
	return resolvedRequestRaw(headers, withBody, authCtx)
}

func resolvedRequestRaw(headers map[string][]string, attrs map[string]string, authCtx *policy.AuthContext) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:            "test-request-id",
			Metadata:             map[string]any{metadataBodyResolved: true},
			AuthContext:          authCtx,
			OperationPath:        "/mcp",
			APIKind:              policy.APIKindMCP,
			ResolvedOperation:    "mcp",
			ResolutionAttributes: policy.NewResolutionAttributes(attrs),
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/mcp",
		Method:  "POST",
		Scheme:  "http",
	}
}

func runResolved(p *McpAuthzPolicy, ctx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	return p.OnRequestHeaders(context.Background(), ctx, map[string]any{})
}

// legacyAttrs is what the resolver publishes for a legacy tools/call.
func legacyAttrs(tool string) map[string]string {
	return map[string]string{
		attrBodyMethod:         "tools/call",
		attrBodyCapabilityName: tool,
	}
}

// modernHeaders is what a 2026-07-28 client sends for a tools/call.
func modernHeaders(tool string) map[string][]string {
	return map[string][]string{
		headerProtocolVersion: {"2026-07-28"},
		headerMcpMethod:       {"tools/call"},
		headerMcpName:         {tool},
	}
}

func scopedAuth(scope string) *policy.AuthContext {
	return authenticatedAuthCtx(map[string]bool{scope: true}, "user", "iss", nil, nil)
}

// assertGoverned fails unless the action is a rejection with the given status. A skip test
// that only asserts nil proves nothing about whether the input reached the policy — these
// paired assertions are what make the skip tests below meaningful.
func assertGoverned(t *testing.T, action policy.RequestHeaderAction, wantStatus int, whatFor string) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("%s: expected a %d rejection, got %T", whatFor, wantStatus, action)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s: status = %d, want %d (%s)", whatFor, resp.StatusCode, wantStatus, string(resp.Body))
	}
}

func assertSkipped(t *testing.T, action policy.RequestHeaderAction, whatFor string) {
	t.Helper()
	if action != nil {
		if resp, ok := action.(policy.ImmediateResponse); ok {
			t.Fatalf("%s: expected a skip, got %d: %s", whatFor, resp.StatusCode, string(resp.Body))
		}
		t.Fatalf("%s: expected a skip, got %T", whatFor, action)
	}
}

// ─── Mode ────────────────────────────────────────────────────────────────────

// Both request phases are asked for unconditionally; which one decides is settled per request
// by shouldParseBody, since Mode() is read once at chain-build time.
func TestMode_AsksForBothRequestPhases(t *testing.T) {
	m := (&McpAuthzPolicy{}).Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeBuffer {
		t.Errorf("request modes = %v/%v, want Process/Buffer", m.RequestHeaderMode, m.RequestBodyMode)
	}
	if m.ResponseHeaderMode != policy.HeaderModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("unexpected response modes %+v", m)
	}
}

// The route's resolver is read off the request, not a parameter, so an unknown parameter cannot
// silently leave the policy parsing a body the resolver already read.
func TestShouldParseBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared *policy.SharedContext
		want   bool
	}{
		{"nil shared context", nil, false},
		{"no resolver on the route", &policy.SharedContext{APIKind: policy.APIKindMCP}, false},
		{"an engine that never sets the marker",
			&policy.SharedContext{APIKind: policy.APIKindMCP, Metadata: map[string]any{}}, false},
		{"a marker that is not true",
			&policy.SharedContext{APIKind: policy.APIKindMCP, Metadata: map[string]any{metadataBodyResolved: false}}, false},
		{"a marker of the wrong type",
			&policy.SharedContext{APIKind: policy.APIKindMCP, Metadata: map[string]any{metadataBodyResolved: "true"}}, false},
		{"a resolver, but not on an MCP route",
			&policy.SharedContext{Metadata: map[string]any{metadataBodyResolved: true}}, false},
		{"a resolver on an MCP route",
			&policy.SharedContext{APIKind: policy.APIKindMCP,
				Metadata: map[string]any{metadataBodyResolved: true}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := !shouldParseBody(tc.shared); got != tc.want {
				t.Errorf("shouldParseBody = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── The same rules enforced from every fact source ──────────────────────────

// The backward-compatibility claim as a test: the same rule, the same request, the same
// outcome, whichever gateway it lands on and whichever era the client speaks.
func TestSameRuleEnforcedFromEverySource(t *testing.T) {
	t.Run("resolved route, legacy request — denied without the scope", func(t *testing.T) {
		ctx := resolvedRequest(nil, legacyAttrs("toolA"), scopedAuth("scope:other"))
		assertGoverned(t, runResolved(toolAOnlyPolicy(), ctx), 403, "governed tool, wrong scope")
	})
	t.Run("resolved route, legacy request — allowed with the scope", func(t *testing.T) {
		ctx := resolvedRequest(nil, legacyAttrs("toolA"), scopedAuth("scope:a"))
		assertSkipped(t, runResolved(toolAOnlyPolicy(), ctx), "governed tool, right scope")
	})

	t.Run("resolved route, modern request — denied from the mirrored headers", func(t *testing.T) {
		ctx := resolvedRequest(modernHeaders("toolA"), nil, scopedAuth("scope:other"))
		assertGoverned(t, runResolved(toolAOnlyPolicy(), ctx), 403, "modern headers, wrong scope")
	})

	// The regression this version exists to prevent: on a gateway with no resolver the
	// policy must still parse the body and still deny.
	t.Run("no resolver — still denied, by parsing the body", func(t *testing.T) {
		action := runBody(toolAOnlyPolicy(), toolCallBody("toolA"), scopedAuth("scope:other"))
		resp, ok := action.(policy.ImmediateResponse)
		if !ok || resp.StatusCode != 403 {
			t.Fatalf("a denied capability must stay denied on an old gateway, got %#v", action)
		}
	})
	t.Run("no resolver — allowed with the scope", func(t *testing.T) {
		assertPassthrough(t, runBody(toolAOnlyPolicy(), toolCallBody("toolA"), scopedAuth("scope:a")),
			"governed tool, right scope, no resolver")
	})

	// A modern client on an old gateway: the body is buffered anyway, so it decides.
	t.Run("no resolver, modern headers — the buffered body decides", func(t *testing.T) {
		ctx := createMockContext("POST", "/mcp", toolCallBody("toolA"), scopedAuth("scope:other"))
		ctx.Headers = policy.NewHeaders(modernHeaders("toolB"))
		resp, ok := ctx2action(t, toolAOnlyPolicy(), ctx).(policy.ImmediateResponse)
		if !ok || resp.StatusCode != 403 {
			t.Fatalf("the body names toolA and must be governed, whatever the header says")
		}
	})
}

func ctx2action(t *testing.T, p *McpAuthzPolicy, ctx *policy.RequestContext) policy.RequestAction {
	t.Helper()
	return p.OnRequestBody(context.Background(), ctx, map[string]any{})
}

// resources/read authorises on the URI in both eras — the regression that deleting
// getAttributeNameFromParams would cause.
func TestResourceReadAuthorisesOnTheURI(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "resource", Name: "file:///secret.txt"},
		RequiredScopes: []string{"scope:read"},
	}}}

	t.Run("legacy, from the resolver's capability name", func(t *testing.T) {
		ctx := resolvedRequest(nil, map[string]string{
			attrBodyMethod:         "resources/read",
			attrBodyCapabilityName: "file:///secret.txt",
		}, scopedAuth("scope:other"))
		assertGoverned(t, runResolved(p, ctx), 403, "resource governed by URI")
	})

	t.Run("no resolver, from params.uri", func(t *testing.T) {
		body := mcpBody("resources/read", map[string]any{"uri": "file:///secret.txt"})
		resp, ok := runBody(p, body, scopedAuth("scope:other")).(policy.ImmediateResponse)
		if !ok || resp.StatusCode != 403 {
			t.Fatal("resources/read must be governed by its URI when parsed locally")
		}
	})
}

// ─── An unreadable body is rejected on the era that reads the body ───────────

// A legacy request is governed on those bytes, so a reason means the gateway and the MCP server
// may read them differently and governing our reading would be governing a guess.
func TestUnusableBodyIsRejected(t *testing.T) {
	for _, reason := range []string{"syntax-error", "invalid-member-type", "not-an-object", "ambiguous"} {
		t.Run(reason, func(t *testing.T) {
			ctx := resolvedRequest(nil, map[string]string{attrBodyUnusable: reason}, scopedAuth("scope:a"))
			assertGoverned(t, runResolved(toolAOnlyPolicy(), ctx), 400, "unusable body")
		})
	}

	// And the same bytes on a gateway with no resolver, where the policy sees them itself.
	t.Run("no resolver, ambiguous body parsed locally", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","id":1,"Method":"tools/list","method":"tools/call","params":{"name":"toolA"}}`)
		resp, ok := runBody(toolAOnlyPolicy(), body, scopedAuth("scope:a")).(policy.ImmediateResponse)
		if !ok || resp.StatusCode != 400 {
			t.Fatalf("an ambiguous body must still be rejected without a resolver, got %#v", resp)
		}
	})
}

// ─── The accepted skips, named one by one ────────────────────────────────────

// Each of these passes through ungoverned, and each is a decision rather than an oversight.
// They are named individually so the trade is legible in the test output — a later reader
// otherwise sees only "no facts and we allow?" and closes it back.
//
// Every case here also asserts, via the governed control below, that the same policy DOES
// reject when the capability is identified. A skip test that only checks for nil would pass
// even if the request never reached the policy.
func TestAcceptedSkips(t *testing.T) {
	// The control: this policy rejects an identified toolA without the scope.
	t.Run("control — an identified capability IS governed", func(t *testing.T) {
		ctx := resolvedRequest(nil, legacyAttrs("toolA"), scopedAuth("scope:other"))
		assertGoverned(t, runResolved(toolAOnlyPolicy(), ctx), 403, "control")
	})

	cases := []struct {
		name    string
		headers map[string][]string
		attrs   map[string]string
	}{
		{"no facts at all — a bodyless POST", nil, nil},
		{
			// The one that made blanket rejection wrong: a legacy client POSTs a JSON-RPC
			// response to answer a server-initiated sampling or elicitation call. It carries
			// an id and a result and no method, and denying it breaks those flows.
			name: "a legacy JSON-RPC response, which names no method",
			// The resolver publishes the id and protocol version for a body it read fine
			// that named no operation. mcp_facts.go declares only the keys this policy
			// reads, so the id is named literally here.
			attrs: map[string]string{"mcp.body.jsonrpc.id": "1"},
		},
		{
			name: "a method addressing no capability family",
			attrs: map[string]string{
				attrBodyMethod: "initialize",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := resolvedRequest(tc.headers, tc.attrs, scopedAuth("scope:other"))
			assertSkipped(t, runResolved(toolAOnlyPolicy(), ctx), tc.name)
		})
	}

}

// The skip above is legacy-only: 2026-07-28 requires Mcp-Method, so a modern request without it
// is malformed rather than unidentified.
func TestModernRequestWithoutMcpMethodIsRejected(t *testing.T) {
	ctx := resolvedRequest(map[string][]string{headerProtocolVersion: {"2026-07-28"}},
		nil, scopedAuth("scope:other"))
	action := runResolved(toolAOnlyPolicy(), ctx)
	assertGoverned(t, action, 400, "modern request with no Mcp-Method")
	assertHeaderFault(t, ctx, action, "Mcp-Method header is required")
}

// assertHeaderFault checks that a missing-header rejection reports FaultCodeInvalidRequestHeader
// while the client still receives exactly the invalid_request response handleAuthFailure builds.
func assertHeaderFault(t *testing.T, ctx *policy.RequestHeaderContext, action policy.RequestHeaderAction, message string) {
	t.Helper()
	resp := action.(policy.ImmediateResponse)
	if resp.Fault == nil || resp.Fault.Code != policy.FaultCodeInvalidRequestHeader ||
		resp.Fault.Type != policy.FaultTypeValidation || resp.Fault.Message != message {
		t.Fatalf("fault = %+v, want %s/%s %q", resp.Fault, policy.FaultCodeInvalidRequestHeader, policy.FaultTypeValidation, message)
	}
	want := toolAOnlyPolicy().handleAuthFailure(ctx, 400, ErrorInvalidRequest, message, nil)
	if resp.StatusCode != want.StatusCode || !reflect.DeepEqual(resp.Headers, want.Headers) {
		t.Fatalf("status/headers = %d %v, want %d %v", resp.StatusCode, resp.Headers, want.StatusCode, want.Headers)
	}
	if wantBody := `{"error":"Bad Request","message":"` + message + `"}`; string(resp.Body) != wantBody {
		t.Fatalf("body = %s, want %s", resp.Body, wantBody)
	}
}

// Likewise a missing or undecodable Mcp-Name on a method that must mirror one.
func TestModernRequestWithoutRequiredMcpNameIsRejected(t *testing.T) {
	for name, headerName := range map[string][]string{
		"withheld":        nil,
		"does not decode": {"=?base64?!!!not-base64!!!?="},
	} {
		t.Run(name, func(t *testing.T) {
			headers := map[string][]string{
				headerProtocolVersion: {"2026-07-28"},
				headerMcpMethod:       {"tools/call"},
			}
			if headerName != nil {
				headers[headerMcpName] = headerName
			}
			ctx := resolvedRequest(headers, nil, scopedAuth("scope:other"))
			action := runResolved(toolAOnlyPolicy(), ctx)
			assertGoverned(t, action, 400, "Mcp-Name "+name)
			assertHeaderFault(t, ctx, action, "Mcp-Name header is required for tools/call")
		})
	}

	// A method that mirrors no name is unaffected.
	t.Run("tools/list needs no Mcp-Name", func(t *testing.T) {
		ctx := resolvedRequest(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/list"},
		}, nil, scopedAuth("scope:other"))
		assertSkipped(t, runResolved(toolAOnlyPolicy(), ctx), "tools/list")
	})
}

// ─── Metadata and the gatewayHost handshake ──────────────────────────────────

// The mcp.method / mcp.type / mcp.name writes are published for peers on every identified
// capability, governed or not — and must survive the move to the header phase.
func TestMetadataIsPublishedOnBothPaths(t *testing.T) {
	t.Run("resolved route", func(t *testing.T) {
		ctx := resolvedRequest(nil, legacyAttrs("toolZ"), nil)
		// toolZ matches no rule, so this is an ungoverned invocation.
		assertSkipped(t, runResolved(toolAOnlyPolicy(), ctx), "ungoverned invocation")
		if got := ctx.Metadata[MetadataMcpCapabilityName]; got != "toolZ" {
			t.Errorf("mcp.name = %v, want toolZ", got)
		}
		if got := ctx.Metadata[MetadataMcpCapabilityType]; got != "tool" {
			t.Errorf("mcp.type = %v, want tool", got)
		}
	})

	t.Run("no resolver", func(t *testing.T) {
		ctx := createMockContext("POST", "/mcp", toolCallBody("toolZ"), nil)
		assertPassthrough(t, ctx2action(t, toolAOnlyPolicy(), ctx), "ungoverned invocation")
		if got := ctx.Metadata[MetadataMcpCapabilityName]; got != "toolZ" {
			t.Errorf("mcp.name = %v, want toolZ", got)
		}
	})
}

// gatewayHost is written by mcp-auth into shared metadata and read here to build the
// resource_metadata URL in the WWW-Authenticate challenge. Both policies read the same route
// state, so both land in the same phase and the ordering holds.
func TestGatewayHostReachesTheChallengeOnBothPaths(t *testing.T) {
	t.Run("resolved route", func(t *testing.T) {
		ctx := resolvedRequest(nil, legacyAttrs("toolA"), scopedAuth("scope:other"))
		ctx.Metadata["gatewayHost"] = "gw.example.com"
		resp := runResolved(toolAOnlyPolicy(), ctx).(policy.ImmediateResponse)
		if got := resp.Headers[WWWAuthenticateHeader]; !strings.Contains(got, "gw.example.com") {
			t.Errorf("WWW-Authenticate = %q, want it to name the gateway host", got)
		}
	})

	t.Run("no resolver", func(t *testing.T) {
		ctx := createMockContext("POST", "/mcp", toolCallBody("toolA"), scopedAuth("scope:other"))
		ctx.Metadata["gatewayHost"] = "gw.example.com"
		resp := ctx2action(t, toolAOnlyPolicy(), ctx).(policy.ImmediateResponse)
		if got := resp.Headers[WWWAuthenticateHeader]; !strings.Contains(got, "gw.example.com") {
			t.Errorf("WWW-Authenticate = %q, want it to name the gateway host", got)
		}
	})
}

// ─── The header phase defers when there is no resolver ───────────────────────

// Mode() asks for both request phases, so the engine does call the header hook on a route with
// no resolver. There are no facts to decide on there, and OnRequestBody parses the body instead,
// so this pins that the header phase decides nothing.
func TestHeaderPhaseDecidesNothingWithoutAResolver(t *testing.T) {
	ctx := unresolved(resolvedRequest(nil, legacyAttrs("toolA"), scopedAuth("scope:other")))
	assertSkipped(t, runResolved(toolAOnlyPolicy(), ctx),
		"a route with no resolver must not decide at the header phase")
}

// And the body phase stands down when the header phase already decided.
func TestBodyPhaseStandsDownOnAResolvedRoute(t *testing.T) {
	ctx := resolved(createMockContext("POST", "/mcp", toolCallBody("toolA"), scopedAuth("scope:other")))
	assertPassthrough(t, ctx2action(t, toolAOnlyPolicy(), ctx),
		"the body phase must not authorize twice on a resolved route")
}

// A modern request is governed on Mcp-Method and Mcp-Name, so the body verdict says nothing
// about the decision and the rules apply as usual. Rejecting that body is
// mcp-spec-validation's job.
func TestUnusableBodyOnAModernRequestStillGovernsOnTheHeaders(t *testing.T) {
	for _, reason := range []string{"syntax-error", "invalid-member-type", "not-an-object", "ambiguous"} {
		t.Run(reason+", governed capability", func(t *testing.T) {
			ctx := resolvedRequest(modernHeaders("toolA"), map[string]string{attrBodyUnusable: reason}, scopedAuth("scope:other"))
			assertGoverned(t, runResolved(toolAOnlyPolicy(), ctx), 403, "a governed capability named in the headers")
		})

		t.Run(reason+", capability no rule targets", func(t *testing.T) {
			ctx := resolvedRequest(modernHeaders("toolB"), map[string]string{attrBodyUnusable: reason}, scopedAuth("scope:other"))
			if action := runResolved(toolAOnlyPolicy(), ctx); action != nil {
				t.Fatalf("expected the request to pass, got %#v", action)
			}
		})
	}
}
