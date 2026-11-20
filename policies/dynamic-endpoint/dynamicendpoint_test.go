package dynamicendpoint

import (
	"context"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func withBackends(t *testing.T, backends map[string]map[string]string) {
	t.Helper()
	store := policy.NewLazyResourceStore()
	for name, labels := range backends {
		l := map[string]interface{}{}
		for k, v := range labels {
			l[k] = v
		}
		if err := store.StoreResource(&policy.LazyResource{
			ID:           name,
			ResourceType: policy.LazyResourceTypeBackend,
			Resource:     map[string]interface{}{"name": name, "basePath": "/v1", "labels": l},
		}); err != nil {
			t.Fatal(err)
		}
	}
	previous := lookupBackend
	lookupBackend = store.LookupBackend
	t.Cleanup(func() { lookupBackend = previous })
}

func newPolicy(t *testing.T, params map[string]interface{}) *DynamicEndpointPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "orders-route"}, params)
	if err != nil {
		t.Fatalf("GetPolicy(%v): %v", params, err)
	}
	return p.(*DynamicEndpointPolicy)
}

func request(headers map[string][]string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{}, Headers: policy.NewHeaders(headers)}
}

const headerExpression = `request.Headers["x-backend"][0]`

// expressionMode is a valid backendExpression configuration reading the x-backend header and
// selecting Backends labelled team=orders, with extra parameters merged in.
func expressionMode(extra map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"backendExpression": headerExpression,
		"backendSelector":   map[string]interface{}{"matchLabels": map[string]interface{}{"team": "orders"}},
	}
	for k, v := range extra {
		params[k] = v
	}
	return params
}

func mustModify(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected modifications, got %#v", action)
	}
	return mods
}

// mustRouteTo expects a Backend chosen by the expression: a value from the request names a
// Backend only, never one of the API's own upstream definitions.
func mustRouteTo(t *testing.T, action policy.RequestHeaderAction, backend string) {
	t.Helper()
	mods := mustModify(t, action)
	if mods.BackendName == nil || *mods.BackendName != backend || mods.UpstreamName != nil {
		t.Fatalf("mods = %#v, want only BackendName %q", mods, backend)
	}
	if len(mods.HeadersToRemove) != 0 {
		t.Fatalf("the policy must not remove headers: %#v", mods.HeadersToRemove)
	}
}

// mustTarget expects targetUpstream, named both ways so the policy engine prefers the API's
// upstream definition of that name and otherwise routes to the Backend.
func mustTarget(t *testing.T, action policy.RequestHeaderAction, target string) {
	t.Helper()
	mods := mustModify(t, action)
	if mods.UpstreamName == nil || *mods.UpstreamName != target || mods.BackendName == nil || *mods.BackendName != target {
		t.Fatalf("mods = %#v, want UpstreamName and BackendName %q", mods, target)
	}
	if len(mods.HeadersToRemove) != 0 {
		t.Fatalf("the policy must not remove headers: %#v", mods.HeadersToRemove)
	}
}

func mustReject(t *testing.T, action policy.RequestHeaderAction) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected a rejection, got %#v", action)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), rejectionMessage) {
		t.Fatalf("body = %s", resp.Body)
	}
	if !resp.IsFault || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeInvalidRequestHeader {
		t.Fatalf("IsFault = %v, fault = %#v", resp.IsFault, resp.Fault)
	}
}

func TestGetPolicy_ParameterRules(t *testing.T) {
	bad := map[string]map[string]interface{}{
		"nothing set":                    {},
		"expression without selector":    {"backendExpression": headerExpression},
		"selector without expression":    {"targetUpstream": "tenant-a", "backendSelector": map[string]interface{}{}},
		"onMissingValue without expr":    {"targetUpstream": "tenant-a", "onMissingValue": "reject"},
		"unknown onMissingValue":         expressionMode(map[string]interface{}{"onMissingValue": "drop"}),
		"expression does not compile":    expressionMode(map[string]interface{}{"backendExpression": `request.Headers["x-backend"`}),
		"unknown variable":               expressionMode(map[string]interface{}{"backendExpression": `response.Status`}),
		"expression returns an int":      expressionMode(map[string]interface{}{"backendExpression": `size(request.Path)`}),
		"expression returns a list":      expressionMode(map[string]interface{}{"backendExpression": `request.Headers["x-backend"]`}),
		"expression too long":            expressionMode(map[string]interface{}{"backendExpression": `"` + strings.Repeat("a", maxExpressionLength) + `"`}),
		"selector with matchExpressions": expressionMode(map[string]interface{}{"backendSelector": map[string]interface{}{"matchExpressions": []interface{}{}}}),
		"non-string label value":         expressionMode(map[string]interface{}{"backendSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"team": 1}}}),
		"non-string parameter":           {"targetUpstream": 3},
		"null selector":                  {"backendExpression": headerExpression, "backendSelector": nil},
		"null matchLabels":               expressionMode(map[string]interface{}{"backendSelector": map[string]interface{}{"matchLabels": nil}}),
	}
	for name, params := range bad {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("%s: GetPolicy(%v) accepted an invalid configuration", name, params)
		}
	}
	good := []map[string]interface{}{
		{"targetUpstream": "alt"},
		{"targetUpstream": "Not_A_Backend_Name"},
		{"targetUpstream": ""},
		expressionMode(nil),
		expressionMode(map[string]interface{}{"targetUpstream": "alt", "onMissingValue": "reject"}),
		expressionMode(map[string]interface{}{"backendExpression": `request.Metadata["tenant"]`}),
		{"backendExpression": `auth.Properties["tenant_id"]`, "backendSelector": map[string]interface{}{}},
		expressionMode(map[string]interface{}{"backendSelector": map[string]interface{}{"matchLabels": map[string]interface{}{}}}),
		// 1024 characters, but more than 1024 UTF-8 bytes: the limit counts characters.
		expressionMode(map[string]interface{}{"backendExpression": `"` + strings.Repeat("é", maxExpressionLength-2) + `"`}),
	}
	for _, params := range good {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
			t.Errorf("GetPolicy(%v): %v", params, err)
		}
	}
}

// An empty targetUpstream leaves the route's own upstream in place, as in v1.0, and a name is
// passed on exactly as written.
func TestOnRequestHeaders_TargetUpstreamAsWritten(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"targetUpstream": ""})
	if mods := mustModify(t, p.OnRequestHeaders(context.Background(), request(nil), nil)); mods.UpstreamName != nil || mods.BackendName != nil {
		t.Fatalf("mods = %#v, want no routing change", mods)
	}
	p = newPolicy(t, map[string]interface{}{"targetUpstream": "Alt-Upstream "})
	mustTarget(t, p.OnRequestHeaders(context.Background(), request(nil), nil), "Alt-Upstream ")
}

// targetUpstream keeps its v1.0 meaning when it names one of the API's upstream definitions: the
// policy engine resolves the definition first. Otherwise it names a gateway-wide Backend.
func TestOnRequestHeaders_TargetUpstream(t *testing.T) {
	for _, target := range []string{"alt", "tenant-a"} {
		p := newPolicy(t, map[string]interface{}{"targetUpstream": target})
		mustTarget(t, p.OnRequestHeaders(context.Background(), request(nil), nil), target)
	}
}

func TestOnRequestHeaders_ExpressionSelectsASelectableBackend(t *testing.T) {
	withBackends(t, map[string]map[string]string{
		"tenant-a":         {"team": "orders"},
		"billing-internal": {"team": "billing"},
	})
	p := newPolicy(t, expressionMode(nil))

	mustRouteTo(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-backend": {" tenant-a "}}), nil), "tenant-a")
	// The expression decides which value counts: [0] takes the first of several.
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-backend": {"tenant-a", "tenant-z"}}), nil), "tenant-a")

	// One response for every value that cannot be routed.
	for _, value := range []string{"billing-internal", "tenant-z", "Tenant-A", "tenant-a,tenant-b", "../tenant-a"} {
		mustReject(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-backend": {value}}), nil))
	}
}

func TestOnRequestHeaders_EmptySelectorAllowsEveryBackend(t *testing.T) {
	withBackends(t, map[string]map[string]string{"billing-internal": {"team": "billing"}})
	p := newPolicy(t, map[string]interface{}{"backendExpression": headerExpression, "backendSelector": map[string]interface{}{}})
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-backend": {"billing-internal"}}), nil), "billing-internal")
}

func TestOnRequestHeaders_ExpressionReadsTheRequestContext(t *testing.T) {
	withBackends(t, map[string]map[string]string{
		"tenant-a":        {},
		"orders-eu":       {},
		"orders-v1":       {},
		"orders-route":    {},
		"catalog-v2":      {},
		"tenant-from-jwt": {},
	})
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata:   map[string]interface{}{"tenant": "tenant-a", "count": 3},
			APIName:    "catalog",
			APIVersion: "v2",
			AuthContext: &policy.AuthContext{
				Authenticated: true,
				Subject:       "alice",
				Properties:    map[string]string{"tenant_id": "tenant-from-jwt"},
			},
		},
		Headers: policy.NewHeaders(map[string][]string{"x-region": {"EU"}}),
		Path:    "/orders/v1/items",
		Method:  "GET",
	}
	cases := map[string]string{
		`request.Metadata["tenant"]`:                              "tenant-a",
		`auth.Properties["tenant_id"]`:                            "tenant-from-jwt",
		`"orders-" + request.Headers["x-region"][0].lowerAscii()`: "orders-eu",
		`"orders-" + request.Path.split("/")[2]`:                  "orders-v1",
		`route.Name`:                                              "orders-route",
		`api.Name + "-" + api.Version`:                            "catalog-v2",
	}
	for expression, want := range cases {
		p := newPolicy(t, map[string]interface{}{"backendExpression": expression, "backendSelector": map[string]interface{}{}})
		mustRouteTo(t, p.OnRequestHeaders(context.Background(), ctx, nil), want)
	}

	// A metadata value that is not a string is malformed, not missing.
	p := newPolicy(t, map[string]interface{}{"backendExpression": `request.Metadata["count"]`, "backendSelector": map[string]interface{}{}})
	mustReject(t, p.OnRequestHeaders(context.Background(), ctx, nil))
}

func TestOnRequestHeaders_NoValue(t *testing.T) {
	withBackends(t, nil)
	noValue := map[string]*policy.RequestHeaderContext{
		"header absent":            request(nil),
		"header empty":             request(map[string][]string{"x-backend": {"  "}}),
		"no shared context at all": {Headers: policy.NewHeaders(nil)},
		"nil request":              nil,
	}

	t.Run("fallback to targetUpstream", func(t *testing.T) {
		p := newPolicy(t, expressionMode(map[string]interface{}{"targetUpstream": "tenant-default"}))
		for name, req := range noValue {
			t.Run(name, func(t *testing.T) {
				mustTarget(t, p.OnRequestHeaders(context.Background(), req, nil), "tenant-default")
			})
		}
	})
	t.Run("fallback to the route's own upstream", func(t *testing.T) {
		p := newPolicy(t, expressionMode(nil))
		mods := mustModify(t, p.OnRequestHeaders(context.Background(), request(nil), nil))
		if mods.UpstreamName != nil || mods.BackendName != nil {
			t.Fatalf("mods = %#v", mods)
		}
	})
	t.Run("absent metadata and auth context", func(t *testing.T) {
		for _, expression := range []string{`request.Metadata["tenant"]`, `auth.Properties["tenant_id"]`, `auth.Subject`} {
			p := newPolicy(t, map[string]interface{}{"backendExpression": expression, "backendSelector": map[string]interface{}{}, "targetUpstream": "tenant-default"})
			mustTarget(t, p.OnRequestHeaders(context.Background(), request(nil), nil), "tenant-default")
		}
	})
	t.Run("reject", func(t *testing.T) {
		p := newPolicy(t, expressionMode(map[string]interface{}{"onMissingValue": "reject", "targetUpstream": "tenant-default"}))
		for name, req := range noValue {
			t.Run(name, func(t *testing.T) {
				mustReject(t, p.OnRequestHeaders(context.Background(), req, nil))
			})
		}
	})
}

// Only a missing input falls back. A present value that makes the expression fail, such as a
// header that isn't a number, is rejected like any other value that can't be routed.
func TestOnRequestHeaders_EvaluationErrorsThatAreNotMissingInputsAreRejected(t *testing.T) {
	withBackends(t, map[string]map[string]string{"tenant-7": {}})
	p := newPolicy(t, map[string]interface{}{
		"backendExpression": `"tenant-" + string(int(request.Headers["x-tenant-no"][0]))`,
		"backendSelector":   map[string]interface{}{},
		"targetUpstream":    "tenant-default",
	})
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-tenant-no": {"7"}}), nil), "tenant-7")
	mustTarget(t, p.OnRequestHeaders(context.Background(), request(nil), nil), "tenant-default")
	mustReject(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-tenant-no": {"seven"}}), nil))
}

// The query-parameter expression the policy docs show matches the parameter name at a parameter
// boundary only.
func TestOnRequestHeaders_QueryParameterExpressionMatchesWholeNames(t *testing.T) {
	withBackends(t, map[string]map[string]string{"tenant-b": {}})
	p := newPolicy(t, map[string]interface{}{
		"backendExpression": `("&" + request.Path.substring(request.Path.indexOf("?") + 1)).split("&tenant=")[1].split("&")[0]`,
		"backendSelector":   map[string]interface{}{},
		"targetUpstream":    "tenant-default",
	})
	at := func(path string) *policy.RequestHeaderContext {
		r := request(nil)
		r.Path = path
		return r
	}
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), at("/orders/items?tenant=tenant-b"), nil), "tenant-b")
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), at("/orders/items?page=2&tenant=tenant-b&sort=asc"), nil), "tenant-b")
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), at("/orders/items?next=/help?view=1&tenant=tenant-b"), nil), "tenant-b")
	for _, path := range []string{"/orders/items?previous_tenant=tenant-b", "/orders/items?page=2", "/orders/items"} {
		mustTarget(t, p.OnRequestHeaders(context.Background(), at(path), nil), "tenant-default")
	}
}
