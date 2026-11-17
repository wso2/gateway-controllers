package dynamicendpoint

import (
	"context"
	"errors"
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
			Resource:     map[string]interface{}{"name": name, "clusterName": revisionCluster(name), "basePath": "/v1", "labels": l},
		}); err != nil {
			t.Fatal(err)
		}
	}
	previous := lookupBackend
	lookupBackend = store.LookupBackend
	t.Cleanup(func() { lookupBackend = previous })
}

// revisionCluster is the cluster of the revision each test Backend's record names.
func revisionCluster(name string) string { return "backend_" + name + "_0123456789ab" }

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
	// The selector was checked against this record, so the request is held to its revision.
	if mods.BackendClusterName == nil || *mods.BackendClusterName != revisionCluster(backend) {
		t.Fatalf("BackendClusterName = %v, want the checked record's cluster %q", mods.BackendClusterName, revisionCluster(backend))
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
	if mods.BackendClusterName != nil {
		t.Fatalf("a fixed target checks no record, so it pins no revision: %q", *mods.BackendClusterName)
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
		"expression too long":            expressionMode(map[string]interface{}{"backendExpression": `"` + strings.Repeat("a", maxExpressionLength-1) + `"`}), // 1025 characters
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
		// Exactly 1024 characters.
		expressionMode(map[string]interface{}{"backendExpression": `"` + strings.Repeat("a", maxExpressionLength-2) + `"`}),
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
// boundary only, and only in the query string: a path without "?" yields no value.
func TestOnRequestHeaders_QueryParameterExpressionMatchesWholeNames(t *testing.T) {
	withBackends(t, map[string]map[string]string{"tenant-b": {}})
	p := newPolicy(t, map[string]interface{}{
		"backendExpression": queryParameterExpression,
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
	for _, path := range []string{"/orders/items?previous_tenant=tenant-b", "/orders/items?page=2", "/orders/items",
		"/orders/items&tenant=tenant-b"} {
		mustTarget(t, p.OnRequestHeaders(context.Background(), at(path), nil), "tenant-default")
	}
}

// queryParameterExpression is the tenant query-parameter example in the policy docs.
const queryParameterExpression = `request.Path.indexOf("?") >= 0 ? ("&" + request.Path.substring(request.Path.indexOf("?") + 1)).split("&tenant=")[1].split("&")[0] : ""`

// Only the CEL errors for an absent key, attribute or list index are missing inputs, and only when
// the message starts with them: an error that quotes a request value containing the same words is
// an evaluation error.
func TestIsMissingInput(t *testing.T) {
	missing := []string{
		"no such key: x-backend",
		"no such attribute(s): request.Headers",
		"index out of bounds: 1",
		"index '3' out of range in list size '2'",
	}
	for _, msg := range missing {
		if !isMissingInput(errors.New(msg)) {
			t.Errorf("isMissingInput(%q) = false, want true", msg)
		}
	}
	notMissing := []string{
		`invalid RFC 3339 timestamp "no such key: x"`,
		`invalid RFC 3339 timestamp "index out of bounds: 1"`,
		"type conversion error from 'string' to 'int'",
		"index 'x' out of range in list size '2' and more",
	}
	for _, msg := range notMissing {
		if isMissingInput(errors.New(msg)) {
			t.Errorf("isMissingInput(%q) = true, want false", msg)
		}
	}
}

// A present header whose value merely contains a missing-input phrase is not a missing input: the
// conversion error that quotes it is rejected, not sent to the fallback.
func TestOnRequestHeaders_AnErrorQuotingTheRequestValueIsNotAMissingInput(t *testing.T) {
	withBackends(t, nil)
	p := newPolicy(t, map[string]interface{}{
		"backendExpression": `string(timestamp(request.Headers["x-ts"][0]))`,
		"backendSelector":   map[string]interface{}{},
		"targetUpstream":    "tenant-default",
	})
	mustTarget(t, p.OnRequestHeaders(context.Background(), request(nil), nil), "tenant-default")
	for _, value := range []string{"no such key", "no such key: x-ts", "index out of bounds: 1"} {
		mustReject(t, p.OnRequestHeaders(context.Background(), request(map[string][]string{"x-ts": {value}}), nil))
	}
}

// The wrong-type guard the policy docs show tells a value of the wrong type apart from an absent
// one: a string where a map is expected is rejected, an absent key follows onMissingValue.
func TestOnRequestHeaders_WrongTypeGuardFromTheDocs(t *testing.T) {
	withBackends(t, map[string]map[string]string{"tenant-a": {}})
	p := newPolicy(t, map[string]interface{}{
		"backendExpression": `type(request.Metadata["tenant"]) == map ? request.Metadata["tenant"].id : "<wrong type>"`,
		"backendSelector":   map[string]interface{}{},
		"targetUpstream":    "tenant-default",
	})
	withMetadata := func(metadata map[string]interface{}) *policy.RequestHeaderContext {
		r := request(nil)
		r.SharedContext = &policy.SharedContext{Metadata: metadata}
		return r
	}
	mustRouteTo(t, p.OnRequestHeaders(context.Background(), withMetadata(map[string]interface{}{"tenant": map[string]interface{}{"id": "tenant-a"}}), nil), "tenant-a")
	mustReject(t, p.OnRequestHeaders(context.Background(), withMetadata(map[string]interface{}{"tenant": "tenant-a"}), nil))
	mustTarget(t, p.OnRequestHeaders(context.Background(), withMetadata(map[string]interface{}{}), nil), "tenant-default")
	mustTarget(t, p.OnRequestHeaders(context.Background(), withMetadata(map[string]interface{}{"tenant": map[string]interface{}{}}), nil), "tenant-default")
}

// withTemplated adds templated Backends (name -> endpoint template) to the store withBackends
// uses, next to a plain Backend tenant-a labelled team=orders.
func withTemplated(t *testing.T, templates map[string]string, labels map[string]string) {
	t.Helper()
	store := policy.NewLazyResourceStore()
	l := map[string]interface{}{}
	for k, v := range labels {
		l[k] = v
	}
	for name, template := range templates {
		if err := store.StoreResource(&policy.LazyResource{
			ID:           name,
			ResourceType: policy.LazyResourceTypeBackend,
			Resource: map[string]interface{}{"name": name, "clusterName": revisionCluster(name), "basePath": "",
				"labels": l, "urlTemplate": template},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.StoreResource(&policy.LazyResource{
		ID:           "tenant-a",
		ResourceType: policy.LazyResourceTypeBackend,
		Resource: map[string]interface{}{"name": "tenant-a", "clusterName": revisionCluster("tenant-a"), "basePath": "/v1",
			"labels": map[string]interface{}{"team": "orders"}},
	}); err != nil {
		t.Fatal(err)
	}
	previous := lookupBackend
	lookupBackend = store.LookupBackend
	t.Cleanup(func() { lookupBackend = previous })
}

const envKeyExpression = `request.Headers["env"][0].lowerAscii()`

func envRequest(values ...string) *policy.RequestHeaderContext {
	if len(values) == 0 {
		return request(map[string][]string{})
	}
	return request(map[string][]string{"env": values})
}

func mustKey(t *testing.T, action policy.RequestHeaderAction, key string) {
	t.Helper()
	mods := mustModify(t, action)
	if mods.BackendKey == nil || *mods.BackendKey != key {
		t.Fatalf("BackendKey = %v, want %q", mods.BackendKey, key)
	}
}

func mustHaveNoKey(t *testing.T, action policy.RequestHeaderAction) {
	t.Helper()
	if mods := mustModify(t, action); mods.BackendKey != nil {
		t.Fatalf("BackendKey = %q, want none", *mods.BackendKey)
	}
}

func TestGetPolicy_BackendKeyExpressionRules(t *testing.T) {
	bad := map[string]map[string]interface{}{
		"alone":                        {"backendKeyExpression": envKeyExpression},
		"with an empty targetUpstream": {"targetUpstream": "", "backendKeyExpression": envKeyExpression},
		"does not compile":             {"targetUpstream": "env-router", "backendKeyExpression": `request.Headers[`},
		"not a string result":          {"targetUpstream": "env-router", "backendKeyExpression": `1 + 1`},
		"too long":                     {"targetUpstream": "env-router", "backendKeyExpression": `"` + strings.Repeat("a", 1023) + `"`},
		"not a string":                 {"targetUpstream": "env-router", "backendKeyExpression": 42},
	}
	for name, params := range bad {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("%s: GetPolicy accepted %v", name, params)
		}
	}
	for name, params := range map[string]map[string]interface{}{
		"with targetUpstream":    {"targetUpstream": "env-router", "backendKeyExpression": envKeyExpression},
		"with backendExpression": expressionMode(map[string]interface{}{"backendKeyExpression": envKeyExpression}),
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
			t.Errorf("%s: GetPolicy rejected %v: %v", name, params, err)
		}
	}
}

// A fixed targetUpstream that names a templated Backend carries the request's key; the policy
// engine expands it into the host. A request without a valid key goes on without one: the policy
// can't see the API's upstream definitions, and one of that name needs no key. The policy engine
// answers 400 when it routes such a request to the templated Backend.
func TestOnRequestHeaders_TargetUpstreamTemplatedBackend(t *testing.T) {
	withTemplated(t, map[string]string{"env-router": "https://url-{key}.url.fr"}, nil)
	p := newPolicy(t, map[string]interface{}{"targetUpstream": "env-router", "backendKeyExpression": envKeyExpression})

	action := p.OnRequestHeaders(context.Background(), envRequest("DEV"), nil)
	mustTarget(t, action, "env-router")
	mustKey(t, action, "dev")

	for name, req := range map[string]*policy.RequestHeaderContext{
		"no env header":     envRequest(),
		"an empty key":      envRequest(""),
		"a dotted key":      envRequest("dev.evil.io"),
		"a key with a port": envRequest("dev:1"),
		"userinfo":          envRequest("x@169.254.169.254"),
		"a label too long":  envRequest(strings.Repeat("a", 60)),
	} {
		t.Run(name, func(t *testing.T) {
			action := p.OnRequestHeaders(context.Background(), req, nil)
			mustTarget(t, action, "env-router")
			mustHaveNoKey(t, action)
		})
	}
}

// The key is evaluated only for a templated Backend: a plain Backend, or an upstream definition
// of the API, is routed as before even when the request has no key.
func TestOnRequestHeaders_TheKeyIsOnlyForATemplatedBackend(t *testing.T) {
	withTemplated(t, map[string]string{"env-router": "https://url-{key}.url.fr"}, nil)
	for _, target := range []string{"tenant-a", "alt-upstream"} {
		p := newPolicy(t, map[string]interface{}{"targetUpstream": target, "backendKeyExpression": envKeyExpression})
		action := p.OnRequestHeaders(context.Background(), envRequest(), nil)
		mustTarget(t, action, target)
		mustHaveNoKey(t, action)
	}
}

// A templated Backend chosen by backendExpression gets the key next to its revision pin. Without
// backendKeyExpression it can't be reached, so the request is rejected. A plain Backend chosen
// the same way needs no key.
func TestOnRequestHeaders_ExpressionChoosesATemplatedBackend(t *testing.T) {
	withTemplated(t, map[string]string{"env-router": "http://env-{key}.testbench:3000"}, map[string]string{"team": "orders"})
	withKey := newPolicy(t, expressionMode(map[string]interface{}{"backendKeyExpression": envKeyExpression}))
	req := request(map[string][]string{"x-backend": {"env-router"}, "env": {"prod"}})
	action := withKey.OnRequestHeaders(context.Background(), req, nil)
	mustRouteTo(t, action, "env-router")
	mustKey(t, action, "prod")

	withoutKey := newPolicy(t, expressionMode(nil))
	mustReject(t, withoutKey.OnRequestHeaders(context.Background(), req, nil))

	plain := withKey.OnRequestHeaders(context.Background(), request(map[string][]string{"x-backend": {"tenant-a"}}), nil)
	mustRouteTo(t, plain, "tenant-a")
	mustHaveNoKey(t, plain)
}

// The key can come from the subscription plan an earlier policy stored, and CEL can restrict the
// keys a caller may use.
func TestOnRequestHeaders_KeyFromPlanMetadataAndARestrictedHeader(t *testing.T) {
	withTemplated(t, map[string]string{"plans": "https://backend-{key}.internal"}, nil)

	plan := newPolicy(t, map[string]interface{}{"targetUpstream": "plans",
		"backendKeyExpression": `request.Metadata["x-wso2-subscription-plan-name"].lowerAscii().replace(" ", "-")`})
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{"x-wso2-subscription-plan-name": "Gold Plus"}},
		Headers:       policy.NewHeaders(nil),
	}
	mustKey(t, plan.OnRequestHeaders(context.Background(), ctx, nil), "gold-plus")

	restricted := newPolicy(t, map[string]interface{}{"targetUpstream": "plans",
		"backendKeyExpression": `request.Headers["env"][0].matches("^(dev|prod)$") ? request.Headers["env"][0] : ""`})
	mustKey(t, restricted.OnRequestHeaders(context.Background(), envRequest("dev"), nil), "dev")
	// A disallowed value yields no key; the request goes on without one, and the policy engine
	// answers 400 for the templated Backend.
	mustHaveNoKey(t, restricted.OnRequestHeaders(context.Background(), envRequest("qa"), nil))
}
