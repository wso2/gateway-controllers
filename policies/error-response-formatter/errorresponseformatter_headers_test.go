package errorresponseformatter

import (
	"context"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The motivating case for header customization: a client that wants to branch on the failure
// without parsing the body needs the code in a header, and the value has to come from the
// failure rather than be a fixed string.
func TestHeadersToSetCarryTheFailuresOwnDetail(t *testing.T) {
	fault := render(t, map[string]interface{}{
		"preset":       "canonical",
		"headersToSet": []interface{}{map[string]interface{}{"name": "x-error-code", "value": "${Code}"}, map[string]interface{}{"name": "x-error-source", "value": "${Source}"}, map[string]interface{}{"name": "x-error-status", "value": "${Status}"}, map[string]interface{}{"name": "x-house-style", "value": "acme-v2"}},
	}, faultCtx(429, &policy.FaultDetails{
		Code: "900802", Type: policy.FaultTypeThrottling, Message: "Too many requests",
	}, "basic-ratelimit"))

	want := map[string]string{
		"x-error-code":   "900802",
		"x-error-source": "",
		"x-error-status": "429",
		"x-house-style":  "acme-v2",
		"content-type":   "application/json",
	}
	for name, value := range want {
		if got := fault.HeadersToSet[name]; got != value {
			t.Errorf("HeadersToSet[%q] = %q, want %q", name, got, value)
		}
	}
}

// Source is the field a status cannot supply, so it has to survive into a header: a backend's
// own 503 and the router's 503 are the same number and mean opposite things.
func TestSourcePlaceholderResolves(t *testing.T) {
	ctx := faultCtx(503, nil, "")
	ctx.Source = policy.FaultSourceBackend

	fault := render(t, map[string]interface{}{
		"preset":       "canonical",
		"headersToSet": []interface{}{map[string]interface{}{"name": "x-error-source", "value": "${Source}"}},
	}, ctx)

	if got := fault.HeadersToSet["x-error-source"]; got != "backend" {
		t.Fatalf("x-error-source = %q, want %q", got, "backend")
	}
}

func TestPolicyPhasePlaceholderResolves(t *testing.T) {
	ctx := faultCtx(422, &policy.FaultDetails{Code: "900514"}, "word-count-guardrail")
	ctx.PolicyPhase = policy.PolicyPhaseResponseBody

	fault := render(t, map[string]interface{}{
		"preset":       "canonical",
		"headersToSet": []interface{}{map[string]interface{}{"name": "x-error-phase", "value": "${PolicyPhase}"}},
	}, ctx)

	if got := fault.HeadersToSet["x-error-phase"]; got != "response_body" {
		t.Fatalf("x-error-phase = %q, want %q", got, "response_body")
	}
}

// Response splitting. A header value templated from Message or Description is content the
// gateway did not author — for a guardrail rejection, Description IS the blocked content — so
// a newline in it would end the header and start whatever came next.
//
// The escape modes this policy already has do not cover it: they are about a body's syntax,
// not the header framing around it. Hence a separate sanitizer, and hence this test.
func TestHeaderValuesCannotSplitTheResponse(t *testing.T) {
	fault := render(t, map[string]interface{}{
		"preset":       "canonical",
		"headersToSet": []interface{}{map[string]interface{}{"name": "x-error-detail", "value": "${Message}"}},
	}, faultCtx(400, &policy.FaultDetails{
		Message: "bad\r\nx-injected: yes\r\n\r\n<html>gotcha</html>",
	}, ""))

	got := fault.HeadersToSet["x-error-detail"]
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("header value still contains CR/LF: %q", got)
	}
	if strings.Contains(got, "gotcha") != true {
		t.Fatalf("the value should be neutralised, not truncated — got %q", got)
	}
	if got != "bad  x-injected: yes    <html>gotcha</html>" {
		t.Fatalf("unexpected sanitized value %q", got)
	}
}

func TestHeadersToAppendAcceptsAScalarOrAList(t *testing.T) {
	fault := render(t, map[string]interface{}{
		"preset":          "canonical",
		"headersToAppend": []interface{}{map[string]interface{}{"name": "x-one", "value": "only"}, map[string]interface{}{"name": "x-many", "value": "a"}, map[string]interface{}{"name": "x-many", "value": "${Code}"}},
	}, faultCtx(401, &policy.FaultDetails{Code: "900902"}, ""))

	if got := fault.HeadersToAppend["x-one"]; len(got) != 1 || got[0] != "only" {
		t.Errorf("x-one = %v, want [only]", got)
	}
	if got := fault.HeadersToAppend["x-many"]; len(got) != 2 || got[1] != "900902" {
		t.Errorf("x-many = %v, want [a 900902]", got)
	}
}

func TestHeadersToRemoveReachesTheFaultResponse(t *testing.T) {
	fault := render(t, map[string]interface{}{
		"preset":          "canonical",
		"headersToRemove": []interface{}{"x-internal-trace", "server"},
	}, faultCtx(500, nil, ""))

	if len(fault.HeadersToRemove) != 2 || fault.HeadersToRemove[0] != "x-internal-trace" {
		t.Fatalf("HeadersToRemove = %v", fault.HeadersToRemove)
	}
}

// A number in YAML is what an operator means by a header value, so accepting only strings
// would reject `x-retry-after: 30` for no reason — and must not render it as "30.000000",
// since YAML hands every plain number over as a float64.
func TestHeaderValuesAcceptYAMLScalars(t *testing.T) {
	fault := render(t, map[string]interface{}{
		"preset":       "canonical",
		"headersToSet": []interface{}{map[string]interface{}{"name": "x-retry-after", "value": float64(30)}, map[string]interface{}{"name": "x-cacheable", "value": false}},
	}, faultCtx(429, nil, ""))

	if got := fault.HeadersToSet["x-retry-after"]; got != "30" {
		t.Errorf("x-retry-after = %q, want %q", got, "30")
	}
	if got := fault.HeadersToSet["x-cacheable"]; got != "false" {
		t.Errorf("x-cacheable = %q, want %q", got, "false")
	}
}

// Header names are case-insensitive, so names differing only by case share one entry and the
// later configured value wins.
func TestHeaderNamesAreCaseInsensitive(t *testing.T) {
	fault := render(t, map[string]interface{}{
		"preset": "canonical",
		"headersToSet": []interface{}{
			map[string]interface{}{"name": "X-Error-Code", "value": "first"},
			map[string]interface{}{"name": "x-error-code", "value": "second"},
		},
		"headersToAppend": []interface{}{
			map[string]interface{}{"name": "X-Trace", "value": "a"},
			map[string]interface{}{"name": "x-trace", "value": "b"},
		},
	}, faultCtx(500, nil, ""))

	if len(fault.HeadersToSet) != 2 || fault.HeadersToSet["x-error-code"] != "second" {
		t.Errorf("HeadersToSet = %v, want x-error-code: second plus content-type", fault.HeadersToSet)
	}
	if got := fault.HeadersToAppend["x-trace"]; len(fault.HeadersToAppend) != 1 || len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("HeadersToAppend = %v, want x-trace: [a b]", fault.HeadersToAppend)
	}
}

// contentType is a header value too, so it gets the same line-break stripping.
func TestContentTypeCannotSplitTheResponse(t *testing.T) {
	fault := render(t, map[string]interface{}{"contentType": "application/json\r\nx-injected: 1"},
		faultCtx(500, nil, ""))
	if got := fault.HeadersToSet["content-type"]; strings.ContainsAny(got, "\r\n") {
		t.Errorf("content-type = %q, must not contain CR or LF", got)
	}
}

// Up-front rejections, when the chain is built. Each of these produces a working-looking deployment that misbehaves
// only when a request actually fails, which is the worst time to discover it.
func TestHeaderConfigurationIsValidatedUpFront(t *testing.T) {
	cases := []struct {
		name    string
		params  map[string]interface{}
		wantErr string
	}{
		{
			"unknown placeholder in a header value",
			map[string]interface{}{"headersToSet": []interface{}{map[string]interface{}{"name": "x-a", "value": "${Coed}"}}},
			"unknown placeholder",
		},
		{
			"gateway templating syntax in a header value",
			map[string]interface{}{"headersToSet": []interface{}{map[string]interface{}{"name": "x-a", "value": "{{ .Code }}"}}},
			"never reaches this policy",
		},
		{
			"content-type as a header",
			map[string]interface{}{"headersToSet": []interface{}{map[string]interface{}{"name": "Content-Type", "value": "text/plain"}}},
			"set the response content type with contentType",
		},
		{
			"the same header written and removed",
			map[string]interface{}{
				"headersToSet":    []interface{}{map[string]interface{}{"name": "x-a", "value": "1"}},
				"headersToRemove": []interface{}{"X-A"},
			},
			"both written and removed",
		},
		{
			"a header name that cannot be sent",
			map[string]interface{}{"headersToSet": []interface{}{map[string]interface{}{"name": "x a: b", "value": "1"}}},
			"cannot appear in one",
		},
		{
			"a header name outside the token syntax",
			map[string]interface{}{"headersToAppend": []interface{}{map[string]interface{}{"name": "x@code", "value": "1"}}},
			"cannot appear in one",
		},
		{
			"a placeholder in a header name",
			map[string]interface{}{"headersToRemove": []interface{}{"${Code}"}},
			"cannot appear in one",
		},
		{
			"an underscore placeholder in a header value",
			map[string]interface{}{"headersToSet": []interface{}{map[string]interface{}{"name": "x-a", "value": "${Request_ID}"}}},
			"unknown placeholder",
		},
		{
			"a non-scalar header value",
			map[string]interface{}{
				"headersToSet": []interface{}{map[string]interface{}{"name": "x-a", "value": map[string]interface{}{"nested": "no"}}},
			},
			"must be a string, number or boolean",
		},
		{
			"headersToSet is not a list",
			map[string]interface{}{"headersToSet": map[string]interface{}{"x-a": "1"}},
			"must be a list of {name, value} entries",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// Configuring no headers must add none beyond the content type the body needs — otherwise
// every existing deployment of this policy would start emitting something new.
func TestNoHeaderConfigurationAddsNothing(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"preset": "canonical"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	fault := p.(*ErrorFormatterPolicy).OnFault(context.Background(),
		faultCtx(500, nil, ""), nil)

	if len(fault.HeadersToSet) != 1 {
		t.Fatalf("HeadersToSet = %v, want only content-type", fault.HeadersToSet)
	}
	if fault.HeadersToAppend != nil {
		t.Errorf("HeadersToAppend = %v, want nil", fault.HeadersToAppend)
	}
	if fault.HeadersToRemove != nil {
		t.Errorf("HeadersToRemove = %v, want nil", fault.HeadersToRemove)
	}
}
