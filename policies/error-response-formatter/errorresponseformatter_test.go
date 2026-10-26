package errorresponseformatter

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func faultCtx(status int, e *policy.FaultDetails, failing string) *policy.FaultContext {
	return &policy.FaultContext{
		SharedContext:  &policy.SharedContext{RequestID: "req-42"},
		ResponseStatus: status,
		Policy:         failing,
		Fault:          e,
	}
}

func render(t *testing.T, params map[string]interface{}, ctx *policy.FaultContext) policy.FaultResponse {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	fault := p.(*ErrorFormatterPolicy).OnFault(context.Background(), ctx, nil)
	if fault == nil {
		t.Fatal("expected a FaultResponse, got nil (which means the error was left unchanged)")
	}
	return *fault
}

func asJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, body)
	}
	return out
}

// The motivating case: an OpenAI SDK client needs error.message to exist as an object field,
// and its own error-type vocabulary rather than the gateway's class names.
func TestPresetOpenAI(t *testing.T) {
	m := render(t, map[string]interface{}{"preset": "openai"},
		faultCtx(401, &policy.FaultDetails{Code: "900902", Type: "authentication", Message: "Valid API key required"}, "api-key-auth"))

	got := asJSON(t, m.Body)
	errObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("error must be an OBJECT, not a string — a flat string is what OpenAI clients reject: %s", m.Body)
	}
	if errObj["message"] != "Valid API key required" {
		t.Fatalf("message: %s", m.Body)
	}
	if errObj["type"] != "authentication_error" {
		t.Fatalf("type must use OpenAI's vocabulary, got %v", errObj["type"])
	}
	if errObj["code"] != "900902" {
		t.Fatalf("code: %s", m.Body)
	}
	if m.HeadersToSet["content-type"] != "application/json" {
		t.Fatalf("content type = %q", m.HeadersToSet["content-type"])
	}
}

// OpenAI's type vocabulary is status-derived, so each status must map correctly.
func TestOpenAITypeByStatus(t *testing.T) {
	for status, want := range map[int]string{
		400: "invalid_request_error", 401: "authentication_error", 403: "permission_error",
		404: "not_found_error", 413: "request_too_large", 422: "invalid_request_error",
		429: "rate_limit_error", 503: "server_error", 418: "api_error",
	} {
		m := render(t, map[string]interface{}{"preset": "openai"}, faultCtx(status, nil, ""))
		errObj := asJSON(t, m.Body)["error"].(map[string]any)
		if errObj["type"] != want {
			t.Errorf("status %d -> %v, want %s", status, errObj["type"], want)
		}
	}
}

// A leaf that is exactly ${Status} must keep its numeric type. `"status":"401"` versus
// `"status":401` is the difference between a client parsing the value and choking on it.
func TestStatusKeepsItsNumericType(t *testing.T) {
	m := render(t, map[string]interface{}{
		"template": map[string]interface{}{"status": "${Status}", "text": "status ${Status}"},
	}, faultCtx(429, nil, ""))

	got := asJSON(t, m.Body)
	if _, isNum := got["status"].(float64); !isNum {
		t.Fatalf("bare ${Status} must render as a number, got %T: %s", got["status"], m.Body)
	}
	if got["text"] != "status 429" {
		t.Fatalf("interpolated ${Status} must be text: %s", m.Body)
	}
}

// Nesting is the normal case for provider envelopes.
func TestNestedTemplate(t *testing.T) {
	m := render(t, map[string]interface{}{
		"template": map[string]interface{}{
			"error": map[string]interface{}{
				"detail": map[string]interface{}{"code": "${Code}", "policy": "${Policy}"},
			},
			"apiVersion": "v1", // a literal with no placeholders survives
		},
	}, faultCtx(422, &policy.FaultDetails{Code: "900514"}, "word-count-guardrail"))

	got := asJSON(t, m.Body)
	detail := got["error"].(map[string]any)["detail"].(map[string]any)
	if detail["code"] != "900514" || detail["policy"] != "word-count-guardrail" {
		t.Fatalf("nested values not substituted: %s", m.Body)
	}
	if got["apiVersion"] != "v1" {
		t.Fatalf("literal leaf lost: %s", m.Body)
	}
}

// A sparse error is normal — a router failure, or a policy that has not adopted the type. The
// result must be absence, not empty strings.
func TestSparseErrorDropsEmptyLeaves(t *testing.T) {
	m := render(t, map[string]interface{}{"preset": "canonical"}, faultCtx(503, nil, ""))

	got := asJSON(t, m.Body)
	for _, k := range []string{"code", "type"} {
		if _, present := got[k]; present {
			t.Fatalf("%q must be absent for a sparse error, not empty: %s", k, m.Body)
		}
	}
	if got["message"] != "An unexpected error occurred." {
		t.Fatalf("message must always have a value: %s", m.Body)
	}
}

// An object whose every leaf dropped must itself be dropped, so a sparse error cannot leave
// {"error":{}} behind.
func TestEmptyObjectIsDropped(t *testing.T) {
	m := render(t, map[string]interface{}{
		"template": map[string]interface{}{
			"detail": map[string]interface{}{"code": "${Code}"},
			"keep":   "${Message}",
		},
	}, faultCtx(503, nil, ""))

	got := asJSON(t, m.Body)
	if _, present := got["detail"]; present {
		t.Fatalf("an all-empty object must be dropped: %s", m.Body)
	}
	if got["keep"] == nil {
		t.Fatalf("message must survive: %s", m.Body)
	}
}

// A message containing quotes and backslashes must not be able to break the document. This is
// the property a string template cannot offer without hand-rolled escaping per syntax.
func TestQuotesCannotBreakTheDocument(t *testing.T) {
	nasty := `he said "no" \ then {"injected":true} left`
	m := render(t, map[string]interface{}{"preset": "openai"},
		faultCtx(400, &policy.FaultDetails{Message: nasty}, ""))

	errObj := asJSON(t, m.Body)["error"].(map[string]any)
	if errObj["message"] != nasty {
		t.Fatalf("message did not round-trip: %v", errObj["message"])
	}
}

// stringTemplate covers output that is not an object.
func TestStringTemplate(t *testing.T) {
	m := render(t, map[string]interface{}{
		"stringTemplate": `<err code="${Code}">${Message}</err>`,
		"contentType":    "application/xml",
	}, faultCtx(401, &policy.FaultDetails{Code: "900902", Message: "Denied"}, ""))

	if string(m.Body) != `<err code="900902">Denied</err>` {
		t.Fatalf("unexpected body: %s", m.Body)
	}
	if m.HeadersToSet["content-type"] != "application/xml" {
		t.Fatalf("content type = %q", m.HeadersToSet["content-type"])
	}
}

// Up-front validation, when the chain is built. Each of these would otherwise surface while a
// request is already failing, which is the worst possible moment.
func TestConfigurationIsValidatedUpFront(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]interface{}
		expect string
	}{
		{"unknown placeholder", map[string]interface{}{
			"template": map[string]interface{}{"a": "${Mesage}"}}, "Mesage"},
		{"go templating refused", map[string]interface{}{
			"template": map[string]interface{}{"a": "{{.Message}}"}}, "${Field}"},
		{"go templating refused in stringTemplate", map[string]interface{}{
			"stringTemplate": "{{ .Message }}"}, "${Field}"},
		{"unknown preset", map[string]interface{}{"preset": "bedrock"}, "unknown"},
		{"template must be an object", map[string]interface{}{
			"template": "just a string"}, "must be an object"},
		{"mutually exclusive", map[string]interface{}{
			"preset": "openai", "stringTemplate": "x"}, "only one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if err == nil {
				t.Fatal("expected the configuration to be refused")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("error should mention %q: %v", tc.expect, err)
			}
		})
	}
}

// No configuration at all is a reasonable ask — "give me a consistent error body".
func TestNoConfigurationUsesCanonical(t *testing.T) {
	m := render(t, nil, faultCtx(401, &policy.FaultDetails{Code: "900900", Message: "Denied"}, ""))
	got := asJSON(t, m.Body)
	if got["code"] != "900900" || got["message"] != "Denied" {
		t.Fatalf("unexpected default body: %s", m.Body)
	}
}

// The context arrives with fields unset on several real paths; none may panic on an error path.
func TestToleratesAnEmptyContext(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"preset": "openai"})
	if err != nil {
		t.Fatal(err)
	}
	// A context with nothing in it is still a context: the formatter has a status (zero) and
	// a preset, which is enough to author a body, so it must produce one.
	for _, in := range []*policy.FaultContext{
		{},
		{ResponseStatus: 500},
	} {
		if got := p.(*ErrorFormatterPolicy).OnFault(context.Background(), in, nil); got == nil {
			t.Fatal("a non-nil context must still yield a formatted body")
		}
	}

	// A nil context is the one case that yields nil, which now MEANS something: "changed
	// nothing", so the gateway's own protocol formatter still gets its turn. The old
	// contract had to express that as an empty modification, which the caller could not
	// distinguish from a deliberate no-op.
	if got := p.(*ErrorFormatterPolicy).OnFault(context.Background(), nil, nil); got != nil {
		t.Fatalf("a nil context must leave the error unchanged, got %+v", got)
	}
}

// ─── any format: escaping, SOAP, JSON-RPC ────────────────────────────────────

// The bug this fixes. Without syntax-aware escaping a message containing markup breaks out of
// its element — a malformed document AND an injection primitive. Measured before the fix:
// `<err>a < b & c </err><injected/></err>`.
func TestXMLEscapingPreventsElementInjection(t *testing.T) {
	m := render(t, map[string]interface{}{
		"stringTemplate": `<err>${Message}</err>`,
		"contentType":    "application/xml",
	}, faultCtx(400, &policy.FaultDetails{Message: `a < b & c </err><injected/>`}, ""))

	body := string(m.Body)
	if strings.Contains(body, "<injected/>") {
		t.Fatalf("element injection survived escaping: %s", body)
	}
	for _, raw := range []string{"a < b", "& c"} {
		if strings.Contains(body, raw) {
			t.Fatalf("unescaped %q in output: %s", raw, body)
		}
	}
	// And it must still be parseable, with the original text intact after unescaping.
	var out struct {
		Value string `xml:",chardata"`
	}
	if err := xml.Unmarshal(m.Body, &out); err != nil {
		t.Fatalf("escaped output is not valid XML: %v (%s)", err, body)
	}
	if out.Value != `a < b & c </err><injected/>` {
		t.Fatalf("message did not round-trip: %q", out.Value)
	}
}

// Escaping is chosen by the syntax being produced, so an operator does not state it twice.
func TestEscapeModeDerivedFromContentType(t *testing.T) {
	cases := []struct {
		contentType string
		want        escapeMode
	}{
		{"application/xml", escapeXML},
		{"text/xml", escapeXML},
		{"application/soap+xml", escapeXML},
		{"application/json", escapeJSON},
		{"text/plain", escapeNone},
	}
	for _, tc := range cases {
		p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"stringTemplate": "${Message}", "contentType": tc.contentType})
		if err != nil {
			t.Fatal(err)
		}
		if got := p.(*ErrorFormatterPolicy).effectiveEscape(); got != tc.want {
			t.Errorf("%s -> %s, want %s", tc.contentType, got, tc.want)
		}
	}
}

// SOAP 1.1: unqualified fault children, text/xml, Client/Server. A SOAP stack rejects the
// envelope if any of those is wrong.
func TestPresetSOAP11(t *testing.T) {
	m := render(t, map[string]interface{}{"preset": "soap11"},
		faultCtx(401, &policy.FaultDetails{Code: "900902", Message: "Valid API key required"}, ""))

	if m.HeadersToSet["content-type"] != "text/xml" {
		t.Fatalf("SOAP 1.1 uses text/xml, got %q", m.HeadersToSet["content-type"])
	}
	var env struct {
		Fault struct {
			Code   string `xml:"faultcode"`
			String string `xml:"faultstring"`
			Detail struct {
				FaultCode string `xml:"errorcode"`
			} `xml:"detail"`
		} `xml:"Body>Fault"`
	}
	if err := xml.Unmarshal(m.Body, &env); err != nil {
		t.Fatalf("not a parseable SOAP envelope: %v (%s)", err, m.Body)
	}
	if env.Fault.Code != "soapenv:Client" {
		t.Errorf("a 401 is a client fault, got %q", env.Fault.Code)
	}
	if env.Fault.String != "Valid API key required" {
		t.Errorf("faultstring = %q", env.Fault.String)
	}
	if env.Fault.Detail.FaultCode != "900902" {
		t.Errorf("detail errorcode = %q", env.Fault.Detail.FaultCode)
	}
	if !strings.Contains(string(m.Body), "schemas.xmlsoap.org/soap/envelope") {
		t.Errorf("wrong namespace for SOAP 1.1: %s", m.Body)
	}
}

// SOAP 1.2 renamed the children and qualified them, and uses its own media type.
func TestPresetSOAP12(t *testing.T) {
	m := render(t, map[string]interface{}{"preset": "soap12"},
		faultCtx(503, &policy.FaultDetails{Code: "905001", Message: "Upstream unavailable"}, ""))

	if m.HeadersToSet["content-type"] != "application/soap+xml" {
		t.Fatalf("SOAP 1.2 media type = %q", m.HeadersToSet["content-type"])
	}
	var env struct {
		Fault struct {
			Value string `xml:"Code>Value"`
			Text  string `xml:"Reason>Text"`
		} `xml:"Body>Fault"`
	}
	if err := xml.Unmarshal(m.Body, &env); err != nil {
		t.Fatalf("not a parseable SOAP 1.2 envelope: %v (%s)", err, m.Body)
	}
	if env.Fault.Value != "env:Receiver" {
		t.Errorf("a 5xx is a receiver fault in SOAP 1.2, got %q", env.Fault.Value)
	}
	if env.Fault.Text != "Upstream unavailable" {
		t.Errorf("Reason/Text = %q", env.Fault.Text)
	}
	if !strings.Contains(string(m.Body), "www.w3.org/2003/05/soap-envelope") {
		t.Errorf("wrong namespace for SOAP 1.2: %s", m.Body)
	}
	if !strings.Contains(string(m.Body), `xml:lang="en"`) {
		t.Errorf("SOAP 1.2 Reason/Text requires xml:lang: %s", m.Body)
	}
}

// A 4xx must be a client/sender fault and a 5xx a server/receiver one, in both versions.
func TestSoapFaultCodeFollowsStatus(t *testing.T) {
	for _, tc := range []struct {
		status   int
		v11, v12 string
	}{
		{422, "soapenv:Client", "env:Sender"},
		{500, "soapenv:Server", "env:Receiver"},
	} {
		m11 := render(t, map[string]interface{}{"preset": "soap11"}, faultCtx(tc.status, nil, ""))
		if !strings.Contains(string(m11.Body), tc.v11) {
			t.Errorf("status %d soap11 should be %s: %s", tc.status, tc.v11, m11.Body)
		}
		m12 := render(t, map[string]interface{}{"preset": "soap12"}, faultCtx(tc.status, nil, ""))
		if !strings.Contains(string(m12.Body), tc.v12) {
			t.Errorf("status %d soap12 should be %s: %s", tc.status, tc.v12, m12.Body)
		}
	}
}

// No preset renders the description. For a guardrail rejection it is the content the
// guardrail blocked, and a preset is the one place an operator did not choose to send it.
func TestPresetsNeverRenderTheDescription(t *testing.T) {
	const blocked = "THE-BLOCKED-CONTENT"
	for _, preset := range presetNames() {
		m := render(t, map[string]interface{}{"preset": preset},
			faultCtx(422, &policy.FaultDetails{Message: "Content rejected", Description: blocked}, ""))
		if strings.Contains(string(m.Body), blocked) {
			t.Errorf("preset %s rendered the description: %s", preset, m.Body)
		}
	}
}

// JSON-RPC: a numeric code from the reserved server range, and id present-and-null.
func TestPresetJSONRPC(t *testing.T) {
	m := render(t, map[string]interface{}{"preset": "jsonrpc"},
		faultCtx(401, &policy.FaultDetails{Message: "Denied", Description: "token expired"}, ""))

	got := asJSON(t, m.Body)
	if got["jsonrpc"] != "2.0" {
		t.Fatalf("missing version: %s", m.Body)
	}
	id, present := got["id"]
	if !present || id != nil {
		t.Fatalf("id must be present AND null, got %v (present=%v)", id, present)
	}
	errObj := got["error"].(map[string]any)
	code, isNum := errObj["code"].(float64)
	if !isNum {
		t.Fatalf("JSON-RPC code must be a NUMBER, got %T: %s", errObj["code"], m.Body)
	}
	if code != -32600 {
		t.Errorf("a 4xx maps to -32600, got %v", code)
	}
	if _, present := errObj["data"]; present {
		t.Errorf("the description must not reach the client as data: %s", m.Body)
	}

	// 5xx uses the internal-error code instead.
	m5 := render(t, map[string]interface{}{"preset": "jsonrpc"}, faultCtx(503, nil, ""))
	e5 := asJSON(t, m5.Body)["error"].(map[string]any)
	if e5["code"].(float64) != -32603 {
		t.Errorf("a 5xx maps to -32603, got %v", e5["code"])
	}
}

// An operator writing their own SOAP-ish shape gets the same escaping and status mapping.
func TestCustomXMLTemplateUsesTheSoapPlaceholders(t *testing.T) {
	m := render(t, map[string]interface{}{
		"stringTemplate": `<f><c>${Soap11Code}</c><m>${Message}</m><s>${Status}</s></f>`,
		"contentType":    "text/xml",
	}, faultCtx(429, &policy.FaultDetails{Message: "slow down"}, ""))

	body := string(m.Body)
	for _, want := range []string{"<c>soapenv:Client</c>", "<m>slow down</m>", "<s>429</s>"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
}

// An explicit contentType overrides a preset's default, without changing the shape.
func TestExplicitContentTypeBeatsThePreset(t *testing.T) {
	m := render(t, map[string]interface{}{
		"preset": "soap11", "contentType": "application/soap+xml",
	}, faultCtx(401, nil, ""))
	if m.HeadersToSet["content-type"] != "application/soap+xml" {
		t.Fatalf("explicit contentType ignored: %q", m.HeadersToSet["content-type"])
	}
	if !strings.Contains(string(m.Body), "faultcode") {
		t.Fatalf("shape should still be SOAP 1.1: %s", m.Body)
	}
}

// statusCode replaces the status, and the body is rendered for the NEW status: a body that said
// 401 while the client received 400 would contradict itself.
func TestStatusCodeReplacesTheStatus(t *testing.T) {
	m := render(t, map[string]interface{}{
		"statusCode": float64(400), // YAML and JSON numbers arrive as float64
		"template":   map[string]interface{}{"status": "${Status}", "type": "${OpenAIType}"},
	}, faultCtx(401, &policy.FaultDetails{Code: "900902", Message: "Valid API key required"}, "api-key-auth"))

	if m.StatusCode == nil || *m.StatusCode != 400 {
		t.Fatalf("StatusCode = %v, want 400", m.StatusCode)
	}
	got := asJSON(t, m.Body)
	if got["status"] != float64(400) {
		t.Errorf("${Status} = %v, want the new status 400", got["status"])
	}
	if got["type"] != "invalid_request_error" {
		t.Errorf("${OpenAIType} = %v, want the type for 400, not for 401", got["type"])
	}
}

// Without statusCode the status is left alone: nil, not the current value, so the policy does
// not claim to have changed something it did not.
func TestStatusCodeUnsetKeepsTheStatus(t *testing.T) {
	m := render(t, map[string]interface{}{"preset": "canonical"}, faultCtx(503, nil, ""))
	if m.StatusCode != nil {
		t.Fatalf("StatusCode = %d, want nil when statusCode is not configured", *m.StatusCode)
	}
}

// The status-derived protocol codes follow the new status — a 500 turned into a 400 is a SOAP
// Client fault and a JSON-RPC invalid request — but a JSON-RPC code the failing policy stated
// itself is kept, because it is more specific than anything a status can say.
func TestStatusCodeDrivesTheDerivedCodes(t *testing.T) {
	soap := render(t, map[string]interface{}{"preset": "soap11", "statusCode": 400}, faultCtx(500, nil, ""))
	if !strings.Contains(string(soap.Body), "<faultcode>soapenv:Client</faultcode>") {
		t.Errorf("SOAP fault code must follow the new 4xx status: %s", soap.Body)
	}

	rpc := render(t, map[string]interface{}{"preset": "jsonrpc", "statusCode": 200}, faultCtx(503, nil, ""))
	if code := asJSON(t, rpc.Body)["error"].(map[string]any)["code"]; code != float64(-32603) {
		t.Errorf("a 200 carrying an error keeps the internal-error code, got %v", code)
	}
	if *rpc.StatusCode != 200 {
		t.Errorf("JSON-RPC over HTTP may answer 200; got %d", *rpc.StatusCode)
	}

	stated := -32602
	kept := render(t, map[string]interface{}{"preset": "jsonrpc", "statusCode": 500},
		faultCtx(400, &policy.FaultDetails{JSONRPC: &policy.JSONRPCError{Code: &stated}}, "mcp-auth"))
	if code := asJSON(t, kept.Body)["error"].(map[string]any)["code"]; code != float64(stated) {
		t.Errorf("a stated JSON-RPC code must survive a status change, got %v", code)
	}
}

// Each response gets its own copy of the status, so no caller holds a pointer into the shared
// policy instance.
func TestStatusCodeIsNotShared(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"statusCode": 418})
	if err != nil {
		t.Fatal(err)
	}
	first := p.(*ErrorFormatterPolicy).OnFault(context.Background(), faultCtx(500, nil, ""), nil)
	*first.StatusCode = 999
	second := p.(*ErrorFormatterPolicy).OnFault(context.Background(), faultCtx(500, nil, ""), nil)
	if *second.StatusCode != 418 {
		t.Fatalf("a mutated response leaked into the next one: %d", *second.StatusCode)
	}
}

// A status the gateway cannot send is refused when the API is deployed, not discovered while a
// request is failing.
func TestStatusCodeIsValidatedUpFront(t *testing.T) {
	for name, value := range map[string]interface{}{
		"informational": 101,
		"out of range":  600,
		"fractional":    401.5,
		"a string":      "401",
		"negative":      -1,
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"statusCode": value}); err == nil {
			t.Errorf("%s (%v): expected a configuration error", name, value)
		}
	}
	for _, ok := range []interface{}{200, int64(302), float64(599)} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"statusCode": ok}); err != nil {
			t.Errorf("statusCode %v should be accepted: %v", ok, err)
		}
	}
}
