package jsonxmlmediation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestJSONXMLMediationPolicy_Mode(t *testing.T) {
	p := &JSONXMLMediationPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func createHeaders(key, value string) *policy.Headers {
	h := map[string][]string{}
	h[key] = []string{value}
	return policy.NewHeaders(h)
}

func parseErrorJSON(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	return out
}

func newConfiguredPolicy(t *testing.T, params map[string]interface{}) *JSONXMLMediationPolicy {
	t.Helper()

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	typed, ok := p.(*JSONXMLMediationPolicy)
	if !ok {
		t.Fatalf("expected *JSONXMLMediationPolicy, got %T", p)
	}

	return typed
}

func configuredParams(upstreamPayloadFormat string, downstreamPayloadFormat ...string) map[string]interface{} {
	params := map[string]interface{}{
		"upstreamPayloadFormat": upstreamPayloadFormat,
	}
	if len(downstreamPayloadFormat) > 0 {
		params["downstreamPayloadFormat"] = downstreamPayloadFormat[0]
	}
	return params
}

func TestGetPolicy(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams(" XML ", " json "))
	if p.upstreamPayloadFormat != upstreamPayloadFormatXML {
		t.Fatalf("expected normalized upstream format %q, got %q", upstreamPayloadFormatXML, p.upstreamPayloadFormat)
	}
	if p.downstreamPayloadFormat != upstreamPayloadFormatJSON {
		t.Fatalf("expected downstream format %q, got %q", upstreamPayloadFormatJSON, p.downstreamPayloadFormat)
	}

	p2 := newConfiguredPolicy(t, configuredParams("json", " xml "))
	if p2.upstreamPayloadFormat != upstreamPayloadFormatJSON {
		t.Fatalf("expected upstream format %q, got %q", upstreamPayloadFormatJSON, p2.upstreamPayloadFormat)
	}
	if p2.downstreamPayloadFormat != upstreamPayloadFormatXML {
		t.Fatalf("expected normalized downstream format %q, got %q", upstreamPayloadFormatXML, p2.downstreamPayloadFormat)
	}

	if p == p2 {
		t.Fatalf("expected distinct policy instances per configuration")
	}
}

// TestGetPolicy_DownstreamPayloadFormatAliasing covers the backward-compatible
// resolution of the preferred "downstreamPayloadFormat" key and its deprecated
// "downsteamPayloadFormat" alias: either key alone is accepted, both set to the
// same value is accepted, and conflicting values are covered separately in
// TestGetPolicy_InvalidUpstreamFormatConfig.
func TestGetPolicy_DownstreamPayloadFormatAliasing(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]interface{}
	}{
		{
			name:   "new key only",
			params: map[string]interface{}{"upstreamPayloadFormat": "xml", "downstreamPayloadFormat": "json"},
		},
		{
			name:   "deprecated key only",
			params: map[string]interface{}{"upstreamPayloadFormat": "xml", "downsteamPayloadFormat": "json"},
		},
		{
			name:   "both keys set to the same value",
			params: map[string]interface{}{"upstreamPayloadFormat": "xml", "downstreamPayloadFormat": "json", "downsteamPayloadFormat": "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newConfiguredPolicy(t, tc.params)
			if p.upstreamPayloadFormat != upstreamPayloadFormatXML {
				t.Fatalf("expected upstream format %q, got %q", upstreamPayloadFormatXML, p.upstreamPayloadFormat)
			}
			if p.downstreamPayloadFormat != upstreamPayloadFormatJSON {
				t.Fatalf("expected downstream format %q, got %q", upstreamPayloadFormatJSON, p.downstreamPayloadFormat)
			}
		})
	}
}

func TestGetPolicy_InvalidUpstreamFormatConfig(t *testing.T) {
	cases := []struct {
		name      string
		params    map[string]interface{}
		expectMsg string
	}{
		{
			name:      "nil params",
			params:    nil,
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "missing upstreamPayloadFormat",
			params:    map[string]interface{}{},
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "empty upstreamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": ""},
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "invalid enum value",
			params:    map[string]interface{}{"upstreamPayloadFormat": "yaml"},
			expectMsg: "upstreamPayloadFormat must be one of [xml, json]",
		},
		{
			name:      "invalid type",
			params:    map[string]interface{}{"upstreamPayloadFormat": true},
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "missing downstreamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml"},
			expectMsg: "downstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "empty downstreamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downstreamPayloadFormat": ""},
			expectMsg: "downstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "invalid downstream enum value",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downstreamPayloadFormat": "yaml"},
			expectMsg: "downstreamPayloadFormat must be one of [xml, json]",
		},
		{
			name:      "same upstream and downstream format",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downstreamPayloadFormat": "xml"},
			expectMsg: "downstreamPayloadFormat must be different from upstreamPayloadFormat",
		},
		{
			name:      "empty deprecated downsteamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downsteamPayloadFormat": ""},
			expectMsg: "downsteamPayloadFormat must be a non-empty string",
		},
		{
			name:      "invalid deprecated downsteamPayloadFormat enum value",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downsteamPayloadFormat": "yaml"},
			expectMsg: "downsteamPayloadFormat must be one of [xml, json]",
		},
		{
			name:      "both downstream keys set to conflicting values",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downstreamPayloadFormat": "json", "downsteamPayloadFormat": "xml"},
			expectMsg: `downstreamPayloadFormat ("json") and the deprecated downsteamPayloadFormat ("xml") must not be set to different values`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if err == nil {
				t.Fatalf("expected error for params %#v", tc.params)
			}
			if !strings.Contains(err.Error(), tc.expectMsg) {
				t.Fatalf("expected error containing %q, got %q", tc.expectMsg, err.Error())
			}
		})
	}
}

func TestOnRequest_JSONToXML_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))
	ctx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`{"name":"John","age":30}`), Present: true},
		Headers: createHeaders("content-type", "application/json"),
	}

	result := p.OnRequestBody(context.Background(), ctx, nil)
	mods, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
	if mods.Body == nil || !strings.Contains(string(mods.Body), "<name>John</name>") {
		t.Fatalf("expected transformed XML body, got: %s", string(mods.Body))
	}
	if mods.HeadersToSet["content-type"] != "application/xml" {
		t.Fatalf("unexpected content-type: %s", mods.HeadersToSet["content-type"])
	}
	if mods.HeadersToSet["content-length"] == "" {
		t.Fatalf("expected content-length header")
	}
}

func TestOnRequest_XMLToJSON_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("json", "xml"))
	ctx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`<root><name>John</name><age>30</age></root>`), Present: true},
		Headers: createHeaders("content-type", "text/xml; charset=utf-8"),
	}

	result := p.OnRequestBody(context.Background(), ctx, nil)
	mods, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
	if mods.Body == nil {
		t.Fatalf("expected transformed JSON body")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(mods.Body, &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v", err)
	}
	if mods.HeadersToSet["content-type"] != "application/json" {
		t.Fatalf("unexpected content-type: %s", mods.HeadersToSet["content-type"])
	}
}

func TestOnResponse_XMLToJSON_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`<root><status>ok</status></root>`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/xml"),
	}

	result := p.OnResponseBody(context.Background(), ctx, nil)
	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mods.Body == nil {
		t.Fatalf("expected transformed JSON response body")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(mods.Body, &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v", err)
	}
	if mods.HeadersToSet["content-type"] != "application/json" {
		t.Fatalf("unexpected content-type: %s", mods.HeadersToSet["content-type"])
	}
}

func TestOnResponse_JSONToXML_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("json", "xml"))
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"status":"ok"}`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/json; charset=utf-8"),
	}

	result := p.OnResponseBody(context.Background(), ctx, nil)
	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mods.Body == nil || !strings.Contains(string(mods.Body), "<status>ok</status>") {
		t.Fatalf("expected transformed XML response body, got: %s", string(mods.Body))
	}
	if mods.HeadersToSet["content-type"] != "application/xml" {
		t.Fatalf("unexpected content-type: %s", mods.HeadersToSet["content-type"])
	}
}

func TestOnRequest_ContentTypeAndPayloadErrors(t *testing.T) {
	pJSONToXML := newConfiguredPolicy(t, configuredParams("xml", "json"))
	pXMLToJSON := newConfiguredPolicy(t, configuredParams("json", "xml"))

	wrongTypeCtx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`{"name":"x"}`), Present: true},
		Headers: createHeaders("content-type", "application/xml"),
	}
	res := pJSONToXML.OnRequestBody(context.Background(), wrongTypeCtx, nil)
	immediate, ok := res.(policy.ImmediateResponse)
	if !ok || immediate.StatusCode != 500 {
		t.Fatalf("expected 500 ImmediateResponse for wrong content type, got %T %#v", res, res)
	}

	invalidJSONCtx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`{"name":`), Present: true},
		Headers: createHeaders("content-type", "application/json"),
	}
	res = pJSONToXML.OnRequestBody(context.Background(), invalidJSONCtx, nil)
	immediate, ok = res.(policy.ImmediateResponse)
	if !ok || immediate.StatusCode != 500 {
		t.Fatalf("expected 500 ImmediateResponse for invalid JSON, got %T %#v", res, res)
	}

	invalidXMLCtx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`<root><name>x</root>`), Present: true},
		Headers: createHeaders("content-type", "application/xml"),
	}
	res = pXMLToJSON.OnRequestBody(context.Background(), invalidXMLCtx, nil)
	immediate, ok = res.(policy.ImmediateResponse)
	if !ok || immediate.StatusCode != 500 {
		t.Fatalf("expected 500 ImmediateResponse for invalid XML, got %T %#v", res, res)
	}

	errBody := parseErrorJSON(t, immediate.Body)
	if errBody["error"] != "Internal Server Error" {
		t.Fatalf("expected internal server error body, got %#v", errBody)
	}
}

func TestOnResponse_ContentTypeAndPayloadErrors(t *testing.T) {
	pXMLToJSON := newConfiguredPolicy(t, configuredParams("xml", "json"))
	pJSONToXML := newConfiguredPolicy(t, configuredParams("json", "xml"))

	wrongTypeCtx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`<root/>`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/json"),
	}
	res := pXMLToJSON.OnResponseBody(context.Background(), wrongTypeCtx, nil)
	mods, ok := res.(policy.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != 500 {
		t.Fatalf("expected 500 UpstreamResponseModifications for wrong content type, got %T %#v", res, res)
	}

	invalidJSONCtx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"x":`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/json"),
	}
	res = pJSONToXML.OnResponseBody(context.Background(), invalidJSONCtx, nil)
	mods, ok = res.(policy.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != 500 {
		t.Fatalf("expected 500 UpstreamResponseModifications for invalid JSON, got %T %#v", res, res)
	}

	invalidXMLCtx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`<root><x></root>`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/xml"),
	}
	res = pXMLToJSON.OnResponseBody(context.Background(), invalidXMLCtx, nil)
	mods, ok = res.(policy.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != 500 {
		t.Fatalf("expected 500 UpstreamResponseModifications for invalid XML, got %T %#v", res, res)
	}

	errBody := parseErrorJSON(t, mods.Body)
	if errBody["error"] != "Internal Server Error" {
		t.Fatalf("expected internal server error body, got %#v", errBody)
	}
}

func TestNoBodyPassThrough(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))

	reqCtx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte{}, Present: false},
		Headers: createHeaders("content-type", "application/json"),
	}
	reqResult := p.OnRequestBody(context.Background(), reqCtx, nil)
	reqMods, ok := reqResult.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", reqResult)
	}
	if reqMods.Body != nil {
		t.Fatalf("expected nil body for request pass-through, got %s", string(reqMods.Body))
	}

	respCtx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte{}, Present: false},
		ResponseHeaders: createHeaders("content-type", "application/xml"),
	}
	respResult := p.OnResponseBody(context.Background(), respCtx, nil)
	respMods, ok := respResult.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", respResult)
	}
	if respMods.Body != nil {
		t.Fatalf("expected nil body for response pass-through, got %s", string(respMods.Body))
	}
}

func TestConversionHelpers(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))

	xmlData, err := p.convertJSONBytesToXML([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("convertJSONBytesToXML failed: %v", err)
	}
	if !strings.Contains(string(xmlData), "<a>1</a>") {
		t.Fatalf("unexpected XML: %s", xmlData)
	}

	jsonData, err := p.convertXMLToJSON([]byte(`<root><a>1</a></root>`))
	if err != nil {
		t.Fatalf("convertXMLToJSON failed: %v", err)
	}
	if !json.Valid(jsonData) {
		t.Fatalf("expected valid JSON output: %s", jsonData)
	}
}

// ─── conversion budget coverage ───────────────────────────────────────────────

// buildNestedJSONArray returns a JSON array nested `depth` levels deep whose
// innermost level holds `leaves` integer values.
func buildNestedJSONArray(depth, leaves int) []byte {
	var b strings.Builder
	b.WriteString(strings.Repeat("[", depth))
	b.WriteString("1")
	b.WriteString(strings.Repeat(",1", leaves-1))
	b.WriteString(strings.Repeat("]", depth))
	return []byte(b.String())
}

// A request body that exceeds the conversion budget must be rejected with a
// 500 and a complexity message, rather than converted.
func TestOnRequest_JSONToXML_RejectsAmplificationPayload(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))
	ctx := &policy.RequestContext{
		Body:    &policy.Body{Content: buildNestedJSONArray(9000, 12000), Present: true},
		Headers: createHeaders("content-type", "application/json"),
	}

	result := p.OnRequestBody(context.Background(), ctx, nil)
	res, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected an over-budget payload to be rejected, got %T", result)
	}
	if res.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", res.StatusCode)
	}
	if msg, _ := parseErrorJSON(t, res.Body)["message"].(string); !strings.Contains(msg, "too complex") {
		t.Fatalf("expected a complexity rejection, got %q", msg)
	}
}

// For input within the conversion budget, output size must stay proportional
// to input size rather than growing with nesting depth.
func TestConvertJSONToXML_OutputIsNotAmplified(t *testing.T) {
	p := &JSONXMLMediationPolicy{}
	input := buildNestedJSONArray(200, 1000) // Within budget, but deeply nested

	out, err := p.convertJSONBytesToXML(input)
	if err != nil {
		t.Fatalf("conversion of an in-budget payload should succeed: %v", err)
	}
	if ratio := float64(len(out)) / float64(len(input)); ratio > 20 {
		t.Fatalf("output size ratio %.0fx exceeds the expected bound (%d -> %d bytes)",
			ratio, len(input), len(out))
	}
}

// TestConvertJSONToXML_RejectsExcessDepth covers the depth budget independently
// of the element budget — a single deep chain spends almost no elements.
func TestConvertJSONToXML_RejectsExcessDepth(t *testing.T) {
	p := &JSONXMLMediationPolicy{}
	if _, err := p.convertJSONBytesToXML(buildNestedJSONArray(maxConversionDepth+50, 1)); err == nil {
		t.Fatal("expected a payload past maxConversionDepth to be rejected")
	}
	if _, err := p.convertJSONBytesToXML(buildNestedJSONArray(10, 1)); err != nil {
		t.Fatalf("a shallow payload must still convert: %v", err)
	}
}

// TestConvertJSONToXML_RejectsExcessElements covers the element budget
// independently of depth — a flat but very wide document.
func TestConvertJSONToXML_RejectsExcessElements(t *testing.T) {
	p := &JSONXMLMediationPolicy{}
	if _, err := p.convertJSONBytesToXML(buildNestedJSONArray(1, maxConversionElements+10)); err == nil {
		t.Fatal("expected a payload past maxConversionElements to be rejected")
	}
}

// XML input that exceeds the conversion budget must be rejected, while an
// ordinary document still converts.
func TestConvertXMLToJSON_RejectsAmplificationPayload(t *testing.T) {
	p := &JSONXMLMediationPolicy{}
	const depth = 4900
	body := strings.Repeat("<a>", depth) + strings.Repeat("<v>1</v>", 20000) + strings.Repeat("</a>", depth)

	if _, err := p.convertXMLToJSON([]byte(body)); err == nil {
		t.Fatal("expected an over-budget XML payload to be rejected")
	}
	if _, err := p.convertXMLToJSON([]byte(`<root><name>John</name></root>`)); err != nil {
		t.Fatalf("an ordinary XML document must still convert: %v", err)
	}
}
