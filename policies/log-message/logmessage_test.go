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

package logmessage

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var slogMessagePattern = regexp.MustCompile(`msg="((?:\\.|[^"])*)"`)

func TestLogMessagePolicy_Mode(t *testing.T) {
	p := &LogMessagePolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeStream,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func createTestHeaders(headers map[string]string) *policy.Headers {
	headerMap := make(map[string][]string)
	for key, value := range headers {
		headerMap[key] = []string{value}
	}
	return policy.NewHeaders(headerMap)
}

func createTestHeadersMulti(headers map[string][]string) *policy.Headers {
	headerMap := make(map[string][]string)
	for key, values := range headers {
		headerMap[key] = values
	}
	return policy.NewHeaders(headerMap)
}

func toInterfaceSlice(items []string) []interface{} {
	result := make([]interface{}, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}

func captureLogRecords(t *testing.T, fn func()) []LogRecord {
	t.Helper()

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(previous)

	fn()

	output := strings.TrimSpace(buf.String())
	if output == "" {
		return nil
	}

	lines := strings.Split(output, "\n")
	records := make([]LogRecord, 0, len(lines))
	for _, line := range lines {
		match := slogMessagePattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}

		unescaped, err := strconv.Unquote(`"` + match[1] + `"`)
		if err != nil {
			t.Fatalf("failed to decode slog message: %v", err)
		}

		var record LogRecord
		if err := json.Unmarshal([]byte(unescaped), &record); err != nil {
			t.Fatalf("failed to unmarshal log record: %v", err)
		}
		records = append(records, record)
	}

	return records
}

func getHeaderValue(headers map[string]interface{}, name string) (interface{}, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func TestGetPolicy(t *testing.T) {
	policyInstance, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	if _, ok := policyInstance.(*LogMessagePolicy); !ok {
		t.Fatalf("expected *LogMessagePolicy, got %T", policyInstance)
	}
}

func TestParseFlowConfig_ValidRequestConfig(t *testing.T) {
	p := &LogMessagePolicy{}

	cfg := p.parseFlowConfig(map[string]interface{}{
		"request": map[string]interface{}{
			"payload": true,
			"headers": true,
		},
	}, "request")

	if !cfg.logPayload {
		t.Fatalf("expected logPayload to be true")
	}
	if !cfg.logHeaders {
		t.Fatalf("expected logHeaders to be true")
	}
}

func TestParseFlowConfig_InvalidTypesFallbackToDefaults(t *testing.T) {
	p := &LogMessagePolicy{}

	cfg := p.parseFlowConfig(map[string]interface{}{
		"request": "invalid",
	}, "request")
	if cfg.logPayload || cfg.logHeaders {
		t.Fatalf("expected default config for invalid flow type, got %+v", cfg)
	}

	cfg = p.parseFlowConfig(map[string]interface{}{
		"request": map[string]interface{}{
			"payload": "true",
			"headers": 1,
		},
	}, "request")
	if cfg.logPayload || cfg.logHeaders {
		t.Fatalf("expected default values for invalid fields, got %+v", cfg)
	}
}

func TestBuildHeadersMapV2_MasksAuthorization(t *testing.T) {
	p := &LogMessagePolicy{}
	headers := createTestHeadersMulti(map[string][]string{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer secret"},
		"X-API-Key":     {"api-key"},
		"X-Multi":       {"one", "two"},
	})

	result := p.buildHeadersMap(headers)

	authValue, ok := getHeaderValue(result, "authorization")
	if !ok {
		t.Fatalf("expected authorization header in result")
	}
	if authValue != "***" {
		t.Fatalf("expected authorization to be masked, got %v", authValue)
	}

	if _, ok := getHeaderValue(result, "x-api-key"); !ok {
		t.Fatalf("expected x-api-key to be present (exclusion is via fields.exclude dotted paths)")
	}

	multiValue, ok := getHeaderValue(result, "x-multi")
	if !ok {
		t.Fatalf("expected x-multi header to exist")
	}
	multiSlice, ok := multiValue.([]string)
	if !ok {
		t.Fatalf("expected x-multi to be []string, got %T", multiValue)
	}
	if len(multiSlice) != 2 || multiSlice[0] != "one" || multiSlice[1] != "two" {
		t.Fatalf("unexpected x-multi header value: %v", multiSlice)
	}
}

func TestBuildHeadersMapV2_NilHeaders(t *testing.T) {
	p := &LogMessagePolicy{}
	result := p.buildHeadersMap(nil)
	if len(result) != 0 {
		t.Fatalf("expected empty map for nil headers, got %v", result)
	}
}

func TestGetRequestID(t *testing.T) {
	p := &LogMessagePolicy{}

	t.Run("present", func(t *testing.T) {
		headers := createTestHeaders(map[string]string{"x-request-id": "req-123"})
		if requestID := p.getRequestID(headers); requestID != "req-123" {
			t.Fatalf("expected req-123, got %s", requestID)
		}
	})

	t.Run("missing", func(t *testing.T) {
		headers := createTestHeaders(map[string]string{"content-type": "application/json"})
		if requestID := p.getRequestID(headers); requestID != ErrMsgMissingReqID {
			t.Fatalf("expected %s, got %s", ErrMsgMissingReqID, requestID)
		}
	})

	t.Run("nil headers", func(t *testing.T) {
		if requestID := p.getRequestID(nil); requestID != ErrMsgMissingReqID {
			t.Fatalf("expected %s, got %s", ErrMsgMissingReqID, requestID)
		}
	})
}

func TestOnRequestHeaders_NoRequestConfig_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestHeaderContext{
		Headers: createTestHeaders(map[string]string{
			"x-request-id": "req-001",
		}),
		Method: "POST",
		Path:   "/resource",
	}

	records := captureLogRecords(t, func() {
		result := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
			"response": map[string]interface{}{"headers": true},
		})
		if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
		}
	})

	if len(records) != 0 {
		t.Fatalf("expected no request logs, got %d", len(records))
	}
}

func TestOnRequestHeaders_LogsHeaders(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestHeaderContext{
		Headers: createTestHeaders(map[string]string{
			"x-request-id":   "req-123",
			"authorization":  "Bearer secret",
			"x-api-key":      "api-key-1",
			"x-trace-header": "trace-abc",
		}),
		Method: "POST",
		Path:   "/login",
	}

	records := captureLogRecords(t, func() {
		result := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{
			"request": map[string]interface{}{
				"headers": true,
			},
		})
		if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
		}
	})

	if len(records) != 1 {
		t.Fatalf("expected 1 request log record, got %d", len(records))
	}

	record := records[0]
	if record.MediationFlow != MediationFlowRequest {
		t.Fatalf("expected mediation flow %s, got %s", MediationFlowRequest, record.MediationFlow)
	}
	if record.RequestID != "req-123" {
		t.Fatalf("expected request id req-123, got %s", record.RequestID)
	}
	if record.Payload != "" {
		t.Fatalf("expected no payload in header phase log, got %q", record.Payload)
	}

	auth, ok := getHeaderValue(record.Headers, "authorization")
	if !ok || auth != "***" {
		t.Fatalf("expected masked authorization header, got %v", auth)
	}
	if traceValue, ok := getHeaderValue(record.Headers, "x-trace-header"); !ok || traceValue != "trace-abc" {
		t.Fatalf("expected x-trace-header to be logged, got %v", traceValue)
	}
}

func TestOnRequestHeaders_InvalidRequestConfigType_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestHeaderContext{
		Headers: createTestHeaders(map[string]string{"x-request-id": "req-002"}),
		Method:  "POST",
		Path:    "/resource",
	}

	records := captureLogRecords(t, func() {
		p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{"request": true})
	})

	if len(records) != 0 {
		t.Fatalf("expected no logs for invalid request config type, got %d", len(records))
	}
}

func TestOnRequestBody_NoRequestConfig_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestContext{
		Body: &policy.Body{Content: []byte(`{"hello":"world"}`), Present: true},
		Headers: createTestHeaders(map[string]string{
			"x-request-id": "req-001",
		}),
		Method: "POST",
		Path:   "/resource",
	}

	records := captureLogRecords(t, func() {
		result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{
			"response": map[string]interface{}{"payload": true},
		})
		if _, ok := result.(policy.UpstreamRequestModifications); !ok {
			t.Fatalf("expected UpstreamRequestModifications, got %T", result)
		}
	})

	if len(records) != 0 {
		t.Fatalf("expected no request logs, got %d", len(records))
	}
}

func TestOnRequestBody_LogsPayload(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestContext{
		Body: &policy.Body{Content: []byte(`{"action":"login"}`), Present: true},
		Headers: createTestHeaders(map[string]string{
			"x-request-id": "req-123",
		}),
		Method: "POST",
		Path:   "/login",
	}

	records := captureLogRecords(t, func() {
		result := p.OnRequestBody(context.Background(), ctx, map[string]interface{}{
			"request": map[string]interface{}{
				"payload": true,
			},
		})
		mods, ok := result.(policy.UpstreamRequestModifications)
		if !ok {
			t.Fatalf("expected UpstreamRequestModifications, got %T", result)
		}
		if mods.Body != nil {
			t.Fatalf("expected no body modification, got %s", string(mods.Body))
		}
	})

	if len(records) != 1 {
		t.Fatalf("expected 1 request log record, got %d", len(records))
	}

	record := records[0]
	if record.MediationFlow != MediationFlowRequest {
		t.Fatalf("expected mediation flow %s, got %s", MediationFlowRequest, record.MediationFlow)
	}
	if record.RequestID != "req-123" {
		t.Fatalf("expected request id req-123, got %s", record.RequestID)
	}
	if record.Payload != `{"action":"login"}` {
		t.Fatalf("unexpected payload: %s", record.Payload)
	}
}

func TestOnRequestBody_InvalidRequestConfigType_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`{"hello":"world"}`), Present: true},
		Headers: createTestHeaders(map[string]string{"x-request-id": "req-002"}),
		Method:  "POST",
		Path:    "/resource",
	}

	records := captureLogRecords(t, func() {
		p.OnRequestBody(context.Background(), ctx, map[string]interface{}{"request": true})
	})

	if len(records) != 0 {
		t.Fatalf("expected no logs for invalid request config type, got %d", len(records))
	}
}

func TestOnResponseHeaders_NoResponseConfig_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseHeaderContext{
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-001"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		result := p.OnResponseHeaders(context.Background(), ctx, map[string]interface{}{
			"request": map[string]interface{}{"headers": true},
		})
		if _, ok := result.(policy.DownstreamResponseHeaderModifications); !ok {
			t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", result)
		}
	})

	if len(records) != 0 {
		t.Fatalf("expected no response logs, got %d", len(records))
	}
}

func TestOnResponseHeaders_LogsHeaders(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseHeaderContext{
		ResponseHeaders: createTestHeaders(map[string]string{
			"x-request-id":     "resp-123",
			"set-cookie":       "session=abc",
			"x-internal-token": "token-1",
		}),
		RequestMethod: "GET",
		RequestPath:   "/users",
	}

	records := captureLogRecords(t, func() {
		result := p.OnResponseHeaders(context.Background(), ctx, map[string]interface{}{
			"response": map[string]interface{}{
				"headers": true,
			},
		})
		if _, ok := result.(policy.DownstreamResponseHeaderModifications); !ok {
			t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", result)
		}
	})

	if len(records) != 1 {
		t.Fatalf("expected 1 response log record, got %d", len(records))
	}

	record := records[0]
	if record.MediationFlow != MediationFlowResponse {
		t.Fatalf("expected mediation flow %s, got %s", MediationFlowResponse, record.MediationFlow)
	}
	if record.RequestID != "resp-123" {
		t.Fatalf("expected request id resp-123, got %s", record.RequestID)
	}
	if record.Payload != "" {
		t.Fatalf("expected no payload in header phase log, got %q", record.Payload)
	}

	if token, ok := getHeaderValue(record.Headers, "x-internal-token"); !ok || token != "token-1" {
		t.Fatalf("expected x-internal-token to be logged, got %v", token)
	}
}

func TestOnResponseHeaders_InvalidResponseConfigType_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseHeaderContext{
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-002"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		p.OnResponseHeaders(context.Background(), ctx, map[string]interface{}{"response": "invalid"})
	})

	if len(records) != 0 {
		t.Fatalf("expected no logs for invalid response config type, got %d", len(records))
	}
}

func TestOnResponseBody_NoResponseConfig_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"ok":true}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-001"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		result := p.OnResponseBody(context.Background(), ctx, map[string]interface{}{
			"request": map[string]interface{}{"payload": true},
		})
		if _, ok := result.(policy.DownstreamResponseModifications); !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", result)
		}
	})

	if len(records) != 0 {
		t.Fatalf("expected no response logs, got %d", len(records))
	}
}

func TestOnResponseBody_LogsPayload(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody: &policy.Body{Content: []byte(`{"status":"success"}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{
			"x-request-id": "resp-123",
		}),
		RequestMethod: "GET",
		RequestPath:   "/users",
	}

	records := captureLogRecords(t, func() {
		result := p.OnResponseBody(context.Background(), ctx, map[string]interface{}{
			"response": map[string]interface{}{
				"payload": true,
			},
		})
		mods, ok := result.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", result)
		}
		if mods.Body != nil {
			t.Fatalf("expected no body modification, got %s", string(mods.Body))
		}
	})

	if len(records) != 1 {
		t.Fatalf("expected 1 response log record, got %d", len(records))
	}

	record := records[0]
	if record.MediationFlow != MediationFlowResponse {
		t.Fatalf("expected mediation flow %s, got %s", MediationFlowResponse, record.MediationFlow)
	}
	if record.RequestID != "resp-123" {
		t.Fatalf("expected request id resp-123, got %s", record.RequestID)
	}
	if record.Payload != `{"status":"success"}` {
		t.Fatalf("unexpected payload: %s", record.Payload)
	}
}

func TestOnResponseBody_InvalidResponseConfigType_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"ok":true}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-002"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		p.OnResponseBody(context.Background(), ctx, map[string]interface{}{"response": "invalid"})
	})

	if len(records) != 0 {
		t.Fatalf("expected no logs for invalid response config type, got %d", len(records))
	}
}

func TestOnResponseBody_LogsWithMissingRequestID(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"ok":true}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{"content-type": "application/json"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		p.OnResponseBody(context.Background(), ctx, map[string]interface{}{
			"response": map[string]interface{}{"payload": true},
		})
	})

	if len(records) != 1 {
		t.Fatalf("expected 1 log record, got %d", len(records))
	}
	if records[0].RequestID != ErrMsgMissingReqID {
		t.Fatalf("expected fallback request id %s, got %s", ErrMsgMissingReqID, records[0].RequestID)
	}
}

// ─── Access-log destination (per-API traffic-logging signal) ──────────────────

// newAccessLogPolicy builds a log-message instance in traffic-logging mode via the
// factory, asserting the enableTrafficLogging flag was parsed.
func newAccessLogPolicy(t *testing.T) *LogMessagePolicy {
	t.Helper()
	inst, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		FieldNameEnableTrafficLogging: true,
	})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	p, ok := inst.(*LogMessagePolicy)
	if !ok {
		t.Fatalf("expected *LogMessagePolicy, got %T", inst)
	}
	if !p.trafficLogging {
		t.Fatalf("expected traffic-logging mode instance")
	}
	return p
}

// stampMarker runs OnRequestHeaders in traffic-logging mode and returns the parsed marker.
func stampMarker(t *testing.T, p *LogMessagePolicy, params map[string]interface{}) trafficLogDirective {
	t.Helper()
	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, params)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	raw, ok := mods.AnalyticsMetadata[trafficLogMetadataKey]
	if !ok {
		t.Fatalf("expected %q in analytics metadata, got %v", trafficLogMetadataKey, mods.AnalyticsMetadata)
	}
	marker, ok := raw.(string)
	if !ok {
		t.Fatalf("expected marker to be a JSON string, got %T", raw)
	}
	var dir trafficLogDirective
	if err := json.Unmarshal([]byte(marker), &dir); err != nil {
		t.Fatalf("marker is not valid JSON: %v (%q)", err, marker)
	}
	return dir
}

func TestGetPolicy_EnableTrafficLoggingParsing(t *testing.T) {
	cases := []struct {
		name       string
		params     map[string]interface{}
		wantAccess bool
	}{
		{"default (absent)", map[string]interface{}{}, false},
		{"explicit false", map[string]interface{}{FieldNameEnableTrafficLogging: false}, false},
		{"explicit true", map[string]interface{}{FieldNameEnableTrafficLogging: true}, true},
		{"non-bool ignored", map[string]interface{}{FieldNameEnableTrafficLogging: "true"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if err != nil {
				t.Fatalf("GetPolicy failed: %v", err)
			}
			p := inst.(*LogMessagePolicy)
			if p.trafficLogging != tc.wantAccess {
				t.Fatalf("trafficLogging = %v, want %v", p.trafficLogging, tc.wantAccess)
			}
		})
	}
}

func TestMode_AccessLog(t *testing.T) {
	p := newAccessLogPolicy(t)
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("access-log mode: got %+v, want %+v", got, want)
	}
}

func TestOnRequestHeaders_AccessLog_StampsMarkerAndDoesNotLogInline(t *testing.T) {
	p := newAccessLogPolicy(t)

	var dir trafficLogDirective
	records := captureLogRecords(t, func() {
		dir = stampMarker(t, p, map[string]interface{}{
			"request": map[string]interface{}{
				"payload": false,
				"headers": true,
			},
			"response": map[string]interface{}{
				"payload": true,
			},
		})
	})

	// Access-log mode must not emit any inline slog line.
	if len(records) != 0 {
		t.Fatalf("expected no inline logs in access-log mode, got %d", len(records))
	}

	if dir.Request == nil || dir.Request.Payload || !dir.Request.Headers {
		t.Fatalf("unexpected request directive: %+v", dir.Request)
	}
	if dir.Response == nil || !dir.Response.Payload || dir.Response.Headers {
		t.Fatalf("unexpected response directive: %+v", dir.Response)
	}
}

func TestOnRequestHeaders_AccessLog_RequestOnlyOmitsResponse(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{
		"request": map[string]interface{}{"headers": true},
	})
	if dir.Request == nil || !dir.Request.Headers {
		t.Fatalf("expected request directive, got %+v", dir.Request)
	}
	if dir.Response != nil {
		t.Fatalf("expected response omitted, got %+v", dir.Response)
	}
}

func TestOnRequestHeaders_AccessLog_EmptyParamsStillStamps(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{})
	if dir.Request != nil || dir.Response != nil {
		t.Fatalf("expected no flows for empty params, got %+v", dir)
	}
	if dir.Fields != nil {
		t.Fatalf("expected no fields selection for empty params, got %+v", dir.Fields)
	}
}

func TestOnRequestHeaders_AccessLog_FieldsOnly(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{
		"fields": map[string]interface{}{
			"only": []interface{}{"latencies", " target ", "properties.requestHeaders", "", 7},
		},
	})
	if dir.Fields == nil {
		t.Fatalf("expected fields selection in marker")
	}
	want := []string{"latencies", "target", "properties.requestHeaders"}
	if len(dir.Fields.Only) != len(want) {
		t.Fatalf("expected only %v, got %v", want, dir.Fields.Only)
	}
	for i, n := range want {
		if dir.Fields.Only[i] != n {
			t.Fatalf("only[%d] = %q, want %q (full: %v)", i, dir.Fields.Only[i], n, dir.Fields.Only)
		}
	}
}

func TestOnRequestHeaders_AccessLog_FieldsExclude(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{
		"fields": map[string]interface{}{
			"exclude": []interface{}{"properties.requestBody", "properties.responseBody"},
		},
	})
	if dir.Fields == nil {
		t.Fatalf("expected fields selection in marker")
	}
	want := []string{"properties.requestBody", "properties.responseBody"}
	if len(dir.Fields.Exclude) != len(want) {
		t.Fatalf("expected exclude %v, got %v", want, dir.Fields.Exclude)
	}
}

func TestOnRequestHeaders_AccessLog_FieldsEmptyOmitted(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{
		"fields": map[string]interface{}{"only": []interface{}{}, "exclude": []interface{}{}},
	})
	if dir.Fields != nil {
		t.Fatalf("expected fields omitted when both empty, got %+v", dir.Fields)
	}
}

func TestOnRequestHeaders_AccessLog_MaskedHeadersInMarker(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{
		FieldNameMaskedHeaders: toInterfaceSlice([]string{"X-Token", " Authorization "}),
	})
	if len(dir.MaskedHeaders) != 2 {
		t.Fatalf("expected 2 masked headers in marker, got %v", dir.MaskedHeaders)
	}
	// Values must be normalized to lower-case.
	if dir.MaskedHeaders[0] != "x-token" || dir.MaskedHeaders[1] != "authorization" {
		t.Fatalf("expected normalized lower-case names, got %v", dir.MaskedHeaders)
	}
}

func TestOnRequestHeaders_AccessLog_MaskedHeadersAbsentOmitted(t *testing.T) {
	p := newAccessLogPolicy(t)
	dir := stampMarker(t, p, map[string]interface{}{})
	if dir.MaskedHeaders != nil {
		t.Fatalf("expected maskedHeaders absent when not configured, got %v", dir.MaskedHeaders)
	}
}

// ─── Properties ($ctx resolution) ─────────────────────────────────────────────

// ctxWithAuth builds a request-header context with headers and an authenticated
// AuthContext for exercising $ctx resolution.
func ctxWithAuth() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIName:       "PetStore",
			APIVersion:    "v1.0.0",
			APIKind:       policy.APIKindRestApi,
			APIContext:    "/petstore",
			OperationPath: "/pets/{id}",
			ProjectID:     "proj-7",
			RequestID:     "req-abc",
			AuthContext: &policy.AuthContext{
				Authenticated: true,
				Authorized:    true,
				AuthType:      "jwt",
				Subject:       "alice",
				Issuer:        "https://idp.example",
				CredentialID:  "client-123",
				TokenId:       "jti-42",
				Audience:      []string{"aud1", "aud2"},
				Scopes:        map[string]bool{"write": true, "read": true},
				Properties:    map[string]string{"tenant": "acme"},
			},
		},
		Headers:   createTestHeaders(map[string]string{"x-tenant-id": "t-9"}),
		Path:      "/pets",
		Method:    "GET",
		Authority: "api.example.com",
		Scheme:    "https",
		Vhost:     "default",
	}
}

func TestResolveContextValue(t *testing.T) {
	reqCtx := ctxWithAuth()
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"literal passthrough", "plain-value", "plain-value", true},
		{"request.method", "$ctx:request.method", "GET", true},
		{"request.path", "$ctx:request.path", "/pets", true},
		{"request.header present", "$ctx:request.header.x-tenant-id", "t-9", true},
		{"request.header case-insensitive", "$ctx:request.header.X-Tenant-Id", "t-9", true},
		{"request.header missing", "$ctx:request.header.x-absent", "", false},
		{"request.authority", "$ctx:request.authority", "api.example.com", true},
		{"request.scheme", "$ctx:request.scheme", "https", true},
		{"request.vhost", "$ctx:request.vhost", "default", true},
		{"request.id", "$ctx:request.id", "req-abc", true},
		{"api.name", "$ctx:api.name", "PetStore", true},
		{"api.version", "$ctx:api.version", "v1.0.0", true},
		{"api.context", "$ctx:api.context", "/petstore", true},
		{"api.kind", "$ctx:api.kind", "RestApi", true},
		{"api.operation_path", "$ctx:api.operation_path", "/pets/{id}", true},
		{"project.id", "$ctx:project.id", "proj-7", true},
		{"auth.subject", "$ctx:auth.subject", "alice", true},
		{"auth.type", "$ctx:auth.type", "jwt", true},
		{"auth.credential_id", "$ctx:auth.credential_id", "client-123", true},
		{"auth.token_id", "$ctx:auth.token_id", "jti-42", true},
		{"auth.issuer", "$ctx:auth.issuer", "https://idp.example", true},
		{"auth.authenticated", "$ctx:auth.authenticated", "true", true},
		{"auth.audience joined", "$ctx:auth.audience", "aud1,aud2", true},
		{"auth.scopes sorted", "$ctx:auth.scopes", "read write", true},
		{"auth.property case-sensitive", "$ctx:auth.property.tenant", "acme", true},
		{"auth.property missing", "$ctx:auth.property.nope", "", false},
		{"unknown var", "$ctx:does.not.exist", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveContextValue(tc.in, reqCtx)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("resolveContextValue(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestResolveContextValue_NilAuthSkipped(t *testing.T) {
	reqCtx := &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{}}
	if _, ok := resolveContextValue("$ctx:auth.subject", reqCtx); ok {
		t.Fatalf("expected auth.* to be unresolved when AuthContext is nil")
	}
}

func TestStampMarker_Properties(t *testing.T) {
	p := newAccessLogPolicy(t)
	action := p.OnRequestHeaders(context.Background(), ctxWithAuth(), map[string]interface{}{
		"request": map[string]interface{}{"headers": true},
		"properties": map[string]interface{}{
			"who":        "$ctx:auth.subject",          // resolves
			"tenant":     "$ctx:auth.property.tenant",  // resolves (case-sensitive key)
			"authType":   "$ctx:auth.type",             // resolves
			"env":        "prod",                       // literal
			"missing":    "$ctx:request.header.x-none", // unresolved -> skipped
			"retryCount": 3,                            // non-string literal passthrough
		},
	})
	mods := action.(policy.UpstreamRequestHeaderModifications)
	var dir trafficLogDirective
	if err := json.Unmarshal([]byte(mods.AnalyticsMetadata[trafficLogMetadataKey].(string)), &dir); err != nil {
		t.Fatalf("marker not valid JSON: %v", err)
	}

	if dir.Properties["who"] != "alice" {
		t.Errorf("who = %v, want alice", dir.Properties["who"])
	}
	if dir.Properties["tenant"] != "acme" {
		t.Errorf("tenant = %v, want acme", dir.Properties["tenant"])
	}
	if dir.Properties["authType"] != "jwt" {
		t.Errorf("authType = %v, want jwt", dir.Properties["authType"])
	}
	if dir.Properties["env"] != "prod" {
		t.Errorf("env = %v, want prod", dir.Properties["env"])
	}
	if _, present := dir.Properties["missing"]; present {
		t.Errorf("unresolved $ctx ref should be skipped, got %v", dir.Properties["missing"])
	}
	// JSON round-trips numbers as float64.
	if v, ok := dir.Properties["retryCount"].(float64); !ok || v != 3 {
		t.Errorf("retryCount = %v (%T), want 3", dir.Properties["retryCount"], dir.Properties["retryCount"])
	}
}

func TestStampMarker_PropertiesOmittedWhenEmpty(t *testing.T) {
	p := newAccessLogPolicy(t)
	// No properties param at all.
	dir := stampMarker(t, p, map[string]interface{}{"request": map[string]interface{}{"headers": true}})
	if dir.Properties != nil {
		t.Fatalf("expected properties omitted, got %+v", dir.Properties)
	}
	// All references unresolvable -> nothing survives -> omitted.
	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{}}, map[string]interface{}{
		"request":    map[string]interface{}{"headers": true},
		"properties": map[string]interface{}{"who": "$ctx:auth.subject"},
	})
	mods := action.(policy.UpstreamRequestHeaderModifications)
	var dir2 trafficLogDirective
	_ = json.Unmarshal([]byte(mods.AnalyticsMetadata[trafficLogMetadataKey].(string)), &dir2)
	if dir2.Properties != nil {
		t.Fatalf("expected properties omitted when nothing resolves, got %+v", dir2.Properties)
	}
}
