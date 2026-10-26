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
			"payload":        true,
			"headers":        true,
			"excludeHeaders": toInterfaceSlice([]string{"Authorization", " X-API-Key "}),
		},
	}, "request")

	if !cfg.logPayload {
		t.Fatalf("expected logPayload to be true")
	}
	if !cfg.logHeaders {
		t.Fatalf("expected logHeaders to be true")
	}
	if _, ok := cfg.excludedHeaders["authorization"]; !ok {
		t.Fatalf("expected authorization in excluded headers")
	}
	if _, ok := cfg.excludedHeaders["x-api-key"]; !ok {
		t.Fatalf("expected x-api-key in excluded headers")
	}
}

func TestParseFlowConfig_InvalidTypesFallbackToDefaults(t *testing.T) {
	p := &LogMessagePolicy{}

	cfg := p.parseFlowConfig(map[string]interface{}{
		"request": "invalid",
	}, "request")
	if cfg.logPayload || cfg.logHeaders || len(cfg.excludedHeaders) != 0 {
		t.Fatalf("expected default config for invalid flow type, got %+v", cfg)
	}

	cfg = p.parseFlowConfig(map[string]interface{}{
		"request": map[string]interface{}{
			"payload":        "true",
			"headers":        1,
			"excludeHeaders": "Authorization",
		},
	}, "request")
	if cfg.logPayload || cfg.logHeaders || len(cfg.excludedHeaders) != 0 {
		t.Fatalf("expected default values for invalid fields, got %+v", cfg)
	}
}

func TestParseExcludedHeaders(t *testing.T) {
	p := &LogMessagePolicy{}

	t.Run("from interface slice", func(t *testing.T) {
		result := p.parseExcludedHeaders([]interface{}{"Authorization", " x-api-key ", "", 7})
		if len(result) != 2 {
			t.Fatalf("expected 2 excluded headers, got %d", len(result))
		}
		if _, ok := result["authorization"]; !ok {
			t.Fatalf("expected authorization to be excluded")
		}
		if _, ok := result["x-api-key"]; !ok {
			t.Fatalf("expected x-api-key to be excluded")
		}
	})

	t.Run("from string slice", func(t *testing.T) {
		result := p.parseExcludedHeaders([]string{"Set-Cookie", " X-Token "})
		if len(result) != 2 {
			t.Fatalf("expected 2 excluded headers, got %d", len(result))
		}
		if _, ok := result["set-cookie"]; !ok {
			t.Fatalf("expected set-cookie to be excluded")
		}
		if _, ok := result["x-token"]; !ok {
			t.Fatalf("expected x-token to be excluded")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		result := p.parseExcludedHeaders("Authorization")
		if len(result) != 0 {
			t.Fatalf("expected empty result for invalid type, got %d", len(result))
		}
	})
}

func TestBuildHeadersMapV2_MasksAuthorizationAndExcludes(t *testing.T) {
	p := &LogMessagePolicy{}
	headers := createTestHeadersMulti(map[string][]string{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer secret"},
		"X-API-Key":     {"api-key"},
		"X-Multi":       {"one", "two"},
	})

	result := p.buildHeadersMap(headers, map[string]struct{}{"x-api-key": {}})

	authValue, ok := getHeaderValue(result, "authorization")
	if !ok {
		t.Fatalf("expected authorization header in result")
	}
	if authValue != "***" {
		t.Fatalf("expected authorization to be masked, got %v", authValue)
	}

	if _, ok := getHeaderValue(result, "x-api-key"); ok {
		t.Fatalf("expected x-api-key to be excluded")
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
	result := p.buildHeadersMap(nil, map[string]struct{}{})
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
				"headers":        true,
				"excludeHeaders": toInterfaceSlice([]string{"x-api-key"}),
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
	if _, ok := getHeaderValue(record.Headers, "x-api-key"); ok {
		t.Fatalf("expected x-api-key to be excluded")
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
				"headers":        true,
				"excludeHeaders": toInterfaceSlice([]string{"set-cookie"}),
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

	if _, ok := getHeaderValue(record.Headers, "set-cookie"); ok {
		t.Fatalf("expected set-cookie to be excluded")
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

func TestLogMessagePolicy_StreamingRequestAndResponse(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := context.Background()

	// 1. Test NeedsMoreRequestData & NeedsMoreResponseData (should always return false)
	if p.NeedsMoreRequestData(nil) {
		t.Error("expected NeedsMoreRequestData to be false")
	}
	if p.NeedsMoreResponseData(nil) {
		t.Error("expected NeedsMoreResponseData to be false")
	}

	// 2. Test OnRequestBodyChunk
	reqStreamCtx := &policy.RequestStreamContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-stream-123",
		},
		Headers: createTestHeaders(map[string]string{"x-request-id": "req-stream-123"}),
		Method:  "POST",
		Path:    "/stream",
	}
	reqChunk := &policy.StreamBody{
		Chunk: []byte("request chunk payload"),
	}
	params := map[string]interface{}{
		"request": map[string]interface{}{
			"payload": true,
		},
	}

	records := captureLogRecords(t, func() {
		action := p.OnRequestBodyChunk(ctx, reqStreamCtx, reqChunk, params)
		if _, ok := action.(policy.ForwardRequestChunk); !ok {
			t.Fatalf("expected ForwardRequestChunk, got %T", action)
		}
	})

	if len(records) != 1 {
		t.Fatalf("expected 1 logged record, got %d", len(records))
	}
	if records[0].Payload != "request chunk payload" || records[0].RequestID != "req-stream-123" {
		t.Errorf("unexpected record logged: %+v", records[0])
	}

	// 3. Test OnResponseBodyChunk
	respStreamCtx := &policy.ResponseStreamContext{
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-stream-123"}),
		RequestMethod:   "GET",
		RequestPath:     "/stream",
	}
	respChunk := &policy.StreamBody{
		Chunk: []byte("response chunk payload"),
	}
	respParams := map[string]interface{}{
		"response": map[string]interface{}{
			"payload": true,
		},
	}

	respRecords := captureLogRecords(t, func() {
		action := p.OnResponseBodyChunk(ctx, respStreamCtx, respChunk, respParams)
		if _, ok := action.(policy.ForwardResponseChunk); !ok {
			t.Fatalf("expected ForwardResponseChunk, got %T", action)
		}
	})

	if len(respRecords) != 1 {
		t.Fatalf("expected 1 logged record, got %d", len(respRecords))
	}
	if respRecords[0].Payload != "response chunk payload" || respRecords[0].RequestID != "resp-stream-123" {
		t.Errorf("unexpected record logged: %+v", respRecords[0])
	}
}

