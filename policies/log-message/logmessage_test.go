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
	"encoding/json"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

var slogMessagePattern = regexp.MustCompile(`msg="((?:\\.|[^"])*)"`)

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

func TestLogMessagePolicy_Mode(t *testing.T) {
	p := &LogMessagePolicy{}
	mode := p.Mode()

	expectedMode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}

	if mode != expectedMode {
		t.Fatalf("expected mode %+v, got %+v", expectedMode, mode)
	}
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

func TestBuildHeadersMap_MasksAuthorizationAndExcludes(t *testing.T) {
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

func TestBuildHeadersMap_NilHeaders(t *testing.T) {
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

func TestOnRequest_NoRequestConfig_DoesNotLog(t *testing.T) {
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
		result := p.OnRequest(ctx, map[string]interface{}{
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

func TestOnRequest_LogsPayloadAndHeaders(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestContext{
		Body: &policy.Body{Content: []byte(`{"action":"login"}`), Present: true},
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
		result := p.OnRequest(ctx, map[string]interface{}{
			"request": map[string]interface{}{
				"payload":        true,
				"headers":        true,
				"excludeHeaders": toInterfaceSlice([]string{"x-api-key"}),
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

func TestOnRequest_InvalidRequestConfigType_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.RequestContext{
		Body:    &policy.Body{Content: []byte(`{"hello":"world"}`), Present: true},
		Headers: createTestHeaders(map[string]string{"x-request-id": "req-002"}),
		Method:  "POST",
		Path:    "/resource",
	}

	records := captureLogRecords(t, func() {
		p.OnRequest(ctx, map[string]interface{}{"request": true})
	})

	if len(records) != 0 {
		t.Fatalf("expected no logs for invalid request config type, got %d", len(records))
	}
}

func TestOnResponse_NoResponseConfig_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"ok":true}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-001"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		result := p.OnResponse(ctx, map[string]interface{}{
			"request": map[string]interface{}{"payload": true},
		})
		if _, ok := result.(policy.UpstreamResponseModifications); !ok {
			t.Fatalf("expected UpstreamResponseModifications, got %T", result)
		}
	})

	if len(records) != 0 {
		t.Fatalf("expected no response logs, got %d", len(records))
	}
}

func TestOnResponse_LogsPayloadAndHeaders(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody: &policy.Body{Content: []byte(`{"status":"success"}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{
			"x-request-id":     "resp-123",
			"set-cookie":       "session=abc",
			"x-internal-token": "token-1",
		}),
		RequestMethod: "GET",
		RequestPath:   "/users",
	}

	records := captureLogRecords(t, func() {
		result := p.OnResponse(ctx, map[string]interface{}{
			"response": map[string]interface{}{
				"payload":        true,
				"headers":        true,
				"excludeHeaders": toInterfaceSlice([]string{"set-cookie"}),
			},
		})
		mods, ok := result.(policy.UpstreamResponseModifications)
		if !ok {
			t.Fatalf("expected UpstreamResponseModifications, got %T", result)
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

	if _, ok := getHeaderValue(record.Headers, "set-cookie"); ok {
		t.Fatalf("expected set-cookie to be excluded")
	}
	if token, ok := getHeaderValue(record.Headers, "x-internal-token"); !ok || token != "token-1" {
		t.Fatalf("expected x-internal-token to be logged, got %v", token)
	}
}

func TestOnResponse_InvalidResponseConfigType_DoesNotLog(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"ok":true}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{"x-request-id": "resp-002"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		p.OnResponse(ctx, map[string]interface{}{"response": "invalid"})
	})

	if len(records) != 0 {
		t.Fatalf("expected no logs for invalid response config type, got %d", len(records))
	}
}

func TestOnResponse_LogsWithMissingRequestID(t *testing.T) {
	p := &LogMessagePolicy{}
	ctx := &policy.ResponseContext{
		ResponseBody:    &policy.Body{Content: []byte(`{"ok":true}`), Present: true},
		ResponseHeaders: createTestHeaders(map[string]string{"content-type": "application/json"}),
		RequestMethod:   "GET",
		RequestPath:     "/status",
	}

	records := captureLogRecords(t, func() {
		p.OnResponse(ctx, map[string]interface{}{
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
