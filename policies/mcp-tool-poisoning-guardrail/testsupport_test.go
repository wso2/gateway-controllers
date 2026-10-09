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

package mcptoolpoisoningguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	testModel    = "wso2/tool-poisoning-detection"
	testRevision = "1d62fb57258ee41c3e3ebe8520faad633de12ac2"
)

// Wire shapes of the classifier contract, used by the mock to decode requests
// and encode replies with encoding/json. The policy itself decodes replies with
// its own strict decoder; these exist only on the test side.
type classifyRequestBody struct {
	Items []classifyItem `json:"items"` // matched to ID/Text case-insensitively
}

type classifyResultEntry struct {
	ID             string   `json:"id"`
	PoisoningScore *float64 `json:"poisoningScore"`
}

type classifyResponseBody struct {
	Model    string                `json:"model"`
	Revision string                `json:"revision"`
	Results  []classifyResultEntry `json:"results"`
}

// mockReply is a scripted classifier reply. body may be a value to JSON-encode,
// a string or []byte sent verbatim, or nil for an empty body.
type mockReply struct {
	status  int
	body    any
	headers map[string]string
}

// mockClassifier is a stand-in for the Python classifier service. Tests drive
// it with a scorer so inspection outcomes stay deterministic and no model is
// needed to exercise the gateway policy.
type mockClassifier struct {
	server *httptest.Server

	mu             sync.Mutex
	calls          int
	requests       int
	seen           []classifyItem
	maxBatch       int
	paths          []string
	authorizations []string
}

// classifierHandler builds the HTTP response for one batch. Returning a status
// other than 200 lets a test exercise the error paths.
type classifierHandler func(items []classifyItem) (int, classifyResponseBody)

func newMockClassifier(t *testing.T, handler classifierHandler) *mockClassifier {
	t.Helper()
	return newScriptedClassifier(t, func(items []classifyItem) mockReply {
		status, body := handler(items)
		if status != http.StatusOK {
			return mockReply{status: status}
		}
		return mockReply{status: status, body: body}
	})
}

// newScriptedClassifier starts a mock whose replies are fully scripted: status,
// raw or structured body, and headers such as Retry-After or Location.
func newScriptedClassifier(t *testing.T, script func(items []classifyItem) mockReply) *mockClassifier {
	t.Helper()

	mock := &mockClassifier{}
	mock.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		mock.requests++
		mock.paths = append(mock.paths, r.URL.Path)
		mock.authorizations = append(mock.authorizations, r.Header.Get("Authorization"))
		mock.mu.Unlock()

		if r.URL.Path != classifyPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var request classifyRequestBody
		if err := json.Unmarshal(raw, &request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mock.mu.Lock()
		mock.calls++
		mock.seen = append(mock.seen, request.Items...)
		if len(request.Items) > mock.maxBatch {
			mock.maxBatch = len(request.Items)
		}
		mock.mu.Unlock()

		reply := script(request.Items)
		var payload []byte
		switch body := reply.body.(type) {
		case nil:
		case string:
			payload = []byte(body)
		case []byte:
			payload = body
		default:
			payload, _ = json.Marshal(body)
		}
		w.Header().Set("Content-Type", "application/json")
		for key, value := range reply.headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(reply.status)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(mock.server.Close)

	return mock
}

// requestCount counts every HTTP request, including ones to the wrong path.
func (m *mockClassifier) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

func (m *mockClassifier) seenPaths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.paths...)
}

func (m *mockClassifier) seenAuthorizations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.authorizations...)
}

// texts lists the text of every item the mock has classified.
func (m *mockClassifier) texts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	texts := make([]string, 0, len(m.seen))
	for _, item := range m.seen {
		texts = append(texts, item.Text)
	}
	return texts
}

func (m *mockClassifier) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockClassifier) items() []classifyItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]classifyItem(nil), m.seen...)
}

func (m *mockClassifier) largestBatch() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maxBatch
}

// scoreBy builds a handler that scores each item with the supplied function.
func scoreBy(score func(item classifyItem) float64) classifierHandler {
	return func(items []classifyItem) (int, classifyResponseBody) {
		results := make([]classifyResultEntry, 0, len(items))
		for _, item := range items {
			value := score(item)
			results = append(results, classifyResultEntry{ID: item.ID, PoisoningScore: &value})
		}
		return http.StatusOK, classifyResponseBody{Model: testModel, Revision: testRevision, Results: results}
	}
}

// alwaysScore builds a handler that returns the same score for every item.
func alwaysScore(value float64) classifierHandler {
	return scoreBy(func(classifyItem) float64 { return value })
}

// newTestPolicy builds a policy pointed at the mock classifier. overrides are
// merged over a benign default configuration.
func newTestPolicy(t *testing.T, endpoint string, overrides map[string]any) *McpToolPoisoningGuardrailPolicy {
	t.Helper()

	params := map[string]any{
		"endpoint":                     endpoint,
		"classifierThreshold":          0.6,
		"requestTimeoutMillis":         2000,
		"classificationDeadlineMillis": 3000,
	}
	for key, value := range overrides {
		params[key] = value
	}

	instance, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	typed, ok := instance.(*McpToolPoisoningGuardrailPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *McpToolPoisoningGuardrailPolicy", instance)
	}
	return typed
}

// testExchange carries one request/response pair through both policy phases.
type testExchange struct {
	requestBody     []byte
	requestHeaders  map[string][]string
	responseBody    []byte
	responseHeaders map[string][]string
	status          int
	operationPath   string
	shared          *policy.SharedContext
}

func newExchange(requestBody, responseBody []byte) *testExchange {
	return &testExchange{
		requestBody:     requestBody,
		requestHeaders:  map[string][]string{"content-type": {"application/json"}},
		responseBody:    responseBody,
		responseHeaders: map[string][]string{"content-type": {"application/json"}, mcpSessionHeader: {"session-123"}},
		status:          200,
		operationPath:   "/mcp",
		shared:          &policy.SharedContext{Metadata: map[string]any{}, OperationPath: "/mcp"},
	}
}

func (e *testExchange) asSSE() *testExchange {
	e.responseHeaders["content-type"] = []string{"text/event-stream"}
	return e
}

func (e *testExchange) requestContext() *policy.RequestContext {
	headers := policy.NewHeaders(e.requestHeaders)
	e.shared.OperationPath = e.operationPath
	return &policy.RequestContext{
		SharedContext: e.shared,
		Headers:       headers,
		Body:          &policy.Body{Content: e.requestBody, Present: true, EndOfStream: true},
		Path:          "/mcp",
		Method:        "POST",
		Downstream: &policy.DownstreamContext{
			Request: &policy.DownstreamRequest{Headers: headers, Path: "/mcp", Method: "POST"},
		},
	}
}

func (e *testExchange) responseContext() *policy.ResponseContext {
	requestHeaders := policy.NewHeaders(e.requestHeaders)
	responseHeaders := policy.NewHeaders(e.responseHeaders)
	e.shared.OperationPath = e.operationPath

	var body *policy.Body
	if e.responseBody != nil {
		body = &policy.Body{Content: e.responseBody, Present: true, EndOfStream: true}
	}

	return &policy.ResponseContext{
		SharedContext:   e.shared,
		RequestHeaders:  requestHeaders,
		RequestPath:     "/mcp",
		RequestMethod:   "POST",
		ResponseHeaders: responseHeaders,
		ResponseBody:    body,
		ResponseStatus:  e.status,
		Downstream: &policy.DownstreamContext{
			Request: &policy.DownstreamRequest{Headers: requestHeaders, Path: "/mcp", Method: "POST"},
		},
		Upstream: &policy.UpstreamResponseContext{
			Response: &policy.UpstreamResponse{Headers: responseHeaders, StatusCode: e.status},
		},
	}
}

// run drives both phases and returns the response-phase action.
func (e *testExchange) run(t *testing.T, p *McpToolPoisoningGuardrailPolicy) policy.ResponseAction {
	t.Helper()
	return e.runWithContext(t, t.Context(), p)
}

// runWithContext drives both phases with a caller-supplied context, which is
// how a test stands in for the gateway's own deadline or cancellation.
func (e *testExchange) runWithContext(t *testing.T, ctx context.Context, p *McpToolPoisoningGuardrailPolicy) policy.ResponseAction {
	t.Helper()
	e.runRequest(t, p)
	return e.runResponse(ctx, p)
}

// runRequest drives the request phase only. The request phase never modifies
// or short-circuits the request, which is asserted here for every exchange.
func (e *testExchange) runRequest(t *testing.T, p *McpToolPoisoningGuardrailPolicy) {
	t.Helper()
	action := p.OnRequestBody(t.Context(), e.requestContext(), nil)
	if modifications, ok := action.(policy.UpstreamRequestModifications); !ok || !reflect.ValueOf(modifications).IsZero() {
		t.Fatalf("the request phase must pass the request through untouched, got %#v", action)
	}
}

// runResponse drives the response phase only.
func (e *testExchange) runResponse(ctx context.Context, p *McpToolPoisoningGuardrailPolicy) policy.ResponseAction {
	return p.OnResponseBody(ctx, e.responseContext(), nil)
}

// toolsListRequest builds a tools/list JSON-RPC request body.
func toolsListRequest(id string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list","params":{}}`)
}

// compactJSON collapses a payload onto one line. SSE data lines cannot contain
// raw newlines, so every payload embedded in a test stream goes through this.
func compactJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		t.Fatalf("failed to compact %q: %v", string(raw), err)
	}
	return buffer.String()
}

// sseFrame wraps a JSON payload in a single SSE event.
func sseFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	return []byte("event: message\nid: 7\ndata: " + compactJSON(t, payload) + "\n\n")
}

// decodeBody decodes a response body, preserving number literals.
func decodeBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	payload, _, err := decodeJSONObject(string(body), false)
	if err != nil {
		t.Fatalf("failed to decode body %q: %v", string(body), err)
	}
	return payload
}

// resultTools pulls result.tools out of a decoded payload.
func resultTools(t *testing.T, payload map[string]any) []any {
	t.Helper()
	result, ok := payload["result"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no result object: %v", payload)
	}
	tools, ok := result[resultToolsKey].([]any)
	if !ok {
		t.Fatalf("result has no tools array: %v", result)
	}
	return tools
}

// toolNames lists the names of the tools in a decoded tools/list result.
func toolNames(t *testing.T, payload map[string]any) []string {
	t.Helper()
	names := make([]string, 0)
	for _, raw := range resultTools(t, payload) {
		entry, ok := raw.(map[string]any)
		if !ok {
			names = append(names, "<not-an-object>")
			continue
		}
		name, _ := entry["name"].(string)
		names = append(names, name)
	}
	return names
}

// modifications asserts the action is a pass-through/mutation action.
func modifications(t *testing.T, action policy.ResponseAction) policy.DownstreamResponseModifications {
	t.Helper()
	typed, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	return typed
}

// immediate asserts the action short-circuits the response.
func immediate(t *testing.T, action policy.ResponseAction) policy.ImmediateResponse {
	t.Helper()
	typed, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	return typed
}

// jsonRPCErrorCode extracts error.code from a JSON-RPC error body.
func jsonRPCErrorCode(t *testing.T, body []byte) int {
	t.Helper()
	payload := decodeBody(t, body)
	errorObject, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("body is not a JSON-RPC error: %s", string(body))
	}
	code, ok := errorObject["code"].(json.Number)
	if !ok {
		t.Fatalf("error.code is not a number: %v", errorObject["code"])
	}
	parsed, err := code.Int64()
	if err != nil {
		t.Fatalf("error.code is not an integer: %v", err)
	}
	return int(parsed)
}

// sseEvents parses an event stream, failing the test if it is not one.
func sseEvents(t *testing.T, body []byte) []sseEvent {
	t.Helper()
	events, err := parseEventStream(string(body))
	if err != nil {
		t.Fatalf("failed to parse event stream %q: %v", string(body), err)
	}
	return events
}

// mustDecodeObject strictly decodes a JSON object, failing the test otherwise.
func mustDecodeObject(t *testing.T, raw string) map[string]any {
	t.Helper()
	payload, _, err := decodeJSONObject(raw, false)
	if err != nil {
		t.Fatalf("failed to decode %q: %v", raw, err)
	}
	return payload
}

// TestMain silences the policy's logging so test output shows failures, not
// every inspection record. Set MCP_TOOL_POISONING_TEST_LOGS=1 to see them.
func TestMain(m *testing.M) {
	if os.Getenv("MCP_TOOL_POISONING_TEST_LOGS") == "" {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	os.Exit(m.Run())
}

// captureLogs records everything logged at debug level and above while fn
// runs. Tests using it must not run in parallel: it swaps the default logger.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buffer bytes.Buffer
	var mu sync.Mutex
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buffer}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	fn()
	mu.Lock()
	defer mu.Unlock()
	return buffer.String()
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
