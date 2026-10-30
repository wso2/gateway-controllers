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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testClassifier(endpoint string, mutate func(*SystemParams)) *classifierClient {
	system := SystemParams{
		Endpoint:               endpoint,
		RequestTimeout:         2 * time.Second,
		ClassificationDeadline: 3 * time.Second,
		BatchSize:              defaultBatchSize,
		MaxConcurrentBatches:   defaultMaxConcurrentBatches,
		MaxClassifierAttempts:  defaultMaxClassifierAttempts,
	}
	if mutate != nil {
		mutate(&system)
	}
	return newClassifierClient(system)
}

func items(n int) []classifyItem {
	built := make([]classifyItem, 0, n)
	for i := range n {
		built = append(built, classifyItem{ID: fmt.Sprintf("tools[%d].description", i), Text: "text"})
	}
	return built
}

func TestSplitBatches(t *testing.T) {
	// items() builds entries of "text" (4 bytes) plus a field-path id, so a byte
	// budget below one entry's cost still yields one entry per batch rather than
	// no progress.
	const unlimited = 0

	tests := []struct {
		name     string
		items    int
		size     int
		maxBytes int
		want     []int
	}{
		{name: "exact multiple", items: 4, size: 2, maxBytes: unlimited, want: []int{2, 2}},
		{name: "remainder", items: 5, size: 2, maxBytes: unlimited, want: []int{2, 2, 1}},
		{name: "single batch", items: 3, size: 10, maxBytes: unlimited, want: []int{3}},
		{name: "size floors at one", items: 2, size: 0, maxBytes: unlimited, want: []int{1, 1}},
		// The byte budget is what keeps a batch inside the classifier service's
		// own per-request total, whatever the count limit allows.
		{name: "byte budget splits below the count limit", items: 4, size: 10, maxBytes: 60, want: []int{2, 2}},
		{name: "an item larger than the budget still gets a batch", items: 3, size: 10, maxBytes: 1, want: []int{1, 1, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batches := splitBatches(items(tt.items), tt.size, tt.maxBytes)
			if len(batches) != len(tt.want) {
				t.Fatalf("batch count = %d, want %d", len(batches), len(tt.want))
			}
			for i, batch := range batches {
				if len(batch) != tt.want[i] {
					t.Fatalf("batch %d size = %d, want %d", i, len(batch), tt.want[i])
				}
			}
		})
	}
}

func TestClassifyEmptyInputMakesNoCalls(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	result, err := testClassifier(server.URL, nil).classify(t.Context(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Scores) != 0 {
		t.Fatalf("scores = %v, want none", result.Scores)
	}
	if calls.Load() != 0 {
		t.Fatalf("classifier was called for an empty item list")
	}
}

func TestClassifySendsAuthorizationHeaderOnlyWhenConfigured(t *testing.T) {
	var seen []string
	var mu sync.Mutex

	mock := newMockClassifier(t, alwaysScore(0.1))
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		mock.server.Config.Handler.ServeHTTP(w, r)
	}))
	defer authServer.Close()

	withKey := testClassifier(authServer.URL, func(s *SystemParams) { s.APIKey = "s3cr3t" })
	if _, err := withKey.classify(t.Context(), items(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	withoutKey := testClassifier(authServer.URL, nil)
	if _, err := withoutKey.classify(t.Context(), items(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("calls = %d, want 2", len(seen))
	}
	if seen[0] != "Bearer s3cr3t" {
		t.Fatalf("authorization = %q, want the configured bearer token", seen[0])
	}
	if seen[1] != "" {
		t.Fatalf("authorization = %q, want no header when no key is configured", seen[1])
	}
}

func TestClassifyBoundsConcurrency(t *testing.T) {
	var inFlight, peak atomic.Int64

	handler := func(items []classifyItem) (int, classifyResponseBody) {
		current := inFlight.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
		return alwaysScore(0.1)(items)
	}

	mock := newMockClassifier(t, handler)
	client := testClassifier(mock.server.URL, func(s *SystemParams) {
		s.BatchSize = 1
		s.MaxConcurrentBatches = 2
	})

	if _, err := client.classify(t.Context(), items(8)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := peak.Load(); got > 2 {
		t.Fatalf("peak concurrency = %d, want at most 2", got)
	}
	if mock.callCount() != 8 {
		t.Fatalf("calls = %d, want one per item", mock.callCount())
	}
}

func TestClassifyAppliesOneDeadlineAcrossBatches(t *testing.T) {
	handler := func(items []classifyItem) (int, classifyResponseBody) {
		time.Sleep(120 * time.Millisecond)
		return alwaysScore(0.1)(items)
	}

	mock := newMockClassifier(t, handler)
	client := testClassifier(mock.server.URL, func(s *SystemParams) {
		s.BatchSize = 1
		s.MaxConcurrentBatches = 1
	})

	// Ten sequential 120ms batches need 1.2s; the shared 300ms deadline must
	// stop them well before that.
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := client.classify(ctx, items(10))
	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("expected the shared deadline to fail the classification")
	}
	if elapsed > 900*time.Millisecond {
		t.Fatalf("classification took %v, the shared deadline was not applied", elapsed)
	}
}

func TestClassifyReportsNoPartialResults(t *testing.T) {
	// The first batch succeeds and the second fails. A partial map of scores
	// would silently read as "the rest scored zero".
	var calls atomic.Int64
	handler := func(items []classifyItem) (int, classifyResponseBody) {
		if calls.Add(1) > 1 {
			return http.StatusServiceUnavailable, classifyResponseBody{}
		}
		return alwaysScore(0.1)(items)
	}

	mock := newMockClassifier(t, handler)
	client := testClassifier(mock.server.URL, func(s *SystemParams) {
		s.BatchSize = 1
		s.MaxConcurrentBatches = 1
	})

	result, err := client.classify(t.Context(), items(4))
	if err == nil {
		t.Fatalf("expected an error when a batch fails")
	}
	if len(result.Scores) != 0 {
		t.Fatalf("scores = %v, want none on failure", result.Scores)
	}
}

func TestClassifyRejectsInconsistentModelIdentity(t *testing.T) {
	var calls atomic.Int64
	handler := func(items []classifyItem) (int, classifyResponseBody) {
		revision := testRevision
		if calls.Add(1) > 1 {
			revision = "0000000000000000000000000000000000000000"
		}
		score := 0.1
		return http.StatusOK, classifyResponseBody{
			Model:    testModel,
			Revision: revision,
			Results:  []classifyResultEntry{{ID: items[0].ID, PoisoningScore: &score}},
		}
	}

	mock := newMockClassifier(t, handler)
	client := testClassifier(mock.server.URL, func(s *SystemParams) {
		s.BatchSize = 1
		s.MaxConcurrentBatches = 1
	})

	_, err := client.classify(t.Context(), items(2))
	if err == nil || !strings.Contains(err.Error(), "inconsistent model identity") {
		t.Fatalf("error = %v, want an inconsistent model identity error", err)
	}
}

func TestClassifyRejectsNonJSONResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not the classifier</html>"))
	}))
	defer server.Close()

	_, err := testClassifier(server.URL, nil).classify(t.Context(), items(1))
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error = %v, want a decode failure", err)
	}
}

func TestClassifyReportsLatency(t *testing.T) {
	handler := func(items []classifyItem) (int, classifyResponseBody) {
		time.Sleep(30 * time.Millisecond)
		return alwaysScore(0.1)(items)
	}

	mock := newMockClassifier(t, handler)
	result, err := testClassifier(mock.server.URL, nil).classify(t.Context(), items(1))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Latency < 30*time.Millisecond {
		t.Fatalf("latency = %v, want at least the handler delay", result.Latency)
	}
	if result.Model != testModel || result.Revision != testRevision {
		t.Fatalf("model identity = %q@%q, want %q@%q", result.Model, result.Revision, testModel, testRevision)
	}
}

func TestClassifyPostsToTheClassifyPath(t *testing.T) {
	var path, method string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		method = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"model":%q,"revision":%q,"results":[{"id":"tools[0].description","poisoningScore":0.1}]}`, testModel, testRevision)
	}))
	defer server.Close()

	if _, err := testClassifier(server.URL, nil).classify(t.Context(), items(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != classifyPath {
		t.Fatalf("path = %q, want %q", path, classifyPath)
	}
	if method != http.MethodPost {
		t.Fatalf("method = %q, want POST", method)
	}
}

// The classifier service bounds its own concurrency and sheds load with 503 +
// Retry-After instead of queueing. That is a transient signal, not a verdict:
// two tools/list inspections arriving together is an ordinary MCP client
// start-up burst, and turning it into a discovery failure would make the
// guardrail the outage.
func TestClassifierRetriesWhenTheServiceIsAtCapacity(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var request classifyRequestBody
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		results := make([]classifyResultEntry, 0, len(request.Items))
		for _, item := range request.Items {
			score := 0.5
			results = append(results, classifyResultEntry{ID: item.ID, PoisoningScore: &score})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(classifyResponseBody{
			Model: testModel, Revision: testRevision, Results: results,
		})
	}))
	defer server.Close()

	result, err := testClassifier(server.URL, nil).classify(t.Context(), items(2))
	if err != nil {
		t.Fatalf("a capacity rejection must be retried, not surfaced as a failure: %v", err)
	}
	if len(result.Scores) != 2 {
		t.Fatalf("scores = %d, want 2", len(result.Scores))
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want one rejected and one successful", calls.Load())
	}
}

// Retries are bounded. A service that is down rather than briefly busy must
// still surface as a classification failure, so onClassifierError decides.
func TestClassifierStopsRetryingCapacityRejections(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := testClassifier(server.URL, nil).classify(t.Context(), items(1))
	if err == nil {
		t.Fatalf("a persistently unavailable classifier must fail the inspection")
	}
	if calls.Load() != defaultMaxClassifierAttempts {
		t.Fatalf("calls = %d, want %d attempts", calls.Load(), defaultMaxClassifierAttempts)
	}
}

// A non-capacity status is a real error and is not retried: retrying a 400 or a
// 401 just multiplies load against a service that will keep refusing.
func TestClassifierDoesNotRetryOtherStatuses(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := testClassifier(server.URL, nil).classify(t.Context(), items(1)); err == nil {
		t.Fatalf("a 401 must fail the inspection")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want a single attempt", calls.Load())
	}
}

func TestRetryAfterDelayIsClamped(t *testing.T) {
	tests := []struct {
		header string
		want   time.Duration
	}{
		{header: "", want: minCapacityBackoff},
		{header: "not-a-delay", want: minCapacityBackoff},
		{header: "0", want: minCapacityBackoff},
		{header: "1", want: time.Second},
		// A hostile or misconfigured service must not be able to park the
		// inspection for the whole classification deadline.
		{header: "3600", want: maxCapacityBackoff},
		{header: "-5", want: minCapacityBackoff},
	}

	for _, tt := range tests {
		t.Run("Retry-After: "+tt.header, func(t *testing.T) {
			if got := retryAfterDelay(tt.header); got != tt.want {
				t.Fatalf("delay = %v, want %v", got, tt.want)
			}
		})
	}
}

// Retries are bounded by attempt count, and the bound is configurable.
func TestCapacityRetriesRespectTheConfiguredAttemptCap(t *testing.T) {
	for _, attempts := range []int{1, 2, 5} {
		t.Run(fmt.Sprintf("%d attempts", attempts), func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()

			client := testClassifier(server.URL, func(s *SystemParams) {
				s.MaxClassifierAttempts = attempts
			})
			if _, err := client.classify(t.Context(), items(1)); err == nil {
				t.Fatalf("persistent saturation must fail the inspection")
			}
			if int(calls.Load()) != attempts {
				t.Fatalf("calls = %d, want exactly %d", calls.Load(), attempts)
			}
		})
	}
}

func TestCapacityRetriesStayInsideTheClassificationDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Ask for far longer than the deadline allows; the clamp and the
		// shared context must both bound it.
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := testClassifier(server.URL, func(s *SystemParams) { s.MaxClassifierAttempts = 10 })
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := client.classify(ctx, items(1))
	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("expected the deadline to end the retries")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("retries ran %v past the 1.5s deadline", elapsed)
	}
}

func TestOnly429And503AreRetried(t *testing.T) {
	for _, tc := range []struct {
		status      int
		wantCalls   int
		description string
	}{
		{status: http.StatusServiceUnavailable, wantCalls: defaultMaxClassifierAttempts, description: "503 is capacity"},
		{status: http.StatusTooManyRequests, wantCalls: defaultMaxClassifierAttempts, description: "429 is capacity"},
		{status: http.StatusInternalServerError, wantCalls: 1, description: "500 is not capacity"},
		{status: http.StatusUnauthorized, wantCalls: 1, description: "401 is not capacity"},
		{status: http.StatusRequestEntityTooLarge, wantCalls: 1, description: "413 is not capacity"},
		{status: http.StatusUnprocessableEntity, wantCalls: 1, description: "422 is not capacity"},
	} {
		t.Run(tc.description, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			client := testClassifier(server.URL, nil)
			if _, err := client.classify(t.Context(), items(1)); err == nil {
				t.Fatalf("status %d must fail the inspection", tc.status)
			}
			if int(calls.Load()) != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestSplitBatchesCountsUTF8Bytes(t *testing.T) {
	wide := []classifyItem{{ID: "f0", Text: strings.Repeat("€", 10)}, {ID: "f1", Text: strings.Repeat("€", 10)}} // 32 bytes each
	if got := splitBatches(wide, 10, 50); len(got) != 2 {
		t.Fatalf("batches = %d, want 2: the budget counts UTF-8 bytes, not characters", len(got))
	}
}

func TestClassifyUsesAllowedConcurrency(t *testing.T) {
	var inFlight, peak atomic.Int64
	mock := newMockClassifier(t, func(items []classifyItem) (int, classifyResponseBody) {
		current := inFlight.Add(1)
		for observed := peak.Load(); current > observed && !peak.CompareAndSwap(observed, current); observed = peak.Load() {
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
		return alwaysScore(0.1)(items)
	})
	client := testClassifier(mock.server.URL, func(s *SystemParams) { s.BatchSize = 1; s.MaxConcurrentBatches = 2 })
	if _, err := client.classify(t.Context(), items(8)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if peak.Load() != 2 {
		t.Fatalf("peak concurrency = %d, want exactly 2", peak.Load())
	}
}

func TestClassifySendsTheWireContract(t *testing.T) {
	var body []byte
	var contentType, accept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		contentType, accept = r.Header.Get("Content-Type"), r.Header.Get("Accept")
		_, _ = fmt.Fprintf(w, `{"model":%q,"revision":%q,"results":[{"id":"f0","poisoningScore":0.25}]}`, testModel, testRevision)
	}))
	defer server.Close()

	result, err := testClassifier(server.URL, nil).classify(t.Context(), []classifyItem{{ID: "f0", Text: `a "quoted" <b> é`}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contentType != "application/json" || accept != "application/json" {
		t.Fatalf("headers = %q / %q", contentType, accept)
	}
	var decoded struct {
		Items []struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Items) != 1 ||
		decoded.Items[0].ID != "f0" || decoded.Items[0].Text != `a "quoted" <b> é` {
		t.Fatalf("request body = %s (%v)", body, err)
	}
	if result.Scores["f0"] != 0.25 {
		t.Fatalf("scores = %v", result.Scores)
	}
}

func TestClassifyPathIsAppendedToAnEndpointBasePath(t *testing.T) {
	mock := newMockClassifier(t, alwaysScore(0.1))
	_, err := testClassifier(mock.server.URL+"/base", nil).classify(t.Context(), items(1))
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("error = %v, want the mock's 404 for a path it does not serve", err)
	}
	if paths := mock.seenPaths(); !slices.Equal(paths, []string{"/base/classify"}) {
		t.Fatalf("paths = %v", paths)
	}
}

func TestClassifyRejectsOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", 4096)))
	}))
	defer server.Close()
	client := testClassifier(server.URL, nil)
	client.maxResponseBytes = 1024
	if _, err := client.classify(t.Context(), items(1)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v, want a too-large error rather than a truncated decode", err)
	}
}

func TestClassifyDoesNotFollowRedirects(t *testing.T) {
	// A redirect would carry the bearer token to wherever it points.
	var elsewhere atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	mock := newScriptedClassifier(t, func([]classifyItem) mockReply {
		return mockReply{status: http.StatusTemporaryRedirect, headers: map[string]string{"Location": target.URL + "/classify"}}
	})
	_, err := testClassifier(mock.server.URL, func(s *SystemParams) { s.APIKey = "k" }).classify(t.Context(), items(1))
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("error = %v, want the 307 refused", err)
	}
	if mock.callCount() != 1 || elsewhere.Load() != 0 {
		t.Fatalf("the redirect was followed")
	}
}

func TestClassifyIgnoresProxyEnvironment(t *testing.T) {
	// A gateway-wide HTTP proxy must not receive classifier traffic and the
	// bearer token with it.
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	mock := newMockClassifier(t, alwaysScore(0.1))
	// A non-loopback name makes the standard library consult the proxy, and
	// resolves back to the mock through the dialer.
	client := testClassifier("http://classifier.test:"+mock.server.URL[strings.LastIndex(mock.server.URL, ":")+1:], nil)
	transport := client.http.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatalf("the classifier transport must not use a proxy")
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, mock.server.Listener.Addr().String())
	}
	if _, err := client.classify(t.Context(), items(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxied.Load() != 0 || mock.callCount() != 1 {
		t.Fatalf("proxied = %d, direct = %d", proxied.Load(), mock.callCount())
	}
}

func TestClassifierUnavailableFailsQuickly(t *testing.T) {
	started := time.Now()
	_, err := testClassifier(closedPortURL(t), nil).classify(t.Context(), items(1))
	if err == nil || !strings.Contains(err.Error(), "classifier request failed") {
		t.Fatalf("error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("a refused connection took %v to fail", time.Since(started))
	}
}

func TestRequestTimeoutIsEnforced(t *testing.T) {
	mock := newMockClassifier(t, func(items []classifyItem) (int, classifyResponseBody) {
		time.Sleep(time.Second)
		return alwaysScore(0.1)(items)
	})
	client := testClassifier(mock.server.URL, func(s *SystemParams) { s.RequestTimeout = 150 * time.Millisecond })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err := client.classify(ctx, items(1))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v, want a timeout", err)
	}
	if time.Since(started) > 800*time.Millisecond {
		t.Fatalf("the request timeout was not applied: %v", time.Since(started))
	}
}

func TestRetryAfterDelayIsClampedForEveryForm(t *testing.T) {
	for header, want := range map[string]time.Duration{
		" 1 ":                           time.Second,
		"1.5":                           minCapacityBackoff,
		"\u0663":                        minCapacityBackoff, // non-ASCII digits are not delta-seconds
		"+1":                            time.Second,
		"99999999999999999999999999":    maxCapacityBackoff,
		"-99999999999999999999999999":   minCapacityBackoff,
		"9223372036854775807":           maxCapacityBackoff,
		"Wed, 21 Oct 2015 07:28:00 GMT": minCapacityBackoff, // in the past
	} {
		if got := retryAfterDelay(header); got != want {
			t.Fatalf("retryAfterDelay(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestRetryAfterAcceptsAnHTTPDate(t *testing.T) {
	soon := time.Now().Add(time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfterDelay(soon); got < minCapacityBackoff || got > maxCapacityBackoff {
		t.Fatalf("retryAfterDelay(%q) = %v", soon, got)
	}
	if got := retryAfterDelay(time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)); got != maxCapacityBackoff {
		t.Fatalf("a far date must clamp to the maximum, got %v", got)
	}
	if got := retryAfterDelay(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)); got != minCapacityBackoff {
		t.Fatalf("a past date must clamp to the minimum, got %v", got)
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	mock := newScriptedClassifier(t, func(batch []classifyItem) mockReply {
		mu.Lock()
		times = append(times, time.Now())
		first := len(times) == 1
		mu.Unlock()
		if first {
			return mockReply{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "1"}}
		}
		_, body := alwaysScore(0.2)(batch)
		return mockReply{status: http.StatusOK, body: body}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := testClassifier(mock.server.URL, nil).classify(ctx, items(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gap := times[1].Sub(times[0]); gap < 950*time.Millisecond {
		t.Fatalf("retried after %v, want the requested second", gap)
	}
}

func TestAWaitThatCannotFinishInsideTheDeadlineIsNotStarted(t *testing.T) {
	mock := newScriptedClassifier(t, func([]classifyItem) mockReply {
		return mockReply{status: http.StatusServiceUnavailable, headers: map[string]string{"Retry-After": "2"}}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := testClassifier(mock.server.URL, func(s *SystemParams) { s.MaxClassifierAttempts = 10 }).classify(ctx, items(1))
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("error = %v, want a deadline failure", err)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("took %v: a wait longer than the remaining deadline must fail at once", elapsed)
	}
	if mock.callCount() != 1 {
		t.Fatalf("calls = %d, want 1", mock.callCount())
	}
}

func TestCancellationDuringARetryWaitStopsImmediately(t *testing.T) {
	mock := newScriptedClassifier(t, func([]classifyItem) mockReply {
		return mockReply{status: http.StatusServiceUnavailable, headers: map[string]string{"Retry-After": "2"}}
	})
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(150*time.Millisecond, cancel)
	started := time.Now()
	_, err := testClassifier(mock.server.URL, func(s *SystemParams) { s.MaxClassifierAttempts = 10 }).classify(ctx, items(1))
	if err == nil {
		t.Fatalf("expected cancellation to fail the classification")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancellation took %v to end the retry wait", elapsed)
	}
	if mock.callCount() != 1 {
		t.Fatalf("calls = %d, want no retry after cancellation", mock.callCount())
	}
}

func TestTheFirstFailingBatchCancelsTheRest(t *testing.T) {
	var started atomic.Int64
	mock := newMockClassifier(t, func(batch []classifyItem) (int, classifyResponseBody) {
		if started.Add(1) == 1 {
			return http.StatusInternalServerError, classifyResponseBody{}
		}
		time.Sleep(2 * time.Second)
		return alwaysScore(0.1)(batch)
	})
	client := testClassifier(mock.server.URL, func(s *SystemParams) { s.BatchSize = 1; s.MaxConcurrentBatches = 2 })
	begin := time.Now()
	_, err := client.classify(t.Context(), items(6))
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("error = %v, want the first failure reported", err)
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("the remaining batches kept running for %v after a failure", elapsed)
	}
	if started.Load() > 3 {
		t.Fatalf("%d batches started, want the rest cancelled", started.Load())
	}
}

func TestClassifyLeavesNoGoroutinesBehind(t *testing.T) {
	mock := newMockClassifier(t, func(batch []classifyItem) (int, classifyResponseBody) {
		time.Sleep(50 * time.Millisecond)
		return alwaysScore(0.1)(batch)
	})
	client := testClassifier(mock.server.URL, func(s *SystemParams) { s.BatchSize = 1; s.MaxConcurrentBatches = 4 })
	// Warm the connection pool so its long-lived goroutines exist before the
	// baseline is taken.
	_, _ = client.classify(t.Context(), items(4))
	baseline := runtime.NumGoroutine()

	for range 5 {
		_, _ = client.classify(t.Context(), items(8))
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		_, _ = client.classify(ctx, items(8))
		cancel()
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline+8 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if now := runtime.NumGoroutine(); now > baseline+8 {
		t.Fatalf("goroutines grew from %d to %d", baseline, now)
	}
}

func TestErrorMessagesNeverContainTheKeyOrTheText(t *testing.T) {
	const secretKey = "sk-must-not-leak"
	const secretText = "tool metadata that must not leak"
	mock := newScriptedClassifier(t, func([]classifyItem) mockReply {
		return mockReply{status: http.StatusOK, body: fmt.Sprintf(`{"model":%q,"revision":%q,"results":[{"id":"x","poisoningScore":0.1}]}`, testModel, testRevision)}
	})
	_, err := testClassifier(mock.server.URL, func(s *SystemParams) { s.APIKey = secretKey }).
		classify(t.Context(), []classifyItem{{ID: "f0", Text: secretText}})
	if err == nil || strings.Contains(err.Error(), secretKey) || strings.Contains(err.Error(), secretText) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoneSurrogatesAreSentAsReplacementCharacters(t *testing.T) {
	mock := newMockClassifier(t, alwaysScore(0.1))
	p := newTestPolicy(t, mock.server.URL, nil)
	newExchange(toolsListRequest("1"), toolsListResponse("1", `{"name":"t","description":"a\ud800b"}`)).run(t, p)
	if texts := mock.texts(); !slices.Contains(texts, "a\uFFFDb") {
		t.Fatalf("texts = %q, want the lone surrogate sent as U+FFFD", texts)
	}
}

func TestConnectionsAreReused(t *testing.T) {
	var connections atomic.Int64
	mock := newMockClassifier(t, alwaysScore(0.1))
	// A server of its own, so the connection hook is installed before it
	// starts serving.
	counting := httptest.NewUnstartedServer(mock.server.Config.Handler)
	counting.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	counting.Start()
	defer counting.Close()
	client := testClassifier(counting.URL, nil)
	for range 5 {
		if _, err := client.classify(t.Context(), items(1)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if connections.Load() > 2 || mock.callCount() != 5 {
		t.Fatalf("connections = %d for %d requests, want reuse", connections.Load(), mock.callCount())
	}
}

func TestOtherStatusesAreNotRetried(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			mock := newScriptedClassifier(t, func([]classifyItem) mockReply {
				return mockReply{status: status, headers: map[string]string{"Retry-After": "0"}}
			})
			if _, err := testClassifier(mock.server.URL, nil).classify(t.Context(), items(1)); err == nil {
				t.Fatalf("status %d must fail the inspection", status)
			}
			if mock.callCount() != 1 {
				t.Fatalf("calls = %d, want 1", mock.callCount())
			}
		})
	}
}
