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

package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/catalog/infrastructure"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

type fakeBase struct {
	url     string
	headers map[string]string
	// replicas maps an ordinal word to the base URL of that gateway replica.
	replicas map[string]string
}

func (f fakeBase) GatewayURLAt(ordinal, path string) (string, error) {
	base, ok := f.replicas[ordinal]
	if !ok {
		return "", fmt.Errorf("no gateway %q", ordinal)
	}
	return base + path, nil
}

func (f fakeBase) GatewayURL(path string) (string, error) { return f.url + path, nil }

func (f fakeBase) ScenarioHeaders(context.Context) map[string]string { return f.headers }

func (f fakeBase) RequestHost(context.Context) string { return "" }

func scenarioContext() context.Context {
	return tcontext.WithLocal(context.Background(), tcontext.NewLocal("test-runner"))
}

func TestCheckStatusSplit(t *testing.T) {
	tests := []struct {
		name     string
		statuses []int
		want     map[int]int
		wantErr  string
	}{
		{name: "exact split", statuses: []int{200, 429, 200, 429, 200}, want: map[int]int{200: 3, 429: 2}},
		{name: "all one status", statuses: []int{200, 200}, want: map[int]int{200: 2, 429: 0}},
		{name: "too many admitted", statuses: []int{200, 200, 200}, want: map[int]int{200: 2, 429: 1},
			wantErr: "status 200: want 2, got 3"},
		{name: "too many rejected", statuses: []int{200, 429, 429}, want: map[int]int{200: 2, 429: 1},
			wantErr: "status 429: want 1, got 2"},
		{name: "unexpected status", statuses: []int{200, 500}, want: map[int]int{200: 1, 429: 1},
			wantErr: "status 500: want 0, got 1"},
		{name: "no responses", statuses: nil, want: map[int]int{200: 0, 429: 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStatusSplit(tc.statuses, tc.want)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestSendConcurrentSplit(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Scenario") != "yes" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if served.Add(1) > 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := newSteps(fakeBase{url: server.URL, headers: map[string]string{"X-Scenario": "yes"}}, nil)

	if err := s.sendConcurrentSplit(scenarioContext(), 5, "get", "/limited", 3, 200, 2, 429); err != nil {
		t.Fatalf("a 3/2 split should match: %v", err)
	}
	if err := s.sendConcurrentSplit(scenarioContext(), 5, "GET", "/limited", 5, 200, 0, 429); err == nil {
		t.Fatal("a split that does not match should fail")
	}
	if err := s.sendConcurrentSplit(scenarioContext(), 0, "GET", "/limited", 0, 200, 0, 429); err == nil {
		t.Fatal("a zero request count should be rejected")
	}
}

func TestSecretAbsent(t *testing.T) {
	if err := secretAbsent("policy engine started", "s3cret", "gateway-runtime"); err != nil {
		t.Fatalf("a log without the secret should pass: %v", err)
	}
	err := secretAbsent("dial failed: AUTH s3cret", "s3cret", "gateway-runtime")
	if err == nil {
		t.Fatal("a log holding the secret should fail")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("the failure must not repeat the secret: %v", err)
	}
	if err := secretAbsent("anything", "", "gateway-runtime"); err == nil {
		t.Fatal("an empty secret should be refused")
	}
}

func TestLogsHideRedisPasswordNeedsTopology(t *testing.T) {
	s := newSteps(fakeBase{}, nil)
	if err := s.logsHideRedisPassword(scenarioContext(), "gateway-runtime"); err == nil {
		t.Fatal("a step without a topology should fail")
	}
}

func TestSoleContainerID(t *testing.T) {
	if id, err := soleContainerID("abc123\n", 6379); err != nil || id != "abc123" {
		t.Fatalf("one container should be returned, got %q, %v", id, err)
	}
	for _, out := range []string{"", "a\nb\n"} {
		if _, err := soleContainerID(out, 6379); err == nil {
			t.Fatalf("output %q should be refused", out)
		}
	}
}

func TestRedisStartAndStopGuards(t *testing.T) {
	var calls [][]string
	s := newSteps(fakeBase{}, nil)
	s.docker = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		return "", nil
	}
	if err := s.startRedis(scenarioContext()); err == nil {
		t.Fatal("starting Redis that was never stopped should fail")
	}
	if err := s.stopRedis(scenarioContext()); err == nil {
		t.Fatal("stopping Redis without a topology should fail")
	}
	s.stoppedRedis = "abc123"
	if err := s.stopRedis(scenarioContext()); err == nil {
		t.Fatal("stopping Redis twice should fail")
	}
	if err := s.startRedis(scenarioContext()); err != nil {
		t.Fatalf("starting the stopped container: %v", err)
	}
	if s.stoppedRedis != "" || len(calls) != 1 || calls[0][0] != "start" || calls[0][1] != "abc123" {
		t.Fatalf("unexpected state %q after calls %v", s.stoppedRedis, calls)
	}
}

func TestRedisContainerIDIsRememberedAcrossARestart(t *testing.T) {
	s := newSteps(fakeBase{}, nil)
	s.docker = func(context.Context, ...string) (string, error) {
		t.Fatal("a known container must not be looked up again by its port")
		return "", nil
	}
	s.redisID = "abc123"
	for i := 0; i < 2; i++ {
		if id, err := s.redisContainerID(scenarioContext()); err != nil || id != "abc123" {
			t.Fatalf("redisContainerID = %q, %v; want abc123", id, err)
		}
	}
}

func TestRunDockerReportsFailures(t *testing.T) {
	if _, err := runDocker(context.Background(), "this-subcommand-does-not-exist"); err == nil {
		t.Skip("docker accepted an unknown subcommand")
	}
}

func TestSendConcurrentSplitReportsTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	s := newSteps(fakeBase{url: url}, nil)
	if err := s.sendConcurrentSplit(scenarioContext(), 2, "GET", "/x", 2, 200, 0, 429); err == nil {
		t.Fatal("an unreachable gateway should fail the step")
	}
}

func TestSendRepeatedAtTargetsReplicaAndPublishesLast(t *testing.T) {
	var firstHits, secondHits atomic.Int64
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Scenario") != "yes" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if secondHits.Add(1) > 2 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	s := newSteps(fakeBase{
		headers:  map[string]string{"X-Scenario": "yes"},
		replicas: map[string]string{"first": first.URL, "second": second.URL},
	}, nil)

	ctx := scenarioContext()
	if err := s.sendRepeatedAt(ctx, 3, "get", "second", "/limited"); err != nil {
		t.Fatalf("sending to the second replica: %v", err)
	}
	if firstHits.Load() != 0 || secondHits.Load() != 3 {
		t.Fatalf("requests went to first=%d second=%d, want 0 and 3", firstHits.Load(), secondHits.Load())
	}
	published, err := httpx.Published(ctx)
	if err != nil {
		t.Fatalf("the last response should be published: %v", err)
	}
	if published.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("published status %d, want 429", published.StatusCode)
	}
	if got := published.Headers.Get("X-RateLimit-Remaining"); got != "0" {
		t.Fatalf("published X-RateLimit-Remaining %q, want 0", got)
	}

	ctx = scenarioContext()
	if err := s.sendRepeatedAt(ctx, 1, "GET", "first", "/limited"); err != nil {
		t.Fatalf("sending to the first replica: %v", err)
	}
	if firstHits.Load() != 1 {
		t.Fatalf("first replica served %d requests, want 1", firstHits.Load())
	}
}

func TestSendUntilHeaderAtWaitsForTheHeaderAndPublishesThatResponse(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The policy is not loaded for the first two requests, so no rate limit header yet.
		if hits.Add(1) > 2 {
			w.Header().Set("X-RateLimit-Limit", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := newSteps(fakeBase{replicas: map[string]string{"second": server.URL}}, nil)
	ctx := scenarioContext()
	if err := s.sendUntilHeaderAt(ctx, "get", "second", "/limited", "X-RateLimit-Limit", "2"); err != nil {
		t.Fatalf("polling for the header: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("the poll sent %d requests, want 3", hits.Load())
	}
	published, err := httpx.Published(ctx)
	if err != nil {
		t.Fatalf("the response that carried the header should be published: %v", err)
	}
	if published.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("published status %d, want 429", published.StatusCode)
	}
}

func TestSendUntilHeaderAtRejectsAnUnknownReplica(t *testing.T) {
	s := newSteps(fakeBase{replicas: map[string]string{"first": "http://127.0.0.1:1"}}, nil)
	if err := s.sendUntilHeaderAt(scenarioContext(), "GET", "third", "/x", "X-A", "1"); err == nil {
		t.Fatal("an unknown replica should be rejected")
	}
}

func TestSendRepeatedAtRejectsBadInput(t *testing.T) {
	s := newSteps(fakeBase{replicas: map[string]string{"first": "http://127.0.0.1:1"}}, nil)
	if err := s.sendRepeatedAt(scenarioContext(), 0, "GET", "first", "/x"); err == nil {
		t.Fatal("a zero request count should be rejected")
	}
	if err := s.sendRepeatedAt(scenarioContext(), 1, "GET", "third", "/x"); err == nil {
		t.Fatal("an unknown replica should be rejected")
	}
}

func TestSendRepeatedAtReportsTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	s := newSteps(fakeBase{replicas: map[string]string{"first": url}}, nil)
	if err := s.sendRepeatedAt(scenarioContext(), 2, "GET", "first", "/x"); err == nil {
		t.Fatal("an unreachable replica should fail the step")
	}
}

func TestParseQuotas(t *testing.T) {
	quotas, err := parseQuotas(`[{"name":"q","limits":[{"limit":2,"duration":"1m"}]}]`)
	if err != nil || len(quotas) != 1 {
		t.Fatalf("a quota array should parse: %v (%d)", err, len(quotas))
	}
	for name, raw := range map[string]string{
		"not json": "nope", "object": `{"a":1}`, "empty": `[]`, "blank": "",
	} {
		if _, err := parseQuotas(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRestAPIPayloadAttachesPolicyToTheLimitedOperationOnly(t *testing.T) {
	quotas, err := parseQuotas(`[{"name":"q","limits":[{"limit":2,"duration":"1m"}]}]`)
	if err != nil {
		t.Fatal(err)
	}
	payload := restAPIPayload("api-1", "proj-1", "/ctx", quotas)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DisplayName string `json:"displayName"`
		Context     string `json:"context"`
		ProjectID   string `json:"projectId"`
		Upstream    struct {
			Main struct {
				URL string `json:"url"`
			} `json:"main"`
		} `json:"upstream"`
		Policies   []any `json:"policies"`
		Operations []struct {
			Request struct {
				Method   string `json:"method"`
				Path     string `json:"path"`
				Policies []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Params  struct {
						Quotas []any `json:"quotas"`
					} `json:"params"`
				} `json:"policies"`
			} `json:"request"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "api-1" || got.Context != "/ctx" || got.ProjectID != "proj-1" || got.Upstream.Main.URL != upstreamURL {
		t.Fatalf("unexpected API header fields: %+v", got)
	}
	if len(got.Policies) != 0 {
		t.Fatal("the policy must be attached at operation level, not on the API")
	}
	if len(got.Operations) != 2 {
		t.Fatalf("want 2 operations, got %d", len(got.Operations))
	}
	health, limited := got.Operations[0].Request, got.Operations[1].Request
	if health.Path != "/health" || len(health.Policies) != 0 {
		t.Fatalf("/health must carry no policy: %+v", health)
	}
	if limited.Method != "GET" || limited.Path != "/limited" || len(limited.Policies) != 1 {
		t.Fatalf("/limited must carry one policy: %+v", limited)
	}
	policy := limited.Policies[0]
	if policy.Name != "advanced-ratelimit" || policy.Version != "v1" || len(policy.Params.Quotas) != 1 {
		t.Fatalf("unexpected policy: %+v", policy)
	}
}

func TestCreateRestAPIWithQuotasValidatesBeforeCallingTheControlPlane(t *testing.T) {
	s := newSteps(fakeBase{}, nil)
	ctx := scenarioContext()
	if err := s.createRestAPIWithQuotas(ctx, "api", "proj", "/ctx", nil); err == nil {
		t.Fatal("a missing DocString should be rejected")
	}
	err := s.createRestAPIWithQuotas(ctx, "api", "proj", "/ctx", &godog.DocString{Content: "not json"})
	if err == nil || !strings.Contains(err.Error(), "JSON array") {
		t.Fatalf("an invalid quotas DocString should be rejected, got %v", err)
	}
}

func TestAssignedHandle(t *testing.T) {
	for name, tc := range map[string]struct{ handle, id, uuid, want string }{
		"handle first": {"h", "i", "u", "h"},
		"id next":      {"", "i", "u", "i"},
		"uuid last":    {"", "", "u", "u"},
		"none":         {"", "", "", ""},
	} {
		if got := assignedHandle(tc.handle, tc.id, tc.uuid); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

func TestCheckAssignedHandle(t *testing.T) {
	if err := checkAssignedHandle("", "api"); err != nil {
		t.Fatalf("a response without a handle should pass: %v", err)
	}
	if err := checkAssignedHandle("api", "api"); err != nil {
		t.Fatalf("a matching handle should pass: %v", err)
	}
	if err := checkAssignedHandle("uuid-1", "api"); err == nil {
		t.Fatal("a different identifier should fail")
	}
}

func TestGatewayHandleAt(t *testing.T) {
	for ordinal, want := range map[string]string{"first": "it-gateway-1", "second": "it-gateway-2"} {
		if got, err := gatewayHandleAt(ordinal); err != nil || got != want {
			t.Errorf("%s: got %q, %v", ordinal, got, err)
		}
	}
	if _, err := gatewayHandleAt("third"); err == nil {
		t.Fatal("an unknown ordinal should be rejected")
	}
}

func TestIsLastProjectValidation(t *testing.T) {
	body := `{"code":"VALIDATION_FAILED","message":"Organization must have at least one project"}`
	if !isLastProjectValidation(&httpx.Response{StatusCode: http.StatusBadRequest, Body: []byte(body)}) {
		t.Fatal("the last-project refusal should be recognised")
	}
	if isLastProjectValidation(&httpx.Response{StatusCode: http.StatusBadRequest, Body: []byte(`{"code":"OTHER"}`)}) {
		t.Fatal("another refusal must not be swallowed")
	}
	if isLastProjectValidation(&httpx.Response{StatusCode: http.StatusInternalServerError, Body: []byte(body)}) {
		t.Fatal("a non-400 status must not be swallowed")
	}
	if isLastProjectValidation(nil) {
		t.Fatal("a nil response is not the refusal")
	}
}

func TestStoreValue(t *testing.T) {
	ctx := scenarioContext()
	if err := storeValue(ctx, "metadata", "keyType"); err != nil {
		t.Fatalf("storing a value: %v", err)
	}
	if got, err := tcontext.ResolveString(ctx, "keyType"); err != nil || got != "metadata" {
		t.Fatalf("stored %q, %v; want metadata", got, err)
	}
	if err := storeValue(ctx, "x", "  "); err == nil {
		t.Fatal("an empty key should be rejected")
	}
	if err := storeValue(context.Background(), "x", "k"); err == nil {
		t.Fatal("a context without a runner should be rejected")
	}
}

func TestParseCounter(t *testing.T) {
	for in, want := range map[string]int64{"3\n": 3, "  12 ": 12, "": 0, "\n": 0} {
		if got, err := parseCounter(in); err != nil || got != want {
			t.Errorf("parseCounter(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseCounter("(error) WRONGTYPE"); err == nil {
		t.Fatal("a non-number should be rejected")
	}
}

func TestHighestCounterReadsEveryMatchingKeyWithoutPuttingThePasswordOnTheCommandLine(t *testing.T) {
	var calls [][]string
	s := newSteps(fakeBase{}, nil)
	s.docker = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		switch {
		case strings.Contains(strings.Join(args, " "), "--scan"):
			return "ratelimit:v1:user-1:1\nratelimit:v1:user-1:2\n", nil
		case args[len(args)-1] == "ratelimit:v1:user-1:1":
			return "2\n", nil
		default:
			return "5\n", nil
		}
	}
	got, err := s.highestCounter(context.Background(), "cid", "user-1")
	if err != nil || got != 5 {
		t.Fatalf("highestCounter = %d, %v; want 5", got, err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected one scan and two reads, got %v", calls)
	}
	scan := calls[0]
	if scan[len(scan)-1] != "ratelimit:v1:*user-1*" {
		t.Fatalf("scan pattern %q", scan[len(scan)-1])
	}
	for _, call := range calls {
		if call[1] != "-e" || call[2] != "REDISCLI_AUTH="+infrastructure.RedisPassword {
			t.Fatalf("the password must travel as REDISCLI_AUTH in the exec environment: %v", call)
		}
		for _, arg := range call[3:] {
			if arg == infrastructure.RedisPassword {
				t.Fatalf("the password must not be a command-line argument: %v", call)
			}
		}
	}
}

func TestHighestCounterIsZeroWithoutKeysAndReportsDockerFailures(t *testing.T) {
	s := newSteps(fakeBase{}, nil)
	s.docker = func(context.Context, ...string) (string, error) { return "", nil }
	if got, err := s.highestCounter(context.Background(), "cid", "none"); err != nil || got != 0 {
		t.Fatalf("no keys should read as zero, got %d, %v", got, err)
	}
	s.docker = func(context.Context, ...string) (string, error) { return "", fmt.Errorf("docker is down") }
	if _, err := s.highestCounter(context.Background(), "cid", "x"); err == nil {
		t.Fatal("a docker failure should be reported")
	}
}

func TestRedisCounterReachesRejectsGlobCharacters(t *testing.T) {
	s := newSteps(fakeBase{}, nil)
	s.docker = func(context.Context, ...string) (string, error) { return "", nil }
	for _, fragment := range []string{"", "a*b", "a b", "x[1]"} {
		if err := s.redisCounterReaches(scenarioContext(), fragment, 1); err == nil {
			t.Errorf("fragment %q should be rejected", fragment)
		}
	}
}
