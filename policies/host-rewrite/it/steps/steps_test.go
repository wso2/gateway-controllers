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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

type fakeBase struct {
	url     string
	headers map[string]string
	host    string
}

func (f fakeBase) GatewayURL(path string) (string, error) { return f.url + path, nil }

func (f fakeBase) ScenarioHeaders(context.Context) map[string]string { return f.headers }

func (f fakeBase) RequestHost(context.Context) string { return f.host }

func newScenarioContext() context.Context {
	return tcontext.WithLocal(context.Background(), tcontext.NewLocal("test-runner"))
}

// table returns two-cell rows, as tableCells reads them from a Gherkin table.
func table(rows ...[2]string) [][]string {
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, []string{row[0], row[1]})
	}
	return out
}

// echoServer answers each path with {"headers":{"Host": <host for that path>}}.
func echoServer(t *testing.T, hostFor func(path string) string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"headers": map[string]any{"Host": hostFor(r.URL.Path)}})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestPathExpectationsExpandsAndValidates(t *testing.T) {
	ctx := newScenarioContext()
	require.NoError(t, tcontext.Set(ctx, "ctx", "/api/v1"))

	rows, err := pathExpectations(ctx, table([2]string{"${CTX:ctx}/a", "a.example"}, [2]string{" /b ", " b.example "}))
	require.NoError(t, err)
	require.Equal(t, []pathExpectation{{path: "/api/v1/a", want: "a.example"}, {path: "/b", want: "b.example"}}, rows)

	_, err = pathExpectations(ctx, nil)
	require.ErrorContains(t, err, "required")
	_, err = pathExpectations(ctx, table([2]string{"", "x"}))
	require.ErrorContains(t, err, "empty path")
}

func TestJSONFieldReadsDottedFields(t *testing.T) {
	body := []byte(`{"headers":{"Host":"a.example","Count":3},"path":"/x"}`)
	got, err := jsonField(body, "headers.Host")
	require.NoError(t, err)
	require.Equal(t, "a.example", got)
	got, err = jsonField(body, "headers.Count")
	require.NoError(t, err)
	require.Equal(t, "3", got)

	_, err = jsonField(body, "headers.Missing")
	require.ErrorContains(t, err, "missing")
	_, err = jsonField(body, "path.deeper")
	require.ErrorContains(t, err, "not inside an object")
	_, err = jsonField([]byte("not json"), "headers.Host")
	require.ErrorContains(t, err, "not JSON")
}

func TestCheckEchoedField(t *testing.T) {
	row := pathExpectation{path: "/a", want: "a.example"}
	ok := &httpx.Response{StatusCode: 200, Body: []byte(`{"headers":{"Host":"a.example"}}`)}
	require.Empty(t, checkEchoedField(ok, nil, "headers.Host", row))

	wrong := &httpx.Response{StatusCode: 200, Body: []byte(`{"headers":{"Host":"b.example"}}`)}
	require.Contains(t, checkEchoedField(wrong, nil, "headers.Host", row), `want "a.example"`)
	require.Contains(t, checkEchoedField(&httpx.Response{StatusCode: 503}, nil, "headers.Host", row), "status 503")
	require.Contains(t, checkEchoedField(nil, errors.New("boom"), "headers.Host", row), "request failed")
	require.Contains(t, checkEchoedField(nil, nil, "headers.Host", row), "no response")
}

func TestSendConcurrentAlternatingPathsPassesWhenEveryResponseMatches(t *testing.T) {
	var calls, sawHost atomic.Int32
	// The request host and scenario headers reach every request.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host == "client.example" && r.Header.Get("X-Test") == "1" {
			sawHost.Add(1)
		}
		host := "b.example"
		if r.URL.Path == "/a" {
			host = "a.example"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"headers": map[string]any{"Host": host}})
	}))
	t.Cleanup(server.Close)

	steps := newSteps(fakeBase{url: server.URL, headers: map[string]string{"X-Test": "1"}, host: "client.example"})
	err := steps.sendConcurrentAlternating(newScenarioContext(), 40, "get", "headers.Host",
		table([2]string{"/a", "a.example"}, [2]string{"/b", "b.example"}))
	require.NoError(t, err)
	require.Equal(t, int32(40), calls.Load())
	require.Equal(t, int32(40), sawHost.Load())
}

func TestSendConcurrentAlternatingPathsReportsALeakedValue(t *testing.T) {
	var n atomic.Int32
	server := echoServer(t, func(path string) string {
		if path == "/b" && n.Add(1) == 3 {
			return "a.example" // one /b response carries /a's value
		}
		if path == "/a" {
			return "a.example"
		}
		return "b.example"
	})
	steps := newSteps(fakeBase{url: server.URL})
	err := steps.sendConcurrentAlternating(newScenarioContext(), 20, "GET", "headers.Host",
		table([2]string{"/a", "a.example"}, [2]string{"/b", "b.example"}))
	require.ErrorContains(t, err, "1 of 20 concurrent requests")
	require.ErrorContains(t, err, `/b: headers.Host is "a.example", want "b.example"`)
}

func TestSendConcurrentAlternatingPathsRejectsBadInput(t *testing.T) {
	steps := newSteps(fakeBase{url: "http://unused"})
	ctx := newScenarioContext()
	rows := table([2]string{"/a", "a.example"})
	require.ErrorContains(t, steps.sendConcurrentAlternating(ctx, 0, "GET", "headers.Host", rows), "between 1 and")
	require.ErrorContains(t, steps.sendConcurrentAlternating(ctx, maxConcurrentRequests+1, "GET", "headers.Host", rows), "between 1 and")
	require.ErrorContains(t, steps.sendConcurrentAlternating(ctx, 1, "GET", " ", rows), "JSON field is required")
}

func TestSummarizeFailuresCapsTheReasons(t *testing.T) {
	require.NoError(t, summarizeFailures(3, []string{"", "", ""}))
	failures := []string{"r1", "", "r2", "r3", "r4", "r5", "r6", "r7"}
	err := summarizeFailures(len(failures), failures)
	require.ErrorContains(t, err, "7 of 8")
	require.NotContains(t, err.Error(), "r6")
}

// valueTable returns one-cell rows, as tableCells reads them from a Gherkin table.
func valueTable(values ...string) [][]string {
	out := make([][]string, 0, len(values))
	for _, v := range values {
		out = append(out, []string{v})
	}
	return out
}

func hostBody(host string) []byte {
	b, _ := json.Marshal(map[string]any{"headers": map[string]any{"Host": host}})
	return b
}

func TestCheckEveryResponseIsOneOf(t *testing.T) {
	allowed := map[string]bool{"v1.example": true, "v2.example": true}
	ok := []backgroundResponse{{status: 200, body: hostBody("v1.example")}, {status: 200, body: hostBody("v2.example")}}
	require.NoError(t, checkEveryResponseIsOneOf(ok, "headers.Host", allowed))

	require.ErrorContains(t, checkEveryResponseIsOneOf(nil, "headers.Host", allowed), "no background response")

	bad := append(append([]backgroundResponse{}, ok...),
		backgroundResponse{status: 200, body: hostBody("client.example")},
		backgroundResponse{status: 503},
		backgroundResponse{err: "connection reset"})
	err := checkEveryResponseIsOneOf(bad, "headers.Host", allowed)
	require.ErrorContains(t, err, "3 of 5 background responses")
	require.ErrorContains(t, err, `headers.Host is "client.example"`)
	require.ErrorContains(t, err, "status 503")
	require.ErrorContains(t, err, "connection reset")
}

func TestDistinctValuesKeepsFirstSeenOrderAndSkipsFailures(t *testing.T) {
	responses := []backgroundResponse{
		{status: 200, body: hostBody("v1.example")}, {status: 503, body: hostBody("v9.example")},
		{status: 200, body: hostBody("v2.example")}, {status: 200, body: hostBody("v1.example")},
		{err: "boom"},
	}
	require.Equal(t, []string{"v1.example", "v2.example"}, distinctValues(responses, "headers.Host"))
}

func TestAllowedValuesExpandsStoredValues(t *testing.T) {
	ctx := newScenarioContext()
	require.NoError(t, tcontext.Set(ctx, "h", "v3.example"))
	got, err := allowedValues(ctx, valueTable(" v1.example ", "${CTX:h}"))
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"v1.example": true, "v3.example": true}, got)
	_, err = allowedValues(ctx, nil)
	require.ErrorContains(t, err, "required")
}

func TestBackgroundRequestsRecordAndCheckResponses(t *testing.T) {
	var calls, wrongRequest atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := "v1.example"
		if calls.Add(1) > 3 {
			host = "v2.example"
		}
		if r.Host != "client.example" || r.Header.Get("X-Test") != "1" || r.Method != http.MethodPost {
			wrongRequest.Add(1)
		}
		_, _ = w.Write(hostBody(host))
	}))
	t.Cleanup(server.Close)
	steps := newSteps(fakeBase{url: server.URL, headers: map[string]string{"X-Test": "1"}, host: "client.example"})
	ctx := newScenarioContext()
	t.Cleanup(func() { stopAllBackgroundRequests(ctx) }) // runs before server.Close, even if a check fails

	require.NoError(t, steps.startBackgroundRequests(ctx, "post", "/probe", "traffic"))
	require.ErrorContains(t, steps.startBackgroundRequests(ctx, "post", "/probe", "traffic"), "already running")
	probe, err := namedBackgroundProbe(ctx, "traffic")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(probe.snapshot()) >= 6 }, 5*time.Second, 20*time.Millisecond)
	require.NoError(t, steps.stopBackgroundRequests(ctx, "traffic"))
	require.Zero(t, wrongRequest.Load(), "every request carries the method, request host and scenario headers")

	require.NoError(t, steps.everyBackgroundResponseIsOneOfValues(ctx, "traffic", "headers.Host", valueTable("v1.example", "v2.example")))
	require.ErrorContains(t, steps.everyBackgroundResponseIsOneOfValues(ctx, "traffic", "headers.Host", valueTable("v1.example")),
		`headers.Host is "v2.example"`)
	require.ErrorContains(t, steps.stopBackgroundRequests(ctx, "other"), "no background requests named")
}

func TestStopAllBackgroundRequestsStopsEveryProbe(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write(hostBody("v1.example"))
	}))
	t.Cleanup(server.Close)
	steps := newSteps(fakeBase{url: server.URL})
	ctx := newScenarioContext()
	t.Cleanup(func() { stopAllBackgroundRequests(ctx) })
	require.NoError(t, steps.startBackgroundRequests(ctx, "GET", "/a", "one"))
	require.NoError(t, steps.startBackgroundRequests(ctx, "GET", "/b", "two"))
	require.Eventually(t, func() bool { return calls.Load() >= 2 }, 5*time.Second, 20*time.Millisecond)

	stopAllBackgroundRequests(ctx)
	after := calls.Load()
	time.Sleep(3 * backgroundRequestInterval)
	require.Equal(t, after, calls.Load(), "no request is sent after the probes are stopped")
	_, err := namedBackgroundProbe(ctx, "one")
	require.ErrorContains(t, err, "no background requests named")
}

func TestTableCellsRejectsAMissingTable(t *testing.T) {
	_, err := tableCells(nil, 2)
	require.ErrorContains(t, err, "a table is required")
}

func TestEveryBackgroundResponseFailsWhenResponsesWereDropped(t *testing.T) {
	steps := newSteps(fakeBase{url: "http://unused"})
	ctx := newScenarioContext()
	hosts := make([]string, maxBackgroundResponses+1)
	for i := range hosts {
		hosts[i] = "v1.example"
	}
	stoppedProbe(t, ctx, "full", hosts...)

	err := steps.everyBackgroundResponseIsOneOfValues(ctx, "full", "headers.Host", valueTable("v1.example"))
	require.ErrorContains(t, err, "dropped 1 responses")
}

func TestBackgroundRequestsEventuallyEchoWaitsForTheValue(t *testing.T) {
	var calls atomic.Int32
	server := echoServer(t, func(string) string {
		if calls.Add(1) > 5 {
			return "v3.example"
		}
		return "v1.example"
	})
	steps := newSteps(fakeBase{url: server.URL})
	ctx := newScenarioContext()
	t.Cleanup(func() { stopAllBackgroundRequests(ctx) })

	require.NoError(t, steps.startBackgroundRequests(ctx, "GET", "/probe", "traffic"))
	require.NoError(t, steps.backgroundRequestsEventuallyEcho(ctx, "traffic", "v1.example", "headers.Host"))
	// The value only appears after the fifth response: the step must wait for it.
	require.NoError(t, steps.backgroundRequestsEventuallyEcho(ctx, "traffic", "v3.example", "headers.Host"))
	require.NoError(t, steps.stopBackgroundRequests(ctx, "traffic"))

	err := steps.backgroundRequestsEventuallyEcho(ctx, "traffic", "v9.example", "headers.Host")
	require.ErrorContains(t, err, `never echoed headers.Host "v9.example"; values seen: v1.example, v3.example`)
}

func TestStoppedByProbeKeepsErrorsTheStopDidNotCause(t *testing.T) {
	live := context.Background()
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	canceledRequest := fmt.Errorf("httpx: GET /probe: %w", context.Canceled)

	require.True(t, stoppedByProbe(stopped, canceledRequest))
	require.False(t, stoppedByProbe(stopped, errors.New("connection reset by peer")),
		"an error the stop did not cause is recorded, even after the stop")
	require.False(t, stoppedByProbe(live, canceledRequest), "a running probe records every error")
	require.False(t, stoppedByProbe(stopped, nil))
}

func TestStoppingAProbeMidResponseRecordsNoFailure(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"headers":`))
		w.(http.Flusher).Flush()
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done() // hold the body open until the client goes away
	}))
	t.Cleanup(server.Close)
	steps := newSteps(fakeBase{url: server.URL})
	ctx := newScenarioContext()
	t.Cleanup(func() { stopAllBackgroundRequests(ctx) })

	require.NoError(t, steps.startBackgroundRequests(ctx, "GET", "/probe", "traffic"))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the probe sent no request")
	}
	require.NoError(t, steps.stopBackgroundRequests(ctx, "traffic"))
	probe, err := namedBackgroundProbe(ctx, "traffic")
	require.NoError(t, err)
	require.Empty(t, probe.snapshot(), "a body read cut short by the stop is not a gateway failure")
}

func TestBackgroundRequestsEventuallyEchoFindsAValueOfAStoppedProbe(t *testing.T) {
	steps := newSteps(fakeBase{url: "http://unused"})
	ctx := newScenarioContext()
	stoppedProbe(t, ctx, "stopped", "v3.example")

	require.NoError(t, steps.backgroundRequestsEventuallyEcho(ctx, "stopped", "v3.example", "headers.Host"))
	err := steps.backgroundRequestsEventuallyEcho(ctx, "stopped", "v9.example", "headers.Host")
	require.ErrorContains(t, err, `never echoed headers.Host "v9.example"; values seen: v3.example`)
}

func TestFirstEchoIgnoresFailedResponses(t *testing.T) {
	responses := []backgroundResponse{
		{status: 503, body: hostBody("v3.example")}, {err: "boom"},
		{status: 200, body: hostBody("v1.example")}, {status: 200, body: hostBody("v3.example")},
	}
	require.Equal(t, 2, firstEcho(responses, "headers.Host", "v1.example"))
	require.Equal(t, 3, firstEcho(responses, "headers.Host", "v3.example"))
	require.Equal(t, -1, firstEcho(responses, "headers.Host", "v9.example"))
}

// stoppedProbe registers, under name, a stopped probe that recorded the given hosts in order.
func stoppedProbe(t *testing.T, ctx context.Context, name string, hosts ...string) {
	t.Helper()
	probes, err := backgroundProbes(ctx)
	require.NoError(t, err)
	done := make(chan struct{})
	close(done)
	probe := &backgroundProbe{cancel: func() {}, done: done}
	for _, host := range hosts {
		probe.record(backgroundResponse{status: 200, body: hostBody(host)})
	}
	probes[name] = probe
}

func TestAnswerDuringRolloutPassesWhenARequestIsAnsweredBeforeTheNewValue(t *testing.T) {
	var calls atomic.Int32
	server := echoServer(t, func(string) string {
		if calls.Add(1) > 5 {
			return "v3.example"
		}
		return "v1.example"
	})
	steps := newSteps(fakeBase{url: server.URL})
	ctx := newScenarioContext()
	t.Cleanup(func() { stopAllBackgroundRequests(ctx) })

	require.NoError(t, steps.startBackgroundRequests(ctx, "GET", "/probe", "traffic"))
	require.NoError(t, steps.backgroundRequestsEventuallyEcho(ctx, "traffic", "v1.example", "headers.Host"))
	// v3 appears only from the sixth response, so some responses come after the step begins and before it.
	require.NoError(t, steps.backgroundRequestsAnswerDuringRolloutThenEcho(ctx, "traffic", "v3.example", "headers.Host"))
}

func TestAnswerDuringRolloutFailsWhenTheNewValueWasAlreadyServed(t *testing.T) {
	steps := newSteps(fakeBase{url: "http://unused"})
	ctx := newScenarioContext()
	stoppedProbe(t, ctx, "traffic", "v1.example", "v3.example")

	err := steps.backgroundRequestsAnswerDuringRolloutThenEcho(ctx, "traffic", "v3.example", "headers.Host")
	require.ErrorContains(t, err, `no request of background requests "traffic" was answered before headers.Host "v3.example" took effect`)
	require.ErrorContains(t, err, "within one request interval")

	err = steps.backgroundRequestsAnswerDuringRolloutThenEcho(ctx, "traffic", "v9.example", "headers.Host")
	require.ErrorContains(t, err, `never echoed headers.Host "v9.example"`)
}

func TestAnswerDuringRolloutFailsWhenTheFirstNewResponseCarriesTheValue(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		host := "v1.example"
		if calls.Add(1) > 1 {
			<-release // hold the second request until the step has begun
			host = "v3.example"
		}
		_, _ = w.Write(hostBody(host))
	}))
	t.Cleanup(server.Close)
	steps := newSteps(fakeBase{url: server.URL})
	ctx := newScenarioContext()
	t.Cleanup(func() { stopAllBackgroundRequests(ctx) })

	require.NoError(t, steps.startBackgroundRequests(ctx, "GET", "/probe", "traffic"))
	require.NoError(t, steps.backgroundRequestsEventuallyEcho(ctx, "traffic", "v1.example", "headers.Host"))
	require.Eventually(t, func() bool { return calls.Load() >= 2 }, 5*time.Second, 10*time.Millisecond)
	go func() {
		time.Sleep(backgroundRequestInterval)
		close(release) // from here every response carries v3
	}()
	err := steps.backgroundRequestsAnswerDuringRolloutThenEcho(ctx, "traffic", "v3.example", "headers.Host")
	require.ErrorContains(t, err, "within one request interval")
}
