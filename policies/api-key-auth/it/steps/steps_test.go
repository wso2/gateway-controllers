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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/components"
	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
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

func topologyAt(t *testing.T, addr net.Addr) *frameworkruntime.Topology {
	t.Helper()
	port := addr.(*net.TCPAddr).Port
	definition := &components.Definition{
		Name: "platform-gateway", Alias: "platform-gateway",
		Endpoints: []components.Endpoint{{Name: "http", Port: port, Scheme: "http"}},
	}
	instance, err := components.NewInstance(definition, 0, 1, "127.0.0.1", map[int]int{port: port})
	require.NoError(t, err)
	instances := components.NewSet()
	require.NoError(t, instances.Add(instance))
	return &frameworkruntime.Topology{Instances: instances}
}

func newStepsWithServer(t *testing.T, handler http.HandlerFunc) *Steps {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	steps := newSteps(fakeBase{url: server.URL}, topologyAt(t, server.Listener.Addr()))
	steps.funnel = httpx.NewFunnel(httpx.NewClient(httpx.Options{Timeout: 5 * time.Second}), 0, 0)
	return steps
}

func cells(pairs ...[2]string) [][2]string { return pairs }

func TestGenerateSizedValueExactLength(t *testing.T) {
	ctx := newScenarioContext()
	steps := &Steps{}

	require.NoError(t, steps.generateSizedValue(ctx, 10, "ab", "divides"))
	divides, ok := tcontext.Get(ctx, "divides")
	require.True(t, ok)
	require.Equal(t, "ababababab", divides)

	require.NoError(t, steps.generateSizedValue(ctx, 7, "abc", "notDivides"))
	notDivides, _ := tcontext.Get(ctx, "notDivides")
	require.Equal(t, "abcabca", notDivides)

	require.NoError(t, steps.generateSizedValue(ctx, 1, "x", "single"))
	single, _ := tcontext.Get(ctx, "single")
	require.Equal(t, "x", single)
}

func TestIsConnectionRejection(t *testing.T) {
	require.True(t, isConnectionRejection(io.EOF))
	require.True(t, isConnectionRejection(io.ErrUnexpectedEOF))
	require.True(t, isConnectionRejection(fmt.Errorf("wrapped: %w", io.EOF)))
	require.True(t, isConnectionRejection(errors.New("read tcp 127.0.0.1:1234: connection reset by peer")))
	require.False(t, isConnectionRejection(context.DeadlineExceeded))
	require.False(t, isConnectionRejection(errors.New("no such host")))
}

func TestSendRequestExpectingRejectionAcceptsAnAbruptConnectionClose(t *testing.T) {
	steps := newStepsWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, _, err := hijacker.Hijack()
		require.NoError(t, err)
		_ = conn.Close()
	})
	require.NoError(t, steps.sendRequestExpectingRejection(newScenarioContext(), "GET", "/probe"))
}

func TestSendRequestExpectingRejectionFailsOnSuccess(t *testing.T) {
	steps := newStepsWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	err := steps.sendRequestExpectingRejection(newScenarioContext(), "GET", "/probe")
	require.ErrorContains(t, err, "expected the gateway to reject the request")
}

func TestSendRequestExpectingRejectionFailsOnATimeout(t *testing.T) {
	release := make(chan struct{})
	// Must close before the server's cleanup, which waits for in-flight handlers.
	defer close(release)
	steps := newStepsWithServer(t, func(http.ResponseWriter, *http.Request) { <-release })
	steps.funnel = httpx.NewFunnel(httpx.NewClient(httpx.Options{Timeout: 50 * time.Millisecond}), 0, 0)

	err := steps.sendRequestExpectingRejection(newScenarioContext(), "GET", "/probe")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "expected the gateway to reject the request")
}

func TestSendRequestOverHTTP2PublishesTheHTTP2Response(t *testing.T) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Key", r.Header.Get("API-Key"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	server.Config.Protocols = &protocols
	server.Start()
	t.Cleanup(server.Close)

	steps := newSteps(fakeBase{url: server.URL, headers: map[string]string{"API-Key": "k1"}}, nil)
	ctx := newScenarioContext()

	require.NoError(t, steps.sendRequestOverHTTP2(ctx, "get", "/probe"))
	resp, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "k1", resp.Headers.Get("X-Seen-Key"))
}

func TestSendRequestOverHTTP2RejectsAServerThatDoesNotSpeakHTTP2(t *testing.T) {
	steps := newStepsWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	err := steps.sendRequestOverHTTP2(newScenarioContext(), "GET", "/probe")
	require.ErrorContains(t, err, "HTTP/2")
}

func TestSendRawRequestKeepsHeaderOrderCasingAndDuplicates(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			request.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		received <- request.String()
		_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
	}()

	steps := newSteps(fakeBase{host: "api.example.com"}, topologyAt(t, listener.Addr()))
	steps.funnel = httpx.NewFunnel(httpx.NewClient(httpx.Options{Timeout: 5 * time.Second}), 0, 0)
	ctx := newScenarioContext()

	require.NoError(t, steps.sendRawRequest(ctx, "get", "ctx/probe", cells(
		[2]string{"api-KEY", "first"},
		[2]string{"api-KEY", "second"},
		[2]string{"X-Tab", `a\tb`},
	)))

	require.Equal(t, "GET /ctx/probe HTTP/1.1\r\nHost: api.example.com\r\n"+
		"api-KEY: first\r\napi-KEY: second\r\nX-Tab: a\tb\r\nConnection: close\r\n\r\n", <-received)
	resp, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "no", string(resp.Body))
}

func TestDecodeRawHeaderValue(t *testing.T) {
	tests := map[string]struct {
		in, want string
	}{
		"tabs":                {`\t\t`, "\t\t"},
		"spaces untouched":    {"   ", "   "},
		"carriage return":     {`\r\n`, "\r\n"},
		"escaped byte":        {`\x20\x20\x20`, "   "},
		"escaped byte upper":  {`\x4A`, "J"},
		"literal backslash":   {`a\\b`, `a\b`},
		"mixed":               {`abc\x01def`, "abc\x01def"},
		"crlf injection":      {`abc\r\nX-Injected: yes`, "abc\r\nX-Injected: yes"},
		"trailing backslash":  {`abc\`, `abc\`},
		"unknown escape kept": {`a\zb`, `a\zb`},
		"truncated hex kept":  {`a\x2`, `a\x2`},
		"invalid hex kept":    {`a\xZZb`, `a\xZZb`},
		"empty":               {"", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tt.want, decodeRawHeaderValue(tt.in))
		})
	}
}

func TestRawHeaderLinesPreservesOrderAndDuplicates(t *testing.T) {
	headers, err := rawHeaderLines(context.Background(), cells(
		[2]string{"API-Key", "first"},
		[2]string{"API-Key", "second"},
		[2]string{"x-api-key", `\t`},
	))
	require.NoError(t, err)
	require.Equal(t, []rawHeader{
		{name: "API-Key", value: "first"},
		{name: "API-Key", value: "second"},
		{name: "x-api-key", value: "\t"},
	}, headers)
}

func TestRawHeaderLinesExpandsContextValues(t *testing.T) {
	ctx := newScenarioContext()
	require.NoError(t, tcontext.Set(ctx, "akaKey", "secret-value"))

	headers, err := rawHeaderLines(ctx, cells([2]string{"API-Key", "${CTX:akaKey}"}))
	require.NoError(t, err)
	require.Equal(t, []rawHeader{{name: "API-Key", value: "secret-value"}}, headers)
}

func TestRawHeaderLinesRejectsInvalidTables(t *testing.T) {
	_, err := rawHeaderLines(context.Background(), nil)
	require.Error(t, err, "empty table")

	_, err = rawHeaderLines(context.Background(), cells([2]string{"  ", "value"}))
	require.Error(t, err, "empty header name")
}

func TestConcurrentCyclingRowsParsesValuesAndAbsentMarker(t *testing.T) {
	ctx := newScenarioContext()
	require.NoError(t, tcontext.Set(ctx, "k1", "secret-value"))

	rows, err := concurrentCyclingRows(ctx, cells(
		[2]string{"${CTX:k1}", "200"},
		[2]string{"bad", "401"},
		[2]string{absentHeaderMarker, "401"},
	))
	require.NoError(t, err)
	require.Equal(t, []concurrentCyclingRow{
		{value: "secret-value", status: 200},
		{value: "bad", status: 401},
		{absent: true, status: 401},
	}, rows)
}

func TestSendConcurrentCyclingRequestsRecordsEachOutcome(t *testing.T) {
	var absent atomic.Int32
	steps := newStepsWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("API-Key") {
		case "good":
			w.WriteHeader(http.StatusOK)
		case "":
			absent.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	ctx := newScenarioContext()

	require.NoError(t, steps.sendConcurrentCycling(ctx, 30, "GET", "/probe", "API-Key", cells(
		[2]string{"good", "200"},
		[2]string{"bad", "401"},
		[2]string{absentHeaderMarker, "401"},
	)))
	require.NoError(t, steps.everyConcurrentResponseMatchesExpectedStatus(ctx))
	require.EqualValues(t, 10, absent.Load(), "every third request omits the header")

	require.Error(t, steps.sendConcurrentCycling(ctx, 0, "GET", "/probe", "API-Key", cells([2]string{"good", "200"})))
}

func TestEveryConcurrentResponseMatchesExpectedStatus(t *testing.T) {
	ctx := newScenarioContext()
	steps := &Steps{}

	require.Error(t, steps.everyConcurrentResponseMatchesExpectedStatus(ctx), "nothing was sent")

	require.NoError(t, tcontext.Set(ctx, keyConcurrentOutcomes, []concurrentCyclingOutcome{
		{row: concurrentCyclingRow{value: "k1", status: 200}, gotStatus: 200},
		{row: concurrentCyclingRow{absent: true, status: 401}, gotStatus: 401},
	}))
	require.NoError(t, steps.everyConcurrentResponseMatchesExpectedStatus(ctx))

	require.NoError(t, tcontext.Set(ctx, keyConcurrentOutcomes, []concurrentCyclingOutcome{
		{row: concurrentCyclingRow{value: "secret-key-value", status: 200}, gotStatus: 401},
		{row: concurrentCyclingRow{value: "k1", status: 200}, requestErr: errors.New("boom")},
	}))
	err := steps.everyConcurrentResponseMatchesExpectedStatus(ctx)
	require.ErrorContains(t, err, "want 200, got 401")
	require.ErrorContains(t, err, "transport error (boom)")
	require.NotContains(t, err.Error(), "secret-key-value", "a key is masked in the failure")
}

func TestBackgroundTrafficRecordsAndStops(t *testing.T) {
	var hits atomic.Int32
	steps := newStepsWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("API-Key") == "good" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	ctx := newScenarioContext()

	require.NoError(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "API-Key", "bad", "probe"))
	require.Error(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "API-Key", "bad", "probe"))

	require.Eventually(t, func() bool { return hits.Load() >= 3 }, 2*time.Second, 20*time.Millisecond)

	require.NoError(t, steps.stopBackgroundTraffic(ctx, "probe"))
	require.NoError(t, steps.backgroundTrafficAtLeastAttempts(ctx, "probe", 1))
	require.NoError(t, steps.backgroundTrafficNeverReceivedStatus(ctx, "probe", http.StatusOK))
	require.Error(t, steps.backgroundTrafficNeverReceivedStatus(ctx, "probe", http.StatusUnauthorized))
	require.Error(t, steps.backgroundTrafficAtLeastAttempts(ctx, "probe", 1000))
	require.Error(t, steps.stopBackgroundTraffic(ctx, "unknown"))
}

func TestStopAllBackgroundTrafficStopsEveryProbe(t *testing.T) {
	steps := newStepsWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ctx := newScenarioContext()

	require.NoError(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "X", "1", "a"))
	require.NoError(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "X", "1", "b"))
	running, err := steps.backgroundProbes(ctx)
	require.NoError(t, err)
	probes := make([]*backgroundTrafficProbe, 0, len(running))
	for _, probe := range running {
		probes = append(probes, probe)
	}
	require.Len(t, probes, 2)

	steps.stopAllBackgroundTraffic(ctx)

	for _, probe := range probes {
		select {
		case <-probe.done:
		default:
			t.Fatal("a probe did not stop")
		}
	}
	after, err := steps.backgroundProbes(ctx)
	require.NoError(t, err)
	require.Empty(t, after)
	require.NoError(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "X", "1", "a"))
	steps.stopAllBackgroundTraffic(ctx)
}

func TestRememberAndForgetStoppedProcess(t *testing.T) {
	ctx := newScenarioContext()
	steps := &Steps{}

	require.NoError(t, steps.rememberStoppedProcess(ctx, "gateway-runtime", "policy-engine"))
	list, err := steps.stoppedProcessList(ctx)
	require.NoError(t, err)
	require.Equal(t, []stoppedProcess{{service: "gateway-runtime", process: "policy-engine"}}, list)

	require.NoError(t, steps.rememberStoppedProcess(ctx, "gateway-runtime", "envoy"))
	list, err = steps.stoppedProcessList(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)

	require.NoError(t, steps.forgetStoppedProcess(ctx, "gateway-runtime", "policy-engine"))
	list, err = steps.stoppedProcessList(ctx)
	require.NoError(t, err)
	require.Equal(t, []stoppedProcess{{service: "gateway-runtime", process: "envoy"}}, list)

	require.NoError(t, steps.forgetStoppedProcess(ctx, "gateway-runtime", "never-stopped"))
	list, err = steps.stoppedProcessList(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func TestProcessSignalScriptTargetsTheCommandSuffixWithoutPkill(t *testing.T) {
	script := processSignalScript("STOP", "policy-engine")
	require.Contains(t, script, `grep -q '/policy-engine$'`)
	require.Contains(t, script, "kill -STOP")
	require.NotContains(t, script, "pkill")
	require.NotContains(t, script, "pgrep")
}

func TestResumeStoppedProcessesClearsTheList(t *testing.T) {
	ctx := newScenarioContext()
	steps := &Steps{topo: &frameworkruntime.Topology{}}

	require.NoError(t, steps.rememberStoppedProcess(ctx, "gateway-runtime", "policy-engine"))

	steps.resumeStoppedProcesses(ctx)

	list, err := steps.stoppedProcessList(ctx)
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestIsLastProjectValidation(t *testing.T) {
	retained := &httpx.Response{
		StatusCode: http.StatusBadRequest,
		Body:       []byte(`{"code":"VALIDATION_FAILED","message":"Organization must have at least one project"}`),
	}
	require.True(t, isLastProjectValidation(retained))

	require.False(t, isLastProjectValidation(nil))
	require.False(t, isLastProjectValidation(&httpx.Response{StatusCode: http.StatusNotFound, Body: retained.Body}))
	require.False(t, isLastProjectValidation(&httpx.Response{StatusCode: http.StatusBadRequest, Body: []byte(`{"code":"OTHER"}`)}))
	require.False(t, isLastProjectValidation(&httpx.Response{StatusCode: http.StatusBadRequest, Body: []byte("not json")}))
}
