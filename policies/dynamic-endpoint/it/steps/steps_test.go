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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

type fakeBase struct {
	url     string
	headers map[string]string
}

func (f fakeBase) GatewayURL(path string) (string, error) { return f.url + path, nil }

func (f fakeBase) ScenarioHeaders(context.Context) map[string]string { return f.headers }

func (f fakeBase) RequestHost(context.Context) string { return "" }

func newScenarioContext() context.Context {
	return tcontext.WithLocal(context.Background(), tcontext.NewLocal("test-runner"))
}

func newStepsWithServer(t *testing.T, handler http.HandlerFunc) *Steps {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	steps := newSteps(fakeBase{url: server.URL})
	steps.client = httpx.NewClient(httpx.Options{Timeout: 5 * time.Second})
	steps.funnel = httpx.NewFunnel(steps.client, 0, 0)
	return steps
}

func table(t *testing.T, rows ...[]string) *godog.Table {
	t.Helper()
	type cell struct {
		Value string `json:"value"`
	}
	type row struct {
		Cells []cell `json:"cells"`
	}
	payload := struct {
		Rows []row `json:"rows"`
	}{}
	for _, values := range rows {
		r := row{}
		for _, v := range values {
			r.Cells = append(r.Cells, cell{Value: v})
		}
		payload.Rows = append(payload.Rows, r)
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	out := &godog.Table{}
	require.NoError(t, json.Unmarshal(raw, out))
	return out
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestJSONField(t *testing.T) {
	body := []byte(`{"path":"/a","status":201,"ok":true,"none":null,"nested":{"deep":"x"},"list":[1,2]}`)

	for field, want := range map[string]string{
		"path": "/a", "status": "201", "ok": "true", "none": "null", "nested.deep": "x", "list": "[1,2]",
	} {
		got, present := jsonField(body, field)
		require.True(t, present, field)
		require.Equal(t, want, got, field)
	}
	for _, field := range []string{"missing", "path.deeper", "nested.missing"} {
		_, present := jsonField(body, field)
		require.False(t, present, field)
	}
	_, present := jsonField([]byte(`not json`), "path")
	require.False(t, present)
}

func TestServedBy(t *testing.T) {
	steps := newSteps(fakeBase{})
	publish := func(body string) context.Context {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, body)
		}))
		t.Cleanup(server.Close)
		ctx := newScenarioContext()
		resp, err := steps.funnel.Send(ctx, httpx.Request{Method: http.MethodGet, URL: server.URL})
		require.NoError(t, err)
		require.NoError(t, steps.funnel.Publish(ctx, resp))
		return ctx
	}

	echo := publish(`{"method":"GET","url":"/x","args":{}}`)
	require.NoError(t, steps.servedBy(echo, "echo"))
	require.ErrorContains(t, steps.servedBy(echo, "backend"), "expected the backend service")

	backend := publish(`{"method":"GET","path":"/x"}`)
	require.NoError(t, steps.servedBy(backend, "backend"))
	require.ErrorContains(t, steps.servedBy(backend, "echo"), "expected the echo service")
}

func TestSplitURL(t *testing.T) {
	ctx := newScenarioContext()
	steps := newSteps(fakeBase{})

	require.NoError(t, steps.splitURL(ctx, "http://testbench:3010/dynamic-endpoint/", "origin", "basePath"))
	origin, _ := tcontext.Get(ctx, "origin")
	basePath, _ := tcontext.Get(ctx, "basePath")
	require.Equal(t, "http://testbench:3010", origin)
	require.Equal(t, "/dynamic-endpoint", basePath)

	require.ErrorContains(t, steps.splitURL(ctx, "http://testbench:3010", "o", "b"), "no path")
	require.ErrorContains(t, steps.splitURL(ctx, "/only/a/path", "o", "b"), "no scheme and host")
	require.ErrorContains(t, steps.splitURL(ctx, "http://h/p", " ", "b"), "must not be empty")
}

func TestSendUntilJSONFieldWaitsForTheValue(t *testing.T) {
	var calls atomic.Int32
	steps := newStepsWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			writeJSON(w, http.StatusOK, `{"path":"/old"}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"path":"/new"}`)
	})

	ctx := newScenarioContext()
	require.NoError(t, steps.sendUntilJSONField(ctx, "GET", "/probe", "path", "/new"))
	require.GreaterOrEqual(t, calls.Load(), int32(3))
	resp, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Contains(t, string(resp.Body), "/new")
}

func TestSendConcurrentRoutesChecksEveryResponse(t *testing.T) {
	steps := newStepsWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"path":"`+r.URL.Path+`"}`)
	})
	ctx := newScenarioContext()

	require.NoError(t, steps.sendConcurrentRoutes(ctx, 40, table(t,
		[]string{"GET", "/a", "path", "/a"},
		[]string{"GET", "/b", "path", "/b"},
	)))
	require.NoError(t, steps.everyConcurrentRouteMatched(ctx))

	require.NoError(t, steps.sendConcurrentRoutes(ctx, 10, table(t,
		[]string{"GET", "/a", "path", "/leaked"},
	)))
	err := steps.everyConcurrentRouteMatched(ctx)
	require.ErrorContains(t, err, "10 of 10 concurrent responses did not match")
	require.ErrorContains(t, err, `field "path" is "/a", want "/leaked"`)
}

func TestSendConcurrentRoutesRejectsBadInput(t *testing.T) {
	steps := newSteps(fakeBase{})
	ctx := newScenarioContext()

	require.ErrorContains(t, steps.sendConcurrentRoutes(ctx, 0, table(t, []string{"GET", "/a", "path", "/a"})), "between 1 and")
	require.ErrorContains(t, steps.sendConcurrentRoutes(ctx, 1001, table(t, []string{"GET", "/a", "path", "/a"})), "between 1 and")
	require.ErrorContains(t, steps.sendConcurrentRoutes(ctx, 1, nil), "table")
	require.ErrorContains(t, steps.sendConcurrentRoutes(ctx, 1, table(t, []string{"GET", "/a"})), "four cells")
	require.ErrorContains(t, steps.everyConcurrentRouteMatched(newScenarioContext()), "no concurrent requests")
}

func TestDescribeMismatchesReportsStatusAndAbsentField(t *testing.T) {
	route := routeCase{method: "GET", path: "/a", field: "path", expected: "/a"}
	err := describeMismatches([]routeOutcome{
		{route: route, status: 503},
		{route: route, status: 200, present: false},
		{route: route, status: 200, present: true, got: "/a"},
	})
	require.ErrorContains(t, err, "2 of 3")
	require.ErrorContains(t, err, "status 503")
	require.ErrorContains(t, err, `JSON field "path" is absent`)
}

func TestCheckOnlyPrefixes(t *testing.T) {
	ok := trafficSample{status: 200, body: []byte(`{"path":"/aaa/x"}`)}
	other := trafficSample{status: 200, body: []byte(`{"path":"/bbb/x"}`)}
	failed := trafficSample{status: 503, body: []byte(`{"path":"/never/x"}`)}
	leaked := trafficSample{status: 200, body: []byte(`{"path":"/never/x"}`)}

	require.NoError(t, checkOnlyPrefixes("p", "path", []string{"/aaa", "/bbb"}, []trafficSample{ok, other, failed}))
	err := checkOnlyPrefixes("p", "path", []string{"/aaa", "/bbb"}, []trafficSample{ok, leaked})
	require.ErrorContains(t, err, `"/never/x"`)
	require.ErrorContains(t, checkOnlyPrefixes("p", "path", []string{"/aaa"},
		[]trafficSample{{status: 200, body: []byte(`{}`)}}), "without JSON field")
	// An empty prefix must not match everything.
	require.Error(t, checkOnlyPrefixes("p", "path", []string{""}, []trafficSample{ok}))
}

func TestBackgroundTrafficLifecycle(t *testing.T) {
	var hits atomic.Int32
	steps := newStepsWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writeJSON(w, http.StatusOK, `{"path":"/aaa/probe"}`)
	})
	ctx := newScenarioContext()

	require.NoError(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "probe"))
	require.ErrorContains(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "probe"), "already running")
	require.Eventually(t, func() bool { return hits.Load() >= 3 }, 5*time.Second, 20*time.Millisecond)
	require.NoError(t, steps.stopBackgroundTraffic(ctx, "probe"))

	require.NoError(t, steps.backgroundTrafficAtLeastAttempts(ctx, "probe", 3))
	require.NoError(t, steps.backgroundTrafficAtLeastSuccesses(ctx, "probe", 3))
	require.NoError(t, steps.backgroundTrafficOnlyPrefixes(ctx, "probe", "path", "/aaa, /bbb"))
	require.ErrorContains(t, steps.backgroundTrafficOnlyPrefixes(ctx, "probe", "path", "/bbb"), "starts with none")
	require.ErrorContains(t, steps.backgroundTrafficAtLeastAttempts(ctx, "probe", 100000), "want at least")
	require.ErrorContains(t, steps.stopBackgroundTraffic(ctx, "missing"), "no background traffic probe")

	steps.stopAllBackgroundTraffic(ctx)
	require.ErrorContains(t, steps.backgroundTrafficAtLeastAttempts(ctx, "probe", 1), "no background traffic probe")
}

func TestBackgroundTrafficKeepsScenarioHeadersFromTheStart(t *testing.T) {
	seen := make(chan string, 8)
	steps := newStepsWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("X-Probe"):
		default:
		}
		writeJSON(w, http.StatusOK, `{}`)
	})
	headers := map[string]string{"X-Probe": "start"}
	steps.base = fakeBase{url: steps.base.(fakeBase).url, headers: headers}
	ctx := newScenarioContext()

	require.NoError(t, steps.startBackgroundTraffic(ctx, "GET", "/probe", "probe"))
	headers["X-Probe"] = "changed"
	t.Cleanup(func() { steps.stopAllBackgroundTraffic(ctx) })

	select {
	case value := <-seen:
		require.Equal(t, "start", strings.TrimSpace(value))
	case <-time.After(5 * time.Second):
		t.Fatal("the probe sent no request")
	}
}

func TestFieldStartsWithIfPresent(t *testing.T) {
	steps := newSteps(fakeBase{})
	publish := func(status int, body string) context.Context {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, status, body)
		}))
		t.Cleanup(server.Close)
		ctx := newScenarioContext()
		resp, err := steps.funnel.Send(ctx, httpx.Request{Method: http.MethodGet, URL: server.URL})
		require.NoError(t, err)
		require.NoError(t, steps.funnel.Publish(ctx, resp))
		return ctx
	}

	require.NoError(t, steps.fieldStartsWithIfPresent(publish(200, `{"path":"/public/x"}`), "path", "/public/"))
	require.NoError(t, steps.fieldStartsWithIfPresent(publish(404, `{"error":"Not Found"}`), "path", "/public/"))
	require.NoError(t, steps.fieldStartsWithIfPresent(publish(200, `not json`), "path", "/public/"))

	// The attacker's own text echoed after the prefix is fine; a different prefix is not.
	require.NoError(t, steps.fieldStartsWithIfPresent(publish(200, `{"path":"/public/../../internal"}`), "path", "/public/"))
	err := steps.fieldStartsWithIfPresent(publish(200, `{"path":"/internal/probe"}`), "path", "/public/")
	require.ErrorContains(t, err, "does not start with")
}
