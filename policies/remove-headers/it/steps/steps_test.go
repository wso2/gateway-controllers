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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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

// echoServer returns the request headers as {"headers":{...}} after letting modify change them,
// standing in for the gateway in front of the echo backend.
func echoServer(t *testing.T, modify func(http.Header)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header.Clone()
		if modify != nil {
			modify(headers)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"headers": headers})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestConcurrentIdentifiedRequestsPassWhenTheHeaderIsRemoved(t *testing.T) {
	var withExtra, withHost atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "" {
			withExtra.Add(1)
		}
		if r.Host == "api.example" && r.Header.Get("X-Scenario") == "kept" {
			withHost.Add(1)
		}
		headers := r.Header.Clone()
		headers.Del("X-Internal-Token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"headers": headers})
	}))
	t.Cleanup(server.Close)

	ctx := newScenarioContext()
	require.NoError(t, tcontext.Set(ctx, "apiPath", "/api/v1/get"))
	steps := newSteps(fakeBase{url: server.URL, headers: map[string]string{"X-Scenario": "kept"}, host: "api.example"})

	require.NoError(t, steps.sendConcurrentIdentified(ctx, 10, "get", "${CTX:apiPath}", "X-Request-Id", "X-Internal-Token"))
	require.Equal(t, int32(5), withExtra.Load(), "every other request carries the extra header")
	require.Equal(t, int32(10), withHost.Load(), "every request carries the scenario's headers and host")
	require.NoError(t, everyRequestEchoedOwnIdentity(ctx, "X-Request-Id", "X-Internal-Token"))
	require.NoError(t, noResponseCarriesHeader(ctx, "X-Removed-Response"))
}

func TestConcurrentIdentifiedRequestsFailWhenTheHeaderReachesTheBackend(t *testing.T) {
	server := echoServer(t, nil)
	ctx := newScenarioContext()

	require.NoError(t, newSteps(fakeBase{url: server.URL}).sendConcurrentIdentified(
		ctx, 4, "GET", "/get", "X-Request-Id", "X-Internal-Token"))
	err := everyRequestEchoedOwnIdentity(ctx, "X-Request-Id", "X-Internal-Token")
	require.ErrorContains(t, err, "2 of 4 concurrent requests failed the check")
	require.ErrorContains(t, err, "the backend received X-Internal-Token")
}

func TestConcurrentIdentifiedRequestsFailWhenAnIdentityLeaks(t *testing.T) {
	// The fake gateway removes X-Internal-Token correctly but gives every request the first
	// request's X-Request-Id, as a leak between requests would.
	server := echoServer(t, func(headers http.Header) {
		headers.Del("X-Internal-Token")
		headers.Set("X-Request-Id", "request-1")
	})
	ctx := newScenarioContext()

	require.NoError(t, newSteps(fakeBase{url: server.URL}).sendConcurrentIdentified(
		ctx, 3, "GET", "/get", "X-Request-Id", "X-Internal-Token"))
	err := everyRequestEchoedOwnIdentity(ctx, "X-Request-Id", "X-Internal-Token")
	require.ErrorContains(t, err, "2 of 3 concurrent requests failed the check")
	require.ErrorContains(t, err, `request-2: the backend received X-Request-Id ["request-1"]`)
}

func TestConcurrentIdentifiedRequestsFailWhenTheIdentityHeaderIsMissing(t *testing.T) {
	server := echoServer(t, func(headers http.Header) { headers.Del("X-Internal-Token") })
	ctx := newScenarioContext()

	require.NoError(t, newSteps(fakeBase{url: server.URL}).sendConcurrentIdentified(
		ctx, 2, "GET", "/get", "X-Request-Id", "X-Internal-Token"))
	err := everyRequestEchoedOwnIdentity(ctx, "X-Correlation-Id", "X-Internal-Token")
	require.ErrorContains(t, err, "the backend received no X-Correlation-Id header")
}

func TestSendConcurrentIdentifiedStopsWhenTheScenarioIsCancelled(t *testing.T) {
	server := echoServer(t, nil)
	ctx, cancel := context.WithCancel(newScenarioContext())
	cancel()

	err := newSteps(fakeBase{url: server.URL}).sendConcurrentIdentified(
		ctx, 2*maxInFlight, "GET", "/get", "X-Request-Id", "X-Internal-Token")
	require.ErrorIs(t, err, context.Canceled)
}

func TestNoResponseCarriesHeaderReportsTheHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Removed-Response", "removed")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"headers":{}}`))
	}))
	t.Cleanup(server.Close)
	ctx := newScenarioContext()

	require.NoError(t, newSteps(fakeBase{url: server.URL}).sendConcurrentIdentified(
		ctx, 2, "GET", "/get", "X-Request-Id", "X-Internal-Token"))
	err := noResponseCarriesHeader(ctx, "X-Removed-Response")
	require.ErrorContains(t, err, "2 of 2 concurrent requests failed the check")
	require.ErrorContains(t, err, `response header X-Removed-Response is ["removed"]`)
}

func TestSendConcurrentIdentifiedRejectsInvalidInput(t *testing.T) {
	steps := newSteps(fakeBase{url: "http://127.0.0.1:1"})
	ctx := newScenarioContext()

	require.ErrorContains(t, steps.sendConcurrentIdentified(ctx, 0, "GET", "/get", "X-Request-Id", "X-Internal-Token"),
		"between 1 and 1000")
	require.ErrorContains(t, steps.sendConcurrentIdentified(ctx, 1001, "GET", "/get", "X-Request-Id", "X-Internal-Token"),
		"between 1 and 1000")
	require.ErrorContains(t, steps.sendConcurrentIdentified(ctx, 2, "GET", "/get", " ", "X-Internal-Token"),
		"need a name")
	require.ErrorContains(t, steps.sendConcurrentIdentified(ctx, 2, "GET", "/get", "X-Request-Id", "x-request-id"),
		"must differ")
}

func TestAssertionsRequireAConcurrentSend(t *testing.T) {
	ctx := newScenarioContext()
	require.ErrorContains(t, everyRequestEchoedOwnIdentity(ctx, "X-Request-Id", "X-Internal-Token"),
		"no concurrent requests have been sent")
	require.ErrorContains(t, noResponseCarriesHeader(ctx, "X-Removed-Response"),
		"no concurrent requests have been sent")
}

func TestCheckEchoedIdentity(t *testing.T) {
	ok := concurrentResult{identity: "request-1", response: &httpx.Response{
		StatusCode: 200, Body: []byte(`{"headers":{"X-Request-Id":["request-1"]}}`),
	}}
	require.Empty(t, checkEchoedIdentity(ok, "x-request-id", "X-Internal-Token"))

	failed := concurrentResult{identity: "request-2", err: errors.New("connection reset")}
	require.Contains(t, checkEchoedIdentity(failed, "X-Request-Id", "X-Internal-Token"), "request failed")

	require.Contains(t, checkEchoedIdentity(concurrentResult{identity: "request-3"}, "X-Request-Id", "X-Internal-Token"),
		"no response")

	rejected := concurrentResult{identity: "request-4", response: &httpx.Response{StatusCode: 503}}
	require.Contains(t, checkEchoedIdentity(rejected, "X-Request-Id", "X-Internal-Token"), "status 503")

	notEcho := concurrentResult{identity: "request-5", response: &httpx.Response{StatusCode: 200, Body: []byte("plain")}}
	require.Contains(t, checkEchoedIdentity(notEcho, "X-Request-Id", "X-Internal-Token"), "not an echo")

	noHeaders := concurrentResult{identity: "request-6", response: &httpx.Response{StatusCode: 200, Body: []byte(`{}`)}}
	require.Contains(t, checkEchoedIdentity(noHeaders, "X-Request-Id", "X-Internal-Token"), "no echoed headers")

	duplicated := concurrentResult{identity: "request-7", response: &httpx.Response{
		StatusCode: 200, Body: []byte(`{"headers":{"X-Request-Id":["request-7","request-8"]}}`),
	}}
	require.Contains(t, checkEchoedIdentity(duplicated, "X-Request-Id", "X-Internal-Token"),
		`["request-7" "request-8"]`)
}
