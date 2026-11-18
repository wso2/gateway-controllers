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

	"github.com/cucumber/godog"
	messages "github.com/cucumber/messages/go/v34"
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

func table(rows ...[2]string) *godog.Table {
	t := &godog.Table{}
	for _, row := range rows {
		t.Rows = append(t.Rows, &messages.PickleTableRow{Cells: []*messages.PickleTableCell{
			{Value: row[0]}, {Value: row[1]},
		}})
	}
	return t
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
	server := echoServer(t, func(path string) string {
		calls.Add(1)
		if path == "/a" {
			return "a.example"
		}
		return "b.example"
	})
	// The request host and scenario headers reach every request.
	server.Config.Handler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "client.example" && r.Header.Get("X-Test") == "1" {
				sawHost.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	}(server.Config.Handler)

	steps := newSteps(fakeBase{url: server.URL, headers: map[string]string{"X-Test": "1"}, host: "client.example"})
	err := steps.sendConcurrentAlternatingPaths(newScenarioContext(), 40, "get", "headers.Host",
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
	err := steps.sendConcurrentAlternatingPaths(newScenarioContext(), 20, "GET", "headers.Host",
		table([2]string{"/a", "a.example"}, [2]string{"/b", "b.example"}))
	require.ErrorContains(t, err, "1 of 20 concurrent requests")
	require.ErrorContains(t, err, `/b: headers.Host is "a.example", want "b.example"`)
}

func TestSendConcurrentAlternatingPathsRejectsBadInput(t *testing.T) {
	steps := newSteps(fakeBase{url: "http://unused"})
	ctx := newScenarioContext()
	rows := table([2]string{"/a", "a.example"})
	require.ErrorContains(t, steps.sendConcurrentAlternatingPaths(ctx, 0, "GET", "headers.Host", rows), "between 1 and")
	require.ErrorContains(t, steps.sendConcurrentAlternatingPaths(ctx, maxConcurrentRequests+1, "GET", "headers.Host", rows), "between 1 and")
	require.ErrorContains(t, steps.sendConcurrentAlternatingPaths(ctx, 1, "GET", " ", rows), "JSON field is required")
}

func TestSummarizeFailuresCapsTheReasons(t *testing.T) {
	require.NoError(t, summarizeFailures(3, []string{"", "", ""}))
	failures := []string{"r1", "", "r2", "r3", "r4", "r5", "r6", "r7"}
	err := summarizeFailures(len(failures), failures)
	require.ErrorContains(t, err, "7 of 8")
	require.NotContains(t, err.Error(), "r6")
}
