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
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	// requestTimeout bounds each concurrent request.
	requestTimeout = 30 * time.Second
	// maxConcurrentRequests caps the request count one step may send.
	maxConcurrentRequests = 1000
	// maxInFlight keeps a large request count from exhausting local connections.
	maxInFlight = 25
	// maxReportedMismatches keeps a failure message readable.
	maxReportedMismatches = 5
)

// requestBase is the part of the shared steps' base these steps use.
type requestBase interface {
	GatewayURL(path string) (string, error)
	ScenarioHeaders(ctx context.Context) map[string]string
	RequestHost(ctx context.Context) string
}

// Steps holds the host-rewrite policy's own steps.
type Steps struct {
	base   requestBase
	client *httpx.Client
}

func newSteps(base requestBase) *Steps {
	return &Steps{base: base, client: httpx.NewClient(httpx.Options{Timeout: requestTimeout})}
}

func (s *Steps) register(sc *godog.ScenarioContext) {
	sc.Step(`^I send (\d+) concurrent "([^"]*)" requests alternating between these paths, each echoing the JSON field "([^"]*)":$`,
		s.sendConcurrentAlternatingPaths)
	s.registerBackgroundRequests(sc)
}

// pathExpectation is one table row: a data-plane path and the value its response must echo.
type pathExpectation struct {
	path string
	want string
}

func pathExpectations(ctx context.Context, table *godog.Table) ([]pathExpectation, error) {
	if table == nil || len(table.Rows) == 0 {
		return nil, fmt.Errorf("a table of paths and expected values is required")
	}
	rows := make([]pathExpectation, 0, len(table.Rows))
	for i, row := range table.Rows {
		if row == nil || len(row.Cells) != 2 {
			return nil, fmt.Errorf("table row %d must contain exactly two cells", i+1)
		}
		path, err := stepscommon.Expand(ctx, strings.TrimSpace(row.Cells[0].Value))
		if err != nil {
			return nil, err
		}
		want, err := stepscommon.Expand(ctx, strings.TrimSpace(row.Cells[1].Value))
		if err != nil {
			return nil, err
		}
		if path == "" {
			return nil, fmt.Errorf("table row %d has an empty path", i+1)
		}
		rows = append(rows, pathExpectation{path: path, want: want})
	}
	return rows, nil
}

// sendConcurrentAlternatingPaths sends n requests at once, request i (0-based) to the path of
// table row i mod rows, with the scenario's headers and request host. Every response must be
// 2xx and carry, at the dotted JSON field, the value of its own row. A response that echoes
// another row's value shows one request's configuration reaching another.
func (s *Steps) sendConcurrentAlternatingPaths(
	ctx context.Context, n int, method, field string, table *godog.Table,
) error {
	if n <= 0 || n > maxConcurrentRequests {
		return fmt.Errorf("the concurrent request count must be between 1 and %d, got %d", maxConcurrentRequests, n)
	}
	field = strings.TrimSpace(field)
	if field == "" {
		return fmt.Errorf("a JSON field is required")
	}
	rows, err := pathExpectations(ctx, table)
	if err != nil {
		return err
	}
	targets := make([]string, len(rows))
	for i, row := range rows {
		if targets[i], err = s.base.GatewayURL(row.path); err != nil {
			return err
		}
	}
	method = strings.ToUpper(method)
	headers := s.base.ScenarioHeaders(ctx)
	host := s.base.RequestHost(ctx)

	failures := make([]string, n)
	sem := make(chan struct{}, min(n, maxInFlight))
	var wg sync.WaitGroup
	for i := range n {
		row, target := rows[i%len(rows)], targets[i%len(rows)]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, requestErr := s.client.Do(ctx, httpx.Request{
				Method: method, URL: target, Headers: copyHeaders(headers), Host: host,
			}, 0, 0)
			failures[i] = checkEchoedField(resp, requestErr, field, row)
		}()
	}
	wg.Wait()
	return summarizeFailures(n, failures)
}

func copyHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[name] = value
	}
	return out
}

// checkEchoedField returns "" when the response is 2xx and its JSON field holds the row's
// value, and a short description of the mismatch otherwise.
func checkEchoedField(resp *httpx.Response, requestErr error, field string, row pathExpectation) string {
	if requestErr != nil {
		return fmt.Sprintf("%s: request failed: %v", row.path, requestErr)
	}
	if resp == nil {
		return fmt.Sprintf("%s: no response", row.path)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Sprintf("%s: status %d", row.path, resp.StatusCode)
	}
	got, err := jsonField(resp.Body, field)
	if err != nil {
		return fmt.Sprintf("%s: %v", row.path, err)
	}
	if got != row.want {
		return fmt.Sprintf("%s: %s is %q, want %q", row.path, field, got, row.want)
	}
	return ""
}

// jsonField reads a dotted field (headers.Host) from a JSON object body as text.
func jsonField(body []byte, field string) (string, error) {
	var current any
	if err := json.Unmarshal(body, &current); err != nil {
		return "", fmt.Errorf("response is not JSON: %w", err)
	}
	for _, key := range strings.Split(field, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return "", fmt.Errorf("field %q: %q is not inside an object", field, key)
		}
		if current, ok = object[key]; !ok {
			return "", fmt.Errorf("field %q is missing", field)
		}
	}
	if text, ok := current.(string); ok {
		return text, nil
	}
	return fmt.Sprintf("%v", current), nil
}

// summarizeFailures reports how many of n requests failed and the first few reasons.
func summarizeFailures(n int, failures []string) error {
	var reasons []string
	count := 0
	for _, failure := range failures {
		if failure == "" {
			continue
		}
		count++
		if len(reasons) < maxReportedMismatches {
			reasons = append(reasons, failure)
		}
	}
	if count == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d concurrent requests did not echo their expected value: %s",
		count, n, strings.Join(reasons, "; "))
}
