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
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

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
	// keyConcurrentResults holds the outcomes of the latest concurrent send in the scenario.
	keyConcurrentResults = "removeHeadersConcurrentResults"
)

// requestBase is the part of the shared steps' base these steps use.
type requestBase interface {
	GatewayURL(path string) (string, error)
	ScenarioHeaders(ctx context.Context) map[string]string
	RequestHost(ctx context.Context) string
}

// Steps holds the remove-headers policy's own steps.
type Steps struct {
	base   requestBase
	client *httpx.Client
}

func newSteps(base requestBase) *Steps {
	return &Steps{base: base, client: httpx.NewClient(httpx.Options{Timeout: requestTimeout})}
}

func (s *Steps) register(sc *godog.ScenarioContext) {
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		tcontext.Remove(ctx, keyConcurrentResults)
		return ctx, nil
	})
	sc.Step(`^I send (\d+) concurrent "([^"]*)" requests to "([^"]*)" identified by the "([^"]*)" header, every other one also carrying the "([^"]*)" header$`,
		s.sendConcurrentIdentified)
	sc.Step(`^every concurrent request should reach the backend with its own "([^"]*)" header and without the "([^"]*)" header$`,
		everyRequestEchoedOwnIdentity)
	sc.Step(`^no concurrent response should carry the "([^"]*)" header$`, noResponseCarriesHeader)
}

// concurrentResult is the outcome of one concurrent request.
type concurrentResult struct {
	// identity is the value the request sent in its identifying header.
	identity string
	response *httpx.Response
	err      error
}

// sendConcurrentIdentified sends n requests at once. Request i (1-based) carries the identity
// header with the value "request-<i>", and each odd-numbered request also carries the extra
// header with the value "secret-<i>", so requests with different header combinations are in
// flight together. The scenario's headers and request host apply to each request. The outcomes
// are kept for the assertion steps; none is published, so a later response assertion cannot
// read an arbitrary one of them.
func (s *Steps) sendConcurrentIdentified(
	ctx context.Context, n int, method, path, identityHeader, extraHeader string,
) error {
	if n <= 0 || n > maxConcurrentRequests {
		return fmt.Errorf("the concurrent request count must be between 1 and %d, got %d", maxConcurrentRequests, n)
	}
	identityHeader, extraHeader = strings.TrimSpace(identityHeader), strings.TrimSpace(extraHeader)
	if identityHeader == "" || extraHeader == "" {
		return fmt.Errorf("both the identifying header and the extra header need a name")
	}
	if strings.EqualFold(identityHeader, extraHeader) {
		return fmt.Errorf("the identifying header and the extra header must differ, both are %q", identityHeader)
	}
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	method = strings.ToUpper(method)
	scenarioHeaders := s.base.ScenarioHeaders(ctx)
	host := s.base.RequestHost(ctx)
	httpx.ClearPublished(ctx)

	results := make([]concurrentResult, n)
	sem := make(chan struct{}, min(n, maxInFlight))
	var wg sync.WaitGroup
	for i := range n {
		number := i + 1
		headers := copyHeaders(scenarioHeaders)
		identity := fmt.Sprintf("request-%d", number)
		headers[identityHeader] = identity
		if number%2 == 1 {
			headers[extraHeader] = fmt.Sprintf("secret-%d", number)
		}
		// Stop starting requests once the scenario is cancelled, also while waiting for a free slot.
		if err := ctx.Err(); err != nil {
			wg.Wait()
			return fmt.Errorf("sending concurrent requests: %w", err)
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return fmt.Errorf("sending concurrent requests: %w", ctx.Err())
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, requestErr := s.client.Do(ctx, httpx.Request{
				Method: method, URL: target, Headers: headers, Host: host,
			}, 0, 0)
			results[i] = concurrentResult{identity: identity, response: resp, err: requestErr}
		}()
	}
	wg.Wait()
	return tcontext.Set(ctx, keyConcurrentResults, results)
}

// everyRequestEchoedOwnIdentity checks that every concurrent request succeeded, reached the
// backend with its own identity value, and reached it without the removed header. A request that
// echoes another request's identity shows headers leaking between requests.
func everyRequestEchoedOwnIdentity(ctx context.Context, identityHeader, removedHeader string) error {
	results, err := concurrentResults(ctx)
	if err != nil {
		return err
	}
	failures := make([]string, len(results))
	for i, result := range results {
		failures[i] = checkEchoedIdentity(result, identityHeader, removedHeader)
	}
	return summarizeFailures(len(results), failures)
}

// noResponseCarriesHeader checks that no concurrent response reached the client with the header.
func noResponseCarriesHeader(ctx context.Context, name string) error {
	results, err := concurrentResults(ctx)
	if err != nil {
		return err
	}
	failures := make([]string, len(results))
	for i, result := range results {
		if result.response == nil {
			failures[i] = fmt.Sprintf("%s: no response", result.identity)
			continue
		}
		if values := result.response.Headers.Values(name); len(values) > 0 {
			failures[i] = fmt.Sprintf("%s: response header %s is %q", result.identity, name, values)
		}
	}
	return summarizeFailures(len(results), failures)
}

func concurrentResults(ctx context.Context) ([]concurrentResult, error) {
	stored, ok := tcontext.Get(ctx, keyConcurrentResults)
	if !ok {
		return nil, fmt.Errorf("no concurrent requests have been sent in this scenario")
	}
	results, ok := stored.([]concurrentResult)
	if !ok {
		return nil, fmt.Errorf("the stored concurrent results are %T, not []concurrentResult", stored)
	}
	return results, nil
}

// checkEchoedIdentity returns "" when the response is 2xx, echoes the request's own identity
// value and does not echo the removed header, and a short description of the mismatch otherwise.
func checkEchoedIdentity(result concurrentResult, identityHeader, removedHeader string) string {
	if result.err != nil {
		return fmt.Sprintf("%s: request failed: %v", result.identity, result.err)
	}
	if result.response == nil {
		return fmt.Sprintf("%s: no response", result.identity)
	}
	if result.response.StatusCode < 200 || result.response.StatusCode >= 300 {
		return fmt.Sprintf("%s: status %d", result.identity, result.response.StatusCode)
	}
	echoed, err := echoedHeaders(result.response.Body)
	if err != nil {
		return fmt.Sprintf("%s: %v", result.identity, err)
	}
	if values, found := lookupHeader(echoed, removedHeader); found {
		return fmt.Sprintf("%s: the backend received %s %q", result.identity, removedHeader, values)
	}
	values, found := lookupHeader(echoed, identityHeader)
	if !found {
		return fmt.Sprintf("%s: the backend received no %s header", result.identity, identityHeader)
	}
	if len(values) != 1 || values[0] != result.identity {
		return fmt.Sprintf("%s: the backend received %s %q", result.identity, identityHeader, values)
	}
	return ""
}

// echoedHeaders reads the request headers the echo backend returns as {"headers":{name:[values]}}.
func echoedHeaders(body []byte) (map[string][]string, error) {
	var echo struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(body, &echo); err != nil {
		return nil, fmt.Errorf("the response is not an echo of the request: %w", err)
	}
	if echo.Headers == nil {
		return nil, fmt.Errorf("the response carries no echoed headers")
	}
	return echo.Headers, nil
}

// lookupHeader finds a header case-insensitively, as HTTP requires.
func lookupHeader(headers map[string][]string, name string) ([]string, bool) {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}

// copyHeaders returns a copy of headers with room for the identity and extra headers a request
// adds to it.
func copyHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers)+2)
	for name, value := range headers {
		out[name] = value
	}
	return out
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
	return fmt.Errorf("%d of %d concurrent requests failed the check: %s", count, n, strings.Join(reasons, "; "))
}
