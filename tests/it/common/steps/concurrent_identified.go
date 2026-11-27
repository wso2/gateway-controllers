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
	"fmt"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	// keyConcurrentIdentified holds the outcomes of the latest identified concurrent send.
	keyConcurrentIdentified = "concurrentIdentifiedResults"
	// maxReportedConcurrentFailures keeps a failure message readable.
	maxReportedConcurrentFailures = 5
)

// identifiedRequestBase is the part of the shared base the identified concurrent steps use.
type identifiedRequestBase interface {
	GatewayURL(path string) (string, error)
	ScenarioHeaders(ctx context.Context) map[string]string
	RequestHost(ctx context.Context) string
}

// concurrentIdentifiedSteps sends concurrent requests that each carry their own identity, and
// checks what reached the backend and the client per request, so headers that leak between
// requests in flight together fail the check.
type concurrentIdentifiedSteps struct {
	base   identifiedRequestBase
	client *httpx.Client
}

func newConcurrentIdentifiedSteps(base identifiedRequestBase, client *httpx.Client) *concurrentIdentifiedSteps {
	return &concurrentIdentifiedSteps{base: base, client: client}
}

func (s *concurrentIdentifiedSteps) register(sc *godog.ScenarioContext) {
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		tcontext.Remove(ctx, keyConcurrentIdentified)
		return ctx, nil
	})
	sc.Step(`^I send (\d+) concurrent "([^"]*)" requests to "([^"]*)" identified by the "([^"]*)" header, every other one also carrying the "([^"]*)" header$`,
		s.sendConcurrentIdentified)
	sc.Step(`^every concurrent request should reach the backend with its own "([^"]*)" header and without the "([^"]*)" header$`,
		everyRequestEchoedOwnIdentityWithout)
	sc.Step(`^every concurrent request should reach the backend with its own "([^"]*)" header and the "([^"]*)" header set to "([^"]*)"$`,
		everyRequestEchoedOwnIdentityWith)
	sc.Step(`^no concurrent response should carry the "([^"]*)" header$`, noConcurrentResponseCarriesHeader)
	sc.Step(`^every concurrent response should carry the "([^"]*)" header with value "([^"]*)"$`,
		everyConcurrentResponseCarriesHeader)
}

// identifiedResult is the outcome of one identified concurrent request.
type identifiedResult struct {
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
func (s *concurrentIdentifiedSteps) sendConcurrentIdentified(
	ctx context.Context, n int, method, path, identityHeader, extraHeader string,
) error {
	if n <= 0 || n > maxConcurrentSendRequests {
		return fmt.Errorf("the concurrent request count must be between 1 and %d, got %d", maxConcurrentSendRequests, n)
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

	results := make([]identifiedResult, n)
	sem := make(chan struct{}, min(n, maxConcurrentSendInFlight))
	var wg sync.WaitGroup
	for i := range n {
		number := i + 1
		headers := withRequestHeaders(scenarioHeaders)
		identity := fmt.Sprintf("request-%d", number)
		setRequestHeader(headers, identityHeader, identity)
		if number%2 == 1 {
			setRequestHeader(headers, extraHeader, fmt.Sprintf("secret-%d", number))
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
			results[i] = identifiedResult{identity: identity, response: resp, err: requestErr}
		}()
	}
	wg.Wait()
	return tcontext.Set(ctx, keyConcurrentIdentified, results)
}

// everyRequestEchoedOwnIdentityWithout checks that every concurrent request succeeded and reached
// the backend with its own identity value and without the named header.
func everyRequestEchoedOwnIdentityWithout(ctx context.Context, identityHeader, absentHeader string) error {
	return checkEveryIdentifiedResult(ctx, func(result identifiedResult) string {
		return checkEchoedIdentity(result, identityHeader, func(echoed map[string]any) string {
			if value, found := lookupEchoed(echoed, absentHeader); found {
				return fmt.Sprintf("the backend received %s %v", absentHeader, value)
			}
			return ""
		})
	})
}

// everyRequestEchoedOwnIdentityWith checks that every concurrent request succeeded and reached the
// backend with its own identity value and with the named header holding exactly the given value,
// whatever value the request itself carried.
func everyRequestEchoedOwnIdentityWith(ctx context.Context, identityHeader, header, want string) error {
	resolved, err := stepscommon.Expand(ctx, want)
	if err != nil {
		return err
	}
	return checkEveryIdentifiedResult(ctx, func(result identifiedResult) string {
		return checkEchoedIdentity(result, identityHeader, func(echoed map[string]any) string {
			value, found := lookupEchoed(echoed, header)
			if !found {
				return fmt.Sprintf("the backend received no %s header", header)
			}
			values, ok := echoedStrings(value)
			if !ok || len(values) != 1 || values[0] != resolved {
				return fmt.Sprintf("the backend received %s %v, want %q", header, value, resolved)
			}
			return ""
		})
	})
}

// noConcurrentResponseCarriesHeader checks that no concurrent response reached the client with
// the header.
func noConcurrentResponseCarriesHeader(ctx context.Context, name string) error {
	return checkEveryIdentifiedResult(ctx, func(result identifiedResult) string {
		if result.response == nil {
			return fmt.Sprintf("%s: no response", result.identity)
		}
		if values := result.response.Headers.Values(name); len(values) > 0 {
			return fmt.Sprintf("%s: response header %s is %q", result.identity, name, values)
		}
		return ""
	})
}

// everyConcurrentResponseCarriesHeader checks that every concurrent response reached the client
// with the header holding exactly the given value.
func everyConcurrentResponseCarriesHeader(ctx context.Context, name, want string) error {
	resolved, err := stepscommon.Expand(ctx, want)
	if err != nil {
		return err
	}
	return checkEveryIdentifiedResult(ctx, func(result identifiedResult) string {
		if result.response == nil {
			return fmt.Sprintf("%s: no response", result.identity)
		}
		if values := result.response.Headers.Values(name); len(values) != 1 || values[0] != resolved {
			return fmt.Sprintf("%s: response header %s is %q, want %q", result.identity, name, values, resolved)
		}
		return ""
	})
}

// checkEveryIdentifiedResult applies check to every stored result and reports how many failed.
func checkEveryIdentifiedResult(ctx context.Context, check func(identifiedResult) string) error {
	stored, ok := tcontext.Get(ctx, keyConcurrentIdentified)
	if !ok {
		return fmt.Errorf("no concurrent requests have been sent in this scenario")
	}
	results, ok := stored.([]identifiedResult)
	if !ok {
		return fmt.Errorf("the stored concurrent results are %T, not []identifiedResult", stored)
	}
	var reasons []string
	failed := 0
	for _, result := range results {
		reason := check(result)
		if reason == "" {
			continue
		}
		failed++
		if len(reasons) < maxReportedConcurrentFailures {
			reasons = append(reasons, reason)
		}
	}
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d concurrent requests failed the check: %s", failed, len(results), strings.Join(reasons, "; "))
}

// checkEchoedIdentity returns "" when the response is 2xx, echoes the request's own identity value
// and passes checkHeader, and a short description of the mismatch otherwise.
func checkEchoedIdentity(result identifiedResult, identityHeader string, checkHeader func(map[string]any) string) string {
	if result.err != nil {
		return fmt.Sprintf("%s: request failed: %v", result.identity, result.err)
	}
	if result.response == nil {
		return fmt.Sprintf("%s: no response", result.identity)
	}
	if !result.response.Succeeded() {
		return fmt.Sprintf("%s: status %d", result.identity, result.response.StatusCode)
	}
	echoed, err := echoedHeaders(result.response)
	if err != nil {
		return fmt.Sprintf("%s: %v", result.identity, err)
	}
	if reason := checkHeader(echoed); reason != "" {
		return fmt.Sprintf("%s: %s", result.identity, reason)
	}
	value, found := lookupEchoed(echoed, identityHeader)
	if !found {
		return fmt.Sprintf("%s: the backend received no %s header", result.identity, identityHeader)
	}
	if values, ok := echoedStrings(value); !ok || len(values) != 1 || values[0] != result.identity {
		return fmt.Sprintf("%s: the backend received %s %v", result.identity, identityHeader, value)
	}
	return ""
}

// withRequestHeaders returns a copy of the scenario's headers with room for the identity and
// extra headers a request adds to it.
func withRequestHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers)+2)
	for name, value := range headers {
		out[name] = value
	}
	return out
}

// setRequestHeader sets name to value, first removing every header whose name differs only in
// case. The HTTP client canonicalizes names, so a scenario's "x-request-id" and the step's
// "X-Request-Id" would otherwise become one header holding whichever value map order wrote last.
func setRequestHeader(headers map[string]string, name, value string) {
	for existing := range headers {
		if strings.EqualFold(existing, name) {
			delete(headers, existing)
		}
	}
	headers[name] = value
}
