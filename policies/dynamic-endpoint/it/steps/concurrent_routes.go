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
	"sort"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	keyConcurrentRouteOutcomes = "concurrentRouteOutcomes"

	maxConcurrentRouteRequests = 1000
	maxConcurrentRouteWorkers  = 20

	// maxReportedCauses keeps a failing run from printing one line per request.
	maxReportedCauses = 10
)

func (s *Steps) registerConcurrentRoutes(sc *godog.ScenarioContext) {
	sc.Step(`^I send (\d+) concurrent requests cycling through:$`, s.sendConcurrentRoutes)
	sc.Step(`^every concurrent response should have matched its expectation$`, s.everyConcurrentRouteMatched)
}

// routeCase is one row of the cycling table: a request, and the JSON field its response must
// carry.
type routeCase struct {
	method, path, field, expected string
}

type routeOutcome struct {
	route      routeCase
	status     int
	got        string
	present    bool
	requestErr error
}

func (o routeOutcome) matched() bool {
	return o.requestErr == nil && o.status >= 200 && o.status < 300 && o.present && o.got == o.route.expected
}

func routeCases(ctx context.Context, table *godog.Table) ([]routeCase, error) {
	if table == nil || len(table.Rows) == 0 {
		return nil, fmt.Errorf("a table of method, path, JSON field and expected value is required")
	}
	cases := make([]routeCase, 0, len(table.Rows))
	for i, row := range table.Rows {
		if row == nil || len(row.Cells) != 4 {
			return nil, fmt.Errorf("row %d must have four cells: method, path, JSON field, expected value", i+1)
		}
		cells := make([]string, 4)
		for j, cell := range row.Cells {
			value, err := stepscommon.Expand(ctx, strings.TrimSpace(cell.Value))
			if err != nil {
				return nil, err
			}
			cells[j] = value
		}
		if cells[0] == "" || cells[1] == "" || cells[2] == "" {
			return nil, fmt.Errorf("row %d needs a method, a path and a JSON field", i+1)
		}
		cases = append(cases, routeCase{
			method: strings.ToUpper(cells[0]), path: cells[1], field: cells[2], expected: cells[3],
		})
	}
	return cases, nil
}

// sendConcurrentRoutes sends n requests at once, request i taking row i mod len(rows). The
// existing concurrent steps check only the status of each response, which cannot show which
// upstream answered; this one records the response's JSON field so a later step can check it.
func (s *Steps) sendConcurrentRoutes(ctx context.Context, n int, table *godog.Table) error {
	if n <= 0 || n > maxConcurrentRouteRequests {
		return fmt.Errorf("the concurrent request count must be between 1 and %d, got %d",
			maxConcurrentRouteRequests, n)
	}
	cases, err := routeCases(ctx, table)
	if err != nil {
		return err
	}
	targets := make([]string, len(cases))
	for i, c := range cases {
		if targets[i], err = s.base.GatewayURL(c.path); err != nil {
			return err
		}
	}
	headers := s.base.ScenarioHeaders(ctx)
	host := s.base.RequestHost(ctx)

	outcomes := make([]routeOutcome, n)
	semaphore := make(chan struct{}, min(n, maxConcurrentRouteWorkers))
	var wg sync.WaitGroup
	for i := range n {
		c, target := cases[i%len(cases)], targets[i%len(cases)]
		wg.Add(1)
		semaphore <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-semaphore }()
			resp, requestErr := s.client.Do(ctx, httpx.Request{
				Method: c.method, URL: target, Headers: headers, Host: host,
			}, 0, 0)
			outcome := routeOutcome{route: c, requestErr: requestErr}
			if resp != nil {
				outcome.status = resp.StatusCode
				outcome.got, outcome.present = jsonField(resp.Body, c.field)
			}
			outcomes[i] = outcome
		}()
	}
	wg.Wait()
	return tcontext.Set(ctx, keyConcurrentRouteOutcomes, outcomes)
}

func (s *Steps) everyConcurrentRouteMatched(ctx context.Context) error {
	stored, ok := tcontext.Get(ctx, keyConcurrentRouteOutcomes)
	if !ok {
		return fmt.Errorf("no concurrent requests have been sent in this scenario")
	}
	outcomes, ok := stored.([]routeOutcome)
	if !ok {
		return fmt.Errorf("concurrent request outcomes have an unexpected type %T", stored)
	}
	return describeMismatches(outcomes)
}

func describeMismatches(outcomes []routeOutcome) error {
	causes := map[string]int{}
	failed := 0
	for _, o := range outcomes {
		if o.matched() {
			continue
		}
		failed++
		label := fmt.Sprintf("%s %s", o.route.method, o.route.path)
		switch {
		case o.requestErr != nil:
			causes[fmt.Sprintf("%s: transport error (%v)", label, o.requestErr)]++
		case o.status < 200 || o.status >= 300:
			causes[fmt.Sprintf("%s: status %d", label, o.status)]++
		case !o.present:
			causes[fmt.Sprintf("%s: JSON field %q is absent", label, o.route.field)]++
		default:
			causes[fmt.Sprintf("%s: field %q is %q, want %q", label, o.route.field, o.got, o.route.expected)]++
		}
	}
	if failed == 0 {
		return nil
	}
	lines := make([]string, 0, len(causes))
	for cause, count := range causes {
		lines = append(lines, fmt.Sprintf("%dx %s", count, cause))
	}
	sort.Strings(lines)
	if len(lines) > maxReportedCauses {
		lines = append(lines[:maxReportedCauses], fmt.Sprintf("and %d more", len(lines)-maxReportedCauses))
	}
	return fmt.Errorf("%d of %d concurrent responses did not match their expectation: %s",
		failed, len(outcomes), strings.Join(lines, "; "))
}
