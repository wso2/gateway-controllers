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
	"strconv"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	absentHeaderMarker = "<absent>"

	keyConcurrentOutcomes = "concurrentCyclingOutcomes"

	// maxConcurrentWorkers keeps a large request count from exhausting local connections.
	maxConcurrentWorkers = 20
)

func (s *Steps) registerConcurrentRequests(sc *godog.ScenarioContext) {
	sc.Step(`^I send (\d+) concurrent "([^"]*)" requests to "([^"]*)" cycling header "([^"]*)" through:$`,
		s.sendConcurrentCyclingRequests)
	sc.Step(`^every concurrent response should have its expected status$`,
		s.everyConcurrentResponseMatchesExpectedStatus)
}

type concurrentCyclingRow struct {
	value  string
	absent bool
	status int
}

type concurrentCyclingOutcome struct {
	row        concurrentCyclingRow
	gotStatus  int
	requestErr error
}

func concurrentCyclingRows(ctx context.Context, cells [][2]string) ([]concurrentCyclingRow, error) {
	if len(cells) == 0 {
		return nil, fmt.Errorf("cycling values table must not be empty")
	}
	rows := make([]concurrentCyclingRow, 0, len(cells))
	for i, cell := range cells {
		status, err := strconv.Atoi(strings.TrimSpace(cell[1]))
		if err != nil {
			return nil, fmt.Errorf("cycling values row %d: invalid status %q: %w", i+1, cell[1], err)
		}
		if strings.TrimSpace(cell[0]) == absentHeaderMarker {
			rows = append(rows, concurrentCyclingRow{absent: true, status: status})
			continue
		}
		value, err := stepscommon.Expand(ctx, cell[0])
		if err != nil {
			return nil, err
		}
		rows = append(rows, concurrentCyclingRow{value: value, status: status})
	}
	return rows, nil
}

// sendConcurrentCyclingRequests sends request i with the header value of row i mod len(rows).
func (s *Steps) sendConcurrentCyclingRequests(
	ctx context.Context, n int, method, path, header string, table *godog.Table,
) error {
	cells, err := tableRows(table)
	if err != nil {
		return err
	}
	return s.sendConcurrentCycling(ctx, n, method, path, header, cells)
}

func (s *Steps) sendConcurrentCycling(
	ctx context.Context, n int, method, path, header string, cells [][2]string,
) error {
	if n <= 0 {
		return fmt.Errorf("concurrent request count must be positive, got %d", n)
	}
	resolvedPath, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolvedPath)
	if err != nil {
		return err
	}
	rows, err := concurrentCyclingRows(ctx, cells)
	if err != nil {
		return err
	}
	method = strings.ToUpper(method)
	baseHeaders := s.base.ScenarioHeaders(ctx)
	host := s.base.RequestHost(ctx)
	client := s.funnel.Client()

	outcomes := make([]concurrentCyclingOutcome, n)
	sem := make(chan struct{}, min(n, maxConcurrentWorkers))
	var wg sync.WaitGroup
	for i := range n {
		row := rows[i%len(rows)]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			headers := make(map[string]string, len(baseHeaders)+1)
			for name, value := range baseHeaders {
				headers[name] = value
			}
			if !row.absent {
				headers[header] = row.value
			}
			resp, requestErr := client.Do(ctx, httpx.Request{
				Method: method, URL: target, Headers: headers, Host: host,
			}, 0, 0)
			outcome := concurrentCyclingOutcome{row: row, requestErr: requestErr}
			if resp != nil {
				outcome.gotStatus = resp.StatusCode
			}
			outcomes[i] = outcome
		}()
	}
	wg.Wait()
	return tcontext.Set(ctx, keyConcurrentOutcomes, outcomes)
}

// maskConcurrentValue keeps a real API key out of the test output.
func maskConcurrentValue(row concurrentCyclingRow) string {
	if row.absent {
		return absentHeaderMarker
	}
	const shown = 6
	if len(row.value) <= shown {
		return row.value
	}
	return row.value[:shown] + "..."
}

func countMatching(outcomes []concurrentCyclingOutcome) int {
	matching := 0
	for _, o := range outcomes {
		if o.requestErr == nil && o.gotStatus == o.row.status {
			matching++
		}
	}
	return matching
}

func (s *Steps) everyConcurrentResponseMatchesExpectedStatus(ctx context.Context) error {
	stored, ok := tcontext.Get(ctx, keyConcurrentOutcomes)
	if !ok {
		return fmt.Errorf("no concurrent requests have been sent in this scenario")
	}
	outcomes, ok := stored.([]concurrentCyclingOutcome)
	if !ok {
		return fmt.Errorf("concurrent request outcomes have an unexpected type %T", stored)
	}

	counts := map[string]int{}
	for _, o := range outcomes {
		masked := maskConcurrentValue(o.row)
		switch {
		case o.requestErr != nil:
			counts[fmt.Sprintf("%s: transport error (%v)", masked, o.requestErr)]++
		case o.gotStatus != o.row.status:
			counts[fmt.Sprintf("%s: want %d, got %d", masked, o.row.status, o.gotStatus)]++
		}
	}
	if len(counts) == 0 {
		return nil
	}

	causes := make([]string, 0, len(counts))
	for cause, count := range counts {
		causes = append(causes, fmt.Sprintf("%dx %s", count, cause))
	}
	sort.Strings(causes)
	return fmt.Errorf("%d of %d concurrent responses did not match their expected status: %s",
		len(outcomes)-countMatching(outcomes), len(outcomes), strings.Join(causes, "; "))
}
