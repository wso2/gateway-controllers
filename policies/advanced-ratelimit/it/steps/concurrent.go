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
	"maps"
	"sort"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

// maxConcurrentWorkers keeps a large request count from exhausting local connections.
const maxConcurrentWorkers = 20

func (s *Steps) registerConcurrent(sc *godog.ScenarioContext) {
	sc.Step(`^I send (\d+) concurrent "([^"]*)" requests to "([^"]*)" and exactly (\d+) should return (\d+) while (\d+) should return (\d+)$`,
		s.sendConcurrentSplit)
}

// sendConcurrentSplit sends n requests at the same time and requires exactly firstCount of them to
// return firstStatus and secondCount to return secondStatus, which is how a quota boundary is
// shown to hold under load: no request is wrongly rejected and none is wrongly admitted.
func (s *Steps) sendConcurrentSplit(
	ctx context.Context, n int, method, path string, firstCount, firstStatus, secondCount, secondStatus int,
) error {
	if n <= 0 {
		return fmt.Errorf("the concurrent request count must be positive, got %d", n)
	}
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	headers := s.base.ScenarioHeaders(ctx)
	host := s.base.RequestHost(ctx)
	method = strings.ToUpper(method)

	statuses := make([]int, n)
	errs := make([]error, n)
	slots := make(chan struct{}, min(n, maxConcurrentWorkers))
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			resp, requestErr := s.funnel.Client().Do(ctx, httpx.Request{
				Method: method, URL: target, Headers: maps.Clone(headers), Host: host,
			}, 0, 0)
			if requestErr != nil {
				errs[i] = requestErr
				return
			}
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for i, requestErr := range errs {
		if requestErr != nil {
			return fmt.Errorf("concurrent request %d of %d: %w", i+1, n, requestErr)
		}
	}
	return checkStatusSplit(statuses, map[int]int{firstStatus: firstCount, secondStatus: secondCount})
}

// checkStatusSplit returns why the observed statuses differ from the wanted count per status, or
// nil when they are identical. A status that was neither wanted nor counted is reported as well.
func checkStatusSplit(statuses []int, want map[int]int) error {
	got := make(map[int]int, len(want))
	for _, status := range statuses {
		got[status]++
	}
	var diffs []string
	for status, count := range want {
		if got[status] != count {
			diffs = append(diffs, fmt.Sprintf("status %d: want %d, got %d", status, count, got[status]))
		}
	}
	for status, count := range got {
		if _, wanted := want[status]; !wanted {
			diffs = append(diffs, fmt.Sprintf("status %d: want 0, got %d", status, count))
		}
	}
	if len(diffs) == 0 {
		return nil
	}
	sort.Strings(diffs)
	return fmt.Errorf("the %d concurrent responses did not split as expected: %s",
		len(statuses), strings.Join(diffs, "; "))
}
