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
	"time"

	"github.com/cucumber/godog"
)

// maxWindowWait caps how long the window step may sleep, so a mistaken duration cannot stall a run.
const maxWindowWait = 2 * time.Minute

func (s *Steps) registerWindow(sc *godog.ScenarioContext) {
	sc.Step(`^I wait until the current "([^"]*)" rate limit window has at least (\d+) seconds left$`,
		s.waitForWindowRoom)
}

// waitForWindowRoom returns once the fixed window of the given duration that contains "now" has at
// least minSeconds left. The policy aligns a fixed window to the clock (it truncates the time to the
// window length), so a scenario that counts requests against a quota and then expects the count to
// still be there fails when the wall clock crosses a boundary in between: the quota starts again at
// zero and the request that should be rejected is admitted. Waiting for the next window when the
// current one is nearly over puts the whole scenario inside one window, and the scenario's own
// assertions stay as strict as before. It returns at once when enough of the window is left, which
// is almost always the case for a 1h window.
func (s *Steps) waitForWindowRoom(ctx context.Context, duration string, minSeconds int) error {
	window, err := time.ParseDuration(duration)
	if err != nil || window <= 0 {
		return fmt.Errorf("window duration %q is not a positive Go duration such as 1h: %v", duration, err)
	}
	minLeft := time.Duration(minSeconds) * time.Second
	if minLeft >= window {
		return fmt.Errorf("cannot ask for %s left in a %s window", minLeft, window)
	}

	now := time.Now
	if s.now != nil {
		now = s.now
	}
	current := now()
	left := current.Truncate(window).Add(window).Sub(current)
	if left >= minLeft {
		return nil
	}
	if left > maxWindowWait {
		return fmt.Errorf("the next %s window starts in %s, longer than the %s this step waits", window, left, maxWindowWait)
	}

	// Wait for the boundary itself; the new window then has its full length left.
	wait := left + 100*time.Millisecond
	if s.sleep != nil {
		return s.sleep(ctx, wait)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
