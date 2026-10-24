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
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	backgroundTrafficInterval = 200 * time.Millisecond

	keyBackgroundProbes = "backgroundTrafficProbes"
)

func (s *Steps) registerBackgroundTraffic(sc *godog.ScenarioContext) {
	sc.Step(`^I start background "([^"]*)" traffic to "([^"]*)" with header "([^"]*)" set to "([^"]*)" as "([^"]*)"$`,
		s.startBackgroundTraffic)
	sc.Step(`^I stop background traffic "([^"]*)"$`, s.stopBackgroundTraffic)
	sc.Step(`^background traffic "([^"]*)" should never have received status (\d+)$`,
		s.backgroundTrafficNeverReceivedStatus)
	sc.Step(`^background traffic "([^"]*)" should have recorded at least (\d+) attempts$`,
		s.backgroundTrafficAtLeastAttempts)

	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		s.stopAllBackgroundTraffic(ctx)
		return ctx, nil
	})
}

// backgroundTrafficProbe records the status of each response, 0 for a request that got none.
type backgroundTrafficProbe struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	statuses []int
}

func (p *backgroundTrafficProbe) record(status int) {
	p.mu.Lock()
	p.statuses = append(p.statuses, status)
	p.mu.Unlock()
}

func (p *backgroundTrafficProbe) snapshot() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.statuses...)
}

func (s *Steps) backgroundProbes(ctx context.Context) (map[string]*backgroundTrafficProbe, error) {
	if stored, ok := tcontext.Get(ctx, keyBackgroundProbes); ok {
		probes, ok := stored.(map[string]*backgroundTrafficProbe)
		if !ok {
			return nil, fmt.Errorf("background traffic probes have an unexpected type %T", stored)
		}
		return probes, nil
	}
	probes := map[string]*backgroundTrafficProbe{}
	if err := tcontext.Set(ctx, keyBackgroundProbes, probes); err != nil {
		return nil, err
	}
	return probes, nil
}

// startBackgroundTraffic resolves the URL on every tick, so a probe started before the gateway
// runtime restarts keeps polling the right port once the runtime is back.
func (s *Steps) startBackgroundTraffic(ctx context.Context, method, path, header, value, name string) error {
	resolvedPath, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	resolvedValue, err := stepscommon.Expand(ctx, value)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("background traffic probe name must not be empty")
	}
	probes, err := s.backgroundProbes(ctx)
	if err != nil {
		return err
	}
	if _, exists := probes[name]; exists {
		return fmt.Errorf("background traffic probe %q is already running", name)
	}

	method = strings.ToUpper(method)
	host := s.base.RequestHost(ctx)
	client := s.funnel.Client()
	probeCtx, cancel := context.WithCancel(context.Background())
	probe := &backgroundTrafficProbe{cancel: cancel, done: make(chan struct{})}

	go func() {
		defer close(probe.done)
		ticker := time.NewTicker(backgroundTrafficInterval)
		defer ticker.Stop()
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-ticker.C:
				status := 0
				if target, urlErr := s.base.GatewayURL(resolvedPath); urlErr == nil {
					resp, doErr := client.Do(probeCtx, httpx.Request{
						Method: method, URL: target, Headers: map[string]string{header: resolvedValue}, Host: host,
					}, 0, 0)
					if doErr == nil && resp != nil {
						status = resp.StatusCode
					}
				}
				probe.record(status)
			}
		}
	}()

	probes[name] = probe
	return nil
}

func (s *Steps) namedBackgroundProbe(ctx context.Context, name string) (*backgroundTrafficProbe, error) {
	name = strings.TrimSpace(name)
	probes, err := s.backgroundProbes(ctx)
	if err != nil {
		return nil, err
	}
	probe, ok := probes[name]
	if !ok {
		return nil, fmt.Errorf("no background traffic probe named %q was started in this scenario", name)
	}
	return probe, nil
}

func (s *Steps) stopBackgroundTraffic(ctx context.Context, name string) error {
	probe, err := s.namedBackgroundProbe(ctx, name)
	if err != nil {
		return err
	}
	probe.cancel()
	<-probe.done
	return nil
}

// stopAllBackgroundTraffic also deletes the probes: the context outlives the scenario, and a
// leftover name would stop the next scenario from reusing it.
func (s *Steps) stopAllBackgroundTraffic(ctx context.Context) {
	probes, err := s.backgroundProbes(ctx)
	if err != nil {
		return
	}
	for _, probe := range probes {
		probe.cancel()
	}
	for _, probe := range probes {
		<-probe.done
	}
	for name := range probes {
		delete(probes, name)
	}
}

func (s *Steps) backgroundTrafficNeverReceivedStatus(ctx context.Context, name string, want int) error {
	probe, err := s.namedBackgroundProbe(ctx, name)
	if err != nil {
		return err
	}
	statuses := probe.snapshot()
	for _, got := range statuses {
		if got == want {
			return fmt.Errorf("background traffic %q received status %d at least once; recorded statuses: %v",
				name, want, statuses)
		}
	}
	return nil
}

func (s *Steps) backgroundTrafficAtLeastAttempts(ctx context.Context, name string, minimum int) error {
	probe, err := s.namedBackgroundProbe(ctx, name)
	if err != nil {
		return err
	}
	if got := len(probe.snapshot()); got < minimum {
		return fmt.Errorf("background traffic %q recorded %d attempts, want at least %d", name, got, minimum)
	}
	return nil
}
