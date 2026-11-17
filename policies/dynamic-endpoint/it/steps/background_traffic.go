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
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	backgroundTrafficInterval = 100 * time.Millisecond
	// backgroundAttemptsWait bounds the wait for a probe to record the attempts a scenario needs.
	backgroundAttemptsWait = 30 * time.Second

	keyBackgroundProbes = "dynamicEndpointBackgroundTraffic"
)

func (s *Steps) registerBackgroundTraffic(sc *godog.ScenarioContext) {
	sc.Step(`^I start background "([^"]*)" traffic to "([^"]*)" as "([^"]*)"$`, s.startBackgroundTraffic)
	sc.Step(`^I wait until background traffic "([^"]*)" has recorded at least (\d+) attempts$`,
		s.waitForBackgroundAttempts)
	sc.Step(`^I stop background traffic "([^"]*)"$`, s.stopBackgroundTraffic)
	sc.Step(`^background traffic "([^"]*)" should have recorded at least (\d+) attempts$`,
		s.backgroundTrafficAtLeastAttempts)
	sc.Step(`^background traffic "([^"]*)" should have received at least (\d+) successful responses$`,
		s.backgroundTrafficAtLeastSuccesses)
	sc.Step(`^background traffic "([^"]*)" should only have received successful responses whose JSON field "([^"]*)" starts with one of "([^"]*)"$`,
		s.backgroundTrafficOnlyPrefixes)

	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		s.stopAllBackgroundTraffic(ctx)
		return ctx, nil
	})
}

// trafficSample is one answered request. A request that got no answer is recorded with status 0.
type trafficSample struct {
	status int
	body   []byte
}

func (t trafficSample) successful() bool { return t.status >= 200 && t.status < 300 }

type backgroundTrafficProbe struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	samples []trafficSample
}

func (p *backgroundTrafficProbe) record(sample trafficSample) {
	p.mu.Lock()
	p.samples = append(p.samples, sample)
	p.mu.Unlock()
}

func (p *backgroundTrafficProbe) snapshot() []trafficSample {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]trafficSample(nil), p.samples...)
}

func backgroundProbes(ctx context.Context) (map[string]*backgroundTrafficProbe, error) {
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

// startBackgroundTraffic sends one request every tick, with the headers the scenario holds when
// the step runs, until the probe is stopped or the scenario ends.
func (s *Steps) startBackgroundTraffic(ctx context.Context, method, path, name string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("background traffic probe name must not be empty")
	}
	probes, err := backgroundProbes(ctx)
	if err != nil {
		return err
	}
	if _, exists := probes[name]; exists {
		return fmt.Errorf("background traffic probe %q is already running", name)
	}

	method = strings.ToUpper(method)
	// Copied: the scenario keeps changing its own headers while the probe runs.
	headers := maps.Clone(s.base.ScenarioHeaders(ctx))
	host := s.base.RequestHost(ctx)
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
				sample := trafficSample{}
				resp, doErr := s.client.Do(probeCtx, httpx.Request{
					Method: method, URL: target, Headers: headers, Host: host,
				}, 0, 0)
				if doErr == nil && resp != nil {
					sample = trafficSample{status: resp.StatusCode, body: resp.Body}
				}
				if probeCtx.Err() != nil {
					return
				}
				probe.record(sample)
			}
		}
	}()

	probes[name] = probe
	return nil
}

func namedProbe(ctx context.Context, name string) (*backgroundTrafficProbe, error) {
	name = strings.TrimSpace(name)
	probes, err := backgroundProbes(ctx)
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
	probe, err := namedProbe(ctx, name)
	if err != nil {
		return err
	}
	probe.cancel()
	<-probe.done
	return nil
}

// stopAllBackgroundTraffic also forgets the probes: the context outlives the scenario, and a
// leftover name would stop the next scenario from reusing it.
func (s *Steps) stopAllBackgroundTraffic(ctx context.Context) {
	probes, err := backgroundProbes(ctx)
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

// waitForBackgroundAttempts holds a scenario until the probe has recorded enough attempts, so the
// number of samples does not depend on how quickly the steps before it finished. It is bounded:
// a probe that cannot record the attempts in time fails the step with the count it reached.
func (s *Steps) waitForBackgroundAttempts(ctx context.Context, name string, minimum int) error {
	probe, err := namedProbe(ctx, name)
	if err != nil {
		return err
	}
	deadline := time.NewTimer(backgroundAttemptsWait)
	defer deadline.Stop()
	ticker := time.NewTicker(backgroundTrafficInterval)
	defer ticker.Stop()
	for {
		got := len(probe.snapshot())
		if got >= minimum {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for background traffic %q to record %d attempts: %w", name, minimum, ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("background traffic %q recorded %d attempts within %s, want at least %d",
				name, got, backgroundAttemptsWait, minimum)
		case <-ticker.C:
		}
	}
}

func (s *Steps) backgroundTrafficAtLeastAttempts(ctx context.Context, name string, minimum int) error {
	probe, err := namedProbe(ctx, name)
	if err != nil {
		return err
	}
	if got := len(probe.snapshot()); got < minimum {
		return fmt.Errorf("background traffic %q recorded %d attempts, want at least %d", name, got, minimum)
	}
	return nil
}

func (s *Steps) backgroundTrafficAtLeastSuccesses(ctx context.Context, name string, minimum int) error {
	probe, err := namedProbe(ctx, name)
	if err != nil {
		return err
	}
	samples := probe.snapshot()
	got := 0
	for _, sample := range samples {
		if sample.successful() {
			got++
		}
	}
	if got < minimum {
		return fmt.Errorf("background traffic %q received %d successful responses out of %d attempts, want at least %d",
			name, got, len(samples), minimum)
	}
	return nil
}

// backgroundTrafficOnlyPrefixes fails when any successful response carries a value outside the
// allowed prefixes. Unsuccessful responses are ignored: a configuration change may be answered
// with an error while it applies, and what must never happen is a success from the wrong place.
func (s *Steps) backgroundTrafficOnlyPrefixes(ctx context.Context, name, field, prefixes string) error {
	probe, err := namedProbe(ctx, name)
	if err != nil {
		return err
	}
	resolved, err := stepscommon.Expand(ctx, prefixes)
	if err != nil {
		return err
	}
	allowed := strings.Split(resolved, ",")
	for i := range allowed {
		allowed[i] = strings.TrimSpace(allowed[i])
	}
	return checkOnlyPrefixes(name, field, allowed, probe.snapshot())
}

func checkOnlyPrefixes(name, field string, allowed []string, samples []trafficSample) error {
	for _, sample := range samples {
		if !sample.successful() {
			continue
		}
		got, present := jsonField(sample.body, field)
		if !present {
			return fmt.Errorf("background traffic %q received a successful response without JSON field %q: %s",
				name, field, sample.body)
		}
		matched := false
		for _, prefix := range allowed {
			if prefix != "" && strings.HasPrefix(got, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("background traffic %q received %s=%q, which starts with none of %v",
				name, field, got, allowed)
		}
	}
	return nil
}
