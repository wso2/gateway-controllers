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
	"errors"
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
	// backgroundRequestInterval is the pause between two background requests.
	backgroundRequestInterval = 100 * time.Millisecond
	// maxBackgroundResponses bounds what one probe keeps, so a probe left running cannot grow
	// without limit.
	maxBackgroundResponses = 3000
	// backgroundEchoWait bounds how long an echo check waits for a running probe.
	backgroundEchoWait = 30 * time.Second

	keyBackgroundRequests = "hostRewriteBackgroundRequests"
)

func (s *Steps) registerBackgroundRequests(sc *godog.ScenarioContext) {
	sc.Step(`^I start background "([^"]*)" requests to "([^"]*)" as "([^"]*)"$`, s.startBackgroundRequests)
	sc.Step(`^I stop background requests "([^"]*)"$`, s.stopBackgroundRequests)
	sc.Step(`^every background response of "([^"]*)" should be successful with JSON field "([^"]*)" set to one of:$`,
		s.everyBackgroundResponseIsOneOf)
	sc.Step(`^background requests "([^"]*)" should eventually echo "([^"]*)" in JSON field "([^"]*)"$`,
		s.backgroundRequestsEventuallyEcho)

	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		stopAllBackgroundRequests(ctx)
		return ctx, nil
	})
}

// backgroundResponse is one recorded response; status 0 marks a request that got no response.
type backgroundResponse struct {
	status int
	body   []byte
	err    string
}

// backgroundProbe sends requests until it is stopped and records every response.
type backgroundProbe struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	responses []backgroundResponse
	// dropped counts responses not kept because the probe was full; any makes the record
	// incomplete, so the "every response" check fails rather than pass on what it kept.
	dropped int
}

func (p *backgroundProbe) record(r backgroundResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.responses) < maxBackgroundResponses {
		p.responses = append(p.responses, r)
		return
	}
	p.dropped++
}

func (p *backgroundProbe) droppedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped
}

// running reports whether the probe is still sending requests.
func (p *backgroundProbe) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *backgroundProbe) snapshot() []backgroundResponse {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]backgroundResponse(nil), p.responses...)
}

func (p *backgroundProbe) stop() {
	p.cancel()
	<-p.done
}

func backgroundProbes(ctx context.Context) (map[string]*backgroundProbe, error) {
	if stored, ok := tcontext.Get(ctx, keyBackgroundRequests); ok {
		probes, ok := stored.(map[string]*backgroundProbe)
		if !ok {
			return nil, fmt.Errorf("background requests have an unexpected type %T", stored)
		}
		return probes, nil
	}
	probes := map[string]*backgroundProbe{}
	if err := tcontext.Set(ctx, keyBackgroundRequests, probes); err != nil {
		return nil, err
	}
	return probes, nil
}

// stopAllBackgroundRequests stops every probe of the scenario and forgets them, so none
// outlives the scenario that started it.
func stopAllBackgroundRequests(ctx context.Context) {
	stored, ok := tcontext.Get(ctx, keyBackgroundRequests)
	if !ok {
		return
	}
	if probes, ok := stored.(map[string]*backgroundProbe); ok {
		for _, probe := range probes {
			probe.stop()
		}
	}
	tcontext.Remove(ctx, keyBackgroundRequests)
}

// startBackgroundRequests sends the request every backgroundRequestInterval, with the
// scenario's headers and request host as they are now, until the probe is stopped.
func (s *Steps) startBackgroundRequests(ctx context.Context, method, path, name string) error {
	resolvedPath, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("background requests need a name")
	}
	target, err := s.base.GatewayURL(resolvedPath)
	if err != nil {
		return err
	}
	probes, err := backgroundProbes(ctx)
	if err != nil {
		return err
	}
	if _, exists := probes[name]; exists {
		return fmt.Errorf("background requests %q are already running", name)
	}
	request := httpx.Request{
		Method: strings.ToUpper(method), URL: target, Headers: copyHeaders(s.base.ScenarioHeaders(ctx)),
		Host: s.base.RequestHost(ctx),
	}
	probeCtx, cancel := context.WithCancel(context.Background())
	probe := &backgroundProbe{cancel: cancel, done: make(chan struct{})}
	go s.runBackgroundRequests(probeCtx, probe, request)
	probes[name] = probe
	return nil
}

func (s *Steps) runBackgroundRequests(ctx context.Context, probe *backgroundProbe, request httpx.Request) {
	defer close(probe.done)
	ticker := time.NewTicker(backgroundRequestInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req := request
			req.Headers = copyHeaders(request.Headers)
			resp, err := s.client.Do(ctx, req, 0, 0)
			if stoppedByProbe(ctx, err) {
				return // the request was cut short by stopping the probe; it says nothing about the gateway
			}
			r := backgroundResponse{}
			if err != nil {
				r.err = err.Error()
			} else if resp != nil {
				r.status, r.body = resp.StatusCode, resp.Body
			}
			probe.record(r) // a response that completed is kept, even if the probe stopped meanwhile
		}
	}
}

// stoppedByProbe reports whether err comes from stopping the probe: the probe is stopped and the
// error wraps its cancellation. Any other error is the gateway's, even one that arrives as the
// probe stops, and is recorded.
func stoppedByProbe(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() != nil && errors.Is(err, context.Canceled)
}

func namedBackgroundProbe(ctx context.Context, name string) (*backgroundProbe, error) {
	probes, err := backgroundProbes(ctx)
	if err != nil {
		return nil, err
	}
	probe, ok := probes[strings.TrimSpace(name)]
	if !ok {
		return nil, fmt.Errorf("no background requests named %q were started in this scenario", name)
	}
	return probe, nil
}

func (s *Steps) stopBackgroundRequests(ctx context.Context, name string) error {
	probe, err := namedBackgroundProbe(ctx, name)
	if err != nil {
		return err
	}
	probe.stop()
	return nil
}

func (s *Steps) everyBackgroundResponseIsOneOf(ctx context.Context, name, field string, table *godog.Table) error {
	cells, err := tableCells(table, 1)
	if err != nil {
		return err
	}
	return s.everyBackgroundResponseIsOneOfValues(ctx, name, field, cells)
}

// everyBackgroundResponseIsOneOfValues is everyBackgroundResponseIsOneOf on table rows already read.
func (s *Steps) everyBackgroundResponseIsOneOfValues(ctx context.Context, name, field string, cells [][]string) error {
	probe, err := namedBackgroundProbe(ctx, name)
	if err != nil {
		return err
	}
	allowed, err := allowedValues(ctx, cells)
	if err != nil {
		return err
	}
	if dropped := probe.droppedCount(); dropped > 0 {
		return fmt.Errorf("background requests %q dropped %d responses past the %d it keeps, so not every response can be checked",
			name, dropped, maxBackgroundResponses)
	}
	return checkEveryResponseIsOneOf(probe.snapshot(), strings.TrimSpace(field), allowed)
}

// backgroundRequestsEventuallyEcho waits, while the probe still runs, until one of its successful
// responses carries want in the JSON field. It waits on the probe's own responses, not on fresh
// requests, so the probe is known to have seen the value before the scenario stops it.
func (s *Steps) backgroundRequestsEventuallyEcho(ctx context.Context, name, want, field string) error {
	probe, err := namedBackgroundProbe(ctx, name)
	if err != nil {
		return err
	}
	want, err = stepscommon.Expand(ctx, want)
	if err != nil {
		return err
	}
	field = strings.TrimSpace(field)
	deadline := time.Now().Add(backgroundEchoWait)
	for {
		// Decide whether this is the last look before reading the responses, so the last look
		// covers every response recorded before the probe stopped or the wait ran out.
		last := !probe.running() || time.Now().After(deadline)
		responses := probe.snapshot()
		if echoed(responses, field, want) {
			return nil
		}
		if last {
			return fmt.Errorf("background requests %q never echoed %s %q; values seen: %s",
				name, field, want, strings.Join(distinctValues(responses, field), ", "))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backgroundRequestInterval / 2):
		}
	}
}

// echoed reports whether a successful response carries want in the JSON field.
func echoed(responses []backgroundResponse, field, want string) bool {
	for _, value := range distinctValues(responses, field) {
		if value == want {
			return true
		}
	}
	return false
}

// allowedValues reads one-cell rows of values, expanding stored values.
func allowedValues(ctx context.Context, cells [][]string) (map[string]bool, error) {
	if len(cells) == 0 {
		return nil, fmt.Errorf("a table of allowed values is required")
	}
	allowed := map[string]bool{}
	for i, row := range cells {
		if len(row) != 1 {
			return nil, fmt.Errorf("allowed values row %d must contain exactly one cell", i+1)
		}
		value, err := stepscommon.Expand(ctx, strings.TrimSpace(row[0]))
		if err != nil {
			return nil, err
		}
		allowed[value] = true
	}
	return allowed, nil
}

// checkEveryResponseIsOneOf fails when no response was recorded, or when any response is not
// 2xx or carries a field value outside allowed. The failure names how many responses were off
// and the first few.
func checkEveryResponseIsOneOf(responses []backgroundResponse, field string, allowed map[string]bool) error {
	if len(responses) == 0 {
		return fmt.Errorf("no background response was recorded")
	}
	var problems []string
	count := 0
	for i, r := range responses {
		problem := ""
		switch {
		case r.err != "":
			problem = fmt.Sprintf("request %d failed: %s", i+1, r.err)
		case r.status < 200 || r.status >= 300:
			problem = fmt.Sprintf("request %d got status %d", i+1, r.status)
		default:
			got, err := jsonField(r.body, field)
			if err != nil {
				problem = fmt.Sprintf("request %d: %v", i+1, err)
			} else if !allowed[got] {
				problem = fmt.Sprintf("request %d: %s is %q", i+1, field, got)
			}
		}
		if problem == "" {
			continue
		}
		count++
		if len(problems) < maxReportedMismatches {
			problems = append(problems, problem)
		}
	}
	if count == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d background responses were not successful with an allowed %s: %s",
		count, len(responses), field, strings.Join(problems, "; "))
}

// distinctValues returns the different values of field among the successful responses, in the
// order they first appeared.
func distinctValues(responses []backgroundResponse, field string) []string {
	seen := map[string]bool{}
	var order []string
	for _, r := range responses {
		if r.err != "" || r.status < 200 || r.status >= 300 {
			continue
		}
		got, err := jsonField(r.body, field)
		if err != nil || seen[got] {
			continue
		}
		seen[got] = true
		order = append(order, got)
	}
	return order
}
