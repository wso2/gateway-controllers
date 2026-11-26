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

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/retry"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

func (s *Steps) registerReplicas(sc *godog.ScenarioContext) {
	sc.Step(`^I send (\d+) "([^"]*)" requests to the (first|second) gateway "([^"]*)"$`, s.sendRepeatedAt)
	sc.Step(`^I send a "([^"]*)" request to the (first|second) gateway "([^"]*)" until header "([^"]*)" is "([^"]*)"$`,
		s.sendUntilHeaderAt)
}

// sendUntilHeaderAt polls a gateway replica until a response header carries the wanted value. A
// rate limit header only appears once the replica has loaded the policy, so this waits for that
// without depending on the quota's state: the response it stops on is the first one the policy
// counted, which the next assertion can then check.
func (s *Steps) sendUntilHeaderAt(ctx context.Context, method, ordinal, path, name, want string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	wantValue, err := stepscommon.Expand(ctx, want)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURLAt(ordinal, resolved)
	if err != nil {
		return err
	}
	method = strings.ToUpper(method)
	return stepscommon.AwaitResponse(ctx, func(ctx context.Context) (*httpx.Response, error) {
		resp, sendErr := s.funnel.Send(ctx, httpx.Request{
			Method: method, URL: target, Headers: maps.Clone(s.base.ScenarioHeaders(ctx)), Host: s.base.RequestHost(ctx),
		})
		if sendErr != nil {
			return nil, retry.Transient(sendErr)
		}
		return resp, nil
	}, func(resp *httpx.Response) bool {
		return resp != nil && resp.Headers.Get(name) == wantValue
	}, fmt.Sprintf("waiting for %s %s to answer with header %s: %q", method, target, name, wantValue))
}

// sendRepeatedAt sends n requests one after another to the chosen gateway replica, without
// retrying a rejection. Each response is published, so the assertions that follow see the last
// one.
func (s *Steps) sendRepeatedAt(ctx context.Context, n int, method, ordinal, path string) error {
	if n <= 0 {
		return fmt.Errorf("the request count must be positive, got %d", n)
	}
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURLAt(ordinal, resolved)
	if err != nil {
		return err
	}
	method = strings.ToUpper(method)
	for i := 1; i <= n; i++ {
		if _, err := s.funnel.Send(ctx, httpx.Request{
			Method: method, URL: target, Headers: maps.Clone(s.base.ScenarioHeaders(ctx)), Host: s.base.RequestHost(ctx),
		}); err != nil {
			return fmt.Errorf("request %d of %d to %s %s: %w", i, n, method, target, err)
		}
	}
	return nil
}
