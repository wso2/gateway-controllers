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

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

func (s *Steps) registerReplicas(sc *godog.ScenarioContext) {
	sc.Step(`^I send (\d+) "([^"]*)" requests to the (first|second) gateway "([^"]*)"$`, s.sendRepeatedAt)
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
