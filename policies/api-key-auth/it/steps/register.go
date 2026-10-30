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

// Package steps holds the step definitions only the api-key-auth policy's scenarios need. The
// shared steps in tests/it/common/steps are bound before these, so search them first and do not
// repeat one here.
package steps

import (
	"context"
	"time"

	"github.com/cucumber/godog"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"

	sharedsteps "github.com/wso2/gateway-controllers/tests/it/common/steps"
)

const requestTimeout = 30 * time.Second

type requestBase interface {
	GatewayURL(path string) (string, error)
	ScenarioHeaders(ctx context.Context) map[string]string
	RequestHost(ctx context.Context) string
}

type Steps struct {
	base   requestBase
	topo   *frameworkruntime.Topology
	funnel *httpx.Funnel

	controlPlane controlPlane
}

func newSteps(base requestBase, topo *frameworkruntime.Topology) *Steps {
	client := httpx.NewClient(httpx.Options{Timeout: requestTimeout, MaxRetries: 3, RetryDelay: 2 * time.Second})
	return &Steps{
		base:   base,
		topo:   topo,
		funnel: httpx.NewFunnel(client, 3, 2*time.Second),
	}
}

// Register binds the policy's own steps to the scenario.
func Register(sc *godog.ScenarioContext, base *sharedsteps.Base, topo *frameworkruntime.Topology) {
	s := newSteps(base, topo)
	s.registerDataPlane(sc)
	s.registerBackgroundTraffic(sc)
	s.registerProcessSignals(sc)
	s.registerControlPlane(sc)
}
