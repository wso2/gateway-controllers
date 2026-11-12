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

	"github.com/cucumber/godog"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

// policySteps holds the state the oauth2-token-exchange policy's steps share within one runner.
type policySteps struct {
	topo *frameworkruntime.Topology
}

func newPolicySteps(topo *frameworkruntime.Topology) *policySteps {
	return &policySteps{topo: topo}
}

// register binds the steps below. Add a step here only when no shared step expresses the
// behaviour, and give it a unit test in steps_test.go.
func (s *policySteps) register(sc *godog.ScenarioContext) {
	sc.Step(`^I store the masked preview of context value "([^"]*)" as "([^"]*)"$`, s.storeMaskedPreview)
}

// storeMaskedPreview stores the masked form of a stored credential, matching the testbench oauth2
// service's maskSecret, so a scenario can assert which credential the authorization server
// received from its /debug/stats preview without the raw value ever being recorded.
func (s *policySteps) storeMaskedPreview(ctx context.Context, sourceKey, key string) error {
	value, err := tcontext.ResolveString(ctx, strings.TrimSpace(sourceKey))
	if err != nil {
		return err
	}
	if len(value) <= 8 {
		return fmt.Errorf("context value %q is too short to have a distinguishing masked preview", sourceKey)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("cannot store a masked preview with an empty key")
	}
	return tcontext.Set(ctx, key, value[:4]+"..."+value[len(value)-4:])
}
