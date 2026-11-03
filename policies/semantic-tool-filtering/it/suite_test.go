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

// Package it_test runs the integration tests of the semantic-tool-filtering policy.
package it_test

import (
	"testing"

	"github.com/wso2/gateway-controllers/tests/it/common/suite"

	"github.com/wso2/gateway-controllers/policies/semantic-tool-filtering/it/steps"
)

var config = suite.Config{Register: steps.Register}

func TestMain(m *testing.M) {
	suite.Main(m, config)
}

// TestIntegrationSuite runs the suite declared in it-suite.yaml.
func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, config)
}
