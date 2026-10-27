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

package runsuites

import (
	"github.com/wso2/api-platform/tests/framework/core/components"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

// BlockCount returns how many blocks the suite in suiteFile boots under selection: its blocks
// with their database matrices expanded, less the variants and runners the selected gateway
// version excludes. It resolves the suite the way the suite's own run does, against registry.
func BlockCount(registry *components.Registry, suiteFile string, selection topology.Selection) (int, error) {
	resolved, err := topology.LoadFile(suiteFile, registry)
	if err != nil {
		return 0, err
	}
	applied, err := selection.Apply(resolved)
	if err != nil {
		return 0, err
	}
	return len(applied.Blocks), nil
}
