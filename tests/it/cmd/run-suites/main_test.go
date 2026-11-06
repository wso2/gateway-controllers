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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisplayNameKeepsABlockNamedAfterItsPolicy(t *testing.T) {
	require.Equal(t, "backend-jwt-policy-key", displayName("backend-jwt", "backend-jwt-policy-key"))
	require.Equal(t, "backend-jwt-v2-claim-types", displayName("backend-jwt/v2", "backend-jwt-v2-claim-types"))
	require.Equal(t, "cors/sqlite", displayName("cors", "sqlite"))
}

func TestJobNameIsUniqueAcrossSuites(t *testing.T) {
	items := map[string]item{}
	first := jobName(items, "backend-jwt", "backend-jwt-claims")
	items[first] = item{policy: "backend-jwt", block: "backend-jwt-claims"}

	// The same display name from a second suite must not replace the first suite's job.
	second := jobName(items, "backend-jwt", "backend-jwt-claims")
	require.NotEqual(t, first, second)
	require.Equal(t, "backend-jwt/backend-jwt-claims", second)
}
