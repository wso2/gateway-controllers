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

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

// storeValue stores a literal value in the runner context, for a scenario to reference as
// ${CTX:<key>}. A values-table row that contains the word "metadata" is read by the framework
// standards check as a resource's metadata block, so a policy name on that row looks like a
// hard-coded resource name. Storing the advanced-ratelimit key type "metadata" keeps the word off
// the row.
func storeValue(ctx context.Context, value, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("cannot store %q under an empty key", value)
	}
	local, ok := tcontext.LocalOf(ctx)
	if !ok || local == nil {
		return fmt.Errorf("cannot store %q as %q without runner context", value, key)
	}
	local.Set(key, value)
	return nil
}
