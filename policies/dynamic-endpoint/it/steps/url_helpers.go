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
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

func (s *Steps) registerURLHelpers(sc *godog.ScenarioContext) {
	sc.Step(`^I split the URL "([^"]*)" into origin "([^"]*)" and base path "([^"]*)"$`, s.splitURL)
}

// splitURL stores the scheme and host of a URL under one key and its path under another.
//
// An upstream definition takes a host and port in its url and the path in its basePath, but the
// address of a partitioned testbench service resolves to one string that holds both. A scenario
// that points a definition at such a service splits that string here.
func (s *Steps) splitURL(ctx context.Context, raw, originKey, basePathKey string) error {
	resolved, err := stepscommon.Expand(ctx, raw)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(resolved)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", resolved, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%q has no scheme and host to split", resolved)
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if basePath == "" {
		return fmt.Errorf("%q has no path, so there is no base path to store", resolved)
	}
	originKey, basePathKey = strings.TrimSpace(originKey), strings.TrimSpace(basePathKey)
	if originKey == "" || basePathKey == "" {
		return fmt.Errorf("the origin key and the base path key must not be empty")
	}
	if err := tcontext.Set(ctx, originKey, parsed.Scheme+"://"+parsed.Host); err != nil {
		return err
	}
	return tcontext.Set(ctx, basePathKey, basePath)
}
