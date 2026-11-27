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
	"io"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

func (s *Steps) registerDataPlane(sc *godog.ScenarioContext) {
	sc.Step(`^the response should be a server error$`, s.responseServerError)
	sc.Step(`^I generate a (\d+)-character value from "([^"]*)" and store it as "([^"]*)"$`, s.generateSizedValue)
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" expecting rejection$`, s.sendRequestExpectingRejection)
	s.registerConcurrentRequests(sc)
}

func (s *Steps) responseServerError(ctx context.Context) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode < 500 || resp.StatusCode >= 600 {
		return fmt.Errorf("expected a server error response, got %s", resp.Describe())
	}
	return nil
}

func (s *Steps) generateSizedValue(ctx context.Context, size int, seed, key string) error {
	if size <= 0 {
		return fmt.Errorf("sized value length must be positive, got %d", size)
	}
	resolvedSeed, err := stepscommon.Expand(ctx, seed)
	if err != nil {
		return err
	}
	if resolvedSeed == "" {
		return fmt.Errorf("sized value seed must not be empty")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("cannot store a sized value with an empty key")
	}
	repeated := strings.Repeat(resolvedSeed, size/len(resolvedSeed)+1)[:size]
	return tcontext.Set(ctx, key, repeated)
}

// sendRequestExpectingRejection accepts a client error or a connection the gateway ended before
// answering. Any other transport failure fails the step, so a hung gateway is not taken for a
// rejecting one.
func (s *Steps) sendRequestExpectingRejection(ctx context.Context, method, path string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	resp, err := s.funnel.Send(ctx, httpx.Request{
		Method:  strings.ToUpper(method),
		URL:     target,
		Headers: s.base.ScenarioHeaders(ctx),
		Host:    s.base.RequestHost(ctx),
	})
	if err == nil {
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			return fmt.Errorf("expected the gateway to reject the request, got %s", resp.Describe())
		}
		return nil
	}
	if isConnectionRejection(err) {
		return nil
	}
	return fmt.Errorf("invoking %s %s: %w", method, target, err)
}

func isConnectionRejection(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset")
}

// tableRows returns the two cells of each row of a two-column table.
func tableRows(table *godog.Table) ([][2]string, error) {
	if table == nil || len(table.Rows) == 0 {
		return nil, fmt.Errorf("table must not be empty")
	}
	rows := make([][2]string, 0, len(table.Rows))
	for i, row := range table.Rows {
		if row == nil || len(row.Cells) != 2 {
			return nil, fmt.Errorf("table row %d must contain exactly two cells", i+1)
		}
		rows = append(rows, [2]string{row.Cells[0].Value, row.Cells[1].Value})
	}
	return rows, nil
}
