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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/retry"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

func (s *Steps) registerRouting(sc *godog.ScenarioContext) {
	sc.Step(`^the response should be served by the "(backend|echo)" testbench service$`, s.servedBy)
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" until the JSON field "([^"]*)" is "([^"]*)"$`,
		s.sendUntilJSONField)
	sc.Step(`^the JSON response field "([^"]*)", if present, should start with "([^"]*)"$`, s.fieldStartsWithIfPresent)
}

// fieldStartsWithIfPresent checks where a reflected request came from without requiring the
// request to have been answered. A request the gateway refuses or does not route has no such
// field, which is a fine outcome for an attack that must not reach another upstream; a request
// that is answered must carry the expected prefix. Asserting the absence of a word instead
// would trip over the attacker's own text, which the reflecting upstream echoes back.
func (s *Steps) fieldStartsWithIfPresent(ctx context.Context, field, prefix string) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	expected, err := stepscommon.Expand(ctx, prefix)
	if err != nil {
		return err
	}
	got, present := jsonField(resp.Body, field)
	if !present {
		return nil
	}
	if !strings.HasPrefix(got, expected) {
		return fmt.Errorf("JSON field %q is %q, which does not start with %q: %s", field, got, expected, resp.Describe())
	}
	return nil
}

// jsonField reads a dotted path from a JSON object. A string is returned as is and any other
// scalar in its JSON text form, so a number reads as 201 and not 201.0.
func jsonField(body []byte, path string) (string, bool) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", false
	}
	for _, key := range strings.Split(path, ".") {
		object, ok := doc.(map[string]any)
		if !ok {
			return "", false
		}
		if doc, ok = object[key]; !ok {
			return "", false
		}
	}
	switch value := doc.(type) {
	case string:
		return value, true
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case nil:
		return "null", true
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", false
		}
		return string(encoded), true
	}
}

// servedBy tells the two reflecting testbench upstreams apart by the shape of their JSON. The
// echo service always reports the request "url"; the backend service never does. A scenario
// that points two upstream definitions at port 3000 and port 3002 uses it to prove the request
// reached the other service, and not only another path on the same one.
func (s *Steps) servedBy(ctx context.Context, service string) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return fmt.Errorf("response is not a JSON object: %w (%s)", err, resp.Describe())
	}
	_, hasURL := doc["url"]
	_, hasMethod := doc["method"]
	switch service {
	case "echo":
		if !hasURL {
			return fmt.Errorf("expected the echo service to have answered, but the body has no \"url\": %s", resp.Describe())
		}
	case "backend":
		if hasURL || !hasMethod {
			return fmt.Errorf("expected the backend service to have answered, got %s", resp.Describe())
		}
	default:
		return fmt.Errorf("unknown testbench service %q", service)
	}
	return nil
}

// sendUntilJSONField polls a data-plane path until a JSON field of the response has the wanted
// value. A configuration change reaches the router after the update call has returned, so a
// scenario that changes routing waits for the new routing here instead of sleeping.
func (s *Steps) sendUntilJSONField(ctx context.Context, method, path, field, want string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	expected, err := stepscommon.Expand(ctx, want)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	headers := s.base.ScenarioHeaders(ctx)
	host := s.base.RequestHost(ctx)

	return stepscommon.AwaitResponse(ctx,
		func(ctx context.Context) (*httpx.Response, error) {
			response, sendErr := s.funnel.Send(ctx, httpx.Request{
				Method: strings.ToUpper(method), URL: target, Headers: headers, Host: host,
			})
			if sendErr != nil {
				return nil, retry.Transient(sendErr)
			}
			return response, nil
		},
		func(r *httpx.Response) bool {
			if r == nil || !r.Succeeded() {
				return false
			}
			got, present := jsonField(r.Body, field)
			return present && got == expected
		},
		fmt.Sprintf("waiting for %s %s to answer with JSON field %q equal to %q", method, resolved, field, expected))
}
