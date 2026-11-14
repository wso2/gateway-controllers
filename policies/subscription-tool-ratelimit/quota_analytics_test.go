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

package subscriptiontoolratelimit

import (
	"context"
	"reflect"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// analyticsOf returns the analytics metadata of a header- or body-phase action.
func analyticsOf(t *testing.T, action interface{}) map[string]any {
	t.Helper()
	switch a := action.(type) {
	case policy.UpstreamRequestHeaderModifications:
		return a.AnalyticsMetadata
	case policy.UpstreamRequestModifications:
		return a.AnalyticsMetadata
	case policy.ImmediateResponse:
		return a.AnalyticsMetadata
	case nil:
		return nil
	default:
		t.Fatalf("unexpected action %#v", action)
		return nil
	}
}

func assertToolAnalytics(t *testing.T, action interface{}, want map[string]any) {
	t.Helper()
	if got := analyticsOf(t, action); !reflect.DeepEqual(got, want) {
		t.Fatalf("analytics metadata = %#v, want %#v", got, want)
	}
}

var (
	toolWithin = map[string]any{"x-wso2-subscription-quota-status-tool-calls": "within"}
	toolOver   = func(action string) map[string]any {
		return map[string]any{
			"x-wso2-subscription-quota-status-tool-calls": "over",
			"x-wso2-subscription-quota-action-tool-calls": action,
			"x-wso2-subscription-quota-limit-tool-calls":  "1 tool calls per 1 hour",
		}
	}
)

func TestToolQuotaStatusBodyPath(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	first := p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)
	assertToolAnalytics(t, first, toolWithin)
	second := p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, toolCall), nil)
	if _, isBlocked := blocked(second); !isBlocked {
		t.Fatalf("second tool call should be rejected")
	}
	assertToolAnalytics(t, second, toolOver("rejected"))
}

func TestToolQuotaStatusHeaderPathAllow(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "allow")
	first := p.OnRequestHeaders(context.Background(), modernRequest(t, "sub-1", conds, "tools/call"), nil)
	assertToolAnalytics(t, first, toolWithin)
	second := p.OnRequestHeaders(context.Background(), modernRequest(t, "sub-1", conds, "tools/call"), nil)
	if _, isBlocked := blocked(second); isBlocked {
		t.Fatalf("onExceed allow must let the call through")
	}
	assertToolAnalytics(t, second, toolOver("allowed"))
}

func TestToolQuotaStatusNotSetForUncountedMethods(t *testing.T) {
	p := newPolicy(t)
	conds := toolConditions(1, "reject")
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`,
	} {
		assertToolAnalytics(t, p.OnRequestBody(context.Background(), bodyRequest(t, "sub-1", conds, body), nil), nil)
	}
	assertToolAnalytics(t, p.OnRequestHeaders(context.Background(), modernRequest(t, "sub-1", conds, "tools/list"), nil), nil)
}
