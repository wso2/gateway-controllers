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

package openaitoazureopenai

import (
	"context"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_RequiresAPIVersion(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"model": "gpt-4o"}); err == nil {
		t.Fatal("expected error when 'apiVersion' param is missing")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"apiVersion": "2024-02-15-preview",
		"model":      "gpt-4o",
		"providerId": "azure-openai-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
}

func TestBuildAzurePath(t *testing.T) {
	got := buildAzurePath("gpt-4o", DefaultPathSuffix, "2024-02-15-preview")
	want := "/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview"
	if got != want {
		t.Errorf("buildAzurePath = %q, want %q", got, want)
	}
}

func TestParseParams_PathSuffixLeadingSlash(t *testing.T) {
	// A pathSuffix without a leading slash must be normalised so buildAzurePath
	// concatenates cleanly.
	p, err := parseParams(map[string]interface{}{
		"apiVersion": "2024-02-15-preview",
		"model":      "gpt-4o",
		"pathSuffix": "embeddings",
	})
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	if p.PathSuffix != "/embeddings" {
		t.Errorf("expected normalised pathSuffix '/embeddings', got %q", p.PathSuffix)
	}
}

func TestReadModelFromBody(t *testing.T) {
	reqCtx := &policy.RequestContext{
		Body: &policy.Body{Present: true, Content: []byte(`{"model":"gpt-4o-mini","messages":[]}`)},
	}
	raw, present := readModelFromBody(reqCtx)
	if !present || raw != "gpt-4o-mini" {
		t.Errorf("expected model read from body 'gpt-4o-mini', got %v (present=%v)", raw, present)
	}
	// An absent body names no model at all — distinct from naming an empty one.
	if raw, present := readModelFromBody(&policy.RequestContext{}); present || raw != nil {
		t.Errorf("expected no model for missing body, got %v (present=%v)", raw, present)
	}
	// A non-string is returned as-is so the caller can reject rather than coerce it.
	raw, present = readModelFromBody(&policy.RequestContext{
		Body: &policy.Body{Present: true, Content: []byte(`{"model":123}`)},
	})
	if !present {
		t.Error("expected a non-string model to be reported as present")
	}
	if _, isString := raw.(string); isString {
		t.Errorf("expected a non-string model to survive as non-string, got %T", raw)
	}
}

// TestBuildAzurePath_EscapesUntrustedDeployment verifies the deployment id —
// which may come from the request body's "model" field — cannot inject extra
// path segments or query parameters into the Azure URL.
func TestBuildAzurePath_EscapesUntrustedDeployment(t *testing.T) {
	got := buildAzurePath("evil?api-version=hacked&x=", DefaultPathSuffix, "2024-02-15-preview")
	if strings.Contains(got, "?api-version=hacked") {
		t.Errorf("query injection via deployment not escaped: %s", got)
	}
	got = buildAzurePath("a/../../b", DefaultPathSuffix, "2024-02-15-preview")
	if strings.Contains(got, "/../") {
		t.Errorf("path traversal via deployment not escaped: %s", got)
	}
}

func newReqCtx(body string, metadata map[string]interface{}) *policy.RequestContext {
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
	}
	if body != "" {
		ctx.Body = &policy.Body{Present: true, Content: []byte(body)}
	}
	return ctx
}

func TestOnRequestBody_RewritesPathAndSetsUpstream(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{
		APIVersion: "2024-02-15-preview",
		Model:      "gpt-4o",
		PathSuffix: DefaultPathSuffix,
		ProviderID: "azure-openai-provider",
	}}
	action := p.OnRequestBody(context.Background(), newReqCtx(`{"messages":[]}`, map[string]interface{}{}), nil)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview"
	if mods.Path == nil || *mods.Path != want {
		t.Errorf("expected path %q, got %v", want, mods.Path)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "azure-openai-provider" {
		t.Errorf("expected UpstreamName azure-openai-provider, got %v", mods.UpstreamName)
	}
}

// TestOnRequestBody_MissingDeploymentErrors covers the case where neither the
// policy param nor the request body supplies a model to use as the deployment.
func TestOnRequestBody_MissingDeploymentErrors(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{APIVersion: "2024-02-15-preview", PathSuffix: DefaultPathSuffix}}
	action := p.OnRequestBody(context.Background(), newReqCtx(`{"messages":[]}`, map[string]interface{}{}), nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestShouldRun_RoutingGates covers single-provider mode (no selection -> run)
// and multi-provider mode (run only on a matching selected_provider).
func TestShouldRun_RoutingGates(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{ProviderID: "azure-openai-provider"}}

	if !p.shouldRun(newReqCtx("", map[string]interface{}{})) {
		t.Error("single-provider mode (no selected_provider): expected to run")
	}
	if !p.shouldRun(newReqCtx("", map[string]interface{}{"selected_provider": "azure-openai-provider"})) {
		t.Error("matching selected_provider: expected to run")
	}
	if !p.shouldRun(newReqCtx("", map[string]interface{}{"selected_provider": "AZURE-OPENAI-PROVIDER"})) {
		t.Error("selected_provider match must be case-insensitive")
	}
	if p.shouldRun(newReqCtx("", map[string]interface{}{"selected_provider": "gemini-provider"})) {
		t.Error("non-matching selected_provider: expected to be skipped")
	}
}

// TestResolveDeployment covers every row of the resolution table. Azure OpenAI
// resolved configuration-first until the payload-first rule was adopted for all
// five policies, and it coerced a non-string model to "" rather than rejecting
// it.
func TestResolveDeployment(t *testing.T) {
	const configured = "gpt-4o"
	const requested = "gpt-4o-mini"

	cases := []struct {
		name           string
		configured     string
		body           string // empty means no body at all
		wantDeployment string // empty means the request must be rejected
		wantErr        string
	}{
		{"request overrides the configured deployment", configured, `{"model":"` + requested + `"}`, requested, ""},
		{"configured deployment is the fallback when the request names none", configured, `{"messages":[]}`, configured, ""},
		{"empty request model falls back to the configured deployment", configured, `{"model":""}`, configured, ""},
		{"null request model falls back to the configured deployment", configured, `{"model":null}`, configured, ""},
		{"absent body falls back to the configured deployment", configured, "", configured, ""},
		{"unparseable body falls back to the configured deployment", configured, `not json`, configured, ""},
		{"request model used when none is configured", "", `{"model":"` + requested + `"}`, requested, ""},
		{"padded request model is trimmed, not rejected", "", `{"model":"  ` + requested + `  "}`, requested, ""},
		{"neither source supplies one", "", `{"messages":[]}`, "", "'model' is required in the request body"},
		{"whitespace-only request model is malformed", "", `{"model":"   "}`, "", "must not be blank"},
		{"whitespace-only is malformed even with a configured deployment", configured, `{"model":"   "}`, "", "must not be blank"},
		{"non-string request model is a bad request", "", `{"model":123}`, "", "must be a string"},
		{"non-string is a bad request even with a configured deployment", configured, `{"model":123}`, "", "must be a string"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{Model: tc.configured, APIVersion: "2024-02-15-preview"}}
			reqCtx := &policy.RequestContext{}
			if tc.body != "" {
				reqCtx.Body = &policy.Body{Present: true, Content: []byte(tc.body)}
			}
			got, err := p.resolveDeployment(reqCtx)

			if tc.wantDeployment == "" {
				if err == nil {
					t.Fatalf("expected rejection, got deployment %q", got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantDeployment {
				t.Errorf("resolved deployment = %q, want %q", got, tc.wantDeployment)
			}
		})
	}
}

// TestErrResponseDirectionAndCode covers what this translator refuses and how it labels it.
//
// Direction is the point: a payload the caller sent that will not convert is a
// request-side refusal, while a provider reply that will not translate back is a
// response-side one. They share a helper and nothing else, and only the caller knows which
// it made — so it is passed in rather than inferred from the status.
func TestErrResponseDirectionAndCode(t *testing.T) {
	t.Run("request side", func(t *testing.T) {
		resp := errResponse(400, "Request body is empty.",
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a refused request")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeInvalidRequestBody {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeInvalidRequestBody, resp.Fault.Code)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
		if resp.Fault.Type != policy.FaultTypeValidation {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeValidation, resp.Fault.Type)
		}
	})

	t.Run("response side", func(t *testing.T) {
		resp := errResponse(500, "failed to translate response",
			policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a failed translation")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeMediationFailed {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
		}
		if resp.Fault.Direction != policy.DirectionResponse {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionResponse, resp.Fault.Direction)
		}
	})
}
