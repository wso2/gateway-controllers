/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package semanticmodelrouting

import (
	"encoding/json"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func providerTestParams() map[string]interface{} {
	return map[string]interface{}{
		"defaultModel":      "fallback-model",
		"defaultProvider":   "fallback-provider",
		"contentPath":       "$.messages[-1].content",
		"requestModel":      map[string]interface{}{"location": "payload", "identifier": "$.model"},
		"embeddingProvider": "OPENAI", "embeddingEndpoint": "https://example.invalid", "embeddingModel": "embedder", "apiKey": "embedding-key",
		"routes": []interface{}{
			map[string]interface{}{"model": "shared-model", "provider": "provider-a", "utterances": []interface{}{"coding"}},
			map[string]interface{}{"model": "shared-model", "provider": "provider-b", "utterances": []interface{}{"weather"}},
		},
	}
}

func TestProviderConfiguration(t *testing.T) {
	for _, field := range []string{"route", "defaultProvider"} {
		for _, tc := range []struct {
			name    string
			value   interface{}
			omit    bool
			want    string
			invalid bool
		}{
			{name: "omitted", omit: true}, {name: "empty", value: ""}, {name: "whitespace", value: "  "},
			{name: "alias", value: " provider-a ", want: "provider-a"},
			{name: "number", value: 42, invalid: true}, {name: "null", value: nil, invalid: true},
			{name: "object", value: map[string]interface{}{}, invalid: true},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				params := providerTestParams()
				values, key, errorField := params, "defaultProvider", "defaultProvider"
				if field == "route" {
					values = params["routes"].([]interface{})[0].(map[string]interface{})
					key, errorField = "provider", "routes[0].provider"
				}
				if tc.omit {
					delete(values, key)
				} else {
					values[key] = tc.value
				}
				p := &SemanticModelRoutingPolicy{}
				err := parseParams(params, p)
				if tc.invalid {
					if err == nil || !strings.Contains(err.Error(), errorField) {
						t.Fatalf("expected error for %s, got %v", errorField, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				got := p.defaultProvider
				if field == "route" {
					got = p.routes[0].Provider
				}
				if got != tc.want {
					t.Fatalf("provider = %q, want %q", got, tc.want)
				}
			})
		}
	}
}

func assertProviderAction(t *testing.T, action policy.RequestAction, req *policy.RequestContext, model, provider string) {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("unexpected action %T", action)
	}
	if provider == "" {
		if mods.UpstreamName != nil {
			t.Fatalf("unexpected upstream %q", *mods.UpstreamName)
		}
		if _, exists := req.Metadata["selected_provider"]; exists {
			t.Fatal("unexpected provider metadata")
		}
	} else {
		if mods.UpstreamName == nil || *mods.UpstreamName != provider {
			t.Fatalf("upstream = %v, want %s", mods.UpstreamName, provider)
		}
		if req.Metadata["selected_provider"] != provider {
			t.Fatalf("provider metadata = %v", req.Metadata)
		}
	}
	if model != "" {
		var body map[string]interface{}
		if err := json.Unmarshal(mods.Body, &body); err != nil {
			t.Fatal(err)
		}
		if body["model"] != model {
			t.Fatalf("model = %v, want %s", body["model"], model)
		}
		if _, exists := body["messages"]; !exists {
			t.Fatal("model rewrite lost messages")
		}
	}
}

func TestProviderNotAppliedOnInvalidPayload(t *testing.T) {
	p := &SemanticModelRoutingPolicy{requestModel: RequestModelConfig{Location: "payload", Identifier: "$.model"}}
	for _, body := range []string{"not-json", "null", "[]"} {
		t.Run(body, func(t *testing.T) {
			req := &policy.RequestContext{SharedContext: &policy.SharedContext{}}
			mods := p.modifyRequestModel(req, []byte(body), modelTarget{Model: "target", Provider: "provider-a"}).(policy.UpstreamRequestModifications)
			if mods.Body != nil || mods.UpstreamName != nil || len(req.Metadata) != 0 {
				t.Fatalf("invalid body changed routing: %+v", mods)
			}
		})
	}
}

func TestOmittedProviderPreservesPreviousRouting(t *testing.T) {
	p := &SemanticModelRoutingPolicy{requestModel: RequestModelConfig{Location: "payload", Identifier: "$.model"}}
	req := &policy.RequestContext{SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{"selected_provider": "earlier-provider"}}}
	mods := p.modifyRequestModel(req, []byte(`{"model":"old","messages":[]}`), modelTarget{Model: "target"}).(policy.UpstreamRequestModifications)
	if mods.UpstreamName != nil || req.Metadata["selected_provider"] != "earlier-provider" {
		t.Fatal("omitted provider changed prior routing")
	}
}

func TestOnRequestBody_ProviderRouting(t *testing.T) {
	for _, tc := range []struct {
		name, prompt, wantModel, wantProvider string
		omitRoute, omitDefault                bool
	}{
		{name: "first provider", prompt: "coding", wantModel: "shared-model", wantProvider: "provider-a"},
		{name: "same model second provider", prompt: "weather", wantModel: "shared-model", wantProvider: "provider-b"},
		{name: "matched primary ignores fallback provider", prompt: "coding", omitRoute: true, wantModel: "shared-model"},
		{name: "below threshold fallback", prompt: "unknown", wantModel: "fallback-model", wantProvider: "fallback-provider"},
		{name: "embedding failure fallback", prompt: "failure", wantModel: "fallback-model", wantProvider: "fallback-provider"},
		{name: "nil embedding fallback", prompt: "nil", wantModel: "fallback-model", wantProvider: "fallback-provider"},
		{name: "blank prompt fallback", prompt: "  ", wantModel: "fallback-model", wantProvider: "fallback-provider"},
		{name: "missing prompt fallback", prompt: "missing", wantModel: "fallback-model", wantProvider: "fallback-provider"},
		{name: "empty body preserves upstream", prompt: "empty"},
		{name: "legacy fallback", prompt: "unknown", omitDefault: true, wantModel: "fallback-model"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer embedding-key" {
					t.Error("embedding credentials changed")
				}
				var request struct {
					Input string `json:"input"`
					Model string `json:"model"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if request.Model != "embedder" {
					t.Errorf("embedding model = %q", request.Model)
				}
				if request.Input == "failure" {
					w.WriteHeader(500)
					return
				}
				var vector []float32
				switch request.Input {
				case "coding":
					vector = []float32{1, 0}
				case "weather":
					vector = []float32{0, 1}
				case "nil":
				default:
					vector = []float32{-1, -1}
				}
				json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{map[string]interface{}{"embedding": vector, "index": 0}}})
			}))
			defer server.Close()
			params := providerTestParams()
			params["embeddingEndpoint"] = server.URL
			if tc.omitRoute {
				delete(params["routes"].([]interface{})[0].(map[string]interface{}), "provider")
			}
			if tc.omitDefault {
				delete(params, "defaultProvider")
			}
			impl, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"model":"old","messages":[{"content":%q}]}`, tc.prompt)
			if tc.prompt == "missing" {
				body = `{"model":"old","messages":[]}`
			}
			if tc.prompt == "empty" {
				body = ""
			}
			req := &policy.RequestContext{SharedContext: &policy.SharedContext{}, Body: &policy.Body{Content: []byte(body)}}
			action := impl.(*SemanticModelRoutingPolicy).OnRequestBody(t.Context(), req, nil)
			assertProviderAction(t, action, req, tc.wantModel, tc.wantProvider)
		})
	}
}

// A configured fallback must not redirect a bodyless request or overwrite an
// earlier router's metadata. Nil clients also ensure no classification call occurs.
func TestEmptyBodyPreservesRouting(t *testing.T) {
	for _, body := range []struct {
		name  string
		value *policy.Body
	}{
		{name: "absent"},
		{name: "nil content", value: &policy.Body{Present: true}},
		{name: "empty content", value: &policy.Body{Present: true, Content: []byte{}}},
	} {
		for _, prior := range []string{"", "earlier-provider"} {
			t.Run(body.name+"/"+prior, func(t *testing.T) {
				p := &SemanticModelRoutingPolicy{defaultModel: "fallback-model", defaultProvider: "fallback-provider",
					requestModel: RequestModelConfig{Location: "payload", Identifier: "$.model"}}
				var metadata map[string]interface{}
				var want map[string]interface{}
				if prior != "" {
					metadata = map[string]interface{}{"selected_provider": prior, "other": "retained"}
					want = map[string]interface{}{"selected_provider": prior, "other": "retained"}
				}
				req := &policy.RequestContext{SharedContext: &policy.SharedContext{Metadata: metadata}, Body: body.value}
				mods := p.OnRequestBody(t.Context(), req, nil).(policy.UpstreamRequestModifications)
				if !reflect.DeepEqual(mods, policy.UpstreamRequestModifications{}) {
					t.Fatalf("empty body modified request: %+v", mods)
				}
				if !reflect.DeepEqual(req.Metadata, want) {
					t.Fatalf("metadata changed: %#v", req.Metadata)
				}
				// The modification helper must also refuse a provider-only override.
				mods = p.modifyRequestModel(req, nil, p.defaultTarget()).(policy.UpstreamRequestModifications)
				if !reflect.DeepEqual(mods, policy.UpstreamRequestModifications{}) || !reflect.DeepEqual(req.Metadata, want) {
					t.Fatal("empty-body helper changed routing")
				}
			})
		}
	}
}
