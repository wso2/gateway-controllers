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
 */

package semanticpromptguard

import (
	"strings"
	"testing"

	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
)

const testClientID = "11111111-2222-3333-4444-555555555555"

func TestReadAzureAuth(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]interface{}
		want    authentication
		wantErr string
	}{
		{name: "absent", params: map[string]interface{}{}, want: authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}},
		{name: "nil", params: map[string]interface{}{"azureAuth": nil}, want: authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}},
		{name: "empty object", params: map[string]interface{}{"azureAuth": map[string]interface{}{}}, want: authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}},
		{
			name: "api-key ignores leftover identity fields",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": "api-key", "clientId": "x", "scope": "y",
			}},
			want: authentication{typ: embeddingproviders.AuthenticationTypeAPIKey},
		},
		{
			name:   "workload identity gets the default scope",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{"authenticationType": "workload-identity"}},
			want:   authentication{typ: "workload-identity", tokenScope: embeddingproviders.DefaultTokenScope},
		},
		{
			name: "custom scope kept and fields trimmed",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": " managed-identity ", "clientId": " " + testClientID + " ", "scope": " https://x.example/.default ",
			}},
			want: authentication{typ: "managed-identity", clientID: testClientID, tokenScope: "https://x.example/.default"},
		},
		{name: "not an object", params: map[string]interface{}{"azureAuth": "x"}, wantErr: "'azureAuth' must be an object"},
		{
			name:    "unknown type",
			params:  map[string]interface{}{"azureAuth": map[string]interface{}{"authenticationType": "bogus"}},
			wantErr: "'azureAuth.authenticationType' must be",
		},
		{
			name: "client ID not a GUID",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": "managed-identity", "clientId": "nope",
			}},
			wantErr: "'azureAuth.clientId' is invalid",
		},
		{
			name: "scope without /.default",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": "workload-identity", "scope": "https://x.example",
			}},
			wantErr: "'azureAuth.scope' is invalid",
		},
		{
			name:    "non-string field",
			params:  map[string]interface{}{"azureAuth": map[string]interface{}{"authenticationType": 3}},
			wantErr: "must be a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAzureAuth(tt.params)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCheckAllowedType(t *testing.T) {
	list := func(entries ...interface{}) map[string]interface{} {
		return map[string]interface{}{allowedAuthTypesParam: entries}
	}
	tests := []struct {
		name    string
		params  map[string]interface{}
		typ     string
		wantErr string
	}{
		{name: "absent list", params: map[string]interface{}{}, typ: "api-key"},
		{name: "empty list", params: list(), typ: "workload-identity"},
		{name: "listed type", params: list("workload-identity"), typ: "workload-identity"},
		{name: "unlisted type", params: list("workload-identity"), typ: "api-key", wantErr: "is not allowed on this gateway"},
		{name: "bad entry beside a match", params: list("api-key", "bogus"), typ: "api-key", wantErr: "is not an authentication type"},
		{name: "not an array", params: map[string]interface{}{allowedAuthTypesParam: "api-key"}, typ: "api-key", wantErr: "must be an array of strings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAllowedType(tt.params, tt.typ)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckAllowedEndpoint(t *testing.T) {
	const e = "https://res.openai.azure.com/openai/deployments/d/embeddings?api-version=2024-10-21"
	tests := []struct {
		name     string
		entries  []string
		endpoint string
		wantErr  string
	}{
		{name: "no list", endpoint: e},
		{name: "resource listed", entries: []string{"https://res.openai.azure.com"}, endpoint: e},
		{name: "other deployment, same resource", entries: []string{"https://res.openai.azure.com"}, endpoint: "https://res.openai.azure.com/openai/deployments/other/embeddings?api-version=2025-01-01"},
		{name: "trailing slash", entries: []string{"https://res.openai.azure.com/"}, endpoint: e},
		{name: "upper case", entries: []string{"HTTPS://Res.OpenAI.Azure.com"}, endpoint: e},
		{name: "default port", entries: []string{"https://res.openai.azure.com:443"}, endpoint: e},
		{name: "http default port", entries: []string{"http://testbench:80"}, endpoint: "http://testbench/openai/deployments/d/embeddings?api-version=x"},
		{name: "other host", entries: []string{"https://other.openai.azure.com"}, endpoint: e, wantErr: "is not allowed on this gateway"},
		{name: "other port", entries: []string{"http://testbench:3004"}, endpoint: "http://testbench:3002/openai/deployments/d/embeddings?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "other scheme", entries: []string{"http://res.openai.azure.com"}, endpoint: e, wantErr: "is not allowed on this gateway"},
		{name: "endpoint is not a URL", entries: []string{"https://res.openai.azure.com"}, endpoint: "not a url", wantErr: "is not allowed on this gateway"},
		{name: "userinfo before another host", entries: []string{"https://res.openai.azure.com"}, endpoint: "https://res.openai.azure.com@evil.example/openai/deployments/d/embeddings?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "unicode look-alike host", entries: []string{"https://myai.openai.azure.com"}, endpoint: "https://myaİ.openai.azure.com/openai/deployments/d/embeddings?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "non-ASCII entry", entries: []string{"https://myaİ.openai.azure.com"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry with path", entries: []string{"https://res.openai.azure.com/openai"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry with query", entries: []string{"https://res.openai.azure.com?x=1"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry with fragment", entries: []string{"https://res.openai.azure.com#f"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry not absolute", entries: []string{"res.openai.azure.com"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "bad entry beside a match", entries: []string{"https://res.openai.azure.com", "ftp://x"}, endpoint: e, wantErr: "is not a resource URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]interface{}{}
			if tt.entries != nil {
				params[allowedEndpointsParam] = tt.entries
			}
			err := checkAllowedEndpoint(params, tt.endpoint)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
