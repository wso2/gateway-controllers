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

package semanticcache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/wso2/api-platform/sdk/ai/azureauthentication"
	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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

// captureLogs routes slog.Default() to a JSON buffer for the test and restores it afterwards.
// Tests that use it must not run in parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]interface{} {
	t.Helper()
	var records []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

func runTokenFailure(t *testing.T, embedErr error) (policy.RequestAction, *policy.RequestContext, []map[string]interface{}) {
	t.Helper()
	return runEmbeddingFailure(t, authentication{typ: "container-apps", tokenScope: embeddingproviders.DefaultTokenScope}, embedErr)
}

func runEmbeddingFailure(t *testing.T, auth authentication, embedErr error) (policy.RequestAction, *policy.RequestContext, []map[string]interface{}) {
	t.Helper()
	buf := captureLogs(t)
	p := &SemanticCachePolicy{
		embeddingProvider:   &mockEmbeddingProvider{getEmbeddingFn: func(string) ([]float32, error) { return nil, embedErr }},
		vectorStoreProvider: &mockVectorDBProvider{},
		threshold:           0.5,
		auth:                auth,
	}
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Content: []byte("hello"), Present: true},
	}
	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	return action, reqCtx, logRecords(t, buf)
}

func assertFailsOpen(t *testing.T, action policy.RequestAction, reqCtx *policy.RequestContext) {
	t.Helper()
	got, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if !reflect.DeepEqual(got, policy.UpstreamRequestModifications{}) {
		t.Fatalf("expected empty modifications, got %+v", got)
	}
	if _, ok := reqCtx.Metadata[MetadataKeyEmbedding]; ok {
		t.Fatalf("no embedding should be stored")
	}
}

func tokenErr(cached bool) error {
	return fmt.Errorf("could not obtain an access token for the embedding provider: %w",
		&azureauthentication.TokenError{Reason: "Azure Container Apps answered 400", Cached: cached})
}

func TestOnRequestBodyTokenFailureLogsErrorAndFailsOpen(t *testing.T) {
	action, reqCtx, recs := runTokenFailure(t, tokenErr(false))
	assertFailsOpen(t, action, reqCtx)
	if len(recs) != 1 {
		t.Fatalf("expected one log record, got %d: %v", len(recs), recs)
	}
	rec := recs[0]
	want := map[string]interface{}{
		"level":              "ERROR",
		"msg":                "SemanticCache: could not obtain an access token for the embedding provider",
		"reason":             "Azure Container Apps answered 400",
		"authenticationType": "container-apps",
		"clientId":           "host-default",
		"scope":              embeddingproviders.DefaultTokenScope,
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %v, want %v", k, rec[k], v)
		}
	}
}

func TestOnRequestBodyCachedTokenFailureLogsAtDebug(t *testing.T) {
	action, reqCtx, recs := runTokenFailure(t, tokenErr(true))
	assertFailsOpen(t, action, reqCtx)
	if len(recs) != 1 || recs[0]["level"] != "DEBUG" {
		t.Fatalf("expected one DEBUG record, got %v", recs)
	}
}

func TestOnRequestBodyOtherEmbeddingErrorsStayAtDebug(t *testing.T) {
	action, reqCtx, recs := runTokenFailure(t, errors.New("status 500"))
	assertFailsOpen(t, action, reqCtx)
	if len(recs) != 1 {
		t.Fatalf("expected one record, got %v", recs)
	}
	if recs[0]["level"] != "DEBUG" || recs[0]["msg"] != "SemanticCache: Error generating embedding" {
		t.Fatalf("unexpected record %v", recs[0])
	}
}

// refusedBody stands for Azure OpenAI's answer to a refused token, which must stay out of the logs.
const refusedBody = `{"error":{"code":"PermissionDenied","message":"refused-body-marker"}}`

func errorRecords(recs []map[string]interface{}) []map[string]interface{} {
	var errs []map[string]interface{}
	for _, rec := range recs {
		if rec["level"] == "ERROR" {
			errs = append(errs, rec)
		}
	}
	return errs
}

func TestOnRequestBodyRefusedTokenLogsErrorAndFailsOpen(t *testing.T) {
	auth := authentication{typ: azureauthentication.WorkloadIdentity, clientID: testClientID, tokenScope: embeddingproviders.DefaultTokenScope}
	action, reqCtx, recs := runEmbeddingFailure(t, auth, &embeddingproviders.StatusError{StatusCode: 403, Body: refusedBody})
	assertFailsOpen(t, action, reqCtx)
	errs := errorRecords(recs)
	if len(errs) != 1 {
		t.Fatalf("expected one ERROR record, got %v", recs)
	}
	want := map[string]interface{}{
		"msg":                "SemanticCache: the embedding provider refused the access token",
		"status":             float64(403),
		"authenticationType": azureauthentication.WorkloadIdentity,
		"clientId":           testClientID,
		"scope":              embeddingproviders.DefaultTokenScope,
	}
	for k, v := range want {
		if errs[0][k] != v {
			t.Errorf("%s = %v, want %v", k, errs[0][k], v)
		}
	}
	logged, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), "refused-body-marker") {
		t.Fatalf("the response body was logged: %s", logged)
	}
}

func TestOnRequestBodyRefusedTokenWithoutClientIDNamesTheDefault(t *testing.T) {
	auth := authentication{typ: "container-apps", tokenScope: embeddingproviders.DefaultTokenScope}
	_, _, recs := runEmbeddingFailure(t, auth, fmt.Errorf("wrapped: %w", &embeddingproviders.StatusError{StatusCode: 401, Body: refusedBody}))
	errs := errorRecords(recs)
	if len(errs) != 1 || errs[0]["status"] != float64(401) || errs[0]["clientId"] != "host-default" {
		t.Fatalf("expected one ERROR record for 401 naming host-default, got %v", recs)
	}
}

func TestOnRequestBodyIdentityServerErrorStaysAtDebug(t *testing.T) {
	auth := authentication{typ: azureauthentication.WorkloadIdentity, tokenScope: embeddingproviders.DefaultTokenScope}
	action, reqCtx, recs := runEmbeddingFailure(t, auth, &embeddingproviders.StatusError{StatusCode: 500, Body: "boom"})
	assertFailsOpen(t, action, reqCtx)
	if errs := errorRecords(recs); len(errs) != 0 {
		t.Fatalf("expected no ERROR record, got %v", errs)
	}
	if len(recs) != 1 || recs[0]["msg"] != "SemanticCache: Error generating embedding" {
		t.Fatalf("expected the DEBUG embedding line, got %v", recs)
	}
}

func TestOnRequestBodyAPIKeyRefusedStaysAtDebug(t *testing.T) {
	auth := authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}
	action, reqCtx, recs := runEmbeddingFailure(t, auth, &embeddingproviders.StatusError{StatusCode: 401, Body: refusedBody})
	assertFailsOpen(t, action, reqCtx)
	if errs := errorRecords(recs); len(errs) != 0 {
		t.Fatalf("expected no ERROR record, got %v", errs)
	}
	if len(recs) != 1 || recs[0]["level"] != "DEBUG" || recs[0]["msg"] != "SemanticCache: Error generating embedding" {
		t.Fatalf("expected the DEBUG embedding line, got %v", recs)
	}
}
