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

package semanticmodelrouting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
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

// recordsAt returns the records logged at level (DEBUG, INFO, WARN or ERROR).
func recordsAt(recs []map[string]interface{}, level string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, rec := range recs {
		if rec["level"] == level {
			out = append(out, rec)
		}
	}
	return out
}

// mentioning returns the records whose JSON contains text anywhere.
func mentioning(t *testing.T, recs []map[string]interface{}, text string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, rec := range recs {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if strings.Contains(string(b), text) {
			out = append(out, rec)
		}
	}
	return out
}

const (
	tokenReason   = "Azure Container Apps answered 400"
	refusedAnswer = "audience is incorrect for client 1111"
	fallbackMsg   = "SemanticModelRouting: Failed to compute request embedding, using default model"
	noTokenMsg    = "SemanticModelRouting: could not obtain an access token for the embedding provider"
	refusedMsg    = "SemanticModelRouting: the embedding provider refused the access token"
)

var containerAppsAuth = authentication{typ: azureauthentication.ContainerApps, clientID: testIdentityID, tokenScope: embeddingproviders.DefaultTokenScope}

func tokenErr(cached bool) error {
	return fmt.Errorf("could not obtain an access token for the embedding provider: %w",
		&azureauthentication.TokenError{Reason: tokenReason, Cached: cached})
}

type fakeEmbeddingProvider struct {
	embed func(input string) ([]float32, error)
}

func (f *fakeEmbeddingProvider) Init(embeddingproviders.EmbeddingProviderConfig) error { return nil }
func (f *fakeEmbeddingProvider) GetType() string                                       { return "AZURE_OPENAI" }
func (f *fakeEmbeddingProvider) GetEmbedding(input string) ([]float32, error)          { return f.embed(input) }
func (f *fakeEmbeddingProvider) GetEmbeddings(inputs []string) ([][]float32, error) {
	out := make([][]float32, 0, len(inputs))
	for _, in := range inputs {
		e, err := f.embed(in)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// routeWhenEmbeddingFails sends a prompt that matches the policy's one route through a policy whose
// prompt embedding fails with err, and checks that the request still goes to the default model.
func routeWhenEmbeddingFails(t *testing.T, auth authentication, err error) []map[string]interface{} {
	t.Helper()
	buf := captureLogs(t)
	p := &SemanticModelRoutingPolicy{
		routes:            []SemanticRoute{{Model: "coding-model", ScoreThreshold: 0.9, UtteranceEmbeddings: [][]float32{{1, 0}}}},
		defaultModel:      "default-model",
		contentPath:       "$.messages[-1].content",
		requestModel:      RequestModelConfig{Location: "payload", Identifier: "$.model"},
		embeddingProvider: &fakeEmbeddingProvider{embed: func(string) ([]float32, error) { return nil, err }},
		auth:              auth,
	}
	body := `{"model":"original","messages":[{"role":"user","content":"write a python function"}]}`
	req := &policy.RequestContext{SharedContext: &policy.SharedContext{}, Body: &policy.Body{Content: []byte(body)}}
	action := p.OnRequestBody(t.Context(), req, nil)
	assertProviderAction(t, action, req, "default-model", "")
	return logRecords(t, buf)
}

func TestOnRequestBodyTokenFailureLogsErrorAndUsesTheDefaultModel(t *testing.T) {
	recs := routeWhenEmbeddingFails(t, containerAppsAuth, tokenErr(false))
	errs := recordsAt(recs, "ERROR")
	if len(errs) != 1 || errs[0]["msg"] != noTokenMsg {
		t.Fatalf("expected one ERROR %q, got %v", noTokenMsg, errs)
	}
	if errs[0]["reason"] != tokenReason || errs[0]["authenticationType"] != "container-apps" || errs[0]["clientId"] != testIdentityID {
		t.Fatalf("ERROR record lacks the reason or the identity: %v", errs[0])
	}
	if warns := recordsAt(recs, "WARN"); len(warns) != 0 {
		t.Fatalf("expected no WARN, got %v", warns)
	}
}

func TestOnRequestBodyCachedTokenFailureLogsOnlyAtDebug(t *testing.T) {
	recs := routeWhenEmbeddingFails(t, containerAppsAuth, tokenErr(true))
	if loud := append(recordsAt(recs, "ERROR"), recordsAt(recs, "WARN")...); len(loud) != 0 {
		t.Fatalf("a cached failure must not log above DEBUG, got %v", loud)
	}
	found := false
	for _, rec := range recordsAt(recs, "DEBUG") {
		found = found || rec["msg"] == noTokenMsg
	}
	if !found {
		t.Fatalf("expected a DEBUG %q, got %v", noTokenMsg, recs)
	}
}

func TestOnRequestBodyRefusedTokenKeepsTheAnswerAtDebug(t *testing.T) {
	refused := &embeddingproviders.StatusError{StatusCode: 401, Body: refusedAnswer}
	recs := routeWhenEmbeddingFails(t, containerAppsAuth, fmt.Errorf("embedding: %w", refused))
	errs := recordsAt(recs, "ERROR")
	if len(errs) != 1 || errs[0]["msg"] != refusedMsg || errs[0]["status"] != float64(401) {
		t.Fatalf("expected one ERROR %q with status 401, got %v", refusedMsg, errs)
	}
	if loud := mentioning(t, append(errs, recordsAt(recs, "WARN")...), refusedAnswer); len(loud) != 0 {
		t.Fatalf("Azure's answer must stay out of ERROR and WARN, got %v", loud)
	}
	if len(mentioning(t, recordsAt(recs, "DEBUG"), refusedAnswer)) == 0 {
		t.Fatalf("expected Azure's answer at DEBUG, got %v", recs)
	}
}

// assertFailureLoggedAsBefore checks the single DEBUG line the policy has always logged for a
// failed prompt embedding, with the provider's answer in it, and nothing louder.
func assertFailureLoggedAsBefore(t *testing.T, recs []map[string]interface{}, answer string) {
	t.Helper()
	if loud := append(recordsAt(recs, "ERROR"), recordsAt(recs, "WARN")...); len(loud) != 0 {
		t.Fatalf("expected nothing above DEBUG, got %v", loud)
	}
	got := recordsAt(recs, "DEBUG")
	if len(got) != 1 || got[0]["msg"] != fallbackMsg || !strings.Contains(fmt.Sprint(got[0]["error"]), answer) {
		t.Fatalf("expected one DEBUG %q carrying %q, got %v", fallbackMsg, answer, got)
	}
}

func TestOnRequestBodyAPIKeyFailureIsUnchanged(t *testing.T) {
	apiKey := authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}
	refused := &embeddingproviders.StatusError{StatusCode: 401, Body: refusedAnswer}
	recs := routeWhenEmbeddingFails(t, apiKey, refused)
	assertFailureLoggedAsBefore(t, recs, refusedAnswer)
}

func TestOnRequestBodyIdentityServerErrorIsUnchanged(t *testing.T) {
	serverError := &embeddingproviders.StatusError{StatusCode: 500, Body: "server-error-marker"}
	recs := routeWhenEmbeddingFails(t, containerAppsAuth, serverError)
	assertFailureLoggedAsBefore(t, recs, "server-error-marker")
}
