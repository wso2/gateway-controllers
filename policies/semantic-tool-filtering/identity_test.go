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

package semantictoolfiltering

import (
	"bytes"
	"context"
	"encoding/json"
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
	queryText     = "weather in London"
	refusedAnswer = "audience is incorrect for client 1111"
	queryErrorMsg = "SemanticToolFiltering: Error generating query embedding"
	noTokenMsg    = "SemanticToolFiltering: could not obtain an access token for the embedding provider"
	refusedMsg    = "SemanticToolFiltering: the embedding provider refused the access token"
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

// requestFormat is one of the policy's three ways of reading the query and the tools.
type requestFormat struct {
	name      string
	queryJSON bool
	toolsJSON bool
	body      string
}

var requestFormats = []requestFormat{
	{"json", true, true, `{"messages":[{"role":"user","content":"` + queryText + `"}],"tools":[{"name":"get_weather","description":"Get weather"},{"name":"send_email","description":"Send email"}]}`},
	{"text", false, false, `<userq>` + queryText + `</userq> <toolname>get_weather</toolname><tooldescription>Get weather</tooldescription><toolname>send_email</toolname><tooldescription>Send email</tooldescription>`},
	{"mixed", true, false, `{"messages":[{"role":"user","content":"` + queryText + `"}],"system":"<toolname>get_weather</toolname><tooldescription>Get weather</tooldescription>"}`},
}

// runRequest sends f's request through a policy whose embeddings come from embed, and returns the
// action and the log records.
func runRequest(t *testing.T, f requestFormat, auth authentication, embed func(string) ([]float32, error)) (policy.RequestAction, []map[string]interface{}) {
	t.Helper()
	buf := captureLogs(t)
	p := &SemanticToolFilteringPolicy{
		embeddingConfig:   embeddingproviders.EmbeddingProviderConfig{EmbeddingProvider: "AZURE_OPENAI"},
		embeddingProvider: &fakeEmbeddingProvider{embed: embed},
		selectionMode:     SelectionModeTopK,
		topK:              1,
		threshold:         0.7,
		queryJSONPath:     "$.messages[0].content",
		toolsJSONPath:     "$.tools",
		userQueryIsJson:   f.queryJSON,
		toolsIsJson:       f.toolsJSON,
		auth:              auth,
	}
	reqCtx := &policy.RequestContext{
		// The tool embedding cache is process-wide, so every test gets an API of its own.
		SharedContext: &policy.SharedContext{RequestID: "r1", APIId: t.Name(), Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Content: []byte(f.body), Present: true},
	}
	return p.OnRequestBody(context.Background(), reqCtx, nil), logRecords(t, buf)
}

func failing(err error) func(string) ([]float32, error) {
	return func(string) ([]float32, error) { return nil, err }
}

func assertPassesThrough(t *testing.T, action policy.RequestAction) {
	t.Helper()
	got, ok := action.(policy.UpstreamRequestModifications)
	if !ok || !reflect.DeepEqual(got, policy.UpstreamRequestModifications{}) {
		t.Fatalf("expected the request to pass through unchanged, got %#v", action)
	}
}

func TestOnRequestBodyTokenFailureLogsErrorAndPassesThrough(t *testing.T) {
	for _, f := range requestFormats {
		t.Run(f.name, func(t *testing.T) {
			action, recs := runRequest(t, f, containerAppsAuth, failing(tokenErr(false)))
			assertPassesThrough(t, action)
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
		})
	}
}

func TestOnRequestBodyCachedTokenFailureLogsOnlyAtDebug(t *testing.T) {
	for _, f := range requestFormats {
		t.Run(f.name, func(t *testing.T) {
			action, recs := runRequest(t, f, containerAppsAuth, failing(tokenErr(true)))
			assertPassesThrough(t, action)
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
		})
	}
}

func TestOnRequestBodyRefusedTokenKeepsTheAnswerAtDebug(t *testing.T) {
	refused := &embeddingproviders.StatusError{StatusCode: 401, Body: refusedAnswer}
	for _, f := range requestFormats {
		t.Run(f.name, func(t *testing.T) {
			action, recs := runRequest(t, f, containerAppsAuth, failing(fmt.Errorf("embedding: %w", refused)))
			assertPassesThrough(t, action)
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
		})
	}
}

// assertQueryFailureLoggedAsBefore checks the ERROR and WARN lines the policy has always logged
// for a failed query embedding, with the provider's answer in both.
func assertQueryFailureLoggedAsBefore(t *testing.T, recs []map[string]interface{}, answer string) {
	t.Helper()
	for _, level := range []string{"ERROR", "WARN"} {
		got := recordsAt(recs, level)
		if len(got) != 1 || got[0]["msg"] != queryErrorMsg || !strings.Contains(fmt.Sprint(got[0]["error"]), answer) {
			t.Fatalf("expected one %s %q carrying %q, got %v", level, queryErrorMsg, answer, got)
		}
	}
}

func TestOnRequestBodyAPIKeyFailuresAreUnchanged(t *testing.T) {
	apiKey := authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}
	refused := &embeddingproviders.StatusError{StatusCode: 401, Body: refusedAnswer}
	action, recs := runRequest(t, requestFormats[0], apiKey, failing(refused))
	assertPassesThrough(t, action)
	assertQueryFailureLoggedAsBefore(t, recs, refusedAnswer)
}

func TestOnRequestBodyIdentityServerErrorIsUnchanged(t *testing.T) {
	serverError := &embeddingproviders.StatusError{StatusCode: 500, Body: "server-error-marker"}
	action, recs := runRequest(t, requestFormats[0], containerAppsAuth, failing(serverError))
	assertPassesThrough(t, action)
	assertQueryFailureLoggedAsBefore(t, recs, "server-error-marker")
}

func TestToolEmbeddingRefusedTokenSkipsTheToolQuietly(t *testing.T) {
	refused := &embeddingproviders.StatusError{StatusCode: 403, Body: "forbidden for client 1111"}
	embed := func(input string) ([]float32, error) {
		if input == queryText {
			return []float32{1, 0}, nil
		}
		return nil, refused
	}
	action, recs := runRequest(t, requestFormats[0], containerAppsAuth, embed)
	assertPassesThrough(t, action)
	if leaks := mentioning(t, append(recordsAt(recs, "WARN"), recordsAt(recs, "ERROR")...), "forbidden for client 1111"); len(leaks) != 0 {
		t.Fatalf("Azure's answer must stay out of ERROR and WARN, got %v", leaks)
	}
	errs := recordsAt(recs, "ERROR")
	if len(errs) == 0 || errs[0]["msg"] != refusedMsg || errs[0]["status"] != float64(403) {
		t.Fatalf("expected an ERROR %q with status 403, got %v", refusedMsg, errs)
	}
}
