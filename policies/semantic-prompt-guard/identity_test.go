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
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func errorRecords(recs []map[string]interface{}) []map[string]interface{} {
	var errs []map[string]interface{}
	for _, rec := range recs {
		if rec["level"] == "ERROR" {
			errs = append(errs, rec)
		}
	}
	return errs
}

const (
	// tokenReason names the identity, as a real reason can, so it must stay out of the client body.
	tokenReason = "Azure Container Apps answered 400 for client 00000000-0000-0000-0000-000000000001"
	// refusedBody stands for Azure OpenAI's answer to a refused token, which can name the principal.
	refusedBody = `{"error":{"code":"PermissionDenied","message":"refused-body-marker"}}`
)

var containerAppsAuth = authentication{typ: azureauthentication.ContainerApps, tokenScope: embeddingproviders.DefaultTokenScope}

func tokenErr(cached bool) error {
	return fmt.Errorf("could not obtain an access token for the embedding provider: %w",
		&azureauthentication.TokenError{Reason: tokenReason, Cached: cached})
}

// runEmbeddingFailure checks a prompt whose embedding fails with embedErr, and returns the response
// and the log records.
func runEmbeddingFailure(t *testing.T, auth authentication, embedErr error, showAssessment bool) (policy.ImmediateResponse, []map[string]interface{}) {
	t.Helper()
	buf := captureLogs(t)
	p := &SemanticPromptGuardPolicy{
		embeddingProvider: &mockEmbeddingProvider{getEmbeddingFn: func(string) ([]float32, error) { return nil, embedErr }},
		auth:              auth,
	}
	params := SemanticPromptGuardPolicyParams{JsonPath: "$.prompt", DeniedPhrases: []PhraseEmbedding{{Phrase: "x", Embedding: []float32{1, 0}}}, DenySimilarityThreshold: 0.9, ShowAssessment: showAssessment}
	got, ok := p.validatePayload(context.Background(), []byte(`{"prompt":"hello"}`), params).(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse")
	}
	return got, logRecords(t, buf)
}

func assertMediationFault(t *testing.T, got policy.ImmediateResponse, description string) {
	t.Helper()
	if got.StatusCode != 422 || !got.IsFault || got.Fault == nil {
		t.Fatalf("expected a 422 that declares a fault, got %d %+v", got.StatusCode, got.Fault)
	}
	if got.Fault.Code != policy.FaultCodeMediationFailed || got.Fault.Type != policy.FaultTypeMediation || got.Fault.Direction != policy.DirectionRequest || got.Fault.Guardrail != nil {
		t.Fatalf("unexpected fault %+v", got.Fault)
	}
	if got.Fault.Description != description {
		t.Fatalf("fault description = %q, want %q", got.Fault.Description, description)
	}
}

func TestValidatePayloadTokenFailureAnswers422WithoutTheReason(t *testing.T) {
	got, _ := runEmbeddingFailure(t, containerAppsAuth, tokenErr(false), false)
	const wantBody = `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Failed to generate embedding for prompt","direction":"REQUEST","interveningGuardrail":"SemanticPromptGuard"},"type":"SEMANTIC_PROMPT_GUARD"}`
	if string(got.Body) != wantBody {
		t.Fatalf("body = %s, want %s", got.Body, wantBody)
	}
	assertMediationFault(t, got, "Could not obtain an access token for the embedding provider: "+tokenReason)
}

func TestValidatePayloadTokenFailureAssessmentSaysOnlyNoToken(t *testing.T) {
	got, _ := runEmbeddingFailure(t, containerAppsAuth, tokenErr(false), true)
	if a := decodeSemanticPromptGuardMessage(t, got.Body)["assessments"]; a != "Could not obtain an access token for the embedding provider" {
		t.Fatalf("assessments = %v", a)
	}
	for _, leak := range []string{"answered 400", "00000000-0000-0000-0000-000000000001"} {
		if strings.Contains(string(got.Body), leak) {
			t.Fatalf("the body leaks %q: %s", leak, got.Body)
		}
	}
}

func TestValidatePayloadTokenFailureLogsAtError(t *testing.T) {
	_, recs := runEmbeddingFailure(t, containerAppsAuth, tokenErr(false), false)
	errs := errorRecords(recs)
	if len(errs) != 1 {
		t.Fatalf("expected one ERROR record, got %v", recs)
	}
	want := map[string]interface{}{
		"msg":                "SemanticPromptGuard: could not obtain an access token for the embedding provider",
		"reason":             tokenReason,
		"authenticationType": "container-apps",
		"clientId":           hostDefaultClientID,
		"scope":              embeddingproviders.DefaultTokenScope,
	}
	for k, v := range want {
		if errs[0][k] != v {
			t.Fatalf("record %s = %v, want %v (record %v)", k, errs[0][k], v, errs[0])
		}
	}
}

func TestValidatePayloadCachedTokenFailureLogsAtDebug(t *testing.T) {
	_, recs := runEmbeddingFailure(t, containerAppsAuth, tokenErr(true), false)
	if errs := errorRecords(recs); len(errs) != 0 {
		t.Fatalf("a cached failure must not log at ERROR, got %v", errs)
	}
	for _, rec := range recs {
		if rec["msg"] == "SemanticPromptGuard: could not obtain an access token for the embedding provider" && rec["level"] == "DEBUG" {
			return
		}
	}
	t.Fatalf("expected a DEBUG record for the cached failure, got %v", recs)
}

func TestValidatePayloadOtherEmbeddingErrorsAreUnchanged(t *testing.T) {
	got, recs := runEmbeddingFailure(t, containerAppsAuth, errors.New("provider unavailable"), true)
	if a := decodeSemanticPromptGuardMessage(t, got.Body)["assessments"]; a != "provider unavailable" {
		t.Fatalf("assessments = %v", a)
	}
	assertMediationFault(t, got, "Failed to generate embedding for prompt: provider unavailable")
	if errs := errorRecords(recs); len(errs) != 0 {
		t.Fatalf("expected no ERROR record, got %v", errs)
	}
}

func TestValidatePayloadRefusedTokenAnswers422WithoutTheProviderAnswer(t *testing.T) {
	auth := authentication{typ: azureauthentication.WorkloadIdentity, clientID: testClientID, tokenScope: embeddingproviders.DefaultTokenScope}
	got, recs := runEmbeddingFailure(t, auth, &embeddingproviders.StatusError{StatusCode: 403, Body: refusedBody}, true)
	if a := decodeSemanticPromptGuardMessage(t, got.Body)["assessments"]; a != "The embedding provider refused the access token" {
		t.Fatalf("assessments = %v", a)
	}
	if strings.Contains(string(got.Body), "refused-body-marker") {
		t.Fatalf("the body leaks the provider's answer: %s", got.Body)
	}
	assertMediationFault(t, got, "The embedding provider refused the access token: status 403")
	errs := errorRecords(recs)
	if len(errs) != 1 || errs[0]["msg"] != "SemanticPromptGuard: the embedding provider refused the access token" ||
		errs[0]["status"] != float64(403) || errs[0]["authenticationType"] != "workload-identity" ||
		errs[0]["clientId"] != testClientID || errs[0]["scope"] != embeddingproviders.DefaultTokenScope {
		t.Fatalf("expected one ERROR record for the refused token, got %v", recs)
	}
	if strings.Contains(fmt.Sprint(recs), "refused-body-marker") {
		t.Fatalf("the provider's answer must not be logged: %v", recs)
	}
}

func TestValidatePayloadAPIKeyRefusalIsUnchanged(t *testing.T) {
	refused := &embeddingproviders.StatusError{StatusCode: 401, Body: refusedBody}
	got, recs := runEmbeddingFailure(t, authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}, refused, true)
	if a := decodeSemanticPromptGuardMessage(t, got.Body)["assessments"]; a != refused.Error() {
		t.Fatalf("assessments = %v, want %q", a, refused.Error())
	}
	assertMediationFault(t, got, "Failed to generate embedding for prompt: "+refused.Error())
	if errs := errorRecords(recs); len(errs) != 0 {
		t.Fatalf("expected no ERROR record, got %v", errs)
	}
}

func TestValidatePayloadIdentityServerErrorIsUnchanged(t *testing.T) {
	failed := &embeddingproviders.StatusError{StatusCode: 500, Body: "busy"}
	got, recs := runEmbeddingFailure(t, containerAppsAuth, failed, true)
	if a := decodeSemanticPromptGuardMessage(t, got.Body)["assessments"]; a != failed.Error() {
		t.Fatalf("assessments = %v, want %q", a, failed.Error())
	}
	if errs := errorRecords(recs); len(errs) != 0 {
		t.Fatalf("expected no ERROR record, got %v", errs)
	}
}
