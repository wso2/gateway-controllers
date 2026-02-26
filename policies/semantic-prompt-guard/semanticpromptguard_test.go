package semanticpromptguard

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	embeddingproviders "github.com/wso2/api-platform/sdk/utils/embeddingproviders"
)

type mockEmbeddingProvider struct {
	getEmbeddingFn  func(input string) ([]float32, error)
	getEmbeddingsFn func(inputs []string) ([][]float32, error)
}

func (m *mockEmbeddingProvider) Init(config embeddingproviders.EmbeddingProviderConfig) error {
	return nil
}

func (m *mockEmbeddingProvider) GetType() string {
	return "MOCK"
}

func (m *mockEmbeddingProvider) GetEmbedding(input string) ([]float32, error) {
	if m.getEmbeddingFn != nil {
		return m.getEmbeddingFn(input)
	}
	return []float32{1, 0}, nil
}

func (m *mockEmbeddingProvider) GetEmbeddings(inputs []string) ([][]float32, error) {
	if m.getEmbeddingsFn != nil {
		return m.getEmbeddingsFn(inputs)
	}
	result := make([][]float32, len(inputs))
	for i := range inputs {
		result[i] = []float32{float32(i + 1), 0}
	}
	return result, nil
}

func TestSemanticPromptGuardPolicy_Mode(t *testing.T) {
	p := &SemanticPromptGuardPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestSemanticPromptGuardPolicy_OnResponse_NoOp(t *testing.T) {
	p := &SemanticPromptGuardPolicy{}
	action := p.OnResponse(&policy.ResponseContext{}, nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}

func TestGetPolicy_InvalidEmbeddingConfig(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil {
		t.Fatalf("expected error for missing embedding config")
	}
	if !strings.Contains(err.Error(), "invalid embedding config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseEmbeddingConfig(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantHeader     string
		wantModel      string
		wantErrContain string
	}{
		{
			name: "openai success",
			params: map[string]interface{}{
				"embeddingProvider": "OPENAI",
				"embeddingEndpoint": "http://example.com",
				"embeddingModel":    "text-embedding-3-small",
				"apiKey":            "secret",
			},
			wantHeader: "Authorization",
			wantModel:  "text-embedding-3-small",
		},
		{
			name: "azure openai without model",
			params: map[string]interface{}{
				"embeddingProvider": "AZURE_OPENAI",
				"embeddingEndpoint": "http://example.com",
				"apiKey":            "secret",
			},
			wantHeader: "api-key",
			wantModel:  "",
		},
		{
			name: "missing provider",
			params: map[string]interface{}{
				"embeddingEndpoint": "http://example.com",
				"embeddingModel":    "m",
				"apiKey":            "secret",
			},
			wantErrContain: "'embeddingProvider' is required",
		},
		{
			name: "openai missing model",
			params: map[string]interface{}{
				"embeddingProvider": "OPENAI",
				"embeddingEndpoint": "http://example.com",
				"apiKey":            "secret",
			},
			wantErrContain: "'embeddingModel' is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SemanticPromptGuardPolicy{}
			err := parseEmbeddingConfig(tt.params, p)
			if tt.wantErrContain != "" {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseEmbeddingConfig failed: %v", err)
			}
			if p.embeddingConfig.AuthHeaderName != tt.wantHeader {
				t.Fatalf("unexpected auth header: got %q, want %q", p.embeddingConfig.AuthHeaderName, tt.wantHeader)
			}
			if p.embeddingConfig.EmbeddingModel != tt.wantModel {
				t.Fatalf("unexpected embedding model: got %q, want %q", p.embeddingConfig.EmbeddingModel, tt.wantModel)
			}
		})
	}
}

func TestParseParams(t *testing.T) {
	basePolicy := &SemanticPromptGuardPolicy{
		embeddingProvider: &mockEmbeddingProvider{},
	}

	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name: "valid allowed and denied phrases",
			params: map[string]interface{}{
				"jsonPath":                 "$.prompt",
				"allowSimilarityThreshold": 0.7,
				"denySimilarityThreshold":  0.8,
				"showAssessment":           true,
				"allowedPhrases":           []interface{}{"safe"},
				"deniedPhrases":            []interface{}{"attack"},
			},
		},
		{
			name: "invalid jsonPath type",
			params: map[string]interface{}{
				"jsonPath":       true,
				"allowedPhrases": []interface{}{"safe"},
			},
			wantErrContain: "'jsonPath' must be a string",
		},
		{
			name: "invalid allow threshold",
			params: map[string]interface{}{
				"allowSimilarityThreshold": 2.0,
				"allowedPhrases":           []interface{}{"safe"},
			},
			wantErrContain: "'allowSimilarityThreshold' must be between 0.0 and 1.0",
		},
		{
			name: "invalid deny threshold",
			params: map[string]interface{}{
				"denySimilarityThreshold": -1.0,
				"allowedPhrases":          []interface{}{"safe"},
			},
			wantErrContain: "'denySimilarityThreshold' must be between 0.0 and 1.0",
		},
		{
			name: "invalid showAssessment type",
			params: map[string]interface{}{
				"showAssessment": "true",
				"allowedPhrases": []interface{}{"safe"},
			},
			wantErrContain: "'showAssessment' must be a boolean",
		},
		{
			name: "invalid allowed phrases type",
			params: map[string]interface{}{
				"allowedPhrases": "safe",
			},
			wantErrContain: "error parsing allowedPhrases",
		},
		{
			name:           "no allowed or denied phrases",
			params:         map[string]interface{}{},
			wantErrContain: "at least one allowedPhrases or deniedPhrases entry is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SemanticPromptGuardPolicy{embeddingProvider: basePolicy.embeddingProvider}
			got, err := parseParams(tt.params, p)
			if tt.wantErrContain != "" {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseParams failed: %v", err)
			}
			if got.JsonPath != "$.prompt" {
				t.Fatalf("unexpected jsonPath: %q", got.JsonPath)
			}
			if !got.ShowAssessment {
				t.Fatalf("expected showAssessment=true")
			}
			if len(got.AllowedPhrases) != 1 || len(got.DeniedPhrases) != 1 {
				t.Fatalf("unexpected phrase counts: allowed=%d denied=%d", len(got.AllowedPhrases), len(got.DeniedPhrases))
			}
			if got.AllowedPhrases[0].Embedding == nil || got.DeniedPhrases[0].Embedding == nil {
				t.Fatalf("expected embeddings to be populated")
			}
		})
	}
}

func TestEnsureEmbeddings(t *testing.T) {
	tests := []struct {
		name           string
		provider       *mockEmbeddingProvider
		phrases        []PhraseEmbedding
		wantErrContain string
	}{
		{
			name: "success",
			provider: &mockEmbeddingProvider{
				getEmbeddingsFn: func(inputs []string) ([][]float32, error) {
					return [][]float32{{1, 0}, {0, 1}}, nil
				},
			},
			phrases: []PhraseEmbedding{{Phrase: "a"}, {Phrase: "b"}},
		},
		{
			name: "provider error",
			provider: &mockEmbeddingProvider{
				getEmbeddingsFn: func(inputs []string) ([][]float32, error) {
					return nil, errors.New("provider failed")
				},
			},
			phrases:        []PhraseEmbedding{{Phrase: "a"}},
			wantErrContain: "failed to get embeddings",
		},
		{
			name: "count mismatch",
			provider: &mockEmbeddingProvider{
				getEmbeddingsFn: func(inputs []string) ([][]float32, error) {
					return [][]float32{{1, 0}}, nil
				},
			},
			phrases:        []PhraseEmbedding{{Phrase: "a"}, {Phrase: "b"}},
			wantErrContain: "expected 2 embeddings but got 1",
		},
		{
			name:           "empty phrase",
			provider:       &mockEmbeddingProvider{},
			phrases:        []PhraseEmbedding{{Phrase: ""}},
			wantErrContain: "phrase at index 0 is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SemanticPromptGuardPolicy{embeddingProvider: tt.provider}
			got, err := p.ensureEmbeddings(tt.phrases)
			if tt.wantErrContain != "" {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("ensureEmbeddings failed: %v", err)
			}
			if len(got) != len(tt.phrases) {
				t.Fatalf("unexpected count: got %d, want %d", len(got), len(tt.phrases))
			}
			for _, phrase := range got {
				if len(phrase.Embedding) == 0 {
					t.Fatalf("expected embedding for phrase %q", phrase.Phrase)
				}
			}
		})
	}
}

func TestParsePhraseEmbeddings(t *testing.T) {
	tests := []struct {
		name           string
		raw            interface{}
		wantCount      int
		wantErrContain string
	}{
		{name: "nil raw", raw: nil, wantCount: 0},
		{name: "valid array", raw: []interface{}{"a", "b"}, wantCount: 2},
		{name: "not array", raw: "a", wantErrContain: "must be an array"},
		{name: "non string entry", raw: []interface{}{1}, wantErrContain: "must be a string"},
		{name: "empty entry", raw: []interface{}{""}, wantErrContain: "cannot be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePhraseEmbeddings(tt.raw, "allowedPhrases")
			if tt.wantErrContain != "" {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("parsePhraseEmbeddings failed: %v", err)
			}
			if len(got) != tt.wantCount {
				t.Fatalf("unexpected count: got %d, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestParseFloatParam(t *testing.T) {
	params := map[string]interface{}{
		"float64": float64(0.1),
		"float32": float32(0.2),
		"int":     int(3),
		"int64":   int64(4),
		"string":  "0.5",
		"bad":     "x",
	}

	if got := parseFloatParam(params, "float64", 1); got != 0.1 {
		t.Fatalf("unexpected float64 parse: %v", got)
	}
	if got := parseFloatParam(params, "float32", 1); math.Abs(got-0.2) > 1e-6 {
		t.Fatalf("unexpected float32 parse: %v", got)
	}
	if got := parseFloatParam(params, "int", 1); got != 3 {
		t.Fatalf("unexpected int parse: %v", got)
	}
	if got := parseFloatParam(params, "int64", 1); got != 4 {
		t.Fatalf("unexpected int64 parse: %v", got)
	}
	if got := parseFloatParam(params, "string", 1); got != 0.5 {
		t.Fatalf("unexpected string parse: %v", got)
	}
	if got := parseFloatParam(params, "bad", 1); got != 1 {
		t.Fatalf("expected default for bad string, got %v", got)
	}
	if got := parseFloatParam(params, "missing", 1); got != 1 {
		t.Fatalf("expected default for missing key, got %v", got)
	}
}

func TestSemanticPromptGuardPolicy_OnRequestAndValidatePayload(t *testing.T) {
	tests := []struct {
		name               string
		payload            string
		params             SemanticPromptGuardPolicyParams
		provider           *mockEmbeddingProvider
		wantImmediate      bool
		wantStatus         int
		wantAssessment     bool
		wantAssessmentText string
	}{
		{
			name:    "jsonpath extraction error",
			payload: `{"message":"hi"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:       "$.prompt",
				ShowAssessment: true,
			},
			provider:       &mockEmbeddingProvider{},
			wantImmediate:  true,
			wantStatus:     GuardrailErrorCode,
			wantAssessment: true,
		},
		{
			name:    "empty extracted prompt",
			payload: `{"prompt":""}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:       "$.prompt",
				ShowAssessment: true,
			},
			provider:       &mockEmbeddingProvider{},
			wantImmediate:  true,
			wantStatus:     GuardrailErrorCode,
			wantAssessment: true,
		},
		{
			name:    "embedding provider error",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:       "$.prompt",
				DeniedPhrases:  []PhraseEmbedding{{Phrase: "ban", Embedding: []float32{1, 0}}},
				ShowAssessment: true,
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return nil, errors.New("boom")
				},
			},
			wantImmediate:  true,
			wantStatus:     GuardrailErrorCode,
			wantAssessment: true,
		},
		{
			name:    "deny list blocks",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:                "$.prompt",
				DenySimilarityThreshold: 0.8,
				DeniedPhrases:           []PhraseEmbedding{{Phrase: "ban", Embedding: []float32{1, 0}}},
				ShowAssessment:          true,
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{1, 0}, nil
				},
			},
			wantImmediate:      true,
			wantStatus:         GuardrailErrorCode,
			wantAssessment:     true,
			wantAssessmentText: "denied phrase",
		},
		{
			name:    "deny list allows",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:                "$.prompt",
				DenySimilarityThreshold: 0.9,
				DeniedPhrases:           []PhraseEmbedding{{Phrase: "ban", Embedding: []float32{0, 1}}},
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{1, 0}, nil
				},
			},
			wantImmediate: false,
		},
		{
			name:    "allow list allows",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:                 "$.prompt",
				AllowSimilarityThreshold: 0.8,
				AllowedPhrases:           []PhraseEmbedding{{Phrase: "safe", Embedding: []float32{1, 0}}},
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{1, 0}, nil
				},
			},
			wantImmediate: false,
		},
		{
			name:    "allow list blocks",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:                 "$.prompt",
				AllowSimilarityThreshold: 0.8,
				AllowedPhrases:           []PhraseEmbedding{{Phrase: "safe", Embedding: []float32{0, 1}}},
				ShowAssessment:           true,
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{1, 0}, nil
				},
			},
			wantImmediate:      true,
			wantStatus:         GuardrailErrorCode,
			wantAssessment:     true,
			wantAssessmentText: "not similar enough",
		},
		{
			name:    "both lists deny takes precedence",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:                 "$.prompt",
				AllowSimilarityThreshold: 0.5,
				DenySimilarityThreshold:  0.5,
				AllowedPhrases:           []PhraseEmbedding{{Phrase: "safe", Embedding: []float32{1, 0}}},
				DeniedPhrases:            []PhraseEmbedding{{Phrase: "ban", Embedding: []float32{1, 0}}},
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{1, 0}, nil
				},
			},
			wantImmediate: true,
			wantStatus:    GuardrailErrorCode,
		},
		{
			name:    "similarity error due to dimension mismatch",
			payload: `{"prompt":"hello"}`,
			params: SemanticPromptGuardPolicyParams{
				JsonPath:      "$.prompt",
				DeniedPhrases: []PhraseEmbedding{{Phrase: "ban", Embedding: []float32{1, 0, 1}}},
			},
			provider: &mockEmbeddingProvider{
				getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{1, 0}, nil
				},
			},
			wantImmediate: true,
			wantStatus:    GuardrailErrorCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SemanticPromptGuardPolicy{
				embeddingProvider: tt.provider,
				params:            tt.params,
			}

			ctx := &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}},
				Body:          &policy.Body{Content: []byte(tt.payload), Present: true, EndOfStream: true},
			}

			action := p.OnRequest(ctx, nil)
			if !tt.wantImmediate {
				if _, ok := action.(policy.UpstreamRequestModifications); !ok {
					t.Fatalf("expected UpstreamRequestModifications, got %T", action)
				}
				return
			}

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			message := decodeSemanticPromptGuardMessage(t, resp.Body)
			if tt.wantAssessment {
				if _, ok := message["assessments"]; !ok {
					t.Fatalf("expected assessments in error message")
				}
			}
			if tt.wantAssessmentText != "" {
				assessments := ""
				if v, ok := message["assessments"].(string); ok {
					assessments = v
				}
				if !strings.Contains(assessments, tt.wantAssessmentText) {
					t.Fatalf("assessment mismatch: got %q, want contain %q", assessments, tt.wantAssessmentText)
				}
			}
		})
	}
}

func TestBuildAssessmentObject(t *testing.T) {
	p := &SemanticPromptGuardPolicy{}

	withErrNoAssessment := p.buildAssessmentObject("reason", errors.New("err details"), false)
	if withErrNoAssessment["actionReason"] != "reason" {
		t.Fatalf("expected custom reason with validation error, got %v", withErrNoAssessment["actionReason"])
	}
	if _, ok := withErrNoAssessment["assessments"]; ok {
		t.Fatalf("did not expect assessments when showAssessment=false")
	}

	withoutErrWithAssessment := p.buildAssessmentObject("friendly reason", nil, true)
	if withoutErrWithAssessment["actionReason"] != "Violation of applied semantic prompt guard constraints detected." {
		t.Fatalf("unexpected actionReason: %v", withoutErrWithAssessment["actionReason"])
	}
	if withoutErrWithAssessment["assessments"] != "friendly reason" {
		t.Fatalf("unexpected assessments: %v", withoutErrWithAssessment["assessments"])
	}
}

func TestMaxSimilarityAndCosineSimilarity(t *testing.T) {
	t.Run("maxSimilarity picks closest", func(t *testing.T) {
		target := []float32{1, 0}
		phrases := []PhraseEmbedding{
			{Phrase: "first", Embedding: []float32{0, 1}},
			{Phrase: "second", Embedding: []float32{1, 0}},
		}

		sim, closest, err := maxSimilarity(target, phrases)
		if err != nil {
			t.Fatalf("maxSimilarity failed: %v", err)
		}
		if sim < 0.99 {
			t.Fatalf("expected high similarity, got %f", sim)
		}
		if closest.Phrase != "second" {
			t.Fatalf("unexpected closest phrase: %q", closest.Phrase)
		}
	})

	t.Run("cosineSimilarity errors", func(t *testing.T) {
		if _, err := cosineSimilarity(nil, []float32{1}); err == nil {
			t.Fatalf("expected error for empty vector")
		}
		if _, err := cosineSimilarity([]float32{1}, []float32{1, 2}); err == nil {
			t.Fatalf("expected error for dimension mismatch")
		}
		if _, err := cosineSimilarity([]float32{0, 0}, []float32{1, 0}); err == nil {
			t.Fatalf("expected error for zero norm")
		}
	})

	t.Run("maxSimilarity empty phrases", func(t *testing.T) {
		sim, closest, err := maxSimilarity([]float32{1, 0}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sim != 0 {
			t.Fatalf("expected similarity 0, got %f", sim)
		}
		if !reflect.DeepEqual(closest, PhraseEmbedding{}) {
			t.Fatalf("expected zero closest phrase, got %+v", closest)
		}
	})
}

func decodeSemanticPromptGuardMessage(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var outer map[string]interface{}
	if err := json.Unmarshal(body, &outer); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	message, ok := outer["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected message object, got %T", outer["message"])
	}
	return message
}
