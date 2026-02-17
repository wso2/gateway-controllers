package semanticcache

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	embeddingproviders "github.com/wso2/api-platform/sdk/utils/embeddingproviders"
	vectordbproviders "github.com/wso2/api-platform/sdk/utils/vectordbproviders"
)

type mockEmbeddingProvider struct {
	getEmbeddingFn func(input string) ([]float32, error)
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
	return []float32{0.1, 0.2}, nil
}

func (m *mockEmbeddingProvider) GetEmbeddings(inputs []string) ([][]float32, error) {
	result := make([][]float32, len(inputs))
	for i := range inputs {
		result[i] = []float32{0.1, 0.2}
	}
	return result, nil
}

type mockVectorDBProvider struct {
	retrieveFn func(embeddings []float32, filter map[string]interface{}) (vectordbproviders.CacheResponse, error)
	storeFn    func(embeddings []float32, response vectordbproviders.CacheResponse, filter map[string]interface{}) error
}

func (m *mockVectorDBProvider) Init(config vectordbproviders.VectorDBProviderConfig) error {
	return nil
}

func (m *mockVectorDBProvider) GetType() string {
	return "MOCK_DB"
}

func (m *mockVectorDBProvider) CreateIndex() error {
	return nil
}

func (m *mockVectorDBProvider) Store(embeddings []float32, response vectordbproviders.CacheResponse, filter map[string]interface{}) error {
	if m.storeFn != nil {
		return m.storeFn(embeddings, response, filter)
	}
	return nil
}

func (m *mockVectorDBProvider) Retrieve(embeddings []float32, filter map[string]interface{}) (vectordbproviders.CacheResponse, error) {
	if m.retrieveFn != nil {
		return m.retrieveFn(embeddings, filter)
	}
	return vectordbproviders.CacheResponse{}, nil
}

func (m *mockVectorDBProvider) Close() error {
	return nil
}

func TestSemanticCachePolicy_Mode(t *testing.T) {
	p := &SemanticCachePolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestGetPolicy_InvalidParams(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid params") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseParams(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		assert         func(t *testing.T, p *SemanticCachePolicy)
		wantErrContain string
	}{
		{
			name: "openai success",
			params: map[string]interface{}{
				"embeddingProvider":   "OPENAI",
				"vectorStoreProvider": "REDIS",
				"similarityThreshold": 0.55,
				"embeddingEndpoint":   "http://example.com",
				"embeddingModel":      "text-embedding-3-small",
				"apiKey":              "secret",
				"dbHost":              "localhost",
				"dbPort":              6379,
				"embeddingDimension":  1536,
				"username":            "user",
				"password":            "pass",
				"database":            "1",
				"ttl":                 3600,
				"jsonPath":            "$.messages[-1].content",
			},
			assert: func(t *testing.T, p *SemanticCachePolicy) {
				if p.threshold != 0.55 {
					t.Fatalf("unexpected threshold: %v", p.threshold)
				}
				if p.embeddingConfig.AuthHeaderName != "Authorization" {
					t.Fatalf("unexpected auth header name: %q", p.embeddingConfig.AuthHeaderName)
				}
				if p.vectorStoreConfig.Threshold != "0.55" {
					t.Fatalf("unexpected vector threshold: %q", p.vectorStoreConfig.Threshold)
				}
				if p.vectorStoreConfig.DBPort != 6379 {
					t.Fatalf("unexpected db port: %d", p.vectorStoreConfig.DBPort)
				}
				if p.jsonPath != "$.messages[-1].content" {
					t.Fatalf("unexpected jsonPath: %q", p.jsonPath)
				}
			},
		},
		{
			name: "azure without model",
			params: map[string]interface{}{
				"embeddingProvider":   "AZURE_OPENAI",
				"vectorStoreProvider": "REDIS",
				"similarityThreshold": "0.5",
				"embeddingEndpoint":   "http://example.com",
				"apiKey":              "secret",
				"dbHost":              "localhost",
				"dbPort":              "6379",
				"embeddingDimension":  "1536",
			},
			assert: func(t *testing.T, p *SemanticCachePolicy) {
				if p.embeddingConfig.AuthHeaderName != "api-key" {
					t.Fatalf("unexpected auth header: %q", p.embeddingConfig.AuthHeaderName)
				}
				if p.embeddingConfig.EmbeddingModel != "" {
					t.Fatalf("expected empty embedding model for azure, got %q", p.embeddingConfig.EmbeddingModel)
				}
			},
		},
		{
			name: "missing embedding provider",
			params: map[string]interface{}{
				"vectorStoreProvider": "REDIS",
				"similarityThreshold": 0.5,
			},
			wantErrContain: "'embeddingProvider' parameter is required",
		},
		{
			name: "missing vector store provider",
			params: map[string]interface{}{
				"embeddingProvider":   "OPENAI",
				"similarityThreshold": 0.5,
			},
			wantErrContain: "'vectorStoreProvider' parameter is required",
		},
		{
			name: "missing similarity threshold",
			params: map[string]interface{}{
				"embeddingProvider":   "OPENAI",
				"vectorStoreProvider": "REDIS",
			},
			wantErrContain: "'similarityThreshold' parameter is required",
		},
		{
			name: "threshold out of range",
			params: map[string]interface{}{
				"embeddingProvider":   "OPENAI",
				"vectorStoreProvider": "REDIS",
				"similarityThreshold": 2.0,
			},
			wantErrContain: "'similarityThreshold' must be between 0.0 and 1.0",
		},
		{
			name: "openai missing model",
			params: map[string]interface{}{
				"embeddingProvider":   "OPENAI",
				"vectorStoreProvider": "REDIS",
				"similarityThreshold": 0.5,
				"embeddingEndpoint":   "http://example.com",
				"apiKey":              "secret",
				"dbHost":              "localhost",
				"dbPort":              6379,
				"embeddingDimension":  1536,
			},
			wantErrContain: "'embeddingModel' is required for OPENAI provider",
		},
		{
			name: "invalid dbPort numeric",
			params: map[string]interface{}{
				"embeddingProvider":   "AZURE_OPENAI",
				"vectorStoreProvider": "REDIS",
				"similarityThreshold": 0.5,
				"embeddingEndpoint":   "http://example.com",
				"apiKey":              "secret",
				"dbHost":              "localhost",
				"dbPort":              12.5,
				"embeddingDimension":  1536,
			},
			wantErrContain: "'dbPort' must be a number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SemanticCachePolicy{}
			err := parseParams(tt.params, p)
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
			if tt.assert != nil {
				tt.assert(t, p)
			}
		})
	}
}

func TestExtractFloat64(t *testing.T) {
	tests := []struct {
		name      string
		value     interface{}
		want      float64
		wantError bool
	}{
		{name: "float64", value: float64(0.5), want: 0.5},
		{name: "float32", value: float32(0.5), want: 0.5},
		{name: "int", value: int(1), want: 1},
		{name: "int64", value: int64(2), want: 2},
		{name: "string", value: "0.7", want: 0.7},
		{name: "bad string", value: "x", wantError: true},
		{name: "invalid type", value: true, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractFloat64(tt.value)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractFloat64 failed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected value: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractInt(t *testing.T) {
	tests := []struct {
		name      string
		value     interface{}
		want      int
		wantError bool
	}{
		{name: "int", value: int(3), want: 3},
		{name: "int64", value: int64(4), want: 4},
		{name: "float64 integer", value: float64(5), want: 5},
		{name: "string", value: "6", want: 6},
		{name: "float64 non integer", value: float64(1.1), wantError: true},
		{name: "bad string", value: "x", wantError: true},
		{name: "invalid type", value: true, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractInt(tt.value)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractInt failed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected value: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSemanticCachePolicy_OnRequest(t *testing.T) {
	tests := []struct {
		name             string
		policy           *SemanticCachePolicy
		ctx              *policy.RequestContext
		wantImmediate    bool
		wantStatus       int
		wantCacheStatus  string
		wantMetadataSave bool
	}{
		{
			name: "empty body passes through",
			policy: &SemanticCachePolicy{
				embeddingProvider:   &mockEmbeddingProvider{},
				vectorStoreProvider: &mockVectorDBProvider{},
				threshold:           0.5,
			},
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}},
				Body:          &policy.Body{Content: nil, Present: false},
			},
			wantImmediate: false,
		},
		{
			name: "jsonpath extraction failure returns error",
			policy: &SemanticCachePolicy{
				embeddingProvider:   &mockEmbeddingProvider{},
				vectorStoreProvider: &mockVectorDBProvider{},
				jsonPath:            "$.missing",
				threshold:           0.5,
			},
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}},
				Body:          &policy.Body{Content: []byte(`{"prompt":"hello"}`), Present: true},
			},
			wantImmediate: true,
			wantStatus:    400,
		},
		{
			name: "embedding provider error passes through",
			policy: &SemanticCachePolicy{
				embeddingProvider: &mockEmbeddingProvider{getEmbeddingFn: func(input string) ([]float32, error) {
					return nil, errors.New("embedding failed")
				}},
				vectorStoreProvider: &mockVectorDBProvider{},
				threshold:           0.5,
			},
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}},
				Body:          &policy.Body{Content: []byte("hello"), Present: true},
			},
			wantImmediate: false,
		},
		{
			name: "cache miss passes through and stores embedding",
			policy: &SemanticCachePolicy{
				embeddingProvider: &mockEmbeddingProvider{getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{0.2, 0.3}, nil
				}},
				vectorStoreProvider: &mockVectorDBProvider{retrieveFn: func(embeddings []float32, filter map[string]interface{}) (vectordbproviders.CacheResponse, error) {
					if filter["api_id"] != "Books:v1" {
						t.Fatalf("unexpected api_id in filter: %v", filter["api_id"])
					}
					if filter["threshold"] != "0.70" {
						t.Fatalf("unexpected threshold in filter: %v", filter["threshold"])
					}
					if _, ok := filter["ctx"].(context.Context); !ok {
						t.Fatalf("expected context.Context in filter")
					}
					return vectordbproviders.CacheResponse{}, nil
				}},
				threshold: 0.7,
			},
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}, APIName: "Books", APIVersion: "v1"},
				Body:          &policy.Body{Content: []byte("hello"), Present: true},
			},
			wantImmediate:    false,
			wantMetadataSave: true,
		},
		{
			name: "cache hit returns immediate response",
			policy: &SemanticCachePolicy{
				embeddingProvider: &mockEmbeddingProvider{getEmbeddingFn: func(input string) ([]float32, error) {
					return []float32{0.2, 0.3}, nil
				}},
				vectorStoreProvider: &mockVectorDBProvider{retrieveFn: func(embeddings []float32, filter map[string]interface{}) (vectordbproviders.CacheResponse, error) {
					return vectordbproviders.CacheResponse{ResponsePayload: map[string]interface{}{"answer": "cached"}}, nil
				}},
				threshold: 0.5,
			},
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}, APIName: "Books", APIVersion: "v1"},
				Body:          &policy.Body{Content: []byte("hello"), Present: true},
			},
			wantImmediate:   true,
			wantStatus:      200,
			wantCacheStatus: "HIT",
		},
		{
			name: "retrieve error passes through",
			policy: &SemanticCachePolicy{
				embeddingProvider: &mockEmbeddingProvider{},
				vectorStoreProvider: &mockVectorDBProvider{retrieveFn: func(embeddings []float32, filter map[string]interface{}) (vectordbproviders.CacheResponse, error) {
					return vectordbproviders.CacheResponse{}, errors.New("redis down")
				}},
				threshold: 0.5,
			},
			ctx: &policy.RequestContext{
				SharedContext: &policy.SharedContext{RequestID: "r1", Metadata: map[string]interface{}{}, APIName: "Books", APIVersion: "v1"},
				Body:          &policy.Body{Content: []byte("hello"), Present: true},
			},
			wantImmediate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := tt.policy.OnRequest(tt.ctx, nil)

			if !tt.wantImmediate {
				if _, ok := action.(policy.UpstreamRequestModifications); !ok {
					t.Fatalf("expected UpstreamRequestModifications, got %T", action)
				}
				if tt.wantMetadataSave {
					if _, ok := tt.ctx.Metadata[MetadataKeyEmbedding].(string); !ok {
						t.Fatalf("expected embedding to be stored in metadata")
					}
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
			if tt.wantCacheStatus != "" {
				if resp.Headers["X-Cache-Status"] != tt.wantCacheStatus {
					t.Fatalf("unexpected cache status: %q", resp.Headers["X-Cache-Status"])
				}
				var body map[string]interface{}
				if err := json.Unmarshal(resp.Body, &body); err != nil {
					t.Fatalf("invalid JSON body: %v", err)
				}
				if body["answer"] != "cached" {
					t.Fatalf("unexpected cached payload: %v", body)
				}
			}
		})
	}
}

func TestSemanticCachePolicy_OnResponse(t *testing.T) {
	tests := []struct {
		name      string
		policy    *SemanticCachePolicy
		ctx       *policy.ResponseContext
		assertion func(t *testing.T, action policy.ResponseAction)
	}{
		{
			name: "non-200 response skipped",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{},
			},
			ctx:       newResponseContext(500, []byte(`{"answer":"x"}`), map[string]interface{}{}),
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "empty body skipped",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{},
			},
			ctx:       newResponseContext(200, nil, map[string]interface{}{}),
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "missing embedding metadata skipped",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{},
			},
			ctx:       newResponseContext(200, []byte(`{"answer":"x"}`), map[string]interface{}{}),
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "invalid embedding metadata skipped",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{},
			},
			ctx:       newResponseContext(200, []byte(`{"answer":"x"}`), map[string]interface{}{MetadataKeyEmbedding: "not-json"}),
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "invalid response body json skipped",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{},
			},
			ctx:       newResponseContext(200, []byte("not-json"), map[string]interface{}{MetadataKeyEmbedding: "[0.1,0.2]"}),
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "store error still no-op",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{storeFn: func(embeddings []float32, response vectordbproviders.CacheResponse, filter map[string]interface{}) error {
					return errors.New("store failed")
				}},
			},
			ctx:       newResponseContext(200, []byte(`{"answer":"x"}`), map[string]interface{}{MetadataKeyEmbedding: "[0.1,0.2]"}),
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "store success with api fallback",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{storeFn: func(embeddings []float32, response vectordbproviders.CacheResponse, filter map[string]interface{}) error {
					if !reflect.DeepEqual(embeddings, []float32{0.1, 0.2}) {
						t.Fatalf("unexpected embeddings: %v", embeddings)
					}
					if response.ResponsePayload["answer"] != "x" {
						t.Fatalf("unexpected response payload: %v", response.ResponsePayload)
					}
					if filter["api_id"] != "req-1" {
						t.Fatalf("expected fallback api_id=req-1, got %v", filter["api_id"])
					}
					if _, ok := filter["ctx"].(context.Context); !ok {
						t.Fatalf("expected context in store filter")
					}
					if response.RequestHash == "" {
						t.Fatalf("expected generated request hash")
					}
					if time.Since(response.ResponseFetchedTime) > 2*time.Second {
						t.Fatalf("response timestamp too old: %v", response.ResponseFetchedTime)
					}
					return nil
				}},
			},
			ctx: &policy.ResponseContext{
				SharedContext:  &policy.SharedContext{RequestID: "req-1", Metadata: map[string]interface{}{MetadataKeyEmbedding: "[0.1,0.2]"}},
				ResponseStatus: 200,
				ResponseBody:   &policy.Body{Content: []byte(`{"answer":"x"}`), Present: true},
			},
			assertion: assertUpstreamResponseMods,
		},
		{
			name: "store success with api name/version",
			policy: &SemanticCachePolicy{
				vectorStoreProvider: &mockVectorDBProvider{storeFn: func(embeddings []float32, response vectordbproviders.CacheResponse, filter map[string]interface{}) error {
					if filter["api_id"] != "Books:v2" {
						t.Fatalf("unexpected api_id: %v", filter["api_id"])
					}
					return nil
				}},
			},
			ctx: &policy.ResponseContext{
				SharedContext:  &policy.SharedContext{RequestID: "req-2", Metadata: map[string]interface{}{MetadataKeyEmbedding: "[0.1,0.2]"}, APIName: "Books", APIVersion: "v2"},
				ResponseStatus: 200,
				ResponseBody:   &policy.Body{Content: []byte(`{"answer":"x"}`), Present: true},
			},
			assertion: assertUpstreamResponseMods,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := tt.policy.OnResponse(tt.ctx, nil)
			tt.assertion(t, action)
		})
	}
}

func TestBuildErrorResponse(t *testing.T) {
	p := &SemanticCachePolicy{}
	action := p.buildErrorResponse("jsonpath failed", errors.New("bad path"))
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Fatalf("unexpected content type: %q", resp.Headers["Content-Type"])
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("invalid json body: %v", err)
	}
	if body["type"] != "SEMANTIC_CACHE" {
		t.Fatalf("unexpected type: %v", body["type"])
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "jsonpath failed") || !strings.Contains(msg, "bad path") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestCreateProviderHelpers_UnsupportedTypes(t *testing.T) {
	_, err := createEmbeddingProvider(embeddingproviders.EmbeddingProviderConfig{EmbeddingProvider: "UNKNOWN"})
	if err == nil || !strings.Contains(err.Error(), "unsupported embedding provider") {
		t.Fatalf("expected unsupported embedding provider error, got %v", err)
	}

	_, err = createVectorDBProvider(vectordbproviders.VectorDBProviderConfig{VectorStoreProvider: "UNKNOWN"})
	if err == nil || !strings.Contains(err.Error(), "unsupported vector store provider") {
		t.Fatalf("expected unsupported vector store provider error, got %v", err)
	}
}

func newResponseContext(status int, body []byte, metadata map[string]interface{}) *policy.ResponseContext {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	return &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{RequestID: "req-1", Metadata: metadata, APIName: "Books", APIVersion: "v1"},
		ResponseStatus: status,
		ResponseBody:   &policy.Body{Content: body, Present: len(body) > 0},
	}
}

func assertUpstreamResponseMods(t *testing.T, action policy.ResponseAction) {
	t.Helper()
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}
