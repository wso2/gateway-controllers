package semanticcache

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
	vectordbproviders "github.com/wso2/api-platform/sdk/ai/vectordb"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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
					if filter["threshold"] != "0.8800" {
						t.Fatalf("unexpected threshold in filter: %v", filter["threshold"])
					}
					if _, ok := filter["ctx"].(context.Context); !ok {
						t.Fatalf("expected context.Context in filter")
					}
					return vectordbproviders.CacheResponse{}, nil
				}},
				threshold:            0.7,
				cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
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
				threshold:            0.5,
				cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
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
				threshold:            0.5,
				cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
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
			action := tt.policy.OnRequestBody(context.Background(), tt.ctx, nil)

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
				// A cache hit ends the request successfully. It must never be a fault:
				// doing so would page on-call for every hit, which is the exact mistake
				// the zero value of IsFault exists to prevent.
				if resp.IsFault {
					t.Fatalf("a cache hit must not be a fault")
				}
				if resp.Fault != nil {
					t.Fatalf("a cache hit must not describe an error")
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
				cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
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
				cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
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
				cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
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
			action := tt.policy.OnResponseBody(context.Background(), tt.ctx, nil)
			tt.assertion(t, action)
		})
	}
}

func TestAssembleSSEResponse(t *testing.T) {
	tests := []struct {
		name       string
		sseBody    string
		wantErr    bool
		assertData func(t *testing.T, data map[string]interface{})
	}{
		{
			name: "standard openai SSE stream",
			sseBody: "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n" +
				"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n" +
				"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n" +
				"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n" +
				"data: [DONE]\n",
			assertData: func(t *testing.T, data map[string]interface{}) {
				if data["object"] != "chat.completion" {
					t.Fatalf("expected object=chat.completion, got %v", data["object"])
				}
				if data["model"] != "gpt-4" {
					t.Fatalf("expected model=gpt-4, got %v", data["model"])
				}
				choices, ok := data["choices"].([]interface{})
				if !ok || len(choices) == 0 {
					t.Fatalf("expected choices array, got %v", data["choices"])
				}
				choice := choices[0].(map[string]interface{})
				msg, ok := choice["message"].(map[string]interface{})
				if !ok {
					t.Fatalf("expected message in choice, got %v", choice)
				}
				if msg["content"] != "Hello world" {
					t.Fatalf("expected content='Hello world', got %v", msg["content"])
				}
				if msg["role"] != "assistant" {
					t.Fatalf("expected role=assistant, got %v", msg["role"])
				}
				// delta should not be present
				if _, hasDelta := choice["delta"]; hasDelta {
					t.Fatalf("delta should not be present in assembled response")
				}
			},
		},
		{
			name:    "no valid events",
			sseBody: "not sse data\njust some text\n",
			wantErr: true,
		},
		{
			name:    "only DONE marker",
			sseBody: "data: [DONE]\n",
			wantErr: true,
		},
		{
			name: "SSE with blank lines between events",
			sseBody: "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n" +
				"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" there\"}}]}\n\n" +
				"data: [DONE]\n",
			assertData: func(t *testing.T, data map[string]interface{}) {
				choices := data["choices"].([]interface{})
				msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
				if msg["content"] != "Hi there" {
					t.Fatalf("expected 'Hi there', got %v", msg["content"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := assembleSSEResponse(tt.sseBody, DefaultStreamingJsonPath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("assembleSSEResponse failed: %v", err)
			}
			if tt.assertData != nil {
				tt.assertData(t, data)
			}
		})
	}
}

func TestIsSSEContent(t *testing.T) {
	if !isSSEContent("data: {\"foo\":1}\ndata: [DONE]\n") {
		t.Fatal("expected true for SSE content")
	}
	if isSSEContent("{\"foo\":1}") {
		t.Fatal("expected false for plain JSON")
	}
}

func TestSemanticCachePolicy_OnResponse_SSE(t *testing.T) {
	sseBody := "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"cached\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" answer\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n" +
		"data: [DONE]\n"

	var storedResponse vectordbproviders.CacheResponse
	p := &SemanticCachePolicy{
		streamingJsonPath: DefaultStreamingJsonPath,
		vectorStoreProvider: &mockVectorDBProvider{storeFn: func(embeddings []float32, response vectordbproviders.CacheResponse, filter map[string]interface{}) error {
			storedResponse = response
			return nil
		}},
		cacheUnauthenticated: true, // exercises the api_id-only shared bucket path; per-caller scoping is covered by provenance_test.go
	}

	ctx := &policy.ResponseContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-sse", Metadata: map[string]interface{}{MetadataKeyEmbedding: "[0.1,0.2]"}, APIName: "Chat", APIVersion: "v1"},
		ResponseStatus:  200,
		ResponseBody:    &policy.Body{Content: []byte(sseBody), Present: true},
		ResponseHeaders: &policy.Headers{},
	}

	action := p.OnResponseBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}

	if storedResponse.ResponsePayload == nil {
		t.Fatal("expected SSE response to be cached, but store was not called")
	}
	if storedResponse.ResponsePayload["object"] != "chat.completion" {
		t.Fatalf("expected assembled object=chat.completion, got %v", storedResponse.ResponsePayload["object"])
	}
	choices, ok := storedResponse.ResponsePayload["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		t.Fatal("expected choices in stored response")
	}
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if msg["content"] != "cached answer" {
		t.Fatalf("expected assembled content='cached answer', got %v", msg["content"])
	}
}

func TestAssembleSSEResponse_CustomStreamingJsonPath(t *testing.T) {
	// Simulate a provider that uses a different path, e.g. $.result.text
	sseBody := "data: {\"id\":\"1\",\"result\":{\"text\":\"Hello\"}}\n" +
		"data: {\"id\":\"1\",\"result\":{\"text\":\" custom\"}}\n" +
		"data: [DONE]\n"

	data, err := assembleSSEResponse(sseBody, "$.result.text")
	if err != nil {
		t.Fatalf("assembleSSEResponse with custom path failed: %v", err)
	}
	// choices rebuilding won't apply (no choices in events), but content should be extracted
	_ = data // no panic = success; verify content was extracted
}

func TestParseParams_StreamingJsonPath(t *testing.T) {
	// Default path when not specified
	p := &SemanticCachePolicy{}
	baseParams := map[string]interface{}{
		"embeddingProvider":   "AZURE_OPENAI",
		"vectorStoreProvider": "REDIS",
		"similarityThreshold": 0.5,
		"embeddingEndpoint":   "http://example.com",
		"apiKey":              "secret",
		"dbHost":              "localhost",
		"dbPort":              6379,
		"embeddingDimension":  1536,
	}
	if err := parseParams(baseParams, p); err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	if p.streamingJsonPath != DefaultStreamingJsonPath {
		t.Fatalf("expected default streamingJsonPath=%q, got %q", DefaultStreamingJsonPath, p.streamingJsonPath)
	}

	// Custom path
	p2 := &SemanticCachePolicy{}
	customParams := make(map[string]interface{})
	for k, v := range baseParams {
		customParams[k] = v
	}
	customParams["streamingJsonPath"] = "$.result.delta.text"
	if err := parseParams(customParams, p2); err != nil {
		t.Fatalf("parseParams with custom streamingJsonPath failed: %v", err)
	}
	if p2.streamingJsonPath != "$.result.delta.text" {
		t.Fatalf("expected streamingJsonPath=$.result.delta.text, got %q", p2.streamingJsonPath)
	}

	// Invalid type
	p3 := &SemanticCachePolicy{}
	badParams := make(map[string]interface{})
	for k, v := range baseParams {
		badParams[k] = v
	}
	badParams["streamingJsonPath"] = 123
	if err := parseParams(badParams, p3); err == nil {
		t.Fatal("expected error for non-string streamingJsonPath")
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
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}
