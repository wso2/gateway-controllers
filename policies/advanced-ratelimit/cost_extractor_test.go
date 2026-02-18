package ratelimit

import (
	"bytes"
	"compress/gzip"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestCostExtractor_ExtractResponseCost_GzipEncodedBody(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	body := gzipBytes(t, []byte(`{"usage":{"prompt_tokens":42}}`))
	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-encoding": {"gzip"},
			"content-type":     {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: body,
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from gzip response body to succeed")
	}
	if cost != 42 {
		t.Fatalf("expected extracted cost to be 42, got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCost_InvalidGzipBodyFallsBackToDefault(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 7,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-encoding": {"gzip"},
			"content-type":     {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"usage":{"prompt_tokens":42}}`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if extracted {
		t.Fatal("expected extraction to fail for invalid gzip payload")
	}
	if cost != 7 {
		t.Fatalf("expected default cost 7, got %v", cost)
	}
}

func gzipBytes(t *testing.T, input []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(input); err != nil {
		t.Fatalf("failed to gzip test input: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	return buf.Bytes()
}
