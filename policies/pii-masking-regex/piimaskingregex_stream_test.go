package piimaskingregex

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// driveResponseStream simulates the kernel driving the streaming response phase:
// it delivers each chunk to OnResponseBodyChunk (EndOfStream set on the last),
// and reconstructs the bytes sent downstream using the documented action
// semantics — ForwardResponseChunk.Body nil = pass the original chunk through,
// non-nil = replace the chunk with those bytes (empty slice = emit nothing).
// See sdk action.go and openai-to-bedrock-transformer for the same contract.
func driveResponseStream(t *testing.T, p *PIIMaskingRegexPolicy, respCtx *policy.ResponseStreamContext, chunks []string) string {
	t.Helper()
	var out strings.Builder
	for i, c := range chunks {
		sb := &policy.StreamBody{
			Chunk:       []byte(c),
			EndOfStream: i == len(chunks)-1,
			Index:       uint64(i),
		}
		action := p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)
		switch a := action.(type) {
		case policy.ForwardResponseChunk:
			if a.Body == nil {
				out.WriteString(c) // passthrough original chunk
			} else {
				out.Write(a.Body) // replace (empty = nothing)
			}
		case policy.TerminateResponseChunk:
			if a.Body != nil {
				out.Write(a.Body)
			}
			return out.String()
		default:
			t.Fatalf("chunk %d: unexpected action type %T", i, action)
		}
	}
	return out.String()
}

func streamingRespCtxWithPII(mapping map[string]string) *policy.ResponseStreamContext {
	return &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata: map[string]interface{}{
				MetadataKeyPIIEntities: mapping,
			},
		},
	}
}

// splitEvery breaks s into chunks of at most n bytes, mimicking arbitrary TCP /
// chunked-transfer framing boundaries.
func splitEvery(s string, n int) []string {
	var chunks []string
	for len(s) > n {
		chunks = append(chunks, s[:n])
		s = s[n:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

const maskedMenuBody = `{
  "id": "chatcmpl-ECLSc2xRestoreTest",
  "object": "chat.completion",
  "created": 1786611132,
  "model": "gpt-4o-2024-08-06",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Thanks! I've sent the confirmation to [EMAIL_0000]. Call us on [PHONE_0001] if anything changes."
      },
      "finish_reason": "stop"
    }
  ]
}
`

// TestOnResponseBodyChunk_NonSSE_RestoresAcrossChunkBoundaries is the core
// regression test. The body is delivered in small chunks (27 bytes first, to
// mirror the production truncation report) and a placeholder is deliberately
// split across a chunk boundary. The full restored body must be reconstructed
// exactly, with every placeholder replaced and nothing truncated.
func TestOnResponseBodyChunk_NonSSE_RestoresAcrossChunkBoundaries(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true})
	respCtx := streamingRespCtxWithPII(map[string]string{
		"guest@example.com": "[EMAIL_0000]",
		"212-555-0175":      "[PHONE_0001]",
	})

	out := driveResponseStream(t, p, respCtx, splitEvery(maskedMenuBody, 27))

	if !json.Valid([]byte(strings.TrimSpace(out))) {
		t.Fatalf("restored body is not valid JSON:\n%s", out)
	}
	if strings.Contains(out, "[EMAIL_0000]") || strings.Contains(out, "[PHONE_0001]") {
		t.Fatalf("placeholders were not fully restored:\n%s", out)
	}
	if !strings.Contains(out, "guest@example.com") || !strings.Contains(out, "212-555-0175") {
		t.Fatalf("original PII values missing from restored body:\n%s", out)
	}
	// Byte-for-byte: the output must equal the masked body with placeholders
	// swapped for originals — no bytes dropped anywhere.
	want := strings.NewReplacer(
		"[EMAIL_0000]", "guest@example.com",
		"[PHONE_0001]", "212-555-0175",
	).Replace(maskedMenuBody)
	if out != want {
		t.Fatalf("restored body mismatch\n got: %q\nwant: %q", out, want)
	}
}

// TestOnResponseBodyChunk_NonSSE_NoPlaceholderInResponse is the exact production
// failure: a request tripped a PII regex (metadata is set), but the response
// body contains no placeholder. The whole body must still be forwarded intact —
// previously it was truncated to an early chunk.
func TestOnResponseBodyChunk_NonSSE_NoPlaceholderInResponse(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"phone": true})
	respCtx := streamingRespCtxWithPII(map[string]string{"212-555-0175": "[PHONE_0000]"})

	body := `{
  "id": "chatcmpl-ECLSc2xNoPlaceholder",
  "object": "chat.completion",
  "choices": [{"index":0,"message":{"role":"assistant","content":"How can I help you today?"},"finish_reason":"stop"}]
}
`
	out := driveResponseStream(t, p, respCtx, splitEvery(body, 27))
	if out != body {
		t.Fatalf("body was altered or truncated\n got: %q\nwant: %q", out, body)
	}
}

// TestOnResponseBodyChunk_NonSSE_IntermediateChunksSuppressed verifies the
// withhold-then-emit mechanism: every non-final chunk emits an empty (non-nil)
// body, and the final chunk carries the entire restored body.
func TestOnResponseBodyChunk_NonSSE_IntermediateChunksSuppressed(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtxWithPII(map[string]string{"guest@example.com": "[EMAIL_0000]"})

	chunks := splitEvery(maskedMenuBody, 40)
	var emittedBeforeLast int
	for i, c := range chunks {
		sb := &policy.StreamBody{Chunk: []byte(c), EndOfStream: i == len(chunks)-1, Index: uint64(i)}
		action := p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)
		fwd, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("chunk %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if i < len(chunks)-1 {
			if fwd.Body == nil || len(fwd.Body) != 0 {
				t.Fatalf("chunk %d: expected suppressed ([]byte{}) body, got %q (nil=%v)", i, fwd.Body, fwd.Body == nil)
			}
			emittedBeforeLast += len(fwd.Body)
		} else {
			if len(fwd.Body) == 0 {
				t.Fatalf("final chunk: expected full restored body, got empty")
			}
			if strings.Contains(string(fwd.Body), "[EMAIL_0000]") {
				t.Fatalf("final chunk still contains placeholder:\n%s", fwd.Body)
			}
		}
	}
	if emittedBeforeLast != 0 {
		t.Fatalf("expected 0 bytes emitted before final chunk, got %d", emittedBeforeLast)
	}
}

// TestOnResponseBodyChunk_NonSSE_EmptyEndOfStreamSentinel covers the case where
// the terminating EndOfStream arrives as a separate empty chunk after the
// content chunks. The accumulated body must still be flushed and restored.
func TestOnResponseBodyChunk_NonSSE_EmptyEndOfStreamSentinel(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtxWithPII(map[string]string{"guest@example.com": "[EMAIL_0000]"})

	// Content chunks (none marked EndOfStream) followed by an empty sentinel.
	chunks := append(splitEvery(maskedMenuBody, 50), "")
	out := driveResponseStream(t, p, respCtx, chunks)

	want := strings.Replace(maskedMenuBody, "[EMAIL_0000]", "guest@example.com", 1)
	want = strings.Replace(want, "[PHONE_0001]", "[PHONE_0001]", 1) // PHONE not in mapping; unchanged
	if out != want {
		t.Fatalf("empty-sentinel flush mismatch\n got: %q\nwant: %q", out, want)
	}
}

// TestNeedsMoreResponseData_NonSSE_ReturnsFalse ensures we no longer gate
// non-SSE bodies on kernel-level accumulation (which truncated the response);
// each chunk is handed to us directly.
func TestNeedsMoreResponseData_NonSSE_ReturnsFalse(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	// A partial (invalid) JSON fragment — the old code returned true here.
	if p.NeedsMoreResponseData([]byte(`{` + "\n" + `  "id": "chatcmpl-ECLSc2x`)) {
		t.Fatal("expected NeedsMoreResponseData=false for a non-SSE JSON fragment")
	}
	// A complete JSON body — also false.
	if p.NeedsMoreResponseData([]byte(`{"a":"b"}`)) {
		t.Fatal("expected NeedsMoreResponseData=false for a complete non-SSE JSON body")
	}
}

// TestOnResponseBodyChunk_NoMetadata_StreamsThrough verifies that responses for
// requests that masked no PII stream through unchanged, chunk by chunk (no
// withholding, no added latency).
func TestOnResponseBodyChunk_NoMetadata_StreamsThrough(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id", Metadata: map[string]interface{}{}},
	}
	out := driveResponseStream(t, p, respCtx, splitEvery(maskedMenuBody, 33))
	if out != maskedMenuBody {
		t.Fatalf("expected passthrough of full body, got:\n%s", out)
	}
}
