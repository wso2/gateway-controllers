package piimaskingregex

import (
	"context"
	"regexp"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var emailPlaceholder = regexp.MustCompile(`\[EMAIL_[0-9a-f]{4}\]`)

// An object-valued JSONPath target used to be skipped, forwarding the PII upstream unmasked.
func TestPIIMaskingRegexPolicy_OnRequest_MasksEveryFieldOfObjectValue(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})

	ctx := piiRequestContext(`{"model":"jev-latest","state":{"ticket":"reach me at a.user@example.com","notes":{"cc":"b.user@example.com"}}}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	if len(mods.Body) == 0 {
		t.Fatalf("expected a modified body")
	}
	body := string(mods.Body)
	if strings.Contains(body, "a.user@example.com") || strings.Contains(body, "b.user@example.com") {
		t.Fatalf("expected every email to be masked, got %s", body)
	}
	if got := len(emailPlaceholder.FindAllString(body, -1)); got != 2 {
		t.Fatalf("expected 2 placeholders, got %d in %s", got, body)
	}
	if !strings.Contains(body, `"model":"jev-latest"`) {
		t.Fatalf("expected fields outside the JSONPath to be untouched, got %s", body)
	}
}

// Values matched by a wildcard share one placeholder map, so two different emails never
// collide on the same placeholder and response restoration stays unambiguous.
func TestPIIMaskingRegexPolicy_OnRequest_WildcardSharesOnePlaceholderMap(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.questions.*.instructions"})

	ctx := piiRequestContext(`{"questions":{"a":{"type":"noul","instructions":"Is a.user@example.com urgent?"},"b":{"type":"noul","instructions":"Is b.user@example.com urgent?"},"c":{"type":"noul","instructions":"Again a.user@example.com?"}}}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	body := string(mods.Body)
	if strings.Contains(body, "@example.com") {
		t.Fatalf("expected every email to be masked, got %s", body)
	}

	mapping, ok := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if !ok || len(mapping) != 2 {
		t.Fatalf("expected one mapping entry per distinct email, got %#v", ctx.Metadata[MetadataKeyPIIEntities])
	}
	if mapping["a.user@example.com"] == mapping["b.user@example.com"] {
		t.Fatalf("expected distinct placeholders, got %#v", mapping)
	}
}

// Chat multimodal content is an array of parts; its text parts used to be skipped.
func TestPIIMaskingRegexPolicy_OnRequest_MasksMultimodalContentParts(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})

	ctx := piiRequestContext(`{"messages":[{"role":"user","content":[{"type":"text","text":"mail a.user@example.com"},{"type":"image_url","image_url":{"url":"https://example.com/cat.png"}}]}]}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	body := string(mods.Body)
	if strings.Contains(body, "a.user@example.com") || !emailPlaceholder.MatchString(body) {
		t.Fatalf("expected the text part to be masked, got %s", body)
	}
	if !strings.Contains(body, "https://example.com/cat.png") {
		t.Fatalf("expected the image URL to be untouched, got %s", body)
	}
}

// A JSON number is masked too, so an SSN sent as a number is not forwarded as-is.
func TestPIIMaskingRegexPolicy_OnRequest_MasksNumericLeaf(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"ssn": true, "jsonPath": "$.state"})

	ctx := piiRequestContext(`{"state":{"applicant":{"ssn":123456789,"age":42}}}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	body := string(mods.Body)
	if strings.Contains(body, "123456789") {
		t.Fatalf("expected the numeric SSN to be masked, got %s", body)
	}
	if !strings.Contains(body, `"age":42`) {
		t.Fatalf("expected non-PII numbers to stay numbers, got %s", body)
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_RedactsObjectValue(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "redactPII": true, "jsonPath": "$.state"})

	ctx := piiRequestContext(`{"state":{"ticket":"reach me at a.user@example.com","status":"open"}}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	body := string(mods.Body)
	if strings.Contains(body, "a.user@example.com") || !strings.Contains(body, "*****") {
		t.Fatalf("expected the email to be redacted, got %s", body)
	}
	if !strings.Contains(body, `"status":"open"`) {
		t.Fatalf("expected fields without PII to be untouched, got %s", body)
	}
	if _, exists := ctx.Metadata[MetadataKeyPIIEntities]; exists {
		t.Fatalf("did not expect a restore mapping in redact mode")
	}
}

func TestPIIMaskingRegexPolicy_OnRequest_ObjectValueWithoutPII_NoOp(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})

	ctx := piiRequestContext(`{"state":{"ticket":"no pii here","count":3}}`)
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	if mods.Body != nil {
		t.Fatalf("expected no modification, got %s", string(mods.Body))
	}
}

// Masked values from a structured request are restored in the response by the existing path.
func TestPIIMaskingRegexPolicy_StructuredMaskRestoresInResponse(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})

	reqCtx := piiRequestContext(`{"state":{"ticket":"reach me at a.user@example.com"}}`)
	mustPIIRequestMods(t, p.OnRequestBody(context.Background(), reqCtx, nil))
	mapping := reqCtx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	placeholder := mapping["a.user@example.com"]

	respCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id", Metadata: reqCtx.Metadata},
		ResponseBody:  &policy.Body{Content: []byte(`{"answers":{"note":"contact ` + placeholder + `"}}`), Present: true},
	}
	mods, ok := p.OnResponseBody(context.Background(), respCtx, nil).(policy.DownstreamResponseModifications)
	if !ok || !strings.Contains(string(mods.Body), "a.user@example.com") {
		t.Fatalf("expected the placeholder to be restored, got %s", string(mods.Body))
	}
}

// A failed write-back must never return the original, unmasked payload.
func TestPIIMaskingRegexPolicy_UpdatePayload_FailsInsteadOfReturningOriginal(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})

	original := []byte(`not json a.user@example.com`)
	out, err := p.updatePayloadWithMaskedContent(original, "a.user@example.com", "[EMAIL_0000]", "$.messages[-1].content")
	if err == nil {
		t.Fatalf("expected an error, got payload %s", string(out))
	}
	if out != nil {
		t.Fatalf("expected no payload on error, got %s", string(out))
	}
}
