package contentlengthguardrail

import (
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// An object value or a wildcard match is measured on all of its text, where it used to be
// rejected as an extraction error.
func TestValidatePayload_StructuredValues(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	// "abc" + "\n" + "de" = 6 bytes, whichever order the keys come in.
	pass := p.validatePayload([]byte(`{"state":{"a":"abc","b":"de"}}`), ContentLengthGuardrailPolicyParams{
		Min: 6, Max: 6, JsonPath: "$.state",
	}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected an object state to be measured in full, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"questions":{"a":{"instructions":"short"},"b":{"instructions":"this one is much longer"}}}`), ContentLengthGuardrailPolicyParams{
		Min: 1, Max: 10, JsonPath: "$.questions.*.instructions",
	}, false)
	if _, ok := fail.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected the joined questions to exceed the limit, got %T", fail)
	}
}
