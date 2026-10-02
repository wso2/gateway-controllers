package llmcost_test

import (
	"testing"

	llmcost "github.com/wso2/gateway-controllers/policies/llm-cost"
)

// TypeSafe bills purely per token, so it is priced from the shipped template
// alone with no calculator. Jev pricing in testdata/model_prices.json: input
// $0.042 per 1M tokens (4.2e-8 per token), output free.

// 296 input tokens * 4.2e-8 = "0.0000124320"; the 20 output tokens are free.
// The template has no totalTokens, so this also covers the derived total.
func TestTypeSafeExactCost(t *testing.T) {
	loadShippedTemplate(t, "typesafe", "typesafe-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"jev-1.13.0","answers":{"is_urgent":{"type":"noul","noul":0.95}},"usage":{"input_tokens":296,"output_tokens":20}}`)

	cost, status := runResponse(t, p, "typesafe", body, nil, "/v1/systemone")

	if status != llmcost.CostStatusCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusCalculated)
	}
	if want := "0.0000124320"; cost != want {
		t.Fatalf("cost = %q, want %q", cost, want)
	}
}

// Output tokens never add cost for Jev: 1M input tokens cost exactly $0.042.
func TestTypeSafeOutputIsFree(t *testing.T) {
	loadShippedTemplate(t, "typesafe", "typesafe-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"jev-1.13.0","answers":{},"usage":{"input_tokens":1000000,"output_tokens":500000}}`)

	if cost, _ := runResponse(t, p, "typesafe", body, nil, "/v1/systemone"); cost != "0.0420000000" {
		t.Fatalf("cost = %q, want %q", cost, "0.0420000000")
	}
}

// A Jev version with no pricing entry must not borrow another version's price.
func TestTypeSafeUnknownJevVersionIsNotCalculated(t *testing.T) {
	loadShippedTemplate(t, "typesafe", "typesafe-template.yaml")
	p := newTestPolicy(t)

	body := []byte(`{"model":"jev-2.0.0","answers":{},"usage":{"input_tokens":296,"output_tokens":20}}`)

	cost, status := runResponse(t, p, "typesafe", body, nil, "/v1/systemone")

	if status != llmcost.CostStatusNotCalculated {
		t.Fatalf("status = %q, want %q", status, llmcost.CostStatusNotCalculated)
	}
	if cost != "0.0000000000" {
		t.Fatalf("cost = %q, want %q", cost, "0.0000000000")
	}
}

// Every listed Jev model, including the aliases a caller may echo back, is priced.
func TestTypeSafeJevModelsArePriced(t *testing.T) {
	loadShippedTemplate(t, "typesafe", "typesafe-template.yaml")
	p := newTestPolicy(t)

	for _, model := range []string{"jev-1.13.0", "jev-latest", "jev-preview"} {
		body := []byte(`{"model":"` + model + `","answers":{},"usage":{"input_tokens":296,"output_tokens":20}}`)
		cost, status := runResponse(t, p, "typesafe", body, nil, "/v1/systemone")
		if status != llmcost.CostStatusCalculated || cost != "0.0000124320" {
			t.Errorf("model %q: cost = %q, status = %q; want 0.0000124320, calculated", model, cost, status)
		}
	}
}

// TypeSafe has no non-token charges, so it needs no calculator.
func TestTypeSafeHasNoCalculator(t *testing.T) {
	if llmcost.SelectCalculator("typesafe") != nil {
		t.Error("SelectCalculator(\"typesafe\") should be nil")
	}
}
