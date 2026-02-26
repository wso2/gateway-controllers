package basicratelimit

import (
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestTransformToRatelimitParams_TranslatesRequestsToLimit(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 100,
				"duration": "1m",
			},
		},
		"algorithm": "gcra",
		"backend":   "memory",
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})

	quotas, ok := rlParams["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatalf("expected one quota, got %v", rlParams["quotas"])
	}

	quota, ok := quotas[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected quota to be map, got %T", quotas[0])
	}

	limits, ok := quota["limits"].([]interface{})
	if !ok || len(limits) != 1 {
		t.Fatalf("expected one limit, got %v", quota["limits"])
	}

	limitEntry, ok := limits[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected limit entry to be map, got %T", limits[0])
	}

	if _, hasRequests := limitEntry["requests"]; hasRequests {
		t.Fatalf("expected requests field to be translated out, got %v", limitEntry)
	}

	if got := limitEntry["limit"]; got != 100 {
		t.Fatalf("expected translated limit=100, got %v", got)
	}

	if rlParams["algorithm"] != "gcra" {
		t.Fatalf("expected algorithm pass-through, got %v", rlParams["algorithm"])
	}
	if rlParams["backend"] != "memory" {
		t.Fatalf("expected backend pass-through, got %v", rlParams["backend"])
	}
}

func TestTransformToRatelimitParams_UsesAPINamespaceKeyForAPILevel(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 10,
				"duration": "1s",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{
		AttachedTo: policy.LevelAPI,
	})

	quotas := rlParams["quotas"].([]interface{})
	quota := quotas[0].(map[string]interface{})
	keyExtraction := quota["keyExtraction"].([]interface{})
	firstExtractor := keyExtraction[0].(map[string]interface{})

	if firstExtractor["type"] != "apiname" {
		t.Fatalf("expected apiname key extraction for API level, got %v", firstExtractor["type"])
	}
}

func TestTransformToRatelimitParams_AllowsLegacyLimitField(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"limit":    50,
				"duration": "1m",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})

	quotas := rlParams["quotas"].([]interface{})
	quota := quotas[0].(map[string]interface{})
	limits := quota["limits"].([]interface{})
	limitEntry := limits[0].(map[string]interface{})

	if got := limitEntry["limit"]; got != 50 {
		t.Fatalf("expected legacy limit=50 to remain supported, got %v", got)
	}
}

