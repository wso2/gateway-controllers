/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package costbasedrouting

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestParseConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(map[string]interface{})
		contains string
	}{
		{
			name:     "missing primary",
			mutate:   func(p map[string]interface{}) { delete(p, "primary") },
			contains: "'primary' must be an object",
		},
		{
			name:     "primary is not an object",
			mutate:   func(p map[string]interface{}) { p["primary"] = "gpt-4o" },
			contains: "'primary' must be an object",
		},
		{
			name:     "missing primary model",
			mutate:   func(p map[string]interface{}) { p["primary"] = map[string]interface{}{} },
			contains: "'primary.modelName' is required",
		},
		{
			name:     "empty primary model",
			mutate:   func(p map[string]interface{}) { p["primary"] = map[string]interface{}{"model": "   "} },
			contains: "'primary.model' must be a non-empty string",
		},
		{
			name: "primary model wrong type",
			mutate: func(p map[string]interface{}) {
				p["primary"] = map[string]interface{}{"model": 42}
			},
			contains: "'primary.model' must be a non-empty string",
		},
		{
			name: "invalid primary provider",
			mutate: func(p map[string]interface{}) {
				p["primary"] = map[string]interface{}{"model": "gpt-4o", "provider": ""}
			},
			contains: "'primary.provider' must be a non-empty string when supplied",
		},
		{
			name: "primary provider wrong type",
			mutate: func(p map[string]interface{}) {
				p["primary"] = map[string]interface{}{"model": "gpt-4o", "provider": 7}
			},
			contains: "'primary.provider' must be a non-empty string when supplied",
		},
		{
			name:     "missing fallback",
			mutate:   func(p map[string]interface{}) { delete(p, "fallback") },
			contains: "'fallback' must be an object",
		},
		{
			name:     "missing fallback model",
			mutate:   func(p map[string]interface{}) { p["fallback"] = map[string]interface{}{} },
			contains: "'fallback.modelName' is required",
		},
		{
			name:     "empty fallback model",
			mutate:   func(p map[string]interface{}) { p["fallback"] = map[string]interface{}{"model": ""} },
			contains: "'fallback.model' must be a non-empty string",
		},
		{
			name: "invalid fallback provider",
			mutate: func(p map[string]interface{}) {
				p["fallback"] = map[string]interface{}{"model": "gpt-4o-mini", "provider": "  "}
			},
			contains: "'fallback.provider' must be a non-empty string when supplied",
		},
		{
			name:     "missing budgetLimits",
			mutate:   func(p map[string]interface{}) { delete(p, "budgetLimits") },
			contains: "'budgetLimits' is required",
		},
		{
			name:     "empty budgetLimits",
			mutate:   func(p map[string]interface{}) { p["budgetLimits"] = []interface{}{} },
			contains: "'budgetLimits' must contain at least one entry",
		},
		{
			name:     "budgetLimits not an array",
			mutate:   func(p map[string]interface{}) { p["budgetLimits"] = map[string]interface{}{} },
			contains: "'budgetLimits' must be an array",
		},
		{
			name: "budget entry not an object",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{"10 dollars"}
			},
			contains: "'budgetLimits[0]' must be an object",
		},
		{
			name: "missing amount",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"duration": "24h"}}
			},
			contains: "'budgetLimits[0].amount' is required",
		},
		{
			name: "zero amount",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 0, "duration": "24h"}}
			},
			contains: "'budgetLimits[0].amount' must be greater than zero",
		},
		{
			name: "negative amount",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": -5.0, "duration": "24h"}}
			},
			contains: "'budgetLimits[0].amount' must be greater than zero",
		},
		{
			name: "unsupported amount type",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": "10", "duration": "24h"}}
			},
			contains: "'budgetLimits[0].amount' must be a number",
		},
		{
			name: "missing duration",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 10.0}}
			},
			contains: "'budgetLimits[0].duration' is required",
		},
		{
			name: "invalid duration",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 10.0, "duration": "one day"}}
			},
			contains: "'budgetLimits[0].duration' is not a valid Go duration",
		},
		{
			name: "duration wrong type",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 10.0, "duration": 24}}
			},
			contains: "'budgetLimits[0].duration' must be a non-empty Go duration string",
		},
		{
			name: "non-positive duration",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 10.0, "duration": "0s"}}
			},
			contains: "'budgetLimits[0].duration' must be greater than zero",
		},
		{
			name: "second budget entry reports its own index",
			mutate: func(p map[string]interface{}) {
				p["budgetLimits"] = []interface{}{
					map[string]interface{}{"amount": 2.0, "duration": "1h"},
					map[string]interface{}{"amount": 20.0, "duration": "bogus"},
				}
			},
			contains: "'budgetLimits[1].duration'",
		},
		{
			name:     "missing requestModel",
			mutate:   func(p map[string]interface{}) { delete(p, "requestModel") },
			contains: "'requestModel' system parameter is required",
		},
		{
			name: "invalid model location",
			mutate: func(p map[string]interface{}) {
				p["requestModel"] = map[string]interface{}{"location": "cookie", "identifier": "$.model"}
			},
			contains: "'requestModel.location' must be one of payload, header, queryParam, or pathParam",
		},
		{
			name: "model location wrong type",
			mutate: func(p map[string]interface{}) {
				p["requestModel"] = map[string]interface{}{"location": 1, "identifier": "$.model"}
			},
			contains: "'requestModel.location' must be a string",
		},
		{
			name: "empty model identifier",
			mutate: func(p map[string]interface{}) {
				p["requestModel"] = map[string]interface{}{"location": "header", "identifier": "  "}
			},
			contains: "'requestModel.identifier' must be a non-empty string",
		},
		{
			name: "invalid path regular expression",
			mutate: func(p map[string]interface{}) {
				p["requestModel"] = map[string]interface{}{"location": "pathParam", "identifier": "model/(["}
			},
			contains: "'requestModel.identifier' is not a valid model path expression",
		},
		{
			name: "path expression without a capture group",
			mutate: func(p map[string]interface{}) {
				p["requestModel"] = map[string]interface{}{"location": "pathParam", "identifier": "model/[^/]+"}
			},
			contains: "expression must contain a capture group identifying the model segment",
		},
		{
			name: "scale factor overflow",
			mutate: func(p map[string]interface{}) {
				p["costScaleFactor"] = int64(math.MaxInt64)
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 1000.0, "duration": "24h"}}
			},
			contains: "cannot be scaled by costScaleFactor",
		},
		{
			name: "amount too small for the scale factor",
			mutate: func(p map[string]interface{}) {
				p["costScaleFactor"] = 100
				p["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 0.000001, "duration": "24h"}}
			},
			contains: "is too small to represent with costScaleFactor",
		},
		{
			name:     "invalid cost scale factor",
			mutate:   func(p map[string]interface{}) { p["costScaleFactor"] = 0 },
			contains: "'costScaleFactor' must be an integer greater than zero",
		},
		{
			name:     "invalid consumerBased type",
			mutate:   func(p map[string]interface{}) { p["consumerBased"] = "yes" },
			contains: "'consumerBased' is no longer supported",
		},
		{
			name:     "invalid respectRequestedModel type",
			mutate:   func(p map[string]interface{}) { p["respectRequestedModel"] = "yes" },
			contains: "'respectRequestedModel' is no longer supported",
		},
		{
			name:     "invalid onExhausted type",
			mutate:   func(p map[string]interface{}) { p["onExhausted"] = true },
			contains: "'onExhausted' must be a string",
		},
		{
			name:     "invalid onExhausted value",
			mutate:   func(p map[string]interface{}) { p["onExhausted"] = "passthrough" },
			contains: "'onExhausted' must be one of fallback or reject",
		},
		{
			name:     "invalid algorithm",
			mutate:   func(p map[string]interface{}) { p["algorithm"] = "leaky-bucket" },
			contains: "'algorithm' must be one of fixed-window or gcra",
		},
		{
			name:     "invalid backend",
			mutate:   func(p map[string]interface{}) { p["backend"] = "postgres" },
			contains: "'backend' must be one of memory, redis, or redis-local-async",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := validParams()
			tt.mutate(params)

			_, err := parseConfig(params)
			if err == nil {
				t.Fatalf("expected a validation error, got nil")
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected error containing %q, got %q", tt.contains, err.Error())
			}
		})
	}
}

func TestParseConfigDefaults(t *testing.T) {
	params := validParams()
	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CostScaleFactor != DefaultCostScaleFactor {
		t.Errorf("costScaleFactor = %d, want %d", cfg.CostScaleFactor, DefaultCostScaleFactor)
	}
	if cfg.Algorithm != "fixed-window" {
		t.Errorf("algorithm = %q, want fixed-window", cfg.Algorithm)
	}
	if cfg.Backend != "memory" {
		t.Errorf("backend = %q, want memory", cfg.Backend)
	}

	if cfg.OnExhausted != onExhaustedFallback {
		t.Errorf("onExhausted = %q, want fallback", cfg.OnExhausted)
	}
	if !cfg.Redis.FailOpen {
		t.Error("redis.failureMode should default to open")
	}
	if cfg.Redis.KeyPrefix != defaultRedisKeyPrefix {
		t.Errorf("redis.keyPrefix = %q, want %q", cfg.Redis.KeyPrefix, defaultRedisKeyPrefix)
	}
	if cfg.MemoryCleanupInterval != 5*time.Minute {
		t.Errorf("memory.cleanupInterval = %v, want 5m", cfg.MemoryCleanupInterval)
	}
	if len(cfg.BudgetLimits) != 1 {
		t.Fatalf("budgetLimits length = %d, want 1", len(cfg.BudgetLimits))
	}
	if cfg.BudgetLimits[0].Scaled != 10*DefaultCostScaleFactor {
		t.Errorf("scaled limit = %d, want %d", cfg.BudgetLimits[0].Scaled, 10*DefaultCostScaleFactor)
	}
	if cfg.BudgetLimits[0].Duration != 24*time.Hour {
		t.Errorf("duration = %v, want 24h", cfg.BudgetLimits[0].Duration)
	}
	if cfg.Primary.Provider != "openai-primary" || cfg.Fallback.Provider != "openai-fallback" {
		t.Errorf("providers not parsed: %+v %+v", cfg.Primary, cfg.Fallback)
	}
}

func TestParseConfigRejectAllowsFallbackToBeOmitted(t *testing.T) {
	params := validMultiRouteParams()
	params["onExhausted"] = onExhaustedReject
	delete(params, "fallback")

	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OnExhausted != onExhaustedReject {
		t.Errorf("onExhausted = %q, want reject", cfg.OnExhausted)
	}
	if cfg.Fallback != nil {
		t.Errorf("fallback = %+v, want nil", cfg.Fallback)
	}
}

func TestParseConfigFallbackExhaustionRequiresFallbackModel(t *testing.T) {
	params := validMultiRouteParams()
	delete(params, "fallback")

	_, err := parseConfig(params)
	if err == nil || !strings.Contains(err.Error(), "'fallback' is required when 'onExhausted' is 'fallback'") {
		t.Fatalf("expected missing fallback error, got %v", err)
	}
}

func TestParseConfigOptionalProviderOmitted(t *testing.T) {
	params := validParams()
	params["primary"] = map[string]interface{}{"model": "gpt-4o"}
	params["fallback"] = map[string]interface{}{"model": "gpt-4o-mini"}

	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Primary.Provider != "" || cfg.Fallback.Provider != "" {
		t.Errorf("expected empty providers, got %q and %q", cfg.Primary.Provider, cfg.Fallback.Provider)
	}
}

func TestParseConfigSystemParametersBlock(t *testing.T) {
	params := validParams()
	delete(params, "costScaleFactor")
	params["systemParameters"] = map[string]interface{}{"costScaleFactor": 1000000}

	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CostScaleFactor != 1_000_000 {
		t.Errorf("costScaleFactor = %d, want 1000000", cfg.CostScaleFactor)
	}
	if cfg.BudgetLimits[0].Scaled != 10_000_000 {
		t.Errorf("scaled limit = %d, want 10000000", cfg.BudgetLimits[0].Scaled)
	}
}

func TestParseConfigNestedSystemParameters(t *testing.T) {
	params := validParams()
	params["backend"] = "redis"
	params["algorithm"] = "gcra"
	params["redis"] = map[string]interface{}{
		"host":        "redis.example.com",
		"port":        6380,
		"db":          3,
		"keyPrefix":   "cbr:v1:",
		"failureMode": "closed",
		"readTimeout": "7s",
		"poolSize":    12,
	}
	params["memory"] = map[string]interface{}{"cleanupInterval": "1m"}
	params["local"] = map[string]interface{}{"syncInterval": "100ms", "flushWorkers": 4}

	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Redis.Host != "redis.example.com" || cfg.Redis.Port != 6380 || cfg.Redis.DB != 3 {
		t.Errorf("redis connection not parsed: %+v", cfg.Redis)
	}
	if cfg.Redis.KeyPrefix != "cbr:v1:" {
		t.Errorf("redis.keyPrefix = %q", cfg.Redis.KeyPrefix)
	}
	if cfg.Redis.FailOpen {
		t.Error("redis.failureMode=closed should disable fail-open")
	}
	if cfg.Redis.ReadTimeout != 7*time.Second {
		t.Errorf("redis.readTimeout = %v, want 7s", cfg.Redis.ReadTimeout)
	}
	if cfg.Redis.PoolSize != 12 {
		t.Errorf("redis.poolSize = %d, want 12", cfg.Redis.PoolSize)
	}
	if cfg.MemoryCleanupInterval != time.Minute {
		t.Errorf("memory.cleanupInterval = %v, want 1m", cfg.MemoryCleanupInterval)
	}
	if cfg.Local.SyncInterval != 100*time.Millisecond || cfg.Local.FlushWorkers != 4 {
		t.Errorf("local config not parsed: %+v", cfg.Local)
	}
	if cfg.Algorithm != "gcra" {
		t.Errorf("algorithm = %q, want gcra", cfg.Algorithm)
	}
}

func TestParseConfigMultipleBudgetWindows(t *testing.T) {
	params := validParams()
	params["budgetLimits"] = []interface{}{
		map[string]interface{}{"amount": 2.0, "duration": "1h"},
		map[string]interface{}{"amount": 20.0, "duration": "24h"},
	}

	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.BudgetLimits) != 2 {
		t.Fatalf("budgetLimits length = %d, want 2", len(cfg.BudgetLimits))
	}
	if cfg.BudgetLimits[0].Duration != time.Hour || cfg.BudgetLimits[1].Duration != 24*time.Hour {
		t.Errorf("durations not parsed in order: %+v", cfg.BudgetLimits)
	}
}

func TestParseConfigBodyLocationAlias(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "body", "identifier": "$.model"}

	cfg, err := parseConfig(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RequestModel.Location != "payload" {
		t.Errorf("location = %q, want payload", cfg.RequestModel.Location)
	}
}

func TestCompilePathModelExpression(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		path       string
		wantModel  string
		wantErr    bool
	}{
		{
			name:       "explicit capture group",
			expression: `model/([^/]+)/`,
			path:       "/v1/model/gpt-4o/invoke",
			wantModel:  "gpt-4o",
		},
		{
			name:       "positive lookbehind is normalized",
			expression: `(?<=models/)[^:]+`,
			path:       "/v1beta/models/gemini-pro:generateContent",
			wantModel:  "gemini-pro",
		},
		{
			name:       "no capture group is rejected",
			expression: `model/[^/]+`,
			wantErr:    true,
		},
		{
			name:       "invalid regular expression",
			expression: `model/([`,
			wantErr:    true,
		},
		{
			name:       "unterminated lookbehind",
			expression: `(?<=models/`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expression, group, err := compilePathModelExpression(tt.expression)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			model, _ := modelFromPath(tt.path, expression, group)
			if model != tt.wantModel {
				t.Errorf("captured model = %q, want %q", model, tt.wantModel)
			}
		})
	}
}

func TestScaleDollarsOverflow(t *testing.T) {
	if _, err := scaleDollars(1e30, DefaultCostScaleFactor); err == nil {
		t.Error("expected an overflow error for an enormous amount")
	}
	if _, err := scaleDollars(math.NaN(), DefaultCostScaleFactor); err == nil {
		t.Error("expected an error for NaN")
	}
	if _, err := scaleDollars(math.Inf(1), DefaultCostScaleFactor); err == nil {
		t.Error("expected an error for +Inf")
	}
	scaled, err := scaleDollars(10, DefaultCostScaleFactor)
	if err != nil || scaled != 10*DefaultCostScaleFactor {
		t.Errorf("scaleDollars(10) = %d, %v", scaled, err)
	}
}

func TestModelBudgetValidation(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(map[string]interface{})
		contains string
	}{
		{"duplicate models", func(p map[string]interface{}) {
			entries := p["modelBudgets"].([]interface{})
			entries[1].(map[string]interface{})["model"] = entries[0].(map[string]interface{})["model"]
		}, "duplicates model name"},
		{"duplicate wildcard aliases", func(p map[string]interface{}) {
			entries := p["modelBudgets"].([]interface{})
			entries[0].(map[string]interface{})["model"] = map[string]interface{}{"modelName": "*"}
			entries[1].(map[string]interface{})["model"] = map[string]interface{}{"modelName": "other"}
		}, "duplicates model name"},
		{"wildcard provider", func(p map[string]interface{}) {
			p["modelBudgets"].([]interface{})[0].(map[string]interface{})["model"] = map[string]interface{}{"modelName": "*", "providerName": "openai"}
		}, "wildcard budget must omit providerName"},
		{"wildcard fallback", func(p map[string]interface{}) {
			p["fallback"] = map[string]interface{}{"modelName": "*"}
		}, "must specify a concrete model"},
		{"empty model budgets", func(p map[string]interface{}) { p["modelBudgets"] = []interface{}{} }, "between 1 and 10"},
		{"missing models", func(p map[string]interface{}) {
			delete(p["modelBudgets"].([]interface{})[0].(map[string]interface{}), "model")
		}, "modelBudgets[0].model"},
		{"missing model name", func(p map[string]interface{}) {
			p["modelBudgets"].([]interface{})[0].(map[string]interface{})["model"] = map[string]interface{}{}
		}, "modelBudgets[0].model.modelName"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := validMultiRouteParams()
			tt.mutate(params)
			if _, err := parseConfig(params); err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("error = %v; want %s", err, tt.contains)
			}
		})
	}
}

func TestLegacyRoutingNamesUseNewMatchingBehavior(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{map[string]interface{}{
			"target":       map[string]interface{}{"model": "gpt-4o", "provider": "openai"},
			"budgetLimits": []interface{}{map[string]interface{}{"amount": 1.0, "duration": "24h"}},
		}},
		"default":      map[string]interface{}{"model": "gpt-4o-mini"},
		"onExhausted":  "default",
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	}
	p := newPolicy(t, params)
	if p.config.OnExhausted != onExhaustedFallback {
		t.Fatal("legacy exhaustion value not normalized")
	}
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	response := immediate(t, requestBody(p, metadata, []byte(`{"model":"unknown-model"}`)))
	if response.StatusCode != 429 {
		t.Fatal("legacy names allowed an unbudgeted fallback")
	}
}
