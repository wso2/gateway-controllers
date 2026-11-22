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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package modelaccesscontrol

import (
	"os"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_ValidConfiguration(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		// The controller merges every template extraction field; the policy ignores them.
		"responseModel": map[string]any{"location": "payload", "identifier": "$.model"},
		"promptTokens":  map[string]any{"location": "payload", "identifier": "$.usage.prompt_tokens"},
		"access":        map[string]any{"mode": "allow", "models": []any{" GPT-4o "}, "modelPatterns": []any{"gpt-4o-mini-.*"}, "onMissingModel": "skip"},
		"fallback": map[string]any{
			"mappingPatterns": []any{patternRule("claude-(.+)", "anthropic-$1", "anthropic")},
		},
	})
	if p.cfg.access.mode != modeAllow || p.cfg.access.onMissingModel != missingModelSkip {
		t.Fatalf("access = %+v", p.cfg.access)
	}
	if _, ok := p.cfg.access.models["gpt-4o"]; !ok {
		t.Error("model was not normalized to lower case and trimmed")
	}
	if got := p.cfg.mapping.resolve("claude-opus"); got.target.model != "anthropic-opus" || got.target.provider != "anthropic" {
		t.Errorf("pattern mapping = %+v", got)
	}
}

func TestGetPolicy_Defaults(t *testing.T) {
	p := mustPolicy(t, map[string]any{"requestModel": payloadModel(), "access": allowOnly("gpt-4o")})
	if p.cfg.access.onMissingModel != missingModelDeny {
		t.Errorf("onMissingModel = %q, want deny", p.cfg.access.onMissingModel)
	}
	if p.cfg.mapping != nil {
		t.Error("mapping should be nil when not configured")
	}
}

func TestGetPolicy_RejectsInvalidConfiguration(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{"requestModel": payloadModel(), "access": allowOnly("gpt-4o")}
	}
	with := func(key string, value any) map[string]any {
		params := valid()
		params[key] = value
		return params
	}
	withAccess := func(key string, value any) map[string]any {
		access := allowOnly("gpt-4o")
		access[key] = value
		return with("access", access)
	}
	withMapping := func(mapping map[string]any) map[string]any { return with("fallback", mapping) }

	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"nil params", nil, "'params' is required"},
		{"missing access", map[string]any{"requestModel": payloadModel()}, "'access' is required"},
		{"access not object", with("access", "deny"), "'access' must be an object"},
		{"unknown access field", withAccess("aliases", []any{}), "unknown field"},
		{"missing mode", with("access", map[string]any{"models": []any{"a"}}), "'access.mode' is required"},
		{"mode wrong case", withAccess("mode", "DENY"), "'access.mode' must be"},
		{"missing models", with("access", map[string]any{"mode": "allow"}), "'access.models' is required"},
		{"empty models", withAccess("models", []any{}), "at least one model"},
		{"blank model", withAccess("models", []any{"  "}), "must not be empty"},
		{"non-string model", withAccess("models", []any{42}), "must be a string"},
		{"duplicate model", withAccess("models", []any{"gpt-4o", "GPT-4O "}), "repeats an earlier model"},
		{"invalid model pattern", withAccess("modelPatterns", []any{"gpt-(4"}), "not a valid RE2"},
		{"too long model pattern", withAccess("modelPatterns", []any{strings.Repeat("a", maxPatternLength+1)}), "at most"},
		{"too many model patterns", withAccess("modelPatterns", make([]any, maxPatterns+1)), "at most"},
		{"statusCode removed", withAccess("statusCode", 403), "unknown field \"statusCode\""},
		{"onMissingModel invalid", withAccess("onMissingModel", "allow"), "'access.onMissingModel' must be"},
		{"mapping not object", with("fallback", []any{}), "'fallback' must be an object"},
		{"old aliases name", withMapping(map[string]any{"aliases": []any{}, "mappingPatterns": []any{literalRule("a", "b", "")}}), "unknown field \"aliases\""},
		{"restoreResponseModel removed", withMapping(map[string]any{"mappingPatterns": []any{literalRule("a", "b", "")}, "restoreResponseModel": true}), "unknown field \"restoreResponseModel\""},
		{"mapping entry not object", withMapping(map[string]any{"mappingPatterns": []any{"a"}}), "must be an object"},
		{"mapping missing from", withMapping(map[string]any{"mappingPatterns": []any{map[string]any{"to": "b"}}}), "fromPattern' is required"},
		{"mapping blank to", withMapping(map[string]any{"mappingPatterns": []any{literalRule("a", " ", "")}}), "must not be empty"},
		{"mapping to with control", withMapping(map[string]any{"mappingPatterns": []any{literalRule("a", "b\nc", "")}}), "control characters"},
		{"mapping blank provider", withMapping(map[string]any{"mappingPatterns": []any{map[string]any{"fromPattern": "a", "to": "b", "provider": ""}}}), "must not be empty"},
		{"mapping provider with quote", withMapping(map[string]any{"mappingPatterns": []any{literalRule("a", "b", "x'y")}}), "without quotes"},
		{"mapping unknown field", withMapping(map[string]any{"mappingPatterns": []any{map[string]any{"from": "a", "to": "b", "alias": "c"}}}), "unknown field"},
		{"exact mappings removed", withMapping(map[string]any{"mappings": []any{map[string]any{"from": "a", "to": "b"}}}), "unknown field \"mappings\""},
		{"invalid mapping pattern", withMapping(map[string]any{"mappingPatterns": []any{patternRule("(", "b", "")}}), "not a valid RE2"},
		{"pattern undefined group", withMapping(map[string]any{"mappingPatterns": []any{patternRule("x-(.+)", "$2", "")}}), "references capture group $2"},
		{"pattern undefined name", withMapping(map[string]any{"mappingPatterns": []any{patternRule("x-(?P<v>.+)", "${w}", "")}}), "does not define"},
		{"pattern empty brace", withMapping(map[string]any{"mappingPatterns": []any{patternRule("x-(.+)", "m-${}", "")}}), "empty capture reference"},
		{"pattern unterminated brace", withMapping(map[string]any{"mappingPatterns": []any{patternRule("x-(.+)", "m-${1", "")}}), "unterminated"},
		{"pattern can expand empty", withMapping(map[string]any{"mappingPatterns": []any{patternRule("(.*)", "$1", "")}}), "empty model name"},
		{"too many mapping patterns", withMapping(map[string]any{"mappingPatterns": make([]any, maxPatterns+1)}), "at most"},
		{"missing requestModel", map[string]any{"access": allowOnly("a")}, "'requestModel' is required"},
		{"requestModel unsupported location", with("requestModel", map[string]any{"location": "body", "identifier": "$.model"}), "must be one of"},
		{"requestModel blank identifier", with("requestModel", map[string]any{"location": "payload", "identifier": " "}), "must not be empty"},
		{"payload root identifier", with("requestModel", map[string]any{"location": "payload", "identifier": "$"}), "document root"},
		{"payload wildcard identifier", with("requestModel", map[string]any{"location": "payload", "identifier": "$.choices.*.model"}), "dotted JSONPath"},
		{"header invalid name", with("requestModel", map[string]any{"location": "header", "identifier": "x model"}), "valid header name"},
		{"query invalid name", with("requestModel", map[string]any{"location": "queryParam", "identifier": "a&b"}), "query parameter name"},
		{"path invalid regex", with("requestModel", map[string]any{"location": "pathParam", "identifier": "/models/(["}), "not a valid RE2"},
		{"path rewrite needs capture", func() map[string]any {
			params := withMapping(map[string]any{"mappingPatterns": []any{literalRule("a", "b", "")}})
			params["requestModel"] = map[string]any{"location": "pathParam", "identifier": "/models/[^/]+"}
			return params
		}(), "capture group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("GetPolicy() error = nil, want one containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("GetPolicy() error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestGetPolicy_PathWithoutCaptureAllowedWhenNothingIsRewritten(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": map[string]any{"location": "pathParam", "identifier": "gpt-[a-z0-9]+"},
		"access":       allowOnly("gpt-4o"),
	})
	model, found, err := p.cfg.requestModel.extractFromRequestLine(policy.NewHeaders(nil), "/v1/gpt-4o/chat")
	if err != nil || !found || model != "gpt-4o" {
		t.Fatalf("extract = %q, %v, %v; want gpt-4o, true, nil", model, found, err)
	}
}

func TestGetPolicy_AcceptsValidCaptureReferences(t *testing.T) {
	for _, to := range []string{"m-$1", "${1}-x", "${name}", "$$literal", "prefix-$name"} {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
			"requestModel": payloadModel(),
			"access":       allowOnly("x"),
			"fallback": map[string]any{
				"mappingPatterns": []any{patternRule("x-(?P<name>.+)", to, "")},
			},
		})
		if err != nil {
			t.Errorf("to %q: GetPolicy() error = %v", to, err)
		}
	}
}

// The definition is the public contract: response restoration, the old aliases name
// and exact mappings must not come back.
func TestPolicyDefinition_HasNoResponseModelContract(t *testing.T) {
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	definition := string(raw)
	for _, forbidden := range []string{"restoreResponseModel", "responseModel", "aliases", " mappings:"} {
		if strings.Contains(definition, forbidden) {
			t.Errorf("policy-definition.yaml mentions %q", forbidden)
		}
	}
	for _, required := range []string{"version: v0.8.0", "mappingPatterns:", "requestModel:"} {
		if !strings.Contains(definition, required) {
			t.Errorf("policy-definition.yaml lacks %q", required)
		}
	}
}

func TestGetPolicy_FallbackIsPatternsOnly(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       allowOnly("gpt-4o"),
		"fallback":     map[string]any{"mappingPatterns": []any{patternRule("claude-(.+)", "anthropic-$1", "anthropic")}},
	})
	if got := p.cfg.mapping.resolve("claude-opus"); !got.matched || got.target.model != "anthropic-opus" || got.target.provider != "anthropic" {
		t.Errorf("patterns-only fallback resolved to %+v", got)
	}

	// A fallback with nothing in it redirects nothing: the same as no fallback, not an error.
	for name, fallback := range map[string]any{
		"empty object": map[string]any{},
		"empty list":   map[string]any{"mappingPatterns": []any{}},
		"null list":    map[string]any{"mappingPatterns": nil},
	} {
		t.Run(name, func(t *testing.T) {
			// A pathParam identifier without a capture group is fine, since nothing is rewritten.
			p := mustPolicy(t, map[string]any{
				"requestModel": map[string]any{"location": "pathParam", "identifier": "/models/[^/]+/chat"},
				"access":       allowOnly("gpt-4o"),
				"fallback":     fallback,
			})
			if p.cfg.mapping != nil {
				t.Errorf("mapping = %+v, want none", p.cfg.mapping)
			}
		})
	}
}

func TestPermits_DecisionTable(t *testing.T) {
	tests := []struct {
		mode  string
		model string
		want  bool
	}{
		{"allow", "gpt-4o", true},   // listed -> permit
		{"allow", "gpt-3.5", false}, // not listed -> deny
		{"deny", "gpt-4o", false},   // listed -> deny
		{"deny", "gpt-3.5", true},   // not listed -> permit
		{"deny", "", false},         // blank never permitted
		{"allow", "   ", false},     // blank never permitted, even in allow mode
	}
	for _, tt := range tests {
		p := mustPolicy(t, map[string]any{
			"requestModel": payloadModel(),
			"access":       map[string]any{"mode": tt.mode, "models": []any{"gpt-4o"}},
		})
		if got := p.cfg.access.permits(tt.model); got != tt.want {
			t.Errorf("mode %s, model %q: permits = %v, want %v", tt.mode, tt.model, got, tt.want)
		}
	}
}

func TestPermits_ListedModelsIgnoreCaseAndWhitespace(t *testing.T) {
	p := mustPolicy(t, map[string]any{"requestModel": payloadModel(), "access": allowOnly("GPT-4o")})
	for _, model := range []string{"gpt-4o", "GPT-4O", "  gpt-4o\t"} {
		if !p.cfg.access.permits(model) {
			t.Errorf("permits(%q) = false, want true", model)
		}
	}
	for _, model := range []string{"gpt-4o-mini", "xgpt-4o", "gpt-4"} {
		if p.cfg.access.permits(model) {
			t.Errorf("permits(%q) = true; listed models must not match substrings", model)
		}
	}
}

func TestPermits_PatternsMatchTheWholeName(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access": map[string]any{
			"mode":          "allow",
			"models":        []any{"placeholder"},
			"modelPatterns": []any{"gpt-4o|gpt-4o-mini", "claude-.*-v[0-9]+"},
		},
	})
	permitted := []string{"gpt-4o", "gpt-4o-mini", "claude-sonnet-v2", " claude-x-v10 ", "Claude-sonnet-v2"}
	denied := []string{"gpt-4o-preview", "my-gpt-4o", "claude-sonnet-v2-beta"}
	for _, model := range permitted {
		if !p.cfg.access.permits(model) {
			t.Errorf("permits(%q) = false, want true", model)
		}
	}
	for _, model := range denied {
		if p.cfg.access.permits(model) {
			t.Errorf("permits(%q) = true, want false (anchored)", model)
		}
	}
}

func TestPermits_PatternCaseFlag(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "deny", "models": []any{"x"}, "modelPatterns": []any{"(?i)preview-.*"}},
	})
	if p.cfg.access.permits("PREVIEW-model") {
		t.Error("a (?i) pattern should restrict PREVIEW-model in allow mode")
	}
}

// Model patterns ignore case like listed models, so a deny-list pattern cannot be
// bypassed by changing case on a provider whose model names ignore case.
func TestPermits_PatternsIgnoreCaseByDefault(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "deny", "models": []any{"x"}, "modelPatterns": []any{`gpt-4\.1.*`}},
	})
	for _, model := range []string{"gpt-4.1", "GPT-4.1", "Gpt-4.1-Mini"} {
		if p.cfg.access.permits(model) {
			t.Errorf("permits(%q) = true, want false", model)
		}
	}
	optOut := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "deny", "models": []any{"x"}, "modelPatterns": []any{`(?-i)gpt-4\.1.*`}},
	})
	if !optOut.cfg.access.permits("GPT-4.1") {
		t.Error("a (?-i) pattern should stay case-sensitive")
	}
}

func mappingPolicy(t *testing.T, patterns ...any) *Policy {
	t.Helper()
	return mustPolicy(t, map[string]any{"requestModel": payloadModel(), "access": allowOnly("gpt-4o"), "fallback": map[string]any{"mappingPatterns": patterns}})
}

func TestResolve_LiteralWithIgnoreCase(t *testing.T) {
	p := mappingPolicy(t, literalRule("Old-Model", "gpt-4o", "primary"))
	got := p.cfg.mapping.resolve("old-model")
	if !got.matched || got.target.model != "gpt-4o" || got.target.provider != "primary" {
		t.Fatalf("resolve = %+v", got)
	}
}

// An unescaped dot is a wildcard; an escaped one matches only itself.
func TestResolve_DotIsAWildcardUnlessEscaped(t *testing.T) {
	p := mappingPolicy(t, patternRule(`gpt-4\.1`, "escaped", ""))
	if got := p.cfg.mapping.resolve("gpt-401"); got.matched {
		t.Fatalf("an escaped dot matched another character: %+v", got)
	}
	p = mappingPolicy(t, patternRule("gpt-4.1", "unescaped", ""))
	if got := p.cfg.mapping.resolve("gpt-401"); !got.matched {
		t.Fatalf("an unescaped dot should match any character: %+v", got)
	}
}

func TestResolve_PatternsInOrderWithCaptures(t *testing.T) {
	p := mappingPolicy(t,
		patternRule("claude-(?P<tier>[a-z]+)-(\\d+)", "anthropic.${tier}-v$2", "bedrock"),
		patternRule("claude-.*", "claude-catch-all", ""),
	)
	got := p.cfg.mapping.resolve("claude-sonnet-4")
	if got.target.model != "anthropic.sonnet-v4" || got.target.provider != "bedrock" {
		t.Fatalf("resolve(claude-sonnet-4) = %+v", got)
	}
	got = p.cfg.mapping.resolve("claude-other")
	if got.target.model != "claude-catch-all" || got.target.provider != "" {
		t.Fatalf("resolve(claude-other) = %+v, want the second pattern", got)
	}
}

func TestResolve_PatternsAreAnchored(t *testing.T) {
	p := mappingPolicy(t, patternRule("old", "gpt-4o", ""))
	if got := p.cfg.mapping.resolve("old-and-more"); got.matched {
		t.Fatalf("resolve = %+v; an unanchored match must not happen", got)
	}
}

func TestResolve_NoMatch(t *testing.T) {
	p := mappingPolicy(t, literalRule("a", "b", ""))
	if got := p.cfg.mapping.resolve("c"); got.matched || got.unusable {
		t.Fatalf("resolve = %+v, want no match", got)
	}
	var none *mappingConfig
	if got := none.resolve("a"); got.matched {
		t.Fatal("a nil mapping must not match")
	}
}

func TestResolve_EmptyExpansionIsUnusable(t *testing.T) {
	p := mappingPolicy(t, patternRule("x-(.*)", "$1", ""))
	if got := p.cfg.mapping.resolve("x-"); !got.matched || !got.unusable {
		t.Fatalf("resolve(x-) = %+v, want an unusable match", got)
	}
	if got := p.cfg.mapping.resolve("x-model"); got.unusable || got.target.model != "model" {
		t.Fatalf("resolve(x-model) = %+v", got)
	}
}
