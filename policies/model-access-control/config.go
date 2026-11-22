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
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds on operator-supplied regular expressions. RE2 never backtracks, but every
// pattern runs on every request, so the count and the length are capped.
const (
	maxPatterns      = 50
	maxPatternLength = 512
)

type accessMode string

const (
	modeAllow accessMode = "allow"
	modeDeny  accessMode = "deny"
)

type missingModelAction string

const (
	missingModelDeny missingModelAction = "deny"
	missingModelSkip missingModelAction = "skip"
)

// config is the parsed, validated and compiled policy configuration. It is built once
// in GetPolicy and never written afterwards, so one instance can serve concurrent
// requests.
type config struct {
	requestModel modelLocation
	access       accessConfig
	mapping      *mappingConfig
}

type accessConfig struct {
	mode accessMode
	// models is keyed by normalizeKey of each configured name.
	models         map[string]struct{}
	patterns       []*regexp.Regexp
	onMissingModel missingModelAction
}

// target is a fallback destination. provider is empty when the mapping keeps the
// provider the request would have used.
type target struct {
	model    string
	provider string
}

type patternMapping struct {
	re       *regexp.Regexp
	to       string
	provider string
	// dynamic is true when to inserts capture groups, so the client's model decides
	// part of the target. Such a target is checked against the access rule.
	dynamic bool
}

type mappingConfig struct {
	patterns []patternMapping
}

// parseConfig validates the controller-merged params. Every error here fails the
// deployment instead of surfacing on the first request.
//
// The top level is not checked for unknown keys: the gateway controller merges every
// extraction field of the provider template (responseModel, promptTokens and so on)
// into the params of an LLM policy, and this policy ignores all but requestModel.
func parseConfig(params map[string]any) (*config, error) {
	if params == nil {
		return nil, fmt.Errorf("'params' is required")
	}

	access, err := parseAccess(params["access"])
	if err != nil {
		return nil, err
	}

	mapping, err := parseMapping(params["fallback"])
	if err != nil {
		return nil, err
	}

	requestModel, err := parseModelLocation(params["requestModel"], mapping != nil)
	if err != nil {
		return nil, err
	}

	return &config{requestModel: requestModel, access: access, mapping: mapping}, nil
}

func parseAccess(raw any) (accessConfig, error) {
	cfg := accessConfig{onMissingModel: missingModelDeny}
	if raw == nil {
		return cfg, fmt.Errorf("'access' is required")
	}
	entry, ok := raw.(map[string]any)
	if !ok {
		return cfg, fmt.Errorf("'access' must be an object")
	}
	if err := rejectUnknownKeys("access", entry,
		"mode", "models", "modelPatterns", "onMissingModel"); err != nil {
		return cfg, err
	}

	// The mode is compared exactly: accepting "DENY" here could disagree with another
	// tool that reads the same configuration.
	mode, ok := entry["mode"].(string)
	if !ok {
		return cfg, fmt.Errorf("'access.mode' is required and must be 'allow' or 'deny'")
	}
	switch accessMode(mode) {
	case modeAllow, modeDeny:
		cfg.mode = accessMode(mode)
	default:
		return cfg, fmt.Errorf("'access.mode' must be 'allow' or 'deny', got %q", mode)
	}

	models, err := parseModels(entry["models"])
	if err != nil {
		return cfg, err
	}
	cfg.models = models

	if cfg.patterns, err = parseModelPatterns(entry["modelPatterns"]); err != nil {
		return cfg, err
	}

	if rawMissing, ok := entry["onMissingModel"]; ok && rawMissing != nil {
		action, ok := rawMissing.(string)
		if !ok {
			return cfg, fmt.Errorf("'access.onMissingModel' must be 'deny' or 'skip'")
		}
		switch missingModelAction(action) {
		case missingModelDeny, missingModelSkip:
			cfg.onMissingModel = missingModelAction(action)
		default:
			return cfg, fmt.Errorf("'access.onMissingModel' must be 'deny' or 'skip', got %q", action)
		}
	}

	return cfg, nil
}

func parseModels(raw any) (map[string]struct{}, error) {
	if raw == nil {
		return nil, fmt.Errorf("'access.models' is required")
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'access.models' must be an array")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("'access.models' must contain at least one model")
	}
	models := make(map[string]struct{}, len(list))
	for i, item := range list {
		field := fmt.Sprintf("access.models[%d]", i)
		value, err := nonBlankString(item, field)
		if err != nil {
			return nil, err
		}
		key := normalizeKey(value)
		if _, exists := models[key]; exists {
			return nil, fmt.Errorf("'%s' repeats an earlier model (names are compared ignoring case)", field)
		}
		models[key] = struct{}{}
	}
	return models, nil
}

func parseModelPatterns(raw any) ([]*regexp.Regexp, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'access.modelPatterns' must be an array")
	}
	if len(list) > maxPatterns {
		return nil, fmt.Errorf("'access.modelPatterns' must contain at most %d entries, got %d", maxPatterns, len(list))
	}
	patterns := make([]*regexp.Regexp, 0, len(list))
	for i, item := range list {
		field := fmt.Sprintf("access.modelPatterns[%d]", i)
		value, err := nonBlankString(item, field)
		if err != nil {
			return nil, err
		}
		// Listed models ignore case, and so do model patterns: a deny-list pattern that
		// matched only one spelling could be bypassed on a provider whose model names
		// ignore case. A pattern can still opt out with (?-i).
		re, err := compileFullMatch("(?i)"+value, field)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, re)
	}
	return patterns, nil
}

func parseMapping(raw any) (*mappingConfig, error) {
	if raw == nil {
		return nil, nil
	}
	entry, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'fallback' must be an object")
	}
	if err := rejectUnknownKeys("fallback", entry, "mappingPatterns"); err != nil {
		return nil, err
	}

	patterns, err := parseMappingPatterns(entry["mappingPatterns"])
	if err != nil {
		return nil, err
	}
	// A fallback without patterns (for example an empty section a form sends back)
	// redirects nothing, so it is the same as no fallback.
	if len(patterns) == 0 {
		return nil, nil
	}
	return &mappingConfig{patterns: patterns}, nil
}

func parseMappingPatterns(raw any) ([]patternMapping, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'fallback.mappingPatterns' must be an array")
	}
	if len(list) > maxPatterns {
		return nil, fmt.Errorf("'fallback.mappingPatterns' must contain at most %d entries, got %d", maxPatterns, len(list))
	}
	patterns := make([]patternMapping, 0, len(list))
	for i, item := range list {
		field := fmt.Sprintf("fallback.mappingPatterns[%d]", i)
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'%s' must be an object", field)
		}
		if err := rejectUnknownKeys(field, entry, "fromPattern", "to", "provider"); err != nil {
			return nil, err
		}
		fromPattern, err := nonBlankString(entry["fromPattern"], field+".fromPattern")
		if err != nil {
			return nil, err
		}
		re, err := compileFullMatch(fromPattern, field+".fromPattern")
		if err != nil {
			return nil, err
		}
		to, err := modelName(entry["to"], field+".to")
		if err != nil {
			return nil, err
		}
		dynamic, err := validateExpansion(re, to, field+".to")
		if err != nil {
			return nil, err
		}
		provider, err := optionalProvider(entry["provider"], field+".provider")
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, patternMapping{re: re, to: to, provider: provider, dynamic: dynamic})
	}
	return patterns, nil
}

// compileFullMatch compiles an operator expression so that it must match the whole
// model name. Without the anchors "gpt-4o" would also match "gpt-4o-preview" and
// silently widen an allow list; the non-capturing group keeps an alternation inside
// the expression from escaping them.
func compileFullMatch(pattern, field string) (*regexp.Regexp, error) {
	if len(pattern) > maxPatternLength {
		return nil, fmt.Errorf("'%s' must be at most %d characters, got %d", field, maxPatternLength, len(pattern))
	}
	re, err := regexp.Compile(`^(?:` + pattern + `)$`)
	if err != nil {
		return nil, fmt.Errorf("'%s' is not a valid RE2 expression: %w", field, err)
	}
	return re, nil
}

// validateExpansion rejects a replacement that could expand to an unusable model:
// a reference to a capture group the expression does not define (Go expands it to
// an empty string), an empty or unterminated ${}, or a replacement made only of
// capture references that can all be empty. dynamic reports whether the replacement
// inserts any capture group.
func validateExpansion(re *regexp.Regexp, replacement, field string) (dynamic bool, err error) {
	numGroups := re.NumSubexp()
	names := map[string]struct{}{}
	for _, name := range re.SubexpNames() {
		if name != "" {
			names[name] = struct{}{}
		}
	}

	literal := false
	for i := 0; i < len(replacement); i++ {
		if replacement[i] != '$' {
			if !unicode.IsSpace(rune(replacement[i])) {
				literal = true
			}
			continue
		}
		if i+1 < len(replacement) && replacement[i+1] == '$' {
			literal = true
			i++
			continue
		}
		ref, next, braced, closed := readCaptureRef(replacement, i+1)
		if braced && !closed {
			return false, fmt.Errorf("'%s' has an unterminated '${'", field)
		}
		if ref == "" {
			if braced {
				return false, fmt.Errorf("'%s' has an empty capture reference '${}'", field)
			}
			// A lone '$' is kept literally by regexp.Expand.
			literal = true
			continue
		}
		i = next - 1
		dynamic = true
		if isAllDigits(ref) {
			index := 0
			for _, c := range ref {
				index = index*10 + int(c-'0')
				if index > numGroups {
					break
				}
			}
			if index > numGroups {
				return false, fmt.Errorf("'%s' references capture group $%s, but the expression has %d group(s)", field, ref, numGroups)
			}
			continue
		}
		if _, ok := names[ref]; !ok {
			return false, fmt.Errorf("'%s' references capture group '%s', which the expression does not define", field, ref)
		}
	}

	// A replacement of references only is accepted when the expression cannot match
	// an empty name for them; anything else is caught at run time as a routing error.
	if !literal && re.MatchString("") {
		return false, fmt.Errorf("'%s' can expand to an empty model name", field)
	}
	return dynamic, nil
}

// readCaptureRef reads the group name after a '$' at start, following the naming
// rules of regexp.Expand: ${name}, or the longest run of letters, digits and
// underscores.
func readCaptureRef(s string, start int) (ref string, next int, braced, closed bool) {
	if start >= len(s) {
		return "", start, false, false
	}
	if s[start] == '{' {
		end := strings.IndexByte(s[start:], '}')
		if end < 0 {
			return "", len(s), true, false
		}
		return s[start+1 : start+end], start + end + 1, true, true
	}
	i := start
	for i < len(s) && (s[i] == '_' || ('0' <= s[i] && s[i] <= '9') || ('a' <= s[i] && s[i] <= 'z') || ('A' <= s[i] && s[i] <= 'Z')) {
		i++
	}
	return s[start:i], i, false, false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// normalizeKey is the comparison key of listed model names.
func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// rejectUnknownKeys fails the deployment on a misspelled field. The schema says
// additionalProperties: false, but params can reach GetPolicy without schema checks.
func rejectUnknownKeys(path string, entry map[string]any, allowed ...string) error {
	for key := range entry {
		known := false
		for _, name := range allowed {
			if key == name {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("'%s' has unknown field %q", path, key)
		}
	}
	return nil
}

func nonBlankString(raw any, field string) (string, error) {
	if raw == nil {
		return "", fmt.Errorf("'%s' is required", field)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", field)
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("'%s' must not be empty", field)
	}
	return trimmed, nil
}

// modelName reads a model name the policy may write into a request. It must not
// contain control characters, which no header, path or JSON consumer should receive.
func modelName(raw any, field string) (string, error) {
	value, err := nonBlankString(raw, field)
	if err != nil {
		return "", err
	}
	if hasControl(value) || !utf8.ValidString(value) {
		return "", fmt.Errorf("'%s' must be valid UTF-8 without control characters", field)
	}
	if len(value) > maxModelLength {
		return "", fmt.Errorf("'%s' must be at most %d bytes, got %d", field, maxModelLength, len(value))
	}
	return value, nil
}

func optionalProvider(raw any, field string) (string, error) {
	if raw == nil {
		return "", nil
	}
	value, err := nonBlankString(raw, field)
	if err != nil {
		return "", err
	}
	if hasControl(value) || !utf8.ValidString(value) || strings.ContainsAny(value, "'\"\\") {
		return "", fmt.Errorf("'%s' must be a provider name without quotes, backslashes or control characters", field)
	}
	return value, nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// permits applies the access rule to the client-requested model. The mode is the
// action for the listed models; every other model gets the opposite:
//
//	allow + listed     -> permit (the models are an allow list)
//	allow + not listed -> deny
//	deny  + listed     -> deny   (the models are a deny list)
//	deny  + not listed -> permit
//
// A blank model is never permitted, whatever the mode.
func (a accessConfig) permits(model string) bool {
	trimmed := strings.TrimSpace(model)
	if trimmed == "" {
		return false
	}
	listed := a.lists(trimmed)
	if a.mode == modeAllow {
		return listed
	}
	return !listed
}

// lists reports whether the trimmed model is one of the models (ignoring case) or
// matches one of the model patterns as a whole.
func (a accessConfig) lists(trimmed string) bool {
	if _, ok := a.models[normalizeKey(trimmed)]; ok {
		return true
	}
	for _, re := range a.patterns {
		if re.MatchString(trimmed) {
			return true
		}
	}
	return false
}

// mappingResult is the fallback found for a denied model.
type mappingResult struct {
	target  target
	matched bool
	// dynamic is true when the target inserts capture groups of the requested model.
	dynamic bool
	// unusable is a pattern match whose expansion is blank or holds control
	// characters. It is a configuration fault, never forwarded upstream.
	unusable bool
}

// resolve finds the fallback of a denied, trimmed model: the patterns in declared
// order, first match wins. Patterns
// are case-sensitive unless the expression sets (?i).
func (m *mappingConfig) resolve(trimmed string) mappingResult {
	if m == nil {
		return mappingResult{}
	}
	for _, pm := range m.patterns {
		idx := pm.re.FindStringSubmatchIndex(trimmed)
		if idx == nil {
			continue
		}
		expanded := strings.TrimSpace(string(pm.re.ExpandString(nil, pm.to, trimmed, idx)))
		if expanded == "" || hasControl(expanded) {
			return mappingResult{matched: true, unusable: true}
		}
		return mappingResult{target: target{model: expanded, provider: pm.provider}, matched: true, dynamic: pm.dynamic}
	}
	return mappingResult{}
}
