/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package requestrewrite

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	matchTypeExact   = "EXACT"
	matchTypeRegex   = "REGEX"
	matchTypePresent = "PRESENT"

	pathReplacePrefix = "REPLACEPREFIXMATCH"
	pathReplaceFull   = "REPLACEFULLPATH"
	pathReplaceRegex  = "REPLACEREGEXMATCH"

	queryActionReplace      = "REPLACE"
	queryActionRemove       = "REMOVE"
	queryActionAdd          = "ADD"
	queryActionAppend       = "APPEND"
	queryActionReplaceRegex = "REPLACEREGEXMATCH"
)

var ins = &RequestRewritePolicy{}

// RequestRewritePolicy implements request rewriting (path, query, method)
type RequestRewritePolicy struct{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}


func (p *RequestRewritePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

type policyConfig struct {
	Match         *matchConfig  `json:"match"`
	PathRewrite   *pathRewrite  `json:"pathRewrite"`
	QueryRewrite  *queryRewrite `json:"queryRewrite"`
	MethodRewrite string        `json:"methodRewrite"`
}

type matchConfig struct {
	Headers     []headerMatcher   `json:"headers"`
	QueryParams []queryParamMatch `json:"queryParams"`
}

type headerMatcher struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type queryParamMatch struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type pathRewrite struct {
	Type               string            `json:"type"`
	ReplacePrefixMatch string            `json:"replacePrefixMatch"`
	ReplaceFullPath    string            `json:"replaceFullPath"`
	ReplaceRegexMatch  *regexReplacement `json:"replaceRegexMatch"`
}

type regexReplacement struct {
	Pattern      string `json:"pattern"`
	Substitution string `json:"substitution"`
}

type queryRewrite struct {
	Rules []queryRule `json:"rules"`
}

type queryRule struct {
	Action       string `json:"action"`
	Name         string `json:"name"`
	Value        string `json:"value"`
	Separator    string `json:"separator"`
	Pattern      string `json:"pattern"`
	Substitution string `json:"substitution"`
}

func parseConfig(params map[string]interface{}) (*policyConfig, error) {
	if params == nil || len(params) == 0 {
		return nil, nil
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize params: %w", err)
	}
	var cfg policyConfig
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}
	return &cfg, nil
}

func matchQueryParam(values url.Values, matcher queryParamMatch) bool {
	name := strings.TrimSpace(matcher.Name)
	if name == "" {
		return false
	}
	matchType := strings.ToUpper(strings.TrimSpace(matcher.Type))
	vals, exists := values[name]

	switch matchType {
	case matchTypePresent:
		return exists && len(vals) > 0
	case matchTypeExact:
		for _, v := range vals {
			if v == matcher.Value {
				return true
			}
		}
		return false
	case matchTypeRegex:
		regex, err := regexp.Compile(matcher.Value)
		if err != nil {
			slog.Warn("[Request Rewrite]: Invalid query regex", "name", name, "pattern", matcher.Value, "error", err)
			return false
		}
		for _, v := range vals {
			if regex.MatchString(v) {
				return true
			}
		}
		return false
	default:
		slog.Warn("[Request Rewrite]: Unsupported query match type", "type", matcher.Type)
		return false
	}
}

func applyPathRewrite(operationPath string, currentPath string, cfg *pathRewrite) string {
	rewriteType := strings.ToUpper(strings.TrimSpace(cfg.Type))

	switch rewriteType {
	case pathReplacePrefix:
		operationPath := strings.TrimSpace(operationPath)
		if operationPath == "" {
			slog.Warn("[Request Rewrite]: Operation path is empty, skipping prefix rewrite")
			return currentPath
		}
		if strings.HasSuffix(operationPath, "/*") {
			operationPath = strings.TrimSuffix(operationPath, "/*")
		}
		if !strings.HasPrefix(currentPath, operationPath) {
			return currentPath
		}
		remainder := strings.TrimPrefix(currentPath, operationPath)
		return cfg.ReplacePrefixMatch + remainder
	case pathReplaceFull:
		if cfg.ReplaceFullPath == "" {
			return currentPath
		}
		return cfg.ReplaceFullPath
	case pathReplaceRegex:
		if cfg.ReplaceRegexMatch == nil {
			return currentPath
		}
		regex, err := regexp.Compile(cfg.ReplaceRegexMatch.Pattern)
		if err != nil {
			slog.Warn("[Request Rewrite]: Invalid path regex", "pattern", cfg.ReplaceRegexMatch.Pattern, "error", err)
			return currentPath
		}
		substitution := normalizeRegexSubstitution(cfg.ReplaceRegexMatch.Substitution)
		return regex.ReplaceAllString(currentPath, substitution)
	default:
		slog.Warn("[Request Rewrite]: Unsupported path rewrite type", "type", cfg.Type)
		return currentPath
	}
}

func splitBasePath(apiContext string, pathOnly string) (string, string) {
	base := strings.TrimSpace(apiContext)
	if base == "" || base == "/" {
		return "", pathOnly
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	base = strings.TrimSuffix(base, "/")
	if !strings.HasPrefix(pathOnly, base) {
		return "", pathOnly
	}
	relative := strings.TrimPrefix(pathOnly, base)
	if relative == "" {
		relative = "/"
	}
	return base, relative
}

func joinBaseAndRelative(base, relative string) string {
	if base == "" {
		return relative
	}
	if relative == "" || relative == "/" {
		return base
	}
	if !strings.HasPrefix(relative, "/") {
		relative = "/" + relative
	}
	return base + relative
}

func applyQueryRewrite(values url.Values, cfg *queryRewrite) error {
	for _, rule := range cfg.Rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			return fmt.Errorf("query rule name cannot be empty")
		}

		action := strings.ToUpper(strings.TrimSpace(rule.Action))
		switch action {
		case queryActionReplace:
			values.Set(name, rule.Value)
		case queryActionRemove:
			values.Del(name)
		case queryActionAdd:
			values.Add(name, rule.Value)
		case queryActionAppend:
			separator := rule.Separator
			vals, exists := values[name]
			if !exists || len(vals) == 0 {
				values.Set(name, rule.Value)
				break
			}
			updated := make([]string, 0, len(vals))
			for _, v := range vals {
				updated = append(updated, v+separator+rule.Value)
			}
			values[name] = updated
		case queryActionReplaceRegex:
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("invalid query regex pattern: %w", err)
			}
			vals, exists := values[name]
			if !exists || len(vals) == 0 {
				break
			}
			substitution := normalizeRegexSubstitution(rule.Substitution)
			updated := make([]string, 0, len(vals))
			for _, v := range vals {
				updated = append(updated, regex.ReplaceAllString(v, substitution))
			}
			values[name] = updated
		default:
			return fmt.Errorf("unsupported query rewrite action: %s", rule.Action)
		}
	}
	return nil
}

func splitPathAndQuery(rawPath string) (string, url.Values, error) {
	parsed, err := url.ParseRequestURI(rawPath)
	if err != nil {
		// Best-effort fallback: treat as path only
		return rawPath, url.Values{}, err
	}
	return parsed.Path, parsed.Query(), nil
}

func buildPath(path string, values url.Values) string {
	encoded := values.Encode()
	if encoded == "" {
		return path
	}
	return path + "?" + encoded
}

func normalizeRegexSubstitution(value string) string {
	if value == "" {
		return value
	}
	// Convert RE2-style \1 to Go's $1 replacement syntax.
	re := regexp.MustCompile(`\\([0-9]+)`)
	return re.ReplaceAllString(value, `$$$1`)
}

func isAllowedMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// OnRequestHeaders applies request transformations in the header phase for v2alpha engine compatibility.
func (p *RequestRewritePolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	newPath, newMethod, err := p.computeRewrite(reqCtx, params)
	if err != nil {
		slog.Error("[Request Rewrite]: Configuration error", "error", err)
		body, _ := json.Marshal(map[string]string{
			"error":   "Configuration Error",
			"message": err.Error(),
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       body,
		}
	}
	return policy.UpstreamRequestHeaderModifications{
		Path:   newPath,
		Method: newMethod,
	}
}

// computeRewrite parses config and computes path/method rewrites from the provided request fields.
// Called from both OnRequestHeaders and OnRequestBody to share logic without duplication.
func (p *RequestRewritePolicy) computeRewrite(reqCtx *policy.RequestHeaderContext, params map[string]interface{}) (newPath *string, newMethod *string, err error) {
	cfg, parseErr := parseConfig(params)
	if parseErr != nil {
		return nil, nil, parseErr
	}

	if cfg == nil {
		slog.Debug("[Request Rewrite]: No configuration provided, passing through")
		return nil, nil, nil
	}

	if !matchesRequest(reqCtx, cfg.Match) {
		slog.Debug("[Request Rewrite]: Match conditions not met, skipping transformations")
		return nil, nil, nil
	}

	originalPath := reqCtx.Path
	pathOnly, queryValues, _ := splitPathAndQuery(originalPath)
	basePrefix, relativePath := splitBasePath(reqCtx.APIContext, pathOnly)
	updatedRelativePath := relativePath
	pathRewriteApplied := false
	queryRewriteConfigured := cfg.QueryRewrite != nil

	if cfg.PathRewrite != nil {
		updatedRelativePath = applyPathRewrite(reqCtx.OperationPath, updatedRelativePath, cfg.PathRewrite)
		pathRewriteApplied = updatedRelativePath != relativePath
	}

	if cfg.QueryRewrite != nil {
		if qErr := applyQueryRewrite(queryValues, cfg.QueryRewrite); qErr != nil {
			return nil, nil, fmt.Errorf("invalid queryRewrite configuration: %w", qErr)
		}
	}

	finalPath := originalPath
	if pathRewriteApplied || queryRewriteConfigured {
		updatedPath := joinBaseAndRelative(basePrefix, updatedRelativePath)
		finalPath = buildPath(updatedPath, queryValues)
	}

	if finalPath != originalPath {
		slog.Info("[Request Rewrite]: Scheduling path rewrite", "from", originalPath, "to", finalPath)
		newPath = &finalPath
	}

	method := strings.TrimSpace(cfg.MethodRewrite)
	if method != "" {
		method = strings.ToUpper(method)
		if !isAllowedMethod(method) {
			return nil, nil, fmt.Errorf("invalid methodRewrite value: unsupported method: %s", method)
		}
		slog.Info("[Request Rewrite]: Scheduling method rewrite", "method", method)
		newMethod = &method
	}

	return newPath, newMethod, nil
}

func matchesRequest(reqCtx *policy.RequestHeaderContext, match *matchConfig) bool {
	if match == nil {
		return true
	}

	if len(match.Headers) == 0 && len(match.QueryParams) == 0 {
		return true
	}

	for _, matcher := range match.Headers {
		if !matchHeader(reqCtx, matcher) {
			return false
		}
	}

	if len(match.QueryParams) > 0 {
		_, queryValues, _ := splitPathAndQuery(reqCtx.Path)
		for _, matcher := range match.QueryParams {
			if !matchQueryParam(queryValues, matcher) {
				return false
			}
		}
	}

	return true
}

func matchHeader(reqCtx *policy.RequestHeaderContext, matcher headerMatcher) bool {
	name := strings.TrimSpace(matcher.Name)
	if name == "" {
		return false
	}

	matchType := strings.ToUpper(strings.TrimSpace(matcher.Type))
	// Evaluate the match condition against the downstream snapshot so
	// the rewrite decision is based on what the client actually sent.
	values := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(name)

	switch matchType {
	case matchTypePresent:
		return len(values) > 0
	case matchTypeExact:
		for _, v := range values {
			if v == matcher.Value {
				return true
			}
		}
		return false
	case matchTypeRegex:
		regex, err := regexp.Compile(matcher.Value)
		if err != nil {
			slog.Warn("[Request Rewrite]: Invalid header regex", "name", name, "pattern", matcher.Value, "error", err)
			return false
		}
		for _, v := range values {
			if regex.MatchString(v) {
				return true
			}
		}
		return false
	default:
		slog.Warn("[Request Rewrite]: Unsupported header match type", "type", matcher.Type)
		return false
	}
}
