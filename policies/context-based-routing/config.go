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

package contextbasedrouting

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

const defaultCharsPerToken int64 = 4

type target struct {
	Model    string
	Provider string
}

type tokenRange struct {
	Name      string
	MinTokens *int64
	MaxTokens *int64
	Target    target
}

type requestModelConfig struct {
	Location       string
	Identifier     string
	PathExpression *regexp.Regexp
	PathModelGroup int
}

type config struct {
	Routes         []tokenRange
	Fallback       *target
	CharsPerToken  int64
	InputJSONPaths []string
	RequestModel   requestModelConfig
}

func parseConfig(params map[string]interface{}) (config, error) {
	result := config{
		CharsPerToken:  defaultCharsPerToken,
		InputJSONPaths: append([]string(nil), defaultInputJSONPaths...),
	}

	routesRaw, ok := params["modelMappings"].([]interface{})
	if !ok || len(routesRaw) == 0 {
		return result, fmt.Errorf("'modelMappings' must be a non-empty array")
	}
	result.Routes = make([]tokenRange, 0, len(routesRaw))
	for i, raw := range routesRaw {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return result, fmt.Errorf("'modelMappings[%d]' must be an object", i)
		}
		route, err := parseRange(item, i)
		if err != nil {
			return result, err
		}
		result.Routes = append(result.Routes, route)
	}
	if err := validateNonOverlappingRanges(result.Routes); err != nil {
		return result, err
	}

	if raw, exists := params["fallback"]; exists {
		parsed, err := parseTarget(raw, "fallback")
		if err != nil {
			return result, err
		}
		result.Fallback = &parsed
	}

	if raw, exists := params["charsPerToken"]; exists {
		value, err := integerValue(raw)
		if err != nil || value < 1 {
			return result, fmt.Errorf("'charsPerToken' must be an integer greater than zero")
		}
		result.CharsPerToken = value
	}
	if raw, exists := params["inputJSONPaths"]; exists {
		values, ok := raw.([]interface{})
		if !ok || len(values) == 0 {
			return result, fmt.Errorf("'inputJSONPaths' must be a non-empty array of strings")
		}
		seen := make(map[string]struct{}, len(values))
		result.InputJSONPaths = make([]string, 0, len(values))
		for i, value := range values {
			jsonPath, ok := value.(string)
			jsonPath = strings.TrimSpace(jsonPath)
			if !ok || jsonPath == "" {
				return result, fmt.Errorf("'inputJSONPaths[%d]' must be a non-empty string", i)
			}
			if jsonPath != "$" && !strings.HasPrefix(jsonPath, "$.") {
				return result, fmt.Errorf("'inputJSONPaths[%d]' must start with '$.'", i)
			}
			if _, duplicate := seen[jsonPath]; duplicate {
				return result, fmt.Errorf("'inputJSONPaths[%d]' duplicates '%s'", i, jsonPath)
			}
			seen[jsonPath] = struct{}{}
			result.InputJSONPaths = append(result.InputJSONPaths, jsonPath)
		}
	}
	requestModelRaw, ok := params["requestModel"].(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("'requestModel' system parameter is required")
	}
	location, ok := requestModelRaw["location"].(string)
	if !ok {
		return result, fmt.Errorf("'requestModel.location' must be a string")
	}
	// "body" was emitted by early custom provider templates. Keep accepting it
	// as a backwards-compatible alias for the canonical "payload" location.
	if location == "body" {
		location = "payload"
	}
	switch location {
	case "payload", "header", "queryParam", "pathParam":
	default:
		return result, fmt.Errorf("'requestModel.location' must be one of payload, header, queryParam, or pathParam")
	}
	identifier, ok := requestModelRaw["identifier"].(string)
	if !ok || strings.TrimSpace(identifier) == "" {
		return result, fmt.Errorf("'requestModel.identifier' must be a non-empty string")
	}
	result.RequestModel = requestModelConfig{Location: location, Identifier: strings.TrimSpace(identifier)}
	if location == "pathParam" {
		expression, group, err := compilePathModelExpression(result.RequestModel.Identifier)
		if err != nil {
			return result, fmt.Errorf("'requestModel.identifier' is not a valid model path expression: %w", err)
		}
		result.RequestModel.PathExpression = expression
		result.RequestModel.PathModelGroup = group
	}

	return result, nil
}

// compilePathModelExpression compiles a provider-template model expression once
// when the policy is attached. Expressions with a capture group replace the
// first captured value (for example Bedrock's model/(...)/). Expressions with
// no capture group replace the complete match. A simple leading positive
// lookbehind is normalized because Go's RE2 engine intentionally does not
// support lookbehind; Gemini's built-in template uses this form.
func compilePathModelExpression(expression string) (*regexp.Regexp, int, error) {
	const lookbehindPrefix = "(?<="
	normalized := expression
	modelGroupName := ""
	if strings.HasPrefix(expression, lookbehindPrefix) {
		closing := strings.Index(expression[len(lookbehindPrefix):], ")")
		if closing < 0 {
			return nil, 0, fmt.Errorf("unterminated positive lookbehind")
		}
		closing += len(lookbehindPrefix)
		prefix := expression[len(lookbehindPrefix):closing]
		suffix := expression[closing+1:]
		if prefix == "" || suffix == "" {
			return nil, 0, fmt.Errorf("positive lookbehind must contain a prefix and a model expression")
		}
		modelGroupName = "context_routing_model"
		normalized = "(?:" + prefix + ")(?P<" + modelGroupName + ">" + suffix + ")"
	}

	compiled, err := regexp.Compile(normalized)
	if err != nil {
		return nil, 0, err
	}
	if modelGroupName != "" {
		return compiled, compiled.SubexpIndex(modelGroupName), nil
	}
	if compiled.NumSubexp() > 0 {
		return compiled, 1, nil
	}
	return compiled, 0, nil
}

func parseRange(item map[string]interface{}, index int) (tokenRange, error) {
	result := tokenRange{}
	if raw, ok := item["name"]; ok {
		name, ok := raw.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return result, fmt.Errorf("'modelMappings[%d].name' must be a non-empty string", index)
		}
		result.Name = strings.TrimSpace(name)
	}

	if raw, ok := item["minTokens"]; ok {
		value, err := integerValue(raw)
		if err != nil || value < 0 {
			return result, fmt.Errorf("'modelMappings[%d].minTokens' must be a non-negative integer", index)
		}
		result.MinTokens = &value
	}
	if raw, ok := item["maxTokens"]; ok {
		value, err := integerValue(raw)
		if err != nil || value < 1 {
			return result, fmt.Errorf("'modelMappings[%d].maxTokens' must be a positive integer", index)
		}
		result.MaxTokens = &value
	}
	if result.MaxTokens == nil {
		return result, fmt.Errorf("'modelMappings[%d].maxTokens' is required", index)
	}
	if result.MinTokens != nil && result.MaxTokens != nil && *result.MinTokens >= *result.MaxTokens {
		return result, fmt.Errorf("'modelMappings[%d].minTokens' must be less than maxTokens", index)
	}

	parsedTarget, err := parseTarget(item["model"], fmt.Sprintf("modelMappings[%d].model", index))
	if err != nil {
		return result, err
	}
	result.Target = parsedTarget
	return result, nil
}

func parseTarget(raw interface{}, field string) (target, error) {
	item, ok := raw.(map[string]interface{})
	if !ok {
		return target{}, fmt.Errorf("'%s' must be an object", field)
	}
	model, ok := item["modelName"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return target{}, fmt.Errorf("'%s.modelName' must be a non-empty string", field)
	}
	result := target{Model: strings.TrimSpace(model)}
	if rawProvider, exists := item["providerName"]; exists {
		provider, ok := rawProvider.(string)
		if !ok || strings.TrimSpace(provider) == "" {
			return target{}, fmt.Errorf("'%s.providerName' must be a non-empty string", field)
		}
		result.Provider = strings.TrimSpace(provider)
	}
	return result, nil
}

func integerValue(raw interface{}) (int64, error) {
	switch value := raw.(type) {
	case int:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return value, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) || value > math.MaxInt64 || value < math.MinInt64 {
			return 0, fmt.Errorf("not an integer")
		}
		return int64(value), nil
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func validateNonOverlappingRanges(routes []tokenRange) error {
	for i := range routes {
		for j := i + 1; j < len(routes); j++ {
			if rangesOverlap(routes[i], routes[j]) {
				return fmt.Errorf("'modelMappings[%d]' overlaps 'modelMappings[%d]'", i, j)
			}
		}
	}
	return nil
}

func rangesOverlap(left, right tokenRange) bool {
	leftMin, leftMax := int64(math.MinInt64), int64(math.MaxInt64)
	rightMin, rightMax := int64(math.MinInt64), int64(math.MaxInt64)
	if left.MinTokens != nil {
		leftMin = *left.MinTokens
	}
	if left.MaxTokens != nil {
		leftMax = *left.MaxTokens
	}
	if right.MinTokens != nil {
		rightMin = *right.MinTokens
	}
	if right.MaxTokens != nil {
		rightMax = *right.MaxTokens
	}
	return leftMin < rightMax && rightMin < leftMax
}
