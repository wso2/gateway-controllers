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

package awsbedrockguardrail

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// selectsStructuredValue reports whether jsonPath selects an object, an array or a wildcard
// match rather than a single string or number. Such a value is inspected as one joined text,
// so guardrail modifications have to be written back into each of its values separately.
func selectsStructuredValue(payload []byte, jsonPath string) bool {
	if jsonPath == "" {
		return false
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return false
	}
	value, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return false
	}
	switch value.(type) {
	case map[string]interface{}, []interface{}:
		return true
	}
	return false
}

// rewriteStructuredPayload applies transform to every string and number under jsonPath and
// returns the re-encoded payload. Values outside jsonPath are untouched.
func rewriteStructuredPayload(payload []byte, jsonPath string, transform func(string) string) ([]byte, error) {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return nil, fmt.Errorf("parsing payload for write-back: %w", err)
	}
	if _, _, err := rewriteValuesAtPath(jsonData, jsonPathKeys(jsonPath), transform); err != nil {
		return nil, fmt.Errorf("writing guardrail modifications to JSONPath: %w", err)
	}
	updated, err := json.Marshal(jsonData)
	if err != nil {
		return nil, fmt.Errorf("encoding modified payload: %w", err)
	}
	return updated, nil
}

// applyReplacements replaces every key of replacements found in content with its value,
// longest first so a match contained in a longer one is not replaced partially.
func applyReplacements(content string, replacements map[string]string) string {
	originals := make([]string, 0, len(replacements))
	for original := range replacements {
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool { return len(originals[i]) > len(originals[j]) })
	for _, original := range originals {
		content = strings.ReplaceAll(content, original, replacements[original])
	}
	return content
}

var jsonPathIndexPattern = regexp.MustCompile(`^([a-zA-Z0-9_]+)\[(-?\d+)\]$`)

// jsonPathKeys splits a JSONPath into the segments rewriteValuesAtPath walks, using the same
// grammar as the SDK's ExtractValueFromJsonpath: dotted keys, key[N] (negative N counts from
// the end) and "*" over an object or array.
func jsonPathKeys(jsonPath string) []string {
	keys := strings.Split(jsonPath, ".")
	if len(keys) > 0 && keys[0] == "$" {
		keys = keys[1:]
	}
	return keys
}

// rewriteValuesAtPath applies transform to every string and number under the node that keys
// select, writing results back in place. It returns the (possibly replaced) node and whether
// anything changed. A "*" segment skips children the rest of the path does not match, as the
// SDK's extractor does.
func rewriteValuesAtPath(node interface{}, keys []string, transform func(string) string) (interface{}, bool, error) {
	if len(keys) == 0 {
		out, changed := rewriteAllValues(node, transform)
		return out, changed, nil
	}
	key, rest := keys[0], keys[1:]

	if key == "*" {
		changed := false
		switch v := node.(type) {
		case map[string]interface{}:
			for _, k := range sortedKeys(v) {
				if out, c, err := rewriteValuesAtPath(v[k], rest, transform); err == nil {
					v[k] = out
					changed = changed || c
				}
			}
		case []interface{}:
			for i := range v {
				if out, c, err := rewriteValuesAtPath(v[i], rest, transform); err == nil {
					v[i] = out
					changed = changed || c
				}
			}
		default:
			return nil, false, fmt.Errorf("wildcard used on non-iterable node")
		}
		return node, changed, nil
	}

	obj, ok := node.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("invalid structure for key: %s", key)
	}

	if m := jsonPathIndexPattern.FindStringSubmatch(key); len(m) == 3 {
		arr, ok := obj[m[1]].([]interface{})
		if !ok {
			return nil, false, fmt.Errorf("not an array: %s", m[1])
		}
		idx, err := strconv.Atoi(m[2])
		if err != nil {
			return nil, false, fmt.Errorf("invalid array index: %s", m[2])
		}
		if idx < 0 {
			idx = len(arr) + idx
		}
		if idx < 0 || idx >= len(arr) {
			return nil, false, fmt.Errorf("array index out of range: %s", m[2])
		}
		out, changed, err := rewriteValuesAtPath(arr[idx], rest, transform)
		if err != nil {
			return nil, false, err
		}
		arr[idx] = out
		return node, changed, nil
	}

	child, exists := obj[key]
	if !exists {
		return nil, false, fmt.Errorf("key not found: %s", key)
	}
	out, changed, err := rewriteValuesAtPath(child, rest, transform)
	if err != nil {
		return nil, false, err
	}
	obj[key] = out
	return node, changed, nil
}

// rewriteAllValues applies transform to every string and number within node. A number is only
// replaced (by a string) when transform changes it, e.g. an SSN sent as a JSON number.
func rewriteAllValues(node interface{}, transform func(string) string) (interface{}, bool) {
	switch v := node.(type) {
	case string:
		out := transform(v)
		return out, out != v
	case float64:
		s := strconv.FormatFloat(v, 'f', -1, 64)
		if out := transform(s); out != s {
			return out, true
		}
		return v, false
	case map[string]interface{}:
		changed := false
		for _, k := range sortedKeys(v) {
			out, c := rewriteAllValues(v[k], transform)
			v[k] = out
			changed = changed || c
		}
		return v, changed
	case []interface{}:
		changed := false
		for i := range v {
			out, c := rewriteAllValues(v[i], transform)
			v[i] = out
			changed = changed || c
		}
		return v, changed
	}
	return node, false
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
