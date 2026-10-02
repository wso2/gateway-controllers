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

package regexguardrail

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// extractInspectableText returns the text a guardrail must inspect at jsonPath.
//
// An empty jsonPath inspects the raw payload. Otherwise the selected value may
// be a string, number, boolean, object or array, including the slice a
// wildcard segment such as "$.questions.*.instructions" produces. Every string
// leaf is collected, with object keys visited in sorted order, and the parts
// are joined with newlines, so no field of a structured value escapes
// inspection. A path that selects no text is an error, so callers fail closed
// rather than letting uninspected content through.
func extractInspectableText(payload []byte, jsonPath string) (string, error) {
	if jsonPath == "" {
		return string(payload), nil
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return "", err
	}

	value, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return "", err
	}

	// A plain string is returned as-is, which keeps behaviour identical for
	// paths that already resolved to a string.
	if s, ok := value.(string); ok {
		return s, nil
	}

	parts := collectTextLeaves(value, nil)
	if len(parts) == 0 {
		return "", errors.New("value at JSONPath contains no text to inspect")
	}
	return strings.Join(parts, "\n"), nil
}

// collectTextLeaves appends every scalar leaf of value to parts. Nulls carry no
// text and are skipped.
func collectTextLeaves(value interface{}, parts []string) []string {
	switch v := value.(type) {
	case string:
		return append(parts, v)
	case float64:
		return append(parts, strconv.FormatFloat(v, 'f', -1, 64))
	case bool:
		return append(parts, strconv.FormatBool(v))
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = collectTextLeaves(v[k], parts)
		}
	case []interface{}:
		for _, item := range v {
			parts = collectTextLeaves(item, parts)
		}
	}
	return parts
}
