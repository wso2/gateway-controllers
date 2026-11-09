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

package platformgateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const keyAuthHeader = "authHeader"

// BasicAuthHeader returns the Authorization header value carrying the supplied
// credentials as HTTP Basic authentication.
func BasicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func scenarioLabel(ctx context.Context) string {
	if local, ok := tcontext.LocalOf(ctx); ok {
		return local.Runner()
	}
	return "unknown runner"
}

func gatewayOrdinal(word string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "first":
		return 0, nil
	case "second":
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported gateway ordinal %q", word)
	}
}

func traverseJSON(doc any, path string) (any, bool) {
	current := doc
	for _, segment := range strings.Split(path, ".") {
		if segment == "" {
			continue
		}
		name, indices := stepscommon.SplitIndices(segment)
		if name != "" {
			asMap, ok := current.(map[string]any)
			if !ok {
				return nil, false
			}
			if current, ok = asMap[name]; !ok {
				return nil, false
			}
		}
		for _, index := range indices {
			asSlice, ok := current.([]any)
			if !ok || index < 0 || index >= len(asSlice) {
				return nil, false
			}
			current = asSlice[index]
		}
	}
	return current, true
}

// numericTolerance is the relative difference two numbers may have and still be equal. It
// absorbs floating-point rounding in a computed value, and nothing larger.
const numericTolerance = 1e-9

// numericMatches reports whether value, a JSON number or a numeric string, is finite and either
// equals want within numericTolerance ("equal to"; a want of zero needs an exact zero) or is at
// least want ("at least").
func numericMatches(field string, value any, op, want string) error {
	expected, err := strconv.ParseFloat(strings.TrimSpace(want), 64)
	if err != nil {
		return fmt.Errorf("expected value %q for %q is not a number", want, field)
	}
	var got float64
	switch v := value.(type) {
	case float64:
		got = v
	case string:
		if got, err = strconv.ParseFloat(strings.TrimSpace(v), 64); err != nil {
			return fmt.Errorf("metadata field %q is %q, not a number", field, v)
		}
	default:
		return fmt.Errorf("metadata field %q is %v (%T), not a number", field, value, value)
	}
	if math.IsNaN(got) || math.IsInf(got, 0) {
		return fmt.Errorf("metadata field %q is %v, want %v", field, got, expected)
	}
	switch op {
	case "equal to":
		if got == expected || math.Abs(got-expected) <= numericTolerance*math.Max(math.Abs(got), math.Abs(expected)) {
			return nil
		}
		return fmt.Errorf("metadata field %q is %v, want %v", field, got, expected)
	case "at least":
		if got >= expected {
			return nil
		}
		return fmt.Errorf("metadata field %q is %v, want at least %v", field, got, expected)
	default:
		return fmt.Errorf("unsupported comparison %q for %q", op, field)
	}
}
