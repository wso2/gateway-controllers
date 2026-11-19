/*
 *  Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 */

package modelfailover

import "testing"

// The default grades EVERY 5xx, because the generated retry policy already retries every 5xx
// (retry_on carries the `5xx` token). Grading only the enumerated subset meant a 501 failed over
// on every request and was never recorded, so the provider returning it was never suspended.
func TestIsFailoverWorthy_DefaultGradesEveryFiveXX(t *testing.T) {
	p := policyWithChain()
	for _, code := range []int{500, 501, 502, 503, 504, 505, 520, 599} {
		if !p.isFailoverWorthy(code) {
			t.Errorf("status %d not graded; Envoy retries it, so health must record it", code)
		}
	}
	for _, code := range []int{200, 400, 404, 422} {
		if p.isFailoverWorthy(code) {
			t.Errorf("status %d graded as a failure; a client error must not suspend a target", code)
		}
	}
	if !p.isFailoverWorthy(429) {
		t.Error("429 is in the default list and must stay graded")
	}
}

// An explicit statusCodes list REPLACES the default entirely, 5xx range included.
func TestIsFailoverWorthy_ExplicitListReplacesTheFiveXXDefault(t *testing.T) {
	p := NewPolicy(map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{429},
	})
	if !p.isFailoverWorthy(429) {
		t.Error("429 was listed and must be graded")
	}
	for _, code := range []int{500, 501, 503} {
		if p.isFailoverWorthy(code) {
			t.Errorf("status %d graded though the publisher listed only 429", code)
		}
	}
}
