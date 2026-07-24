/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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

package semanticcache

import policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"

// getUpstreamHeaders returns the snapshot of the original upstream backend
// response headers when the gateway provides it, falling back to the live
// (possibly peer-mutated) response headers on older gateways that predate the
// Upstream snapshot.
//
// Use this for every response-header read that feeds a parsing or gating
// decision. The kernel runs every policy's header phase before any policy's
// body phase, mutating one shared header set in place, so a decision that reads
// the live headers can observe a value another policy rewrote — regardless of
// policy order. The Upstream snapshot always holds what the upstream backend
// actually returned.
//
// The nil-checks are required, not optional: Upstream (and its Response) is nil
// on gateways built before the snapshot-header-context feature, and the
// fallback preserves the pre-feature behaviour on those runtimes.
func getUpstreamHeaders(us *policy.UpstreamResponseContext, live *policy.Headers) *policy.Headers {
	if us != nil && us.Response != nil && us.Response.Headers != nil {
		return us.Response.Headers
	}
	return live
}
