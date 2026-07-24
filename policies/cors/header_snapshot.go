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

package cors

import policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"

// getDownstreamHeaders returns the snapshot of the original client
// request headers when the gateway provides it, falling back to the live
// (possibly peer-mutated) request headers on older gateways that predate the
// Downstream snapshot.
//
// Use this for every header read that feeds an authentication, authorization,
// or gating decision. The kernel runs every policy's header phase before any
// policy's body phase, mutating one shared header set in place, so a decision
// that reads the live headers can observe a value another policy rewrote —
// regardless of policy order. The Downstream snapshot always holds what the
// client actually sent.
func getDownstreamHeaders(ds *policy.DownstreamContext, live *policy.Headers) *policy.Headers {
	if ds != nil && ds.Request != nil && ds.Request.Headers != nil {
		return ds.Request.Headers
	}
	return live
}
