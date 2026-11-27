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

package modelfailover

import (
	"context"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// OnFault implements policy.FaultPolicy, which is what lets this policy keep working when the
// deployment routes upstream failures through the fault flow.
//
// Why it is needed at all: with policy_engine.fault_policies.handle_upstream_faults enabled,
// the engine sets upstreamFault for any response of 400 or above and responsePolicies() then
// returns NOTHING — every response policy is skipped in favour of the fault chain. For this
// policy that lands on exactly the responses it exists for. Health would stop being graded on
// every failing response, so no target would ever reach suspension, and the exhaustion error
// would never be substituted. Not degraded: off.
//
// The analytics system policy hit the same thing first and solved it the same way, and its
// reasoning is adopted wholesale here — delegate to the response hook rather than reimplement
// it, so there is one implementation rather than two that must be kept in step, and so nothing
// on the ordinary response path can regress from a change made for this one.
func (p *Policy) OnFault(ctx context.Context, faultCtx *policy.FaultContext,
	params map[string]interface{}) *policy.FaultResponse {

	if faultCtx == nil {
		return nil
	}
	// Already graded by the response hook for this request, so stop.
	//
	// Both hooks can run for ONE request: a 200 is graded normally in the response chain, and
	// a later response policy rejecting it (a guardrail refusing the upstream's content, say)
	// opens the fault flow afterwards. Without this the request would be recorded twice —
	// two samples in the window for one request, which inflates the error-rate denominator
	// and skews the percentile. The marker is in shared metadata, which both phases see.
	if graded, _ := faultCtx.Metadata[metadataKeyGraded].(bool); graded {
		return nil
	}

	// The synthesized context is COMPLETE rather than a stub: every field of
	// ResponseHeaderContext exists on FaultContext and is copied, so the response hook sees
	// exactly what it would have seen in the response chain. That is what keeps the
	// delegation safe if it ever reads a field it does not read today.
	respCtx := &policy.ResponseHeaderContext{
		SharedContext:   faultCtx.SharedContext,
		RequestHeaders:  faultCtx.RequestHeaders,
		RequestBody:     faultCtx.RequestBody,
		RequestPath:     faultCtx.RequestPath,
		RequestMethod:   faultCtx.RequestMethod,
		ResponseHeaders: faultCtx.ResponseHeaders,
		ResponseStatus:  faultCtx.ResponseStatus,
		Downstream:      faultCtx.Downstream,
		Upstream:        faultCtx.Upstream,
	}
	// The response hook dereferences SharedContext unguarded, which is right for the response
	// chain because the engine always sets it there. A bare FaultContext can reach here
	// without one, and a request that is already failing must not be turned into a panic.
	if respCtx.SharedContext == nil {
		respCtx.SharedContext = &policy.SharedContext{}
	}

	switch action := p.OnResponseHeaders(ctx, respCtx, params).(type) {
	case policy.ImmediateResponse:
		// The chain was spent. ImmediateResponse is not a member of the fault oneof — on this
		// path there is no upstream response to forward or replace, every entry edits the same
		// object — so the same decision is expressed as an edit to it.
		status := action.StatusCode
		return &policy.FaultResponse{
			StatusCode: &status,
			// The same bytes the response path returns, so enabling the fault flow does not
			// change what a client receives. On this path a body is unconditionally the final
			// word: it tells the gateway's protocol formatter to stand down. That is accepted
			// deliberately — it is the behaviour the response path already has.
			Body:              action.Body,
			Fault:             exhaustionFaultOverlay(faultCtx.Fault),
			HeadersToSet:      action.Headers,
			AnalyticsMetadata: action.AnalyticsMetadata,
		}

	case policy.DownstreamResponseHeaderModifications:
		// Graded, but this was not an exhausted chain — a failing status the publisher never
		// nominated, or one attempt of a chain that still has somewhere to go. Nothing about
		// the response changes; only the record travels.
		if len(action.AnalyticsMetadata) == 0 {
			return nil
		}
		return &policy.FaultResponse{AnalyticsMetadata: action.AnalyticsMetadata}
	}

	// Inert for this request, or another policy cleared the metadata. nil is the ordinary
	// "I changed nothing" return.
	return nil
}
