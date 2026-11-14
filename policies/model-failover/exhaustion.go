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
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The one response a client receives when failover ran out of targets.
//
// It is a FIXED payload — the same bytes for every exhausted chain, whatever the last target
// answered (FR-014, SC-006). That is the point of it. The alternative, forwarding the final
// upstream's own error, hands the caller a body this gateway never wrote: a provider error
// naming the account it was billed to, the region that rejected it, or the key that was
// refused. Which upstream failed and why is an operator's question, and it is answered in the
// telemetry record and the log line beside this response, never in the client's body
// (.claude/rules/error-handling.md directives 1 and 4).
const (
	// exhaustionStatus is 503 for both exhaustion paths: every target was tried and none
	// could serve, or every target was suspended and none could be tried. Not the final
	// upstream's status — a chain that ended on a 429 is not a rate-limited client, it is a
	// gateway with nowhere left to send the request.
	exhaustionStatus = 503

	// exhaustionCode is this policy's own fault code.
	//
	// Allocated at 960100, inside the SDK's ShippedPolicyRangeStart..End block (960000-965000)
	// for policies WSO2 ships, and clear of the two codes that block already defines for
	// conditions every policy shares (960000 mediation-failed, 960001 invalid-request-body).
	// Neither fits: nothing here failed to mediate and the request was perfectly valid.
	// "No model available to route to" is named in the SDK's own allocation note as exactly
	// the kind of condition a policy allocates its own code for.
	exhaustionCode = "960100"

	exhaustionError = "failover_exhausted"

	// exhaustionMessage states the condition and nothing else. No target name, no provider,
	// no upstream status — a client cannot act on any of it, and a chain's membership is
	// publisher configuration the caller was never shown.
	exhaustionMessage = "No model target was able to serve this request."
)

// exhaustionBody is a constant rather than a per-request marshal: it has no per-request
// content, so "the same error every time" is a property of the code rather than a claim about
// it. Held as a string and copied at use — the engine passes ImmediateResponse.Body straight
// into the protobuf by reference, and a package-level slice shared by every request in flight
// is an aliasing risk for the sake of one small allocation on an error path.
const exhaustionBody = `{"code":"` + exhaustionCode +
	`","error":"` + exhaustionError +
	`","message":"` + exhaustionMessage + `"}`

// exhaustionResponse renders the exhaustion error, carrying the request's telemetry with it.
//
// The analytics travel ON the response because a short-circuit replaces it: the record built
// for this request would otherwise be dropped along with the upstream's response, and
// exhaustion is the one outcome an operator most needs the record for.
func exhaustionResponse(record attemptRecord) policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode:        exhaustionStatus,
		Headers:           map[string]string{"content-type": "application/json"},
		Body:              []byte(exhaustionBody),
		AnalyticsMetadata: record.analytics(),
	}
}

// exhaustionFaultOverlay describes the exhaustion ON TOP OF whatever the engine already
// decided, rather than in place of it.
//
// The engine applies a returned Fault with `faultCtx.Fault = &redescribed` — a WHOLESALE
// replacement, keeping only Policy. So returning a freshly-built FaultDetails carrying just
// this policy's code would delete the engine's own classification, and on this path that
// classification is both present and correct: the flow is running precisely because the
// response was an upstream failure, which is a class only the engine may set
// (FaultTypeUpstream is documented "Set by the engine, not by a policy").
//
// Copying first and overlaying second keeps Type, Direction and any other field the engine
// resolved, and adds the two things it could not know: which condition this was, and a
// message safe to show the caller.
func exhaustionFaultOverlay(existing *policy.FaultDetails) *policy.FaultDetails {
	described := policy.FaultDetails{}
	if existing != nil {
		described = *existing
	}
	described.Code = exhaustionCode
	described.Message = exhaustionMessage
	return &described
}

// chainCouldFailOver reports whether this request had anywhere to fail over TO.
//
// This is what separates an exhausted chain from a single-target operation, and the two must
// not be conflated: a chain with one target "behaves exactly like no failover — one attempt,
// response returned as-is", so replacing that target's own error with a gateway error would
// change the behaviour of every single-target operation this policy is attached to, for no
// gain. A chain is a real chain when it held more than one member, or when it held one
// because health removed the others.
func chainCouldFailOver(chain, skipped []Target) bool {
	return len(chain) > 1 || len(skipped) > 0
}

// ACCEPTED LIMIT: a chain whose every member fails at TRANSPORT level is not replaced here.
//
// Envoy does not invoke ext_proc for the replies it generates itself (see classify.go), so a
// chain that ends in a connection failure, reset, or per-attempt timeout never reaches this
// policy's response phase and cannot be given this body. The client receives Envoy's own local
// reply instead.
//
// Left as-is deliberately rather than worked around. That reply is generated by the proxy from
// the reset reason; it carries no upstream response body, no provider hostname and no
// credential, so the disclosure this rule exists to prevent cannot occur on that path. What is
// lost is consistency of SHAPE, not containment — and the only way to recover it would be to
// move exhaustion detection out of the policy and into the router's local-reply mapping, which
// is a platform change and not one this policy can make.
