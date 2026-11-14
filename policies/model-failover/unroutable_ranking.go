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

import (
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The answer to a request whose ROUTING-POLICY ranking could not be addressed at all.
//
// A SCOPED EXCEPTION to FR-030b, and deliberately only that (FR-061). Everywhere else a chain
// that resolves to nothing leaves this policy inert, because inert is genuinely harmless
// there — and the control plane is what makes it harmless. buildFailoverSpecifierPlugin emits
// NO cluster specifier when none of the publisher's targets resolved, and translator.go
// assigns the retry policy only in the branch where that plugin exists. So a publisher whose
// own chain names providers this API has no upstream for gets an ordinary route to the main
// upstream: no groups, no retries, nothing to fall back to incorrectly.
//
// One case does not have that property. When the publisher's targets DID resolve, the route
// carries real priority groups built from them — and a routing policy then ranks providers
// that do not resolve. Publishing nothing there does not mean "no failover": it means Envoy
// walks the CONFIGURED groups, serving a provider the ranking never nominated, with the full
// retry budget behind it. That is the FR-014 defect in its other form — a ranking that still
// routes traffic to an unranked target is not a ranking — and for model traffic it is not a
// harmless substitution, because a routing policy nominates a provider for cost, data
// residency or capability.
//
// Only model-failover can detect this. The provider-to-cluster map (FR-058) is injected into
// this policy alone, so the routing policy that published the ranking has no way to know its
// own targets are unaddressable here.
const (
	// 503, for the same reason exhaustion is: the gateway has nowhere it is willing to send
	// this request. Not a 4xx — the caller's request was valid.
	unroutableStatus = 503

	// Allocated after exhaustionCode (960100) in the SDK's ShippedPolicyRangeStart..End
	// block (960000-965000), clear of the shared 960000/960001.
	unroutableCode  = "960101"
	unroutableError = "failover_unroutable_ranking"

	// States the condition and nothing else — no provider, no cluster, no count. A chain's
	// membership is publisher configuration the caller was never shown, and none of it is
	// actionable by them (.claude/rules/error-handling.md directives 1 and 5).
	unroutableMessage = "No model target for this request is available on this API."
)

const unroutableBody = `{"code":"` + unroutableCode +
	`","error":"` + unroutableError +
	`","message":"` + unroutableMessage + `"}`

// rejectUnroutableRanking answers a request whose routing-policy ranking named only providers
// this API has no upstream for.
//
// Attempts and ChainLength are zero, which is the literal truth: nothing was published and
// nothing was tried. The dropped list is the whole of what happened and is what makes the
// record readable — it names every target that could not be addressed.
func (p *Policy) rejectUnroutableRanking(requestedModel string, published, skipped, dropped []Target) policy.RequestAction {
	record := attemptRecord{
		RequestedModel: requestedModel,
		Outcome:        outcomeUnroutable,
		RankingSource:  rankingSourceOf(published),
		SkippedTargets: skipped,
		DroppedTargets: dropped,
	}
	record.log()
	slog.Warn("ModelFailover: refusing the request, a routing policy ranked only providers "+
		"with no upstream on this API; serving it would send traffic to a target the "+
		"ranking never nominated",
		"dropped", targetLabels(dropped))
	return policy.ImmediateResponse{
		StatusCode:        unroutableStatus,
		Headers:           map[string]string{"content-type": "application/json"},
		Body:              []byte(unroutableBody),
		AnalyticsMetadata: record.analytics(),
	}
}
