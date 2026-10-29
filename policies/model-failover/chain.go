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

import "time"

// resolveChain builds the ordered list of targets to attempt for one request.
//
// Four sources, in this order:
//
//  1. The FIRST target a routing or load-balancing policy chose, if it chose one. That is what
//     such a policy exists to do — round-robin spreads load by varying which target leads, and
//     discarding its pick would silently disable it.
//  2. The publisher's configured fallbacks for this request's chain. These take precedence over
//     the rest of the routing policy's order: an explicitly written fallback chain is a
//     deliberate statement about where traffic may go next, and a load balancer should not
//     overrule it (FR-021, revised 2026-10-29).
//  3. Whatever else the routing policy ranked, as further depth once the configured fallbacks
//     are spent. Ranked targets are not discarded — the policy already judged them usable.
//  4. The configured target itself, if nothing above already reached it, so the model the client
//     actually asked for stays reachable.
//
// Worked through: routing publishes [A, D, C] and the chain for the requested model is
// A -> [B]. The result is A, B, D, C — when A fails the retry goes to B, the fallback the
// publisher wrote for it, rather than to D.
//
// Suspended targets are excluded throughout, and a target that resolves to nothing is skipped
// rather than failing the deployment (FR-006a).
func resolveChain(published []Target, target Target, fallbacks []Target,
	health HealthStore, now time.Time) []Target {

	seen := make(map[string]struct{}, len(published)+len(fallbacks)+1)
	chain := make([]Target, 0, len(published)+len(fallbacks)+1)

	appendUnseen := func(targets []Target) {
		for _, candidate := range targets {
			if !candidate.Valid() {
				// An unresolvable target is skipped, never a deployment failure (FR-006a).
				continue
			}
			key := candidate.Key()
			if _, dup := seen[key]; dup {
				continue
			}
			if !health.Healthy(candidate, now) {
				// Suspended: excluded from this request's chain. Deliberately NOT marked
				// seen, so it re-enters a later request's chain the moment its suspension
				// expires (FR-019).
				continue
			}
			seen[key] = struct{}{}
			chain = append(chain, candidate)
		}
	}

	if len(published) > 0 {
		appendUnseen(published[:1])
	} else {
		appendUnseen([]Target{target})
	}
	appendUnseen(fallbacks)
	if len(published) > 1 {
		appendUnseen(published[1:])
	}
	appendUnseen([]Target{target})

	return chain
}
