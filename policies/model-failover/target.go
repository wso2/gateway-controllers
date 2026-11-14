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

// targetKeySeparator separates provider and model in the composite target key. A NUL byte
// can never appear in a provider or model name, so the key is unambiguous. This mirrors
// model-round-robin's suspensionKey so the two policies agree on what "a target" is.
const targetKeySeparator = "\x00"

// Target is one addressable destination in a failover chain.
//
// Identity is the (Model, Provider) PAIR, never Model alone. The same model reached through
// two provider configurations — say gpt-4o in Azure Sweden and gpt-4o in Azure Spain — is two
// distinct targets with independent health. That is the whole point of regional failover: a
// Sweden outage must not suspend Spain.
type Target struct {
	// Model is the AI model name. Required, minLength 1.
	Model string
	// Provider optionally names the provider configuration this target is reached through.
	// On an LlmProxy it matches a provider's alias in either shape — canonical
	// `providers[].alias` or legacy `additionalProviders[].as` — falling back to the provider
	// id when no alias is set; on a RestApi it names an upstreamDefinition. The policy never
	// resolves this itself: the controller supplies the alias-to-cluster map, so whichever
	// shape the publisher wrote reaches here already reduced to one name.
	// Empty means the primary provider.
	Provider string
}

// Key returns the composite identity used for health tracking and de-duplication.
//
// Keying on provider+model rather than model alone is what keeps one region's degradation
// from suspending the same model everywhere else (FR-017).
func (t Target) Key() string {
	return t.Provider + targetKeySeparator + t.Model
}

// Valid reports whether the target is structurally usable. A target without a model name
// cannot be resolved to anything and is skipped rather than rejected (FR-006a).
func (t Target) Valid() bool {
	return t.Model != ""
}

// Equal compares targets by identity.
func (t Target) Equal(other Target) bool {
	return t.Model == other.Model && t.Provider == other.Provider
}

// WildcardModel is the model name that matches anything.
//
// It means two different things depending on where it appears, and both come from the reviewed
// design:
//
//   - As a CHAIN key (`targets[].model`), it marks the catch-all chain used for any requested
//     model no other entry names. An exact entry always wins.
//   - As a MEMBER model (a chain's own model, or a fallback's), it passes the client's own
//     requested model through unchanged — the mechanism for failing the same model over to a
//     different provider.
const WildcardModel = "*"

// Chain is the ordered list of members tried for one client-requested model.
//
// The chain's own Model/Provider are the first member; Fallbacks follow in order. The authored
// shape is deliberately asymmetric — `{model, provider, fallbacks: [{model, provider}]}` — so a
// chain reads as "this target, then these replacements".
type Chain struct {
	// RequestedModel is the client-requested model this chain matches, or WildcardModel for
	// the catch-all.
	RequestedModel string
	// Target is the chain's first member.
	Target Target
	// Fallbacks are tried in order after Target fails.
	Fallbacks []Target
}

// Members returns the chain as a flat ordered list: the target, then each fallback.
//
// A member whose model is WildcardModel is resolved against requestedModel, so one authored
// "*" member serves every model it matches while keeping a single health circuit per
// (provider, "*") pair — resolution happens for routing, not for identity.
func (c Chain) Members(requestedModel string) []Target {
	members := make([]Target, 0, 1+len(c.Fallbacks))
	members = append(members, resolveMember(c.Target, requestedModel))
	for _, fallback := range c.Fallbacks {
		members = append(members, resolveMember(fallback, requestedModel))
	}
	return members
}

// resolveMember substitutes the client's requested model into a wildcard member.
func resolveMember(member Target, requestedModel string) Target {
	if member.Model == WildcardModel && requestedModel != "" {
		member.Model = requestedModel
	}
	return member
}

// selectChain picks the chain for a requested model: an exact match always wins over the
// catch-all, and no match at all means the request proceeds unchanged (FR-045, FR-046, FR-050).
func selectChain(chains []Chain, requestedModel string) (Chain, bool) {
	var catchAll *Chain
	for i := range chains {
		switch chains[i].RequestedModel {
		case requestedModel:
			if requestedModel != "" {
				return chains[i], true
			}
		case WildcardModel:
			if catchAll == nil {
				catchAll = &chains[i]
			}
		}
	}
	if catchAll != nil {
		return *catchAll, true
	}
	return Chain{}, false
}

// FallbackMembers is the chain's fallbacks only, with any wildcard resolved against the model
// the client asked for. Separate from Members because the two halves now answer different
// questions: a routing policy may replace the target, but never the fallbacks.
func (c Chain) FallbackMembers(requestedModel string) []Target {
	members := make([]Target, 0, len(c.Fallbacks))
	for _, fallback := range c.Fallbacks {
		members = append(members, resolveMember(fallback, requestedModel))
	}
	return members
}
