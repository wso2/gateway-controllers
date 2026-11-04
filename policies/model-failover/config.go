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

// Defaults for every configurable value. These match contracts/model-failover-policy.yaml and
// the conventions already set by model-round-robin, so a publisher meets one consistent set of
// knobs across the model policies.
const (
	// DefaultConsecutiveFailures suspends a member after this many failures in a row.
	// The reviewed schema's suspendAfterFailures defaults to 1 — suspend on the first
	// qualifying failure — and has a minimum of 1, so this rule is never fully disabled.
	DefaultConsecutiveFailures = 1
	// DefaultDurationSeconds is the BASE suspension duration. It doubles on each
	// re-suspension, capped at DefaultMaxSuspendMultiplier times this value.
	//
	// The reviewed schema defaults suspendDuration to 0, which disables suspension tracking
	// entirely: a publisher opts in. Failover still works without it — a failing member is
	// simply re-attempted on every request rather than skipped.
	DefaultDurationSeconds = 0
	// DefaultMaxSuspendMultiplier caps how far the base duration doubles, as a MULTIPLE of
	// it: 8 with a 30s base caps the window at 240s. 1 disables the doubling.
	DefaultMaxSuspendMultiplier = 8
	// DefaultMaxDurationSeconds is derived from the two above and exists only so a Params
	// built directly in a test has a sane ceiling.
	DefaultMaxDurationSeconds = DefaultDurationSeconds * DefaultMaxSuspendMultiplier
	// DefaultBackoffResetSeconds is how long a restored target must stay healthy before its
	// next suspension starts from the base duration again.
	DefaultBackoffResetSeconds = 600

	// DefaultRecoverAfterSuccesses matches the approved design document.
	DefaultRecoverAfterSuccesses = 3
	// DefaultErrorRatePercent suspends when this share of requests in the window failed.
	DefaultErrorRatePercent = 50
	// DefaultWindowSeconds is the rolling window for the rate and latency rules.
	DefaultWindowSeconds = 60
	// DefaultMinimumRequests is the sample size below which the windowed rules never fire.
	DefaultMinimumRequests = 20
	// DefaultP95LatencyMs of 0 disables latency-based suspension; operators opt in, because a
	// sensible threshold depends entirely on the models in use.
	DefaultP95LatencyMs = 0
	// DefaultPerAttemptTimeoutMs of 0 leaves the route's overall timeout in effect, matching
	// the reviewed schema's perTryTimeout default.
	DefaultPerAttemptTimeoutMs = 0
)

// defaultStatusCodes are the response codes treated as failover-worthy when the publisher
// configures none: rate limiting and server errors.
//
// Authentication, authorization and client-input errors are deliberately absent. Retrying a
// 401 or a 400 on another provider fails the same way, or worse, masks a genuine client bug
// behind a second billed inference call.
var defaultStatusCodes = []int{429, 500, 502, 503, 504}

// FailureConditions decides which upstream outcomes move to the next target.
type FailureConditions struct {
	StatusCodes []int
}

// Suspension carries the three independent suspension criteria plus the escalating backoff.
// Any criterion can suspend a target on its own (FR-018c).
type Suspension struct {
	// ConsecutiveFailures catches a hard-down target quickly.
	ConsecutiveFailures int
	// DurationSeconds is the base suspension; see BackoffResetSeconds for how it resets.
	DurationSeconds int
	// MaxDurationSeconds caps the doubling so a target is never held out forever.
	MaxDurationSeconds int
	// BackoffResetSeconds is the healthy period that earns a reset to base. A target that
	// keeps flapping never earns it and keeps doubling toward the cap.
	BackoffResetSeconds int
	// ErrorRatePercent catches sustained partial degradation — a target failing one request
	// in three is badly degraded but never produces a run of consecutive failures, so the
	// consecutive rule alone is blind to it.
	ErrorRatePercent int
	// WindowSeconds is the rolling window for ErrorRatePercent and P95LatencyMs.
	WindowSeconds int
	// MinimumRequests stops the windowed rules firing on a tiny sample. Without it, two
	// failures out of two requests overnight reads as a 100% error rate.
	MinimumRequests int
	// P95LatencyMs catches creeping slowness that never crosses the per-attempt timeout.
	P95LatencyMs int
	// RecoverAfterSuccesses is how many probe requests in a row must succeed before a target
	// whose suspension window has ended returns to normal rotation.
	//
	// Without it, a window ending restores the target to its FULL share of traffic in one
	// step, and nothing finds out it is still broken until the next failure is recorded —
	// so every request dispatched in that gap pays an extra attempt. This is the half-open
	// state of a circuit breaker: admit one request, see what happens, decide.
	RecoverAfterSuccesses int
}

// Params is the parsed policy configuration.
type Params struct {
	// Chains are the publisher's fallback chains, each keyed by the model the CLIENT
	// requested. An exact entry wins over the "*" catch-all. Members absent from a routing
	// policy's published ranking act as a last-resort tail reachable only after that ranking
	// is exhausted.
	Chains []Chain
	// ProviderClusters maps a provider alias to the cluster serving it, injected by the
	// controller. The cluster depends on the provider alone, never the model, so this is
	// enough to build a group for ANY model at request time — including one no configuration
	// enumerated (FR-058).
	ProviderClusters  map[string]string
	FailureConditions FailureConditions
	Suspension        Suspension

	// PerAttemptTimeoutMs is parsed and DELIBERATELY NEVER READ by this policy.
	//
	// It bounds one attempt, and the controller alone acts on it: the same perTryTimeout
	// parameter is generated into Envoy's retry policy, which is where a hung attempt is
	// actually cut off. Nothing here consults it, and nothing here should.
	//
	// That is FR-018f, not an oversight. A timeout is a per-request bound; suspension is an
	// aggregate judgement over a window. Feeding the timeout into a health decision would
	// let ONE slow request condemn a target, which is the behaviour the windowed rules in
	// health.go exist to replace. Kept on Params because the parameter is this policy's to
	// document and validate, not because anything reads it.
	PerAttemptTimeoutMs int
}

// parseParams reads the policy parameters, applying defaults for everything absent.
//
// Parsing never fails on an unresolvable or nonsensical target: the gateway rejects no
// deployment for an unresolvable policy reference, and failover must not become the first
// policy that blocks a GitOps deployment over an environment mismatch (FR-006a, FR-006b).
// Structurally invalid targets are dropped and the rest of the chain is used; if nothing
// survives, the policy is simply inert.
func parseParams(params map[string]interface{}) Params {
	result := Params{
		FailureConditions: FailureConditions{
			StatusCodes: append([]int(nil), defaultStatusCodes...),
		},
		Suspension: Suspension{
			ConsecutiveFailures:   DefaultConsecutiveFailures,
			DurationSeconds:       DefaultDurationSeconds,
			MaxDurationSeconds:    DefaultMaxDurationSeconds,
			BackoffResetSeconds:   DefaultBackoffResetSeconds,
			RecoverAfterSuccesses: DefaultRecoverAfterSuccesses,
			ErrorRatePercent:      DefaultErrorRatePercent,
			WindowSeconds:         DefaultWindowSeconds,
			MinimumRequests:       DefaultMinimumRequests,
			P95LatencyMs:          DefaultP95LatencyMs,
		},
		PerAttemptTimeoutMs: DefaultPerAttemptTimeoutMs,
	}

	result.Chains = parseChains(params["targets"])
	result.ProviderClusters = parseProviderClusters(params[ProviderClustersParam])

	// statusCodes REPLACES the default list entirely rather than extending it, so a
	// publisher who lists only 429 gets failover on 429 and nothing else.
	if codes := parseIntSlice(params["statusCodes"]); len(codes) > 0 {
		result.FailureConditions.StatusCodes = codes
	}

	// The reviewed schema is flat: suspension parameters sit alongside targets rather than
	// nested under a "suspension" object.
	setInt(&result.Suspension.ConsecutiveFailures, params["suspendAfterFailures"])
	setInt(&result.Suspension.DurationSeconds, params["suspendDuration"])
	setInt(&result.Suspension.BackoffResetSeconds, params["backoffResetSeconds"])
	setInt(&result.Suspension.ErrorRatePercent, params["errorRatePercent"])
	setInt(&result.Suspension.WindowSeconds, params["windowSeconds"])
	setInt(&result.Suspension.MinimumRequests, params["minimumRequests"])
	setInt(&result.Suspension.P95LatencyMs, params["p95LatencyMs"])
	setInt(&result.Suspension.RecoverAfterSuccesses, params["recoverAfterSuccesses"])

	// maxSuspendMultiplier is a MULTIPLE of the base duration, not an absolute ceiling, so
	// the authored value has to be turned into one.
	multiplier := DefaultMaxSuspendMultiplier
	setInt(&multiplier, params["maxSuspendMultiplier"])
	if multiplier < 1 {
		multiplier = 1
	}
	result.Suspension.MaxDurationSeconds = result.Suspension.DurationSeconds * multiplier

	// perTryTimeout is authored in SECONDS; everything downstream works in milliseconds.
	perTrySeconds := 0
	setInt(&perTrySeconds, params["perTryTimeout"])
	if perTrySeconds > 0 {
		result.PerAttemptTimeoutMs = perTrySeconds * 1000
	}

	result.Suspension.clamp()
	return result
}

// clamp repairs values that would make the suspension rules behave nonsensically. The
// controller rejects out-of-range values at deployment, so this is belt-and-braces for a
// policy constructed directly in tests or by a future caller.
func (s *Suspension) clamp() {
	if s.MaxDurationSeconds < s.DurationSeconds {
		// A cap below the base would shrink the first suspension rather than bound the last.
		s.MaxDurationSeconds = s.DurationSeconds
	}
	if s.WindowSeconds < 1 {
		s.WindowSeconds = DefaultWindowSeconds
	}
	if s.MinimumRequests < 1 {
		// A zero sample size would let a single failure read as a 100% error rate.
		s.MinimumRequests = DefaultMinimumRequests
	}
	if s.BackoffResetSeconds < 1 {
		s.BackoffResetSeconds = DefaultBackoffResetSeconds
	}
	if s.ErrorRatePercent < 0 {
		s.ErrorRatePercent = 0
	}
	if s.ErrorRatePercent > 100 {
		s.ErrorRatePercent = 100
	}
	if s.P95LatencyMs < 0 {
		s.P95LatencyMs = 0
	}
	if s.RecoverAfterSuccesses < 1 {
		// Zero or negative would mean "restore with no evidence at all", which is the
		// behaviour this parameter exists to prevent. One probe is the weakest meaningful
		// gate, so that is the floor.
		s.RecoverAfterSuccesses = 1
	}
}

// parseProviderClusters reads the controller-injected provider-to-cluster map.
//
// Absent or malformed, the policy falls back to publishing group names alone, which still works
// for every (provider, model) the controller enumerated — so an older controller paired with a
// newer policy degrades rather than breaks.
func parseProviderClusters(raw interface{}) map[string]string {
	entries, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	clusters := make(map[string]string, len(entries))
	for alias, v := range entries {
		if cluster, ok := v.(string); ok && cluster != "" {
			clusters[alias] = cluster
		}
	}
	if len(clusters) == 0 {
		return nil
	}
	return clusters
}

// parseChains reads the nested targets[].fallbacks[] shape of the reviewed schema.
//
// Nothing here fails: an entry with no model is skipped and the rest of the configuration is
// used, because the gateway rejects no deployment for an unresolvable policy reference
// (FR-006a, FR-006b).
func parseChains(raw interface{}) []Chain {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	chains := make([]Chain, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		model, _ := entry["model"].(string)
		if model == "" {
			// No requested-model key means the chain can never be selected.
			continue
		}
		provider, _ := entry["provider"].(string)
		chain := Chain{
			RequestedModel: model,
			// The chain's own model/provider ARE its first member. A chain keyed "*" has a
			// "*" first member, which resolves to the client's own requested model.
			Target:    Target{Model: model, Provider: provider},
			Fallbacks: parseFallbacks(entry["fallbacks"], provider),
		}
		chains = append(chains, chain)
	}
	return chains
}

// parseFallbacks reads one chain's fallback list.
//
// A fallback with no provider inherits the CHAIN'S target provider, not the proxy primary
// (FR-048) — so failing over to the primary from a target on another provider means naming the
// primary explicitly.
func parseFallbacks(raw interface{}, chainProvider string) []Target {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	fallbacks := make([]Target, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		model, _ := entry["model"].(string)
		if model == "" {
			continue
		}
		provider, _ := entry["provider"].(string)
		if provider == "" {
			provider = chainProvider
		}
		fallbacks = append(fallbacks, Target{Model: model, Provider: provider})
	}
	return fallbacks
}

func parseIntSlice(raw interface{}) []int {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]int, 0, len(list))
	for _, item := range list {
		if v, ok := toInt(item); ok {
			out = append(out, v)
		}
	}
	return out
}

func setInt(dst *int, raw interface{}) {
	if v, ok := toInt(raw); ok {
		*dst = v
	}
}

// toInt accepts the numeric shapes a YAML/JSON parameter map can carry.
func toInt(raw interface{}) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	default:
		return 0, false
	}
}
