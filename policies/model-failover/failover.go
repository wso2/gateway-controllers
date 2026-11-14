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

// Package modelfailover re-attempts a failed AI model request against the next target in an
// ordered chain, so a client application receives a successful response instead of an
// upstream failure.
//
// How it fits together:
//
//   - The policy runs ONCE per client request, on the downstream chain. It resolves the
//     chain — a routing policy's per-request ranking first, the publisher's own targets as a
//     last-resort tail, suspended targets removed — and publishes it as priority groups in
//     dynamic metadata.
//   - Envoy's priority_group cluster specifier reads those groups and selects one per attempt:
//     attempt 1 takes group 1, the first retry takes group 2, and so on.
//   - Per-attempt work (provider credentials, request translation) runs in the upstream filter
//     chain, which is the only chain Envoy re-invokes on a retry.
//
// The policy therefore never loops or re-dispatches itself. It states an order once; Envoy
// walks it.
package modelfailover

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Metadata keys used to carry state from the request phase to the response phase, so the
// response phase knows which target it is grading.
const (
	metadataKeySelectedModel    = "model_failover.selected_model"
	metadataKeySelectedProvider = "model_failover.selected_provider"
	metadataKeyRequestStart     = "model_failover.request_start"
	metadataKeyChain            = "model_failover.chain"
	// Request-time facts the response phase cannot recompute: by then the published
	// ranking has served its purpose and the health store has moved on, so which targets
	// were skipped and where the order came from would both be lost.
	metadataKeySkipped = "model_failover.skipped"
	// Members dropped for having no resolvable cluster. Distinct from skipped, which is a
	// HEALTH decision: a drop means the published ranking could not name this target at all,
	// which is a configuration or version-skew problem rather than a runtime one (FR-056a).
	metadataKeyDropped        = "model_failover.dropped"
	metadataKeyRankingSource  = "model_failover.ranking_source"
	metadataKeyRequestedModel = "model_failover.requested_model"

	// metadataKeyGraded records that this request's outcome has already been charged to a
	// target's health, so the fault hook does not charge it a second time. See OnFault.
	metadataKeyGraded = "model_failover.graded"

	// attemptCountHeader is populated by Envoy on the downstream response when the virtual
	// host sets include_attempt_count_in_response.
	attemptCountHeader = "x-envoy-attempt-count"

	// maxRetriesHeader sizes the attempt budget for THIS request.
	//
	// num_retries is generated once from the publisher's own configured chain, so without
	// this a ranking longer than that chain is silently truncated — the tail is published and
	// never tried. Probe H confirmed Envoy honours the header with a route-config retry
	// policy, that it can RAISE the budget above the configured value, and that it is
	// stripped from client requests, so a caller cannot inflate their own retry budget and
	// multiply inference spend (FR-059a).
	maxRetriesHeader = "x-envoy-max-retries"
)

// Policy implements model failover.
type Policy struct {
	params Params
	health HealthStore
	// correlation remembers which target each cluster served, per request, so a completion
	// verdict naming only a cluster can still be graded against the right target. See
	// attempt_correlation.go for why a cluster is not enough on its own.
	correlation *attemptCorrelation
	// now is injectable so tests can drive the suspension clock without sleeping.
	now func() time.Time
}

// GetPolicy is the factory the gateway builder's generated registry calls to instantiate this
// policy. One instance is created per policy attachment, so the health store it owns is scoped
// to that operation — health for one API's targets never leaks into another's.
//
// Parsing never returns an error: an unresolvable or malformed target is dropped and the rest
// of the chain is used, and a policy left with nothing to work with is simply inert. The
// gateway rejects no deployment for an unresolvable policy reference, and failover must not
// become the first policy that blocks a GitOps deployment over an environment mismatch
// (FR-006a, FR-006b).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	parsed := parseParams(params)
	// Both stores shared with the other chain this operation attaches us to — see
	// shared_health.go. The factory runs once per CHAIN entry, so the response chain and the
	// fault chain each get their own *Policy; private stores here would mean the fault chain
	// graded into a store nothing reads.
	health, correlation := sharedStoresFor(metadata, parsed.Suspension)
	return &Policy{
		params:      parsed,
		health:      health,
		correlation: correlation,
		now:         time.Now,
	}, nil
}

// NewPolicy builds a policy from its parameters, with a PRIVATE health store.
//
// Deliberately not the factory path: an attachment's store is shared, and tests that shared a
// process-global store would leak health between cases and pass or fail on execution order.
// Production construction goes through GetPolicy.
func NewPolicy(params map[string]interface{}) *Policy {
	parsed := parseParams(params)
	return &Policy{
		params:      parsed,
		health:      NewHealthStore(parsed.Suspension),
		correlation: newAttemptCorrelation(nil),
		now:         time.Now,
	}
}

// Mode buffers the request body, because the chain is keyed by the model the CLIENT asked
// for and that lives in the payload (FR-045, FR-049).
//
// This is a real cost that a single unconditional chain would avoid, and the reviewed design
// accepts it deliberately: "Request body is buffered (model lookup and replay)". It is confined
// to operations that attach this policy — an operation without it is unaffected (FR-030b).
//
// The response body is still skipped: outcomes are graded from the status code and the attempt
// count, never from the response payload.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders records the start time and nothing else.
//
// The chain cannot be resolved here: it is keyed by the model the client requested, which is in
// the body, so selection waits for OnRequestBody. A routing policy's published ranking is read
// there too, for the same reason — it has to be combined with the selected chain, not before it.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]interface{}) policy.RequestHeaderAction {

	if reqCtx.Metadata != nil {
		reqCtx.Metadata[metadataKeyRequestStart] = p.now()
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// OnRequestBody selects the chain for the requested model and publishes it once for this
// request.
//
// This is the only place the chain is computed. Retries do not re-enter this chain — Envoy
// re-invokes only the upstream filters — so a routing algorithm is consulted at most once per
// request and never pays for repeated classification or scoring (FR-022).
func (p *Policy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext,
	params map[string]interface{}) policy.RequestAction {

	// The per-attempt position, identified by the reserved namespace the engine writes there.
	// A different job entirely: the ranking was decided once, downstream, and this instance
	// only applies the part of it that has to travel in the payload.
	if cluster, perAttempt := attemptCluster(reqCtx.Metadata); perAttempt {
		return p.substituteAttemptModel(reqCtx, cluster)
	}

	now := p.now()
	requestedModel := requestedModelFrom(reqCtx.Body)
	published := p.publishedRanking(reqCtx.Metadata, requestedModel)

	// A request that names NO model, with no routing policy speaking for it, is not this
	// policy's to act on (FR-060).
	//
	// requestedModelFrom returns "" for four different things: no body, a body that is not
	// JSON, JSON with no `model` key, and a `model` that is not a string. None of them is a
	// model this policy can fail over between — but selectChain matches a "*" catch-all on
	// ANY requested model, including "", so without this guard all four were treated as
	// unmatched traffic and absorbed by the catch-all. That is not what a catch-all is for:
	// it exists for a model that WAS named and matched no chain (FR-050), which is a
	// publisher's deliberate "send the rest here", not "apply failover to anything at all".
	//
	// Two concrete consequences, which is why this is a guard rather than a tidy-up. On a
	// kind with no model concept — an A2A agent, a GraphQL API — attaching this policy
	// alongside a catch-all made it publish a ranking and raise the retry budget on every
	// request, when FR-030b requires it to be inert there. And on a kind that does have
	// models, a malformed or model-less body was fanned across every provider in the chain,
	// turning one bad request into as many upstream calls as the chain is long.
	//
	// Guarded on BOTH conditions: a routing policy's ranking names its own models and is
	// perfectly valid for a request whose body named none, so it must still be honoured.
	if requestedModel == "" && len(published) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	// The target this request will ACTUALLY be sent to first — a routing policy's choice when
	// it made one, otherwise the model the client named, since that is where it goes by
	// default.
	first := Target{Model: requestedModel}
	if len(published) > 0 {
		first = published[0]
	}

	// Fallbacks are the ones configured for THAT target, never inferred from the model the
	// client asked for (FR-021a). If a routing policy sent this request somewhere the
	// publisher wrote no chain for, there are no fallbacks — the publisher never said what
	// should happen after that target, and inventing an answer from an unrelated chain would
	// send traffic somewhere nobody nominated.
	var fallbacks []Target
	if chain, matched := selectChain(p.params.Chains, first.Model); matched {
		first = resolveMember(chain.Target, first.Model)
		fallbacks = chain.FallbackMembers(first.Model)
	} else if len(published) == 0 {
		// Nothing configured for this model and no routing policy to obey, so there is
		// nothing to fail over between. The request proceeds unchanged to its normal
		// upstream; an unmatched model is not an error (FR-050).
		return policy.UpstreamRequestModifications{}
	}

	resolved, skipped := resolveChain(published, first, fallbacks, p.health, now)

	// Every candidate is suspended. Answer now rather than letting the request fall through
	// to its configured upstream, which is one of the suspended targets: sending traffic to a
	// target health has taken out of rotation is the one thing suspension exists to prevent,
	// and the request would pay a full per-attempt timeout to learn what is already known
	// (FR-014, "Every target suspended" edge case).
	if len(resolved) == 0 && len(skipped) > 0 {
		return p.rejectAllSuspended(requestedModel, published, skipped)
	}

	metadata, dropped := buildFailoverMetadata(resolved, p.params.ProviderClusters)
	// Said out loud, because a drop is otherwise undetectable: the request still succeeds
	// against whatever remains, and the operator's ranking is quietly shorter than the one
	// they wrote. Warned rather than failed - a shortened chain is still a usable chain, and
	// refusing the request would turn a naming mistake into an outage (FR-056a).
	if len(dropped) > 0 {
		if len(metadata) == 0 {
			slog.Warn("ModelFailover: no chain member resolved to a cluster, so this request "+
				"will not fail over; the controller supplied no provider-to-cluster map, or "+
				"none of the ranked providers exist on this API",
				"dropped", targetLabels(dropped))
		} else {
			slog.Warn("ModelFailover: chain members dropped from the published ranking, having "+
				"no cluster on this API; the ranking is shorter than configured",
				"dropped", targetLabels(dropped), "published", len(resolved)-len(dropped))
		}
	}
	if metadata == nil && len(dropped) > 0 && len(published) > 0 {
		// A routing policy ranked this request, and not one of its targets can be addressed
		// here. Refuse rather than go inert (FR-061).
		//
		// Inert is harmless everywhere else because the control plane makes it so: with none
		// of the PUBLISHER's targets resolvable the controller emits no cluster specifier and
		// no retry policy, so the route is ordinary and there is nothing to fall back to
		// incorrectly. Here the publisher's targets DID resolve, so the route carries real
		// priority groups — and publishing nothing hands the request to those, serving a
		// provider this ranking never nominated with the whole retry budget behind it.
		return p.rejectUnroutableRanking(requestedModel, published, skipped, dropped)
	}
	if metadata == nil {
		// Nothing to fail over between. The policy is inert: no metadata, no telemetry, no
		// behavioural difference from not being attached at all (FR-030b, FR-030e).
		return policy.UpstreamRequestModifications{}
	}

	// Remember which cluster serves which member, so a completion verdict arriving long after
	// this request finished can be graded against the right target. The verdict names only a
	// cluster, and a cluster does not identify a target — see attempt_correlation.go.
	p.correlation.Remember(requestIDFrom(reqCtx.Headers), resolved, p.params.ProviderClusters)

	// Carry the WHOLE chain to the response phase, not just the first member.
	//
	// The response phase runs once and sees only the final response, because Envoy does not
	// re-run downstream filters per attempt. Knowing only the first member would mean grading
	// it for an answer a later one produced — so a consistently failing member would be
	// recorded healthy every time failover rescued the request, and never suspended. The
	// chain plus the attempt count is what makes correct attribution possible.
	leading := resolved[0]
	if reqCtx.Metadata != nil {
		reqCtx.Metadata[metadataKeyChain] = resolved
		reqCtx.Metadata[metadataKeySelectedModel] = leading.Model
		reqCtx.Metadata[metadataKeySelectedProvider] = leading.Provider
		reqCtx.Metadata[metadataKeyRequestedModel] = requestedModel
		reqCtx.Metadata[metadataKeyRankingSource] = rankingSourceOf(published)
		if len(skipped) > 0 {
			reqCtx.Metadata[metadataKeySkipped] = skipped
		}
		if len(dropped) > 0 {
			reqCtx.Metadata[metadataKeyDropped] = dropped
		}
	}

	slog.Debug("ModelFailover: published failover chain",
		"requested_model", requestedModel, "members", len(resolved),
		"first_model", leading.Model, "first_provider", leading.Provider)

	// Size the budget to the ranking actually published: N members need N-1 retries. Order
	// comes from the metadata above, length from this header — both per request.
	retries := len(resolved) - 1
	if retries < 0 {
		retries = 0
	}

	return policy.UpstreamRequestModifications{
		DynamicMetadata: metadata,
		HeadersToSet: map[string]string{
			maxRetriesHeader: strconv.Itoa(retries),
		},
	}
}

// requestedModelFrom reads the client's requested model out of the buffered JSON payload.
//
// A body that is absent, not JSON, or carries no "model" yields "". That is not an error: it
// simply means no exact chain can match, so only a "*" catch-all applies and a wildcard member
// resolves to nothing to substitute. Rejecting the request here would make failover the policy
// that breaks every non-JSON operation it is attached to.
func requestedModelFrom(body *policy.Body) string {
	if body == nil || len(body.Content) == 0 {
		return ""
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body.Content, &payload); err != nil {
		return ""
	}
	model, _ := payload["model"].(string)
	return model
}

// OnResponseHeaders grades the attempt that produced this response.
//
// Only health is updated here. The failover itself already happened inside Envoy: by the time
// a response reaches this phase, the retry sequence is over and this is the answer the client
// will receive. Recording the outcome is what lets the NEXT request avoid a target that has
// started failing.
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext,
	params map[string]interface{}) policy.ResponseHeaderAction {

	chain, ok := p.chainFromMetadata(respCtx.Metadata)
	if !ok {
		// The policy was inert for this request, or another policy cleared the metadata.
		return policy.DownstreamResponseHeaderModifications{}
	}

	now := p.now()
	latency := p.latencySince(respCtx.Metadata, now)
	status := respCtx.ResponseStatus

	// Attempts 1..N-1 were retried, which only happens when they failed. Attempt N produced
	// the response in hand. Grading every target the request actually touched — rather than
	// only the first — is what keeps a failing target moving toward suspension even when
	// failover hid the failure from the client.
	attempts := p.attemptCount(respCtx, len(chain))
	for i := 0; i < attempts-1 && i < len(chain); i++ {
		if event := p.health.RecordFailure(chain[i], latency, now); event != nil {
			p.logSuspension(event)
		}
	}

	target := chain[0]
	if idx := attempts - 1; idx > 0 && idx < len(chain) {
		target = chain[idx]
	}

	failed := append([]Target{}, chain[:min(attempts-1, len(chain))]...)

	outcome := outcomeServed
	switch {
	case p.isFailoverWorthy(status):
		if event := p.health.RecordFailure(target, latency, now); event != nil {
			p.logSuspension(event)
		}
		// The last target answered with a failure too, so the chain is spent. That is the
		// one outcome the client actually sees as an error.
		outcome = outcomeExhausted
		failed = append(failed, target)
	case isProvisionalStatus(respCtx):
		// The status says success, but it was committed to the client before the body
		// existed, so it is not evidence the target SERVED the request: an upstream that
		// dies mid-stream arrives here as the 200 it started as (FR-030n).
		//
		// Recorded as nothing rather than as a success. Banking it would reset the
		// consecutive-failure count and add a healthy sample to the window, which is how a
		// provider that truncates everything immunises itself against the suspension its
		// real failures would otherwise trigger. Probe accounting still advances, or a
		// target whose responses are all streamed could never recover (FR-030p).
		if recovered := p.health.RecordUnverified(target, now); recovered != nil {
			p.logRecovery(recovered)
		}
		if attempts > 1 {
			outcome = outcomeRescued
		}
	default:
		// Any non-failover-worthy status counts as a success for health purposes: the target
		// answered. A 400 is the client's problem, not the provider's.
		recovered, suspended := p.health.RecordSuccess(target, latency, now)
		if recovered != nil {
			p.logRecovery(recovered)
		}
		if suspended != nil {
			// A success that suspended the target: the latency rule reading a window of
			// responses that all arrived, all too slowly (FR-018e).
			p.logSuspension(suspended)
		}
		if attempts > 1 {
			outcome = outcomeRescued
		}
	}

	record := attemptRecord{
		RequestedModel: stringFromMetadata(respCtx.Metadata, metadataKeyRequestedModel),
		Attempts:       attempts,
		ChainLength:    len(chain),
		Outcome:        outcome,
		ServingTarget:  target,
		RankingSource:  stringFromMetadata(respCtx.Metadata, metadataKeyRankingSource),
		FailedTargets:  failed,
		SkippedTargets: targetsFromMetadata(respCtx.Metadata, metadataKeySkipped),
		DroppedTargets: targetsFromMetadata(respCtx.Metadata, metadataKeyDropped),
	}
	record.log()

	// Claim the grading for this request before returning, so a fault chain opened by a
	// LATER response policy does not record the same outcome again.
	if respCtx.Metadata != nil {
		respCtx.Metadata[metadataKeyGraded] = true
	}

	// The chain ran out. Replace the final upstream's own error with this gateway's, so the
	// caller never receives a body this gateway did not write (FR-014).
	//
	// Guarded by chainCouldFailOver: a single-target operation returns its target's response
	// as-is, exactly as it would with no failover policy attached.
	if outcome == outcomeExhausted && chainCouldFailOver(chain, record.SkippedTargets) {
		return exhaustionResponse(record)
	}

	return policy.DownstreamResponseHeaderModifications{
		AnalyticsMetadata: record.analytics(),
	}
}

// rejectAllSuspended answers a request whose every candidate target is suspended, without
// attempting any of them.
//
// The record carries Attempts and ChainLength of zero, which is the literal truth: nothing was
// tried and no chain was published. The skipped list is what makes the record readable — it
// names every target health withheld, which is the whole of what happened here.
func (p *Policy) rejectAllSuspended(requestedModel string, published, skipped []Target) policy.RequestAction {
	record := attemptRecord{
		RequestedModel: requestedModel,
		Outcome:        outcomeUnavailable,
		RankingSource:  rankingSourceOf(published),
		SkippedTargets: skipped,
	}
	record.log()
	return exhaustionResponse(record)
}

// rankingSourceOf reports where this request's order came from: a routing policy that
// published one, or the publisher's configured chain.
func rankingSourceOf(published []Target) string {
	if len(published) > 0 {
		return rankingSourceRoutingPolicy
	}
	return rankingSourceConfigured
}

func stringFromMetadata(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return value
}

func targetsFromMetadata(metadata map[string]interface{}, key string) []Target {
	if metadata == nil {
		return nil
	}
	targets, _ := metadata[key].([]Target)
	return targets
}

// publishedRanking reads the ordered target preference list a routing policy published for
// this request, if any.
//
// Two tiers, both addressed generically — neither names a producer:
//
//  1. MetadataKeyPublishedRanking, the ordered-list contract introduced by this feature. A
//     producer that has adopted it expresses order, model and provider.
//  2. MetadataKeySelectedProvider, the single-selection convention that predates this feature
//     and that every steering policy in the repo writes unmodified. It degrades gracefully:
//     one element, and the configured chain continues after it (FR-023).
//
// requestedModel is passed in rather than re-read because tier 2 carries no model: see the
// comment on MetadataKeySelectedProvider for why a provider-only selection means "the model
// the client asked for, at this provider".
func (p *Policy) publishedRanking(metadata map[string]interface{}, requestedModel string) []Target {
	if metadata == nil {
		return nil
	}

	if raw, ok := metadata[MetadataKeyPublishedRanking]; ok {
		if list := decodeRanking(raw); len(list) > 0 {
			return list
		}
	}

	provider, _ := metadata[MetadataKeySelectedProvider].(string)
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return nil
	}
	return []Target{{Model: requestedModel, Provider: provider}}
}

// decodeRanking converts a published preference list into targets, per the pinned wire
// representation in contracts/target-preference-list.md.
//
// The carrier is []map[string]string — BUILT-IN TYPES ONLY, and that is the whole point. A
// producer lives in a different Go module, and a Go type assertion matches identical named
// types rather than structurally compatible ones, so the previous `raw.([]Target)` could never
// succeed for any real producer: a policy doing exactly the right thing fell silently through
// to the single-selection path. The existing single-selection keys are plain strings for the
// same reason, and they work across modules today.
//
// []any of maps is accepted too, since a producer assembling the list generically naturally
// produces that. Anything else yields no ranking, and the caller degrades rather than failing —
// an unreadable ranking must not take the request down.
func decodeRanking(raw interface{}) []Target {
	switch list := raw.(type) {
	case []map[string]string:
		targets := make([]Target, 0, len(list))
		for _, entry := range list {
			targets = appendRankingEntry(targets, entry["model"], entry["provider"])
		}
		return targets

	case []Target:
		// model-failover's own type, for producers inside this package and for tests. Kept
		// because it costs nothing; it is NOT the contract and no external producer can use it.
		return list

	case []interface{}:
		targets := make([]Target, 0, len(list))
		for _, item := range list {
			switch entry := item.(type) {
			case map[string]string:
				targets = appendRankingEntry(targets, entry["model"], entry["provider"])
			case map[string]interface{}:
				model, _ := entry["model"].(string)
				provider, _ := entry["provider"].(string)
				targets = appendRankingEntry(targets, model, provider)
			}
		}
		return targets
	}
	return nil
}

// appendRankingEntry adds one decoded entry, skipping an unusable one rather than rejecting the
// whole ranking — a producer with one malformed entry should lose that entry, not its order.
func appendRankingEntry(targets []Target, model, provider string) []Target {
	if model == "" {
		return targets
	}
	return append(targets, Target{Model: model, Provider: provider})
}

func (p *Policy) chainFromMetadata(metadata map[string]interface{}) ([]Target, bool) {
	if metadata == nil {
		return nil, false
	}
	chain, ok := metadata[metadataKeyChain].([]Target)
	if !ok || len(chain) == 0 {
		return nil, false
	}
	return chain, true
}

// attemptCount reads how many upstream attempts Envoy made, from the x-envoy-attempt-count
// response header. The virtual host is generated with IncludeAttemptCountInResponse whenever
// any of its routes fails over.
//
// A missing or unparseable header means one attempt. That is the safe reading: it grades only
// the first target and never invents failures for targets the request may not have reached.
func (p *Policy) attemptCount(respCtx *policy.ResponseHeaderContext, chainLen int) int {
	attempts := 1
	if respCtx.ResponseHeaders != nil {
		if values := respCtx.ResponseHeaders.Get(attemptCountHeader); len(values) > 0 {
			if parsed, err := strconv.Atoi(values[0]); err == nil && parsed > 0 {
				attempts = parsed
			}
		}
	}
	if attempts > chainLen {
		// More attempts than targets should not happen, since num_retries is generated as
		// chain length - 1. Clamp rather than index out of range.
		attempts = chainLen
	}
	return attempts
}

// logSuspension records which criterion fired and its observed value, so an operator can tell
// a hard outage from intermittent degradation from creeping slowness without reconstructing
// it from raw logs (FR-018d, FR-019d).
func (p *Policy) logSuspension(event *SuspensionEvent) {
	slog.Info("ModelFailover: target suspended",
		"model", event.Target.Model,
		"provider", event.Target.Provider,
		"reason", string(event.Reason),
		"observed", event.Observed,
		"sample_size", event.SampleSize,
		"duration_seconds", event.DurationSeconds,
		"escalation_step", event.EscalationStep)
}

// logRecovery reports a target returning to rotation. INFO, like a suspension: an operator
// tracking a flapping provider needs both ends of the cycle, and a recovery that is never
// reported leaves the suspension line looking permanent.
func (p *Policy) logRecovery(event *RecoveryEvent) {
	slog.Info("ModelFailover: target recovered",
		"model", event.Target.Model,
		"provider", event.Target.Provider,
		"probes_required", event.ProbesRequired,
		"suspended_for_seconds", event.SuspendedForSeconds,
		"escalation_step", event.EscalationStep)
}

func (p *Policy) latencySince(metadata map[string]interface{}, now time.Time) time.Duration {
	start, ok := metadata[metadataKeyRequestStart].(time.Time)
	if !ok {
		return 0
	}
	return now.Sub(start)
}
