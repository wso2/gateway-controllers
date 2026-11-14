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
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The capability is what the chain builder type-asserts on. A policy listed as a fault entry
// that does not implement this is DROPPED at chain-build time with a log line and then simply
// never runs, so losing the method would disable the whole fault path silently.
var _ policy.FaultPolicy = (*Policy)(nil)

// publishChain drives the request phase so a chain exists in metadata, and returns that
// metadata for the response or fault phase to be driven against.
func publishChain(p *Policy, requestedModel string) map[string]interface{} {
	metadata := map[string]interface{}{}
	body, _ := json.Marshal(map[string]interface{}{"model": requestedModel})
	p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true},
	}, nil)
	return metadata
}

func faultContext(metadata map[string]interface{}, status int, attempts string) *policy.FaultContext {
	return &policy.FaultContext{
		SharedContext:   &policy.SharedContext{Metadata: metadata},
		ResponseStatus:  status,
		ResponseHeaders: policy.NewHeaders(map[string][]string{attemptCountHeader: {attempts}}),
	}
}

// THE case this exists for. With handle_upstream_faults on, the engine skips every response
// policy for a response of 400 or above, so without OnFault nothing would ever be charged to
// a target's health and no target could reach suspension.
func TestFault_GradesHealthWhenTheResponseHookWasSkipped(t *testing.T) {
	p := policyWithChain()
	s := testSuspension()
	s.ConsecutiveFailures = 1
	s.DurationSeconds = 300
	s.clamp()
	p.health = NewHealthStore(s)

	metadata := publishChain(p, "gpt-4o")
	p.OnFault(context.Background(), faultContext(metadata, 503, "1"), nil)

	if p.health.Healthy(Target{Model: "gpt-4o"}, p.now()) {
		t.Fatal("the failing target was not charged, so with the fault flow enabled no target could ever be suspended")
	}
}

// The client must not be able to tell which path served them.
func TestFault_ExhaustionReturnsTheSameStatusAndBody(t *testing.T) {
	p := policyWithChain()
	metadata := publishChain(p, "gpt-4o")

	fr := p.OnFault(context.Background(), faultContext(metadata, 503, "2"), nil)
	if fr == nil {
		t.Fatal("an exhausted chain returned no fault response, so the upstream's own error would reach the client")
	}
	if fr.StatusCode == nil || *fr.StatusCode != exhaustionStatus {
		t.Fatalf("status = %v, want %d", fr.StatusCode, exhaustionStatus)
	}
	if string(fr.Body) != exhaustionBody {
		t.Fatalf("body = %s, want the same bytes the response path returns: %s", fr.Body, exhaustionBody)
	}
}

// The engine applies a returned Fault by REPLACING the whole description, keeping only Policy.
// Building a fresh one carrying just this policy's code would therefore delete the engine's
// own classification of the failure — which on this path is present and correct, and is a
// class a policy is not allowed to set for itself.
func TestFault_OverlaysTheCodeWithoutLosingTheEnginesClassification(t *testing.T) {
	p := policyWithChain()
	metadata := publishChain(p, "gpt-4o")

	ctx := faultContext(metadata, 503, "2")
	ctx.Fault = &policy.FaultDetails{Type: policy.FaultTypeUpstream, Code: "101503", Message: "upstream reset"}

	fr := p.OnFault(context.Background(), ctx, nil)
	if fr == nil || fr.Fault == nil {
		t.Fatal("no fault description returned")
	}
	if fr.Fault.Type != policy.FaultTypeUpstream {
		t.Fatalf("type = %q, want the engine's %q preserved — a policy may not set this class itself",
			fr.Fault.Type, policy.FaultTypeUpstream)
	}
	if fr.Fault.Code != exhaustionCode {
		t.Fatalf("code = %q, want %q", fr.Fault.Code, exhaustionCode)
	}
	if fr.Fault.Message != exhaustionMessage {
		t.Fatalf("message = %q, want the caller-safe one", fr.Fault.Message)
	}
}

// Both hooks can run for ONE request: a 200 is graded in the response chain, and a later
// response policy rejecting it opens the fault flow afterwards. Charging twice would put two
// samples in the window for one request, inflating the error-rate denominator and skewing the
// percentile.
func TestFault_DoesNotChargeARequestTheResponseHookAlreadyGraded(t *testing.T) {
	p := policyWithChain()
	s := testSuspension()
	s.ConsecutiveFailures = 2 // one charge is survivable; two is not
	s.DurationSeconds = 300
	s.clamp()
	p.health = NewHealthStore(s)

	metadata := publishChain(p, "gpt-4o")
	p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: metadata},
		ResponseStatus:  503,
		ResponseHeaders: policy.NewHeaders(map[string][]string{attemptCountHeader: {"1"}}),
	}, nil)

	// The same request now reaches the fault flow.
	p.OnFault(context.Background(), faultContext(metadata, 503, "1"), nil)

	if !p.health.Healthy(Target{Model: "gpt-4o"}, p.now()) {
		t.Fatal("one request was charged twice: a single failure suspended a target configured to tolerate two")
	}
}

// An operation the policy is inert for must stay inert on this path too, or attaching failover
// to an API it does not apply to would start rewriting that API's errors.
func TestFault_IsInertWhenNoChainWasPublished(t *testing.T) {
	p := policyWithChain()
	if fr := p.OnFault(context.Background(), faultContext(map[string]interface{}{}, 503, "1"), nil); fr != nil {
		t.Fatalf("a request with no published chain produced a fault response: %+v", fr)
	}
	if fr := p.OnFault(context.Background(), nil, nil); fr != nil {
		t.Fatalf("a nil fault context produced a fault response: %+v", fr)
	}
}

// A status the publisher never nominated is still returned unchanged on this path: the record
// travels, the response does not.
func TestFault_LeavesANonFailoverWorthyStatusAlone(t *testing.T) {
	p := policyWithChain()
	metadata := publishChain(p, "gpt-4o")

	fr := p.OnFault(context.Background(), faultContext(metadata, 400, "1"), nil)
	if fr == nil {
		t.Fatal("expected the record to travel even when the response is untouched")
	}
	if fr.StatusCode != nil || fr.Body != nil {
		t.Fatalf("a 400 was rewritten: status=%v body=%s", fr.StatusCode, fr.Body)
	}
	if len(fr.AnalyticsMetadata) == 0 {
		t.Fatal("no record travelled")
	}
}
