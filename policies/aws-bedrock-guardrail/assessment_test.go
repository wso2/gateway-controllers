/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package awsbedrockguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// scriptedBedrockClient answers each ApplyGuardrail call from a script, so a
// test can make one chunk of an assessment behave differently from the rest.
type scriptedBedrockClient struct {
	replies []scriptedReply
	calls   []*bedrockruntime.ApplyGuardrailInput
}

type scriptedReply struct {
	output *bedrockruntime.ApplyGuardrailOutput
	err    error
}

func (c *scriptedBedrockClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	c.calls = append(c.calls, params)
	reply := scriptedReply{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}}
	if len(c.replies) > 0 {
		reply = c.replies[0]
		if len(c.replies) > 1 {
			c.replies = c.replies[1:]
		}
	}
	return reply.output, reply.err
}

// callChars returns the characters sent in each ApplyGuardrail call.
func (c *scriptedBedrockClient) callChars() []int {
	sizes := make([]int, 0, len(c.calls))
	for _, call := range c.calls {
		total := 0
		for _, block := range call.Content {
			if text, ok := block.(*types.GuardrailContentBlockMemberText); ok {
				total += len([]rune(aws.ToString(text.Value.Text)))
			}
		}
		sizes = append(sizes, total)
	}
	return sizes
}

func policyWith(client bedrockGuardrailClient) *AWSBedrockGuardrailPolicy {
	return &AWSBedrockGuardrailPolicy{
		region:           "us-east-1",
		guardrailID:      "gr-123",
		guardrailVersion: "DRAFT",
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient { return client },
	}
}

// sentences builds a body of roughly n characters made of whole sentences, so
// the splitter has boundaries to cut at.
func sentences(n int) string {
	var sb strings.Builder
	for sb.Len() < n {
		sb.WriteString("The quick brown fox jumps over the lazy dog. ")
	}
	return sb.String()[:n]
}

func TestSplitTextAtUnits_PiecesStayUnderTheLimitAndCutAtBoundaries(t *testing.T) {
	text := sentences(50000)
	pieces := splitTextAtUnits(text, maxAssessmentChars)

	if len(pieces) < 4 {
		t.Fatalf("expected a 50k body to split into several pieces, got %d", len(pieces))
	}
	for i, piece := range pieces {
		if got := len([]rune(piece)); got > maxAssessmentChars {
			t.Fatalf("piece %d is %d chars, over the %d limit", i, got, maxAssessmentChars)
		}
	}
	if joined := strings.Join(pieces, ""); joined != text {
		t.Fatalf("splitting lost or changed text: %d chars in, %d out", len(text), len(joined))
	}
	// Every cut but the last should land after a sentence terminator, so a value
	// is never split across two calls.
	for i, piece := range pieces[:len(pieces)-1] {
		if !strings.HasSuffix(strings.TrimRight(piece, " "), ".") {
			t.Fatalf("piece %d does not end at a sentence boundary: %q", i, piece[len(piece)-20:])
		}
	}
}

func TestSplitTextAtUnits_BoundaryFreeTextStillProgresses(t *testing.T) {
	// No spaces and no terminators: there is no boundary to cut at, and the
	// splitter must still make progress rather than grow one piece without bound.
	text := strings.Repeat("x", maxAssessmentChars*3)
	pieces := splitTextAtUnits(text, maxAssessmentChars)

	if len(pieces) != 3 {
		t.Fatalf("expected 3 pieces, got %d", len(pieces))
	}
	for i, piece := range pieces {
		if got := len(piece); got > maxAssessmentChars {
			t.Fatalf("piece %d is %d chars, over the limit", i, got)
		}
	}
}

func TestSplitContentsIntoUnits_PacksSegmentsAndSplitsOversizedOnes(t *testing.T) {
	// Several small segments ride in one call.
	batches := splitContentsIntoUnits([]string{"one", "two", "three"}, maxAssessmentChars)
	if len(batches) != 1 || len(batches[0]) != 3 {
		t.Fatalf("expected 3 small segments in 1 batch, got %d batches: %v", len(batches), batches)
	}

	// A segment larger than a whole batch is split, and no batch exceeds the limit.
	batches = splitContentsIntoUnits([]string{"short", sentences(40000)}, maxAssessmentChars)
	if len(batches) < 4 {
		t.Fatalf("expected an oversized segment to produce several batches, got %d", len(batches))
	}
	for i, batch := range batches {
		total := 0
		for _, piece := range batch {
			total += len(piece)
		}
		if total > maxAssessmentChars {
			t.Fatalf("batch %d is %d chars, over the %d limit", i, total, maxAssessmentChars)
		}
	}

	if got := splitContentsIntoUnits(nil, maxAssessmentChars); got != nil {
		t.Fatalf("expected no batches for no contents, got %v", got)
	}
}

func TestValidatePayload_LargeBodyIsAssessedInSeveralCalls(t *testing.T) {
	client := &scriptedBedrockClient{}
	p := policyWith(client)

	body, err := json.Marshal(map[string]string{"msg": sentences(60000)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result := p.validatePayload(body, AWSBedrockGuardrailPolicyParams{JsonPath: "$.msg"},
		true, map[string]interface{}{})
	if _, ok := result.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected the body to pass, got %T", result)
	}

	if len(client.calls) < 5 {
		t.Fatalf("expected a 60k body to take several ApplyGuardrail calls, got %d", len(client.calls))
	}
	for i, chars := range client.callChars() {
		if chars > maxAssessmentChars {
			t.Fatalf("call %d carried %d chars, over the %d per-request limit",
				i, chars, maxAssessmentChars)
		}
	}
}

func TestValidatePayload_ViolationInALaterChunkBlocksTheWholeBody(t *testing.T) {
	client := &scriptedBedrockClient{replies: []scriptedReply{
		{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}},
		{output: &bedrockruntime.ApplyGuardrailOutput{
			Action:      types.GuardrailActionGuardrailIntervened,
			Assessments: []types.GuardrailAssessment{},
		}},
	}}
	p := policyWith(client)

	body, err := json.Marshal(map[string]string{"msg": sentences(30000)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result := p.validatePayload(body, AWSBedrockGuardrailPolicyParams{JsonPath: "$.msg"},
		true, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mod.StatusCode == nil || *mod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected the violation to block with %d, got %v", GuardrailErrorCode, mod.StatusCode)
	}
	if strings.Contains(string(mod.Body), "quick brown fox") {
		t.Fatalf("blocked response must not carry the assessed content back")
	}
}

// A chunk that cannot be assessed must not let the chunks before it be
// delivered as though the whole body had passed. This is the failure mode that
// turns a Bedrock error into a content leak.
func TestValidatePayload_FailureMidAssessmentDoesNotDeliverTheBody(t *testing.T) {
	client := &scriptedBedrockClient{replies: []scriptedReply{
		{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}},
		{err: errors.New("bedrock unavailable")},
	}}
	p := policyWith(client)

	body, err := json.Marshal(map[string]string{"msg": sentences(30000)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result := p.validatePayload(body, AWSBedrockGuardrailPolicyParams{JsonPath: "$.msg"},
		true, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mod.StatusCode == nil {
		t.Fatalf("expected the failed assessment to be refused, got a delivered body")
	}
	if strings.Contains(string(mod.Body), "quick brown fox") {
		t.Fatalf("a body whose assessment failed must not be delivered")
	}
}

func TestValidatePayload_FailureMidAssessmentPassesThroughWhenConfigured(t *testing.T) {
	client := &scriptedBedrockClient{replies: []scriptedReply{
		{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}},
		{err: errors.New("bedrock unavailable")},
	}}
	p := policyWith(client)

	body, err := json.Marshal(map[string]string{"msg": sentences(30000)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result := p.validatePayload(body, AWSBedrockGuardrailPolicyParams{
		JsonPath: "$.msg", PassthroughOnError: true,
	}, true, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mod.StatusCode != nil {
		t.Fatalf("passthroughOnError should deliver the body, got status %d", *mod.StatusCode)
	}
}

// A value reported in one chunk is masked everywhere it appears, including in
// the chunks whose own assessment did not report it.
func TestValidatePayload_MaskingIsAppliedAcrossEveryChunk(t *testing.T) {
	const email = "alice@example.com"
	client := &scriptedBedrockClient{replies: []scriptedReply{
		{output: makePIIIntervenedOutput(email)},
		{output: &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}},
	}}
	p := policyWith(client)

	// The address appears at both ends of a body large enough to need two calls.
	text := email + " " + sentences(30000) + " " + email
	body, err := json.Marshal(map[string]string{"msg": text})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result := p.validatePayload(body, AWSBedrockGuardrailPolicyParams{JsonPath: "$.msg"},
		true, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mod.Body == nil {
		t.Fatalf("expected the masked body to be returned")
	}
	if strings.Contains(string(mod.Body), email) {
		t.Fatalf("the reported value survived in a chunk that did not report it")
	}
	if got := strings.Count(string(mod.Body), "{EMAIL}"); got != 2 {
		t.Fatalf("expected both occurrences masked, got %d", got)
	}
}

// A small body must still take exactly one call: chunking is for bodies that
// need it, not an extra round trip for everything else.
func TestValidatePayload_SmallBodyStillTakesOneCall(t *testing.T) {
	client := &scriptedBedrockClient{}
	p := policyWith(client)

	result := p.validatePayload([]byte(`{"msg":"hello"}`),
		AWSBedrockGuardrailPolicyParams{JsonPath: "$.msg"}, true, map[string]interface{}{})
	if _, ok := result.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected the body to pass, got %T", result)
	}
	if len(client.calls) != 1 {
		t.Fatalf("expected exactly 1 ApplyGuardrail call, got %d", len(client.calls))
	}
}
