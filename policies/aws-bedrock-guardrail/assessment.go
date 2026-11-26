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
	"log/slog"
	"sort"
	"time"
)

const (
	// maxAssessmentChars is the most text sent in one ApplyGuardrail call on the
	// buffered path: 12 text units, the starting point AWS suggests for long
	// input.
	//
	// It is a ceiling, not a target. Every region publishes its own per-request
	// input quota for each guardrail policy type, and the smallest published
	// value for a content filter is 25 text units. Staying well under that keeps
	// one constant correct in every region without the policy having to know
	// which region it runs in or which filters the guardrail has enabled.
	//
	// A text unit is 1000 characters, and a call is billed by whole text units,
	// so a multiple of 1000 wastes nothing.
	maxAssessmentChars = 12 * 1000

	// maxAssessmentDuration bounds a whole buffered assessment, however many
	// calls it takes.
	//
	// Chunking removes the per-request input limit as a reason to refuse a body,
	// but not the throughput one: a guardrail's text units per second are a
	// separate quota, shared by every request on the account. A body large
	// enough to exceed it would otherwise sit here issuing calls until something
	// further out gave up, with no fault to explain why. Reaching this is
	// treated as a Bedrock call failure, so passthroughOnError governs it like
	// any other.
	maxAssessmentDuration = 30 * time.Second
)

// assessInUnits assesses contents in sequential ApplyGuardrail calls of at most
// maxAssessmentChars and merges the verdicts.
//
// A single call for the whole body is what a buffered response used to do. That
// holds only while the body stays under the region's per-request input quota;
// past it Bedrock refuses the call, and the response is refused with it even
// though nothing is wrong with it.
//
// The merge is deliberate about which way each verdict errs:
//
//   - A violation in any chunk blocks the whole payload, and the chunk's own
//     output is what describes it, so the client is told what was found.
//   - Masking replacements are unioned across chunks. A value reported in one
//     chunk is masked everywhere it appears in the payload, including in chunks
//     whose own assessment did not report it.
//   - A chunk that cannot be assessed stops the loop. passthroughOnError
//     decides what happens then, exactly as it does for a single call, so a
//     payload is never delivered as assessed when part of it was not.
//
// text is the payload's whole assessable text, not the chunk's. partOfRequestValue
// has to see every occurrence of a value to tell a restored request value from new
// content, and a chunk's own text would hide the occurrences outside it.
func (p *AWSBedrockGuardrailPolicy) assessInUnits(
	contents []string,
	params AWSBedrockGuardrailPolicyParams,
	isResponse bool,
	metadata map[string]interface{},
	text string,
	payload []byte,
	restored bool,
) ([]piiReplacement, interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), maxAssessmentDuration)
	defer cancel()

	batches := splitContentsIntoUnits(contents, maxAssessmentChars)
	if len(batches) > 1 {
		slog.Debug("AWSBedrockGuardrail: assessing payload in several calls",
			"calls", len(batches), "chars", len(text), "isResponse", isResponse)
	}

	var (
		replacements []piiReplacement
		seen         = make(map[string]bool)
	)
	for _, batch := range batches {
		if err := ctx.Err(); err != nil {
			slog.Warn("AWSBedrockGuardrail: assessment did not complete within the time allowed",
				"limit", maxAssessmentDuration, "isResponse", isResponse)
			return nil, p.passOrBlock("Error calling AWS Bedrock Guardrail", err, params, isResponse, nil,
				checkFailureFault("Error calling AWS Bedrock Guardrail", isResponse), payload, restored)
		}

		output, stop := p.assessContents(ctx, batch, params, isResponse, payload, restored)
		if stop != nil {
			return nil, stop
		}

		violation, batchReplacements, err := p.decide(output, params, isResponse, metadata, text)
		if err != nil {
			return nil, p.passOrBlock("Error evaluating guardrail response", err, params, isResponse, output,
				checkFailureFault("Error evaluating guardrail response", isResponse), payload, restored)
		}
		if violation {
			slog.Debug("AWSBedrockGuardrail: Violation detected", "isResponse", isResponse)
			return nil, p.buildErrorResponse("Violation of AWS Bedrock Guardrails detected", nil,
				isResponse, params.ShowAssessment, output)
		}

		for _, r := range batchReplacements {
			if seen[r.match] {
				continue
			}
			seen[r.match] = true
			replacements = append(replacements, r)
		}
	}

	// applyPIIReplacements takes the first match that applies at a position, so a
	// longer value has to come before a shorter one it contains. piiReplacements
	// orders each chunk's own list; the merged list has to be ordered again.
	sort.SliceStable(replacements, func(i, j int) bool {
		return len(replacements[i].match) > len(replacements[j].match)
	})
	return replacements, nil
}

// splitContentsIntoUnits groups the extracted segments into the batches to
// assess, each at most maxChars.
//
// A segment is kept whole where it fits, so a call carries complete values
// wherever possible. One longer than a whole batch is split by
// splitTextAtUnits.
func splitContentsIntoUnits(contents []string, maxChars int) [][]string {
	var (
		batches [][]string
		current []string
		size    int
	)
	flush := func() {
		if len(current) > 0 {
			batches = append(batches, current)
			current, size = nil, 0
		}
	}
	for _, content := range contents {
		for _, piece := range splitTextAtUnits(content, maxChars) {
			if size+len(piece) > maxChars {
				flush()
			}
			current = append(current, piece)
			size += len(piece)
		}
	}
	flush()
	if len(batches) == 0 {
		return nil
	}
	return batches
}

// splitTextAtUnits cuts text into pieces of at most maxChars, at the end of a
// sentence where there is one and at a word end otherwise.
//
// Cutting mid-phrase is not a tidiness problem, it is a detection one: "my SSN
// is 123-" and "45-6789" assessed separately may each pass where the whole
// phrase would not. This is the same reason the streaming path trims a batch
// back to a boundary, and it uses the same helpers.
func splitTextAtUnits(text string, maxChars int) []string {
	runes := []rune(text)
	if len(runes) <= maxChars {
		return []string{text}
	}
	var pieces []string
	for len(runes) > maxChars {
		cut := lastSentenceEnd(runes, maxChars, false)
		if cut <= 0 {
			cut = lastWordEnd(runes, maxChars)
		}
		if cut <= 0 {
			// Text with no boundary within reach of the cut: take the whole unit
			// rather than let the remainder grow without bound.
			cut = maxChars
		}
		pieces = append(pieces, string(runes[:cut]))
		runes = runes[cut:]
	}
	if len(runes) > 0 {
		pieces = append(pieces, string(runes))
	}
	return pieces
}
