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

package mcptoolpoisoningguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The model never runs in the gateway. This client sends tool metadata text to
// `POST {endpoint}/classify` on a separately deployed classifier service and
// validates what comes back so strictly that a missing, duplicated, unexpected
// or non-finite score can never be read as a low score.

// classifyPath is appended to the configured endpoint.
const classifyPath = "/classify"

// defaultMaxClassifierResponseBytes bounds how much of an untrusted classifier
// response is read into memory.
const defaultMaxClassifierResponseBytes = 8 << 20

// Capacity retries. The classifier service bounds its own concurrency and sheds
// load with 503 or 429 plus Retry-After rather than queueing. That is a
// transient "come back shortly", not a verdict, so a batch that meets it is
// retried.
//
// The budget is bounded by ATTEMPT COUNT, not by the classification deadline.
// With the default three attempts and the service's Retry-After of one second,
// a batch tolerates roughly two seconds of saturation and then fails, even when
// classificationDeadlineMillis is far longer. That is deliberate: retrying until
// the deadline would multiply load against a classifier that is already
// shedding. The wait is clamped so a missing, unreadable or hostile Retry-After
// cannot park the inspection for the whole deadline.
const (
	minCapacityBackoff = 100 * time.Millisecond
	maxCapacityBackoff = 2 * time.Second
)

// capacityError reports that the classifier refused a batch because it is at
// capacity, together with how long it asked the caller to wait.
type capacityError struct {
	status int
	after  time.Duration
}

func (e *capacityError) Error() string {
	return fmt.Sprintf("classifier is at capacity (status %d)", e.status)
}

// classifyItem is one entry of a classify request. ID is a compact generated
// id ("f0", "f1", ...), never a field path.
type classifyItem struct {
	ID   string
	Text string
}

// classification is the aggregate outcome of classifying every item of one
// tools/list response: scores for every item, or an error — never a partial set.
type classification struct {
	// Scores maps item id to the Tool Poisoning class probability.
	Scores   map[string]float64
	Model    string
	Revision string
	Latency  time.Duration
}

// classifierClient is shared by every concurrent inspection of one policy
// instance. It holds only configuration and a connection-pooling HTTP client,
// both safe for concurrent use; no inspection state lives on it.
type classifierClient struct {
	url              string
	apiKey           string
	limits           SystemParams
	maxResponseBytes int
	http             *http.Client
}

func newClassifierClient(system SystemParams) *classifierClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Never route classifier traffic through an HTTP(S)_PROXY from the
	// gateway's environment: the bearer token would be handed to the proxy.
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = max(4, system.MaxConcurrentBatches*4)

	return &classifierClient{
		url:              system.Endpoint + classifyPath,
		apiKey:           system.APIKey,
		limits:           system,
		maxResponseBytes: defaultMaxClassifierResponseBytes,
		http: &http.Client{
			Transport: transport,
			// Never follow a redirect: it would forward the bearer token to
			// wherever the redirect points. The 3xx is returned as-is and
			// refused as an unexpected status.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// classify scores every item, splitting them into bounded batches that run with
// at most MaxConcurrentBatches in flight. ctx carries the single overall
// classification deadline: every batch, every retry and every retry wait shares
// it, so a slow tail cannot extend total inspection time.
//
// The first failing batch cancels the rest: the result is complete or the error
// is non-nil, because a missing score must never be read as a low score. Every
// goroutine started here has returned before classify does.
func (c *classifierClient) classify(ctx context.Context, items []classifyItem) (classification, error) {
	started := time.Now()
	if len(items) == 0 {
		return classification{Scores: map[string]float64{}}, nil
	}

	batches := splitBatches(items, c.limits.BatchSize, c.limits.MaxBatchBytes)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type batchOutcome struct {
		done     bool
		scores   map[string]float64
		model    string
		revision string
	}
	outcomes := make([]batchOutcome, len(batches))

	var (
		mu       sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		cancel()
	}

	indexes := make(chan int)
	var wg sync.WaitGroup
	for range min(c.limits.MaxConcurrentBatches, len(batches)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range indexes {
				scores, model, revision, err := c.safeClassifyBatch(ctx, batches[index])
				if err != nil {
					fail(err)
					continue
				}
				// Each worker writes only its own index.
				outcomes[index] = batchOutcome{done: true, scores: scores, model: model, revision: revision}
			}
		}()
	}

feed:
	for index := range batches {
		select {
		case indexes <- index:
		case <-ctx.Done():
			break feed
		}
	}
	close(indexes)
	wg.Wait()

	latency := time.Since(started)
	if firstErr != nil {
		return classification{Latency: latency}, firstErr
	}

	result := classification{Scores: make(map[string]float64, len(items)), Latency: latency}
	for _, outcome := range outcomes {
		if !outcome.done {
			return classification{Latency: latency}, deadlineError(ctx.Err(), "classification deadline reached before all batches completed")
		}
		if result.Model == "" {
			result.Model, result.Revision = outcome.model, outcome.revision
		} else if result.Model != outcome.model || result.Revision != outcome.revision {
			// Scores from different model builds are not comparable against a
			// single threshold.
			return classification{Latency: latency}, fmt.Errorf("classifier returned inconsistent model identity across batches")
		}
		for id, score := range outcome.scores {
			result.Scores[id] = score
		}
	}
	if len(result.Scores) != len(items) {
		return classification{Latency: latency}, fmt.Errorf("classifier returned %d scores for %d items", len(result.Scores), len(items))
	}
	return result, nil
}

// deadlineError describes why ctx ended without echoing anything upstream.
func deadlineError(err error, deadlineMessage string) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("classification cancelled")
	}
	return errors.New(deadlineMessage)
}

// safeClassifyBatch runs classifyBatch on a worker goroutine. A panic there
// would not reach the recover in OnResponseBody — it would take the gateway
// down — so it is turned into a batch failure, which fails the inspection
// closed like any other classifier error.
func (c *classifierClient) safeClassifyBatch(ctx context.Context, batch []classifyItem) (scores map[string]float64, model, revision string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			scores, model, revision = nil, "", ""
			err = fmt.Errorf("unexpected %T while classifying a batch", recovered)
		}
	}()
	return c.classifyBatch(ctx, batch)
}

// classifyBatch scores one batch, retrying while the service reports it is at
// capacity. Retries are bounded by attempt count, and every attempt and every
// wait stays inside the shared deadline carried by ctx.
func (c *classifierClient) classifyBatch(ctx context.Context, batch []classifyItem) (map[string]float64, string, string, error) {
	wireItems := make([]any, 0, len(batch))
	for _, item := range batch {
		wireItems = append(wireItems, orderedObject{{"id", item.ID}, {"text", item.Text}})
	}
	payload, err := encodeJSON(orderedObject{{"items", wireItems}})
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to encode classifier request: %w", err)
	}

	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, "", "", deadlineError(err, "classification deadline reached")
		}

		scores, model, revision, err := c.postBatch(ctx, []byte(payload), batch)
		if err == nil {
			return scores, model, revision, nil
		}

		var capacity *capacityError
		if !errors.As(err, &capacity) || attempt >= c.limits.MaxClassifierAttempts {
			return nil, "", "", err
		}

		slog.Debug("MCP Tool Poisoning Guardrail Policy: Classifier at capacity, retrying",
			"attempt", attempt,
			"maxAttempts", c.limits.MaxClassifierAttempts,
			"retryAfter", capacity.after,
			"items", len(batch))

		// A wait that cannot finish before the deadline is not started: it
		// could only end in the same failure, later.
		if deadline, ok := ctx.Deadline(); ok && capacity.after >= time.Until(deadline) {
			return nil, "", "", fmt.Errorf("%w and the classification deadline was reached while waiting", err)
		}
		if waitErr := waitWithin(ctx, capacity.after); waitErr != nil {
			return nil, "", "", fmt.Errorf("%w and the classification was abandoned while waiting: %s",
				err, deadlineError(waitErr, "classification deadline reached"))
		}
	}
}

// waitWithin sleeps for delay unless ctx ends first.
func waitWithin(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// deltaSecondsPattern is Retry-After's delta-seconds form. ASCII digits only.
var deltaSecondsPattern = regexp.MustCompile(`^[+-]?[0-9]+$`)

// retryAfterDelay reads a Retry-After header, which is either delta-seconds or
// an HTTP date, clamped to [minCapacityBackoff, maxCapacityBackoff].
func retryAfterDelay(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return minCapacityBackoff
	}
	if deltaSecondsPattern.MatchString(header) {
		seconds, err := strconv.ParseInt(header, 10, 64)
		if err != nil {
			// Out of int64 range: the sign alone decides which bound applies.
			if strings.HasPrefix(header, "-") {
				return minCapacityBackoff
			}
			return maxCapacityBackoff
		}
		// Bounded before conversion so the Duration cannot overflow.
		seconds = max(min(seconds, 3600), -3600)
		return clampBackoff(time.Duration(seconds) * time.Second)
	}
	if when, err := http.ParseTime(header); err == nil {
		return clampBackoff(time.Until(when))
	}
	return minCapacityBackoff
}

func clampBackoff(delay time.Duration) time.Duration {
	return max(min(delay, maxCapacityBackoff), minCapacityBackoff)
}

// postBatch performs one classify request and validates the response. The
// attempt is bounded by requestTimeout and by the overall deadline in ctx,
// whichever ends first; both also bound reading the response body, so a service
// that trickles its answer cannot hold the inspection open.
func (c *classifierClient) postBatch(ctx context.Context, payload []byte, batch []classifyItem) (map[string]float64, string, string, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.limits.RequestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to build classifier request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, "", "", transportError(ctx, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxResponseBytes)+1))
	if err != nil {
		if isTimeout(err) || attemptCtx.Err() != nil {
			return nil, "", "", fmt.Errorf("classifier request timed out")
		}
		return nil, "", "", fmt.Errorf("failed to read classifier response")
	}
	if len(body) > c.maxResponseBytes {
		return nil, "", "", fmt.Errorf("classifier response is too large")
	}

	if response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusTooManyRequests {
		return nil, "", "", &capacityError{
			status: response.StatusCode,
			after:  retryAfterDelay(response.Header.Get("Retry-After")),
		}
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("classifier returned status %d", response.StatusCode)
	}

	return parseClassifierResponse(body, batch)
}

// transportError describes a failed request without echoing the request, the
// response or the endpoint's credentials (there are none: parseEndpoint
// refuses them).
func transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return deadlineError(ctx.Err(), "classifier request timed out")
	}
	if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("classifier request timed out")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return fmt.Errorf("classifier request failed: connection failed")
	}
	// Only the error's type: some transport errors quote part of what the
	// service sent (a malformed status line, for example), which must not reach
	// the logs unbounded.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return fmt.Errorf("classifier request failed: %T", err)
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// parseClassifierResponse validates one classify response against the batch it
// answers. Messages describe what went wrong without echoing the body.
func parseClassifierResponse(body []byte, batch []classifyItem) (map[string]float64, string, string, error) {
	decoded, _, err := decodeJSON(string(body), false)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode classifier response: %v", err)
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, "", "", fmt.Errorf("failed to decode classifier response: not a JSON object")
	}

	model, err := optionalString(object, "model")
	if err != nil {
		return nil, "", "", err
	}
	revision, err := optionalString(object, "revision")
	if err != nil {
		return nil, "", "", err
	}
	if model == "" {
		return nil, "", "", fmt.Errorf("classifier response is missing the model identifier")
	}
	if revision == "" {
		return nil, "", "", fmt.Errorf("classifier response is missing the model revision")
	}

	var results []any
	switch typed := object["results"].(type) {
	case nil:
	case []any:
		results = typed
	default:
		return nil, "", "", fmt.Errorf("failed to decode classifier response: results is not an array")
	}

	expected := make(map[string]struct{}, len(batch))
	for _, item := range batch {
		expected[item.ID] = struct{}{}
	}

	scores := make(map[string]float64, len(batch))
	for _, rawEntry := range results {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, "", "", fmt.Errorf("failed to decode classifier response: a result is not an object")
		}
		id := ""
		if rawID, present := entry["id"]; present {
			if id, ok = rawID.(string); !ok {
				return nil, "", "", fmt.Errorf("failed to decode classifier response: a result id is not a string")
			}
		}
		if _, known := expected[id]; !known {
			return nil, "", "", fmt.Errorf("classifier returned a score for an unrequested item id")
		}
		if _, duplicate := scores[id]; duplicate {
			return nil, "", "", fmt.Errorf("classifier returned duplicate scores for an item id")
		}
		rawScore := entry["poisoningScore"]
		if rawScore == nil {
			return nil, "", "", fmt.Errorf("classifier returned an item without a poisoningScore")
		}
		literal, ok := rawScore.(json.Number)
		if !ok {
			return nil, "", "", fmt.Errorf("failed to decode classifier response: poisoningScore is not a number")
		}
		score, err := strconv.ParseFloat(string(literal), 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, "", "", fmt.Errorf("failed to decode classifier response: poisoningScore is not a number")
		}
		// NaN fails every ordered comparison, so it is rejected explicitly
		// rather than left to the range check. An overflowing literal such as
		// 1e400 parses to ±Inf and is rejected here too.
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			return nil, "", "", fmt.Errorf("classifier returned a poisoningScore outside [0,1]")
		}
		scores[id] = score
	}

	if len(scores) != len(batch) {
		return nil, "", "", fmt.Errorf("classifier returned %d scores for a batch of %d items", len(scores), len(batch))
	}
	return scores, model, revision, nil
}

func optionalString(object map[string]any, key string) (string, error) {
	switch typed := object[key].(type) {
	case nil:
		return "", nil
	case string:
		return typed, nil
	default:
		return "", fmt.Errorf("failed to decode classifier response: %s is not a string", key)
	}
}

// splitBatches groups items into batches bounded by both a count and a byte
// budget.
//
// The byte budget is what keeps a batch inside the classifier service's own
// per-request total. Counting alone is not enough: batchSize items each just
// under maxFieldBytes is a legal gateway configuration that would still exceed
// the service's limit and come back 413, which the guardrail would have to treat
// as an inspection failure. An item larger than the budget on its own still gets
// its own batch rather than blocking progress. Sizes are UTF-8 bytes.
func splitBatches(items []classifyItem, size, maxBytes int) [][]classifyItem {
	if size < 1 {
		size = 1
	}

	batches := make([][]classifyItem, 0, (len(items)+size-1)/size)
	current := make([]classifyItem, 0, size)
	used := 0

	for _, item := range items {
		cost := len(item.Text) + len(item.ID)
		overCount := len(current) >= size
		overBytes := maxBytes > 0 && used+cost > maxBytes
		if len(current) > 0 && (overCount || overBytes) {
			batches = append(batches, current)
			current = make([]classifyItem, 0, size)
			used = 0
		}
		current = append(current, item)
		used += cost
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}

	return batches
}
