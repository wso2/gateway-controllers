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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Enforcement actions.
const (
	// ActionFilter removes violating tools from the tools/list result.
	ActionFilter = "filter"
	// ActionBlock replaces the whole response with a JSON-RPC error.
	ActionBlock = "block"
	// ActionFlag preserves the response and only records findings.
	ActionFlag = "flag"
)

// Classifier enforcement modes. These decide whether a model score can remove
// or block a tool, independently of `action`, which decides what happens to a
// tool that does violate the policy.
const (
	// ClassifierFlag records model findings without enforcing on them. The
	// default: live measurement against the bundled model found honest tool
	// metadata scoring above poisoned metadata, so no global threshold
	// separates the two and a model score alone must not remove a tool.
	ClassifierFlag = "flag"
	// ClassifierEnforce makes a score at or above classifierThreshold an
	// enforceable violation. Requires calibration against the catalogue being
	// served.
	ClassifierEnforce = "enforce"
)

// Classifier error behaviours.
const (
	// OnErrorBlock refuses to deliver the response when classification fails.
	OnErrorBlock = "block"
	// OnErrorUseStaticDetectors falls back to static findings when
	// classification fails, provided parsing and static inspection completed.
	OnErrorUseStaticDetectors = "useStaticDetectors"
)

// Static finding severities, ordered low < medium < high.
const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// severityRank orders severities for threshold comparisons.
var severityRank = map[string]int{
	SeverityLow:    1,
	SeverityMedium: 2,
	SeverityHigh:   3,
}

// Defaults for the operational limits exposed as system parameters.
const (
	defaultRequestTimeout         = 5 * time.Second
	defaultClassificationDeadline = 10 * time.Second
	defaultBatchSize              = 16
	// The classifier service bounds its own concurrency per process, not per
	// inspection, and sheds load beyond it. Keeping this below that bound leaves
	// room for a second tools/list to be inspected concurrently instead of one
	// inspection occupying the whole service; capacity retries in the classifier
	// client cover the bursts that still collide.
	defaultMaxConcurrentBatches = 2
	defaultMaxTools             = 200
	// Every string inside a tool entry is inspected, so a tool with a large
	// inputSchema contributes several fields per parameter (the parameter name,
	// its type, its description). The budget is sized for that: exhausting it
	// marks the tool as not fully inspected, which is a violation in the
	// enforcement actions, so it must not be reachable by an honest catalogue.
	defaultMaxFieldsPerTool = 256
	defaultMaxFieldBytes    = 20000
	defaultMaxTotalBytes    = 1000000
	defaultMaxNestingDepth  = 12
	defaultMaxBatchBytes    = 1000000
	defaultMaxResponseBytes = 5000000
	// Capacity retries are bounded by attempt count, NOT by the classification
	// deadline. Three attempts one Retry-After apart tolerate roughly two
	// seconds of saturation; a longer outage fails the inspection and
	// onClassifierError decides. Retrying until the deadline would amplify
	// load against a classifier that is already struggling.
	defaultMaxClassifierAttempts = 3
	// The classifier threshold defaults to a conservative evaluation starting
	// point. It is not a universal safety boundary: model scores must be
	// calibrated against the deployment's real tool catalogue before
	// classifierAction is changed from flag to enforce.
	defaultClassifierThreshold = 0.9
)

// The bundled classifier service's own request limits. The gateway-side maxima
// are held at or below these so that a configuration the gateway accepts cannot
// produce a request the service refuses — a 413 or 422 from the service is an
// inspection failure, which blocks tools/list under the default error handling.
// Raising any of these requires raising the matching TOOL_POISONING_* limit on
// the service first; see the policy documentation.
const (
	serviceMaxItems      = 32      // TOOL_POISONING_MAX_ITEMS
	serviceMaxTextBytes  = 100000  // TOOL_POISONING_MAX_TEXT_BYTES
	serviceMaxTotalBytes = 1000000 // TOOL_POISONING_MAX_TOTAL_BYTES
)

// StaticDetectorConfig controls the gateway-local (model-free) inspection pass.
type StaticDetectorConfig struct {
	// Enabled turns the whole static pass on or off. When off, no static
	// findings are produced and useStaticDetectors has nothing to fall back to.
	Enabled bool
	// MinSeverity is the lowest severity that counts as a policy violation.
	// Findings below it are still recorded but do not remove or block a tool.
	MinSeverity string
	// HiddenCharacters enables the invisible/control character scanners.
	HiddenCharacters bool
	// InjectionPatterns enables the explicit prompt-injection pattern scanners.
	InjectionPatterns bool
}

// canDetect reports whether the static pass can produce a finding at all: the
// pass has to be on and at least one scanner behind it has to be on. A pass
// that cannot detect anything is not a fallback for the classifier.
func (c StaticDetectorConfig) canDetect() bool {
	return c.Enabled && (c.HiddenCharacters || c.InjectionPatterns)
}

// PolicyParams holds the per-route policy parameters.
type PolicyParams struct {
	Action string
	// ClassifierAction decides whether a model detection participates in
	// Action. Flag records it; Enforce lets it remove or block a tool.
	ClassifierAction    string
	ClassifierThreshold float64
	OnClassifierError   string
	ShowAssessment      bool
	Static              StaticDetectorConfig
}

// SystemParams holds the gateway-level parameters: where the classifier service
// lives, how to authenticate to it, and the resource limits applied to a single
// tools/list inspection.
type SystemParams struct {
	Endpoint string
	APIKey   string

	// RequestTimeout bounds a single HTTP call to the classifier service.
	RequestTimeout time.Duration
	// ClassificationDeadline bounds the whole classification stage — every
	// batch for one tools/list response shares this single deadline.
	ClassificationDeadline time.Duration

	BatchSize            int
	MaxConcurrentBatches int
	MaxTools             int
	MaxFieldsPerTool     int
	MaxFieldBytes        int
	MaxTotalBytes        int
	MaxNestingDepth      int
	// MaxBatchBytes bounds the text in one classifier request, so a batch stays
	// inside the service's own per-request total however the other limits are set.
	MaxBatchBytes int
	// MaxResponseBytes bounds the raw tools/list response the guardrail will
	// decode and walk. It is checked before decoding.
	MaxResponseBytes int
	// MaxClassifierAttempts bounds how many times one batch is sent when the
	// classifier reports it is at capacity.
	MaxClassifierAttempts int
}

// String renders the parameters without the API key, so a SystemParams that
// ends up in a log line or an error message (%v, %+v, %s) never carries it.
func (s SystemParams) String() string {
	return fmt.Sprintf("SystemParams{Endpoint:%q APIKey:%s RequestTimeout:%v ClassificationDeadline:%v "+
		"BatchSize:%d MaxConcurrentBatches:%d MaxTools:%d MaxFieldsPerTool:%d MaxFieldBytes:%d "+
		"MaxTotalBytes:%d MaxNestingDepth:%d MaxBatchBytes:%d MaxResponseBytes:%d MaxClassifierAttempts:%d}",
		s.Endpoint, s.redactedAPIKey(), s.RequestTimeout, s.ClassificationDeadline,
		s.BatchSize, s.MaxConcurrentBatches, s.MaxTools, s.MaxFieldsPerTool, s.MaxFieldBytes,
		s.MaxTotalBytes, s.MaxNestingDepth, s.MaxBatchBytes, s.MaxResponseBytes, s.MaxClassifierAttempts)
}

// GoString covers %#v, which does not use String.
func (s SystemParams) GoString() string {
	return s.String()
}

// LogValue covers structured logging, which does not use String.
func (s SystemParams) LogValue() slog.Value {
	return slog.StringValue(s.String())
}

func (s SystemParams) redactedAPIKey() string {
	if s.APIKey == "" {
		return "<empty>"
	}
	return "<set>"
}

// parsePolicyParams reads the per-route parameters. classifierThreshold has a
// default so the policy can be evaluated out of the box, but operators should
// calibrate it against their own catalogue before enforcing model findings.
func parsePolicyParams(params map[string]any) (PolicyParams, error) {
	parsed := PolicyParams{
		Action:              ActionFilter,
		ClassifierAction:    ClassifierFlag,
		ClassifierThreshold: defaultClassifierThreshold,
		OnClassifierError:   OnErrorBlock,
		Static: StaticDetectorConfig{
			Enabled:           true,
			MinSeverity:       SeverityMedium,
			HiddenCharacters:  true,
			InjectionPatterns: true,
		},
	}

	action, err := optionalEnum(params, "action", parsed.Action, ActionFilter, ActionBlock, ActionFlag)
	if err != nil {
		return PolicyParams{}, err
	}
	parsed.Action = action

	classifierAction, err := optionalEnum(params, "classifierAction", parsed.ClassifierAction, ClassifierFlag, ClassifierEnforce)
	if err != nil {
		return PolicyParams{}, err
	}
	parsed.ClassifierAction = classifierAction

	onError, err := optionalEnum(params, "onClassifierError", parsed.OnClassifierError, OnErrorBlock, OnErrorUseStaticDetectors)
	if err != nil {
		return PolicyParams{}, err
	}
	parsed.OnClassifierError = onError

	if thresholdRaw, ok := params["classifierThreshold"]; ok {
		if thresholdRaw == nil {
			return PolicyParams{}, fmt.Errorf("'classifierThreshold' must be a number")
		}
		threshold, err := toFloat64(thresholdRaw)
		if err != nil {
			return PolicyParams{}, fmt.Errorf("'classifierThreshold' must be a number: %w", err)
		}
		// The non-finite check is deliberately repeated here even though toFloat64
		// already rejects NaN and the infinities. Every comparison against NaN is
		// false, so a NaN threshold would not fail the range check below and would
		// then silently disable classifier enforcement for every score — exactly the
		// failure this guardrail must not have. The check stays local to the
		// security-relevant comparison so a change to toFloat64 cannot reintroduce it.
		if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 || threshold > 1 {
			return PolicyParams{}, fmt.Errorf("'classifierThreshold' must be a finite number between 0 and 1")
		}
		parsed.ClassifierThreshold = threshold
	}

	showAssessment, err := optionalBool(params, "showAssessment", false)
	if err != nil {
		return PolicyParams{}, err
	}
	parsed.ShowAssessment = showAssessment

	staticConfig, err := parseStaticDetectorConfig(params)
	if err != nil {
		return PolicyParams{}, err
	}
	parsed.Static = staticConfig

	// onClassifierError=useStaticDetectors falls back to the static pass, so
	// there has to be a static pass to fall back to. Enabled on its own is not
	// enough: with both scanners off the pass runs and finds nothing, and a
	// classifier failure would then deliver every tool uninspected under a
	// setting chosen to prevent exactly that. Fail the deployment instead.
	if parsed.OnClassifierError == OnErrorUseStaticDetectors && !staticConfig.canDetect() {
		return PolicyParams{}, fmt.Errorf(
			"'onClassifierError' %s requires 'staticDetectors.enabled' with at least one of 'hiddenCharacters' or 'injectionPatterns'",
			OnErrorUseStaticDetectors)
	}

	return parsed, nil
}

func parseStaticDetectorConfig(params map[string]any) (StaticDetectorConfig, error) {
	config := StaticDetectorConfig{
		Enabled:           true,
		MinSeverity:       SeverityMedium,
		HiddenCharacters:  true,
		InjectionPatterns: true,
	}

	raw, ok := params["staticDetectors"]
	if !ok || raw == nil {
		return config, nil
	}

	entry, ok := raw.(map[string]any)
	if !ok {
		return StaticDetectorConfig{}, fmt.Errorf("'staticDetectors' must be an object")
	}

	enabled, err := optionalBool(entry, "enabled", config.Enabled)
	if err != nil {
		return StaticDetectorConfig{}, fmt.Errorf("staticDetectors.%w", err)
	}
	config.Enabled = enabled

	severity, err := optionalEnum(entry, "severity", config.MinSeverity, SeverityLow, SeverityMedium, SeverityHigh)
	if err != nil {
		return StaticDetectorConfig{}, fmt.Errorf("staticDetectors.%w", err)
	}
	config.MinSeverity = severity

	hiddenCharacters, err := optionalBool(entry, "hiddenCharacters", config.HiddenCharacters)
	if err != nil {
		return StaticDetectorConfig{}, fmt.Errorf("staticDetectors.%w", err)
	}
	config.HiddenCharacters = hiddenCharacters

	injectionPatterns, err := optionalBool(entry, "injectionPatterns", config.InjectionPatterns)
	if err != nil {
		return StaticDetectorConfig{}, fmt.Errorf("staticDetectors.%w", err)
	}
	config.InjectionPatterns = injectionPatterns

	return config, nil
}

// parseSystemParams reads the gateway-level parameters and their limits.
func parseSystemParams(params map[string]any) (SystemParams, error) {
	endpoint, err := parseEndpoint(params["endpoint"])
	if err != nil {
		return SystemParams{}, err
	}

	apiKey := ""
	if raw, ok := params["apiKey"]; ok && raw != nil {
		value, ok := raw.(string)
		if !ok {
			return SystemParams{}, fmt.Errorf("'apiKey' must be a string")
		}
		apiKey = strings.TrimSpace(value)
	}
	if strings.ContainsAny(apiKey, "\r\n\x00") {
		// It would otherwise be written into an HTTP header verbatim.
		return SystemParams{}, fmt.Errorf("'apiKey' must not contain line breaks or NUL characters")
	}

	requestTimeoutMillis, err := optionalInt(params, "requestTimeoutMillis", int(defaultRequestTimeout/time.Millisecond), 100, 120000)
	if err != nil {
		return SystemParams{}, err
	}
	deadlineMillis, err := optionalInt(params, "classificationDeadlineMillis", int(defaultClassificationDeadline/time.Millisecond), 100, 300000)
	if err != nil {
		return SystemParams{}, err
	}
	batchSize, err := optionalInt(params, "batchSize", defaultBatchSize, 1, serviceMaxItems)
	if err != nil {
		return SystemParams{}, err
	}
	maxConcurrentBatches, err := optionalInt(params, "maxConcurrentBatches", defaultMaxConcurrentBatches, 1, 16)
	if err != nil {
		return SystemParams{}, err
	}
	maxTools, err := optionalInt(params, "maxTools", defaultMaxTools, 1, 2000)
	if err != nil {
		return SystemParams{}, err
	}
	maxFieldsPerTool, err := optionalInt(params, "maxFieldsPerTool", defaultMaxFieldsPerTool, 1, 512)
	if err != nil {
		return SystemParams{}, err
	}
	maxFieldBytes, err := optionalInt(params, "maxFieldBytes", defaultMaxFieldBytes, 256, serviceMaxTextBytes)
	if err != nil {
		return SystemParams{}, err
	}
	maxTotalBytes, err := optionalInt(params, "maxTotalBytes", defaultMaxTotalBytes, 1024, 20000000)
	if err != nil {
		return SystemParams{}, err
	}
	maxNestingDepth, err := optionalInt(params, "maxNestingDepth", defaultMaxNestingDepth, 1, 64)
	if err != nil {
		return SystemParams{}, err
	}
	maxBatchBytes, err := optionalInt(params, "maxBatchBytes", defaultMaxBatchBytes, 1024, serviceMaxTotalBytes)
	if err != nil {
		return SystemParams{}, err
	}
	maxResponseBytes, err := optionalInt(params, "maxResponseBytes", defaultMaxResponseBytes, 1024, 50000000)
	if err != nil {
		return SystemParams{}, err
	}
	maxClassifierAttempts, err := optionalInt(params, "maxClassifierAttempts", defaultMaxClassifierAttempts, 1, 10)
	if err != nil {
		return SystemParams{}, err
	}

	// A field that cannot fit in a batch would be sent alone and refused by the
	// service, turning an ordinary tool into an inspection failure.
	if maxFieldBytes > maxBatchBytes {
		return SystemParams{}, fmt.Errorf("'maxFieldBytes' (%d) must not exceed 'maxBatchBytes' (%d)", maxFieldBytes, maxBatchBytes)
	}

	return SystemParams{
		Endpoint:               endpoint,
		APIKey:                 apiKey,
		RequestTimeout:         time.Duration(requestTimeoutMillis) * time.Millisecond,
		ClassificationDeadline: time.Duration(deadlineMillis) * time.Millisecond,
		BatchSize:              batchSize,
		MaxConcurrentBatches:   maxConcurrentBatches,
		MaxTools:               maxTools,
		MaxFieldsPerTool:       maxFieldsPerTool,
		MaxFieldBytes:          maxFieldBytes,
		MaxTotalBytes:          maxTotalBytes,
		MaxNestingDepth:        maxNestingDepth,
		MaxBatchBytes:          maxBatchBytes,
		MaxResponseBytes:       maxResponseBytes,
		MaxClassifierAttempts:  maxClassifierAttempts,
	}, nil
}

// parseEndpoint validates the classifier base URL. The bearer token is sent to
// whatever this names, so anything ambiguous is refused rather than repaired.
func parseEndpoint(raw any) (string, error) {
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("'endpoint' is required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(value), "/")
	lower := strings.ToLower(endpoint)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", fmt.Errorf("'endpoint' must be an http or https URL")
	}
	for _, r := range endpoint {
		if unicode.IsSpace(r) || r < 0x20 || r == 0x7F {
			return "", fmt.Errorf("'endpoint' must not contain whitespace or control characters")
		}
	}
	if strings.ContainsAny(endpoint, "?#") {
		return "", fmt.Errorf("'endpoint' must not contain a query or fragment")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("'endpoint' must be a valid http or https URL")
	}
	if port := parsed.Port(); port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 0 || number > 65535 {
			return "", fmt.Errorf("'endpoint' must be a valid http or https URL")
		}
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("'endpoint' must include a host")
	}
	if parsed.User != nil {
		// Credentials in the URL would end up in logs and error messages; the
		// bearer token belongs in apiKey.
		return "", fmt.Errorf("'endpoint' must not contain credentials; use 'apiKey'")
	}
	return endpoint, nil
}

// meetsSeverity reports whether finding severity reaches the configured minimum.
// An unknown minimum is never met, so a bad value cannot turn every finding
// into a violation or none of them.
func meetsSeverity(finding, minimum string) bool {
	required, known := severityRank[minimum]
	if !known {
		return false
	}
	return severityRank[finding] >= required
}

func optionalEnum(params map[string]any, key, fallback string, allowed ...string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return fallback, nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be one of %s", key, strings.Join(allowed, ", "))
	}
	normalized := strings.TrimSpace(value)
	for _, candidate := range allowed {
		if normalized == candidate {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("'%s' must be one of %s", key, strings.Join(allowed, ", "))
}

func optionalBool(params map[string]any, key string, fallback bool) (bool, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return fallback, nil
	}
	switch value := raw.(type) {
	case bool:
		return value, nil
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return false, fmt.Errorf("'%s' must be a boolean", key)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
}

func optionalInt(params map[string]any, key string, fallback, minimum, maximum int) (int, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return fallback, nil
	}
	value, err := toFloat64(raw)
	if err != nil {
		return 0, fmt.Errorf("'%s' must be an integer: %w", key, err)
	}
	// Parameters can arrive as doubles (5000 as 5000.0), which must be
	// accepted, while 2.5 must not be silently truncated. The range is checked
	// on the float, before conversion, so a huge value cannot wrap.
	if math.Trunc(value) != value {
		return 0, fmt.Errorf("'%s' must be an integer", key)
	}
	if value < float64(minimum) || value > float64(maximum) {
		return 0, fmt.Errorf("'%s' must be between %d and %d", key, minimum, maximum)
	}
	return int(value), nil
}

// decimalNumberPattern is a plain decimal number. It deliberately excludes
// "NaN", "Inf", "Infinity", hexadecimal floats ("0x1p-1") and underscore
// separators, all of which strconv.ParseFloat accepts.
var decimalNumberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// toFloat64 converts a configuration value to a finite number.
//
// Values arrive as strings when the control plane delivers scalars as strings.
// Every result is checked for finiteness: a non-finite limit or threshold
// compares false against everything and would quietly neutralise the check it
// configures. "1e400" is a valid decimal that overflows to infinity, so the
// finiteness check is needed even with the pattern.
func toFloat64(value any) (float64, error) {
	var parsed float64

	switch typed := value.(type) {
	case float64:
		parsed = typed
	case float32:
		parsed = float64(typed)
	case int:
		parsed = float64(typed)
	case int8:
		parsed = float64(typed)
	case int16:
		parsed = float64(typed)
	case int32:
		parsed = float64(typed)
	case int64:
		parsed = float64(typed)
	case uint:
		parsed = float64(typed)
	case uint8:
		parsed = float64(typed)
	case uint16:
		parsed = float64(typed)
	case uint32:
		parsed = float64(typed)
	case uint64:
		parsed = float64(typed)
	case json.Number:
		number, err := parseDecimal(string(typed))
		if err != nil {
			return 0, err
		}
		parsed = number
	case string:
		number, err := parseDecimal(strings.TrimSpace(typed))
		if err != nil {
			return 0, err
		}
		parsed = number
	default:
		// bool included: true must not become 1.
		return 0, fmt.Errorf("cannot convert %T to a number", value)
	}

	if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, fmt.Errorf("value is not a finite number")
	}
	return parsed, nil
}

func parseDecimal(text string) (float64, error) {
	if !decimalNumberPattern.MatchString(text) {
		return 0, fmt.Errorf("value is not a finite decimal number")
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("value is not a finite decimal number")
	}
	// An out-of-range literal parses to ±Inf and is refused by the caller's
	// finiteness check; an underflow parses to zero, which is what it is.
	return number, nil
}
