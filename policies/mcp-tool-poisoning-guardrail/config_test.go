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
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestParsePolicyParamsDefaults(t *testing.T) {
	parsed, err := parsePolicyParams(map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.Action != ActionFilter {
		t.Fatalf("action = %q, want %q", parsed.Action, ActionFilter)
	}
	if parsed.OnClassifierError != OnErrorBlock {
		t.Fatalf("onClassifierError = %q, want %q", parsed.OnClassifierError, OnErrorBlock)
	}
	if parsed.ShowAssessment {
		t.Fatalf("showAssessment should default to false")
	}
	if parsed.ClassifierThreshold != defaultClassifierThreshold {
		t.Fatalf("threshold = %v, want %v", parsed.ClassifierThreshold, defaultClassifierThreshold)
	}
	if !parsed.Static.Enabled || !parsed.Static.HiddenCharacters || !parsed.Static.InjectionPatterns {
		t.Fatalf("static detectors should default to fully enabled: %+v", parsed.Static)
	}
	if parsed.Static.MinSeverity != SeverityMedium {
		t.Fatalf("static severity = %q, want %q", parsed.Static.MinSeverity, SeverityMedium)
	}
}

func TestParsePolicyParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]any
		wantErr string
	}{
		{
			name:    "explicit null threshold is still missing",
			params:  map[string]any{"classifierThreshold": nil},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "threshold must be numeric",
			params:  map[string]any{"classifierThreshold": "high"},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "threshold above one is rejected",
			params:  map[string]any{"classifierThreshold": 1.2},
			wantErr: "'classifierThreshold' must be a finite number between 0 and 1",
		},
		{
			name:    "threshold below zero is rejected",
			params:  map[string]any{"classifierThreshold": -0.1},
			wantErr: "'classifierThreshold' must be a finite number between 0 and 1",
		},
		// A non-finite threshold compares false against every score, so it would
		// be accepted by a plain range check and would then silently disable
		// classifier enforcement entirely. It must be refused at configuration
		// time, in every encoding the control plane can deliver it in.
		{
			name:    "NaN threshold is rejected",
			params:  map[string]any{"classifierThreshold": math.NaN()},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "string NaN threshold is rejected",
			params:  map[string]any{"classifierThreshold": "NaN"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "json.Number NaN threshold is rejected",
			params:  map[string]any{"classifierThreshold": json.Number("NaN")},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "positive infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": math.Inf(1)},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "negative infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": math.Inf(-1)},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "string infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": "+Inf"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "string negative infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": "-Inf"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "lower-case nan threshold is rejected",
			params:  map[string]any{"classifierThreshold": "nan"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "spelled-out infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": "infinity"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "capitalised Infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": "Infinity"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "json.Number infinity threshold is rejected",
			params:  map[string]any{"classifierThreshold": json.Number("+Inf")},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "overflowing decimal threshold is rejected",
			params:  map[string]any{"classifierThreshold": "1e400"},
			wantErr: "'classifierThreshold' must be a",
		},
		{
			name:    "overflowing json.Number threshold is rejected",
			params:  map[string]any{"classifierThreshold": json.Number("1e400")},
			wantErr: "'classifierThreshold' must be a",
		},
		// strconv.ParseFloat accepts these; a configured number must be a plain
		// decimal.
		{
			name:    "hexadecimal float threshold is rejected",
			params:  map[string]any{"classifierThreshold": "0x1p-1"},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "hexadecimal json.Number threshold is rejected",
			params:  map[string]any{"classifierThreshold": json.Number("0x1p-1")},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "underscore separated threshold is rejected",
			params:  map[string]any{"classifierThreshold": "1_0"},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "boolean threshold is rejected",
			params:  map[string]any{"classifierThreshold": true},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "list threshold is rejected",
			params:  map[string]any{"classifierThreshold": []any{0.5}},
			wantErr: "'classifierThreshold' must be a number",
		},
		{
			name:    "non-string action is rejected",
			params:  map[string]any{"classifierThreshold": 0.5, "action": 1},
			wantErr: "'action' must be one of filter, block, flag",
		},
		{
			name:    "numeric static enabled is rejected",
			params:  map[string]any{"classifierThreshold": 0.5, "staticDetectors": map[string]any{"enabled": 1}},
			wantErr: "staticDetectors.'enabled' must be a boolean",
		},
		{
			name:    "unrecognised boolean string is rejected",
			params:  map[string]any{"classifierThreshold": 0.5, "showAssessment": "yes"},
			wantErr: "'showAssessment' must be a boolean",
		},
		{
			name:    "unknown action is rejected",
			params:  map[string]any{"classifierThreshold": 0.5, "action": "quarantine"},
			wantErr: "'action' must be one of filter, block, flag",
		},
		{
			name:    "unknown error mode is rejected",
			params:  map[string]any{"classifierThreshold": 0.5, "onClassifierError": "passthrough"},
			wantErr: "'onClassifierError' must be one of block, useStaticDetectors",
		},
		{
			name:    "static detectors must be an object",
			params:  map[string]any{"classifierThreshold": 0.5, "staticDetectors": true},
			wantErr: "'staticDetectors' must be an object",
		},
		{
			name:    "unknown static severity is rejected",
			params:  map[string]any{"classifierThreshold": 0.5, "staticDetectors": map[string]any{"severity": "critical"}},
			wantErr: "staticDetectors.'severity' must be one of low, medium, high",
		},
		{
			name:    "static enabled must be boolean",
			params:  map[string]any{"classifierThreshold": 0.5, "staticDetectors": map[string]any{"enabled": 3.5}},
			wantErr: "staticDetectors.'enabled' must be a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePolicyParams(tt.params)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParsePolicyParamsAcceptsStringEncodedValues(t *testing.T) {
	// xDS config can deliver scalars as strings; the policy must not reject a
	// configuration that only differs in encoding.
	parsed, err := parsePolicyParams(map[string]any{
		"classifierThreshold": "0.75",
		"showAssessment":      "true",
		"staticDetectors":     map[string]any{"hiddenCharacters": "false"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.ClassifierThreshold != 0.75 {
		t.Fatalf("threshold = %v, want 0.75", parsed.ClassifierThreshold)
	}
	if !parsed.ShowAssessment {
		t.Fatalf("showAssessment = false, want true")
	}
	if parsed.Static.HiddenCharacters {
		t.Fatalf("hiddenCharacters = true, want false")
	}
}

func TestParseSystemParamsDefaults(t *testing.T) {
	parsed, err := parseSystemParams(map[string]any{"endpoint": "http://classifier:8080/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.Endpoint != "http://classifier:8080" {
		t.Fatalf("endpoint = %q, want the trailing slash trimmed", parsed.Endpoint)
	}
	if parsed.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("requestTimeout = %v, want %v", parsed.RequestTimeout, defaultRequestTimeout)
	}
	if parsed.ClassificationDeadline != defaultClassificationDeadline {
		t.Fatalf("classificationDeadline = %v, want %v", parsed.ClassificationDeadline, defaultClassificationDeadline)
	}
	if parsed.BatchSize != defaultBatchSize || parsed.MaxConcurrentBatches != defaultMaxConcurrentBatches {
		t.Fatalf("unexpected batching defaults: %+v", parsed)
	}
}

func TestParseSystemParamsUnits(t *testing.T) {
	parsed, err := parseSystemParams(map[string]any{
		"endpoint":                     "https://classifier.internal",
		"requestTimeoutMillis":         250,
		"classificationDeadlineMillis": 2500,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.RequestTimeout != 250*time.Millisecond {
		t.Fatalf("requestTimeout = %v, want 250ms", parsed.RequestTimeout)
	}
	if parsed.ClassificationDeadline != 2500*time.Millisecond {
		t.Fatalf("classificationDeadline = %v, want 2.5s", parsed.ClassificationDeadline)
	}
}

func TestParseSystemParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]any
		wantErr string
	}{
		{name: "endpoint is required", params: map[string]any{}, wantErr: "'endpoint' is required"},
		{name: "blank endpoint is rejected", params: map[string]any{"endpoint": "   "}, wantErr: "'endpoint' is required"},
		{name: "non-http endpoint is rejected", params: map[string]any{"endpoint": "classifier:8080"}, wantErr: "'endpoint' must be an http or https URL"},
		{name: "apiKey must be a string", params: map[string]any{"endpoint": "http://c", "apiKey": 42}, wantErr: "'apiKey' must be a string"},
		{name: "timeout below the floor is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": 10}, wantErr: "'requestTimeoutMillis' must be between 100 and 120000"},
		{name: "fractional limits are rejected", params: map[string]any{"endpoint": "http://c", "batchSize": 2.5}, wantErr: "'batchSize' must be an integer"},
		// The gateway ceilings are held at the bundled service's own request
		// limits: a configuration the gateway accepts must not produce a request
		// the service refuses, since a 413 or 422 becomes an inspection failure.
		{name: "batch size above the service item limit is rejected", params: map[string]any{"endpoint": "http://c", "batchSize": 500}, wantErr: "'batchSize' must be between 1 and 32"},
		{name: "field bytes above the service text limit is rejected", params: map[string]any{"endpoint": "http://c", "maxFieldBytes": 200000}, wantErr: "'maxFieldBytes' must be between 256 and 100000"},
		{name: "batch bytes above the service total limit is rejected", params: map[string]any{"endpoint": "http://c", "maxBatchBytes": 2000000}, wantErr: "'maxBatchBytes' must be between 1024 and 1000000"},
		{name: "a field that cannot fit in a batch is rejected", params: map[string]any{"endpoint": "http://c", "maxFieldBytes": 50000, "maxBatchBytes": 20000}, wantErr: "'maxFieldBytes' (50000) must not exceed 'maxBatchBytes' (20000)"},
		{name: "concurrency above the ceiling is rejected", params: map[string]any{"endpoint": "http://c", "maxConcurrentBatches": 64}, wantErr: "'maxConcurrentBatches' must be between 1 and 16"},
		{name: "nesting depth of zero is rejected", params: map[string]any{"endpoint": "http://c", "maxNestingDepth": 0}, wantErr: "'maxNestingDepth' must be between 1 and 64"},
		{name: "non-string endpoint is rejected", params: map[string]any{"endpoint": 42}, wantErr: "'endpoint' is required"},
		{name: "ftp endpoint is rejected", params: map[string]any{"endpoint": "ftp://classifier"}, wantErr: "'endpoint' must be an http or https URL"},
		{name: "endpoint without a host is rejected", params: map[string]any{"endpoint": "http:///path"}, wantErr: "'endpoint' must include a host"},
		{name: "bare scheme endpoint is rejected", params: map[string]any{"endpoint": "http://"}, wantErr: "'endpoint' must be an http or https URL"},
		// Credentials in the URL would reach logs and error messages.
		{name: "endpoint credentials are rejected", params: map[string]any{"endpoint": "http://user:pass@classifier"}, wantErr: "'endpoint' must not contain credentials"},
		{name: "endpoint query is rejected", params: map[string]any{"endpoint": "http://classifier/?a=b"}, wantErr: "'endpoint' must not contain a query or fragment"},
		{name: "endpoint fragment is rejected", params: map[string]any{"endpoint": "http://classifier/#frag"}, wantErr: "'endpoint' must not contain a query or fragment"},
		{name: "endpoint port out of range is rejected", params: map[string]any{"endpoint": "http://classifier:99999"}, wantErr: "'endpoint' must be a valid http or https URL"},
		{name: "endpoint whitespace is rejected", params: map[string]any{"endpoint": "http://class ifier"}, wantErr: "'endpoint' must not contain whitespace or control characters"},
		{name: "endpoint control character is rejected", params: map[string]any{"endpoint": "http://classifier\x7f"}, wantErr: "'endpoint' must not contain whitespace or control characters"},
		// It would otherwise be written into an HTTP header verbatim.
		{name: "apiKey header injection is rejected", params: map[string]any{"endpoint": "http://c", "apiKey": "a\r\nX-Injected: 1"}, wantErr: "'apiKey' must not contain line breaks"},
		{name: "apiKey NUL is rejected", params: map[string]any{"endpoint": "http://c", "apiKey": "a\x00b"}, wantErr: "'apiKey' must not contain line breaks"},
		{name: "NaN limit is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": "NaN"}, wantErr: "'requestTimeoutMillis' must be an integer"},
		{name: "float NaN limit is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": math.NaN()}, wantErr: "'requestTimeoutMillis' must be an integer"},
		{name: "infinite limit is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": math.Inf(1)}, wantErr: "'requestTimeoutMillis' must be an integer"},
		{name: "negative infinite limit is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": math.Inf(-1)}, wantErr: "'requestTimeoutMillis' must be an integer"},
		{name: "json.Number NaN limit is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": json.Number("NaN")}, wantErr: "'requestTimeoutMillis' must be an integer"},
		{name: "boolean limit is rejected", params: map[string]any{"endpoint": "http://c", "requestTimeoutMillis": true}, wantErr: "'requestTimeoutMillis' must be an integer"},
		{name: "negative deadline is rejected", params: map[string]any{"endpoint": "http://c", "classificationDeadlineMillis": -1}, wantErr: "'classificationDeadlineMillis' must be between 100 and 300000"},
		{name: "fractional string limits are rejected", params: map[string]any{"endpoint": "http://c", "batchSize": "2.5"}, wantErr: "'batchSize' must be an integer"},
		// A huge float must be refused by the range check, not wrapped by an
		// int conversion into something that passes it.
		{name: "huge float limit is out of range", params: map[string]any{"endpoint": "http://c", "maxTools": 1e300}, wantErr: "'maxTools' must be between 1 and 2000"},
		{name: "attempts of zero are rejected", params: map[string]any{"endpoint": "http://c", "maxClassifierAttempts": 0}, wantErr: "'maxClassifierAttempts' must be between 1 and 10"},
		{name: "attempts above the ceiling are rejected", params: map[string]any{"endpoint": "http://c", "maxClassifierAttempts": 11}, wantErr: "'maxClassifierAttempts' must be between 1 and 10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSystemParams(tt.params)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestGetPolicyRejectsInvalidConfiguration(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{"classifierThreshold": 0.5}); err == nil {
		t.Fatalf("expected a missing-endpoint error")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{"endpoint": "http://c"}); err != nil {
		t.Fatalf("unexpected error when threshold is omitted: %v", err)
	}
}

func TestMeetsSeverity(t *testing.T) {
	tests := []struct {
		finding string
		minimum string
		want    bool
	}{
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityHigh, false},
		{SeverityHigh, SeverityMedium, true},
		{SeverityMedium, SeverityMedium, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityLow, SeverityLow, true},
	}

	for _, tt := range tests {
		if got := meetsSeverity(tt.finding, tt.minimum); got != tt.want {
			t.Fatalf("meetsSeverity(%q, %q) = %v, want %v", tt.finding, tt.minimum, got, tt.want)
		}
	}
}

// definitionLimits reads the integer bounds the policy definition advertises.
// The file is small and regularly indented, so it is scanned rather than given
// a YAML dependency the module otherwise does not need.
func definitionLimits(t *testing.T) map[string]map[string]int {
	t.Helper()

	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatalf("failed to read the policy definition: %v", err)
	}

	limits := make(map[string]map[string]int)
	inSystemParams := false
	current := ""

	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "systemParameters:":
			inSystemParams = true
			continue
		case line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#"):
			inSystemParams = false
		}
		if !inSystemParams {
			continue
		}

		if name, found := strings.CutSuffix(strings.TrimPrefix(line, "    "), ":"); found &&
			strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			current = name
			continue
		}
		if current == "" || !strings.HasPrefix(line, "      ") {
			continue
		}
		for _, attribute := range []string{"default", "minimum", "maximum"} {
			value, found := strings.CutPrefix(strings.TrimSpace(line), attribute+": ")
			if !found {
				continue
			}
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				continue // a non-integer bound, such as the endpoint's minLength
			}
			if limits[current] == nil {
				limits[current] = make(map[string]int)
			}
			limits[current][attribute] = parsed
		}
	}

	if len(limits) == 0 {
		t.Fatalf("no system parameter bounds were read from the policy definition")
	}
	return limits
}

// The definition is what an operator configures against, so a bound that
// disagrees with the code is a bound that does not exist. This matters most for
// the limits held at the bundled classifier service's own request limits: if the
// definition advertised a ceiling the code did not enforce, an accepted
// configuration could still produce requests the service refuses, and every
// tools/list would fail inspection.
func TestPolicyDefinitionBoundsMatchTheCode(t *testing.T) {
	limits := definitionLimits(t)

	defaults, err := parseSystemParams(map[string]any{"endpoint": "http://classifier:8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actual := map[string]int{
		"requestTimeoutMillis":         int(defaults.RequestTimeout.Milliseconds()),
		"classificationDeadlineMillis": int(defaults.ClassificationDeadline.Milliseconds()),
		"batchSize":                    defaults.BatchSize,
		"maxConcurrentBatches":         defaults.MaxConcurrentBatches,
		"maxTools":                     defaults.MaxTools,
		"maxFieldsPerTool":             defaults.MaxFieldsPerTool,
		"maxFieldBytes":                defaults.MaxFieldBytes,
		"maxTotalBytes":                defaults.MaxTotalBytes,
		"maxNestingDepth":              defaults.MaxNestingDepth,
		"maxBatchBytes":                defaults.MaxBatchBytes,
		"maxResponseBytes":             defaults.MaxResponseBytes,
		"maxClassifierAttempts":        defaults.MaxClassifierAttempts,
	}
	if len(limits) != len(actual) {
		t.Errorf("the definition declares %d integer system parameters, the code parses %d", len(limits), len(actual))
	}

	for name, value := range actual {
		bounds, documented := limits[name]
		if !documented {
			t.Fatalf("%q is parsed by the policy but not declared in the policy definition", name)
		}

		if bounds["default"] != value {
			t.Errorf("%s: definition default = %d, code default = %d", name, bounds["default"], value)
		}

		// Probe the code's accepted range against the advertised one.
		for _, probe := range []struct {
			label string
			value int
			valid bool
		}{
			{label: "minimum", value: bounds["minimum"], valid: true},
			{label: "maximum", value: bounds["maximum"], valid: true},
			{label: "below minimum", value: bounds["minimum"] - 1, valid: false},
			{label: "above maximum", value: bounds["maximum"] + 1, valid: false},
		} {
			params := map[string]any{"endpoint": "http://classifier:8080", name: probe.value}
			// maxFieldBytes is additionally required to fit inside maxBatchBytes,
			// so give it room when probing its own range.
			if name == "maxFieldBytes" {
				params["maxBatchBytes"] = limits["maxBatchBytes"]["maximum"]
			}
			if name == "maxBatchBytes" {
				params["maxFieldBytes"] = limits["maxFieldBytes"]["minimum"]
			}

			_, err := parseSystemParams(params)
			if probe.valid && err != nil {
				t.Errorf("%s: definition allows %s %d but the code rejects it: %v", name, probe.label, probe.value, err)
			}
			if !probe.valid && err == nil {
				t.Errorf("%s: code accepts %s %d which the definition forbids", name, probe.label, probe.value)
			}
		}
	}
}

// The gateway-side ceilings exist to stay inside the bundled service's own
// request limits. Stating that relationship as a test keeps the two from
// drifting apart silently: raising one without the other is what turns an
// accepted configuration into a 413 or 422, and then into a blocked tools/list.
func TestGatewayCeilingsStayWithinTheBundledServiceLimits(t *testing.T) {
	limits := definitionLimits(t)

	if got := limits["batchSize"]["maximum"]; got != serviceMaxItems {
		t.Errorf("batchSize ceiling = %d, want the service's item limit %d", got, serviceMaxItems)
	}
	if got := limits["maxFieldBytes"]["maximum"]; got != serviceMaxTextBytes {
		t.Errorf("maxFieldBytes ceiling = %d, want the service's text limit %d", got, serviceMaxTextBytes)
	}
	if got := limits["maxBatchBytes"]["maximum"]; got != serviceMaxTotalBytes {
		t.Errorf("maxBatchBytes ceiling = %d, want the service's total limit %d", got, serviceMaxTotalBytes)
	}

	// The worst batch a maximal configuration can build must still fit.
	system, err := parseSystemParams(map[string]any{
		"endpoint":      "http://classifier:8080",
		"batchSize":     serviceMaxItems,
		"maxFieldBytes": serviceMaxTextBytes,
		"maxBatchBytes": serviceMaxTotalBytes,
	})
	if err != nil {
		t.Fatalf("a configuration at every ceiling must be accepted: %v", err)
	}

	worst := make([]classifyItem, 0, system.BatchSize)
	for i := range system.BatchSize {
		worst = append(worst, classifyItem{ID: "f" + strconv.Itoa(i), Text: strings.Repeat("x", system.MaxFieldBytes)})
	}
	for i, batch := range splitBatches(worst, system.BatchSize, system.MaxBatchBytes) {
		size := 0
		for _, item := range batch {
			size += len(item.Text) + len(item.ID)
		}
		if size > serviceMaxTotalBytes {
			t.Fatalf("batch %d is %d bytes, above the service's per-request total of %d", i, size, serviceMaxTotalBytes)
		}
	}
}

func TestClassifierActionConfiguration(t *testing.T) {
	t.Run("defaults to flag", func(t *testing.T) {
		parsed, err := parsePolicyParams(map[string]any{"classifierThreshold": 0.9})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.ClassifierAction != ClassifierFlag {
			t.Fatalf("classifierAction = %q, want %q", parsed.ClassifierAction, ClassifierFlag)
		}
	})

	for _, value := range []string{ClassifierFlag, ClassifierEnforce} {
		t.Run("accepts "+value, func(t *testing.T) {
			parsed, err := parsePolicyParams(map[string]any{
				"classifierThreshold": 0.9,
				"classifierAction":    value,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.ClassifierAction != value {
				t.Fatalf("classifierAction = %q, want %q", parsed.ClassifierAction, value)
			}
		})
	}

	// An unrecognised value must fail configuration rather than silently
	// falling back — a typo here decides whether the model can remove tools.
	for _, bad := range []any{"enforced", "Enforce", "block", "filter", true, 1} {
		t.Run(fmt.Sprintf("rejects %v", bad), func(t *testing.T) {
			_, err := parsePolicyParams(map[string]any{
				"classifierThreshold": 0.9,
				"classifierAction":    bad,
			})
			if err == nil {
				t.Fatalf("expected %v to be rejected", bad)
			}
			if !strings.Contains(err.Error(), "'classifierAction' must be one of flag, enforce") {
				t.Fatalf("error = %q, want it to name the allowed values", err.Error())
			}
		})
	}
}

func TestMaxClassifierAttemptsConfiguration(t *testing.T) {
	parsed, err := parseSystemParams(map[string]any{"endpoint": "http://c"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.MaxClassifierAttempts != defaultMaxClassifierAttempts {
		t.Fatalf("maxClassifierAttempts = %d, want %d", parsed.MaxClassifierAttempts, defaultMaxClassifierAttempts)
	}
	for _, bad := range []int{0, 11} {
		if _, err := parseSystemParams(map[string]any{"endpoint": "http://c", "maxClassifierAttempts": bad}); err == nil {
			t.Fatalf("expected %d to be rejected", bad)
		}
	}
}

func TestThresholdAcceptsTheClosedUnitInterval(t *testing.T) {
	for _, threshold := range []any{0, 1, 0.0, 1.0, "0", "1", " 0.5 ", ".5", "5e-1", json.Number("0.25"), int64(1)} {
		parsed, err := parsePolicyParams(map[string]any{"classifierThreshold": threshold})
		if err != nil {
			t.Fatalf("threshold %#v: unexpected error: %v", threshold, err)
		}
		if parsed.ClassifierThreshold < 0 || parsed.ClassifierThreshold > 1 {
			t.Fatalf("threshold %#v parsed to %v", threshold, parsed.ClassifierThreshold)
		}
	}
}

func TestStructDoublesAreAcceptedAsIntegers(t *testing.T) {
	// Parameters can arrive as doubles, where 5000 is 5000.0, or as strings.
	parsed, err := parseSystemParams(map[string]any{
		"endpoint":             "http://c",
		"requestTimeoutMillis": 5000.0,
		"batchSize":            "8",
		"maxTools":             "10.0",
		"maxNestingDepth":      json.Number("12"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.RequestTimeout != 5*time.Second || parsed.BatchSize != 8 || parsed.MaxTools != 10 || parsed.MaxNestingDepth != 12 {
		t.Fatalf("unexpected parse: %v", parsed)
	}
}

func TestEndpointAcceptsOrdinaryURLs(t *testing.T) {
	for endpoint, want := range map[string]string{
		"http://classifier:8080/":         "http://classifier:8080",
		"HTTPS://Classifier.internal":     "HTTPS://Classifier.internal",
		"http://10.0.0.5:8080/base/":      "http://10.0.0.5:8080/base",
		"http://[::1]:8080":               "http://[::1]:8080",
		"  http://classifier.svc.local  ": "http://classifier.svc.local",
	} {
		parsed, err := parseSystemParams(map[string]any{"endpoint": endpoint})
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", endpoint, err)
		}
		if parsed.Endpoint != want {
			t.Fatalf("%q parsed to %q, want %q", endpoint, parsed.Endpoint, want)
		}
	}
}

func TestTheAPIKeyNeverAppearsInErrorsOrRenderings(t *testing.T) {
	const secret = "sk-this-must-not-leak"

	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"endpoint": "http://c", "apiKey": secret, "classifierThreshold": "NaN",
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v, want an error without the key", err)
	}

	system, err := parseSystemParams(map[string]any{"endpoint": "http://c", "apiKey": secret})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if system.APIKey != secret {
		t.Fatalf("the key itself must still be kept for the request")
	}
	for _, rendered := range []string{
		fmt.Sprint(system), fmt.Sprintf("%v", system), fmt.Sprintf("%+v", system), fmt.Sprintf("%#v", system),
		fmt.Sprintf("%s", system), system.LogValue().String(),
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("rendering leaked the key: %s", rendered)
		}
	}
	if !strings.Contains(fmt.Sprint(system), "APIKey:<set>") {
		t.Fatalf("rendering should say a key is set: %s", fmt.Sprint(system))
	}
}

func TestGetPolicyRejectsNilParameters(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, nil); err == nil {
		t.Fatalf("expected nil parameters to be rejected")
	}
}

func TestMeetsSeverityRefusesAnUnknownMinimum(t *testing.T) {
	for _, finding := range []string{SeverityLow, SeverityMedium, SeverityHigh, "unknown"} {
		if meetsSeverity(finding, "critical") {
			t.Fatalf("an unknown minimum must never be met (finding %q)", finding)
		}
	}
	if meetsSeverity("unknown", SeverityLow) {
		t.Fatalf("an unknown finding severity must not meet the lowest minimum")
	}
}

func TestEverySystemParameterReadsTheExistingConfigKey(t *testing.T) {
	// The config.toml keys are kept, so an existing deployment does not need to
	// change its configuration.
	expected := map[string]string{
		"endpoint":                     "mcp_tool_poisoning_classifier_endpoint",
		"apiKey":                       "mcp_tool_poisoning_classifier_api_key",
		"requestTimeoutMillis":         "mcp_tool_poisoning_classifier_request_timeout_millis",
		"classificationDeadlineMillis": "mcp_tool_poisoning_classification_deadline_millis",
		"batchSize":                    "mcp_tool_poisoning_batch_size",
		"maxConcurrentBatches":         "mcp_tool_poisoning_max_concurrent_batches",
		"maxTools":                     "mcp_tool_poisoning_max_tools",
		"maxFieldsPerTool":             "mcp_tool_poisoning_max_fields_per_tool",
		"maxFieldBytes":                "mcp_tool_poisoning_max_field_bytes",
		"maxTotalBytes":                "mcp_tool_poisoning_max_total_bytes",
		"maxBatchBytes":                "mcp_tool_poisoning_max_batch_bytes",
		"maxClassifierAttempts":        "mcp_tool_poisoning_max_classifier_attempts",
		"maxResponseBytes":             "mcp_tool_poisoning_max_response_bytes",
		"maxNestingDepth":              "mcp_tool_poisoning_max_nesting_depth",
	}

	blocks := systemParameterBlocks(t)
	if len(blocks) != len(expected) {
		t.Fatalf("the definition declares %d system parameters, want %d", len(blocks), len(expected))
	}
	for name, key := range expected {
		lines, declared := blocks[name]
		if !declared {
			t.Fatalf("system parameter %q is not declared", name)
		}
		want := `"wso2/defaultValue": "${config.` + key + `}"`
		found := false
		for _, line := range lines {
			found = found || line == want
		}
		if !found {
			t.Errorf("%s does not read ${config.%s}", name, key)
		}
	}
}

// systemParameterBlocks returns the trimmed attribute lines of every system
// parameter declared in the policy definition.
func systemParameterBlocks(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatalf("failed to read the policy definition: %v", err)
	}
	blocks := make(map[string][]string)
	inSystem := false
	current := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "systemParameters:" {
			inSystem = true
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			inSystem = false
		}
		if !inSystem {
			continue
		}
		if name, ok := strings.CutSuffix(strings.TrimPrefix(line, "    "), ":"); ok &&
			strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			current = name
			blocks[current] = nil
			continue
		}
		if current != "" && strings.HasPrefix(line, "      ") {
			blocks[current] = append(blocks[current], strings.TrimSpace(line))
		}
	}
	return blocks
}

func TestTheRouteParametersDoNotExposeTheAPIKey(t *testing.T) {
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatalf("failed to read the policy definition: %v", err)
	}
	route, _, _ := strings.Cut(string(raw), "\nsystemParameters:\n")
	if strings.Contains(route, "apiKey") {
		t.Fatalf("the route-level parameters must not expose apiKey")
	}
}

func TestTheDefinitionNamesTheGoPolicyAndTheExternalModel(t *testing.T) {
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatalf("failed to read the policy definition: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"name: mcp-tool-poisoning-guardrail\n",
		"version: v0.9.0\n",
		"Go",
		"POST {endpoint}/classify",
		"mcp-acl-list", "mcp-authz",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the definition does not mention %q", want)
		}
	}
	for _, stale := range []string{"Python policy executor", "pipPackage", "Python executor"} {
		if strings.Contains(text, stale) {
			t.Errorf("the definition still mentions %q", stale)
		}
	}
}

// The gateway policy is a pure Go module and a thin client: it must never pull
// a model runtime into the gateway, and no Python policy runtime may remain
// beside it (the release tooling and the gateway builder classify a policy by
// the files at its root).
func TestThePolicyIsAPureGoModule(t *testing.T) {
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(gomod), "\n") {
		if strings.HasPrefix(line, "require ") && strings.TrimSpace(line) != "require github.com/wso2/api-platform/sdk/core v0.3.4" {
			t.Fatalf("unexpected dependency: %s", line)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "require (") {
			t.Fatalf("go.mod must require only the gateway policy SDK")
		}
	}
	for _, stale := range []string{"pyproject.toml", "requirements.txt", "src", "tests", "setup.py"} {
		if _, err := os.Stat(stale); err == nil {
			t.Fatalf("%s is a Python policy artefact and must not exist beside the Go policy", stale)
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".py") {
			t.Fatalf("%s: no Python source belongs at the policy root", entry.Name())
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		_, imports, _ := strings.Cut(string(source), "import (")
		imports, _, _ = strings.Cut(imports, ")")
		for _, line := range strings.Split(imports, "\n") {
			// An import line is `"path"` or `alias "path"`.
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			path := strings.Trim(fields[len(fields)-1], `"`)
			if path == "" || !strings.Contains(path, ".") {
				continue // standard library
			}
			if path != "github.com/wso2/api-platform/sdk/core/policy/v1alpha2" {
				t.Fatalf("%s imports %s; the policy may import only the standard library and the SDK", entry.Name(), path)
			}
		}
	}
}
