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
	"os"
	"slices"
	"testing"
)

// TestAgainstRealClassifierService drives the policy against a running
// classifier service and the real model. Every other test in this package uses
// a mocked classifier so the suite stays deterministic and needs no model
// download; this one exists to verify the wire contract between the two
// components end to end.
//
// It is skipped unless the endpoint is supplied:
//
//	cd <samples-apim>/apim-ai-deployments/mcp-tool-poisoning-classifier
//	docker compose up --build -d
//	MCP_TOOL_POISONING_ENDPOINT=http://localhost:8101 \
//	MCP_TOOL_POISONING_API_KEY="$TOOL_POISONING_API_KEY" \
//	go test -run TestAgainstRealClassifierService -v ./...
func TestAgainstRealClassifierService(t *testing.T) {
	endpoint := os.Getenv("MCP_TOOL_POISONING_ENDPOINT")
	if endpoint == "" {
		t.Skip("set MCP_TOOL_POISONING_ENDPOINT to run against a live classifier service")
	}

	// Comfortably above the benign cluster the model produces and below the
	// poisoned one. See the classifier service README for the measured spread.
	p := newTestPolicy(t, endpoint, map[string]any{
		"classifierThreshold": 0.9,
		// Explicit: under the shipped default (flag) a model score is recorded
		// but never removes a tool, so this test would prove nothing.
		"classifierAction": ClassifierEnforce,
		// Off, so the verdict comes from the model alone — the static
		// detectors would catch this tool on their own.
		"staticDetectors":              map[string]any{"enabled": false},
		"apiKey":                       os.Getenv("MCP_TOOL_POISONING_API_KEY"),
		"requestTimeoutMillis":         30000,
		"classificationDeadlineMillis": 60000,
	})

	exchange := newExchange(toolsListRequest("1"), toolsListResponse("1", benignTool, poisonedTool))
	result := modifications(t, exchange.run(t, p))

	if result.Body == nil {
		t.Fatalf("the real model did not flag the poisoned tool; scores: see the policy logs")
	}
	if names := toolNames(t, decodeBody(t, result.Body)); !slices.Equal(names, []string{"get_weather"}) {
		t.Fatalf("tools = %v, want only get_weather", names)
	}
	if result.AnalyticsMetadata[analyticsModelKey] != "wso2/tool-poisoning-detection" {
		t.Fatalf("model = %v, want wso2/tool-poisoning-detection", result.AnalyticsMetadata[analyticsModelKey])
	}
	if revision, _ := result.AnalyticsMetadata[analyticsRevisionKey].(string); revision == "" {
		t.Fatalf("the service did not report a model revision")
	}
	t.Logf("model=%v revision=%v latencyMs=%v",
		result.AnalyticsMetadata[analyticsModelKey],
		result.AnalyticsMetadata[analyticsRevisionKey],
		result.AnalyticsMetadata[analyticsLatencyKey])
}
