/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * Licensed under the Apache License, Version 2.0.
 */

package contextbasedrouting

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func testParams() map[string]interface{} {
	return map[string]interface{}{
		"charsPerToken": float64(1),
		"modelMappings": []interface{}{
			map[string]interface{}{
				"name":      "small",
				"maxTokens": float64(14),
				"model": map[string]interface{}{
					"modelName": "small-model",
				},
			},
			map[string]interface{}{
				"name":      "large",
				"minTokens": float64(14),
				"maxTokens": float64(1000),
				"model": map[string]interface{}{
					"modelName":    "large-model",
					"providerName": "provider-b",
				},
			},
		},
		"fallback": map[string]interface{}{
			"modelName":    "fallback-model",
			"providerName": "provider-c",
		},
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}
}

func requestContext(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Content: []byte(body)},
		Path:          "/v1/chat/completions",
	}
}

func TestProcessingModeBuffersOnlyRequestBody(t *testing.T) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	mode := raw.(*ContextBasedRoutingPolicy).Mode()
	if mode.RequestBodyMode != policy.BodyModeBuffer ||
		mode.ResponseHeaderMode != policy.HeaderModeSkip ||
		mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("context routing must process only the request body: %#v", mode)
	}
}

func TestBodyRequestModelLocationIsNormalizedToPayload(t *testing.T) {
	params := testParams()
	params["requestModel"] = map[string]interface{}{
		"location":   "body",
		"identifier": "$.model",
	}

	parsed, err := parseConfig(params)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RequestModel.Location != "payload" {
		t.Fatalf("request model location = %q, want payload", parsed.RequestModel.Location)
	}
}

func TestRoutesByEstimatedInputTokens(t *testing.T) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*ContextBasedRoutingPolicy)

	tests := []struct {
		name            string
		content         string
		wantModel       string
		wantProvider    string
		wantInputTokens int64
	}{
		{name: "below boundary", content: "123456789", wantModel: "small-model", wantInputTokens: 13},
		{name: "boundary is inclusive for next range", content: "1234567890", wantModel: "large-model", wantProvider: "provider-b", wantInputTokens: 14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := requestContext(`{"model":"client-model","messages":[{"role":"user","content":"` + tt.content + `"}]}`)
			action := p.OnRequestBody(context.Background(), ctx, nil)
			mods, ok := action.(policy.UpstreamRequestModifications)
			if !ok {
				t.Fatalf("expected modifications, got %T", action)
			}
			var payload map[string]interface{}
			if err := json.Unmarshal(mods.Body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["model"] != tt.wantModel {
				t.Fatalf("model = %v, want %s", payload["model"], tt.wantModel)
			}
			if tt.wantProvider == "" {
				if mods.UpstreamName != nil {
					t.Fatalf("unexpected upstream %q", *mods.UpstreamName)
				}
			} else if mods.UpstreamName == nil || *mods.UpstreamName != tt.wantProvider {
				t.Fatalf("upstream = %v, want %s", mods.UpstreamName, tt.wantProvider)
			}
			if got := ctx.Metadata[metadataInputTokens]; got != tt.wantInputTokens {
				t.Fatalf("input tokens = %v, want %d", got, tt.wantInputTokens)
			}
		})
	}
}

func TestMalformedJSONIsRejected(t *testing.T) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	action := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), requestContext(`{"model":`), nil)
	response, ok := action.(policy.ImmediateResponse)
	if !ok || response.StatusCode != 400 {
		t.Fatalf("expected 400 response, got %#v", action)
	}
}

func TestUnsupportedInputUsesFallback(t *testing.T) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model","temperature":0.5}`)
	action := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
	mods := action.(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "fallback-model" || mods.UpstreamName == nil || *mods.UpstreamName != "provider-c" {
		t.Fatalf("fallback was not applied: payload=%v upstream=%v", payload, mods.UpstreamName)
	}
}

func TestUnsupportedInputWithoutFallbackPreservesRequest(t *testing.T) {
	params := testParams()
	delete(params, "fallback")
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model","temperature":0.5}`)
	action := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
	mods := action.(policy.UpstreamRequestModifications)
	if mods.Body != nil || mods.UpstreamName != nil {
		t.Fatalf("request should be unchanged: %#v", mods)
	}
}

func TestNoMatchUsesFallbackOrPreservesOriginal(t *testing.T) {
	params := testParams()
	params["modelMappings"] = []interface{}{
		map[string]interface{}{
			"minTokens": float64(100),
			"maxTokens": float64(200),
			"model":     map[string]interface{}{"modelName": "huge-model"},
		},
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model","prompt":"short"}`)
	mods := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	_ = json.Unmarshal(mods.Body, &payload)
	if payload["model"] != "fallback-model" {
		t.Fatalf("expected fallback model, got %v", payload["model"])
	}

	delete(params, "fallback")
	raw, err = GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	mods = raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), requestContext(`{"model":"client-model","prompt":"short"}`), nil).(policy.UpstreamRequestModifications)
	if mods.Body != nil || mods.UpstreamName != nil {
		t.Fatalf("expected unchanged request, got %#v", mods)
	}
}

func TestRejectsOverlappingRanges(t *testing.T) {
	params := testParams()
	params["modelMappings"] = []interface{}{
		map[string]interface{}{
			"maxTokens": float64(20),
			"model":     map[string]interface{}{"modelName": "a"},
		},
		map[string]interface{}{
			"minTokens": float64(10),
			"maxTokens": float64(30),
			"model":     map[string]interface{}{"modelName": "b"},
		},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected overlapping range error")
	}
}

func TestEstimatorCountsOnlySelectedInput(t *testing.T) {
	payload := map[string]interface{}{
		"model": "this-model-name-is-not-input",
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "hello"},
		},
	}
	tokens, err := estimateInputTokens(payload, 4, defaultInputJSONPaths)
	if err != nil {
		t.Fatal(err)
	}
	// "user" + "hello" = 9 characters, rounded up to 3 tokens.
	if tokens != 3 {
		t.Fatalf("tokens = %d, want 3", tokens)
	}
}

func TestRewritesEveryRequestModelLocation(t *testing.T) {
	tests := []struct {
		name       string
		location   string
		identifier string
		path       string
		assert     func(*testing.T, policy.UpstreamRequestModifications)
	}{
		{
			name: "header", location: "header", identifier: "x-model", path: "/invoke",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.HeadersToSet["x-model"] != "small-model" {
					t.Fatalf("headers = %#v", mods.HeadersToSet)
				}
			},
		},
		{
			name: "query parameter", location: "queryParam", identifier: "model", path: "/invoke?model=client&x=1",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/invoke?model=small-model&x=1" {
					t.Fatalf("path = %v", mods.Path)
				}
			},
		},
		{
			name: "capture-group path", location: "pathParam", identifier: `model/([A-Za-z0-9.:-]+)/`, path: "/model/client-model/invoke",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/model/small-model/invoke" {
					t.Fatalf("path = %v", mods.Path)
				}
			},
		},
		{
			name: "Gemini lookbehind path", location: "pathParam", identifier: `(?<=models/)[a-zA-Z0-9.\-]+`, path: "/v1beta/models/gemini-old:generateContent",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/v1beta/models/small-model:generateContent" {
					t.Fatalf("path = %v", mods.Path)
				}
			},
		},
		{
			name: "whole-match path", location: "pathParam", identifier: `client-model`, path: "/models/client-model/invoke",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/models/small-model/invoke" {
					t.Fatalf("path = %v", mods.Path)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := testParams()
			params["requestModel"] = map[string]interface{}{
				"location": tt.location, "identifier": tt.identifier,
			}
			raw, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err != nil {
				t.Fatal(err)
			}
			ctx := requestContext(`{"model":"client-model","prompt":"short"}`)
			ctx.Path = tt.path
			action := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
			mods, ok := action.(policy.UpstreamRequestModifications)
			if !ok {
				t.Fatalf("expected modifications, got %#v", action)
			}
			tt.assert(t, mods)
		})
	}
}

func TestQueryRewriteFailureDoesNotPublishRoutingMetadata(t *testing.T) {
	params := testParams()
	params["requestModel"] = map[string]interface{}{
		"location": "queryParam", "identifier": "model",
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model","prompt":"short"}`)
	ctx.Path = "/invoke?model=%zz"
	action := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
	response, ok := action.(policy.ImmediateResponse)
	if !ok || response.StatusCode != 400 {
		t.Fatalf("expected 400 response, got %#v", action)
	}
	if _, exists := ctx.Metadata[metadataSelectedModel]; exists {
		t.Fatalf("routing metadata must not be published after rewrite failure: %#v", ctx.Metadata)
	}
}

func TestPathExpressionIsValidatedAtPolicyCreation(t *testing.T) {
	params := testParams()
	params["requestModel"] = map[string]interface{}{
		"location": "pathParam", "identifier": "([",
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil || !strings.Contains(err.Error(), "valid model path expression") {
		t.Fatalf("expected path expression validation error, got %v", err)
	}
}

func TestEmbeddedBase64DataIsNotCountedAsText(t *testing.T) {
	dataURL := "data:image/png;base64," + strings.Repeat("A", 10000)
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "hello"},
					map[string]interface{}{"type": "image_url", "image_url": map[string]interface{}{"url": dataURL}},
				},
			},
		},
	}
	tokens, err := estimateInputTokens(payload, 1, defaultInputJSONPaths)
	if err != nil {
		t.Fatal(err)
	}
	if tokens >= 10000 {
		t.Fatalf("embedded binary data was counted as text: %d", tokens)
	}
}

func TestCustomInputJSONPaths(t *testing.T) {
	params := testParams()
	params["inputJSONPaths"] = []interface{}{"$.request.turns.*.text"}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model","request":{"turns":[{"text":"hello"},{"text":"world"}]},"ignored":"do not count"}`)
	action := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected modifications, got %#v", action)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "small-model" {
		t.Fatalf("custom input JSONPath did not participate in routing: %#v", payload)
	}
	if got := ctx.Metadata[metadataInputTokens]; got != int64(10) {
		t.Fatalf("input tokens = %v, want 10", got)
	}
}

func TestMaxTokensIsRequiredAndMissingMinStartsAtZero(t *testing.T) {
	params := testParams()
	params["modelMappings"] = []interface{}{
		map[string]interface{}{
			"maxTokens": float64(20),
			"model":     map[string]interface{}{"modelName": "under-limit"},
		},
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("max-only route should be valid: %v", err)
	}
	ctx := requestContext(`{"model":"client-model","prompt":"short"}`)
	mods := raw.(*ContextBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "under-limit" {
		t.Fatalf("missing minTokens should cover input from zero: %#v", payload)
	}

	params["modelMappings"] = []interface{}{
		map[string]interface{}{
			"minTokens": float64(20),
			"model":     map[string]interface{}{"modelName": "missing-max"},
		},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil || !strings.Contains(err.Error(), "maxTokens' is required") {
		t.Fatalf("expected required maxTokens error, got %v", err)
	}
}
