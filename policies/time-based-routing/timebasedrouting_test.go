/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * Licensed under the Apache License, Version 2.0.
 */

package timebasedrouting

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func testParams() map[string]interface{} {
	return map[string]interface{}{
		"timezone": "Asia/Colombo",
		"schedules": []interface{}{
			map[string]interface{}{
				"name": "morning",
				"from": "06:00",
				"to":   "12:00",
				"model": map[string]interface{}{
					"modelName":    "morning-model",
					"providerName": "provider-a",
				},
			},
			map[string]interface{}{
				"name": "evening",
				"from": "18:00",
				"to":   "23:00",
				"model": map[string]interface{}{
					"modelName": "evening-model",
				},
			},
		},
		"fallback": map[string]interface{}{
			"modelName":    "default-model",
			"providerName": "provider-default",
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

func fixedNow(t *testing.T, value string) {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	previous := nowFunc
	nowFunc = func() time.Time { return parsed }
	t.Cleanup(func() { nowFunc = previous })
}

func TestProcessingModeBuffersOnlyRequestBody(t *testing.T) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	mode := raw.(*TimeBasedRoutingPolicy).Mode()
	if mode.RequestBodyMode != policy.BodyModeBuffer ||
		mode.ResponseHeaderMode != policy.HeaderModeSkip ||
		mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("time routing must process only the request body: %#v", mode)
	}
}

func TestRoutesByConfiguredTimezone(t *testing.T) {
	fixedNow(t, "2026-08-30T01:00:00Z") // 06:30 in Asia/Colombo.
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model","messages":[{"role":"user","content":"hello"}]}`)
	action := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected modifications, got %T", action)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "morning-model" {
		t.Fatalf("model = %v, want morning-model", payload["model"])
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "provider-a" {
		t.Fatalf("upstream = %v, want provider-a", mods.UpstreamName)
	}
	if ctx.Metadata[metadataSelectedRoute] != "morning" {
		t.Fatalf("route metadata = %v, want morning", ctx.Metadata[metadataSelectedRoute])
	}
	if ctx.Metadata[metadataProviderRouting] != "provider-a" {
		t.Fatalf("provider routing metadata = %v, want provider-a", ctx.Metadata[metadataProviderRouting])
	}
}

func TestNoMatchUsesDefaultOrPreservesOriginal(t *testing.T) {
	fixedNow(t, "2026-08-30T08:00:00Z") // 13:30 in Asia/Colombo.
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model"}`)
	mods := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "default-model" || mods.UpstreamName == nil || *mods.UpstreamName != "provider-default" {
		t.Fatalf("default was not applied: payload=%v upstream=%v", payload, mods.UpstreamName)
	}

	params := testParams()
	delete(params, "fallback")
	raw, err = GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	mods = raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), requestContext(`{"model":"client-model"}`), nil).(policy.UpstreamRequestModifications)
	if mods.Body != nil || mods.UpstreamName != nil {
		t.Fatalf("expected unchanged request, got %#v", mods)
	}
}

func TestOvernightScheduleMatchesAcrossMidnight(t *testing.T) {
	params := testParams()
	params["schedules"] = []interface{}{
		map[string]interface{}{
			"name": "night",
			"from": "22:00",
			"to":   "06:00",
			"model": map[string]interface{}{
				"modelName": "night-model",
			},
		},
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}

	for _, now := range []string{"2026-08-30T18:00:00Z", "2026-08-30T00:00:00Z"} {
		t.Run(now, func(t *testing.T) {
			fixedNow(t, now)
			ctx := requestContext(`{"model":"client-model"}`)
			mods := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
			var payload map[string]interface{}
			if err := json.Unmarshal(mods.Body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["model"] != "night-model" {
				t.Fatalf("model = %v, want night-model", payload["model"])
			}
		})
	}
}

func TestOvernightScheduleWithDaysUsesStartDay(t *testing.T) {
	params := testParams()
	params["schedules"] = []interface{}{
		map[string]interface{}{
			"name": "saturday-night",
			"from": "22:00",
			"to":   "06:00",
			"days": []interface{}{"Sat"},
			"model": map[string]interface{}{
				"modelName": "saturday-night-model",
			},
		},
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}

	fixedNow(t, "2026-08-29T20:00:00Z") // Sunday 01:30 in Asia/Colombo, from Saturday's window.
	ctx := requestContext(`{"model":"client-model"}`)
	mods := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "saturday-night-model" {
		t.Fatalf("model = %v, want saturday-night-model", payload["model"])
	}

	fixedNow(t, "2026-08-30T20:00:00Z") // Monday 01:30 in Asia/Colombo, not Saturday's window.
	ctx = requestContext(`{"model":"client-model"}`)
	mods = raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "default-model" {
		t.Fatalf("model = %v, want default-model", payload["model"])
	}
}

func TestDaysRestrictSchedule(t *testing.T) {
	params := testParams()
	params["schedules"] = []interface{}{
		map[string]interface{}{
			"name": "weekday",
			"from": "09:00",
			"to":   "17:00",
			"days": []interface{}{"Mon", "Tue", "Wed", "Thu", "Fri"},
			"model": map[string]interface{}{
				"modelName": "weekday-model",
			},
		},
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}

	fixedNow(t, "2026-08-31T05:00:00Z") // Monday 10:30 in Asia/Colombo.
	ctx := requestContext(`{"model":"client-model"}`)
	mods := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "weekday-model" {
		t.Fatalf("model = %v, want weekday-model", payload["model"])
	}

	fixedNow(t, "2026-08-30T05:00:00Z") // Sunday 10:30 in Asia/Colombo.
	ctx = requestContext(`{"model":"client-model"}`)
	mods = raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "default-model" {
		t.Fatalf("model = %v, want default-model", payload["model"])
	}
}

func TestRejectsOverlappingSchedules(t *testing.T) {
	params := testParams()
	params["schedules"] = []interface{}{
		map[string]interface{}{
			"from":  "09:00",
			"to":    "12:00",
			"model": map[string]interface{}{"modelName": "a"},
		},
		map[string]interface{}{
			"from":  "11:00",
			"to":    "13:00",
			"model": map[string]interface{}{"modelName": "b"},
		},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected overlapping schedule error")
	}
}

func TestSameTimesAreRejected(t *testing.T) {
	params := testParams()
	params["schedules"] = []interface{}{
		map[string]interface{}{
			"from":  "09:00",
			"to":    "09:00",
			"model": map[string]interface{}{"modelName": "a"},
		},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil || !strings.Contains(err.Error(), "same from and to") {
		t.Fatalf("expected same time error, got %v", err)
	}
}

func TestRewritesEveryRequestModelLocation(t *testing.T) {
	fixedNow(t, "2026-08-30T01:00:00Z")
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
				if mods.HeadersToSet["x-model"] != "morning-model" {
					t.Fatalf("headers = %#v", mods.HeadersToSet)
				}
			},
		},
		{
			name: "query parameter", location: "queryParam", identifier: "model", path: "/invoke?model=client&x=1",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/invoke?model=morning-model&x=1" {
					t.Fatalf("path = %v", mods.Path)
				}
			},
		},
		{
			name: "capture-group path", location: "pathParam", identifier: `model/([A-Za-z0-9.:-]+)/`, path: "/model/client-model/invoke",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/model/morning-model/invoke" {
					t.Fatalf("path = %v", mods.Path)
				}
			},
		},
		{
			name: "Gemini lookbehind path", location: "pathParam", identifier: `(?<=models/)[a-zA-Z0-9.\-]+`, path: "/v1beta/models/gemini-old:generateContent",
			assert: func(t *testing.T, mods policy.UpstreamRequestModifications) {
				if mods.Path == nil || *mods.Path != "/v1beta/models/morning-model:generateContent" {
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
			action := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
			mods, ok := action.(policy.UpstreamRequestModifications)
			if !ok {
				t.Fatalf("expected modifications, got %#v", action)
			}
			tt.assert(t, mods)
		})
	}
}

func TestQueryRewriteFailureDoesNotPublishRoutingMetadata(t *testing.T) {
	fixedNow(t, "2026-08-30T01:00:00Z")
	params := testParams()
	params["requestModel"] = map[string]interface{}{
		"location": "queryParam", "identifier": "model",
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext(`{"model":"client-model"}`)
	ctx.Path = "/invoke?model=%zz"
	action := raw.(*TimeBasedRoutingPolicy).OnRequestBody(context.Background(), ctx, nil)
	response, ok := action.(policy.ImmediateResponse)
	if !ok || response.StatusCode != 400 {
		t.Fatalf("expected 400 response, got %#v", action)
	}
	if _, exists := ctx.Metadata[metadataSelectedModel]; exists {
		t.Fatalf("routing metadata must not be published after rewrite failure: %#v", ctx.Metadata)
	}
}
