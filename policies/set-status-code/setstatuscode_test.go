/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package setstatuscode

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newResponseContext(statusCode int) *policy.ResponseContext {
	return &policy.ResponseContext{
		ResponseStatus: statusCode,
	}
}

func TestSetStatusCodePolicy_OnResponseBody_Valid(t *testing.T) {
	p := &SetStatusCodePolicy{}

	params := map[string]interface{}{
		"statusCode": 201,
	}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected DownstreamResponseModifications, got %T", result)
	}

	if mods.StatusCode == nil {
		t.Fatal("Expected StatusCode to be set, got nil")
	}

	if *mods.StatusCode != 201 {
		t.Errorf("Expected StatusCode 201, got %d", *mods.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_Float64Param(t *testing.T) {
	p := &SetStatusCodePolicy{}

	// JSON unmarshalling yields float64 for numbers; whole-number floats are accepted
	params := map[string]interface{}{
		"statusCode": float64(404),
	}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected DownstreamResponseModifications, got %T", result)
	}

	if mods.StatusCode == nil || *mods.StatusCode != 404 {
		t.Errorf("Expected StatusCode 404, got %v", mods.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_Float64FractionalParam(t *testing.T) {
	p := &SetStatusCodePolicy{}

	// Fractional float64 should be rejected
	params := map[string]interface{}{
		"statusCode": float64(200.9),
	}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	immediate, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}

	if immediate.StatusCode != 500 {
		t.Errorf("Expected status 500 for fractional float64, got %d", immediate.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_BoundaryMin(t *testing.T) {
	p := &SetStatusCodePolicy{}

	params := map[string]interface{}{"statusCode": 100}
	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected DownstreamResponseModifications, got %T", result)
	}
	if mods.StatusCode == nil || *mods.StatusCode != 100 {
		t.Errorf("Expected StatusCode 100, got %v", mods.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_BoundaryMax(t *testing.T) {
	p := &SetStatusCodePolicy{}

	params := map[string]interface{}{"statusCode": 599}
	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	mods, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected DownstreamResponseModifications, got %T", result)
	}
	if mods.StatusCode == nil || *mods.StatusCode != 599 {
		t.Errorf("Expected StatusCode 599, got %v", mods.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_MissingParam(t *testing.T) {
	p := &SetStatusCodePolicy{}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), map[string]interface{}{})

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}
	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_NilParams(t *testing.T) {
	p := &SetStatusCodePolicy{}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), nil)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}
	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_InvalidType(t *testing.T) {
	p := &SetStatusCodePolicy{}

	params := map[string]interface{}{"statusCode": "200"}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}
	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_BelowRange(t *testing.T) {
	p := &SetStatusCodePolicy{}

	params := map[string]interface{}{"statusCode": 99}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}
	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestSetStatusCodePolicy_OnResponseBody_AboveRange(t *testing.T) {
	p := &SetStatusCodePolicy{}

	params := map[string]interface{}{"statusCode": 600}

	result := p.OnResponseBody(context.Background(), newResponseContext(200), params)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}
	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestSetStatusCodePolicy_Mode(t *testing.T) {
	p := &SetStatusCodePolicy{}
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeSkip {
		t.Errorf("Expected RequestHeaderMode to be HeaderModeSkip, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("Expected RequestBodyMode to be BodyModeSkip, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("Expected ResponseHeaderMode to be HeaderModeSkip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeBuffer {
		t.Errorf("Expected ResponseBodyMode to be BodyModeBuffer, got %v", mode.ResponseBodyMode)
	}
}

func TestSetStatusCodePolicy_GetPolicy(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName:  "test-route",
		APIId:      "test-api-id",
		APIName:    "test-api",
		APIVersion: "v1.0.0",
		AttachedTo: policy.LevelRoute,
	}

	params := map[string]interface{}{"statusCode": 202}

	pol, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Expected no error from GetPolicy, got %v", err)
	}
	if pol == nil {
		t.Fatal("Expected policy instance, got nil")
	}
	if _, ok := pol.(*SetStatusCodePolicy); !ok {
		t.Fatalf("Expected *SetStatusCodePolicy, got %T", pol)
	}
}
