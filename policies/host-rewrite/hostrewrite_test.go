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

package hostrewrite

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestHostRewritePolicy_OnRequestHeaders_ValidHost(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "new-backend.example.com",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original-host.example.com"},
			"content-type": {"application/json"},
		}),
		Path:   "/api/test",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	// Verify the result is UpstreamRequestHeaderModifications
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	// Verify Host field is set correctly
	if mods.Host == nil {
		t.Fatal("Expected Host to be set, got nil")
	}

	if *mods.Host != "new-backend.example.com" {
		t.Errorf("Expected Host to be 'new-backend.example.com', got '%s'", *mods.Host)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_HostWithDash(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "api-backend-v2.example.com",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original.example.com"},
		}),
		Path:   "/",
		Method: "POST",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if mods.Host == nil || *mods.Host != "api-backend-v2.example.com" {
		t.Errorf("Expected Host to be 'api-backend-v2.example.com', got %v", mods.Host)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_HostWithPort(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "backend.example.com",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"frontend.example.com:8080"},
		}),
		Path:   "/api/users",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if mods.Host == nil || *mods.Host != "backend.example.com" {
		t.Errorf("Expected Host to be 'backend.example.com', got %v", mods.Host)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_MissingHostParam(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original.example.com"},
		}),
		Path:   "/test",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	// Should return ImmediateResponse with error
	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}

	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}

	if immResp.Headers["content-type"] != "application/json" {
		t.Errorf("Expected content-type application/json, got %s", immResp.Headers["content-type"])
	}
}

func TestHostRewritePolicy_OnRequestHeaders_EmptyHostParam(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original.example.com"},
		}),
		Path:   "/test",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}

	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_WhitespaceHostParam(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "   ",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original.example.com"},
		}),
		Path:   "/test",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}

	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_InvalidHostParamType(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": 12345, // Invalid type
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original.example.com"},
		}),
		Path:   "/test",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}

	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_NilParams(t *testing.T) {
	p := &HostRewritePolicy{}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"original.example.com"},
		}),
		Path:   "/test",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, nil)

	immResp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", result)
	}

	if immResp.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", immResp.StatusCode)
	}
}

func TestHostRewritePolicy_Mode(t *testing.T) {
	p := &HostRewritePolicy{}
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("Expected RequestHeaderMode to be HeaderModeProcess, got %v", mode.RequestHeaderMode)
	}

	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("Expected RequestBodyMode to be BodyModeSkip, got %v", mode.RequestBodyMode)
	}

	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("Expected ResponseHeaderMode to be HeaderModeSkip, got %v", mode.ResponseHeaderMode)
	}

	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("Expected ResponseBodyMode to be BodyModeSkip, got %v", mode.ResponseBodyMode)
	}
}

func TestHostRewritePolicy_GetPolicy(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName:  "test-route",
		APIId:      "test-api-id",
		APIName:    "test-api",
		APIVersion: "v1.0.0",
		AttachedTo: policy.LevelRoute,
	}

	params := map[string]interface{}{
		"host": "backend.example.com",
	}

	pol, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Expected no error from GetPolicy, got %v", err)
	}

	if pol == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	_, ok := pol.(*HostRewritePolicy)
	if !ok {
		t.Fatalf("Expected *HostRewritePolicy, got %T", pol)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_HostWithSubdomains(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "api.v2.staging.backend.example.com",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"www.frontend.example.com"},
		}),
		Path:   "/api/resource",
		Method: "PUT",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if mods.Host == nil || *mods.Host != "api.v2.staging.backend.example.com" {
		t.Errorf("Expected Host to be 'api.v2.staging.backend.example.com', got %v", mods.Host)
	}
}

func TestHostRewritePolicy_OnRequestHeaders_HostTrimmedWhitespace(t *testing.T) {
	p := &HostRewritePolicy{}

	params := map[string]interface{}{
		"host": "  backend.example.com  ",
	}

	reqCtx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			":authority": {"frontend.example.com"},
		}),
		Path:   "/",
		Method: "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if mods.Host == nil || *mods.Host != "backend.example.com" {
		t.Errorf("Expected Host to be 'backend.example.com' (trimmed), got %v", mods.Host)
	}
}

// TestConfigErrorDeclaresFault covers the one rejection this policy makes. A misconfigured
// policy refuses every request and only the deployment can fix it, so it must reach the
// fault policies.
func TestConfigErrorDeclaresFault(t *testing.T) {
	p := &HostRewritePolicy{}
	// An empty params map has no "host", which is the configuration error.
	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(map[string][]string{}),
	}, map[string]interface{}{})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on a configuration error")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated")
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
	}
	if resp.Fault.Type != policy.FaultTypeConfiguration {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeConfiguration, resp.Fault.Type)
	}
	if resp.Fault.Description == "" {
		t.Fatalf("expected Error.Description to name the configuration problem")
	}
}
