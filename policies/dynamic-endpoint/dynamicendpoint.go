// Package dynamicendpoint provides a policy for dynamic upstream routing.
// It demonstrates the UpstreamName functionality in the SDK.
package dynamicendpoint

import (
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// DynamicEndpointPolicy routes requests to a dynamically specified upstream.
type DynamicEndpointPolicy struct {
	targetUpstream string
}

// GetPolicy creates a new instance of the dynamic endpoint policy.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	slog.Debug("[Dynamic Endpoint]: GetPolicy called")

	targetUpstream, _ := params["targetUpstream"].(string)

	return &DynamicEndpointPolicy{
		targetUpstream: targetUpstream,
	}, nil
}

// Mode returns the processing mode for this policy.
func (p *DynamicEndpointPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Need headers to process the request
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest sets the dynamic upstream for routing.
func (p *DynamicEndpointPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	slog.Info("[Dynamic Endpoint]: OnRequest called", "targetUpstream", p.targetUpstream)

	if p.targetUpstream == "" {
		slog.Warn("[Dynamic Endpoint]: No target upstream configured, passing through")
		return policy.UpstreamRequestModifications{}
	}

	// Use UpstreamName to route the request to the target upstream definition
	// The upstream name must match an entry in the API's upstreamDefinitions
	return policy.UpstreamRequestModifications{
		UpstreamName: &p.targetUpstream,
	}
}

// OnResponse is not used by this policy.
func (p *DynamicEndpointPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return policy.UpstreamResponseModifications{}
}
