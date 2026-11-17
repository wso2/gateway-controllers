// Package dynamicendpoint routes requests to an upstream chosen at runtime: one of the API's own
// upstream definitions, a fixed gateway-wide Backend, or the gateway-wide Backend a CEL
// expression names from the request context.
package dynamicendpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	onMissingValueFallback = "fallback"
	onMissingValueReject   = "reject"

	// rejectionMessage is the one response for every value that cannot be routed — malformed,
	// unknown, or excluded by the selector — so a caller cannot probe which Backends exist.
	rejectionMessage = "The requested backend is not available for this API."
)

// lookupBackend resolves a gateway-wide Backend. A variable so tests can substitute it.
var lookupBackend = policy.LookupBackend

// DynamicEndpointPolicy routes requests to a dynamically chosen upstream.
type DynamicEndpointPolicy struct {
	targetUpstream  string
	expression      *backendExpression
	matchLabels     map[string]string
	rejectOnMissing bool
	routeName       string
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels). It repeats the
// definition's parameter rules and compiles backendExpression, so a configuration that bypassed
// schema validation, or an expression that does not compile, fails here rather than at request
// time.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &DynamicEndpointPolicy{routeName: metadata.RouteName}

	// targetUpstream is taken as written, as in v1.0: names match exactly, and a present but
	// empty value leaves the route's own upstream in place.
	rawTarget, hasTarget := params["targetUpstream"]
	if rawTarget != nil {
		target, ok := rawTarget.(string)
		if !ok {
			return nil, fmt.Errorf("dynamic-endpoint: targetUpstream must be a string")
		}
		p.targetUpstream = target
	}
	var err error
	expression, err := optionalString(params, "backendExpression")
	if err != nil {
		return nil, err
	}
	onMissing, err := optionalString(params, "onMissingValue")
	if err != nil {
		return nil, err
	}
	_, hasSelector := params["backendSelector"]
	if hasSelector {
		if p.matchLabels, err = parseSelector(params["backendSelector"]); err != nil {
			return nil, err
		}
	}

	switch {
	case !hasTarget && expression == "":
		return nil, fmt.Errorf("dynamic-endpoint: set targetUpstream, backendExpression or both")
	case expression != "" && !hasSelector:
		return nil, fmt.Errorf("dynamic-endpoint: backendExpression requires backendSelector; use {} to allow every Backend")
	case expression == "" && hasSelector:
		return nil, fmt.Errorf("dynamic-endpoint: backendSelector is only valid with backendExpression")
	case expression == "" && onMissing != "":
		return nil, fmt.Errorf("dynamic-endpoint: onMissingValue is only valid with backendExpression")
	}
	if expression != "" {
		if p.expression, err = compileBackendExpression(expression); err != nil {
			return nil, err
		}
	}
	switch onMissing {
	case "", onMissingValueFallback:
	case onMissingValueReject:
		p.rejectOnMissing = true
	default:
		return nil, fmt.Errorf("dynamic-endpoint: onMissingValue must be fallback or reject, got %q", onMissing)
	}

	slog.Debug("[Dynamic Endpoint]: policy created",
		"targetUpstream", p.targetUpstream, "backendExpression", expression)
	return p, nil
}

// Mode processes request headers only.
func (p *DynamicEndpointPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders picks the request's upstream.
func (p *DynamicEndpointPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if p.expression == nil {
		return p.staticTarget()
	}

	result := p.expression.evaluate(reqCtx, p.routeName)
	switch {
	case result.malformed:
		return reject()
	case result.value == "":
		if p.rejectOnMissing {
			return reject()
		}
		return p.staticTarget()
	}

	name := result.value
	if !policy.IsValidBackendName(name) {
		return reject()
	}
	backend, ok := lookupBackend(name)
	if !ok || !backend.MatchesLabels(p.matchLabels) {
		slog.Debug("[Dynamic Endpoint]: backendExpression names no selectable Backend", "backend", name, "found", ok)
		return reject()
	}
	// Only a validated, selectable Backend name is logged at info level; values that are
	// rejected come from the caller and stay at debug.
	slog.Info("[Dynamic Endpoint]: routing to Backend", "backend", name)
	return policy.UpstreamRequestHeaderModifications{BackendName: &backend.Name}
}

// staticTarget routes to targetUpstream, or leaves the route's own upstream in place when it is
// not set. The policy cannot see the API's upstream definitions, so it names the target both
// ways: the policy engine routes to the API's upstream definition of that name when the API has
// one, and otherwise to the gateway-wide Backend of that name.
func (p *DynamicEndpointPolicy) staticTarget() policy.RequestHeaderAction {
	if p.targetUpstream == "" {
		slog.Info("[Dynamic Endpoint]: no target, keeping the route's own upstream")
		return policy.UpstreamRequestHeaderModifications{}
	}
	target := p.targetUpstream
	// One info line per routed request, as in v1.0. It names only the configured target.
	slog.Info("[Dynamic Endpoint]: routing to targetUpstream", "targetUpstream", target)
	return policy.UpstreamRequestHeaderModifications{UpstreamName: &target, BackendName: &target}
}

func reject() policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": "Bad Request", "message": rejectionMessage})
	return policy.ImmediateResponse{
		StatusCode: 400,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeInvalidRequestHeader,
			Type:      policy.FaultTypeValidation,
			Direction: policy.DirectionRequest,
			Message:   rejectionMessage,
		},
	}
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("dynamic-endpoint: %s must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

// parseSelector reads backendSelector. {} and an empty matchLabels allow every Backend; a null
// selector or matchLabels is rejected rather than read as "allow every Backend", so a value that
// slipped past schema validation can never widen what the API reaches.
func parseSelector(raw interface{}) (map[string]string, error) {
	if raw == nil {
		return nil, fmt.Errorf("dynamic-endpoint: backendSelector must be an object; use {} to allow every Backend")
	}
	selector, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("dynamic-endpoint: backendSelector must be an object")
	}
	labels := map[string]string{}
	for key, value := range selector {
		if key != "matchLabels" {
			return nil, fmt.Errorf("dynamic-endpoint: backendSelector supports only matchLabels, got %q", key)
		}
		if value == nil {
			return nil, fmt.Errorf("dynamic-endpoint: backendSelector.matchLabels must be an object")
		}
		matchLabels, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("dynamic-endpoint: backendSelector.matchLabels must be an object")
		}
		for k, v := range matchLabels {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("dynamic-endpoint: backendSelector.matchLabels.%s must be a string", k)
			}
			labels[k] = s
		}
	}
	return labels, nil
}
