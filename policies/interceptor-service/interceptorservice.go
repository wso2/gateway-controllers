// Package interceptorservice implements the interceptor-service policy.
//
// The policy posts request- and response-phase data to a user-defined HTTP
// service following the contract in interceptor-service-open-api-v1.yaml. The
// interceptor's reply is translated into gateway actions (header/body/path
// mutations, dynamic-endpoint routing, or a direct response).
package interceptorservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultTimeoutMillis   = 5000
	minTimeoutMillis       = 100
	maxTimeoutMillis       = 60000
	defaultMaxResponseSize = 1024 * 1024 // 1 MiB
	sharedContextKey       = "interceptor-service:context"
	handleRequestPath      = "/handle-request"
	handleResponsePath     = "/handle-response"
	interceptorErrorStatus = 500
	interceptorErrorBody   = `{"message":"Internal Server Error"}`
	contentTypeJSON        = "application/json"
)

// InterceptorServicePolicy implements RequestPolicy and ResponsePolicy.
type InterceptorServicePolicy struct {
	endpoint        string
	timeout         time.Duration
	maxResponseSize int64
	client          *http.Client

	hasRequest  bool
	requestCfg  phaseConfig
	hasResponse bool
	responseCfg phaseConfig
}

type phaseConfig struct {
	IncludeRequestHeaders  bool
	IncludeRequestBody     bool
	IncludeResponseHeaders bool
	IncludeResponseBody    bool
	PassthroughOnError     bool
}

type invocationContext struct {
	RequestID    string `json:"requestId"`
	APIName      string `json:"apiName,omitempty"`
	APIVersion   string `json:"apiVersion,omitempty"`
	Vhost        string `json:"vhost,omitempty"`
	Method       string `json:"method,omitempty"`
	BasePath     string `json:"basePath,omitempty"`
	Path         string `json:"path,omitempty"`
	PathTemplate string `json:"pathTemplate,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
}

type handleRequestBody struct {
	RequestHeaders    map[string]string `json:"requestHeaders,omitempty"`
	RequestBody       string            `json:"requestBody,omitempty"`
	InvocationContext invocationContext `json:"invocationContext"`
}

type handleResponseBody struct {
	ResponseCode       int               `json:"responseCode"`
	RequestHeaders     map[string]string `json:"requestHeaders,omitempty"`
	RequestBody        string            `json:"requestBody,omitempty"`
	ResponseHeaders    map[string]string `json:"responseHeaders,omitempty"`
	ResponseBody       string            `json:"responseBody,omitempty"`
	InvocationContext  invocationContext `json:"invocationContext"`
	InterceptorContext map[string]string `json:"interceptorContext,omitempty"`
}

type dynamicEndpoint struct {
	EndpointName string `json:"endpointName"`
}

type interceptorReply struct {
	DirectRespond      bool              `json:"directRespond"`
	ResponseCode       int               `json:"responseCode"`
	DynamicEndpoint    *dynamicEndpoint  `json:"dynamicEndpoint"`
	HeadersToAdd       map[string]string `json:"headersToAdd"`
	HeadersToReplace   map[string]string `json:"headersToReplace"`
	HeadersToRemove    []string          `json:"headersToRemove"`
	PathToRewrite      string            `json:"pathToRewrite"`
	Body               string            `json:"body"`
	InterceptorContext map[string]string `json:"interceptorContext"`
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	endpointRaw, ok := params["endpoint"]
	if !ok {
		return nil, fmt.Errorf("'endpoint' parameter is required")
	}
	endpoint, ok := endpointRaw.(string)
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("'endpoint' must be a non-empty string")
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return nil, fmt.Errorf("'endpoint' must be a valid URL: %w", err)
	}
	endpoint = strings.TrimRight(endpoint, "/")

	timeoutMs, err := parseTimeout(params)
	if err != nil {
		return nil, err
	}

	skipVerify, err := parseBool(params, "tlsSkipVerify", false)
	if err != nil {
		return nil, err
	}

	maxRespSize, err := parseMaxResponseSize(params)
	if err != nil {
		return nil, err
	}

	requestRaw, hasRequest := params["request"].(map[string]interface{})
	responseRaw, hasResponse := params["response"].(map[string]interface{})
	if !hasRequest && !hasResponse {
		return nil, fmt.Errorf("at least one of 'request' or 'response' must be provided")
	}

	p := &InterceptorServicePolicy{
		endpoint:        endpoint,
		timeout:         time.Duration(timeoutMs) * time.Millisecond,
		maxResponseSize: maxRespSize,
		hasRequest:      hasRequest,
		hasResponse:     hasResponse,
	}
	if hasRequest {
		cfg, err := parsePhaseConfig(requestRaw, false)
		if err != nil {
			return nil, fmt.Errorf("invalid 'request' parameters: %w", err)
		}
		p.requestCfg = cfg
	}
	if hasResponse {
		cfg, err := parsePhaseConfig(responseRaw, true)
		if err != nil {
			return nil, fmt.Errorf("invalid 'response' parameters: %w", err)
		}
		p.responseCfg = cfg
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if skipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-opt-in for dev
	}
	p.client = &http.Client{
		Timeout:   p.timeout,
		Transport: transport,
	}

	return p, nil
}

func parseTimeout(params map[string]interface{}) (int, error) {
	raw, ok := params["timeoutMillis"]
	if !ok {
		return defaultTimeoutMillis, nil
	}
	var ms int
	switch v := raw.(type) {
	case int:
		ms = v
	case int64:
		ms = int(v)
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("'timeoutMillis' must be an integer")
		}
		ms = int(v)
	default:
		return 0, fmt.Errorf("'timeoutMillis' must be an integer")
	}
	if ms < minTimeoutMillis || ms > maxTimeoutMillis {
		return 0, fmt.Errorf("'timeoutMillis' must be between %d and %d", minTimeoutMillis, maxTimeoutMillis)
	}
	return ms, nil
}

func parseMaxResponseSize(params map[string]interface{}) (int64, error) {
	raw, ok := params["maxResponseSize"]
	if !ok {
		return defaultMaxResponseSize, nil
	}
	var n int64
	switch v := raw.(type) {
	case int:
		n = int64(v)
	case int64:
		n = v
	case float64:
		if v != float64(int64(v)) {
			return 0, fmt.Errorf("'maxResponseSize' must be an integer")
		}
		n = int64(v)
	default:
		return 0, fmt.Errorf("'maxResponseSize' must be an integer")
	}
	if n <= 0 {
		return 0, fmt.Errorf("'maxResponseSize' must be a positive integer")
	}
	return n, nil
}

func parseBool(params map[string]interface{}, key string, def bool) (bool, error) {
	raw, ok := params[key]
	if !ok {
		return def, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
	return b, nil
}

func parsePhaseConfig(raw map[string]interface{}, isResponse bool) (phaseConfig, error) {
	cfg := phaseConfig{}
	var err error
	if isResponse {
		if cfg.IncludeRequestHeaders, err = parseBool(raw, "includeRequestHeaders", false); err != nil {
			return cfg, err
		}
		if cfg.IncludeRequestBody, err = parseBool(raw, "includeRequestBody", false); err != nil {
			return cfg, err
		}
		if cfg.IncludeResponseHeaders, err = parseBool(raw, "includeResponseHeaders", true); err != nil {
			return cfg, err
		}
		if cfg.IncludeResponseBody, err = parseBool(raw, "includeResponseBody", true); err != nil {
			return cfg, err
		}
	} else {
		if cfg.IncludeRequestHeaders, err = parseBool(raw, "includeRequestHeaders", true); err != nil {
			return cfg, err
		}
		if cfg.IncludeRequestBody, err = parseBool(raw, "includeRequestBody", true); err != nil {
			return cfg, err
		}
	}
	if cfg.PassthroughOnError, err = parseBool(raw, "passthroughOnError", false); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Mode returns the processing mode.
func (p *InterceptorServicePolicy) Mode() policy.ProcessingMode {
	mode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if p.hasRequest {
		mode.RequestBodyMode = policy.BodyModeBuffer
	}
	if p.hasResponse {
		mode.ResponseBodyMode = policy.BodyModeBuffer
	}
	return mode
}

// OnRequestBody handles the request phase.
func (p *InterceptorServicePolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequest {
		return policy.UpstreamRequestModifications{}
	}

	ds := reqCtx.DownstreamRequest()
	body := handleRequestBody{
		InvocationContext: buildInvocationContext(reqCtx.SharedContext, ds.Path, ds.Method, ds.Scheme, reqCtx.Vhost),
	}
	if p.requestCfg.IncludeRequestHeaders {
		body.RequestHeaders = flattenHeaders(reqCtx.Headers)
	}
	if p.requestCfg.IncludeRequestBody && reqCtx.Body != nil && len(reqCtx.Body.Content) > 0 {
		body.RequestBody = base64.StdEncoding.EncodeToString(reqCtx.Body.Content)
	}

	reply, err := p.callInterceptor(ctx, p.endpoint+handleRequestPath, body)
	if err != nil {
		slog.Debug("InterceptorService: request phase call failed", "error", err)
		if p.requestCfg.PassthroughOnError {
			return policy.UpstreamRequestModifications{}
		}
		return interceptorErrorImmediate(err, policy.DirectionRequest)
	}

	if reply.InterceptorContext != nil && reqCtx.SharedContext != nil {
		if reqCtx.SharedContext.Metadata == nil {
			reqCtx.SharedContext.Metadata = map[string]interface{}{}
		}
		reqCtx.SharedContext.Metadata[sharedContextKey] = reply.InterceptorContext
	}

	if reply.DirectRespond {
		return buildImmediateResponse(reply)
	}

	return buildUpstreamModifications(reply)
}

// OnResponseBody handles the response phase.
func (p *InterceptorServicePolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponse {
		return policy.DownstreamResponseModifications{}
	}

	ds := respCtx.DownstreamRequest()
	body := handleResponseBody{
		ResponseCode:      respCtx.ResponseStatus,
		InvocationContext: buildInvocationContext(respCtx.SharedContext, ds.Path, ds.Method, "", ""),
	}
	if p.responseCfg.IncludeRequestHeaders {
		body.RequestHeaders = flattenHeaders(respCtx.RequestHeaders)
	}
	if p.responseCfg.IncludeRequestBody && respCtx.RequestBody != nil && len(respCtx.RequestBody.Content) > 0 {
		body.RequestBody = base64.StdEncoding.EncodeToString(respCtx.RequestBody.Content)
	}
	if p.responseCfg.IncludeResponseHeaders {
		body.ResponseHeaders = flattenHeaders(respCtx.ResponseHeaders)
	}
	if p.responseCfg.IncludeResponseBody && respCtx.ResponseBody != nil && len(respCtx.ResponseBody.Content) > 0 {
		body.ResponseBody = base64.StdEncoding.EncodeToString(respCtx.ResponseBody.Content)
	}
	if respCtx.SharedContext != nil && respCtx.SharedContext.Metadata != nil {
		if v, ok := respCtx.SharedContext.Metadata[sharedContextKey].(map[string]string); ok {
			body.InterceptorContext = v
		}
	}

	reply, err := p.callInterceptor(ctx, p.endpoint+handleResponsePath, body)
	if err != nil {
		slog.Debug("InterceptorService: response phase call failed", "error", err)
		if p.responseCfg.PassthroughOnError {
			return policy.DownstreamResponseModifications{}
		}
		return interceptorErrorImmediate(err, policy.DirectionResponse)
	}

	mods := policy.DownstreamResponseModifications{
		HeadersToSet:    mergeHeaders(reply.HeadersToAdd, reply.HeadersToReplace),
		HeadersToRemove: reply.HeadersToRemove,
	}
	if reply.ResponseCode != 0 {
		code := reply.ResponseCode
		mods.StatusCode = &code
	}
	if reply.Body != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(reply.Body)
		if decErr != nil {
			slog.Debug("InterceptorService: invalid base64 body in response reply", "error", decErr)
		} else {
			mods.Body = decoded
		}
	}
	return mods
}

func (p *InterceptorServicePolicy) callInterceptor(ctx context.Context, target string, payload interface{}) (*interceptorReply, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Accept", contentTypeJSON)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call interceptor: %w", err)
	}
	defer resp.Body.Close()

	if resp.ContentLength > p.maxResponseSize {
		return nil, fmt.Errorf("interceptor response exceeds max size of %d bytes", p.maxResponseSize)
	}
	// Read up to maxResponseSize+1 so we can detect responses that omit
	// Content-Length (e.g. chunked transfer) but exceed the cap. We discard
	// any partial buffer in that case rather than parsing it.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, p.maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read interceptor response: %w", err)
	}
	if int64(len(bodyBytes)) > p.maxResponseSize {
		return nil, fmt.Errorf("interceptor response exceeds max size of %d bytes", p.maxResponseSize)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("interceptor returned status %d", resp.StatusCode)
	}
	reply := &interceptorReply{}
	if len(bodyBytes) == 0 {
		return reply, nil
	}
	if err := json.Unmarshal(bodyBytes, reply); err != nil {
		return nil, fmt.Errorf("decode interceptor response: %w", err)
	}
	return reply, nil
}

func buildInvocationContext(shared *policy.SharedContext, path, method, scheme, vhost string) invocationContext {
	ic := invocationContext{
		Path:   path,
		Method: method,
		Scheme: scheme,
		Vhost:  vhost,
	}
	if shared != nil {
		ic.RequestID = shared.RequestID
		ic.APIName = shared.APIName
		ic.APIVersion = shared.APIVersion
		ic.BasePath = shared.APIContext
		ic.PathTemplate = shared.OperationPath
	}
	return ic
}

func flattenHeaders(h *policy.Headers) map[string]string {
	if h == nil {
		return nil
	}
	out := map[string]string{}
	h.Iterate(func(name string, values []string) {
		out[name] = strings.Join(values, ",")
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeHeaders(add, replace map[string]string) map[string]string {
	if len(add) == 0 && len(replace) == 0 {
		return nil
	}
	out := make(map[string]string, len(add)+len(replace))
	for k, v := range add {
		out[k] = v
	}
	// headersToReplace wins on collisions.
	for k, v := range replace {
		out[k] = v
	}
	return out
}

func buildImmediateResponse(reply *interceptorReply) policy.ImmediateResponse {
	resp := policy.ImmediateResponse{
		StatusCode: reply.ResponseCode,
		Headers:    mergeHeaders(reply.HeadersToAdd, reply.HeadersToReplace),
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	if reply.Body != "" {
		if decoded, err := base64.StdEncoding.DecodeString(reply.Body); err == nil {
			resp.Body = decoded
		} else {
			slog.Debug("InterceptorService: invalid base64 body in directRespond reply", "error", err)
		}
	}
	return resp
}

func buildUpstreamModifications(reply *interceptorReply) policy.UpstreamRequestModifications {
	mods := policy.UpstreamRequestModifications{
		HeadersToSet:    mergeHeaders(reply.HeadersToAdd, reply.HeadersToReplace),
		HeadersToRemove: reply.HeadersToRemove,
	}
	if reply.Body != "" {
		if decoded, err := base64.StdEncoding.DecodeString(reply.Body); err == nil {
			mods.Body = decoded
		} else {
			slog.Debug("InterceptorService: invalid base64 body in request reply", "error", err)
		}
	}
	if reply.PathToRewrite != "" {
		if parsed, err := url.Parse(reply.PathToRewrite); err == nil {
			path := parsed.Path
			if path == "" {
				path = reply.PathToRewrite
			}
			mods.Path = &path
			if parsed.RawQuery != "" {
				if q, qerr := url.ParseQuery(parsed.RawQuery); qerr == nil && len(q) > 0 {
					mods.QueryParametersToAdd = map[string][]string(q)
				}
			}
		} else {
			slog.Debug("InterceptorService: invalid pathToRewrite", "value", reply.PathToRewrite, "error", err)
		}
	}
	if reply.DynamicEndpoint != nil && reply.DynamicEndpoint.EndpointName != "" {
		name := reply.DynamicEndpoint.EndpointName
		mods.UpstreamName = &name
	}
	return mods
}

func interceptorErrorImmediate(err error, direction string) policy.ImmediateResponse {
	slog.Error("InterceptorService: returning 500 to client", "error", err)
	return policy.ImmediateResponse{
		StatusCode: interceptorErrorStatus,
		Headers:    map[string]string{"Content-Type": contentTypeJSON},
		Body:       []byte(interceptorErrorBody),
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeMediationFailed,
			Type:      policy.FaultTypeMediation,
			Direction: direction,
			Message:   "Interceptor service unavailable",
			// err names the gateway's own connectivity problem; the renderer withholds
			// Description from the client body.
			Description: err.Error(),
		},
	}
}
