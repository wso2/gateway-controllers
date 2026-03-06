package basicratelimit

import (
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

type stubDelegatePolicy struct {
	mode policy.ProcessingMode

	onRequestAction policy.RequestAction
	onRequestCtx    *policy.RequestContext
	onRequestParams map[string]interface{}
	onRequestCalls  int

	onResponseAction policy.ResponseAction
	onResponseCtx    *policy.ResponseContext
	onResponseParams map[string]interface{}
	onResponseCalls  int
}

func (s *stubDelegatePolicy) Mode() policy.ProcessingMode {
	return s.mode
}

func (s *stubDelegatePolicy) OnRequest(
	ctx *policy.RequestContext,
	params map[string]interface{},
) policy.RequestAction {
	s.onRequestCalls++
	s.onRequestCtx = ctx
	s.onRequestParams = params
	return s.onRequestAction
}

func (s *stubDelegatePolicy) OnResponse(
	ctx *policy.ResponseContext,
	params map[string]interface{},
) policy.ResponseAction {
	s.onResponseCalls++
	s.onResponseCtx = ctx
	s.onResponseParams = params
	return s.onResponseAction
}

func getSingleQuota(t *testing.T, rlParams map[string]interface{}) map[string]interface{} {
	t.Helper()

	quotas, ok := rlParams["quotas"].([]interface{})
	if !ok {
		t.Fatalf("expected quotas to be []interface{}, got %T", rlParams["quotas"])
	}
	if len(quotas) != 1 {
		t.Fatalf("expected exactly one quota, got %d", len(quotas))
	}

	quota, ok := quotas[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected quota entry to be map[string]interface{}, got %T", quotas[0])
	}
	return quota
}

func getQuotaLimits(t *testing.T, quota map[string]interface{}) []interface{} {
	t.Helper()

	limits, ok := quota["limits"].([]interface{})
	if !ok {
		t.Fatalf("expected limits to be []interface{}, got %T", quota["limits"])
	}
	return limits
}

func getFirstKeyExtractionType(t *testing.T, quota map[string]interface{}) string {
	t.Helper()

	keyExtraction, ok := quota["keyExtraction"].([]interface{})
	if !ok {
		t.Fatalf("expected keyExtraction to be []interface{}, got %T", quota["keyExtraction"])
	}
	if len(keyExtraction) != 1 {
		t.Fatalf("expected exactly one key extraction entry, got %d", len(keyExtraction))
	}

	firstExtractor, ok := keyExtraction[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected key extraction entry to be map[string]interface{}, got %T", keyExtraction[0])
	}

	extractorType, ok := firstExtractor["type"].(string)
	if !ok {
		t.Fatalf("expected key extraction type to be string, got %T", firstExtractor["type"])
	}

	return extractorType
}

func intPtr(v int) *int {
	return &v
}

func TestTransformToRatelimitParams_DefaultQuotaAndRouteNameKeyExtraction(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 100,
				"duration": "1m",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{
		AttachedTo: policy.LevelRoute,
	})

	quota := getSingleQuota(t, rlParams)

	if gotName, ok := quota["name"].(string); !ok || gotName != "default" {
		t.Fatalf("expected quota name default, got %v", quota["name"])
	}

	if gotKeyType := getFirstKeyExtractionType(t, quota); gotKeyType != "routename" {
		t.Fatalf("expected routename key extraction, got %s", gotKeyType)
	}
}

func TestTransformToRatelimitParams_UsesAPINameKeyExtractionAtAPILevel(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 10,
				"duration": "1s",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{
		AttachedTo: policy.LevelAPI,
	})

	quota := getSingleQuota(t, rlParams)
	if gotKeyType := getFirstKeyExtractionType(t, quota); gotKeyType != "apiname" {
		t.Fatalf("expected apiname key extraction for API level, got %s", gotKeyType)
	}
}

func TestTransformToRatelimitParams_TranslatesRequestsToLimitAndRemovesRequests(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 100,
				"duration": "1m",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})
	quota := getSingleQuota(t, rlParams)

	limits := getQuotaLimits(t, quota)
	if len(limits) != 1 {
		t.Fatalf("expected one limit entry, got %d", len(limits))
	}

	limitEntry, ok := limits[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected limit entry to be map[string]interface{}, got %T", limits[0])
	}

	if _, hasRequests := limitEntry["requests"]; hasRequests {
		t.Fatalf("expected requests key to be removed after translation, got %v", limitEntry)
	}

	if got := limitEntry["limit"]; got != 100 {
		t.Fatalf("expected translated limit=100, got %v", got)
	}
}

func TestTransformToRatelimitParams_AllowsLegacyLimitWhenRequestsAbsent(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"limit":    50,
				"duration": "1m",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})
	quota := getSingleQuota(t, rlParams)
	limits := getQuotaLimits(t, quota)
	if len(limits) != 1 {
		t.Fatalf("expected one limit entry, got %d", len(limits))
	}

	limitEntry, ok := limits[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected legacy limit entry to be map[string]interface{}, got %T", limits[0])
	}

	if got := limitEntry["limit"]; got != 50 {
		t.Fatalf("expected legacy limit value to be preserved, got %v", got)
	}
}

func TestTransformToRatelimitParams_RequestsOverridesLimitWhenBothPresent(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 100,
				"limit":    1,
				"duration": "1s",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})
	quota := getSingleQuota(t, rlParams)
	limits := getQuotaLimits(t, quota)
	if len(limits) != 1 {
		t.Fatalf("expected one limit entry, got %d", len(limits))
	}

	limitEntry, ok := limits[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected translated entry to be map[string]interface{}, got %T", limits[0])
	}

	if _, hasRequests := limitEntry["requests"]; hasRequests {
		t.Fatalf("expected requests key to be removed when both requests and limit are present")
	}
	if got := limitEntry["limit"]; got != 100 {
		t.Fatalf("expected requests to override limit value, got %v", got)
	}
}

func TestTransformToRatelimitParams_TranslatesMultipleLimitEntries(t *testing.T) {
	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 10,
				"duration": "1s",
			},
			map[string]interface{}{
				"limit":    20,
				"duration": "1m",
			},
			map[string]interface{}{
				"requests": 30,
				"limit":    40,
				"duration": "1h",
			},
		},
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})
	quota := getSingleQuota(t, rlParams)
	limits := getQuotaLimits(t, quota)

	if len(limits) != 3 {
		t.Fatalf("expected three limit entries, got %d", len(limits))
	}

	expectedLimits := []int{10, 20, 30}
	for i := range limits {
		limitEntry, ok := limits[i].(map[string]interface{})
		if !ok {
			t.Fatalf("expected limits[%d] to be map[string]interface{}, got %T", i, limits[i])
		}
		if _, hasRequests := limitEntry["requests"]; hasRequests {
			t.Fatalf("expected limits[%d] requests key to be removed, got %v", i, limitEntry)
		}
		if got := limitEntry["limit"]; got != expectedLimits[i] {
			t.Fatalf("expected limits[%d].limit=%d, got %v", i, expectedLimits[i], got)
		}
	}
}

func TestTransformToRatelimitParams_PassesThroughSystemParamsIncludingNestedMaps(t *testing.T) {
	redis := map[string]interface{}{
		"host":          "redis.internal",
		"port":          float64(6380),
		"failureMode":   "open",
		"readTimeout":   "3s",
		"writeTimeout":  "3s",
		"keyPrefix":     "ratelimit:v2:",
		"databaseAlias": "primary",
	}
	memory := map[string]interface{}{
		"maxEntries":      float64(20000),
		"cleanupInterval": "1m",
	}

	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": 100,
				"duration": "1m",
			},
		},
		"algorithm": "gcra",
		"backend":   "redis",
		"redis":     redis,
		"memory":    memory,
	}

	rlParams := transformToRatelimitParams(params, policy.PolicyMetadata{})

	if got := rlParams["algorithm"]; got != "gcra" {
		t.Fatalf("expected algorithm passthrough gcra, got %v", got)
	}
	if got := rlParams["backend"]; got != "redis" {
		t.Fatalf("expected backend passthrough redis, got %v", got)
	}
	if !reflect.DeepEqual(rlParams["redis"], redis) {
		t.Fatalf("expected redis passthrough map to be preserved.\nwant=%v\ngot=%v", redis, rlParams["redis"])
	}
	if !reflect.DeepEqual(rlParams["memory"], memory) {
		t.Fatalf("expected memory passthrough map to be preserved.\nwant=%v\ngot=%v", memory, rlParams["memory"])
	}
}

func TestTransformToRatelimitParams_DoesNotMutateInputLimits(t *testing.T) {
	inputLimit := map[string]interface{}{
		"requests": 100,
		"duration": "1m",
	}
	originalInputLimit := map[string]interface{}{
		"requests": inputLimit["requests"],
		"duration": inputLimit["duration"],
	}

	params := map[string]interface{}{
		"limits": []interface{}{inputLimit},
	}

	_ = transformToRatelimitParams(params, policy.PolicyMetadata{})

	if _, hasRequests := inputLimit["requests"]; !hasRequests {
		t.Fatalf("expected original input map to still contain requests key")
	}
	if _, hasLimit := inputLimit["limit"]; hasLimit {
		t.Fatalf("did not expect original input map to gain a limit key")
	}
	if !reflect.DeepEqual(inputLimit, originalInputLimit) {
		t.Fatalf("expected input limit map to remain unchanged.\nwant=%v\ngot=%v", originalInputLimit, inputLimit)
	}
}

func TestTransformToRatelimitParams_HandlesMissingOrMalformedLimitsWithoutPanic(t *testing.T) {
	testCases := []struct {
		name         string
		params       map[string]interface{}
		expectedLen  int
		expectedRaw0 interface{}
	}{
		{
			name:        "missing limits key",
			params:      map[string]interface{}{},
			expectedLen: 0,
		},
		{
			name: "malformed limits container",
			params: map[string]interface{}{
				"limits": map[string]interface{}{
					"requests": 100,
					"duration": "1m",
				},
			},
			expectedLen: 0,
		},
		{
			name: "non-map limit item passthrough",
			params: map[string]interface{}{
				"limits": []interface{}{
					"raw-limit-entry",
					map[string]interface{}{
						"requests": 5,
						"duration": "1s",
					},
				},
			},
			expectedLen:  2,
			expectedRaw0: "raw-limit-entry",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("expected no panic for case %q, got %v", tc.name, r)
				}
			}()

			rlParams := transformToRatelimitParams(tc.params, policy.PolicyMetadata{})
			quota := getSingleQuota(t, rlParams)
			limits := getQuotaLimits(t, quota)

			if len(limits) != tc.expectedLen {
				t.Fatalf("expected %d transformed limits, got %d", tc.expectedLen, len(limits))
			}

			if tc.expectedRaw0 != nil {
				if got := limits[0]; !reflect.DeepEqual(got, tc.expectedRaw0) {
					t.Fatalf("expected malformed entry passthrough at index 0: want=%v got=%v", tc.expectedRaw0, got)
				}
				translated, ok := limits[1].(map[string]interface{})
				if !ok {
					t.Fatalf("expected translated limits[1] to be map[string]interface{}, got %T", limits[1])
				}
				if got := translated["limit"]; got != 5 {
					t.Fatalf("expected translated limits[1].limit=5, got %v", got)
				}
				if _, hasRequests := translated["requests"]; hasRequests {
					t.Fatalf("expected translated limits[1] to not include requests key")
				}
			}
		})
	}
}

func TestBasicRateLimitPolicy_Mode_ProcessesHeadersAndSkipsBodies(t *testing.T) {
	p := &BasicRateLimitPolicy{}
	gotMode := p.Mode()

	wantMode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}

	if gotMode != wantMode {
		t.Fatalf("unexpected mode.\nwant=%+v\ngot=%+v", wantMode, gotMode)
	}
}

func TestBasicRateLimitPolicy_OnRequest_ForwardsContextParamsAndActionUnchanged(t *testing.T) {
	sentinel := policy.ImmediateResponse{StatusCode: 429}
	delegate := &stubDelegatePolicy{
		onRequestAction: sentinel,
	}
	p := &BasicRateLimitPolicy{delegate: delegate}

	ctx := &policy.RequestContext{
		Headers: policy.NewHeaders(map[string][]string{
			"x-request-id": {"req-123"},
		}),
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				"user": "alice",
			},
		},
	}
	params := map[string]interface{}{
		"limits": "as-provided",
	}

	gotAction := p.OnRequest(ctx, params)

	if delegate.onRequestCalls != 1 {
		t.Fatalf("expected delegate OnRequest to be called once, got %d", delegate.onRequestCalls)
	}
	if delegate.onRequestCtx != ctx {
		t.Fatalf("expected same request context pointer to be forwarded")
	}
	if !reflect.DeepEqual(delegate.onRequestParams, params) {
		t.Fatalf("expected delegate to receive unchanged params map.\nwant=%v\ngot=%v", params, delegate.onRequestParams)
	}
	if !reflect.DeepEqual(gotAction, sentinel) {
		t.Fatalf("expected returned request action to match delegate action.\nwant=%#v\ngot=%#v", sentinel, gotAction)
	}

	delegate.onRequestParams["after_call"] = "visible_in_caller"
	if params["after_call"] != "visible_in_caller" {
		t.Fatalf("expected delegate and caller to observe the same params map reference")
	}
}

func TestBasicRateLimitPolicy_OnResponse_ForwardsContextParamsAndActionUnchanged(t *testing.T) {
	sentinel := policy.UpstreamResponseModifications{
		SetHeaders: map[string]string{
			"x-rate-limit": "ok",
		},
		StatusCode: intPtr(202),
	}
	delegate := &stubDelegatePolicy{
		onResponseAction: sentinel,
	}
	p := &BasicRateLimitPolicy{delegate: delegate}

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"x-response-id": {"res-123"},
		}),
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				"tenant": "foo",
			},
		},
	}
	params := map[string]interface{}{
		"key": "value",
	}

	gotAction := p.OnResponse(ctx, params)

	if delegate.onResponseCalls != 1 {
		t.Fatalf("expected delegate OnResponse to be called once, got %d", delegate.onResponseCalls)
	}
	if delegate.onResponseCtx != ctx {
		t.Fatalf("expected same response context pointer to be forwarded")
	}
	if !reflect.DeepEqual(delegate.onResponseParams, params) {
		t.Fatalf("expected delegate to receive unchanged params map.\nwant=%v\ngot=%v", params, delegate.onResponseParams)
	}
	if !reflect.DeepEqual(gotAction, sentinel) {
		t.Fatalf("expected returned response action to match delegate action.\nwant=%#v\ngot=%#v", sentinel, gotAction)
	}

	delegate.onResponseParams["after_call"] = "visible_in_caller"
	if params["after_call"] != "visible_in_caller" {
		t.Fatalf("expected delegate and caller to observe the same params map reference")
	}
}

func TestGetPolicy_ReturnsBasicRateLimitPolicy_WhenDelegateCreationSucceeds(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "unit-test-basic-ratelimit-getpolicy-success",
	}

	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": float64(10),
				"duration": "1s",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("expected GetPolicy success, got error: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil policy from GetPolicy")
	}
	if _, ok := p.(*BasicRateLimitPolicy); !ok {
		t.Fatalf("expected *BasicRateLimitPolicy, got %T", p)
	}
}

func TestGetPolicy_PropagatesError_WhenDelegateCreationFails(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "unit-test-basic-ratelimit-getpolicy-error",
	}

	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"requests": "bad",
				"duration": "1s",
			},
		},
		"backend": "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err == nil {
		t.Fatalf("expected GetPolicy error for invalid limit value type, got nil")
	}
	if p != nil {
		t.Fatalf("expected nil policy when GetPolicy fails, got %T", p)
	}
	if !strings.Contains(err.Error(), "limit must be a number") {
		t.Fatalf("expected propagated delegate parse error to mention numeric limit, got: %v", err)
	}
}

func TestGetPolicy_AcceptsLegacyLimitShape_ForDocsCompatibility(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "unit-test-basic-ratelimit-getpolicy-legacy-limit",
	}

	params := map[string]interface{}{
		"limits": []interface{}{
			map[string]interface{}{
				"limit":    float64(50),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("expected GetPolicy to accept legacy limit shape, got error: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil policy for legacy limit shape")
	}
	if _, ok := p.(*BasicRateLimitPolicy); !ok {
		t.Fatalf("expected *BasicRateLimitPolicy, got %T", p)
	}
}
