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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package costbasedrouting

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultCostScaleFactor converts dollars to nano-dollars so that small
	// per-request costs survive the int64 counters used by the shared
	// rate-limit storage. $1.00 = 1,000,000,000 nano-dollars.
	DefaultCostScaleFactor int64 = 1_000_000_000

	// defaultAlgorithm is fixed-window because the product behaviour of this
	// policy is a hard "$N per window" budget that resets as a whole. GCRA is
	// supported but replenishes gradually; see the policy documentation.
	defaultAlgorithm = "fixed-window"

	defaultBackend        = "memory"
	defaultRedisKeyPrefix = "ratelimit:v1:"

	// consumerFallbackID is the budget scope used when consumerBased is enabled
	// but no application id is present on the request. Unidentified callers
	// share this single budget rather than bypassing the budget entirely.
	consumerFallbackID = "default"

	// applicationIDMetadataKey is the consumer identity published by the auth
	// policies; llm-cost-based-ratelimit keys per-consumer budgets on the same
	// metadata entry.
	applicationIDMetadataKey = "x-wso2-application-id"

	onExhaustedDefault = "default"
	onExhaustedReject  = "reject"
)

// target is a model, plus the optional additional provider that serves it.
// An empty Provider means the LLM proxy's primary/default provider.
type target struct {
	Model    string
	Provider string
}

// budgetLimit is one configured spending window. Scaled is Amount converted to
// the integer unit used by the storage backend.
type budgetLimit struct {
	Amount   float64
	Duration time.Duration
	Scaled   int64
}

// costRoute is one ordered, budgeted target. A matching requested model may be
// tried first; all fallback selection follows the configured order.
type costRoute struct {
	Name         string
	Target       target
	BudgetLimits []budgetLimit
}

type requestModelConfig struct {
	Location       string
	Identifier     string
	PathExpression *regexp.Regexp
	PathModelGroup int
}

type redisConfig struct {
	Host              string
	Port              int
	Username          string
	Password          string
	DB                int
	KeyPrefix         string
	FailOpen          bool
	ConnectionTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	PoolSize          int
}

type localConfig struct {
	SyncInterval        time.Duration
	FlushWorkers        int
	MaxPipelineCommands int
	MaxLocalEntries     int
}

type config struct {
	Routes                []costRoute
	Default               *target
	OnExhausted           string
	RespectRequestedModel bool

	// Legacy v0.9 fields are still populated when the old primary/fallback
	// shape is used. The current schema exposes Routes + Default, but keeping these avoids
	// surprising older API definitions during rollout.
	LegacyDefaultTier bool
	Primary           target
	Fallback          target
	BudgetLimits      []budgetLimit
	ConsumerBased     bool

	RequestModel    requestModelConfig
	CostScaleFactor int64

	Algorithm             string
	Backend               string
	Redis                 redisConfig
	MemoryCleanupInterval time.Duration
	Local                 localConfig
}

// parseConfig validates the user and system parameters supplied when the policy
// is attached. Every error names the exact offending field so that an invalid
// API definition fails fast with an actionable message.
func parseConfig(params map[string]interface{}) (config, error) {
	result := config{
		CostScaleFactor:       DefaultCostScaleFactor,
		Algorithm:             defaultAlgorithm,
		Backend:               defaultBackend,
		OnExhausted:           onExhaustedDefault,
		RespectRequestedModel: true,
	}

	if raw, exists := params["onExhausted"]; exists {
		value, ok := raw.(string)
		if !ok {
			return result, fmt.Errorf("'onExhausted' must be a string")
		}
		switch strings.TrimSpace(value) {
		case onExhaustedDefault, onExhaustedReject:
			result.OnExhausted = strings.TrimSpace(value)
		default:
			return result, fmt.Errorf("'onExhausted' must be one of default or reject")
		}
	}

	if raw, exists := params["respectRequestedModel"]; exists {
		value, ok := raw.(bool)
		if !ok {
			return result, fmt.Errorf("'respectRequestedModel' must be a boolean")
		}
		result.RespectRequestedModel = value
	}

	if raw, exists := params["consumerBased"]; exists {
		value, ok := raw.(bool)
		if !ok {
			return result, fmt.Errorf("'consumerBased' must be a boolean")
		}
		result.ConsumerBased = value
	}

	// The scale factor has to be resolved before the budget limits so the
	// limits can be scaled and overflow-checked in one pass.
	scaleFactor, err := parseCostScaleFactor(params)
	if err != nil {
		return result, err
	}
	result.CostScaleFactor = scaleFactor

	routes, defaultTarget, legacyDefaultTier, err := parseRoutingTargets(params, scaleFactor, result.OnExhausted)
	if err != nil {
		return result, err
	}
	result.Routes = routes
	result.Default = defaultTarget
	result.LegacyDefaultTier = legacyDefaultTier
	if len(routes) > 0 {
		result.Primary = routes[0].Target
		result.BudgetLimits = routes[0].BudgetLimits
	}
	if defaultTarget != nil {
		result.Fallback = *defaultTarget
	}

	requestModel, err := parseRequestModel(params["requestModel"])
	if err != nil {
		return result, err
	}
	result.RequestModel = requestModel

	if raw, exists := params["algorithm"]; exists {
		algorithm, ok := raw.(string)
		if !ok {
			return result, fmt.Errorf("'algorithm' must be a string")
		}
		switch algorithm {
		case "fixed-window", "gcra":
			result.Algorithm = algorithm
		default:
			return result, fmt.Errorf("'algorithm' must be one of fixed-window or gcra")
		}
	}

	if raw, exists := params["backend"]; exists {
		backend, ok := raw.(string)
		if !ok {
			return result, fmt.Errorf("'backend' must be a string")
		}
		switch backend {
		case "memory", "redis", "redis-local-async":
			result.Backend = backend
		default:
			return result, fmt.Errorf("'backend' must be one of memory, redis, or redis-local-async")
		}
	}

	result.Redis = redisConfig{
		Host:              getStringParam(params, "redis.host", "localhost"),
		Port:              getIntParam(params, "redis.port", 6379),
		Username:          getStringParam(params, "redis.username", ""),
		Password:          getStringParam(params, "redis.password", ""),
		DB:                getIntParam(params, "redis.db", 0),
		KeyPrefix:         getStringParam(params, "redis.keyPrefix", defaultRedisKeyPrefix),
		FailOpen:          getStringParam(params, "redis.failureMode", "open") == "open",
		ConnectionTimeout: getDurationParam(params, "redis.connectionTimeout", 5*time.Second),
		ReadTimeout:       getDurationParam(params, "redis.readTimeout", 3*time.Second),
		WriteTimeout:      getDurationParam(params, "redis.writeTimeout", 3*time.Second),
		PoolSize:          getIntParam(params, "redis.poolSize", 0),
	}
	result.MemoryCleanupInterval = getDurationParam(params, "memory.cleanupInterval", 5*time.Minute)
	result.Local = localConfig{
		SyncInterval:        getDurationParam(params, "local.syncInterval", 50*time.Millisecond),
		FlushWorkers:        getIntParam(params, "local.flushWorkers", 0),
		MaxPipelineCommands: getIntParam(params, "local.maxPipelineCommands", 0),
		MaxLocalEntries:     getIntParam(params, "local.maxLocalEntries", 0),
	}

	return result, nil
}

func parseRoutingTargets(params map[string]interface{}, scaleFactor int64, onExhausted string) ([]costRoute, *target, bool, error) {
	if rawRoutes, exists := params["routes"]; exists {
		routes, err := parseRoutes(rawRoutes, scaleFactor)
		if err != nil {
			return nil, nil, false, err
		}
		if params["default"] == nil {
			if onExhausted == onExhaustedDefault {
				return nil, nil, false, fmt.Errorf("'default' is required when 'onExhausted' is 'default'")
			}
			return routes, nil, false, nil
		}
		defaultTarget, err := parseTarget(params["default"], "default")
		if err != nil {
			return nil, nil, false, err
		}
		return routes, &defaultTarget, false, nil
	}

	primary, err := parseTarget(params["primary"], "primary")
	if err != nil {
		return nil, nil, false, err
	}
	fallback, err := parseTarget(params["fallback"], "fallback")
	if err != nil {
		return nil, nil, false, err
	}
	limits, err := parseBudgetLimits(params["budgetLimits"], scaleFactor, "budgetLimits")
	if err != nil {
		return nil, nil, false, err
	}
	return []costRoute{{
		Name:         tierPrimary,
		Target:       primary,
		BudgetLimits: limits,
	}}, &fallback, true, nil
}

func parseRoutes(raw interface{}, scaleFactor int64) ([]costRoute, error) {
	if raw == nil {
		return nil, fmt.Errorf("'routes' is required")
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'routes' must be an array")
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("'routes' must contain at least one entry")
	}

	names := map[string]struct{}{}
	routes := make([]costRoute, 0, len(items))
	for i, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("'routes[%d]' must be an object", i)
		}

		name := fmt.Sprintf("route-%d", i+1)
		if rawName, exists := entry["name"]; exists {
			value, ok := rawName.(string)
			if !ok || strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("'routes[%d].name' must be a non-empty string when supplied", i)
			}
			name = strings.TrimSpace(value)
		}
		if _, exists := names[name]; exists {
			return nil, fmt.Errorf("'routes[%d].name' duplicates route name %q", i, name)
		}
		names[name] = struct{}{}

		target, err := parseTarget(entry["target"], fmt.Sprintf("routes[%d].target", i))
		if err != nil {
			return nil, err
		}
		limits, err := parseBudgetLimits(entry["budgetLimits"], scaleFactor, fmt.Sprintf("routes[%d].budgetLimits", i))
		if err != nil {
			return nil, err
		}

		routes = append(routes, costRoute{Name: name, Target: target, BudgetLimits: limits})
	}
	return routes, nil
}

// parseTarget validates a routing target. provider is optional but,
// when supplied, must be a non-empty string: an empty upstream name would be
// forwarded to the router as an invalid cluster.
func parseTarget(raw interface{}, field string) (target, error) {
	item, ok := raw.(map[string]interface{})
	if !ok {
		return target{}, fmt.Errorf("'%s' must be an object", field)
	}
	rawModel, exists := item["model"]
	if !exists {
		return target{}, fmt.Errorf("'%s.model' is required", field)
	}
	model, ok := rawModel.(string)
	if !ok || strings.TrimSpace(model) == "" {
		return target{}, fmt.Errorf("'%s.model' must be a non-empty string", field)
	}
	parsed := target{Model: strings.TrimSpace(model)}
	if rawProvider, exists := item["provider"]; exists {
		provider, ok := rawProvider.(string)
		if !ok || strings.TrimSpace(provider) == "" {
			return target{}, fmt.Errorf("'%s.provider' must be a non-empty string when supplied", field)
		}
		parsed.Provider = strings.TrimSpace(provider)
	}
	return parsed, nil
}

func parseBudgetLimits(raw interface{}, scaleFactor int64, field string) ([]budgetLimit, error) {
	if raw == nil {
		return nil, fmt.Errorf("'%s' is required", field)
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' must be an array", field)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("'%s' must contain at least one entry", field)
	}

	limits := make([]budgetLimit, 0, len(items))
	for i, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("'%s[%d]' must be an object", field, i)
		}

		rawAmount, exists := entry["amount"]
		if !exists {
			return nil, fmt.Errorf("'%s[%d].amount' is required", field, i)
		}
		amount, ok := floatValue(rawAmount)
		if !ok {
			return nil, fmt.Errorf("'%s[%d].amount' must be a number", field, i)
		}
		if math.IsNaN(amount) || math.IsInf(amount, 0) || amount <= 0 {
			return nil, fmt.Errorf("'%s[%d].amount' must be greater than zero", field, i)
		}

		scaled, err := scaleDollars(amount, scaleFactor)
		if err != nil {
			return nil, fmt.Errorf("'%s[%d].amount' cannot be scaled by costScaleFactor %d: %w", field, i, scaleFactor, err)
		}
		if scaled <= 0 {
			return nil, fmt.Errorf("'%s[%d].amount' is too small to represent with costScaleFactor %d", field, i, scaleFactor)
		}

		rawDuration, exists := entry["duration"]
		if !exists {
			return nil, fmt.Errorf("'%s[%d].duration' is required", field, i)
		}
		durationText, ok := rawDuration.(string)
		if !ok || strings.TrimSpace(durationText) == "" {
			return nil, fmt.Errorf("'%s[%d].duration' must be a non-empty Go duration string", field, i)
		}
		duration, err := time.ParseDuration(strings.TrimSpace(durationText))
		if err != nil {
			return nil, fmt.Errorf("'%s[%d].duration' is not a valid Go duration: %w", field, i, err)
		}
		if duration <= 0 {
			return nil, fmt.Errorf("'%s[%d].duration' must be greater than zero", field, i)
		}

		limits = append(limits, budgetLimit{Amount: amount, Duration: duration, Scaled: scaled})
	}
	return limits, nil
}

func parseCostScaleFactor(params map[string]interface{}) (int64, error) {
	raw, exists := params["costScaleFactor"]
	if !exists {
		if systemParams, ok := params["systemParameters"].(map[string]interface{}); ok {
			raw, exists = systemParams["costScaleFactor"]
		}
	}
	if !exists || raw == nil {
		return DefaultCostScaleFactor, nil
	}
	value, err := integerValue(raw)
	if err != nil || value < 1 {
		return DefaultCostScaleFactor, fmt.Errorf("'costScaleFactor' must be an integer greater than zero")
	}
	return value, nil
}

func parseRequestModel(raw interface{}) (requestModelConfig, error) {
	result := requestModelConfig{}
	item, ok := raw.(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("'requestModel' system parameter is required")
	}

	location, ok := item["location"].(string)
	if !ok {
		return result, fmt.Errorf("'requestModel.location' must be a string")
	}
	// "body" is emitted by early custom provider templates. Accept it as a
	// backwards-compatible alias for the canonical "payload" location, matching
	// the other model-routing policies.
	if location == "body" {
		location = "payload"
	}
	switch location {
	case "payload", "header", "queryParam", "pathParam":
	default:
		return result, fmt.Errorf("'requestModel.location' must be one of payload, header, queryParam, or pathParam")
	}

	identifier, ok := item["identifier"].(string)
	if !ok || strings.TrimSpace(identifier) == "" {
		return result, fmt.Errorf("'requestModel.identifier' must be a non-empty string")
	}

	result.Location = location
	result.Identifier = strings.TrimSpace(identifier)

	if location == "pathParam" {
		expression, group, err := compilePathModelExpression(result.Identifier)
		if err != nil {
			return result, fmt.Errorf("'requestModel.identifier' is not a valid model path expression: %w", err)
		}
		result.PathExpression = expression
		result.PathModelGroup = group
	}
	return result, nil
}

// compilePathModelExpression compiles a provider-template model expression once
// when the policy is attached. Expressions with a capture group replace the
// first captured value (for example Bedrock's model/(...)/); an expression
// without one is rejected because replacing the whole match would rewrite the
// surrounding path segments too. A simple leading positive lookbehind is
// normalized because Go's RE2 engine intentionally does not support lookbehind;
// Gemini's built-in template uses that form.
func compilePathModelExpression(expression string) (*regexp.Regexp, int, error) {
	const lookbehindPrefix = "(?<="
	normalized := expression
	modelGroupName := ""
	if strings.HasPrefix(expression, lookbehindPrefix) {
		closing := strings.Index(expression[len(lookbehindPrefix):], ")")
		if closing < 0 {
			return nil, 0, fmt.Errorf("unterminated positive lookbehind")
		}
		closing += len(lookbehindPrefix)
		prefix := expression[len(lookbehindPrefix):closing]
		suffix := expression[closing+1:]
		if prefix == "" || suffix == "" {
			return nil, 0, fmt.Errorf("positive lookbehind must contain a prefix and a model expression")
		}
		modelGroupName = "cost_based_routing_model"
		normalized = "(?:" + prefix + ")(?P<" + modelGroupName + ">" + suffix + ")"
	}

	compiled, err := regexp.Compile(normalized)
	if err != nil {
		return nil, 0, err
	}
	if modelGroupName != "" {
		return compiled, compiled.SubexpIndex(modelGroupName), nil
	}
	if compiled.NumSubexp() == 0 {
		return nil, 0, fmt.Errorf("expression must contain a capture group identifying the model segment")
	}
	return compiled, 1, nil
}

// scaleDollars converts a dollar amount into the integer unit used by the
// storage backend, rejecting values that would overflow int64.
func scaleDollars(amount float64, scaleFactor int64) (int64, error) {
	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return 0, fmt.Errorf("amount is not a finite number")
	}
	scaled := amount * float64(scaleFactor)
	if scaled >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("scaled amount exceeds the maximum supported value")
	}
	return int64(scaled), nil
}

func integerValue(raw interface{}) (int64, error) {
	switch value := raw.(type) {
	case int:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return value, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) ||
			value > math.MaxInt64 || value < math.MinInt64 {
			return 0, fmt.Errorf("not an integer")
		}
		return int64(value), nil
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func floatValue(raw interface{}) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int32:
		return float64(value), true
	case int64:
		return float64(value), true
	default:
		return 0, false
	}
}

// getStringParam and its siblings resolve dotted system-parameter paths such as
// "redis.host" against the nested parameter map, matching how advanced-ratelimit
// reads the same shared configuration block.
func getStringParam(params map[string]interface{}, key string, defaultVal string) string {
	raw, ok := nestedParam(params, key)
	if !ok {
		return defaultVal
	}
	if value, ok := raw.(string); ok {
		return value
	}
	return defaultVal
}

func getIntParam(params map[string]interface{}, key string, defaultVal int) int {
	raw, ok := nestedParam(params, key)
	if !ok {
		return defaultVal
	}
	if value, err := integerValue(raw); err == nil {
		return int(value)
	}
	return defaultVal
}

func getDurationParam(params map[string]interface{}, key string, defaultVal time.Duration) time.Duration {
	raw, ok := nestedParam(params, key)
	if !ok {
		return defaultVal
	}
	if value, ok := raw.(string); ok {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultVal
}

func nestedParam(params map[string]interface{}, key string) (interface{}, bool) {
	segments := strings.Split(key, ".")
	current := params
	for i, segment := range segments {
		if i == len(segments)-1 {
			value, ok := current[segment]
			return value, ok
		}
		next, ok := current[segment].(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = next
	}
	return nil, false
}
