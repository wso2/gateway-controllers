package dynamicendpoint

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// maxExpressionLength bounds backendExpression, as advanced-ratelimit bounds its cel key
// expressions.
const maxExpressionLength = 1024

// The CEL variables backendExpression can read. They follow the names advanced-ratelimit's cel
// key extraction uses, plus the authentication context an earlier auth policy set.
var (
	expressionEnv     *cel.Env
	expressionEnvErr  error
	expressionEnvOnce sync.Once
)

func backendExpressionEnv() (*cel.Env, error) {
	expressionEnvOnce.Do(func() {
		expressionEnv, expressionEnvErr = cel.NewEnv(
			// Request: the headers as they reach this policy (lower-case names, so a header an
			// earlier policy set is visible), the path, the method and the shared metadata
			// earlier policies wrote.
			cel.Variable("request.Headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
			cel.Variable("request.Path", cel.StringType),
			cel.Variable("request.Method", cel.StringType),
			cel.Variable("request.Metadata", cel.MapType(cel.StringType, cel.DynType)),
			// The API and route the request matched.
			cel.Variable("api.Name", cel.StringType),
			cel.Variable("api.Version", cel.StringType),
			cel.Variable("api.Context", cel.StringType),
			cel.Variable("api.Id", cel.StringType),
			cel.Variable("route.Name", cel.StringType),
			// The authenticated principal; empty when no auth policy ran before this one.
			cel.Variable("auth.Subject", cel.StringType),
			cel.Variable("auth.Properties", cel.MapType(cel.StringType, cel.StringType)),
			// split, lowerAscii, substring, replace, trim and the rest of the string extensions.
			ext.Strings(),
		)
	})
	return expressionEnv, expressionEnvErr
}

// backendExpression is a compiled CEL parameter: backendExpression, or backendKeyExpression,
// which reads the same variables.
type backendExpression struct {
	param   string
	source  string
	program cel.Program
}

// compileBackendExpression compiles a backendExpression.
func compileBackendExpression(source string) (*backendExpression, error) {
	return compileExpression("backendExpression", source)
}

// compileExpression compiles the CEL parameter param and checks that it yields a string, so a
// typo or a wrong result type rejects the configuration instead of failing every request.
func compileExpression(param, source string) (*backendExpression, error) {
	// Counted in characters, as the definition's maxLength counts them, not in UTF-8 bytes.
	if utf8.RuneCountInString(source) > maxExpressionLength {
		return nil, fmt.Errorf("dynamic-endpoint: %s must be at most %d characters", param, maxExpressionLength)
	}
	env, err := backendExpressionEnv()
	if err != nil {
		return nil, fmt.Errorf("dynamic-endpoint: CEL environment: %w", err)
	}
	ast, issues := env.Compile(source)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("dynamic-endpoint: %s does not compile: %w", param, issues.Err())
	}
	if out := ast.OutputType(); !out.IsExactType(cel.StringType) && !out.IsExactType(cel.DynType) {
		return nil, fmt.Errorf("dynamic-endpoint: %s must return a string, not %s", param, out)
	}
	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("dynamic-endpoint: %s: %w", param, err)
	}
	return &backendExpression{param: param, source: source, program: program}, nil
}

// expressionResult is what one evaluation produced: a value to route by, no value (value ""),
// or a value that is not a string (malformed).
type expressionResult struct {
	value     string
	malformed bool
}

// missingInputError matches the CEL evaluation errors raised when the request lacks what the
// expression reads: a header, metadata key or claim that is absent (no such key, no such
// attribute), or an index past the end of a list (for example a split that found no separator).
// cel-go exports no type for them, so they are matched by message, anchored at its start: other
// errors can quote a request value (an invalid timestamp quotes the header it failed on), and a
// value that merely contains one of these phrases must not pass for a missing input. Any other
// evaluation error — a present value that fails a conversion, for example — is malformed, so an
// unrecognised error fails closed with a 400 rather than falling back.
var missingInputError = regexp.MustCompile(
	`^(?:no such key: |no such attribute\(s\): |index out of bounds: |index '\d+' out of range in list size '\d+'$)`)

func isMissingInput(err error) bool {
	return missingInputError.MatchString(err.Error())
}

// evaluate runs the expression against one request. A missing input — a header, key, claim or
// index the request does not have — and an empty or null result mean the request carries no
// value; any other evaluation error, and a result that is not a string, are malformed.
func (e *backendExpression) evaluate(reqCtx *policy.RequestHeaderContext, routeName string) expressionResult {
	out, _, err := e.program.Eval(activation(reqCtx, routeName))
	if err != nil {
		// The CEL error itself is not logged: some errors quote the request value they failed
		// on (an invalid timestamp, for example), and request values stay out of the log.
		if isMissingInput(err) {
			slog.Debug("[Dynamic Endpoint]: expression yielded no value", "parameter", e.param, "expression", e.source, "reason", "missing_input")
			return expressionResult{}
		}
		slog.Debug("[Dynamic Endpoint]: expression failed on the request's values", "parameter", e.param, "expression", e.source, "reason", "evaluation_error")
		return expressionResult{malformed: true}
	}
	switch v := out.(type) {
	case types.String:
		return expressionResult{value: strings.TrimSpace(string(v))}
	case types.Null:
		return expressionResult{}
	default:
		slog.Debug("[Dynamic Endpoint]: expression returned a non-string value",
			"parameter", e.param, "expression", e.source, "type", out.Type())
		return expressionResult{malformed: true}
	}
}

// activation binds the CEL variables for one request.
func activation(reqCtx *policy.RequestHeaderContext, routeName string) map[string]interface{} {
	vars := map[string]interface{}{
		"request.Headers":  map[string][]string{},
		"request.Path":     "",
		"request.Method":   "",
		"request.Metadata": map[string]interface{}{},
		"api.Name":         "",
		"api.Version":      "",
		"api.Context":      "",
		"api.Id":           "",
		"route.Name":       routeName,
		"auth.Subject":     "",
		"auth.Properties":  map[string]string{},
	}
	if reqCtx == nil {
		return vars
	}
	if reqCtx.Headers != nil {
		vars["request.Headers"] = reqCtx.Headers.GetAll()
	}
	vars["request.Path"] = reqCtx.Path
	vars["request.Method"] = reqCtx.Method
	if shared := reqCtx.SharedContext; shared != nil {
		if shared.Metadata != nil {
			vars["request.Metadata"] = shared.Metadata
		}
		vars["api.Name"] = shared.APIName
		vars["api.Version"] = shared.APIVersion
		vars["api.Context"] = shared.APIContext
		vars["api.Id"] = shared.APIId
		if auth := shared.AuthContext; auth != nil {
			vars["auth.Subject"] = auth.Subject
			if auth.Properties != nil {
				vars["auth.Properties"] = auth.Properties
			}
		}
	}
	return vars
}
