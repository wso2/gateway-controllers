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

package logmessage

import (
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"google.golang.org/protobuf/types/known/structpb"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// CELEvaluator evaluates CEL expressions used by the `properties` param's
// `$ctx:` syntax, giving property values access to the full CEL language
// (arithmetic, string ops, conditionals, and list/map macros like
// has()/exists()/join()) instead of a fixed enum of dotted context
// references. Mirrors the advanced-ratelimit policy's CELEvaluator
// (compiled-program cache behind a singleton environment), but — unlike
// ratelimit's key/cost environments, which constrain the result type to
// string/numeric — an expression here may evaluate to any CEL value; the
// result is converted to a plain Go value and passed through to the emitted
// log line as-is.
type CELEvaluator struct {
	mu           sync.RWMutex
	programCache map[string]cel.Program
	env          *cel.Env
}

var (
	globalCELEvaluator *CELEvaluator
	celEvaluatorOnce   sync.Once
	celInitErr         error
)

// GetCELEvaluator returns the singleton CEL evaluator instance.
func GetCELEvaluator() (*CELEvaluator, error) {
	celEvaluatorOnce.Do(func() {
		evaluator, err := newCELEvaluator()
		if err != nil {
			celInitErr = err
			return
		}
		globalCELEvaluator = evaluator
	})
	if celInitErr != nil {
		return nil, celInitErr
	}
	return globalCELEvaluator, nil
}

func newCELEvaluator() (*CELEvaluator, error) {
	env, err := createPropertyExtractionEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create property-extraction CEL environment: %w", err)
	}
	return &CELEvaluator{
		programCache: make(map[string]cel.Program),
		env:          env,
	}, nil
}

// createPropertyExtractionEnv declares every `$ctx:` variable available to a
// `properties` expression, plus the `ext.Strings()` extension library (join,
// split, replace, trim, quote, format, …) so expressions can shape values
// without a bespoke CEL function per use case.
//
// request.header and auth.property are maps rather than one variable per
// header/claim name (impossible to declare ahead of time for arbitrary
// names): index them with bracket syntax, e.g. request.header['x-tenant-id']
// or auth.property['custom_claim']. request.header keys are always
// lower-cased (see buildPropertyEvalContext) — reference them in lowercase
// regardless of how the client sent the header. auth.property keys are
// case-sensitive, matching the original claim names.
func createPropertyExtractionEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.Strings(),

		cel.Variable("request.path", cel.StringType),
		cel.Variable("request.method", cel.StringType),
		cel.Variable("request.authority", cel.StringType),
		cel.Variable("request.scheme", cel.StringType),
		cel.Variable("request.vhost", cel.StringType),
		cel.Variable("request.id", cel.StringType),
		cel.Variable("request.header", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		// request.metadata is the escape hatch for genuinely dynamic data: SharedContext's
		// inter-policy Metadata map, whose keys are set by whatever other policies ran
		// earlier in the chain and are not knowable ahead of time (unlike every other
		// variable here, which names a fixed SDK field). cel.DynType lets each value be
		// whatever type that other policy stored (string, number, bool, nested map, …).
		cel.Variable("request.metadata", cel.MapType(cel.StringType, cel.DynType)),

		cel.Variable("api.id", cel.StringType),
		cel.Variable("api.name", cel.StringType),
		cel.Variable("api.version", cel.StringType),
		cel.Variable("api.context", cel.StringType),
		cel.Variable("api.kind", cel.StringType),
		cel.Variable("api.operation_path", cel.StringType),

		cel.Variable("project.id", cel.StringType),

		// auth.* variables are declared here but only bound in the evaluation
		// context (see buildPropertyEvalContext) when AuthContext is non-nil.
		// An expression referencing any auth.* variable when no auth policy ran
		// fails evaluation with an unbound-variable error, which EvaluateProperty
		// treats like any other evaluation failure: the property is skipped.
		cel.Variable("auth.subject", cel.StringType),
		cel.Variable("auth.type", cel.StringType),
		cel.Variable("auth.issuer", cel.StringType),
		cel.Variable("auth.credential_id", cel.StringType),
		cel.Variable("auth.token_id", cel.StringType),
		cel.Variable("auth.authenticated", cel.BoolType),
		cel.Variable("auth.authorized", cel.BoolType),
		cel.Variable("auth.audience", cel.ListType(cel.StringType)),
		cel.Variable("auth.scopes", cel.ListType(cel.StringType)),
		cel.Variable("auth.property", cel.MapType(cel.StringType, cel.StringType)),
	)
}

// EvaluateProperty compiles (or reuses a cached compilation of) expression
// and evaluates it against evalCtx, returning a plain Go value (string,
// bool, float64, []interface{}, map[string]interface{}, or nil) suitable for
// JSON marshaling in the emitted log line. Numbers always come back as
// float64 — structpb.Value has no separate integer variant, mirroring JSON's
// own lack of an int/float distinction — even if the CEL expression's result
// type was int64 (e.g. a plain integer stored in request.metadata).
func (e *CELEvaluator) EvaluateProperty(expression string, evalCtx map[string]interface{}) (interface{}, error) {
	program, err := e.getOrCompileProgram(expression)
	if err != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", err)
	}

	result, _, err := program.Eval(evalCtx)
	if err != nil {
		return nil, fmt.Errorf("CEL evaluation failed: %w", err)
	}

	goVal, err := celToGoValue(result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CEL result: %w", err)
	}
	return goVal, nil
}

// getOrCompileProgram gets a cached program or compiles a new one.
func (e *CELEvaluator) getOrCompileProgram(expression string) (cel.Program, error) {
	e.mu.RLock()
	if program, ok := e.programCache[expression]; ok {
		e.mu.RUnlock()
		return program, nil
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if program, ok := e.programCache[expression]; ok {
		return program, nil
	}

	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation failed: %w", issues.Err())
	}

	program, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation failed: %w", err)
	}

	e.programCache[expression] = program
	return program, nil
}

// celToGoValue converts a CEL result to a plain Go value that encoding/json
// can marshal directly. Routing through structpb.Value recursively converts
// nested CEL lists/maps into []interface{}/map[string]interface{}, mirroring
// how a JSON value tree looks, rather than leaving cel-go's internal
// traits.Lister/traits.Mapper wrapper types in the output.
func celToGoValue(val ref.Val) (interface{}, error) {
	native, err := val.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
	if err != nil {
		return nil, err
	}
	pbVal, ok := native.(*structpb.Value)
	if !ok {
		return nil, fmt.Errorf("unexpected CEL native conversion result type %T", native)
	}
	return pbVal.AsInterface(), nil
}

// buildPropertyEvalContext builds the CEL evaluation context for a request.
// request/api/project variables are always bound (they are always populated
// on RequestHeaderContext). auth.* variables are bound as a group only when
// AuthContext is non-nil — see createPropertyExtractionEnv's comment on why
// a missing auth.* binding is the mechanism that makes those references
// "unresolvable" when no auth policy ran, matching this policy's documented
// behavior for auth.* properties.
func buildPropertyEvalContext(reqCtx *policy.RequestHeaderContext) map[string]interface{} {
	headers := make(map[string][]string)
	if reqCtx.Headers != nil {
		for name, values := range reqCtx.Headers.GetAll() {
			headers[name] = values
		}
	}

	// Snapshot Metadata rather than binding the live map: it is mutable shared
	// state other policies write into, so evaluation should see a stable copy
	// rather than racing a concurrent writer (defensive; matches the pattern
	// SharedContext's own accessors use).
	metadata := make(map[string]interface{})
	if reqCtx.Metadata != nil {
		for k, v := range reqCtx.Metadata {
			metadata[k] = v
		}
	}

	evalCtx := map[string]interface{}{
		"request.path":      reqCtx.Path,
		"request.method":    reqCtx.Method,
		"request.authority": reqCtx.Authority,
		"request.scheme":    reqCtx.Scheme,
		"request.vhost":     reqCtx.Vhost,
		"request.id":        reqCtx.RequestID,
		"request.header":    headers,
		"request.metadata":  metadata,

		"api.id":             reqCtx.APIId,
		"api.name":           reqCtx.APIName,
		"api.version":        reqCtx.APIVersion,
		"api.context":        reqCtx.APIContext,
		"api.kind":           string(reqCtx.APIKind),
		"api.operation_path": reqCtx.OperationPath,

		"project.id": reqCtx.ProjectID,
	}

	if authCtx := reqCtx.AuthContext; authCtx != nil {
		audience := authCtx.Audience
		if audience == nil {
			audience = []string{}
		}
		scopes := make([]string, 0, len(authCtx.Scopes))
		for name := range authCtx.Scopes {
			scopes = append(scopes, name)
		}
		sort.Strings(scopes)
		properties := authCtx.Properties
		if properties == nil {
			properties = map[string]string{}
		}

		evalCtx["auth.subject"] = authCtx.Subject
		evalCtx["auth.type"] = authCtx.AuthType
		evalCtx["auth.issuer"] = authCtx.Issuer
		evalCtx["auth.credential_id"] = authCtx.CredentialID
		evalCtx["auth.token_id"] = authCtx.TokenId
		evalCtx["auth.authenticated"] = authCtx.Authenticated
		evalCtx["auth.authorized"] = authCtx.Authorized
		evalCtx["auth.audience"] = audience
		evalCtx["auth.scopes"] = scopes
		evalCtx["auth.property"] = properties
	}

	return evalCtx
}
