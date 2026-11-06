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

package backendjwt

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

// callerClaims is the non-standard part of the caller token in issue #3979.
const callerClaims = `{"roles":["OrganizationAdmin","B"],"groups":["g1","g2"],"org":{"id":"o1"},"amount":1.5,"active":true,"tier":"gold"}`

// jwtAuthContext builds the AuthContext jwt-auth produces for callerClaims: Properties flattened
// the way jwt-auth's claimValueToString does (a float64 loses its fraction), TypedProperties
// holding the claims as the token carried them.
func jwtAuthContext(t *testing.T) *policy.AuthContext {
	t.Helper()
	typed := map[string]interface{}{}
	if err := json.Unmarshal([]byte(callerClaims), &typed); err != nil {
		t.Fatal(err)
	}
	props := map[string]string{
		"roles":  `["OrganizationAdmin","B"]`,
		"groups": `["g1","g2"]`,
		"org":    `{"id":"o1"}`,
		"amount": "1",
		"active": "true",
		"tier":   "gold",
	}
	return &policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "u1",
		Properties: props, TypedProperties: typed,
	}
}

// backendClaims runs the policy and returns the claims of the backend JWT it generated.
func backendClaims(t *testing.T, authCtx *policy.AuthContext, extra map[string]interface{}) map[string]interface{} {
	t.Helper()
	rsaKey, keyPEM := generateRSAKey(t)
	params := baseParams(keyPEM)
	for k, v := range extra {
		params[k] = v
	}
	result := newTestPolicy().OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	return decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)
}

func typedWant() map[string]interface{} {
	return map[string]interface{}{
		"roles":  []interface{}{"OrganizationAdmin", "B"},
		"groups": []interface{}{"g1", "g2"},
		"org":    map[string]interface{}{"id": "o1"},
		"amount": 1.5,
		"active": true,
		"tier":   "gold",
	}
}

func TestTypedClaims_AutoForward(t *testing.T) {
	claims := backendClaims(t, jwtAuthContext(t), nil)
	for k, want := range typedWant() {
		if !reflect.DeepEqual(claims[k], want) {
			t.Errorf("%s = %#v, want %#v", k, claims[k], want)
		}
	}
}

func TestTypedClaims_ClaimMappings(t *testing.T) {
	claims := backendClaims(t, jwtAuthContext(t), map[string]interface{}{
		"claimMappings": map[string]interface{}{"app_roles": "roles", "app_amount": "amount"},
	})
	if want := []interface{}{"OrganizationAdmin", "B"}; !reflect.DeepEqual(claims["app_roles"], want) {
		t.Errorf("app_roles = %#v, want %#v", claims["app_roles"], want)
	}
	if claims["app_amount"] != 1.5 {
		t.Errorf("app_amount = %#v, want 1.5", claims["app_amount"])
	}
	// A mapped source is not also forwarded under its own name.
	if _, ok := claims["roles"]; ok {
		t.Error("roles was forwarded although claimMappings consumed it")
	}
}

func TestTypedClaims_CtxReference(t *testing.T) {
	claims := backendClaims(t, jwtAuthContext(t), map[string]interface{}{
		"customClaims": map[string]interface{}{
			"ctx_groups": "$ctx:auth.property.groups",
			"ctx_org":    "$ctx:auth.property.org",
			"ctx_tier":   "$ctx:auth.property.tier",
			"ctx_gone":   "$ctx:auth.property.absent",
		},
	})
	if want := []interface{}{"g1", "g2"}; !reflect.DeepEqual(claims["ctx_groups"], want) {
		t.Errorf("ctx_groups = %#v, want %#v", claims["ctx_groups"], want)
	}
	if want := map[string]interface{}{"id": "o1"}; !reflect.DeepEqual(claims["ctx_org"], want) {
		t.Errorf("ctx_org = %#v, want %#v", claims["ctx_org"], want)
	}
	if claims["ctx_tier"] != "gold" {
		t.Errorf("ctx_tier = %#v, want gold", claims["ctx_tier"])
	}
	if _, ok := claims["ctx_gone"]; ok {
		t.Error("an unresolvable reference must still be skipped")
	}
}

func TestTypedClaims_StaticCustomClaimUnchanged(t *testing.T) {
	claims := backendClaims(t, jwtAuthContext(t), map[string]interface{}{
		"customClaims": map[string]interface{}{"static_roles": []interface{}{"A", "B"}},
	})
	if want := []interface{}{"A", "B"}; !reflect.DeepEqual(claims["static_roles"], want) {
		t.Errorf("static_roles = %#v, want %#v", claims["static_roles"], want)
	}
}

// customClaims keep winning over claimMappings for the same destination, whichever types the two
// values have.
func TestTypedClaims_CustomClaimsTakePrecedence(t *testing.T) {
	cases := map[string]interface{}{
		"string over array": "fixed",
		"array over array":  []interface{}{"X"},
		"number over array": 7.0,
	}
	for name, custom := range cases {
		t.Run(name, func(t *testing.T) {
			claims := backendClaims(t, jwtAuthContext(t), map[string]interface{}{
				"claimMappings": map[string]interface{}{"dest": "roles"},
				"customClaims":  map[string]interface{}{"dest": custom},
			})
			if !reflect.DeepEqual(claims["dest"], custom) {
				t.Errorf("dest = %#v, want the customClaims value %#v", claims["dest"], custom)
			}
		})
	}

	t.Run("array mapping over unresolvable custom claim", func(t *testing.T) {
		claims := backendClaims(t, jwtAuthContext(t), map[string]interface{}{
			"claimMappings": map[string]interface{}{"dest": "roles"},
			"customClaims":  map[string]interface{}{"dest": "$ctx:auth.property.absent"},
		})
		if want := []interface{}{"OrganizationAdmin", "B"}; !reflect.DeepEqual(claims["dest"], want) {
			t.Errorf("dest = %#v, want the mapped value %#v", claims["dest"], want)
		}
	})
}

// An auth policy that records only Properties (basic-auth, api-key-auth, opaque-token-auth)
// still forwards its values, as strings.
func TestTypedClaims_FallsBackToProperties(t *testing.T) {
	authCtx := &policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "u1",
		Properties: map[string]string{"team": "core", "roles": `["A"]`},
	}
	claims := backendClaims(t, authCtx, map[string]interface{}{
		"claimMappings": map[string]interface{}{"mapped_team": "team"},
		"customClaims":  map[string]interface{}{"ctx_roles": "$ctx:auth.property.roles"},
	})
	// "team" is consumed by the mapping, so it is not also forwarded under its own name.
	for k, want := range map[string]string{"roles": `["A"]`, "mapped_team": "core", "ctx_roles": `["A"]`} {
		if claims[k] != want {
			t.Errorf("%s = %#v, want the string %q", k, claims[k], want)
		}
	}
}

// A nil claim is absent from TypedProperties, so the flattened "null" is what is forwarded.
func TestTypedClaims_NullClaimFallsBackToProperties(t *testing.T) {
	authCtx := &policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "u1",
		Properties:      map[string]string{"nothing": "null", "roles": `["A"]`},
		TypedProperties: map[string]interface{}{"roles": []interface{}{"A"}},
	}
	claims := backendClaims(t, authCtx, nil)
	if claims["nothing"] != "null" {
		t.Errorf("nothing = %#v, want the string \"null\"", claims["nothing"])
	}
	if want := []interface{}{"A"}; !reflect.DeepEqual(claims["roles"], want) {
		t.Errorf("roles = %#v, want %#v", claims["roles"], want)
	}
}

func TestTypedClaims_ExcludedAndDialect(t *testing.T) {
	claims := backendClaims(t, jwtAuthContext(t), map[string]interface{}{
		"excludedClaims": []interface{}{"groups"},
		"dialect":        "http://wso2.org/claims/",
	})
	if _, ok := claims["http://wso2.org/claims/groups"]; ok {
		t.Error("an excluded claim was forwarded")
	}
	if want := []interface{}{"OrganizationAdmin", "B"}; !reflect.DeepEqual(claims["http://wso2.org/claims/roles"], want) {
		t.Errorf("prefixed roles = %#v, want %#v", claims["http://wso2.org/claims/roles"], want)
	}
}

// Auth types other than jwt are not auto-forwarded.
func TestTypedClaims_NoAutoForwardForOtherAuthTypes(t *testing.T) {
	authCtx := jwtAuthContext(t)
	authCtx.AuthType = "mcp/oauth"
	claims := backendClaims(t, authCtx, map[string]interface{}{
		"claimMappings": map[string]interface{}{"app_roles": "roles"},
	})
	if _, ok := claims["groups"]; ok {
		t.Error("claims were auto-forwarded for a non-jwt auth type")
	}
	if want := []interface{}{"OrganizationAdmin", "B"}; !reflect.DeepEqual(claims["app_roles"], want) {
		t.Errorf("app_roles = %#v, want %#v", claims["app_roles"], want)
	}
}

// Properties is lossy (1.5 and 1.4 both become "1"), so two callers that differ only in a typed
// value must not share a cached backend JWT.
func TestTypedClaims_CacheKeyIncludesTypedProperties(t *testing.T) {
	mk := func(amount float64) *policy.AuthContext {
		return &policy.AuthContext{
			Authenticated: true, AuthType: "jwt", Subject: "u1", // no TokenId: the identity key
			Properties:      map[string]string{"amount": "1"},
			TypedProperties: map[string]interface{}{"amount": amount},
		}
	}
	ns := keyNamespace{apiName: "api", algorithm: "SHA256withRSA"}
	if buildTokenCacheKey(ns, mk(1.5), "/p", "GET", resolvedClaims{}) == buildTokenCacheKey(ns, mk(1.4), "/p", "GET", resolvedClaims{}) {
		t.Error("typed values 1.5 and 1.4 share a cache key")
	}
}

func TestTypedClaims_CacheDoesNotMixTypes(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	run := func(amount float64) interface{} {
		authCtx := &policy.AuthContext{
			Authenticated: true, AuthType: "jwt", Subject: "u1",
			Properties:      map[string]string{"amount": "1"},
			TypedProperties: map[string]interface{}{"amount": amount},
		}
		mods := p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params).(policy.UpstreamRequestHeaderModifications)
		return decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)["amount"]
	}
	if got := run(1.5); got != 1.5 {
		t.Fatalf("first caller: amount = %#v, want 1.5", got)
	}
	if got := run(1.4); got != 1.4 {
		t.Errorf("second caller: amount = %#v, want 1.4 (a cached token for 1.5 was served)", got)
	}
}

// A non-string claim and a string that print the same must not collide in the key.
func TestTokenCacheKey_RawClaimTypeDistinguished(t *testing.T) {
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "u1", TokenId: "t"}
	ns := keyNamespace{apiName: "api", algorithm: "SHA256withRSA"}
	num := buildTokenCacheKey(ns, authCtx, "/p", "GET", resolvedClaims{rawClaims: map[string]interface{}{"n": 1.0}})
	str := buildTokenCacheKey(ns, authCtx, "/p", "GET", resolvedClaims{stringClaims: map[string]string{"n": "1"}})
	if num == str {
		t.Error("the number 1 and the string \"1\" share a cache key")
	}
}

// Negative test for v1.2. v1.2 reads only AuthContext.Properties, so the same authenticated
// context that v2 forwards typed reaches the upstream as strings: roles as JSON text inside a
// string and 1.5 truncated to "1" (wso2/api-platform#3979). The helper below is that v1.2 read
// path; the test asserts it cannot satisfy the typed expectation v2 meets.
func TestTypedClaims_V1PropertiesOnlyReadBreaks(t *testing.T) {
	authCtx := jwtAuthContext(t)

	v1Claims := map[string]interface{}{}
	for k, v := range authCtx.Properties { // v1.2: Properties only
		v1Claims[k] = v
	}
	v2Claims := backendClaims(t, authCtx, nil)

	for k, want := range typedWant() {
		if _, isString := want.(string); isString {
			continue // a string claim is identical in v1.2 and v2
		}
		if reflect.DeepEqual(v1Claims[k], want) {
			t.Errorf("%s: the v1.2 Properties-only read produced the typed value %#v; the negative test no longer shows the break", k, want)
		}
		if !reflect.DeepEqual(v2Claims[k], want) {
			t.Errorf("%s: v2 = %#v, want %#v", k, v2Claims[k], want)
		}
	}
	if v1Claims["roles"] != `["OrganizationAdmin","B"]` || v1Claims["amount"] != "1" {
		t.Errorf("v1.2 read = roles %#v, amount %#v; want the JSON string and \"1\"", v1Claims["roles"], v1Claims["amount"])
	}
}

// tokenExpiry sets exp, so an API redeployed with a different tokenExpiry must not be served a
// token cached under the old one.
func TestTokenCacheKey_ExpiryDistinguished(t *testing.T) {
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "u1", TokenId: "t"}
	short := keyNamespace{apiName: "api", algorithm: "SHA256withRSA", expiry: 5 * time.Minute}
	long := keyNamespace{apiName: "api", algorithm: "SHA256withRSA", expiry: time.Hour}
	if buildTokenCacheKey(short, authCtx, "/p", "GET", resolvedClaims{}) == buildTokenCacheKey(long, authCtx, "/p", "GET", resolvedClaims{}) {
		t.Error("different tokenExpiry values share a cache key")
	}
}

// Two accepted tokens can share a jti yet carry different typed claims; they must not share a
// cached backend token.
func TestTokenCacheKey_SameTokenIdDifferentTypedClaims(t *testing.T) {
	ns := keyNamespace{apiName: "api", algorithm: "SHA256withRSA"}
	mk := func(roles []interface{}) *policy.AuthContext {
		return &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "u1", TokenId: "same-jti",
			TypedProperties: map[string]interface{}{"roles": roles}}
	}
	a := buildTokenCacheKey(ns, mk([]interface{}{"A"}), "/p", "GET", resolvedClaims{})
	b := buildTokenCacheKey(ns, mk([]interface{}{"B"}), "/p", "GET", resolvedClaims{})
	if a == b {
		t.Error("same jti with different typed claims share a cache key")
	}
	if a != buildTokenCacheKey(ns, mk([]interface{}{"A"}), "/p", "GET", resolvedClaims{}) {
		t.Error("identical typed claims should share a cache key")
	}
}

// An entry must never outlive the token's absolute exp, even when the 30s cache floor would
// otherwise apply and time passed between signing and insertion.
func TestPutCachedTokenUntil_CappedAtExp(t *testing.T) {
	p := newTestPolicy()
	ctx := context.Background()
	notAfter := time.Now().Add(2 * time.Second)
	p.putCachedTokenUntil(ctx, "k", "signed", 45*time.Second, notAfter)
	entry, ok := p.tokenCache.Get(ctx, cache.CacheKey{Key: "k"})
	if !ok {
		t.Fatal("expected a cached entry")
	}
	if entry.expiresAt.After(notAfter) {
		t.Errorf("entry expires at %v, after exp %v", entry.expiresAt, notAfter)
	}
}
