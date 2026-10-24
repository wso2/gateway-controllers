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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package backendjwt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/signing"
)

// fakeGatewaySigner stands in for the policy engine's signing service. It signs
// ES256 with its own key and sets kid, as the real service does; the policy
// never sees the key.
type fakeGatewaySigner struct {
	key   *ecdsa.PrivateKey
	kid   string
	calls int
}

func (f *fakeGatewaySigner) Sign([]byte) ([]byte, signing.KeyInfo, error) {
	return nil, signing.KeyInfo{}, errors.New("not used")
}

func (f *fakeGatewaySigner) SignJWS(payload []byte, opts signing.Options) (string, signing.KeyInfo, error) {
	f.calls++
	var claims jwt.MapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", signing.KeyInfo{}, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = f.kid
	token.Header["typ"] = opts.Type
	signed, err := token.SignedString(f.key)
	return signed, signing.KeyInfo{Kid: f.kid, Algorithm: signing.ES256}, err
}

func (f *fakeGatewaySigner) SignDetachedJWS([]byte, signing.Options) (signing.DetachedJWS, signing.KeyInfo, error) {
	return signing.DetachedJWS{}, signing.KeyInfo{}, errors.New("not used")
}

func (f *fakeGatewaySigner) ActiveKey() (signing.KeyInfo, bool) {
	return signing.KeyInfo{Kid: f.kid, Algorithm: signing.ES256}, true
}

func (f *fakeGatewaySigner) JWKS() ([]byte, string)         { return []byte(`{"keys":[]}`), `"x"` }
func (f *fakeGatewaySigner) JWKSCacheMaxAge() time.Duration { return time.Minute }

func installGatewaySigner(t *testing.T) *fakeGatewaySigner {
	t.Helper()
	key, _ := generateECKey(t)
	f := &fakeGatewaySigner{key: key, kid: "gw-key-1"}
	signing.Install(f)
	t.Cleanup(func() { signing.Install(nil) })
	return f
}

func generateToken(t *testing.T, p *BackendJWTPolicy, params map[string]interface{}) string {
	t.Helper()
	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice"})
	mods, ok := p.OnRequestHeaders(context.Background(), reqCtx, params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected UpstreamRequestHeaderModifications")
	}
	return mods.HeadersToSet[defaultHeader]
}

func parseWithKid(t *testing.T, tokenStr string, key *ecdsa.PublicKey) (*jwt.Token, jwt.MapClaims) {
	t.Helper()
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return key, nil },
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("verify with the gateway key: %v", err)
	}
	return token, token.Claims.(jwt.MapClaims)
}

func TestGatewaySigning_TakesPrecedenceOverPolicyKey(t *testing.T) {
	gw := installGatewaySigner(t)
	_, policyKeyPEM := generateRSAKey(t)
	p := newTestPolicy()

	tokenStr := generateToken(t, p, baseParams(policyKeyPEM)) // policy-level RSA key also configured

	token, claims := parseWithKid(t, tokenStr, &gw.key.PublicKey)
	if token.Header["kid"] != "gw-key-1" || token.Header["typ"] != "JWT" {
		t.Fatalf("header = %v, want kid gw-key-1 and typ JWT", token.Header)
	}
	if claims["sub"] != "alice" || claims["iss"] != "https://gateway.example.com" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestGatewaySigning_NoPolicyKeyNeeded(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"issuer": "https://gateway.example.com", "tokenExpiry": "15m"}

	if err := p.Validate(params); err != nil {
		t.Fatalf("Validate without signingKey: %v", err)
	}
	parseWithKid(t, generateToken(t, p, params), &gw.key.PublicKey)
}

func TestGatewaySigning_OverridesAlgorithmNone(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"algorithm": "NONE", "issuer": "gw"}

	parseWithKid(t, generateToken(t, p, params), &gw.key.PublicKey)
}

func TestGatewaySigning_ValidateStillChecksNonKeyParams(t *testing.T) {
	installGatewaySigner(t)
	p := newTestPolicy()
	if err := p.Validate(map[string]interface{}{"algorithm": "HS256"}); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}
	if err := p.Validate(map[string]interface{}{"tokenExpiry": "-1m"}); err == nil {
		t.Fatal("negative tokenExpiry accepted")
	}
}

// A token cached under one gateway key must not be served once another key signs.
func TestGatewaySigning_CacheIsKeyedBySigningKey(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"issuer": "gw"}

	first := generateToken(t, p, params)
	if again := generateToken(t, p, params); again != first || gw.calls != 1 {
		t.Fatalf("expected a cache hit for the same key (calls=%d)", gw.calls)
	}

	gw.kid = "gw-key-2"
	rotated := generateToken(t, p, params)
	if rotated == first || gw.calls != 2 {
		t.Fatalf("token signed by the previous key was served after rotation (calls=%d)", gw.calls)
	}
	token, _ := parseWithKid(t, rotated, &gw.key.PublicKey)
	if token.Header["kid"] != "gw-key-2" {
		t.Fatalf("kid = %v, want gw-key-2", token.Header["kid"])
	}
}

func TestGatewaySigning_FailureIs500(t *testing.T) {
	signing.Install(&failingSigner{})
	t.Cleanup(func() { signing.Install(nil) })
	p := newTestPolicy()

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, Subject: "alice"})
	resp, ok := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{}).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 500 {
		t.Fatalf("expected a 500 ImmediateResponse, got %#v", resp)
	}
}

type failingSigner struct{ fakeGatewaySigner }

func (failingSigner) SignJWS([]byte, signing.Options) (string, signing.KeyInfo, error) {
	return "", signing.KeyInfo{}, errors.New("hsm unavailable")
}

func (failingSigner) ActiveKey() (signing.KeyInfo, bool) {
	return signing.KeyInfo{Kid: "k", Algorithm: signing.ES256}, true
}

// With no gateway key installed the policy-level key signs as before, with no kid.
func TestPolicyKeySigning_UnchangedWithoutGatewayKey(t *testing.T) {
	signing.Install(nil)
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()

	tokenStr := generateToken(t, p, baseParams(keyPEM))
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return &rsaKey.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("verify with the policy key: %v", err)
	}
	if _, hasKid := token.Header["kid"]; hasKid {
		t.Fatal("policy-level signing must not add a kid")
	}
}

func TestHasPolicySigningKey(t *testing.T) {
	cases := map[string]struct {
		params map[string]interface{}
		want   bool
	}{
		"inline":  {map[string]interface{}{"signingKey": map[string]interface{}{"inline": "pem"}}, true},
		"path":    {map[string]interface{}{"signingKey": map[string]interface{}{"path": "/k.pem"}}, true},
		"empty":   {map[string]interface{}{"signingKey": map[string]interface{}{"inline": ""}}, false},
		"absent":  {map[string]interface{}{}, false},
		"invalid": {map[string]interface{}{"signingKey": "pem"}, false},
	}
	for name, tc := range cases {
		if got := hasPolicySigningKey(tc.params); got != tc.want {
			t.Errorf("%s: hasPolicySigningKey = %v, want %v", name, got, tc.want)
		}
	}
}

// captureLogs routes slog output to a buffer for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

const ignoredKeyWarning = "ignoring the policy-level signingKey and algorithm"

// The deployment-time warning names the gateway key that is used instead, and never the
// policy-level key material it ignores.
func TestGatewaySigning_WarnsOnceWhenPolicyKeyIsIgnored(t *testing.T) {
	installGatewaySigner(t)
	_, policyKeyPEM := generateRSAKey(t)
	logs := captureLogs(t)

	if _, err := GetPolicy(policy.PolicyMetadata{APIName: "orders-api"}, baseParams(policyKeyPEM)); err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	out := logs.String()
	if strings.Count(out, ignoredKeyWarning) != 1 {
		t.Fatalf("expected exactly one ignored-key warning, got:\n%s", out)
	}
	for _, want := range []string{"api=orders-api", "kid=gw-key-1", "gatewayAlgorithm=ES256"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not carry %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("the ignored policy-level key was logged:\n%s", out)
	}

	// Requests never repeat the warning.
	generateToken(t, newTestPolicy(), baseParams(policyKeyPEM))
	if strings.Count(logs.String(), ignoredKeyWarning) != 1 {
		t.Fatalf("a request logged the ignored-key warning again:\n%s", logs.String())
	}
}

func TestGatewaySigning_NoWarningWithoutAnIgnoredKey(t *testing.T) {
	_, policyKeyPEM := generateRSAKey(t)
	cases := map[string]struct {
		gatewayKey bool
		params     map[string]interface{}
	}{
		"gateway key, no policy key":       {true, map[string]interface{}{"issuer": "gw"}},
		"policy key, no gateway key":       {false, baseParams(policyKeyPEM)},
		"no gateway key and no policy key": {false, map[string]interface{}{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.gatewayKey {
				installGatewaySigner(t)
			} else {
				signing.Install(nil)
			}
			logs := captureLogs(t)
			if _, err := GetPolicy(policy.PolicyMetadata{APIName: "orders-api"}, tc.params); err != nil {
				t.Fatalf("GetPolicy: %v", err)
			}
			if strings.Contains(logs.String(), ignoredKeyWarning) {
				t.Fatalf("unexpected ignored-key warning:\n%s", logs.String())
			}
		})
	}
}

// The policy-level key is not used with a gateway key, so its material is not checked either.
func TestGatewaySigning_ValidateIgnoresInvalidPolicyKey(t *testing.T) {
	installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"signingKey": map[string]interface{}{"inline": "not a PEM key"}}
	if err := p.Validate(params); err != nil {
		t.Fatalf("Validate rejected an unused policy-level key: %v", err)
	}
	signing.Install(nil)
	if err := p.Validate(params); err == nil {
		t.Fatal("Validate accepted invalid key material with no gateway key to sign instead")
	}
}

func TestGatewaySigning_HonoursHeaderAndExpiry(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"issuer": "gw", "header": "X-Backend-Token", "tokenExpiry": "5m"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice"})
	mods, ok := p.OnRequestHeaders(context.Background(), reqCtx, params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected UpstreamRequestHeaderModifications")
	}
	if _, set := mods.HeadersToSet[defaultHeader]; set {
		t.Fatalf("the default header was set although header is %q", "X-Backend-Token")
	}
	_, claims := parseWithKid(t, mods.HeadersToSet["X-Backend-Token"], &gw.key.PublicKey)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp-iat != 300 {
		t.Fatalf("exp - iat = %v, want 300", exp-iat)
	}
}

func TestGatewaySigning_CachingDisabledSignsEveryRequest(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"issuer": "gw", "tokenCaching": false}

	generateToken(t, p, params)
	generateToken(t, p, params)
	if gw.calls != 2 {
		t.Fatalf("gateway signer calls = %d, want 2 with caching disabled", gw.calls)
	}
	if n := tokenCount(p, ""); n != 0 {
		t.Fatalf("cache holds %d tokens with caching disabled", n)
	}
}

// A token cached while the policy-level key signed is not served once a gateway key is installed,
// and a gateway-signed token is not served once the gateway key is gone.
func TestGatewaySigning_CacheSeparatesPolicyAndGatewayKeys(t *testing.T) {
	signing.Install(nil)
	t.Cleanup(func() { signing.Install(nil) })
	rsaKey, policyKeyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(policyKeyPEM)

	policySigned := generateToken(t, p, params)
	if again := generateToken(t, p, params); again != policySigned {
		t.Fatal("expected a cache hit while the policy-level key signs")
	}

	gw := installGatewaySigner(t)
	gatewaySigned := generateToken(t, p, params)
	if gatewaySigned == policySigned || gw.calls != 1 {
		t.Fatalf("the policy-key token was served after a gateway key was installed (calls=%d)", gw.calls)
	}
	parseWithKid(t, gatewaySigned, &gw.key.PublicKey)

	signing.Install(nil)
	afterRemoval := generateToken(t, p, params)
	if afterRemoval == gatewaySigned {
		t.Fatal("the gateway-signed token was served after the gateway key was removed")
	}
	if _, err := jwt.Parse(afterRemoval, func(*jwt.Token) (interface{}, error) { return &rsaKey.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("the token after removal does not verify with the policy-level key: %v", err)
	}
}

// With no gateway key and no policy-level key, the request fails as before gateway signing existed.
func TestPolicyKeySigning_MissingKeyWithoutGatewayKeyIs500(t *testing.T) {
	signing.Install(nil)
	p := newTestPolicy()
	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, Subject: "alice"})
	resp, ok := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{"issuer": "gw"}).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 500 {
		t.Fatalf("expected a 500 ImmediateResponse, got %#v", resp)
	}
}
