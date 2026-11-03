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

package dpop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// testToken is a JWT access token (signature not real) with jti at-7f3c9e, the
	// TokenId jwt-auth records for it.
	testToken    = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiYWxpY2UiLCJqdGkiOiJhdC03ZjNjOWUifQ.c2ln"
	testTokenJTI = "at-7f3c9e"
	testHTU      = "https://api.example.com/orders/v1/items"
)

var testNow = time.Unix(1_800_000_000, 0)

// ─── Fixtures ────────────────────────────────────────────────────────────────

// testKey is a client key pair that signs proofs, with its public JWK and thumbprint.
type testKey struct {
	alg    string
	method jwt.SigningMethod
	signer crypto.Signer
	jwk    map[string]interface{}
	jkt    string
}

var (
	rsaKeyOnce sync.Once
	rsaKey     *rsa.PrivateKey
)

// sharedRSAKey generates one 2048-bit RSA key per test run, since RSA key generation is slow.
func sharedRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		rsaKey = k
	})
	return rsaKey
}

// enc base64url-encodes without padding, as JWKs and JWTs do.
func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newKey generates a client key pair for alg, with its public JWK and thumbprint.
func newKey(t *testing.T, alg string) testKey {
	t.Helper()
	k := testKey{alg: alg, method: jwt.GetSigningMethod(alg)}
	switch alg {
	case "ES256", "ES384", "ES512":
		curve := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		crv := map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		size := (curve.Params().BitSize + 7) / 8
		point, err := priv.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		x, y := point[1:1+size], point[1+size:]
		k.signer = priv
		k.jwk = map[string]interface{}{"kty": "EC", "crv": crv, "x": enc(x), "y": enc(y)}
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		priv := sharedRSAKey(t)
		k.signer = priv
		k.jwk = map[string]interface{}{"kty": "RSA", "n": enc(priv.N.Bytes()), "e": enc(big.NewInt(int64(priv.E)).Bytes())}
	case "EdDSA", "Ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.signer = priv
		k.jwk = map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": enc(pub)}
	default:
		t.Fatalf("unknown alg %s", alg)
	}
	_, jkt, err := parseJWK(k.jwk, alg)
	if err != nil {
		t.Fatalf("parse own jwk: %v", err)
	}
	k.jkt = jkt
	return k
}

// defaultClaims are the claims of a valid proof for the default test request.
func defaultClaims() jwt.MapClaims {
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	return jwt.MapClaims{
		"jti": enc(jti),
		"htm": "GET",
		"htu": testHTU,
		"iat": testNow.Unix(),
		"ath": accessTokenHash(testToken),
	}
}

// sign builds a proof. edit may change the claims and headers before signing.
func (k testKey) sign(t *testing.T, edit func(claims jwt.MapClaims, header map[string]interface{})) string {
	t.Helper()
	claims := defaultClaims()
	tok := jwt.NewWithClaims(k.method, claims)
	tok.Header["typ"] = proofType
	tok.Header["jwk"] = k.jwk
	if edit != nil {
		edit(claims, tok.Header)
	}
	s, err := tok.SignedString(k.signer)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return s
}

// newTestPolicy builds a policy from params with a fixed clock and its own replay store.
func newTestPolicy(t *testing.T, params map[string]interface{}) *DPoPPolicy {
	t.Helper()
	pol, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	p := pol.(*DPoPPolicy)
	p.now = func() time.Time { return testNow }
	p.replay = newReplayStore(1000)
	return p
}

// boundJWT is the AuthContext jwt-auth records for a token bound to jkt.
func boundJWT(jkt string) *policy.AuthContext {
	return &policy.AuthContext{
		Authenticated:   true,
		AuthType:        "jwt",
		Subject:         "alice",
		Issuer:          "https://idp.example",
		TokenId:         testTokenJTI,
		TypedProperties: map[string]interface{}{"cnf": map[string]interface{}{"jkt": jkt}},
	}
}

// fingerprint is the TokenId opaque-token-auth records: the token's hex SHA-256.
func fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// unboundJWT is the AuthContext of a token with no cnf claim.
func unboundJWT() *policy.AuthContext {
	return &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice"}
}

type reqOpts struct {
	auth      *policy.AuthContext
	authz     []string
	proofs    []string
	method    string
	scheme    string
	authority string
	path      string
}

// newRequest builds a request header context, defaulting to GET https://api.example.com/orders/v1/items.
func newRequest(o reqOpts) *policy.RequestHeaderContext {
	headers := map[string][]string{}
	if o.authz != nil {
		headers["authorization"] = o.authz
	}
	if o.proofs != nil {
		headers["dpop"] = o.proofs
	}
	def := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIName:     "orders",
			AuthContext: o.auth,
			Metadata:    map[string]interface{}{},
		},
		Headers:   policy.NewHeaders(headers),
		Method:    def(o.method, "GET"),
		Scheme:    def(o.scheme, "https"),
		Authority: def(o.authority, "api.example.com"),
		Path:      def(o.path, "/orders/v1/items?limit=5"),
	}
}

// dpopRequest is a well-formed DPoP request for key with the given proof.
func dpopRequest(key testKey, proof string) *policy.RequestHeaderContext {
	return newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken}, proofs: []string{proof}})
}

// run passes a request through the policy's request-header phase.
func run(p *DPoPPolicy, req *policy.RequestHeaderContext) policy.RequestHeaderAction {
	return p.OnRequestHeaders(context.Background(), req, nil)
}

// expectAllowed fails the test unless the request continues upstream.
func expectAllowed(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		resp, _ := action.(policy.ImmediateResponse)
		t.Fatalf("expected request to be allowed, got %T: %d %v", action, resp.StatusCode, resp.Headers[wwwAuthenticateHeader])
	}
	return mods
}

// expectRejected fails the test unless the request is refused with a challenge carrying code.
func expectRejected(t *testing.T, action policy.RequestHeaderAction, code string) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected rejection with %s, got %T", code, action)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	challenge := resp.Headers[wwwAuthenticateHeader]
	if !strings.Contains(challenge, `error="`+code+`"`) || !strings.Contains(challenge, "DPoP ") ||
		(!strings.HasPrefix(challenge, "DPoP ") && !strings.HasPrefix(challenge, "Bearer ")) {
		t.Fatalf("WWW-Authenticate = %q, want DPoP challenge with error=%q", challenge, code)
	}
	return resp
}

// ─── RFC test vectors ────────────────────────────────────────────────────────

// TestRFC9449ExampleProof verifies the signed proof of RFC 9449 Figure 13 against
// the request it was made for, with the clock set to the proof's iat.
func TestRFC9449ExampleProof(t *testing.T) {
	const (
		token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
		jkt   = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
		proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19" +
			".eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9" +
			".2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	)
	if got := accessTokenHash(token); got != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatalf("ath = %s", got)
	}

	p := newTestPolicy(t, nil)
	p.now = func() time.Time { return time.Unix(1562262618, 0) }
	auth := boundJWT(jkt)
	auth.TokenId = fingerprint(token) // an opaque token, as opaque-token-auth records it
	req := newRequest(reqOpts{
		auth:      auth,
		authz:     []string{"DPoP " + token},
		proofs:    []string{proof},
		authority: "resource.example.org",
		path:      "/protectedresource",
	})
	mods := expectAllowed(t, run(p, req))
	if req.Metadata[MetadataKeyThumbprint] != jkt {
		t.Errorf("metadata %s = %v", MetadataKeyThumbprint, req.Metadata[MetadataKeyThumbprint])
	}
	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "DPoP" {
		t.Errorf("HeadersToRemove = %v, want [DPoP]", mods.HeadersToRemove)
	}

	// The same proof a second time is a replay.
	expectRejected(t, run(p, newRequest(reqOpts{
		auth: auth, authz: []string{"DPoP " + token}, proofs: []string{proof},
		authority: "resource.example.org", path: "/protectedresource",
	})), "invalid_dpop_proof")
}

// TestRFC7638Thumbprint checks the thumbprint against the example of RFC 7638 section 3.1.
func TestRFC7638Thumbprint(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	_, tp, err := parseJWK(jwk, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if tp != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint = %s", tp)
	}
}

// ─── Accepted proofs ─────────────────────────────────────────────────────────

// TestValidProofEveryAlgorithm accepts a valid proof signed with each supported algorithm.
func TestValidProofEveryAlgorithm(t *testing.T) {
	all := make([]interface{}, len(supportedAlgorithms))
	for i, a := range supportedAlgorithms {
		all[i] = a
	}
	for _, alg := range supportedAlgorithms {
		t.Run(alg, func(t *testing.T) {
			p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": all})
			key := newKey(t, alg)
			req := dpopRequest(key, key.sign(t, nil))
			expectAllowed(t, run(p, req))
			if req.Metadata[MetadataKeyThumbprint] != key.jkt {
				t.Errorf("thumbprint metadata = %v, want %s", req.Metadata[MetadataKeyThumbprint], key.jkt)
			}
		})
	}
}

// TestForwardProofKeepsHeader keeps the DPoP header for the backend when forwardProof is on.
func TestForwardProofKeepsHeader(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"forwardProof": true})
	key := newKey(t, "ES256")
	mods := expectAllowed(t, run(p, dpopRequest(key, key.sign(t, nil))))
	if len(mods.HeadersToRemove) != 0 {
		t.Errorf("HeadersToRemove = %v, want none", mods.HeadersToRemove)
	}
}

// TestOpaqueTokenBindingFromProperties reads cnf.jkt from the JSON opaque-token-auth records.
func TestOpaqueTokenBindingFromProperties(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	cnf, _ := json.Marshal(map[string]string{"jkt": key.jkt})
	auth := &policy.AuthContext{Authenticated: true, AuthType: "opaque", TokenId: fingerprint(testToken), Properties: map[string]string{"cnf": string(cnf)}}
	req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectAllowed(t, run(p, req))
}

// TestStringCNFIsNotABinding covers a JWT whose cnf claim is a JSON string, which
// jwt-auth records both typed (as a string) and flattened: it is not a binding.
func TestStringCNFIsNotABinding(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	cnf := `{"jkt":"` + key.jkt + `"}`
	auth := &policy.AuthContext{Authenticated: true, AuthType: "jwt",
		TypedProperties: map[string]interface{}{"cnf": cnf}, Properties: map[string]string{"cnf": cnf}}
	req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectRejected(t, run(p, req), "invalid_token")
}

// TestBindingFoundBelowNewerAuthLayer finds cnf.jkt below a newer auth layer, such as mtls-auth.
func TestBindingFoundBelowNewerAuthLayer(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	auth := &policy.AuthContext{Authenticated: true, AuthType: "mtls", Previous: boundJWT(key.jkt)}
	req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectAllowed(t, run(p, req))
}

// TestSchemeIsCaseInsensitive accepts the DPoP scheme in any case, as RFC 9110 requires.
func TestSchemeIsCaseInsensitive(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"dpop " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectAllowed(t, run(p, req))
}

// ─── htu matching ────────────────────────────────────────────────────────────

// TestHTUNormalization matches htu after RFC 3986 normalization and refuses other origins and paths.
func TestHTUNormalization(t *testing.T) {
	cases := []struct {
		name string
		htu  string
		ok   bool
	}{
		{"exact", testHTU, true},
		{"query and fragment ignored", testHTU + "?limit=99#frag", true},
		{"scheme and host case", "HTTPS://API.Example.COM/orders/v1/items", true},
		{"default port", "https://api.example.com:443/orders/v1/items", true},
		{"percent-encoded unreserved", "https://api.example.com/%6Frders/v1/items", true},
		{"dot segments", "https://api.example.com/orders/x/../v1/./items", true},
		{"other host", "https://evil.example.com/orders/v1/items", false},
		{"other path", "https://api.example.com/orders/v1/admin", false},
		{"path case", "https://api.example.com/Orders/v1/items", false},
		{"other scheme", "http://api.example.com/orders/v1/items", false},
		{"other port", "https://api.example.com:8443/orders/v1/items", false},
		{"relative", "/orders/v1/items", false},
		{"userinfo", "https://user@api.example.com/orders/v1/items", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newTestPolicy(t, nil)
			key := newKey(t, "ES256")
			proof := key.sign(t, func(cl jwt.MapClaims, _ map[string]interface{}) { cl["htu"] = c.htu })
			action := run(p, dpopRequest(key, proof))
			if c.ok {
				expectAllowed(t, action)
			} else {
				expectRejected(t, action, "invalid_dpop_proof")
			}
		})
	}
}

// TestHTUOriginsBehindLoadBalancer accepts the configured public origins instead of the request's own.
func TestHTUOriginsBehindLoadBalancer(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"htuOrigins": []interface{}{"https://api.example.com", "https://API.example.org:443/"}})
	key := newKey(t, "ES256")
	// The gateway sees plain HTTP from the load balancer on an internal host.
	internal := func(proof string) *policy.RequestHeaderContext {
		return newRequest(reqOpts{
			auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken}, proofs: []string{proof},
			scheme: "http", authority: "gateway.internal:8080",
		})
	}
	expectAllowed(t, run(p, internal(key.sign(t, nil))))
	expectAllowed(t, run(p, internal(key.sign(t, func(cl jwt.MapClaims, _ map[string]interface{}) {
		cl["htu"] = "https://api.example.org/orders/v1/items"
	}))))
	expectRejected(t, run(p, internal(key.sign(t, func(cl jwt.MapClaims, _ map[string]interface{}) {
		cl["htu"] = "http://gateway.internal:8080/orders/v1/items"
	}))), "invalid_dpop_proof")
}

// TestRemoveDotSegments checks dot-segment removal against RFC 3986 examples.
func TestRemoveDotSegments(t *testing.T) {
	// Examples from RFC 3986 section 5.2.4 and 5.4.
	cases := map[string]string{
		"/a/b/c/./../../g":   "/a/g",
		"mid/content=5/../6": "mid/6",
		"/b/c/../../../g":    "/g",
		"/a/b/.":             "/a/b/",
		"/a/b/..":            "/a/",
		"/./a":               "/a",
		"":                   "",
	}
	for in, want := range cases {
		if got := removeDotSegments(in); got != want {
			t.Errorf("removeDotSegments(%q) = %q, want %q", in, got, want)
		}
	}
	if got := normalizePath("/a%2fb/%7euser/%41"); got != "/a%2Fb/~user/A" {
		t.Errorf("normalizePath = %q", got)
	}
	if got := normalizePath(""); got != "/" {
		t.Errorf("normalizePath(\"\") = %q", got)
	}
}

// ─── Rejected proofs ─────────────────────────────────────────────────────────

// TestRejectedProofs refuses proofs with a missing, malformed or mismatching claim.
func TestRejectedProofs(t *testing.T) {
	type edit = func(jwt.MapClaims, map[string]interface{})
	cases := []struct {
		name string
		edit edit
		code string
	}{
		{"wrong typ", func(_ jwt.MapClaims, h map[string]interface{}) { h["typ"] = "JWT" }, "invalid_dpop_proof"},
		{"missing typ", func(_ jwt.MapClaims, h map[string]interface{}) { delete(h, "typ") }, "invalid_dpop_proof"},
		{"missing jwk", func(_ jwt.MapClaims, h map[string]interface{}) { delete(h, "jwk") }, "invalid_dpop_proof"},
		{"missing jti", func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "jti") }, "invalid_dpop_proof"},
		{"oversized jti", func(c jwt.MapClaims, _ map[string]interface{}) { c["jti"] = strings.Repeat("j", maxJTILength+1) }, "invalid_dpop_proof"},
		{"missing htm", func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "htm") }, "invalid_dpop_proof"},
		{"wrong htm", func(c jwt.MapClaims, _ map[string]interface{}) { c["htm"] = "POST" }, "invalid_dpop_proof"},
		{"lowercase htm", func(c jwt.MapClaims, _ map[string]interface{}) { c["htm"] = "get" }, "invalid_dpop_proof"},
		{"missing htu", func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "htu") }, "invalid_dpop_proof"},
		{"missing iat", func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "iat") }, "invalid_dpop_proof"},
		{"string iat", func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = "1800000000" }, "invalid_dpop_proof"},
		{"expired", func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = testNow.Add(-2 * time.Minute).Unix() }, "invalid_dpop_proof"},
		{"from the future", func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = testNow.Add(time.Minute).Unix() }, "invalid_dpop_proof"},
		{"missing ath", func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "ath") }, "invalid_dpop_proof"},
		{"wrong ath", func(c jwt.MapClaims, _ map[string]interface{}) { c["ath"] = accessTokenHash("other-token") }, "invalid_dpop_proof"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newTestPolicy(t, nil)
			key := newKey(t, "ES256")
			expectRejected(t, run(p, dpopRequest(key, key.sign(t, c.edit))), c.code)
		})
	}
}

// TestClockSkewTolerance accepts iat within clockSkew on either side of the window.
func TestClockSkewTolerance(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	for _, iat := range []time.Time{testNow.Add(20 * time.Second), testNow.Add(-time.Minute - 20*time.Second)} {
		proof := key.sign(t, func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = iat.Unix() })
		expectAllowed(t, run(p, dpopRequest(key, proof)))
	}
}

// TestTamperedSignature refuses a proof whose payload was changed after signing.
func TestTamperedSignature(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	parts := strings.Split(proof, ".")
	var claims map[string]interface{}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(payload, &claims)
	claims["htm"] = "DELETE"
	payload, _ = json.Marshal(claims)
	tampered := parts[0] + "." + enc(payload) + "." + parts[2]
	req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken}, proofs: []string{tampered}, method: "DELETE"})
	expectRejected(t, run(p, req), "invalid_dpop_proof")
}

// TestProofSignedByAnotherKey refuses a valid proof from a key other than the token's cnf.jkt.
func TestProofSignedByAnotherKey(t *testing.T) {
	p := newTestPolicy(t, nil)
	bound := newKey(t, "ES256")
	attacker := newKey(t, "ES256")
	req := newRequest(reqOpts{auth: boundJWT(bound.jkt), authz: []string{"DPoP " + testToken}, proofs: []string{attacker.sign(t, nil)}})
	resp := expectRejected(t, run(p, req), "invalid_token")
	if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "Invalid DPoP key binding") &&
		!strings.Contains(resp.Headers[wwwAuthenticateHeader], "invalid DPoP key binding") {
		t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
	}
}

// TestJWKSubstitution swaps the proof's jwk for the bound key's public key while
// keeping the attacker's signature: the signature no longer verifies.
func TestJWKSubstitution(t *testing.T) {
	p := newTestPolicy(t, nil)
	bound := newKey(t, "ES256")
	attacker := newKey(t, "ES256")
	proof := attacker.sign(t, func(_ jwt.MapClaims, h map[string]interface{}) { h["jwk"] = bound.jwk })
	expectRejected(t, run(p, dpopRequest(bound, proof)), "invalid_dpop_proof")
}

// TestRejectedAlgorithms refuses none, HMAC, algorithms outside allowedAlgorithms and curve mismatches.
func TestRejectedAlgorithms(t *testing.T) {
	key := newKey(t, "ES256")
	t.Run("none", func(t *testing.T) {
		p := newTestPolicy(t, nil)
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, defaultClaims())
		tok.Header["typ"] = proofType
		tok.Header["jwk"] = key.jwk
		s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		expectRejected(t, run(p, dpopRequest(key, s)), "invalid_dpop_proof")
	})
	t.Run("HS256 with symmetric jwk", func(t *testing.T) {
		p := newTestPolicy(t, nil)
		secret := []byte("0123456789abcdef0123456789abcdef")
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, defaultClaims())
		tok.Header["typ"] = proofType
		tok.Header["jwk"] = map[string]interface{}{"kty": "oct", "k": enc(secret)}
		s, err := tok.SignedString(secret)
		if err != nil {
			t.Fatal(err)
		}
		expectRejected(t, run(p, dpopRequest(key, s)), "invalid_dpop_proof")
	})
	t.Run("not in allowedAlgorithms", func(t *testing.T) {
		p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"ES256"}})
		rsaKey := newKey(t, "RS256")
		resp := expectRejected(t, run(p, dpopRequest(rsaKey, rsaKey.sign(t, nil))), "invalid_dpop_proof")
		if !strings.HasSuffix(resp.Headers[wwwAuthenticateHeader], `algs="ES256"`) {
			t.Errorf("challenge = %q, want algs=\"ES256\"", resp.Headers[wwwAuthenticateHeader])
		}
	})
	t.Run("EC key with ES384", func(t *testing.T) {
		p := newTestPolicy(t, nil)
		p256 := newKey(t, "ES256")
		// Sign with a P-384 key but advertise the P-256 jwk under ES384.
		p384 := newKey(t, "ES384")
		proof := p384.sign(t, func(_ jwt.MapClaims, h map[string]interface{}) { h["jwk"] = p256.jwk })
		expectRejected(t, run(p, dpopRequest(p256, proof)), "invalid_dpop_proof")
	})
}

// TestPrivateKeyInJWK refuses a proof whose jwk carries private key material.
func TestPrivateKeyInJWK(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	priv := key.signer.(*ecdsa.PrivateKey)
	d, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	proof := key.sign(t, func(_ jwt.MapClaims, h map[string]interface{}) {
		jwk := map[string]interface{}{}
		for k, v := range key.jwk {
			jwk[k] = v
		}
		jwk["d"] = enc(d)
		h["jwk"] = jwk
	})
	expectRejected(t, run(p, dpopRequest(key, proof)), "invalid_dpop_proof")
}

// TestJWKValidation refuses off-curve points, weak RSA keys and malformed JWKs.
func TestJWKValidation(t *testing.T) {
	ec := newKey(t, "ES256")
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		jwk  map[string]interface{}
		alg  string
	}{
		{"off-curve point", map[string]interface{}{"kty": "EC", "crv": "P-256", "x": ec.jwk["x"], "y": ec.jwk["x"]}, "ES256"},
		{"short coordinate", map[string]interface{}{"kty": "EC", "crv": "P-256", "x": enc([]byte{1, 2, 3}), "y": ec.jwk["y"]}, "ES256"},
		{"padded base64", map[string]interface{}{"kty": "EC", "crv": "P-256", "x": ec.jwk["x"].(string) + "=", "y": ec.jwk["y"]}, "ES256"},
		{"wrong curve for alg", ec.jwk, "ES384"},
		{"crv label disagrees with alg", map[string]interface{}{"kty": "EC", "crv": "P-384", "x": ec.jwk["x"], "y": ec.jwk["y"]}, "ES256"},
		{"EC key for RS256", ec.jwk, "RS256"},
		{"RSA below 2048 bits", map[string]interface{}{"kty": "RSA", "n": enc(small.N.Bytes()), "e": "AQAB"}, "RS256"},
		{"RSA even exponent", map[string]interface{}{"kty": "RSA", "n": enc(sharedRSAKey(t).N.Bytes()), "e": enc([]byte{1, 0, 0})}, "RS256"},
		{"unknown kty", map[string]interface{}{"kty": "oct"}, "ES256"},
		{"Ed448", map[string]interface{}{"kty": "OKP", "crv": "Ed448", "x": enc(make([]byte, 57))}, "EdDSA"},
	}
	for _, c := range cases {
		if _, _, err := parseJWK(c.jwk, c.alg); err == nil {
			t.Errorf("%s: parseJWK accepted an unacceptable key", c.name)
		}
	}
}

// TestReplayRejected refuses a proof the second time it is sent.
func TestReplayRejected(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	expectAllowed(t, run(p, dpopRequest(key, proof)))
	expectRejected(t, run(p, dpopRequest(key, proof)), "invalid_dpop_proof")
}

// TestConcurrentReplayAcceptsOnce accepts exactly one of many concurrent copies of a proof.
func TestConcurrentReplayAcceptsOnce(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := run(p, dpopRequest(key, proof)).(policy.UpstreamRequestHeaderModifications); ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d copies of one proof, want 1", accepted)
	}
}

// TestRejectedProofDoesNotBurnJTI leaves a refused proof's jti unrecorded, so it cannot be used up by a failed attempt.
func TestRejectedProofDoesNotBurnJTI(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	// Sent with the wrong method first, then correctly: the first attempt must not
	// have recorded the jti.
	req := dpopRequest(key, proof)
	req.Method = "POST"
	expectRejected(t, run(p, req), "invalid_dpop_proof")
	expectAllowed(t, run(p, dpopRequest(key, proof)))
}

// ─── Headers and scheme ──────────────────────────────────────────────────────

// TestDPoPHeaderCount refuses a missing, empty, repeated or comma-folded DPoP header.
func TestDPoPHeaderCount(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	a, b := key.sign(t, nil), key.sign(t, nil)
	for name, proofs := range map[string][]string{
		"missing":             nil,
		"empty":               {""},
		"two headers":         {a, b},
		"folded with a comma": {a + ", " + b},
		"not a JWT":           {"not-a-jwt"},
	} {
		t.Run(name, func(t *testing.T) {
			req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken}, proofs: proofs})
			expectRejected(t, run(p, req), "invalid_dpop_proof")
		})
	}
}

// TestOversizedProof refuses a proof over 8 KB before parsing it.
func TestOversizedProof(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	expectRejected(t, run(p, dpopRequest(key, strings.Repeat("a", maxProofLength+1))), "invalid_dpop_proof")
}

// TestBoundTokenAsBearerIsRejectedInBothModes refuses a DPoP-bound token sent with the Bearer scheme in either mode.
func TestBoundTokenAsBearerIsRejectedInBothModes(t *testing.T) {
	for _, mode := range []string{modeRequired, modeOptional} {
		t.Run(mode, func(t *testing.T) {
			p := newTestPolicy(t, map[string]interface{}{"mode": mode})
			key := newKey(t, "ES256")
			req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"Bearer " + testToken}, proofs: []string{key.sign(t, nil)}})
			expectRejected(t, run(p, req), "invalid_token")
		})
	}
}

// TestUnboundBearerToken refuses an unbound bearer token in required mode and lets it through in optional mode.
func TestUnboundBearerToken(t *testing.T) {
	t.Run("required", func(t *testing.T) {
		p := newTestPolicy(t, nil)
		req := newRequest(reqOpts{auth: unboundJWT(), authz: []string{"Bearer " + testToken}})
		expectRejected(t, run(p, req), "invalid_token")
	})
	t.Run("optional", func(t *testing.T) {
		p := newTestPolicy(t, map[string]interface{}{"mode": modeOptional})
		req := newRequest(reqOpts{auth: unboundJWT(), authz: []string{"Bearer " + testToken}})
		mods := expectAllowed(t, run(p, req))
		if len(mods.HeadersToRemove) != 0 {
			t.Errorf("HeadersToRemove = %v", mods.HeadersToRemove)
		}
	})
	t.Run("optional strips a stray proof", func(t *testing.T) {
		p := newTestPolicy(t, map[string]interface{}{"mode": modeOptional})
		req := newRequest(reqOpts{auth: unboundJWT(), authz: []string{"Bearer " + testToken}, proofs: []string{"x.y.z"}})
		mods := expectAllowed(t, run(p, req))
		if len(mods.HeadersToRemove) != 1 {
			t.Errorf("HeadersToRemove = %v, want [DPoP]", mods.HeadersToRemove)
		}
	})
}

// TestDPoPSchemeWithUnboundToken refuses the DPoP scheme on a token without cnf.jkt.
func TestDPoPSchemeWithUnboundToken(t *testing.T) {
	for _, mode := range []string{modeRequired, modeOptional} {
		p := newTestPolicy(t, map[string]interface{}{"mode": mode})
		key := newKey(t, "ES256")
		req := newRequest(reqOpts{auth: unboundJWT(), authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
		resp := expectRejected(t, run(p, req), "invalid_token")
		if !strings.Contains(resp.Headers[wwwAuthenticateHeader], `error_description="access token is not DPoP-bound"`) {
			t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
		}
	}
}

// TestMTLSBoundTokenIsNotDPoPBound treats a cnf without jkt (x5t#S256) as not DPoP-bound.
func TestMTLSBoundTokenIsNotDPoPBound(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	auth := &policy.AuthContext{Authenticated: true, AuthType: "jwt",
		TypedProperties: map[string]interface{}{"cnf": map[string]interface{}{"x5t#S256": "abc"}}}
	req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectRejected(t, run(p, req), "invalid_token")
}

// TestNoAuthenticatedToken refuses a request no access-token policy authenticated.
func TestNoAuthenticatedToken(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"mode": modeOptional})
	key := newKey(t, "ES256")
	for name, auth := range map[string]*policy.AuthContext{
		"no auth context": nil,
		"failed layer":    {Authenticated: false, AuthType: "jwt"},
	} {
		t.Run(name, func(t *testing.T) {
			req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
			expectRejected(t, run(p, req), "invalid_token")
		})
	}
}

// TestMalformedAuthorization refuses a DPoP Authorization header with no token or extra parts.
func TestMalformedAuthorization(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	for _, authz := range []string{"DPoP", "DPoP a b"} {
		req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{authz}, proofs: []string{key.sign(t, nil)}})
		expectRejected(t, run(p, req), "invalid_token")
	}
}

// ─── Failure response ────────────────────────────────────────────────────────

// TestFailureResponse checks the challenge, the OAuth error body and the AuthContext failure layer.
func TestFailureResponse(t *testing.T) {
	key := newKey(t, "ES256")
	p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"ES256", "EdDSA"}})
	req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken}})
	resp := expectRejected(t, run(p, req), "invalid_dpop_proof")
	want := `DPoP error="invalid_dpop_proof", error_description="missing DPoP header", algs="ES256 EdDSA"`
	if resp.Headers[wwwAuthenticateHeader] != want {
		t.Errorf("WWW-Authenticate = %q, want %q", resp.Headers[wwwAuthenticateHeader], want)
	}
	// The body repeats the challenge as an OAuth error object.
	if string(resp.Body) != `{"error":"invalid_dpop_proof","error_description":"missing DPoP header"}` {
		t.Errorf("body = %s", resp.Body)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Errorf("content-type = %s", resp.Headers["content-type"])
	}
	if req.AuthContext.Authenticated || req.AuthContext.AuthType != AuthType || req.AuthContext.Previous == nil {
		t.Errorf("failure AuthContext layer = %+v", req.AuthContext)
	}
	if _, ok := resp.Headers[dpopNonceHeader]; ok {
		t.Error("DPoP-Nonce sent although nonces are off")
	}
}

// TestFailureDescriptions checks that every proof failure names the failed check in
// a fixed description, and that no description quotes the request.
func TestFailureDescriptions(t *testing.T) {
	key := newKey(t, "ES256")
	type edit = func(jwt.MapClaims, map[string]interface{})
	cases := []struct {
		edit edit
		want string
	}{
		{func(_ jwt.MapClaims, h map[string]interface{}) { h["typ"] = "evil\"value" }, "typ must be dpop+jwt"},
		{func(_ jwt.MapClaims, h map[string]interface{}) { h["crit"] = []interface{}{"x"} }, "crit header is not supported"},
		{func(_ jwt.MapClaims, h map[string]interface{}) { delete(h, "jwk") }, "jwk header is missing"},
		{func(_ jwt.MapClaims, h map[string]interface{}) { h["jwk"] = map[string]interface{}{"kty": "evil-kty"} }, "jwk is not a public key usable with alg"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "jti") }, "jti is missing or longer than 512 characters"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { c["htm"] = "POST" }, "htm does not match the request method"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { c["htu"] = "https://evil.example/x" }, "htu does not match the request URI"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = testNow.Add(time.Hour).Unix() }, "iat is in the future"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = testNow.Add(-time.Hour).Unix() }, "proof has expired (iat is too old)"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { delete(c, "ath") }, "ath is missing"},
		{func(c jwt.MapClaims, _ map[string]interface{}) { c["ath"] = "x" }, "ath does not match the access token"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			p := newTestPolicy(t, nil)
			resp := expectRejected(t, run(p, dpopRequest(key, key.sign(t, c.edit))), "invalid_dpop_proof")
			challenge := resp.Headers[wwwAuthenticateHeader]
			if !strings.Contains(challenge, `error_description="`+c.want+`"`) {
				t.Errorf("challenge = %q, want description %q", challenge, c.want)
			}
			if strings.Contains(challenge, "evil") || strings.Contains(string(resp.Body), "evil") {
				t.Errorf("response quotes the request: %q / %s", challenge, resp.Body)
			}
		})
	}
	t.Run("bad signature", func(t *testing.T) {
		p := newTestPolicy(t, nil)
		other := newKey(t, "ES256")
		proof := other.sign(t, func(_ jwt.MapClaims, h map[string]interface{}) { h["jwk"] = key.jwk })
		resp := expectRejected(t, run(p, dpopRequest(key, proof)), "invalid_dpop_proof")
		if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "signature does not verify with the jwk") {
			t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
		}
	})
	t.Run("alg not accepted", func(t *testing.T) {
		p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"PS256"}})
		resp := expectRejected(t, run(p, dpopRequest(key, key.sign(t, nil))), "invalid_dpop_proof")
		if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "alg is not one of the accepted algs") {
			t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
		}
	})
}

// ─── Nonces ──────────────────────────────────────────────────────────────────

// TestNonceFlow walks the use_dpop_nonce challenge, retry, rotation, forged and expired nonces, and a second replica.
func TestNonceFlow(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"requireNonce": true, "nonceSecret": "test-secret-test-secret-test-secret"})
	key := newKey(t, "ES256")

	if p.Mode().ResponseHeaderMode != policy.HeaderModeProcess {
		t.Fatal("response headers must be processed when nonces are required")
	}

	// No nonce: challenged with use_dpop_nonce and handed one.
	resp := expectRejected(t, run(p, dpopRequest(key, key.sign(t, nil))), "use_dpop_nonce")
	nonce := resp.Headers[dpopNonceHeader]
	if nonce == "" {
		t.Fatal("use_dpop_nonce challenge without a DPoP-Nonce header")
	}
	if !strings.Contains(resp.Headers[wwwAuthenticateHeader], `error_description="resource server requires nonce in DPoP proof"`) {
		t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
	}

	// Retried with the nonce: accepted, and the response carries the next nonce.
	withNonce := func(n string) func(jwt.MapClaims, map[string]interface{}) {
		return func(c jwt.MapClaims, _ map[string]interface{}) { c["nonce"] = n }
	}
	if resp.Headers["Cache-Control"] != "no-store" {
		t.Errorf("challenge carrying a nonce is cacheable: Cache-Control = %q", resp.Headers["Cache-Control"])
	}
	responseNonce := func(req *policy.RequestHeaderContext) map[string]string {
		respCtx := &policy.ResponseHeaderContext{SharedContext: req.SharedContext}
		return p.OnResponseHeaders(context.Background(), respCtx, nil).(policy.DownstreamResponseHeaderModifications).HeadersToSet
	}

	// Retried with the fresh nonce: accepted, and no new nonce is needed yet.
	req := dpopRequest(key, key.sign(t, withNonce(nonce)))
	expectAllowed(t, run(p, req))
	if h := responseNonce(req); len(h) != 0 {
		t.Errorf("fresh nonce rotated needlessly: %v", h)
	}

	// A nonce past half its lifetime is still accepted, and the response hands over the
	// next one, uncacheable.
	aging := p.nonces.issue(testNow.Add(-3 * time.Minute))
	req = dpopRequest(key, key.sign(t, withNonce(aging)))
	expectAllowed(t, run(p, req))
	if h := responseNonce(req); h[dpopNonceHeader] == "" || h["Cache-Control"] != "no-store" {
		t.Errorf("aging nonce not rotated: %v", h)
	}

	// A forged nonce, and a nonce from another secret, are refused.
	expectRejected(t, run(p, dpopRequest(key, key.sign(t, withNonce("forged")))), "use_dpop_nonce")
	other := newNonceIssuer("another-secret-another-secret-another")
	expectRejected(t, run(p, dpopRequest(key, key.sign(t, withNonce(other.issue(testNow))))), "use_dpop_nonce")

	// An expired nonce is refused.
	stale := p.nonces.issue(testNow.Add(-10 * time.Minute))
	expectRejected(t, run(p, dpopRequest(key, key.sign(t, withNonce(stale)))), "use_dpop_nonce")

	// Another replica with the same secret accepts this replica's nonce.
	replica := newTestPolicy(t, map[string]interface{}{"requireNonce": true, "nonceSecret": "test-secret-test-secret-test-secret"})
	expectAllowed(t, run(replica, dpopRequest(key, key.sign(t, withNonce(p.nonces.issue(testNow))))))
}

// TestNoResponseNonceForUnverifiedRequest sends no nonce on responses to requests the policy did not verify.
func TestNoResponseNonceForUnverifiedRequest(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"requireNonce": true})
	respCtx := &policy.ResponseHeaderContext{SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}}}
	mods := p.OnResponseHeaders(context.Background(), respCtx, nil).(policy.DownstreamResponseHeaderModifications)
	if len(mods.HeadersToSet) != 0 {
		t.Errorf("HeadersToSet = %v", mods.HeadersToSet)
	}
}

// TestNonceValidity checks nonce age limits, clock skew between replicas and the key.
func TestNonceValidity(t *testing.T) {
	n := newNonceIssuer("s")
	lifetime, skew := 5*time.Minute, 30*time.Second
	valid := func(m *nonceIssuer, nonce string) bool { _, ok := m.valid(nonce, testNow, lifetime, skew); return ok }
	if !valid(n, n.issue(testNow)) {
		t.Error("fresh nonce rejected")
	}
	if !valid(n, n.issue(testNow.Add(20*time.Second))) {
		t.Error("nonce from a replica slightly ahead rejected")
	}
	if valid(n, n.issue(testNow.Add(time.Minute))) {
		t.Error("nonce from the future accepted")
	}
	if valid(n, n.issue(testNow.Add(-6*time.Minute))) {
		t.Error("expired nonce accepted")
	}
	if valid(newNonceIssuer(""), n.issue(testNow)) {
		t.Error("nonce accepted under a different key")
	}
}

// TestModeWithoutNonce skips the response phase when nonces are off.
func TestModeWithoutNonce(t *testing.T) {
	p := newTestPolicy(t, nil)
	m := p.Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess || m.ResponseHeaderMode != policy.HeaderModeSkip ||
		m.RequestBodyMode != policy.BodyModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("Mode = %+v", m)
	}
}

// ─── Replay store ────────────────────────────────────────────────────────────

// TestReplayStore checks expiry, and that a full store refuses new entries instead of evicting live ones.
func TestReplayStore(t *testing.T) {
	key := func(s string) [32]byte { return replayKey("jkt", s) }
	s := newReplayStore(2)
	exp := testNow.Add(time.Minute)
	if s.checkAndStore(context.Background(), key("a"), exp, testNow) != replayStored || s.checkAndStore(context.Background(), key("a"), exp, testNow) != replaySeen {
		t.Fatal("first store must succeed and the second must be refused")
	}
	// After expiry, the same key is accepted again.
	if s.checkAndStore(context.Background(), key("a"), testNow.Add(3*time.Minute), testNow.Add(2*time.Minute)) != replayStored {
		t.Error("expired entry still blocks its key")
	}
	if s.checkAndStore(context.Background(), key("b"), testNow.Add(3*time.Minute), testNow.Add(2*time.Minute)) != replayStored {
		t.Fatal("second entry refused")
	}
	// Full of live entries: nothing is evicted, the new entry is refused, and both live
	// entries still block their replays (CVE-2026-41707).
	if r := s.checkAndStore(context.Background(), key("c"), testNow.Add(3*time.Minute), testNow.Add(2*time.Minute)); r != replayFull {
		t.Fatalf("store full of live entries returned %v, want replayFull", r)
	}
	for _, k := range []string{"a", "b"} {
		if s.checkAndStore(context.Background(), key(k), testNow.Add(3*time.Minute), testNow.Add(2*time.Minute)) != replaySeen {
			t.Errorf("live entry %q was evicted", k)
		}
	}
	// Once they expire, room frees up.
	if s.checkAndStore(context.Background(), key("c"), testNow.Add(5*time.Minute), testNow.Add(4*time.Minute)) != replayStored || s.size() != 1 {
		t.Errorf("expired entries not purged: size %d", s.size())
	}
}

// TestReplayCacheFullFailsClosed floods a tiny cache with valid proofs: the next
// proof is refused with 503 rather than accepted unrecorded, and an earlier proof
// still cannot be replayed.
func TestReplayCacheFullFailsClosed(t *testing.T) {
	p := newTestPolicy(t, nil)
	p.replay = newReplayStore(2)
	key := newKey(t, "ES256")
	first := key.sign(t, nil)
	expectAllowed(t, run(p, dpopRequest(key, first)))
	expectAllowed(t, run(p, dpopRequest(key, key.sign(t, nil))))
	action := run(p, dpopRequest(key, key.sign(t, nil)))
	resp, ok := action.(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 503 || resp.Headers["Retry-After"] == "" {
		t.Fatalf("full replay cache: got %T %+v, want 503 with Retry-After", action, resp)
	}
	if _, ok := resp.Headers[wwwAuthenticateHeader]; ok {
		t.Error("503 carries an authentication challenge")
	}
	expectRejected(t, run(p, dpopRequest(key, first)), "invalid_dpop_proof")
}

// ─── Configuration ───────────────────────────────────────────────────────────

// TestConfigValidation refuses unusable parameter values at deployment.
func TestConfigValidation(t *testing.T) {
	bad := []map[string]interface{}{
		{"mode": "strict"},
		{"mode": 1},
		{"allowedAlgorithms": []interface{}{"HS256"}},
		{"allowedAlgorithms": []interface{}{"none"}},
		{"allowedAlgorithms": []interface{}{}},
		{"allowedAlgorithms": "ES256"},
		{"proofMaxAge": "five minutes"},
		{"proofMaxAge": "-1m"},
		{"clockSkew": "0s"},
		{"nonceLifetime": "x"},
		{"requireNonce": "yes"},
		{"htuOrigins": []interface{}{"api.example.com"}},
		{"htuOrigins": []interface{}{"ftp://api.example.com"}},
		{"htuOrigins": []interface{}{"https://api.example.com/base"}},
		{"htuOrigins": []interface{}{"https://api.example.com?x=1"}},
		{"replayCacheMaxSize": float64(0)},
		{"replayCacheMaxSize": 1.5},
		{"nonceSecret": "too-short"},
	}
	for _, params := range bad {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("GetPolicy accepted %v", params)
		}
	}
}

// TestConfigDefaults checks the defaults applied when no parameters are set.
func TestConfigDefaults(t *testing.T) {
	p := newTestPolicy(t, nil)
	c := p.cfg
	if c.mode != modeRequired || c.proofMaxAge != time.Minute || c.clockSkew != 30*time.Second ||
		c.requireNonce || c.forwardProof || len(c.htuOrigins) != 0 {
		t.Errorf("defaults = %+v", c)
	}
	if c.algsChallenge != "ES256 ES384 ES512 PS256 PS384 PS512 EdDSA Ed25519" {
		t.Errorf("algs = %q", c.algsChallenge)
	}
}

// TestConfigNormalizesOrigins normalizes htuOrigins entries, including IPv6 hosts.
func TestConfigNormalizesOrigins(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"htuOrigins": []interface{}{"HTTPS://Api.Example.com:443", "http://[::1]:8080/"}})
	want := []string{"https://api.example.com", "http://[::1]:8080"}
	if strings.Join(p.cfg.htuOrigins, ",") != strings.Join(want, ",") {
		t.Errorf("htuOrigins = %v, want %v", p.cfg.htuOrigins, want)
	}
}

// ─── Hardening from the competitive review ───────────────────────────────────

// TestCritHeaderRejected refuses a proof with a crit header (RFC 7515 section 4.1.11).
func TestCritHeaderRejected(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	proof := key.sign(t, func(_ jwt.MapClaims, h map[string]interface{}) { h["crit"] = []interface{}{"exp"} })
	expectRejected(t, run(p, dpopRequest(key, proof)), "invalid_dpop_proof")
}

// TestEd25519AlgorithmName accepts the RFC 9864 Ed25519 name and keeps it separate from EdDSA in allowedAlgorithms.
func TestEd25519AlgorithmName(t *testing.T) {
	key := newKey(t, "Ed25519")
	expectAllowed(t, run(newTestPolicy(t, nil), dpopRequest(key, key.sign(t, nil))))
	// Allowing only the deprecated EdDSA name does not admit Ed25519, and vice versa.
	p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"EdDSA"}})
	expectRejected(t, run(p, dpopRequest(key, key.sign(t, nil))), "invalid_dpop_proof")
	ed := newKey(t, "EdDSA")
	p = newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"Ed25519"}})
	expectRejected(t, run(p, dpopRequest(ed, ed.sign(t, nil))), "invalid_dpop_proof")
}

// TestMultipleAuthorizationHeaders answers 400 invalid_request to repeated or folded Authorization headers.
func TestMultipleAuthorizationHeaders(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"mode": modeOptional})
	key := newKey(t, "ES256")
	req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken, "Bearer " + testToken}, proofs: []string{key.sign(t, nil)}})
	resp, ok := run(p, req).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 400 || !strings.Contains(resp.Headers[wwwAuthenticateHeader], `error="invalid_request"`) {
		t.Fatalf("got %+v, want 400 invalid_request", resp)
	}
	// The same two credentials folded into one header by a proxy.
	req = newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken + ",Bearer " + testToken}, proofs: []string{key.sign(t, nil)}})
	if resp, ok := run(p, req).(policy.ImmediateResponse); !ok || resp.StatusCode != 400 {
		t.Fatalf("folded Authorization: got %+v, want 400", resp)
	}
}

// TestBearerChallengeForBearerScheme reports a Bearer-scheme error in a Bearer challenge with DPoP algs.
func TestBearerChallengeForBearerScheme(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"ES256"}})
	key := newKey(t, "ES256")
	req := newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"Bearer " + testToken}})
	resp := expectRejected(t, run(p, req), "invalid_token")
	want := `Bearer error="invalid_token", error_description="DPoP-bound access token requires the DPoP authorization scheme", DPoP algs="ES256"`
	if resp.Headers[wwwAuthenticateHeader] != want {
		t.Errorf("WWW-Authenticate = %q, want %q", resp.Headers[wwwAuthenticateHeader], want)
	}
}

// TestMalformedBindingIsRefused refuses a cnf it cannot read reliably, even in optional mode.
func TestMalformedBindingIsRefused(t *testing.T) {
	key := newKey(t, "ES256")
	cases := map[string]*policy.AuthContext{
		"jkt not a string": {Authenticated: true, AuthType: "jwt",
			TypedProperties: map[string]interface{}{"cnf": map[string]interface{}{"jkt": 42.0}}},
		"empty jkt": {Authenticated: true, AuthType: "jwt",
			TypedProperties: map[string]interface{}{"cnf": map[string]interface{}{"jkt": ""}}},
		"cnf not JSON":                {Authenticated: true, AuthType: "opaque", Properties: map[string]string{"cnf": "{"}},
		"token_type DPoP without cnf": {Authenticated: true, AuthType: "opaque", Properties: map[string]string{"token_type": "DPoP"}},
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			// Optional mode must not let these through as unbound bearer tokens.
			p := newTestPolicy(t, map[string]interface{}{"mode": modeOptional})
			req := newRequest(reqOpts{auth: auth, authz: []string{"Bearer " + testToken}, proofs: []string{key.sign(t, nil)}})
			expectRejected(t, run(p, req), "invalid_token")
		})
	}
}

// TestOpaqueTokenTypeDPoPWithBinding accepts an introspected DPoP token that carries cnf.jkt.
func TestOpaqueTokenTypeDPoPWithBinding(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	cnf, _ := json.Marshal(map[string]string{"jkt": key.jkt})
	auth := &policy.AuthContext{Authenticated: true, AuthType: "opaque", TokenId: fingerprint(testToken),
		Properties: map[string]string{"cnf": string(cnf), "token_type": "DPoP"}}
	req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectAllowed(t, run(p, req))
}

// TestNonASCIIHostRefused refuses Unicode hosts and normalizes punycode, IPv6 and empty ports.
func TestNonASCIIHostRefused(t *testing.T) {
	if _, err := normalizeOrigin("https", "bücher.example"); err == nil {
		t.Error("Unicode host accepted")
	}
	if got, err := normalizeOrigin("https", "xn--bcher-kva.example:443"); err != nil || got != "https://xn--bcher-kva.example" {
		t.Errorf("punycode host = %q, %v", got, err)
	}
	if got, _ := normalizeOrigin("https", "[2001:DB8::1]:443"); got != "https://[2001:db8::1]" {
		t.Errorf("IPv6 host = %q", got)
	}
	if got, _ := normalizeOrigin("https", "api.example.com:"); got != "https://api.example.com" {
		t.Errorf("empty port = %q", got)
	}
}

// TestOnlyAccessTokenLayersCount checks that layers from policies that do not
// validate an access token neither satisfy the policy nor supply a binding: the
// gateway's own backend credentials (oauth2-generator), and client credentials
// without a token (api-key-auth), even when such a layer carries a cnf property.
func TestOnlyAccessTokenLayersCount(t *testing.T) {
	victim, attacker := newKey(t, "ES256"), newKey(t, "ES256")
	planted := map[string]string{"cnf": `{"jkt":"` + attacker.jkt + `"}`}
	cases := map[string]*policy.AuthContext{
		"backend credentials only": {Authenticated: true, AuthType: "oauth2"},
		"api key only":             {Authenticated: true, AuthType: "apikey", Properties: planted},
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTestPolicy(t, map[string]interface{}{"mode": modeOptional})
			for _, authz := range []string{"Bearer " + testToken, "DPoP " + testToken} {
				req := newRequest(reqOpts{auth: auth, authz: []string{authz}, proofs: []string{attacker.sign(t, nil)}})
				resp := expectRejected(t, run(p, req), "invalid_token")
				if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "access token required") {
					t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
				}
			}
		})
	}
	t.Run("planted cnf above a real token", func(t *testing.T) {
		p := newTestPolicy(t, nil)
		auth := &policy.AuthContext{Authenticated: true, AuthType: "apikey", Properties: planted, Previous: boundJWT(victim.jkt)}
		req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{attacker.sign(t, nil)}})
		expectRejected(t, run(p, req), "invalid_token")
	})
}

// TestMCPAuthLayerCarriesBinding accepts the binding from mcp-auth, which validates
// the token through jwt-auth and records its layer as mcp/oauth.
func TestMCPAuthLayerCarriesBinding(t *testing.T) {
	p := newTestPolicy(t, nil)
	key := newKey(t, "ES256")
	auth := boundJWT(key.jkt)
	auth.AuthType = "mcp/oauth"
	req := newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	expectAllowed(t, run(p, req))
}

// TestMisconfigurationWarningIsRateLimited logs the missing access-token policy once
// a minute, not once per refused request, even when the engine builds several
// instances of the policy for the same API.
func TestMisconfigurationWarningIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warnLimiter.mu.Lock()
	warnLimiter.last = make(map[string]time.Time)
	warnLimiter.mu.Unlock()

	now := testNow
	instances := []*DPoPPolicy{newTestPolicy(t, nil), newTestPolicy(t, nil)}
	for _, p := range instances {
		p.now = func() time.Time { return now }
	}
	req := func() *policy.RequestHeaderContext {
		return newRequest(reqOpts{authz: []string{"DPoP " + testToken}, proofs: []string{"x.y.z"}})
	}
	for i := 0; i < 6; i++ {
		run(instances[i%2], req())
	}
	now = now.Add(61 * time.Second)
	run(instances[0], req())
	if n := strings.Count(buf.String(), "no access-token policy authenticated the request"); n != 2 {
		t.Errorf("logged %d warnings for 7 requests over 61s on two instances, want 2:\n%s", n, buf.String())
	}
}

// TestAccessTokenAuthTypesIsConfigurable enables a new token policy by configuration:
// its layer is ignored by default, with a warning naming its type, and trusted once
// its type is listed in accessTokenAuthTypes.
func TestAccessTokenAuthTypesIsConfigurable(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warnLimiter.mu.Lock()
	warnLimiter.last = make(map[string]time.Time)
	warnLimiter.mu.Unlock()

	key := newKey(t, "ES256")
	custom := boundJWT(key.jkt)
	custom.AuthType = "acme-token"
	request := func() *policy.RequestHeaderContext {
		return newRequest(reqOpts{auth: custom, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})
	}

	expectRejected(t, run(newTestPolicy(t, nil), request()), "invalid_token")
	if !strings.Contains(buf.String(), "acme-token") {
		t.Errorf("warning does not name the ignored type:\n%s", buf.String())
	}

	p := newTestPolicy(t, map[string]interface{}{"accessTokenAuthTypes": []interface{}{"jwt", "acme-token"}})
	expectAllowed(t, run(p, request()))
	// Listing a type replaces the default list: opaque is no longer trusted here.
	opaque := boundJWT(key.jkt)
	opaque.AuthType = "opaque"
	expectRejected(t, run(p, newRequest(reqOpts{auth: opaque, authz: []string{"DPoP " + testToken}, proofs: []string{key.sign(t, nil)}})), "invalid_token")
}

// TestAccessTokenAuthTypesValidation refuses an empty list or an empty type.
func TestAccessTokenAuthTypesValidation(t *testing.T) {
	for _, v := range []interface{}{[]interface{}{}, []interface{}{" "}, "jwt"} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"accessTokenAuthTypes": v}); err == nil {
			t.Errorf("GetPolicy accepted accessTokenAuthTypes %v", v)
		}
	}
}

// TestDefaultAlgorithmsAreFAPISafe refuses RS256 proofs by default, as FAPI 2.0
// requires, and accepts them once listed.
func TestDefaultAlgorithmsAreFAPISafe(t *testing.T) {
	key := newKey(t, "RS256")
	resp := expectRejected(t, run(newTestPolicy(t, nil), dpopRequest(key, key.sign(t, nil))), "invalid_dpop_proof")
	if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "alg is not one of the accepted algs") {
		t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
	}
	p := newTestPolicy(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"ES256", "RS256"}})
	expectAllowed(t, run(p, dpopRequest(key, key.sign(t, nil))))
}

// TestPlainHTTPNeedsExplicitOrigin refuses a proof whose htu is http, even when it
// matches the request, unless the http origin is listed in htuOrigins.
func TestPlainHTTPNeedsExplicitOrigin(t *testing.T) {
	key := newKey(t, "ES256")
	httpProof := func() string {
		return key.sign(t, func(c jwt.MapClaims, _ map[string]interface{}) { c["htu"] = "http://api.example.com/orders/v1/items" })
	}
	request := func(proof string) *policy.RequestHeaderContext {
		return newRequest(reqOpts{auth: boundJWT(key.jkt), authz: []string{"DPoP " + testToken}, proofs: []string{proof}, scheme: "http"})
	}
	resp := expectRejected(t, run(newTestPolicy(t, nil), request(httpProof())), "invalid_dpop_proof")
	if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "htu must use https") {
		t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
	}
	p := newTestPolicy(t, map[string]interface{}{"htuOrigins": []interface{}{"http://api.example.com"}})
	expectAllowed(t, run(p, request(httpProof())))
}

// TestAuthorizationTokenMustBeTheValidatedOne refuses a request whose Authorization
// token, which the proof's ath covers, is not the token the access-token policy
// validated, as happens when that policy reads the token from another header.
func TestAuthorizationTokenMustBeTheValidatedOne(t *testing.T) {
	key := newKey(t, "ES256")
	jwtWith := func(claims map[string]interface{}) string {
		payload, _ := json.Marshal(claims)
		return "eyJhbGciOiJSUzI1NiJ9." + enc(payload) + ".c2ln"
	}
	cnf := map[string]interface{}{"jkt": key.jkt}
	send := func(auth *policy.AuthContext, token string) policy.RequestHeaderAction {
		proof := key.sign(t, func(c jwt.MapClaims, _ map[string]interface{}) { c["ath"] = accessTokenHash(token) })
		return run(newTestPolicy(t, nil), newRequest(reqOpts{auth: auth, authz: []string{"DPoP " + token}, proofs: []string{proof}}))
	}
	mismatch := func(t *testing.T, action policy.RequestHeaderAction) {
		t.Helper()
		resp := expectRejected(t, action, "invalid_token")
		if !strings.Contains(resp.Headers[wwwAuthenticateHeader], "access token mismatch") {
			t.Errorf("challenge = %q", resp.Headers[wwwAuthenticateHeader])
		}
	}

	t.Run("custom header: policy validated token B, Authorization carries token A", func(t *testing.T) {
		validated := boundJWT(key.jkt) // jwt-auth recorded token B's jti
		mismatch(t, send(validated, jwtWith(map[string]interface{}{"jti": "token-A", "iss": "https://idp.example", "cnf": cnf})))
		mismatch(t, send(validated, "an-arbitrary-string"))
	})
	t.Run("opaque fingerprint matches", func(t *testing.T) {
		auth := boundJWT(key.jkt)
		auth.AuthType, auth.TokenId = "opaque", fingerprint("opaque-token-123")
		expectAllowed(t, send(auth, "opaque-token-123"))
		mismatch(t, send(auth, "opaque-token-456"))
	})
	t.Run("jwt jti matches", func(t *testing.T) {
		auth := boundJWT(key.jkt)
		auth.TokenId = "jti-42"
		expectAllowed(t, send(auth, jwtWith(map[string]interface{}{"jti": "jti-42", "cnf": cnf})))
	})
	t.Run("jwt without jti: same issuer and binding", func(t *testing.T) {
		auth := boundJWT(key.jkt)
		auth.TokenId = ""
		expectAllowed(t, send(auth, jwtWith(map[string]interface{}{"iss": "https://idp.example", "cnf": cnf})))
		mismatch(t, send(auth, jwtWith(map[string]interface{}{"iss": "https://other.example", "cnf": cnf})))
		mismatch(t, send(auth, jwtWith(map[string]interface{}{"iss": "https://idp.example", "cnf": map[string]interface{}{"jkt": "other"}})))
	})
	t.Run("nothing to compare: refused", func(t *testing.T) {
		auth := boundJWT(key.jkt)
		auth.TokenId = ""
		mismatch(t, send(auth, "opaque-token-123"))
	})
}
