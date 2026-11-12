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

package steps

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

// policySteps holds the state the backend-jwt policy's steps share within one runner. The steps
// read the backend JWT and the gateway JWK Set from context values that shared steps stored, so
// they verify the token the way a backend would, using only the standard library.
type policySteps struct {
	topo *frameworkruntime.Topology
}

func newPolicySteps(topo *frameworkruntime.Topology) *policySteps {
	return &policySteps{topo: topo}
}

// register binds the steps below. Add a step here only when no shared step expresses the
// behaviour, and give it a unit test in steps_test.go.
func (s *policySteps) register(sc *godog.ScenarioContext) {
	sc.Step(`^the JWT "([^"]*)" should verify against the JWK Set "([^"]*)"$`, s.jwtShouldVerify)
	sc.Step(`^the JWT "([^"]*)" should not verify against the JWK Set "([^"]*)" once its claims are altered$`, s.alteredJWTShouldNotVerify)
	sc.Step(`^the JWT "([^"]*)" (header|claim) "([^"]*)" should (be|contain) "([^"]*)"$`, s.jwtMemberShouldMatch)
	sc.Step(`^the JWT "([^"]*)" (header|claim) "([^"]*)" should not exist$`, s.jwtMemberShouldNotExist)
	sc.Step(`^the JWT "([^"]*)" should expire (\d+) seconds after it was issued$`, s.jwtShouldExpireAfter)
	sc.Step(`^the JWT "([^"]*)" should have been issued within the last (\d+) seconds$`, s.jwtShouldBeIssuedWithin)
	sc.Step(`^the JWT "([^"]*)" should (be the same as|differ from) the JWT "([^"]*)"$`, s.jwtsShouldCompare)
	sc.Step(`^the JWK Set "([^"]*)" should publish only public "([^"]*)" keys for "([^"]*)" signing$`, s.jwkSetShouldPublishPublicKeys)
	sc.Step(`^I load the JWK Set from "([^"]*)" and store it as "([^"]*)"$`, s.loadJWKSet)
	sc.Step(`^the JWT "([^"]*)" should (verify|not verify) against the only key in the JWK Set "([^"]*)"$`, s.jwtShouldVerifyWithOnlyKey)
}

var b64url = base64.RawURLEncoding

// privateJWKMembers are the JWK members that carry private key material (RFC 7518 §6.2.2, §6.3.2).
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// jwk is one key of a JWK Set, with the members a signature verifier needs.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// compactJWT is a compact JWS split into its parts and decoded.
type compactJWT struct {
	raw          string
	signingInput string
	signature    []byte
	header       map[string]any
	claims       map[string]any
}

func parseCompactJWT(raw string) (*compactJWT, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS: expected 3 dot-separated parts, got %d", len(parts))
	}
	t := &compactJWT{raw: raw, signingInput: parts[0] + "." + parts[1]}
	headerJSON, err := b64url.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding the JWT header: %w", err)
	}
	payloadJSON, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding the JWT payload: %w", err)
	}
	if t.signature, err = b64url.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("decoding the JWT signature: %w", err)
	}
	if err := json.Unmarshal(headerJSON, &t.header); err != nil {
		return nil, fmt.Errorf("parsing the JWT header: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(payloadJSON)))
	dec.UseNumber()
	if err := dec.Decode(&t.claims); err != nil {
		return nil, fmt.Errorf("parsing the JWT claims: %w", err)
	}
	return t, nil
}

// parseJWKSet parses a JWK Set by kid and rejects one that publishes private key material.
func parseJWKSet(raw string) (map[string]jwk, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		return nil, fmt.Errorf("parsing the JWK Set: %w", err)
	}
	keys := make(map[string]jwk, len(set.Keys))
	for i, rawKey := range set.Keys {
		var members map[string]any
		if err := json.Unmarshal(rawKey, &members); err != nil {
			return nil, fmt.Errorf("parsing JWK %d: %w", i, err)
		}
		for _, private := range privateJWKMembers {
			if _, ok := members[private]; ok {
				return nil, fmt.Errorf("JWK %d publishes the private member %q", i, private)
			}
		}
		var k jwk
		if err := json.Unmarshal(rawKey, &k); err != nil {
			return nil, fmt.Errorf("parsing JWK %d: %w", i, err)
		}
		if k.Kid == "" {
			return nil, fmt.Errorf("JWK %d has no kid", i)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, fmt.Errorf("JWK Set has two keys with kid %q", k.Kid)
		}
		keys[k.Kid] = k
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWK Set has no keys")
	}
	return keys, nil
}

func (s *policySteps) resolveJWT(ctx context.Context, key string) (*compactJWT, error) {
	raw, err := tcontext.ResolveString(ctx, strings.TrimSpace(key))
	if err != nil {
		return nil, err
	}
	return parseCompactJWT(raw)
}

func (s *policySteps) resolveJWKSet(ctx context.Context, key string) (map[string]jwk, error) {
	raw, err := tcontext.ResolveString(ctx, strings.TrimSpace(key))
	if err != nil {
		return nil, err
	}
	return parseJWKSet(raw)
}

func (s *policySteps) jwtShouldVerify(ctx context.Context, tokenKey, setKey string) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	keys, err := s.resolveJWKSet(ctx, setKey)
	if err != nil {
		return err
	}
	return verifyJWT(token, keys)
}

// alteredJWTShouldNotVerify keeps the signature and changes one claim. A verifier that accepts the
// result would make every passing signature check meaningless.
func (s *policySteps) alteredJWTShouldNotVerify(ctx context.Context, tokenKey, setKey string) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	keys, err := s.resolveJWKSet(ctx, setKey)
	if err != nil {
		return err
	}
	altered, err := alterClaim(token, "sub", "someone-else")
	if err != nil {
		return err
	}
	if verifyJWT(altered, keys) == nil {
		return fmt.Errorf("JWT %q still verified against JWK Set %q after its claims were altered", tokenKey, setKey)
	}
	return nil
}

func alterClaim(t *compactJWT, name, value string) (*compactJWT, error) {
	claims := make(map[string]any, len(t.claims)+1)
	maps.Copy(claims, t.claims)
	claims[name] = value
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encoding altered claims: %w", err)
	}
	altered := *t
	altered.signingInput = strings.SplitN(t.raw, ".", 2)[0] + "." + b64url.EncodeToString(payload)
	return &altered, nil
}

// verifyJWT selects the key by the JWT's kid and verifies the signature with it. The JWT's alg must
// equal the key's published alg, so a token cannot choose a different algorithm than its key's.
func verifyJWT(t *compactJWT, keys map[string]jwk) error {
	kid, _ := t.header["kid"].(string)
	if kid == "" {
		return fmt.Errorf("JWT has no kid header")
	}
	key, ok := keys[kid]
	if !ok {
		return fmt.Errorf("JWT kid %q is not in the JWK Set", kid)
	}
	alg, _ := t.header["alg"].(string)
	if alg != key.Alg {
		return fmt.Errorf("JWT alg %q does not match the alg %q of key %q", alg, key.Alg, kid)
	}
	return verifySignature(key, alg, []byte(t.signingInput), t.signature)
}

func verifySignature(key jwk, alg string, input, sig []byte) error {
	switch alg {
	case "RS256", "PS256":
		pub, err := rsaPublicKey(key)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(input)
		if alg == "RS256" {
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
		}
		return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256", "ES384":
		pub, size, err := ecPublicKey(key)
		if err != nil {
			return err
		}
		if len(sig) != 2*size {
			return fmt.Errorf("%s signature is %d bytes, want %d", alg, len(sig), 2*size)
		}
		var digest []byte
		if alg == "ES256" {
			d := sha256.Sum256(input)
			digest = d[:]
		} else {
			d := sha512.Sum384(input)
			digest = d[:]
		}
		if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])) {
			return fmt.Errorf("%s signature does not verify", alg)
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWT alg %q", alg)
	}
}

func rsaPublicKey(k jwk) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("key %q is %q, not RSA", k.Kid, k.Kty)
	}
	n, err := b64url.DecodeString(k.N)
	if err != nil || len(n) == 0 {
		return nil, fmt.Errorf("key %q has an invalid modulus", k.Kid)
	}
	e, err := b64url.DecodeString(k.E)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, fmt.Errorf("key %q has an invalid exponent", k.Kid)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}

func ecPublicKey(k jwk) (*ecdsa.PublicKey, int, error) {
	if k.Kty != "EC" {
		return nil, 0, fmt.Errorf("key %q is %q, not EC", k.Kid, k.Kty)
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, 0, fmt.Errorf("key %q has the unsupported curve %q", k.Kid, k.Crv)
	}
	x, errX := b64url.DecodeString(k.X)
	y, errY := b64url.DecodeString(k.Y)
	if errX != nil || errY != nil {
		return nil, 0, fmt.Errorf("key %q has an invalid point", k.Kid)
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, (curve.Params().BitSize + 7) / 8, nil
}

func members(t *compactJWT, part string) map[string]any {
	if part == "header" {
		return t.header
	}
	return t.claims
}

// jwtMemberShouldMatch compares a header parameter or claim with want, after expanding context
// references in want. "contain" also accepts an array member equal to want, as for "aud".
func (s *policySteps) jwtMemberShouldMatch(ctx context.Context, tokenKey, part, name, op, want string) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	if want, err = stepscommon.Expand(ctx, want); err != nil {
		return err
	}
	v, ok := members(token, part)[name]
	if !ok {
		return fmt.Errorf("JWT %q has no %s %q", tokenKey, part, name)
	}
	if op == "contain" {
		if items, isArray := v.([]any); isArray {
			for _, item := range items {
				if fmt.Sprint(item) == want {
					return nil
				}
			}
			return fmt.Errorf("JWT %q %s %q = %v, want it to contain %q", tokenKey, part, name, v, want)
		}
	}
	if got := fmt.Sprint(v); got != want {
		return fmt.Errorf("JWT %q %s %q = %q, want %q", tokenKey, part, name, got, want)
	}
	return nil
}

func (s *policySteps) jwtMemberShouldNotExist(ctx context.Context, tokenKey, part, name string) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	if v, ok := members(token, part)[name]; ok {
		return fmt.Errorf("JWT %q %s %q should not exist, got %v", tokenKey, part, name, v)
	}
	return nil
}

func numericClaim(t *compactJWT, name string) (int64, error) {
	n, ok := t.claims[name].(json.Number)
	if !ok {
		return 0, fmt.Errorf("JWT claim %q is missing or not a number", name)
	}
	return n.Int64()
}

func (s *policySteps) jwtShouldExpireAfter(ctx context.Context, tokenKey string, seconds int) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	iat, err := numericClaim(token, "iat")
	if err != nil {
		return err
	}
	exp, err := numericClaim(token, "exp")
	if err != nil {
		return err
	}
	if exp-iat != int64(seconds) {
		return fmt.Errorf("JWT %q lifetime exp-iat = %ds, want %ds", tokenKey, exp-iat, seconds)
	}
	return nil
}

// issuedSkew tolerates a gateway clock slightly ahead of the test process.
const issuedSkew = 5 * time.Second

func (s *policySteps) jwtShouldBeIssuedWithin(ctx context.Context, tokenKey string, seconds int) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	iat, err := numericClaim(token, "iat")
	if err != nil {
		return err
	}
	age := time.Since(time.Unix(iat, 0))
	if age < -issuedSkew || age > time.Duration(seconds)*time.Second {
		return fmt.Errorf("JWT %q was issued %s ago, want within %ds", tokenKey, age.Round(time.Second), seconds)
	}
	return nil
}

func (s *policySteps) jwtsShouldCompare(ctx context.Context, tokenKey, relation, otherKey string) error {
	a, err := tcontext.ResolveString(ctx, strings.TrimSpace(tokenKey))
	if err != nil {
		return err
	}
	b, err := tcontext.ResolveString(ctx, strings.TrimSpace(otherKey))
	if err != nil {
		return err
	}
	same := a == b
	if relation == "be the same as" && !same {
		return fmt.Errorf("JWT %q differs from JWT %q", tokenKey, otherKey)
	}
	if relation == "differ from" && same {
		return fmt.Errorf("JWT %q is the same as JWT %q", tokenKey, otherKey)
	}
	return nil
}

func (s *policySteps) jwkSetShouldPublishPublicKeys(ctx context.Context, setKey, kty, alg string) error {
	keys, err := s.resolveJWKSet(ctx, setKey)
	if err != nil {
		return err
	}
	for kid, k := range keys {
		if k.Kty != kty || k.Alg != alg || k.Use != "sig" {
			return fmt.Errorf("JWK %q is kty %q alg %q use %q, want kty %q alg %q use \"sig\"", kid, k.Kty, k.Alg, k.Use, kty, alg)
		}
	}
	return nil
}

// loadJWKSet reads a JWK Set file of the suite, such as the public half of a policy-level key, and
// stores it for the JWT steps. The path is relative to the suite directory, the working directory
// of the suite test, and may not leave it.
func (s *policySteps) loadJWKSet(ctx context.Context, path, key string) error {
	clean := filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("JWK Set path %q must be relative to the suite directory", path)
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return fmt.Errorf("reading the JWK Set %q: %w", path, err)
	}
	if _, err := parseJWKSet(string(raw)); err != nil {
		return fmt.Errorf("JWK Set %q: %w", path, err)
	}
	local, ok := tcontext.LocalOf(ctx)
	if !ok {
		return fmt.Errorf("no scenario context to store %q in", key)
	}
	local.Set(key, string(raw))
	return nil
}

// jwtShouldVerifyWithOnlyKey verifies a JWT the way a backend that pins one key does: with the
// set's single key, whatever kid the JWT carries or lacks. The JWT's alg must still equal the
// key's alg.
func (s *policySteps) jwtShouldVerifyWithOnlyKey(ctx context.Context, tokenKey, outcome, setKey string) error {
	token, err := s.resolveJWT(ctx, tokenKey)
	if err != nil {
		return err
	}
	keys, err := s.resolveJWKSet(ctx, setKey)
	if err != nil {
		return err
	}
	if len(keys) != 1 {
		return fmt.Errorf("JWK Set %q has %d keys, want exactly one", setKey, len(keys))
	}
	var key jwk
	for _, k := range keys {
		key = k
	}
	verifyErr := func() error {
		alg, _ := token.header["alg"].(string)
		if alg != key.Alg {
			return fmt.Errorf("JWT alg %q does not match the alg %q of key %q", alg, key.Alg, key.Kid)
		}
		return verifySignature(key, alg, []byte(token.signingInput), token.signature)
	}()
	switch {
	case outcome == "verify" && verifyErr != nil:
		return fmt.Errorf("JWT %q does not verify against the only key in JWK Set %q: %w", tokenKey, setKey, verifyErr)
	case outcome == "not verify" && verifyErr == nil:
		return fmt.Errorf("JWT %q verified against the only key in JWK Set %q", tokenKey, setKey)
	}
	return nil
}
