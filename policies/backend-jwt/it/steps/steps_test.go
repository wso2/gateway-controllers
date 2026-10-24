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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

func TestRegisterBindsThePolicySteps(t *testing.T) {
	dir := t.TempDir()
	feature := "Feature: the policy steps\n  Scenario: the JWT verification step is bound\n" +
		"    Then the JWT \"missing\" should verify against the JWK Set \"missing\"\n"
	if err := os.WriteFile(filepath.Join(dir, "steps.feature"), []byte(feature), 0o600); err != nil {
		t.Fatal(err)
	}
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) { Register(sc, nil) },
		Options:             &godog.Options{Format: "progress", Paths: []string{dir}, Strict: true, NoColors: true},
	}
	// The step is bound, so the scenario fails on the missing context value rather than as
	// undefined, which Strict would report with a different status.
	if status := suite.Run(); status != 1 {
		t.Fatalf("expected the bound step to fail on the missing value, status %d", status)
	}
}

// signer signs compact JWTs for the tests with the standard library only.
type signer struct {
	alg string
	kid string
	key crypto.Signer
}

func (s signer) jwk(t *testing.T) map[string]any {
	t.Helper()
	switch k := s.key.Public().(type) {
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "kid": s.kid, "use": "sig", "alg": s.alg,
			"n": b64url.EncodeToString(k.N.Bytes()), "e": b64url.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		point, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"kty": "EC", "kid": s.kid, "use": "sig", "alg": s.alg, "crv": k.Curve.Params().Name,
			"x": b64url.EncodeToString(point[1 : 1+size]), "y": b64url.EncodeToString(point[1+size:])}
	}
	t.Fatalf("unsupported key %T", s.key)
	return nil
}

func (s signer) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64url.EncodeToString(h) + "." + b64url.EncodeToString(c)
	var sig []byte
	switch s.alg {
	case "RS256":
		d := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA256, d[:])
	case "PS256":
		d := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPSS(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256", "ES384":
		var digest []byte
		size := 32
		if s.alg == "ES256" {
			d := sha256.Sum256([]byte(input))
			digest = d[:]
		} else {
			d := sha512.Sum384([]byte(input))
			digest, size = d[:], 48
		}
		var r, sv *big.Int
		r, sv, err = ecdsa.Sign(rand.Reader, s.key.(*ecdsa.PrivateKey), digest)
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		sv.FillBytes(sig[size:])
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64url.EncodeToString(sig)
}

func (s signer) token(t *testing.T, claims map[string]any) string {
	return s.sign(t, map[string]any{"alg": s.alg, "kid": s.kid, "typ": "JWT"}, claims)
}

func newRSASigner(t *testing.T, alg, kid string) signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{alg: alg, kid: kid, key: k}
}

func newECSigner(t *testing.T, alg, kid string, curve elliptic.Curve) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{alg: alg, kid: kid, key: k}
}

func jwkSet(t *testing.T, keys ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func scenario(values map[string]any) context.Context {
	local := tcontext.NewLocal("runner")
	for k, v := range values {
		local.Set(k, v)
	}
	return tcontext.WithLocal(context.Background(), local)
}

func baseClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"sub": "test-user", "iss": "gw", "iat": now, "exp": now + 900,
		"aud": []string{"test-audience"}, "auth_type": "jwt"}
}

func TestJWTVerifiesForEverySupportedAlgorithm(t *testing.T) {
	for _, s := range []signer{
		newRSASigner(t, "RS256", "rsa"),
		newRSASigner(t, "PS256", "pss"),
		newECSigner(t, "ES256", "p256", elliptic.P256()),
		newECSigner(t, "ES384", "p384", elliptic.P384()),
	} {
		t.Run(s.alg, func(t *testing.T) {
			ctx := scenario(map[string]any{"jwt": s.token(t, baseClaims()), "jwks": jwkSet(t, s.jwk(t))})
			steps := newPolicySteps(nil)
			if err := steps.jwtShouldVerify(ctx, "jwt", "jwks"); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := steps.alteredJWTShouldNotVerify(ctx, "jwt", "jwks"); err != nil {
				t.Fatalf("altered: %v", err)
			}
		})
	}
}

func TestJWTVerificationFailures(t *testing.T) {
	gw := newRSASigner(t, "RS256", "gw")
	other := newRSASigner(t, "RS256", "gw") // same kid, different key
	set := jwkSet(t, gw.jwk(t))

	cases := map[string]string{
		"signed by another key": other.token(t, baseClaims()),
		"kid not in the set":    newRSASigner(t, "RS256", "unknown").token(t, baseClaims()),
		"no kid":                gw.sign(t, map[string]any{"alg": "RS256"}, baseClaims()),
		"alg differs from key":  gw.sign(t, map[string]any{"alg": "PS256", "kid": "gw"}, baseClaims()),
		"unsupported alg":       gw.sign(t, map[string]any{"alg": "HS256", "kid": "gw"}, baseClaims()),
		"not a JWS":             "not.a-jwt",
		"bad base64":            "!!!.e30.sig",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := scenario(map[string]any{"jwt": token, "jwks": set})
			if err := newPolicySteps(nil).jwtShouldVerify(ctx, "jwt", "jwks"); err == nil {
				t.Fatal("verification passed")
			}
		})
	}

	t.Run("missing context values", func(t *testing.T) {
		if err := newPolicySteps(nil).jwtShouldVerify(scenario(nil), "jwt", "jwks"); err == nil {
			t.Fatal("verification passed with no stored values")
		}
	})
}

func TestJWKSetValidation(t *testing.T) {
	gw := newRSASigner(t, "RS256", "gw")
	withPrivate := gw.jwk(t)
	withPrivate["d"] = "secret"
	noKid := gw.jwk(t)
	delete(noKid, "kid")

	cases := map[string]string{
		"private member": jwkSet(t, withPrivate),
		"no keys":        `{"keys":[]}`,
		"duplicate kid":  jwkSet(t, gw.jwk(t), gw.jwk(t)),
		"no kid":         jwkSet(t, noKid),
		"not JSON":       `keys`,
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseJWKSet(set); err == nil {
				t.Fatal("JWK Set accepted")
			}
		})
	}

	ctx := scenario(map[string]any{"jwks": jwkSet(t, gw.jwk(t))})
	steps := newPolicySteps(nil)
	if err := steps.jwkSetShouldPublishPublicKeys(ctx, "jwks", "RSA", "RS256"); err != nil {
		t.Fatalf("public RSA set: %v", err)
	}
	if err := steps.jwkSetShouldPublishPublicKeys(ctx, "jwks", "EC", "ES256"); err == nil {
		t.Fatal("RSA set reported as EC")
	}
}

func TestJWTMemberAssertions(t *testing.T) {
	gw := newRSASigner(t, "RS256", "gw")
	ctx := scenario(map[string]any{"jwt": gw.token(t, baseClaims())})
	steps := newPolicySteps(nil)

	pass := []struct{ part, name, op, want string }{
		{"header", "alg", "be", "RS256"},
		{"header", "typ", "be", "JWT"},
		{"claim", "sub", "be", "test-user"},
		{"claim", "aud", "contain", "test-audience"},
		{"claim", "sub", "contain", "test-user"},
	}
	for _, c := range pass {
		if err := steps.jwtMemberShouldMatch(ctx, "jwt", c.part, c.name, c.op, c.want); err != nil {
			t.Errorf("%s %s %s %q: %v", c.part, c.name, c.op, c.want, err)
		}
	}
	fail := []struct{ part, name, op, want string }{
		{"claim", "sub", "be", "someone"},
		{"claim", "aud", "contain", "other"},
		{"claim", "missing", "be", "x"},
		{"header", "kid", "be", "other"},
	}
	for _, c := range fail {
		if err := steps.jwtMemberShouldMatch(ctx, "jwt", c.part, c.name, c.op, c.want); err == nil {
			t.Errorf("%s %s %s %q passed", c.part, c.name, c.op, c.want)
		}
	}

	expanded := scenario(map[string]any{"jwt": gw.token(t, baseClaims()), "user": "test-user"})
	if err := steps.jwtMemberShouldMatch(expanded, "jwt", "claim", "sub", "be", "${CTX:user}"); err != nil {
		t.Errorf("context reference in the expected value: %v", err)
	}

	if err := steps.jwtMemberShouldNotExist(ctx, "jwt", "header", "jku"); err != nil {
		t.Errorf("absent header: %v", err)
	}
	if err := steps.jwtMemberShouldNotExist(ctx, "jwt", "claim", "sub"); err == nil {
		t.Error("present claim reported absent")
	}
}

func TestJWTLifetimeAssertions(t *testing.T) {
	gw := newRSASigner(t, "RS256", "gw")
	fresh := baseClaims()
	stale := baseClaims()
	stale["iat"] = time.Now().Add(-time.Hour).Unix()
	noExp := baseClaims()
	delete(noExp, "exp")
	ctx := scenario(map[string]any{
		"fresh": gw.token(t, fresh), "stale": gw.token(t, stale), "noExp": gw.token(t, noExp),
	})
	steps := newPolicySteps(nil)

	if err := steps.jwtShouldExpireAfter(ctx, "fresh", 900); err != nil {
		t.Errorf("lifetime: %v", err)
	}
	if err := steps.jwtShouldExpireAfter(ctx, "fresh", 300); err == nil {
		t.Error("wrong lifetime passed")
	}
	if err := steps.jwtShouldExpireAfter(ctx, "noExp", 900); err == nil {
		t.Error("missing exp passed")
	}
	if err := steps.jwtShouldBeIssuedWithin(ctx, "fresh", 60); err != nil {
		t.Errorf("fresh token: %v", err)
	}
	if err := steps.jwtShouldBeIssuedWithin(ctx, "stale", 60); err == nil {
		t.Error("an hour-old token passed")
	}
}

func TestJWTComparison(t *testing.T) {
	ctx := scenario(map[string]any{"a": "x.y.z", "b": "x.y.z", "c": "x.y.w"})
	steps := newPolicySteps(nil)
	if err := steps.jwtsShouldCompare(ctx, "a", "be the same as", "b"); err != nil {
		t.Error(err)
	}
	if err := steps.jwtsShouldCompare(ctx, "a", "differ from", "c"); err != nil {
		t.Error(err)
	}
	if err := steps.jwtsShouldCompare(ctx, "a", "differ from", "b"); err == nil {
		t.Error("equal tokens reported different")
	}
	if err := steps.jwtsShouldCompare(ctx, "a", "be the same as", "missing"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("missing value: %v", err)
	}
}

func TestJWTVerifiesWithTheOnlyKeyOfASet(t *testing.T) {
	pinned := newECSigner(t, "ES256", "policy", elliptic.P256())
	set := jwkSet(t, pinned.jwk(t))
	noKid := pinned.sign(t, map[string]any{"alg": "ES256", "typ": "JWT"}, baseClaims())
	steps := newPolicySteps(nil)

	t.Run("a JWT without a kid verifies with the pinned key", func(t *testing.T) {
		ctx := scenario(map[string]any{"jwt": noKid, "jwks": set})
		if err := steps.jwtShouldVerifyWithOnlyKey(ctx, "jwt", "verify", "jwks"); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if err := steps.jwtShouldVerifyWithOnlyKey(ctx, "jwt", "not verify", "jwks"); err == nil {
			t.Fatal("the negative form passed for a JWT that verifies")
		}
	})

	failures := map[string]string{
		"signed by another key":           newECSigner(t, "ES256", "policy", elliptic.P256()).sign(t, map[string]any{"alg": "ES256"}, baseClaims()),
		"alg differs from the pinned key": newRSASigner(t, "RS256", "gw").token(t, baseClaims()),
	}
	for name, token := range failures {
		t.Run(name, func(t *testing.T) {
			ctx := scenario(map[string]any{"jwt": token, "jwks": set})
			if err := steps.jwtShouldVerifyWithOnlyKey(ctx, "jwt", "verify", "jwks"); err == nil {
				t.Fatal("verification passed")
			}
			if err := steps.jwtShouldVerifyWithOnlyKey(ctx, "jwt", "not verify", "jwks"); err != nil {
				t.Fatalf("the negative form failed: %v", err)
			}
		})
	}

	t.Run("a set with more than one key is rejected", func(t *testing.T) {
		ctx := scenario(map[string]any{"jwt": noKid, "jwks": jwkSet(t, pinned.jwk(t), newRSASigner(t, "RS256", "gw").jwk(t))})
		if err := steps.jwtShouldVerifyWithOnlyKey(ctx, "jwt", "not verify", "jwks"); err == nil {
			t.Fatal("a two-key set was accepted")
		}
	})

	t.Run("missing context values", func(t *testing.T) {
		if err := steps.jwtShouldVerifyWithOnlyKey(scenario(nil), "jwt", "verify", "jwks"); err == nil {
			t.Fatal("verification passed with no stored values")
		}
	})
}

func TestLoadJWKSet(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	pinned := newECSigner(t, "ES256", "policy", elliptic.P256())
	set := jwkSet(t, pinned.jwk(t))
	if err := os.MkdirAll(filepath.Join("resources", "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("resources", "keys", "policy.jwks.json"), []byte(set), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("private.jwks.json", []byte(`{"keys":[{"kty":"EC","kid":"k","d":"secret"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := newPolicySteps(nil)

	ctx := scenario(nil)
	if err := steps.loadJWKSet(ctx, "resources/keys/policy.jwks.json", "policyJwks"); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got, err := tcontext.ResolveString(ctx, "policyJwks"); err != nil || got != set {
		t.Fatalf("stored JWK Set = %q, %v", got, err)
	}

	for name, path := range map[string]string{
		"missing file":           "resources/keys/absent.jwks.json",
		"absolute path":          filepath.Join(dir, "resources", "keys", "policy.jwks.json"),
		"path leaving the suite": "../policy.jwks.json",
		"private key material":   "private.jwks.json",
	} {
		t.Run(name, func(t *testing.T) {
			if err := steps.loadJWKSet(scenario(nil), path, "policyJwks"); err == nil {
				t.Fatalf("loaded %q", path)
			}
		})
	}

	t.Run("no scenario context", func(t *testing.T) {
		if err := steps.loadJWKSet(context.Background(), "resources/keys/policy.jwks.json", "policyJwks"); err == nil {
			t.Fatal("stored a JWK Set without a scenario context")
		}
	})
}
