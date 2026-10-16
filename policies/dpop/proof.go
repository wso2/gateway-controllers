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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// proofType is the required typ header of a DPoP proof (RFC 9449 section 4.2).
	proofType = "dpop+jwt"
	// maxProofLength bounds the DPoP header before any parsing. A proof carrying an
	// 8192-bit RSA key and signature is about 3.5 KB.
	maxProofLength = 8192
	// maxJTILength bounds the jti a client can make the replay store remember.
	maxJTILength  = 512
	minRSAKeyBits = 2048
	maxRSAKeyBits = 8192
)

var b64 = base64.RawURLEncoding.Strict()

// ed25519Alg is the fully specified JOSE algorithm "Ed25519" of RFC 9864, which
// deprecates the polymorphic "EdDSA". It verifies exactly as EdDSA with an Ed25519
// key. Registering the name only makes it parseable; a proof may use it only when
// allowedAlgorithms lists it, and other policies keep their own allowlists.
type ed25519Alg struct{ *jwt.SigningMethodEd25519 }

// Alg returns the algorithm name a proof header must carry to select this method.
func (ed25519Alg) Alg() string { return "Ed25519" }

// init registers "Ed25519" with golang-jwt so proofs that use the RFC 9864 name can be parsed.
func init() {
	jwt.RegisterSigningMethod("Ed25519", func() jwt.SigningMethod { return ed25519Alg{jwt.SigningMethodEdDSA} })
}

// privateJWKMembers are the members that would make a JWK a private or symmetric
// key (RFC 7518 section 6). A proof's jwk must not carry any of them.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// htuTarget is what a proof's htu must match: one of the accepted origins, and the
// request's normalized path.
type htuTarget struct {
	origins []string
	path    string
}

// headerErr is a rejection found while reading the proof's JOSE header. desc is a
// fixed text safe to send to the client; detail, which may quote the proof, only
// reaches the debug log.
type headerErr struct{ desc, detail string }

// Error returns the client-safe description.
func (e *headerErr) Error() string { return e.desc }

// verifiedProof is what a successful verification reports to the caller.
type verifiedProof struct {
	// nonceIssued is when the proof's gateway-issued nonce was minted; zero without nonces.
	nonceIssued time.Time
}

// verifyProof runs the checks of RFC 9449 section 4.3 against one proof. The
// caller has already enforced check 1 (a single DPoP header). The jti is recorded
// for replay detection only once every other check has passed, so a rejected
// proof never occupies the replay store.
func (p *DPoPPolicy) verifyProof(ctx context.Context, proof, method string, target htuTarget, accessToken, jkt string, now time.Time) (verifiedProof, *dpopError) {
	var verified verifiedProof
	if len(proof) > maxProofLength {
		return verified, errInvalidProof("proof is longer than 8192 bytes")
	}

	// Checks 2 and 4-7: a well-formed JWT of type dpop+jwt, signed with an allowed
	// asymmetric algorithm by the public key in its own jwk header. The allowlist is
	// checked here rather than by the parser, so each failure has its own reason.
	var thumbprint string
	parser := jwt.NewParser(jwt.WithoutClaimsValidation(), jwt.WithJSONNumber())
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(proof, claims, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); !strings.EqualFold(typ, proofType) {
			return nil, &headerErr{desc: "typ must be dpop+jwt"}
		}
		alg, _ := t.Header["alg"].(string)
		if !p.cfg.algSet[alg] {
			return nil, &headerErr{desc: "alg is not one of the accepted algs"}
		}
		// RFC 7515 section 4.1.11: a recipient must reject a JWS whose crit lists an
		// extension it does not understand, and this verifier understands none. The
		// key comes only from jwk; kid, jku, x5u and x5c are never consulted.
		if _, ok := t.Header["crit"]; ok {
			return nil, &headerErr{desc: "crit header is not supported"}
		}
		jwk, ok := t.Header["jwk"].(map[string]interface{})
		if !ok {
			return nil, &headerErr{desc: "jwk header is missing"}
		}
		key, tp, err := parseJWK(jwk, alg)
		if err != nil {
			return nil, &headerErr{desc: "jwk is not a public key usable with alg", detail: err.Error()}
		}
		thumbprint = tp
		return key, nil
	})
	if err != nil {
		var he *headerErr
		switch {
		case errors.As(err, &he):
			return verified, errInvalidProofDetail(he.desc, he.detail)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return verified, errInvalidProof("signature does not verify with the jwk")
		case errors.Is(err, jwt.ErrTokenUnverifiable):
			return verified, errInvalidProofDetail("alg is not one of the accepted algs", err.Error())
		default:
			return verified, errInvalidProofDetail("proof is not a well-formed JWT", err.Error())
		}
	}

	// Check 3: the required claims, each well formed.
	jti, _ := claims["jti"].(string)
	if jti == "" || len(jti) > maxJTILength {
		return verified, errInvalidProof("jti is missing or longer than 512 characters")
	}
	htm, _ := claims["htm"].(string)
	htu, _ := claims["htu"].(string)
	if htm == "" || htu == "" {
		return verified, errInvalidProof("htm or htu is missing")
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return verified, errInvalidProof("iat is missing or not a number")
	}

	// Check 8: the method, compared case-sensitively as HTTP methods are.
	if htm != method {
		return verified, errInvalidProof("htm does not match the request method")
	}

	// Check 9: the URI, ignoring query and fragment, after normalization.
	if !htuMatches(htu, target) {
		return verified, errInvalidProof("htu does not match the request URI")
	}

	// Checks 10 and 11: freshness. iat bounds the proof's age; with nonces, the
	// gateway's own clock bounds it as well.
	if iat.After(now.Add(p.cfg.clockSkew)) {
		return verified, errInvalidProof("iat is in the future")
	}
	if now.Sub(iat) > p.cfg.proofMaxAge+p.cfg.clockSkew {
		return verified, errInvalidProof("proof has expired (iat is too old)")
	}
	if p.cfg.requireNonce {
		nonce, _ := claims["nonce"].(string)
		if nonce == "" {
			return verified, errUseNonce("proof has no nonce")
		}
		issued, ok := p.nonces.valid(nonce, now, p.cfg.nonceLifetime, p.cfg.clockSkew)
		if !ok {
			return verified, errUseNonce("nonce is invalid or expired")
		}
		verified.nonceIssued = issued
	}

	// Check 12: bound to this access token and to the key the token names.
	ath, _ := claims["ath"].(string)
	if ath == "" {
		return verified, errInvalidProof("ath is missing")
	}
	if subtle.ConstantTimeCompare([]byte(ath), []byte(accessTokenHash(accessToken))) != 1 {
		return verified, errInvalidProof("ath does not match the access token")
	}
	if subtle.ConstantTimeCompare([]byte(thumbprint), []byte(jkt)) != 1 {
		return verified, errInvalidToken("proof key does not match cnf.jkt", "invalid DPoP key binding")
	}

	// A proof is single use (RFC 9449 section 11.1). Remember it until it would be
	// too old to accept anyway.
	expiry := iat.Add(p.cfg.proofMaxAge + p.cfg.clockSkew)
	switch p.replay.checkAndStore(ctx, replayKey(thumbprint, jti), expiry, now) {
	case replaySeen:
		return verified, errInvalidProof("proof has already been used")
	case replayFull:
		return verified, errReplayUnavailable("replay cache full")
	case replayUnavailable:
		return verified, errReplayUnavailable("replay store unreachable")
	}
	return verified, nil
}

// numericDate reads a JWT NumericDate. Fractional seconds are allowed.
func numericDate(v interface{}) (time.Time, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		var err error
		if f, err = n.Float64(); err != nil {
			return time.Time{}, false
		}
	case float64:
		f = n
	default:
		return time.Time{}, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true
}

// accessTokenHash is the ath of RFC 9449 section 4.2: base64url(SHA-256(token)).
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// replayKey scopes a jti to the key that signed it, so one client cannot burn
// another's jti values, and hashes it so stored entries have a fixed size.
func replayKey(thumbprint, jti string) [32]byte {
	return sha256.Sum256([]byte(thumbprint + "\x00" + jti))
}

// parseJWK turns a proof's jwk header into a verification key for alg, and returns
// the key's RFC 7638 SHA-256 thumbprint. The key type and curve must suit the
// algorithm, so a key can never be used with an algorithm it was not made for.
func parseJWK(jwk map[string]interface{}, alg string) (crypto.PublicKey, string, error) {
	for _, member := range privateJWKMembers {
		if _, ok := jwk[member]; ok {
			return nil, "", errors.New("jwk contains private or symmetric key material")
		}
	}
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return parseECJWK(jwk, alg)
	case "RSA":
		return parseRSAJWK(jwk, alg)
	case "OKP":
		return parseOKPJWK(jwk, alg)
	default:
		return nil, "", fmt.Errorf("unsupported jwk kty %q", kty)
	}
}

// parseECJWK builds an ECDSA key from an EC jwk whose curve matches alg, rejecting points not on the curve.
func parseECJWK(jwk map[string]interface{}, alg string) (crypto.PublicKey, string, error) {
	var curve elliptic.Curve
	var wantCrv string
	switch alg {
	case "ES256":
		curve, wantCrv = elliptic.P256(), "P-256"
	case "ES384":
		curve, wantCrv = elliptic.P384(), "P-384"
	case "ES512":
		curve, wantCrv = elliptic.P521(), "P-521"
	default:
		return nil, "", fmt.Errorf("EC key cannot be used with %s", alg)
	}
	crv, _ := jwk["crv"].(string)
	if crv != wantCrv {
		return nil, "", fmt.Errorf("%s requires curve %s", alg, wantCrv)
	}
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	x, errX := b64.DecodeString(xs)
	y, errY := b64.DecodeString(ys)
	size := (curve.Params().BitSize + 7) / 8
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return nil, "", errors.New("malformed EC jwk coordinates")
	}
	point := make([]byte, 0, 1+2*size)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, "", errors.New("EC jwk is not a point on the curve")
	}
	tp, err := thumbprint(map[string]string{"crv": crv, "kty": "EC", "x": xs, "y": ys})
	return key, tp, err
}

// parseRSAJWK builds an RSA key from an RSA jwk of 2048 to 8192 bits with an odd public exponent.
func parseRSAJWK(jwk map[string]interface{}, alg string) (crypto.PublicKey, string, error) {
	if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
		return nil, "", fmt.Errorf("RSA key cannot be used with %s", alg)
	}
	ns, _ := jwk["n"].(string)
	es, _ := jwk["e"].(string)
	n, errN := b64.DecodeString(ns)
	e, errE := b64.DecodeString(es)
	if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
		return nil, "", errors.New("malformed RSA jwk")
	}
	modulus := new(big.Int).SetBytes(n)
	if bits := modulus.BitLen(); bits < minRSAKeyBits || bits > maxRSAKeyBits {
		return nil, "", fmt.Errorf("RSA key size %d is outside %d-%d bits", bits, minRSAKeyBits, maxRSAKeyBits)
	}
	exponent := new(big.Int).SetBytes(e)
	if exponent.Cmp(big.NewInt(3)) < 0 || exponent.Bit(0) == 0 || exponent.BitLen() > 31 {
		return nil, "", errors.New("unacceptable RSA public exponent")
	}
	key := &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	tp, err := thumbprint(map[string]string{"e": es, "kty": "RSA", "n": ns})
	return key, tp, err
}

// parseOKPJWK builds an Ed25519 key from an OKP jwk, for the EdDSA and Ed25519 algorithms.
func parseOKPJWK(jwk map[string]interface{}, alg string) (crypto.PublicKey, string, error) {
	if alg != "EdDSA" && alg != "Ed25519" {
		return nil, "", fmt.Errorf("OKP key cannot be used with %s", alg)
	}
	crv, _ := jwk["crv"].(string)
	if crv != "Ed25519" {
		return nil, "", fmt.Errorf("unsupported OKP curve %q", crv)
	}
	xs, _ := jwk["x"].(string)
	x, err := b64.DecodeString(xs)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, "", errors.New("malformed Ed25519 jwk")
	}
	tp, err := thumbprint(map[string]string{"crv": crv, "kty": "OKP", "x": xs})
	return ed25519.PublicKey(x), tp, err
}

// thumbprint computes the RFC 7638 JWK SHA-256 thumbprint from a key's required
// members. encoding/json writes map keys sorted and without whitespace, which is
// exactly the canonical form RFC 7638 hashes.
func thumbprint(members map[string]string) (string, error) {
	canonical, err := json.Marshal(members)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// htuMatches compares an htu claim with the request, ignoring query and fragment,
// after the syntax- and scheme-based normalization RFC 9449 section 4.3 asks for.
func htuMatches(htu string, target htuTarget) bool {
	u, err := url.Parse(htu)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Host == "" {
		return false
	}
	origin, err := normalizeOrigin(u.Scheme, u.Host)
	if err != nil {
		return false
	}
	if normalizePath(u.EscapedPath()) != target.path {
		return false
	}
	for _, o := range target.origins {
		if o == origin {
			return true
		}
	}
	return false
}

// normalizeOrigin lowercases scheme and host and drops the scheme's default port.
func normalizeOrigin(scheme, authority string) (string, error) {
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", scheme)
	}
	u := &url.URL{Host: authority}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("invalid authority %q", authority)
	}
	// A client sends an internationalized host in its ASCII (punycode) form; a raw
	// Unicode host is refused rather than guessed at.
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return "", fmt.Errorf("non-ASCII host %q", host)
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host, nil
	}
	return scheme + "://" + host + ":" + port, nil
}

// normalizePath applies RFC 3986 syntax-based normalization to a path: decode
// percent-encoded unreserved characters, uppercase the hex of the rest, and remove
// dot segments. An empty path is "/" (scheme-based normalization for http).
func normalizePath(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2]) {
			v := unhex(p[i+1])<<4 | unhex(p[i+2])
			if isUnreserved(v) {
				b.WriteByte(v)
			} else {
				b.WriteByte('%')
				b.WriteByte(upper(p[i+1]))
				b.WriteByte(upper(p[i+2]))
			}
			i += 2
			continue
		}
		b.WriteByte(c)
	}
	out := removeDotSegments(b.String())
	if out == "" {
		return "/"
	}
	return out
}

// removeDotSegments is the algorithm of RFC 3986 section 5.2.4.
func removeDotSegments(in string) string {
	var out strings.Builder
	trimLast := func() {
		s := out.String()
		i := strings.LastIndexByte(s, '/')
		if i < 0 {
			i = 0
		}
		out.Reset()
		out.WriteString(s[:i])
	}
	for len(in) > 0 {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			trimLast()
		case in == "/..":
			in = "/"
			trimLast()
		case in == "." || in == "..":
			in = ""
		default:
			start := 0
			if in[0] == '/' {
				start = 1
			}
			end := strings.IndexByte(in[start:], '/')
			if end < 0 {
				out.WriteString(in)
				in = ""
			} else {
				out.WriteString(in[:start+end])
				in = in[start+end:]
			}
		}
	}
	return out.String()
}

// isHex reports whether c is a hexadecimal digit.
func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// unhex returns the value of the hexadecimal digit c.
func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// upper uppercases a hexadecimal letter, leaving digits unchanged.
func upper(c byte) byte {
	if 'a' <= c && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

// isUnreserved reports whether c is an RFC 3986 unreserved character, which percent-encoding never needs.
func isUnreserved(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
