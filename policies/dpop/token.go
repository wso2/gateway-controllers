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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// sameToken reports whether token, the credential in Authorization that the proof's
// ath covers, is the token the access-token layer validated. The layer does not carry
// the token, so it is identified by what the policy recorded:
//
//   - TokenId equal to the token's hex SHA-256 fingerprint, as opaque-token-auth
//     records it;
//   - TokenId equal to the token's jti, as jwt-auth (and mcp-auth through it) records
//     it;
//   - with no TokenId, a JWT with the same issuer and the same cnf.jkt, the binding
//     the proof was just checked against.
//
// Anything else cannot be confirmed and is refused. The JWT is decoded without
// verifying its signature: its claims are only compared with what the access-token
// policy verified, never trusted on their own.
func sameToken(layer *policy.AuthContext, token, jkt string) bool {
	if layer == nil {
		return false
	}
	if layer.TokenId != "" {
		sum := sha256.Sum256([]byte(token))
		if constantEqual(layer.TokenId, hex.EncodeToString(sum[:])) {
			return true
		}
		claims, ok := jwtClaims(token)
		return ok && claims.Jti != "" && constantEqual(claims.Jti, layer.TokenId)
	}
	claims, ok := jwtClaims(token)
	if !ok || claims.Cnf.Jkt == "" || !constantEqual(claims.Cnf.Jkt, jkt) {
		return false
	}
	return layer.Issuer == "" || claims.Iss == layer.Issuer
}

// tokenClaims are the access-token claims sameToken compares.
type tokenClaims struct {
	Jti string `json:"jti"`
	Iss string `json:"iss"`
	Cnf struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

// jwtClaims decodes the payload of a compact JWS without verifying it, reporting
// false for anything that is not one.
func jwtClaims(token string) (tokenClaims, bool) {
	var c tokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return c, false
	}
	return c, true
}

// constantEqual compares two strings in constant time for equal lengths.
func constantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
