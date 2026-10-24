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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

const (
	// nonceContext separates nonce MACs from any other use of the same secret.
	nonceContext  = "wso2-dpop-nonce-v1"
	nonceTimeSize = 8
	nonceMACSize  = 16
)

var (
	processNonceKeyOnce sync.Once
	processNonceKey     []byte
)

// nonceIssuer mints and checks stateless DPoP nonces (RFC 9449 section 9). A
// nonce is its issue time and a truncated HMAC over it, so any replica that holds
// the same secret can check a nonce another replica issued, and nothing is stored.
type nonceIssuer struct {
	key []byte
}

// newNonceIssuer keys the issuer with the configured secret, or with a random key
// generated once per process when none is configured.
func newNonceIssuer(secret string) *nonceIssuer {
	if secret != "" {
		return &nonceIssuer{key: []byte(secret)}
	}
	processNonceKeyOnce.Do(func() {
		processNonceKey = make([]byte, 32)
		if _, err := rand.Read(processNonceKey); err != nil {
			panic("dpop: cannot generate nonce key: " + err.Error())
		}
	})
	return &nonceIssuer{key: processNonceKey}
}

// mac returns the truncated HMAC-SHA256 of an issue time under the nonce key.
func (n *nonceIssuer) mac(issued []byte) []byte {
	m := hmac.New(sha256.New, n.key)
	m.Write([]byte(nonceContext))
	m.Write(issued)
	return m.Sum(nil)[:nonceMACSize]
}

// issue returns a nonce stamped with now.
func (n *nonceIssuer) issue(now time.Time) string {
	buf := make([]byte, nonceTimeSize, nonceTimeSize+nonceMACSize)
	binary.BigEndian.PutUint64(buf, uint64(now.Unix()))
	buf = append(buf, n.mac(buf)...)
	return b64.EncodeToString(buf)
}

// valid reports whether nonce was issued with this key no more than lifetime ago,
// allowing skew for replicas whose clocks differ, and when it was issued.
func (n *nonceIssuer) valid(nonce string, now time.Time, lifetime, skew time.Duration) (time.Time, bool) {
	raw, err := b64.DecodeString(nonce)
	if err != nil || len(raw) != nonceTimeSize+nonceMACSize {
		return time.Time{}, false
	}
	if !hmac.Equal(raw[nonceTimeSize:], n.mac(raw[:nonceTimeSize])) {
		return time.Time{}, false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw[:nonceTimeSize])), 0)
	if issued.After(now.Add(skew)) || now.Sub(issued) > lifetime+skew {
		return time.Time{}, false
	}
	return issued, true
}
