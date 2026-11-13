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

package tokenbasedratelimit

import (
	"path/filepath"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// A Redis TLS misconfiguration must fail policy creation, even with failureMode open,
// instead of surfacing when the delegate is first created on a request.
func TestGetPolicyValidatesRedisTLS(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pem")
	params := func(backend string, tls map[string]interface{}) map[string]interface{} {
		p := map[string]interface{}{}
		p["backend"] = backend
		redis := map[string]interface{}{"host": "127.0.0.1", "port": float64(1), "failureMode": "open"}
		if tls != nil {
			redis["tls"] = tls
		}
		p["redis"] = redis
		return p
	}

	for _, tc := range []struct {
		name    string
		params  map[string]interface{}
		wantErr string
	}{
		{"missing ca_file on the redis backend", params("redis", map[string]interface{}{"enabled": true, "caFile": missing}), "ca_file"},
		{"missing ca_file on the redis-local-async backend", params("redis-local-async", map[string]interface{}{"enabled": true, "caFile": missing}), "ca_file"},
		{"client certificate without its key", params("redis", map[string]interface{}{"enabled": true, "certFile": missing}), "cert_file and key_file"},
		{"tls disabled ignores the files", params("redis", map[string]interface{}{"enabled": false, "caFile": missing}), ""},
		{"memory backend ignores redis.tls", params("memory", map[string]interface{}{"enabled": true, "caFile": missing}), ""},
		{"no tls block", params("redis", nil), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{RouteName: "redis-tls-validation"}, tc.params)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "redis.tls") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want a redis.tls error mentioning %q", err, tc.wantErr)
			}
		})
	}
}
