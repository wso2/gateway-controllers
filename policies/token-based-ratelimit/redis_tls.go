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

import "github.com/wso2/gateway-controllers/policies/advanced-ratelimit/redistls"

// validateRedisTLS reads the redis.tls settings the way the advanced-ratelimit delegate
// does and loads the files they name, so a TLS misconfiguration (a missing CA file, a
// certificate without its key) fails policy creation, as it does for advanced-ratelimit
// itself. The delegate is only created on the first request, and a failure there would
// let requests through without a limit, whatever redis.failureMode says.
func validateRedisTLS(params map[string]interface{}) error {
	if backend, _ := params["backend"].(string); backend != "redis" && backend != "redis-local-async" {
		return nil
	}
	redisParams, _ := params["redis"].(map[string]interface{})
	tlsParams, _ := redisParams["tls"].(map[string]interface{})
	str := func(key string) string {
		s, _ := tlsParams[key].(string)
		return s
	}
	enabled, _ := tlsParams["enabled"].(bool)
	insecureSkipVerify, _ := tlsParams["insecureSkipVerify"].(bool)
	_, _, err := redistls.Config{
		Enabled:            enabled,
		CAFile:             str("caFile"),
		ServerName:         str("serverName"),
		InsecureSkipVerify: insecureSkipVerify,
		CertFile:           str("certFile"),
		KeyFile:            str("keyFile"),
	}.Build()
	return err
}
