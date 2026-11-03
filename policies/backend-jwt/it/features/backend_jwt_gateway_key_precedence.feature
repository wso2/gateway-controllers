# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

# The backend-jwt-policy-key block configures both a gateway signing key and a policy-level
# backend-jwt key (overlays/policy-signing-key.toml). On a gateway with gateway signing, the gateway
# key signs backend JWTs and the policy-level key is ignored: the JWT carries the gateway key's kid
# and algorithm, verifies against the gateway JWKS, and does not verify with the policy-level key.
@backend-jwt
Feature: Backend jwt policy prefers the gateway signing key over a policy-level key
  As an operator moving backend-jwt to gateway signing keys
  I want the gateway key to sign backend JWTs even while the old policy-level key is still configured
  So that backends can verify every token from the gateway JWKS by kid

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: backend-jwt signs with the gateway key although a policy-level key is configured
    Given I generate a unique value from "backend-jwt-key-precedence" and store it as "apiName"
    And I generate a unique API version from "backend-jwt-key-precedence" and store it as "apiVersion"
    And I generate a unique API context from "/backend-jwt-key-precedence" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"backend-jwt","version":"v1","params":{}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "callerToken"
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "backendJwt"
    And I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    And I store the response body as "gatewayJwks"
    And I load the JWK Set from "resources/keys/policy-signing-key.jwks.json" and store it as "policyJwks"
    # The gateway key signs: its kid selects it in the gateway JWKS, and its algorithm is used.
    Then the JWT "backendJwt" should verify against the JWK Set "gatewayJwks"
    And the JWT "backendJwt" header "kid" should be "GqWj6qPTMk3medznt-SHvWjANJNmVkHUtMMUhRWhV3I"
    And the JWT "backendJwt" header "alg" should be "ES256"
    And the JWT "backendJwt" should not verify against the only key in the JWK Set "policyJwks"
    # The policy's other settings still apply.
    And the JWT "backendJwt" claim "iss" should be "https://it-gateway.wso2.test"
    And the JWT "backendJwt" claim "sub" should be "test-user"
    And the JWT "backendJwt" should expire 900 seconds after it was issued
    And I delete the API "${CTX:apiName}"
