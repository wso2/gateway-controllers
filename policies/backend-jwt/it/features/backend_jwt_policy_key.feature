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
# backend-jwt key (overlays/policy-signing-key.toml). Gateway 1.2.0 predates gateway signing: it
# ignores [signing], serves no gateway JWKS, and backend-jwt signs with the policy-level RS256 key
# exactly as before, with no kid. A backend therefore pins the policy key; it cannot select a key
# by kid.
@backend-jwt
Feature: Backend jwt policy on a gateway without gateway signing
  As a backend service owner on a gateway release without gateway signing
  I want backend JWTs to keep being signed by the policy-level key
  So that upgrading the backend-jwt policy does not change the tokens my backend verifies

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: The gateway publishes no JWK Set
    When I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    Then the response status code should be 404

  Scenario: backend-jwt signs with the policy-level key and the JWT carries no kid
    Given I generate a unique value from "backend-jwt-policy-key" and store it as "apiName"
    And I generate a unique API version from "backend-jwt-policy-key" and store it as "apiVersion"
    And I generate a unique API context from "/backend-jwt-policy-key" and store it as "apiContext"
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
    And I load the JWK Set from "resources/keys/policy-signing-key.jwks.json" and store it as "policyJwks"
    # The policy-level key signs: its algorithm, no kid, and its signature.
    Then the JWT "backendJwt" header "kid" should not exist
    And the JWT "backendJwt" header "alg" should be "RS256"
    And the JWT "backendJwt" header "typ" should be "JWT"
    And the JWT "backendJwt" should verify against the only key in the JWK Set "policyJwks"
    And the JWT "backendJwt" claim "iss" should be "https://it-gateway.wso2.test"
    And the JWT "backendJwt" claim "sub" should be "test-user"
    And the JWT "backendJwt" should expire 900 seconds after it was issued
    And I clear all headers
    And I delete the API "${CTX:apiName}"
