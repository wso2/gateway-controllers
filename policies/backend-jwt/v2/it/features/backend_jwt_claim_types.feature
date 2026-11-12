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

# jwt-auth verifies caller tokens that the scenarios sign themselves (the testbench JWKS service
# mints string claims only), so a caller's array, object and number claims are real JSON types.
# The gateway signs with the policy-level key on 1.2.0 and older and with the gateway key on newer
# releases (overlays/policy-signing-key.toml), so the scenarios verify the backend JWT against
# resources/keys/signing-keys.jwks.json, which holds both public keys. The testbench echo service
# reflects the backend JWT.
@backend-jwt
Feature: Backend jwt v2 claim types
  As a backend service owner
  I want array, object and number claims of the caller's token to reach me with their real types
  So that my service can read them without parsing a JSON string

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # Negative scenario: backend-jwt v1 (v1.2) reads only the string Properties of the auth context,
  # so the same caller token that v2 forwards typed reaches the upstream as JSON text inside a
  # string. It pins the v1 behavior v2 exists to change and fails if v1 is ever altered.
  Scenario: backend-jwt v1 forwards array and object claims as JSON strings
    Given I generate a unique value from "claim-types-v1" and store it as "apiName"
    And I generate a unique API version from "claim-types-v1" and store it as "apiVersion"
    And I generate a unique API context from "/claim-types-v1" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["suite-caller-key"]}},{"name":"backend-jwt","version":"v1","params":{"claimMappings":{"app_roles":"roles"},"customClaims":{"ctx_groups":"$ctx:auth.property.groups"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I sign a caller JWT for issuer "http://it-caller.wso2.test" with the key "resources/keys/caller-token-key.pem" and store it as "callerToken" with claims:
      """
      {"roles":["OrganizationAdmin","B"],"groups":["g1","g2"],"org":{"id":"o1"},"tier":"gold"}
      """
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "backendJwt"
    And I load the JWK Set from "resources/keys/signing-keys.jwks.json" and store it as "policyJwks"
    Then the JWT "backendJwt" should verify against a key in the JWK Set "policyJwks"
    # claimMappings consumes roles, so it appears only under its mapped name.
    And the JWT "backendJwt" claim "roles" should not exist
    And the JWT "backendJwt" claim "org" should be the JSON:
      """
      "{\"id\":\"o1\"}"
      """
    And the JWT "backendJwt" claim "app_roles" should be the JSON:
      """
      "[\"OrganizationAdmin\",\"B\"]"
      """
    And the JWT "backendJwt" claim "ctx_groups" should be the JSON:
      """
      "[\"g1\",\"g2\"]"
      """
    And the JWT "backendJwt" claim "tier" should be "gold"
    And I clear all headers
    And I delete the API "${CTX:apiName}"

  Scenario: backend-jwt v2 the auto-forwarded claims keep their types
    Given I generate a unique value from "claim-types-forward" and store it as "apiName"
    And I generate a unique API version from "claim-types-forward" and store it as "apiVersion"
    And I generate a unique API context from "/claim-types-forward" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["suite-caller-key"]}},{"name":"backend-jwt","version":"v2","params":{}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I sign a caller JWT for issuer "http://it-caller.wso2.test" with the key "resources/keys/caller-token-key.pem" and store it as "callerToken" with claims:
      """
      {"roles":["OrganizationAdmin","B"],"groups":["g1","g2"],"org":{"id":"o1"},"amount":1.5,"active":true,"tier":"gold"}
      """
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "backendJwt"
    And I load the JWK Set from "resources/keys/signing-keys.jwks.json" and store it as "policyJwks"
    Then the JWT "backendJwt" should verify against a key in the JWK Set "policyJwks"
    And the JWT "backendJwt" claim "roles" should be the JSON:
      """
      ["OrganizationAdmin","B"]
      """
    And the JWT "backendJwt" claim "groups" should be the JSON:
      """
      ["g1","g2"]
      """
    And the JWT "backendJwt" claim "org" should be the JSON:
      """
      {"id":"o1"}
      """
    And the JWT "backendJwt" claim "amount" should be the JSON:
      """
      1.5
      """
    And the JWT "backendJwt" claim "active" should be the JSON:
      """
      true
      """
    And the JWT "backendJwt" claim "tier" should be the JSON:
      """
      "gold"
      """
    # The identity claims the policy sets itself are unchanged.
    And the JWT "backendJwt" claim "sub" should be "test-user"
    And the JWT "backendJwt" claim "auth_type" should be "jwt"
    And I clear all headers
    And I delete the API "${CTX:apiName}"

  Scenario: backend-jwt v2 claimMappings and $ctx references keep types and customClaims still win
    Given I generate a unique value from "claim-types-mapped" and store it as "apiName"
    And I generate a unique API version from "claim-types-mapped" and store it as "apiVersion"
    And I generate a unique API context from "/claim-types-mapped" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["suite-caller-key"]}},{"name":"backend-jwt","version":"v2","params":{"excludedClaims":["groups"],"claimMappings":{"app_roles":"roles","app_org":"org","overridden":"roles"},"customClaims":{"ctx_groups":"$ctx:auth.property.groups","ctx_tier":"$ctx:auth.property.tier","static_roles":["A","B"],"overridden":"from-custom-claims"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I sign a caller JWT for issuer "http://it-caller.wso2.test" with the key "resources/keys/caller-token-key.pem" and store it as "callerToken" with claims:
      """
      {"roles":["OrganizationAdmin","B"],"groups":["g1","g2"],"org":{"id":"o1"},"tier":"gold"}
      """
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "backendJwt"
    And I load the JWK Set from "resources/keys/signing-keys.jwks.json" and store it as "policyJwks"
    Then the JWT "backendJwt" should verify against a key in the JWK Set "policyJwks"
    And the JWT "backendJwt" claim "app_roles" should be the JSON:
      """
      ["OrganizationAdmin","B"]
      """
    And the JWT "backendJwt" claim "app_org" should be the JSON:
      """
      {"id":"o1"}
      """
    And the JWT "backendJwt" claim "ctx_groups" should be the JSON:
      """
      ["g1","g2"]
      """
    And the JWT "backendJwt" claim "ctx_tier" should be the JSON:
      """
      "gold"
      """
    And the JWT "backendJwt" claim "static_roles" should be the JSON:
      """
      ["A","B"]
      """
    # customClaims take precedence over claimMappings for the same destination.
    And the JWT "backendJwt" claim "overridden" should be the JSON:
      """
      "from-custom-claims"
      """
    # A mapped source is not also forwarded under its own name, and an excluded claim is dropped.
    And the JWT "backendJwt" claim "roles" should not exist
    And the JWT "backendJwt" claim "groups" should not exist
    And I clear all headers
    And I delete the API "${CTX:apiName}"

  # jwt-auth flattens 1.5 and 1.4 to the same string, and these tokens carry no jti, so only the
  # typed values tell the two callers apart in the token cache.
  Scenario: backend-jwt v2 callers whose numeric claims differ do not share a cached backend JWT
    Given I generate a unique value from "claim-types-cache" and store it as "apiName"
    And I generate a unique API version from "claim-types-cache" and store it as "apiVersion"
    And I generate a unique API context from "/claim-types-cache" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["suite-caller-key"]}},{"name":"backend-jwt","version":"v2","params":{}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I sign a caller JWT for issuer "http://it-caller.wso2.test" with the key "resources/keys/caller-token-key.pem" and store it as "firstCaller" with claims:
      """
      {"amount":1.5}
      """
    And I set header "Authorization" to "Bearer ${CTX:firstCaller}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "firstBackendJwt"
    Then the JWT "firstBackendJwt" claim "amount" should be the JSON:
      """
      1.5
      """

    When I sign a caller JWT for issuer "http://it-caller.wso2.test" with the key "resources/keys/caller-token-key.pem" and store it as "secondCaller" with claims:
      """
      {"amount":1.4}
      """
    And I set header "Authorization" to "Bearer ${CTX:secondCaller}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "secondBackendJwt"
    Then the JWT "secondBackendJwt" claim "amount" should be the JSON:
      """
      1.4
      """
    And the JWT "secondBackendJwt" should differ from the JWT "firstBackendJwt"
    And I clear all headers
    And I delete the API "${CTX:apiName}"
