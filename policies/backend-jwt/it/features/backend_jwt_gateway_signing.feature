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

# jwt-auth verifies the caller's token from the testbench JWKS service; backend-jwt then signs a JWT
# describing that caller with the gateway signing key (overlays/gateway-signing.toml) and sends it
# to the testbench echo service, which reflects it back. Each scenario verifies the token the way a
# backend would: it fetches the gateway JWK Set from /.well-known/jwks and checks the signature
# with the key the token's kid names.
@backend-jwt
Feature: Backend jwt policy signed with the gateway signing key
  As a backend service owner
  I want the gateway to send me a JWT describing the authenticated caller
  So that I can trust that identity by verifying it against the gateway JWKS

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: The gateway JWKS publishes the public signing key
    When I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    Then the response status code should be 200
    And the response header "Content-Type" should contain "application/jwk-set+json"
    And the response header "Cache-Control" should be "public, max-age=300"
    And the response header "ETag" should exist
    And the JSON response array field "keys" should have 1 item
    When I store the response body as "gatewayJwks"
    Then the JWK Set "gatewayJwks" should publish only public "EC" keys for "ES256" signing

  Scenario: backend-jwt with default parameters forwards the caller identity in a JWT that verifies against the gateway JWKS
    Given I generate a unique value from "backend-jwt-default" and store it as "apiName"
    And I generate a unique API version from "backend-jwt-default" and store it as "apiVersion"
    And I generate a unique API context from "/backend-jwt-default" and store it as "apiContext"
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

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=engineering" and store it as "callerToken"
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "backendJwt"
    And I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    And I store the response body as "gatewayJwks"
    Then the JWT "backendJwt" should verify against the JWK Set "gatewayJwks"
    And the JWT "backendJwt" should not verify against the JWK Set "gatewayJwks" once its claims are altered
    # Header: alg and kid come from the gateway signing key, never from the policy.
    And the JWT "backendJwt" header "alg" should be "ES256"
    # The kid is the RFC 7638 thumbprint of the framework's fixed active.pem test key.
    And the JWT "backendJwt" header "kid" should be "GqWj6qPTMk3medznt-SHvWjANJNmVkHUtMMUhRWhV3I"
    And the JWT "backendJwt" header "typ" should be "JWT"
    And the JWT "backendJwt" header "jku" should not exist
    # Body: system claims from [policy_configurations.backendjwt_v1].
    And the JWT "backendJwt" claim "iss" should be "https://it-gateway.wso2.test"
    And the JWT "backendJwt" should expire 900 seconds after it was issued
    And the JWT "backendJwt" should have been issued within the last 60 seconds
    # Body: the caller identity jwt-auth verified, and its non-standard claims.
    And the JWT "backendJwt" claim "sub" should be "test-user"
    And the JWT "backendJwt" claim "aud" should contain "test-audience"
    And the JWT "backendJwt" claim "auth_type" should be "jwt"
    And the JWT "backendJwt" claim "scope" should be "default"
    And the JWT "backendJwt" claim "department" should be "engineering"
    And the JWT "backendJwt" claim "nbf" should not exist
    And I delete the API "${CTX:apiName}"

  Scenario: backend-jwt honours the header, token expiry and custom claims parameters
    Given I generate a unique value from "backend-jwt-params" and store it as "apiName"
    And I generate a unique API version from "backend-jwt-params" and store it as "apiVersion"
    And I generate a unique API context from "/backend-jwt-params" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"backend-jwt","version":"v1","params":{"header":"X-Backend-Token","tokenExpiry":"5m","customClaims":{"tenant":"acme","tier":3,"request_tenant":"$ctx:request.header.x-tenant-id","api":"$ctx:api.name"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "callerToken"
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I set header "X-Tenant-Id" to "tenant-42"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    And the response should not contain echoed header "X-Jwt-Assertion"
    When I store the JSON response field "headers.X-Backend-Token" as "backendJwt"
    And I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    And I store the response body as "gatewayJwks"
    Then the JWT "backendJwt" should verify against the JWK Set "gatewayJwks"
    And the JWT "backendJwt" header "alg" should be "ES256"
    And the JWT "backendJwt" should expire 300 seconds after it was issued
    And the JWT "backendJwt" claim "sub" should be "test-user"
    And the JWT "backendJwt" claim "tenant" should be "acme"
    And the JWT "backendJwt" claim "tier" should be "3"
    And the JWT "backendJwt" claim "request_tenant" should be "tenant-42"
    And the JWT "backendJwt" claim "api" should be "${CTX:apiName}"
    And I delete the API "${CTX:apiName}"

  Scenario: backend-jwt applies the dialect, claim mappings and excluded claims parameters
    Given I generate a unique value from "backend-jwt-mapping" and store it as "apiName"
    And I generate a unique API version from "backend-jwt-mapping" and store it as "apiVersion"
    And I generate a unique API context from "/backend-jwt-mapping" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/anything","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"backend-jwt","version":"v1","params":{"dialect":"http://wso2.org/claims/","claimMappings":{"org":"department"},"excludedClaims":["internal_note"]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=engineering,email=alice@example.com,internal_note=secret" and store it as "callerToken"
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "backendJwt"
    And I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    And I store the response body as "gatewayJwks"
    Then the JWT "backendJwt" should verify against the JWK Set "gatewayJwks"
    # Standard claims the policy sets itself are never prefixed.
    And the JWT "backendJwt" claim "sub" should be "test-user"
    And the JWT "backendJwt" claim "iss" should be "https://it-gateway.wso2.test"
    # Forwarded caller claims get the dialect prefix.
    And the JWT "backendJwt" claim "http://wso2.org/claims/email" should be "alice@example.com"
    And the JWT "backendJwt" claim "email" should not exist
    # claimMappings renames department to org (prefixed); the source is not also forwarded.
    And the JWT "backendJwt" claim "http://wso2.org/claims/org" should be "engineering"
    And the JWT "backendJwt" claim "http://wso2.org/claims/department" should not exist
    # excludedClaims drops a caller claim entirely.
    And the JWT "backendJwt" claim "http://wso2.org/claims/internal_note" should not exist
    And the JWT "backendJwt" claim "internal_note" should not exist
    And I delete the API "${CTX:apiName}"

  Scenario: backend-jwt caches the JWT per caller, and sends none when jwt-auth rejects the caller
    Given I generate a unique value from "backend-jwt-cache" and store it as "apiName"
    And I generate a unique API version from "backend-jwt-cache" and store it as "apiVersion"
    And I generate a unique API context from "/backend-jwt-cache" and store it as "apiContext"
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

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=engineering" and store it as "callerToken"
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "firstJwt"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "secondJwt"
    Then the JWT "secondJwt" should be the same as the JWT "firstJwt"

    # A caller with different claims gets its own JWT.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=finance" and store it as "otherCallerToken"
    And I set header "Authorization" to "Bearer ${CTX:otherCallerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 200
    When I store the JSON response field "headers.X-Jwt-Assertion" as "otherJwt"
    And I clear all headers
    And I send a "GET" request to "/.well-known/jwks"
    And I store the response body as "gatewayJwks"
    Then the JWT "otherJwt" should differ from the JWT "firstJwt"
    And the JWT "otherJwt" should verify against the JWK Set "gatewayJwks"
    And the JWT "otherJwt" claim "department" should be "finance"

    # jwt-auth rejects a request without a token before backend-jwt runs, so no JWT reaches the
    # upstream.
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/anything"
    Then the response status code should be 401
    And the response body should not contain "X-Jwt-Assertion"
    And I delete the API "${CTX:apiName}"
