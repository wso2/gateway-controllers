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

@jwt-auth
Feature: JWT authentication
  As an API developer
  I want to secure my APIs with JWT authentication
  So that only authorized requests with valid tokens can access my resources
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A request with a valid JWT token is authorized
    Given I generate a unique value from "jwt-auth-basic" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-basic" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-basic" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A request without an authorization header is rejected
    Given I generate a unique value from "jwt-auth-no-header" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-no-header" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-no-header" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    And the response body should contain "Authentication failed"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A request with an invalid JWT token is rejected
    Given I generate a unique value from "jwt-auth-invalid-token" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-invalid-token" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-invalid-token" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I set header "Authorization" to "Bearer invalid.jwt.token"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response body should contain "Authentication failed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A request with a malformed Bearer header is rejected
    Given I generate a unique value from "jwt-auth-malformed" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-malformed" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-malformed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I set header "Authorization" to "NotBearer sometoken"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A request with the wrong issuer is rejected
    Given I generate a unique value from "jwt-auth-wrong-issuer" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-wrong-issuer" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-wrong-issuer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["wrong-issuer-km"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    # Token issued for "mock-jwks" but the operation only trusts "wrong-issuer-km"
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response body should contain "Authentication failed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: JWT authentication with audience validation succeeds
    Given I generate a unique value from "jwt-auth-audience" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-audience" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-audience" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"audiences":["test-audience"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: JWT authentication rejects the wrong audience
    Given I generate a unique value from "jwt-auth-wrong-audience" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-wrong-audience" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-wrong-audience" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"audiences":["expected-audience"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response body should contain "Authentication failed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Multiple key managers are matched by issuer
    Given I generate a unique value from "jwt-auth-multi-km" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-multi-km" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-multi-km" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks","wrong-issuer-km"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: JWT auth does not affect unprotected endpoints
    Given I generate a unique value from "jwt-auth-partial" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-partial" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-partial" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/public"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/public" until status 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: An empty Bearer token is rejected
    Given I generate a unique value from "jwt-auth-empty-bearer" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-empty-bearer" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-empty-bearer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I set header "Authorization" to "Bearer "
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A Bearer scheme without a token is rejected
    Given I generate a unique value from "jwt-auth-bearer-only" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-bearer-only" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-bearer-only" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful

    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I set header "Authorization" to "Bearer"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Token verdict cache: a token's signature verdict is shared by every API with the same key
  # manager and issuer configuration, since audience, scope and claim requirements are not part of
  # the cache key. Each API must still enforce its own requirements on every request.
  Scenario: The shared verdict cache still enforces each API's own audience requirement
    Given I generate a unique value from "jwt-auth-cache-noaud" and store it as "apiNameA"
    And I generate a unique API version from "jwt-auth-cache-noaud" and store it as "apiVersionA"
    And I generate a unique API context from "/jwt-auth-cache-noaud" and store it as "apiContextA"
    And I generate a unique value from "jwt-auth-cache-aud" and store it as "apiNameB"
    And I generate a unique API version from "jwt-auth-cache-aud" and store it as "apiVersionB"
    And I generate a unique API context from "/jwt-auth-cache-aud" and store it as "apiContextB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiNameA}                   |
      | spec.displayName       | ${CTX:apiNameA}                   |
      | spec.version           | ${CTX:apiVersionA}                |
      | spec.context           | ${CTX:apiContextA}/$version       |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/protected" until status 401

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiNameB}                   |
      | spec.displayName       | ${CTX:apiNameB}                   |
      | spec.version           | ${CTX:apiVersionB}                |
      | spec.context           | ${CTX:apiContextB}/$version       |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"audiences":["expected-audience"]}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContextB}/${CTX:apiVersionB}/protected" until status 401

    # The mock JWKS server issues tokens with the audience "test-audience". The first API has no
    # audience requirement, so it accepts the token and caches the verdict.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/protected"
    Then the response status code should be 200

    # The second API reuses the cached verdict but must still reject the token's audience.
    When I send a "GET" request to "${CTX:apiContextB}/${CTX:apiVersionB}/protected"
    Then the response status code should be 401
    And the response body should contain "Authentication failed"

    # The second API's rejection must not affect the first API.
    When I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiNameA}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/health" until status 404
    When I delete the API "${CTX:apiNameB}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContextB}/${CTX:apiVersionB}/health" until status 404

  Scenario: Updating an API's audience requirement applies to a token it already accepted
    Given I generate a unique value from "jwt-auth-update-aud" and store it as "apiName"
    And I generate a unique API version from "jwt-auth-update-aud" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-auth-update-aud" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    # No audience requirement yet: the token is accepted and its verdict cached.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    # Require an audience the token does not carry. The verdict cached before the update must not
    # keep authorizing the same token.
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"audiences":["expected-audience"]}}]}] |
    Then the response should be successful
    When I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    Then the response body should contain "Authentication failed"

    # Require the audience the token carries. The same token is accepted again.
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"audiences":["test-audience"]}}]}] |
    Then the response should be successful
    When I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: jwt-auth rejects a request with no authorization header
    Given I generate a unique value from "compat-jwt-none" and store it as "apiName"
    And I generate a unique API version from "compat-jwt-none" and store it as "apiVersion"
    And I generate a unique API context from "/compat-jwt-none" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3002            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "jwt-auth-missing-token"
