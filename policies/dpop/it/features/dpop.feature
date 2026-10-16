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

# The mock-jwks keymanager mints tokens whose extra claims are strings, so it cannot issue a
# DPoP-bound token (cnf is a JSON object). These scenarios cover the policy deployed behind
# jwt-auth on a real gateway: the challenges it answers with, the unbound-token paths of both
# modes and what reaches the backend. Proof verification itself is covered by the unit tests,
# including the signed example proof of RFC 9449.
@dpop
Feature: DPoP policy
  As an API developer
  I want APIs to accept only access tokens whose holder proves possession of the bound key
  So that a leaked access token cannot be replayed by someone else

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Required mode refuses an access token that is not DPoP-bound
    Given I generate a unique value from "dpop-required" and store it as "apiName"
    And I generate a unique API version from "dpop-required" and store it as "apiVersion"
    And I generate a unique API context from "/dpop-required" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"authHeaderPrefix":"DPoP"}},{"name":"dpop","version":"v0","params":{"allowedAlgorithms":["ES256","EdDSA"]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # jwt-auth accepts the token, then dpop finds no cnf.jkt in it.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "DPoP ${CTX:token}"
    And I set header "DPoP" to "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should contain "DPoP error="
    And the response header "WWW-Authenticate" should contain "invalid_token"
    And the response header "WWW-Authenticate" should contain "access token is not DPoP-bound"
    And the response header "WWW-Authenticate" should contain "ES256 EdDSA"
    And the response header "DPoP-Nonce" should not exist
    And the response body should contain "access token is not DPoP-bound"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Optional mode lets an unbound bearer token through and strips the DPoP header
    Given I generate a unique value from "dpop-optional" and store it as "apiName"
    And I generate a unique API version from "dpop-optional" and store it as "apiVersion"
    And I generate a unique API context from "/dpop-optional" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/optional","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"dpop","version":"v0","params":{"mode":"optional"}}]},{"method":"GET","path":"/required","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"dpop","version":"v0","params":{}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I set header "DPoP" to "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/optional"
    Then the response status code should be 200
    And the response should not contain echoed header "dpop"

    # The same bearer token on an operation in required mode is refused.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/required"
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should contain "DPoP-bound access token required"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: With nonces required, a refusal hands the client a nonce
    Given I generate a unique value from "dpop-nonce" and store it as "apiName"
    And I generate a unique API version from "dpop-nonce" and store it as "apiVersion"
    And I generate a unique API context from "/dpop-nonce" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"authHeaderPrefix":"DPoP"}},{"name":"dpop","version":"v0","params":{"requireNonce":true}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "DPoP ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response header "DPoP-Nonce" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
