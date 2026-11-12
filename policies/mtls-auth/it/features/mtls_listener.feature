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


@mtls @mtls-listener
Feature: HTTPS listener derived from the APIs that use mutual TLS
  As an API developer
  I want attaching the mtls-auth policy to be the only thing I do to require a client certificate
  So that the gateway asks for certificates only while some API needs them, and never turns callers
  of other APIs away

  The listener has no switch of its own. While at least one deployed API attaches mtls-auth, the
  HTTPS listener requests a client certificate from every connection and validates it against the
  pool of client authorities; it never closes a connection over the certificate it received. When
  the last such API is removed the listener stops asking. Deploying an API that attaches mtls-auth
  is refused when its parameters could never authenticate anyone.

  Every scenario starts from an empty client authority pool, and every HTTPS request waits until
  the gateway has applied the pool the scenario built.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I generate a unique value from "mtls-listener" and store it as "apiName"
    And I generate a unique API version from "mtls-listener" and store it as "apiVersion"
    And I generate a unique API context from "/mtls-listener" and store it as "apiContext"
    And I generate a unique resource name from "listener-partner-a" and store it as "partnerA"
    And I generate a unique resource name from "listener-partner-b" and store it as "partnerB"
    And I generate a unique resource name from "listener-edge-lb" and store it as "edgeLb"
    And I generate a unique resource name from "listener-backend-trust" and store it as "backendTrust"

  # ==================== ASKING FOR A CERTIFICATE IS DERIVED, NOT CONFIGURED ====================

  Scenario: A protected operation denies a caller who presents no certificate with the uniform body
    Given the certificate fixture "ca-a" is pooled as "${CTX:partnerA}" with usage "downstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                  |
      | spec.displayName       | mTLS Listener API               |
      | spec.version           | ${CTX:apiVersion}               |
      | spec.context           | ${CTX:apiContext}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1    |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"mtls-auth","version":"v0"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 200
    When I send a "GET" request over HTTPS to "${CTX:apiContext}/${CTX:apiVersion}/protected" with no client certificate
    Then the response status code should be 401
    And the response header "Content-Type" should contain "application/json"
    And the response body should be:
      """
      {"error":"Unauthorized","message":"Authentication failed"}
      """
    And the response header "WWW-Authenticate" should not exist
    When I send a "GET" request over HTTPS to "${CTX:apiContext}/${CTX:apiVersion}/health" with no client certificate
    Then the response status code should be 200
    When I delete the API "${CTX:apiName}"
