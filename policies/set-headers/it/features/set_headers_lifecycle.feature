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

@set-headers
Feature: Set headers policy across updates, concurrent traffic and logs
  As an API developer
  I want header setting to hold as an API changes and under load
  So that the backend and the client receive exactly the headers the API defines

  # The backend is the testbench echo service under /analytics-headers. It returns the request it
  # received as JSON, and answers with X-Allowed-Response: allowed, X-Denied-Response: denied,
  # X-Removed-Response: removed, X-Multi-Response as two header lines, and X-Correlation-Response
  # with the value of the request's X-Correlation-Id. The "echoed header" steps read the request
  # headers that reached the backend, and the "response header" steps read the headers the
  # client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # SH21: The policy first sets X-Gateway-Tenant and overwrites X-Allowed-Response with v1, then the
  # API is updated to set X-Gateway-Region instead and overwrite X-Allowed-Response with v2. After
  # the update, requests must carry the new configuration only, with no stale value.
  Scenario: Update the headers set by a deployed API
    Given I generate a unique value from "sh-update" and store it as "apiName"
    And I generate a unique API version from "sh-update" and store it as "apiVersion"
    And I generate a unique API context from "/sh-update" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]},"response":{"headers":[{"name":"X-Allowed-Response","value":"v1"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
    And the response header "X-Allowed-Response" should be "v1"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Region","value":"eu-west"}]},"response":{"headers":[{"name":"X-Allowed-Response","value":"v2"}]}}}]}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until header "X-Allowed-Response" is "v2"
    Then the response status code should be 200
    And the response should contain echoed header "X-Gateway-Region" with value "eu-west"
    And the response should not contain echoed header "X-Gateway-Tenant"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH22: The policy is removed from a deployed API. After the update, the headers it set must no
  # longer be added: the backend's own X-Allowed-Response value comes back, and X-Gateway-Tenant no
  # longer reaches the backend.
  Scenario: Remove the policy from a deployed API
    Given I generate a unique value from "sh-detach" and store it as "apiName"
    And I generate a unique API version from "sh-detach" and store it as "apiVersion"
    And I generate a unique API context from "/sh-detach" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]},"response":{"headers":[{"name":"X-Allowed-Response","value":"gateway-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
    And the response header "X-Allowed-Response" should be "gateway-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until header "X-Allowed-Response" is "allowed"
    Then the response status code should be 200
    And the response should not contain echoed header "X-Gateway-Tenant"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH24: Many requests are in flight at once, each with its own X-Client-Request-Id, and every
  # other one also sending its own X-Gateway-Tenant value. The policy must overwrite each with the
  # configured value independently: every request reaches the backend with its own
  # X-Client-Request-Id and the configured X-Gateway-Tenant, and every response carries the
  # configured X-Gateway-Response. A request that receives another request's value would show
  # headers leaking between requests.
  Scenario: Set headers under concurrent traffic with different incoming header values
    Given I generate a unique value from "sh-concurrent" and store it as "apiName"
    And I generate a unique API version from "sh-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/sh-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"configured-tenant"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"gateway-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send 100 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/get" identified by the "X-Client-Request-Id" header, every other one also carrying the "X-Gateway-Tenant" header
    Then every concurrent request should reach the backend with its own "X-Client-Request-Id" header and the "X-Gateway-Tenant" header set to "configured-tenant"
    And every concurrent response should carry the "X-Gateway-Response" header with value "gateway-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH27, SH30: The policy sets a sensitive request header, an Authorization credential for the
  # backend, from a value unique to this scenario. It must reach the backend as configured, the
  # client must not receive it as a response header, and the value must not appear in the gateway
  # runtime's or controller's logs. The gateway's analytics events record the headers the client
  # sent, before any policy runs, so they are not checked here.
  Scenario: Set a sensitive header without exposing it in responses or logs
    Given I generate a unique value from "sh-exposure" and store it as "apiName"
    And I generate a unique API version from "sh-exposure" and store it as "apiVersion"
    And I generate a unique API context from "/sh-exposure" and store it as "apiContext"
    And I generate a unique value from "sh-secret" and store it as "secretValue"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"Authorization","value":"Bearer ${CTX:secretValue}"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "Authorization" with value "Bearer ${CTX:secretValue}"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "Authorization" should not exist
    And the "gateway-runtime" service logs should not contain "${CTX:secretValue}"
    And the "gateway-controller" service logs should not contain "${CTX:secretValue}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
