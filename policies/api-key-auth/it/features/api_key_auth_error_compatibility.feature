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

@api-key-auth
Feature: API key auth policy
  As an API developer
  I want the api-key-auth policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: api-key-auth rejects a request with no API key
    Given I generate a unique value from "compat-apikey" and store it as "apiName"
    And I generate a unique API version from "compat-apikey" and store it as "apiVersion"
    And I generate a unique API context from "/compat-apikey" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "api-key-auth-missing-key"

  Scenario: api-key-auth rejects a JSON-RPC call with no API key
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "compat-agent-key-rpc" and store it as "apiName"
    And I generate a unique API context from "/compat-agent-key-rpc" and store it as "apiContext"
    When I create Agent from "resources/templates/agent.yaml" with values:
      | apiVersion                         | ${CTX:gatewaySpecVersion} |
      | name                               | ${CTX:apiName} |
      | displayName                        | ${CTX:apiName} |
      | context                            | ${CTX:apiContext} |
      | upstreamUrl                        | http://testbench:3000 |
      | transports                         | [{"protocolBinding":"JSONRPC","pathPrefix":"/"},{"protocolBinding":"HTTP+JSON","pathPrefix":"/v1"}] |
      | spec.a2a.operationConfigs.policies | [{"name":"api-key-auth","version":"v1","params":{"key":"X-API-Key","in":"header"}}] |
      | spec.a2a.agentCard                 | {"public":{"mode":"passthrough"}} |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    # Absent, A2A-Version reads as protocol 0.3, which a 1.0 route refuses before any policy runs.
    And I set header "A2A-Version" to "1.0"
    And I send a "POST" request to "${CTX:apiContext}/" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"this request has far too many words"}]}}}
      """
    When I send a "POST" request to "${CTX:apiContext}/" with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"this request has far too many words"}]}}}
      """
    Then the response status code should be 401
    And the response should match the expected error response "agent-api-key-auth-missing-key-jsonrpc"

  Scenario: api-key-auth rejects an HTTP+JSON call with no API key
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "compat-agent-key-rest" and store it as "apiName"
    And I generate a unique API context from "/compat-agent-key-rest" and store it as "apiContext"
    When I create Agent from "resources/templates/agent.yaml" with values:
      | apiVersion                         | ${CTX:gatewaySpecVersion} |
      | name                               | ${CTX:apiName} |
      | displayName                        | ${CTX:apiName} |
      | context                            | ${CTX:apiContext} |
      | upstreamUrl                        | http://testbench:3000 |
      | transports                         | [{"protocolBinding":"JSONRPC","pathPrefix":"/"},{"protocolBinding":"HTTP+JSON","pathPrefix":"/v1"}] |
      | spec.a2a.operationConfigs.policies | [{"name":"api-key-auth","version":"v1","params":{"key":"X-API-Key","in":"header"}}] |
      | spec.a2a.agentCard                 | {"public":{"mode":"passthrough"}} |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    # Absent, A2A-Version reads as protocol 0.3, which a 1.0 route refuses before any policy runs.
    And I set header "A2A-Version" to "1.0"
    And I send a "GET" request to "${CTX:apiContext}/v1/tasks" until status 401
    When I send a "GET" request to "${CTX:apiContext}/v1/tasks"
    Then the response status code should be 401
    And the response should match the expected error response "agent-api-key-auth-missing-key-http-json"
