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
# "AS IS" BASIS, WITH WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@dynamic-endpoint
Feature: Dynamic endpoint routing leaves no credentials in logs or analytics
  As an API owner
  I want routing decisions to be observable without exposing what clients send
  So that operating the gateway never leaks a credential

  # This feature resets and reads the block's shared analytics collector, so it runs in a block
  # of its own and no other runner's traffic can interleave with it.
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Routing to an upstream does not expose credentials in logs or analytics
    Given I generate a unique value from "dynamic-sec-observe" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-observe" and store it as "apiContext"
    And I generate a unique value from "dynamic-sec-token" and store it as "secretToken"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Observe-API       |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s36/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s36/probe" until status 200
    And I wait for the analytics collector to settle
    And I reset the analytics collector

    When I set header "Authorization" to "Bearer ${CTX:secretToken}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s36/probe"
    Then the response status code should be 200
    And the JSON response field "path" should be "/public/s36/probe"
    # The gateway records a request that dynamic-endpoint moved under the path the selected
    # upstream received, which is the upstream definition's base path and the operation path.
    And the latest analytics event for path "/public/s36/probe" should have response status 200
    And the latest analytics event for path "/public/s36/probe" should not contain request header "authorization"
    And the "gateway-runtime" service logs should contain "[Dynamic Endpoint]"
    And the "gateway-runtime" service logs should not contain "${CTX:secretToken}"
    And I wait for the analytics collector to settle
