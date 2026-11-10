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

@azure-authentication
Feature: Azure Authentication policy with an unreadable federated token
  As an API developer
  I want a request to fail cleanly when the gateway cannot read its federated service account token
  So that a broken workload identity setup is visible and never sends an unauthenticated request

  # The gateway runtime's federated token file is empty, a setting that applies to every runner in
  # the block, so this runner gets a block of its own. The identity is the runtime's own, shared by
  # every block, so the scenario counts no token requests.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The policy reads the token file for every token request, so an empty file fails the request with
  # the policy's 502, and the gateway runtime log says why.
  Scenario: An unreadable federated token fails the request with 502
    Given I generate a unique value from "az-token-file" and store it as "apiName"
    And I generate a unique API version from "az-token-file" and store it as "apiVersion"
    And I generate a unique API context from "/az-token-file" and store it as "apiContext"
    And I generate a unique resource name from "az-res" and store it as "resourcePartition"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:resourcePartition}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 502
    Then the response should match the expected error response "azure-authentication-upstream-auth-failed"
    And the "gateway-runtime" service logs should contain "the federated service account token could not be read"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
