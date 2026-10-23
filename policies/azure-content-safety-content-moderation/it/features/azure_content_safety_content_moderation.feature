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

@azure-content-safety-content-moderation
Feature: Azure content safety content moderation policy
  As an API developer
  I want the azure-content-safety-content-moderation policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: azure-content-safety-content-moderation rejects a request with hate speech
    Given I generate a unique value from "compat-acs-hate" and store it as "apiName"
    And I generate a unique API version from "compat-acs-hate" and store it as "apiVersion"
    And I generate a unique API context from "/compat-acs-hate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3002            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","hateSeverityThreshold":4}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This content contains hate speech"}
      """
    Then the response status code should be 422
    And the response should match the expected error response "azure-content-safety-content-moderation-request-violation"
