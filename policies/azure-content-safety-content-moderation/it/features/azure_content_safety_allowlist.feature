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

# Runs in the allowlist block, whose gateway has a subscription key, allows its APIs only workload
# identity (azurecontentsafety_allowed_auth_types = ["workload-identity"]), and only its own
# endpoint (azurecontentsafety_allowed_endpoints = ["http://testbench:3005"]). An API the lists
# refuse can't build its policy, and the gateway then answers that API's checked route with 500.
@azure-content-safety-allowlist
Feature: The gateway's lists of allowed authentication types and endpoints
  As a gateway operator
  I want to limit how APIs authenticate to Azure Content Safety
  So that no API sends the subscription key, uses an identity I haven't allowed, or sends either elsewhere

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: An API that chooses an allowed authentication type is checked with it
    Given I generate a unique value from "acs-allow-wi" and store it as "apiName"
    And I generate a unique API version from "acs-allow-wi" and store it as "apiVersion"
    And I generate a unique API context from "/acs-allow-wi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"workload-identity"},"request":{"jsonPath":"$.message","hateSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Hello, this is safe content"}
      """
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This content contains hate speech"}
      """
    Then the response status code should be 422
    And the response body should contain "Violation of Azure content safety content moderation detected"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Gateways up to 1.2.0 handle a policy that can't be built differently, so these run on newer ones.
  Scenario Outline: An API whose authentication type or endpoint the gateway doesn't allow fails closed (<case>)
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "acs-refused" and store it as "apiName"
    And I generate a unique API version from "acs-refused" and store it as "apiVersion"
    And I generate a unique API context from "/acs-refused" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{<params>"request":{"jsonPath":"$.message","hateSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 500 with body:
      """
      {"message":"Hello, this is safe content"}
      """
    Then the JSON response field "error" should be "Internal Server Error"
    And the response body should not contain "test-subscription-key"
    And the response body should not contain "azureContentSafetyAllowedAuthTypes"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                                 | params                                               |
      | no azureAuth, so api-key             |                                                      |
      | an identity that isn't on the list   | "azureAuth":{"authenticationType":"container-apps"}, |
      | an allowed identity sent to an endpoint that isn't on the list | "azureContentSafetyEndpoint":"http://testbench:3002","azureAuth":{"authenticationType":"workload-identity"}, |
