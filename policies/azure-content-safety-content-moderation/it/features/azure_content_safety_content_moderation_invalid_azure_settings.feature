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
Feature: Azure Content Safety content moderation policy with invalid Azure settings
  As an API developer
  I want an attachment with an unusable Azure endpoint or subscription key to be rejected
  So that a misconfigured guardrail never lets content through unchecked

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # Attachments that override the Azure endpoint or key with an empty or non-string value. The
  # policy definition declares both as non-empty strings, so the controller checks the API's
  # params against it and rejects the API when it is created, before any route is deployed.
  Scenario Outline: Omit the Azure endpoint/API key or configure it as an empty or non-string value (<case>)
    Given I generate a unique value from "acs-invalid-settings" and store it as "apiName"
    And I generate a unique API version from "acs-invalid-settings" and store it as "apiVersion"
    And I generate a unique API context from "/acs-invalid-settings" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{<override>,"request":{"jsonPath":"$.message"}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"
    And the response body should contain "<error>"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 404

    Examples:
      | case                | override                           | field                      | error                                            |
      | empty endpoint      | "azureContentSafetyEndpoint":""    | azureContentSafetyEndpoint | String length must be greater than or equal to 1 |
      | non-string endpoint | "azureContentSafetyEndpoint":12345 | azureContentSafetyEndpoint | Invalid type. Expected: string, given: integer   |
      | empty API key       | "azureContentSafetyKey":""         | azureContentSafetyKey      | String length must be greater than or equal to 1 |
      | non-string API key  | "azureContentSafetyKey":true       | azureContentSafetyKey      | Invalid type. Expected: string, given: boolean   |
