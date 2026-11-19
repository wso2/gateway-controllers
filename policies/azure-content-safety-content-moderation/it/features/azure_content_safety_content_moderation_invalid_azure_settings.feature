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
  I want an attachment with an unusable Azure endpoint or subscription key to fail visibly
  So that a misconfigured guardrail never lets content through unchecked

  # Attachments that override the Azure endpoint or key with an empty or non-string value. The
  # gateway does not validate system parameters when an API is created, so the API deploys and
  # every request to the route gets 500.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The policy engine also answers 500 for a route whose policy chain it has not received yet, so
  # the API carries a control operation, /ready, whose attachment uses the block's valid Azure
  # settings. The engine applies every route of an update together: once /ready answers 200,
  # /chat's attachment has been processed, and its 500 can only come from the overridden settings.
  # The message is allowed content, and the response never carries the configured subscription key.
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
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/ready","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message"}}}]},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{<override>,"request":{"jsonPath":"$.message"}}}]}] |
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 500
    And the response body should contain "Internal Server Error"
    And the response body should not contain "What is the capital of France?"
    And the response body should not contain "test-subscription-key"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                | override                           |
      | empty endpoint      | "azureContentSafetyEndpoint":""    |
      | non-string endpoint | "azureContentSafetyEndpoint":12345 |
      | empty API key       | "azureContentSafetyKey":""         |
      | non-string API key  | "azureContentSafetyKey":true       |
