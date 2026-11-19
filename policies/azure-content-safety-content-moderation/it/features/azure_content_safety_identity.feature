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

# Runs in the identity block, whose gateway has the Content Safety endpoint and no subscription
# key, so a check that passes shows the API's Azure identity authenticated it. Each API chooses its
# identity in azureAuth. The gateway gets its workload identity from the testbench Entra ID mock and
# its container app's identity from the testbench Container Apps identity endpoint.
@azure-content-safety-identity
Feature: Azure Content Safety content moderation with the gateway's Azure identity
  As an API developer
  I want my API's Content Safety checks to authenticate with the gateway's Azure identity
  So that no subscription key has to be stored or rotated

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # AKS Workload Identity, on the request and the response side.

  Scenario: Safe content passes the check made with the gateway's workload identity
    Given I generate a unique value from "acs-wi-safe" and store it as "apiName"
    And I generate a unique API version from "acs-wi-safe" and store it as "apiVersion"
    And I generate a unique API context from "/acs-wi-safe" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"workload-identity"},"request":{"jsonPath":"$.message","hateSeverityThreshold":4,"violenceSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Hello, this is safe content"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Hate speech is blocked by the check made with the gateway's workload identity
    Given I generate a unique value from "acs-wi-hate" and store it as "apiName"
    And I generate a unique API version from "acs-wi-hate" and store it as "apiVersion"
    And I generate a unique API context from "/acs-wi-hate" and store it as "apiContext"
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

    # The positive control: the same API passes safe content, so the call is authenticated.
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

  Scenario: A response is checked with the gateway's workload identity
    Given I generate a unique value from "acs-wi-response" and store it as "apiName"
    And I generate a unique API version from "acs-wi-response" and store it as "apiVersion"
    And I generate a unique API context from "/acs-wi-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"workload-identity"},"response":{"jsonPath":"$.json.message","violenceSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Hello, this is safe content"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This response contains violence"}
      """
    Then the response status code should be 422
    And the response body should contain "Violation of Azure content safety content moderation detected"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A managed identity of the container app the gateway runs in: its system-assigned identity.

  Scenario: Safe content passes the check made with the container app's identity
    Given I generate a unique value from "acs-ca-safe" and store it as "apiName"
    And I generate a unique API version from "acs-ca-safe" and store it as "apiVersion"
    And I generate a unique API context from "/acs-ca-safe" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps"},"request":{"jsonPath":"$.message","hateSeverityThreshold":4,"violenceSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Hello, this is safe content"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Hate speech is blocked by the check made with the container app's identity
    Given I generate a unique value from "acs-ca-hate" and store it as "apiName"
    And I generate a unique API version from "acs-ca-hate" and store it as "apiVersion"
    And I generate a unique API context from "/acs-ca-hate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps"},"request":{"jsonPath":"$.message","hateSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # The positive control: the same API passes safe content, so the call is authenticated.
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

  # A token scope the testbench Container Apps identity endpoint always refuses, so no check of the
  # API can get an access token. It fails the way a failed Content Safety call does.

  Scenario: passthroughOnError lets content through when no access token can be obtained
    Given I generate a unique value from "acs-noid-pass" and store it as "apiName"
    And I generate a unique API version from "acs-noid-pass" and store it as "apiVersion"
    And I generate a unique API context from "/acs-noid-pass" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"},"request":{"jsonPath":"$.message","passthroughOnError":true,"hateSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"This content contains hate speech"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Without passthroughOnError, a check without an access token is rejected
    Given I generate a unique value from "acs-noid-block" and store it as "apiName"
    And I generate a unique API version from "acs-noid-block" and store it as "apiVersion"
    And I generate a unique API context from "/acs-noid-block" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"},"request":{"jsonPath":"$.message","hateSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 422 with body:
      """
      {"message":"Hello, this is safe content"}
      """
    Then the response body should contain "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the response body should contain "Error calling Azure Content Safety API"
    And the response body should not contain "assessments"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: showAssessment shows only that no access token was available, never the reason
    Given I generate a unique value from "acs-noid-assess" and store it as "apiName"
    And I generate a unique API version from "acs-noid-assess" and store it as "apiVersion"
    And I generate a unique API context from "/acs-noid-assess" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"},"request":{"jsonPath":"$.message","showAssessment":true,"hateSeverityThreshold":4}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 422 with body:
      """
      {"message":"Hello, this is safe content"}
      """
    Then the response body should contain "Could not obtain an access token for Azure Content Safety"
    And the response body should not contain "identity endpoint"
    And the response body should not contain "HTTP 400"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The controller checks an API's params against the policy definition before deploying it.
  # azureAuth takes a known type, a GUID client ID and a /.default scope, and nothing else; and an
  # API can't set the gateway's allowlists, because the definition lists only the API's own params,
  # among them the endpoint and key it may override.
  Scenario Outline: The controller rejects an API whose authentication settings don't fit the policy (<case>)
    Given I generate a unique value from "acs-invalid-auth" and store it as "apiName"
    And I generate a unique API version from "acs-invalid-auth" and store it as "apiVersion"
    And I generate a unique API context from "/acs-invalid-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{<params>,"request":{"jsonPath":"$.message"}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<error>"
    And the response body should contain "<field>"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate"
    Then the response status code should be 404

    Examples:
      | case                                     | params                                                                                        | error                                                               | field                              |
      | an unknown authentication type           | "azureAuth":{"authenticationType":"client-secret"}                                            | must be one of the following                                        | authenticationType                 |
      | a client ID that is not a GUID           | "azureAuth":{"authenticationType":"managed-identity","clientId":"not-a-guid"}                 | Does not match pattern                                              | clientId                           |
      | a scope without /.default                | "azureAuth":{"authenticationType":"workload-identity","scope":"https://cognitiveservices.azure.com"} | Does not match pattern                                       | scope                              |
      | a field azureAuth doesn't have           | "azureAuth":{"authenticationType":"workload-identity","tenantId":"contoso.onmicrosoft.com"}   | Additional property tenantId is not allowed                         | tenantId                           |
      | the gateway's allowed types, set by the API | "azureContentSafetyAllowedAuthTypes":["workload-identity"]                                 | Additional property azureContentSafetyAllowedAuthTypes is not allowed | azureContentSafetyAllowedAuthTypes |
      | the gateway's allowed endpoints, set by the API | "azureContentSafetyAllowedEndpoints":["http://testbench:3002"] | Additional property azureContentSafetyAllowedEndpoints is not allowed | azureContentSafetyAllowedEndpoints |
