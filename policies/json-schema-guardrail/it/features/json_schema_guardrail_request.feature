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

@json-schema-guardrail
Feature: JSON Schema guardrail policy on requests
  As an API developer
  I want request payloads checked against a JSON Schema before they reach the upstream
  So that only payloads that fit the contract are forwarded

  # Request validation: invertDecision=false, assessment details for an extraction error, the
  # "enabled" default and an unusable schema. Request validation is on only with "enabled": true.
  # Where the upstream is the capture service under the API's name, a lookup shows what reached the
  # backend, and 204 means nothing did.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Configure invertDecision=false and validate normal matching/non-matching payloads
    Given I generate a unique value from "jsg-invert-false" and store it as "apiName"
    And I generate a unique API version from "jsg-invert-false" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-invert-false" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}","invert":false}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Enable guardrail assessment details and trigger a validation failure (extraction error)
    Given I generate a unique value from "jsg-assessment-extraction" and store it as "apiName"
    And I generate a unique API version from "jsg-assessment-extraction" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-assessment-extraction" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.prompt","showAssessment":true,"schema":"{\"type\":\"string\"}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.assessments" should be "key not found: prompt"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # /default leaves "enabled" out, so request validation stays at its default, false.
  Scenario: A request schema without enabled, or with enabled false, is not enforced
    Given I generate a unique value from "jsg-request-enabled" and store it as "apiName"
    And I generate a unique API version from "jsg-request-enabled" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-request-enabled" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/default","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]},{"method":"POST","path":"/disabled","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":false,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]},{"method":"POST","path":"/enabled","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/default" with body:
      """
      {"name":"jsg-e1-ann"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/default"
    Then the response status code should be 200
    And the JSON response field "body" should contain "jsg-e1-ann"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/disabled" with body:
      """
      {"name":"jsg-e1-ann"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/disabled"
    Then the response status code should be 200
    And the JSON response field "body" should contain "jsg-e1-ann"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/enabled" with body:
      """
      {"name":"jsg-e1-ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The schema is valid JSON, so the API deploys, but "type" must be a string. The second request
  # shows every request fails, not only the first.
  Scenario: A schema that is not a valid JSON Schema rejects every request
    Given I generate a unique value from "jsg-unusable-schema" and store it as "apiName"
    And I generate a unique API version from "jsg-unusable-schema" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-unusable-schema" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":5}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error validating schema"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error validating schema"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
