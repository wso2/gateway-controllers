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
Feature: JSON Schema guardrail policy with schema keywords
  As an API developer
  I want the common JSON Schema keywords enforced on request payloads
  So that required fields, types, constraints and structure are checked

  # JSON Schema keywords on the request body: data types and additionalProperties. Every API
  # validates the whole body with showAssessment on, so the error names the field and the rule that
  # failed. The backend reflects the request as JSON.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Validate data types such as string, number, boolean, object, and array fields (<case>)
    Given I generate a unique value from "jsg-types" and store it as "apiName"
    And I generate a unique API version from "jsg-types" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-types" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/products","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"title\":{\"type\":\"string\"},\"price\":{\"type\":\"number\"},\"inStock\":{\"type\":\"boolean\"},\"dimensions\":{\"type\":\"object\"},\"tags\":{\"type\":\"array\"}},\"required\":[\"title\",\"price\",\"inStock\",\"dimensions\",\"tags\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/products" with body:
      """
      {"title":"Desk","price":120.5,"inStock":true,"dimensions":{"width":120},"tags":["office"]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/products" with body:
      """
      <payload>
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "<field>"
    And the JSON response field "message.assessments[0].description" should be "<description>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case    | payload                                                                                      | field      | description                                    |
      | string  | {"title":5,"price":120.5,"inStock":true,"dimensions":{"width":120},"tags":["office"]}        | title      | Invalid type. Expected: string, given: integer |
      | number  | {"title":"Desk","price":"120.5","inStock":true,"dimensions":{"width":120},"tags":["office"]} | price      | Invalid type. Expected: number, given: string  |
      | boolean | {"title":"Desk","price":120.5,"inStock":"true","dimensions":{"width":120},"tags":["office"]} | inStock    | Invalid type. Expected: boolean, given: string |
      | object  | {"title":"Desk","price":120.5,"inStock":true,"dimensions":"120x60","tags":["office"]}        | dimensions | Invalid type. Expected: object, given: string  |
      | array   | {"title":"Desk","price":120.5,"inStock":true,"dimensions":{"width":120},"tags":"office"}     | tags       | Invalid type. Expected: array, given: string   |

  Scenario: Validate additional/unknown fields when additionalProperties is restricted
    Given I generate a unique value from "jsg-additional" and store it as "apiName"
    And I generate a unique API version from "jsg-additional" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-additional" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/users","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"role\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}},\"additionalProperties\":false}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      {"role":"viewer","name":"Ann"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      {"role":"viewer","name":"Ann","isAdmin":true}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].description" should be "Additional property isAdmin is not allowed"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
