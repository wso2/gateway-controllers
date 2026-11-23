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
Feature: JSON Schema guardrail policy against crafted payloads
  As an API developer
  I want oversized, deeply nested and crafted payloads handled safely
  So that they cannot crash the gateway or get past the schema

  # Oversized, deeply nested and crafted request payloads. Every API validates the whole body, and
  # the backend reflects the request as JSON.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The first array is nested 10240 levels deep, past the JSON decoder's limit of 10000; the second
  # 2048 levels. The last request shows the gateway still serves after them.
  Scenario: Send very large/deeply nested JSON or payloads designed to stress schema validation
    Given I generate a unique value from "jsg-stress" and store it as "apiName"
    And I generate a unique API version from "jsg-stress" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-stress" and store it as "apiContext"
    And I generate a value of 10 KiB of "[" and store it as "deepOpen"
    And I generate a value of 10 KiB of "]" and store it as "deepClose"
    And I generate a value of 2 KiB of "[" and store it as "nestOpen"
    And I generate a value of 2 KiB of "]" and store it as "nestClose"
    And I generate a value of 256 KiB of "x" and store it as "bigText"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/payloads","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"array\"},\"text\":{\"type\":\"string\"}}}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payloads" with body:
      """
      {"a":${CTX:deepOpen}${CTX:deepClose}}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error validating schema"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payloads" with body:
      """
      {"a":${CTX:nestOpen}${CTX:nestClose}}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payloads" with body:
      """
      {"text":"${CTX:bigText}"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payloads" with body:
      """
      {"text":"small"}
      """
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The schema allows no other fields at either level. Each crafted payload differs from the valid
  # one in one place. Deep nesting is covered by the stress scenario.
  Scenario Outline: Send malicious JSON content, including unexpected properties, type-confusion attempts, deeply nested objects, or schema-bypass payloads (<case>)
    Given I generate a unique value from "jsg-malicious" and store it as "apiName"
    And I generate a unique API version from "jsg-malicious" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-malicious" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/accounts","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"role\":{\"enum\":[\"viewer\",\"editor\"]},\"age\":{\"type\":\"integer\",\"minimum\":0},\"profile\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"],\"additionalProperties\":false}},\"required\":[\"role\",\"age\",\"profile\"],\"additionalProperties\":false}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/accounts" with body:
      """
      {"role":"viewer","age":30,"profile":{"name":"Ann"}}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/accounts" with body:
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
      | case                       | payload                                                            | field   | description                                    |
      | unexpected property        | {"role":"viewer","age":30,"profile":{"name":"Ann"},"isAdmin":true} | (root)  | Additional property isAdmin is not allowed     |
      | case-variant key           | {"role":"viewer","Role":"admin","age":30,"profile":{"name":"Ann"}} | (root)  | Additional property Role is not allowed        |
      | number as string           | {"role":"viewer","age":"30","profile":{"name":"Ann"}}              | age     | Invalid type. Expected: integer, given: string |
      | fraction for integer       | {"role":"viewer","age":30.5,"profile":{"name":"Ann"}}              | age     | Invalid type. Expected: integer, given: number |
      | null for object            | {"role":"viewer","age":30,"profile":null}                          | profile | Invalid type. Expected: object, given: null    |
      | nested unexpected property | {"role":"viewer","age":30,"profile":{"name":"Ann","admin":true}}   | profile | Additional property admin is not allowed       |
