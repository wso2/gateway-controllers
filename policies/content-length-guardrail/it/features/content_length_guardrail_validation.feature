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

@content-length-guardrail
Feature: Content length guardrail policy configuration validation
  As an API developer
  I want an invalid content length guardrail configuration to be rejected when the API is created
  So that I can enforce content size constraints and protect my backend services

  # Configurations rejected when the API is created, from the policy's parameter schema.
  # Configurations that deploy but that the policy cannot use are in
  # content_length_guardrail_invalid_settings.feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Configure request or response as a non-object value (<case>)
    Given I generate a unique value from "clg-non-object-<key>" and store it as "apiName"
    And I generate a unique API version from "clg-non-object-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/clg-non-object-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case                 | key         | field    | params            |
      | request as a string  | req-string  | request  | {"request":"abc"} |
      | request as an array  | req-array   | request  | {"request":[]}    |
      | response as a number | resp-number | response | {"response":5}    |

  # A side needs both bounds unless it sets enabled to false. The response side is off by
  # default, so it is enabled here.
  Scenario Outline: Enable a path without min or max (<case>)
    Given I generate a unique value from "clg-no-bounds-<key>" and store it as "apiName"
    And I generate a unique API version from "clg-no-bounds-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/clg-no-bounds-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case                                 | key            | field    | params                        |
      | request without min                  | req-no-min     | request  | {"request":{"max":10}}        |
      | request without max                  | req-no-max     | request  | {"request":{"min":1}}         |
      | response enabled without min and max | resp-no-bounds | response | {"response":{"enabled":true}} |

  Scenario: Configure a negative minimum
    Given I generate a unique value from "clg-negative-min" and store it as "apiName"
    And I generate a unique API version from "clg-negative-min" and store it as "apiVersion"
    And I generate a unique API context from "/clg-negative-min" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":-1,"max":10}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "request.min"

  Scenario Outline: Configure max=0 or a negative maximum (<case>)
    Given I generate a unique value from "clg-bad-max-<key>" and store it as "apiName"
    And I generate a unique API version from "clg-bad-max-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/clg-bad-max-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case         | key      | field       | params                         |
      | max of 0     | zero     | request.max | {"request":{"min":0,"max":0}}  |
      | negative max | negative | request.max | {"request":{"min":0,"max":-5}} |

  # The policy has no timeout field, so min and max are the numeric fields. Numeric strings such
  # as "10" are left out: Gateway 1.2.0 and later convert them to numbers before the check.
  Scenario Outline: Configure min, max, or timeout-like numeric fields using invalid types or fractional values (<case>)
    Given I generate a unique value from "clg-bad-number-<key>" and store it as "apiName"
    And I generate a unique API version from "clg-bad-number-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/clg-bad-number-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case                        | key          | field       | params                             |
      | min as a non-numeric string | min-string   | request.min | {"request":{"min":"abc","max":10}} |
      | min as a boolean            | min-bool     | request.min | {"request":{"min":true,"max":10}}  |
      | fractional min              | min-fraction | request.min | {"request":{"min":1.5,"max":10}}   |
      | max as a non-numeric string | max-string   | request.max | {"request":{"min":1,"max":"ten"}}  |
      | fractional max              | max-fraction | request.max | {"request":{"min":1,"max":2.5}}    |

  Scenario Outline: Configure enabled, invert, or showAssessment using a non-boolean value (<case>)
    Given I generate a unique value from "clg-bad-bool-<key>" and store it as "apiName"
    And I generate a unique API version from "clg-bad-bool-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/clg-bad-bool-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case                       | key        | field                  | params                                               |
      | enabled as a string        | enabled    | request.enabled        | {"request":{"enabled":"yes","min":1,"max":10}}       |
      | invert as a number         | invert     | request.invert         | {"request":{"min":1,"max":10,"invert":1}}            |
      | showAssessment as a string | assessment | request.showAssessment | {"request":{"min":1,"max":10,"showAssessment":"no"}} |

  # A non-string streamingJsonPath is in content_length_guardrail_invalid_settings.feature: the
  # schema does not declare that parameter.
  Scenario: Configure jsonPath or streamingJsonPath using a non-string value (jsonPath)
    Given I generate a unique value from "clg-path-number" and store it as "apiName"
    And I generate a unique API version from "clg-path-number" and store it as "apiVersion"
    And I generate a unique API context from "/clg-path-number" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":10,"jsonPath":5}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "request.jsonPath"
