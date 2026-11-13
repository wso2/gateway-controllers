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
Feature: Azure Content Safety content moderation policy configuration validation
  As an API developer
  I want invalid Azure Content Safety moderation configurations to be rejected
  So that a misconfigured guardrail is never deployed

  # Configurations the policy schema rejects when the API is created (400). Attachments that deploy
  # but cannot run have feature files of their own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Configure neither request nor response
    Given I generate a unique value from "acs-no-side" and store it as "apiName"
    And I generate a unique API version from "acs-no-side" and store it as "apiVersion"
    And I generate a unique API context from "/acs-no-side" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "Must validate at least one schema (anyOf)"

  Scenario Outline: Configure request or response as a non-object value (<case>)
    Given I generate a unique value from "acs-non-object-side" and store it as "apiName"
    And I generate a unique API version from "acs-non-object-side" and store it as "apiVersion"
    And I generate a unique API context from "/acs-non-object-side" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<message>"

    Examples:
      | case                  | params                | message                                        |
      | request as a string   | {"request":"enabled"} | Invalid type. Expected: object, given: string  |
      | request as an array   | {"request":[]}        | Invalid type. Expected: object, given: array   |
      | response as a number  | {"response":1}        | Invalid type. Expected: object, given: integer |
      | response as a boolean | {"response":true}     | Invalid type. Expected: object, given: boolean |

  Scenario Outline: Configure a threshold below -1 or above 7 (<case>)
    Given I generate a unique value from "acs-threshold-range" and store it as "apiName"
    And I generate a unique API version from "acs-threshold-range" and store it as "apiVersion"
    And I generate a unique API context from "/acs-threshold-range" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<message>"

    Examples:
      | case                           | params                                       | message                             |
      | request hate threshold -2      | {"request":{"hateSeverityThreshold":-2}}     | Must be greater than or equal to -1 |
      | request violence threshold 8   | {"request":{"violenceSeverityThreshold":8}}  | Must be less than or equal to 7     |
      | response sexual threshold -2   | {"response":{"sexualSeverityThreshold":-2}}  | Must be greater than or equal to -1 |
      | response self-harm threshold 8 | {"response":{"selfHarmSeverityThreshold":8}} | Must be less than or equal to 7     |

  Scenario Outline: Configure a fractional, nonnumeric, boolean, object, or array threshold (<case>)
    Given I generate a unique value from "acs-threshold-type" and store it as "apiName"
    And I generate a unique API version from "acs-threshold-type" and store it as "apiVersion"
    And I generate a unique API context from "/acs-threshold-type" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"hateSeverityThreshold":<threshold>}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "Invalid type. Expected: integer, given: <given>"

    Examples:
      | case       | threshold   | given   |
      | fractional | 4.5         | number  |
      | nonnumeric | "high"      | string  |
      | boolean    | true        | boolean |
      | object     | {"level":4} | object  |
      | array      | [4]         | array   |

  Scenario Outline: Configure passthroughOnError or showAssessment with a non-boolean value (<case>)
    Given I generate a unique value from "acs-non-boolean" and store it as "apiName"
    And I generate a unique API version from "acs-non-boolean" and store it as "apiVersion"
    And I generate a unique API context from "/acs-non-boolean" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "Invalid type. Expected: boolean, given: <given>"

    Examples:
      | case                             | params                                   | given   |
      | request passthroughOnError "yes" | {"request":{"passthroughOnError":"yes"}} | string  |
      | response passthroughOnError 1    | {"response":{"passthroughOnError":1}}    | integer |
      | request showAssessment 0         | {"request":{"showAssessment":0}}         | integer |
      | response showAssessment "no"     | {"response":{"showAssessment":"no"}}     | string  |
