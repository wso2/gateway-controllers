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
Feature: Content length guardrail policy content measurement
  As an API developer
  I want the guardrail to count the bytes of exactly the content it selects
  So that I can enforce content size constraints and protect my backend services

  # These scenarios check what the policy measures. It counts bytes, not characters, and trims
  # surrounding whitespace. jsonPath selects the value to measure, and an empty jsonPath measures
  # the whole body. The response scenario uses the LLM mock, which replies with the text the request
  # scripts in x_testbench_reply.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # A request with no body is rejected as absent before its length is checked, so even with
  # min 0 it gets 422.
  Scenario: Send an empty or missing body with min=0 (request)
    Given I generate a unique value from "clg-empty-min-zero" and store it as "apiName"
    And I generate a unique API version from "clg-empty-min-zero" and store it as "apiVersion"
    And I generate a unique API context from "/clg-empty-min-zero" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":0,"max":10,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message" should be "Request body is absent or could not be buffered"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The whole reply is measured, and the mock replies with an empty body.
  Scenario: Send an empty or missing body with min=0 (response)
    Given I generate a unique value from "clg-empty-resp" and store it as "apiName"
    And I generate a unique API version from "clg-empty-resp" and store it as "apiVersion"
    And I generate a unique API context from "/clg-empty-resp" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":0,"max":10,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"raw":""}}
      """
    And the response body should be empty

    # A 35-byte reply is over the maximum of 10.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"raw":"this reply is longer than ten bytes"}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The message is "hello" with three spaces on each side, 11 bytes, and must be exactly 5 bytes.
  Scenario: Send content with surrounding whitespace
    Given I generate a unique value from "clg-whitespace" and store it as "apiName"
    And I generate a unique API version from "clg-whitespace" and store it as "apiVersion"
    And I generate a unique API context from "/clg-whitespace" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":5,"max":5,"jsonPath":"$.message"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"   hello   "}
      """
    Then the response status code should be 200

    # Without its spaces the message is "hello!", 6 bytes, so it is blocked.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"   hello!   "}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The message must be 4 to 7 bytes. Two accented characters are 4 bytes and pass. Two emoji are
  # 8 bytes and are blocked, although they are only two characters.
  Scenario: Send multibyte UTF-8 characters such as emoji or accented characters
    Given I generate a unique value from "clg-utf8" and store it as "apiName"
    And I generate a unique API version from "clg-utf8" and store it as "apiVersion"
    And I generate a unique API context from "/clg-utf8" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":4,"max":7,"jsonPath":"$.message"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"éé"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"😀😀"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The whole body, {"message":"abc"}, is exactly 17 bytes. The message alone is 3 bytes.
  Scenario: Configure an empty JSONPath
    Given I generate a unique value from "clg-empty-path" and store it as "apiName"
    And I generate a unique API version from "clg-empty-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-empty-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":17,"max":17,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"abc"}
      """
    Then the response status code should be 200

    # The whole body is now 18 bytes, one over the limit.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"abcd"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The 11-byte message is within 5 to 11 bytes. The whole body is far longer than 11 bytes.
  Scenario: Configure a valid JSONPath selecting a string
    Given I generate a unique value from "clg-string-path" and store it as "apiName"
    And I generate a unique API version from "clg-string-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-string-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":5,"max":11,"jsonPath":"$.message"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"Hello World","padding":"this field makes the whole body far longer than eleven bytes"}
      """
    Then the response status code should be 200

    # A 12-byte message is one byte over the maximum.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"Hello World!","padding":"this field makes the whole body far longer than eleven bytes"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The number 12345 is measured as its text, 5 bytes.
  Scenario: Configure a JSONPath selecting a number or boolean (number)
    Given I generate a unique value from "clg-number-path" and store it as "apiName"
    And I generate a unique API version from "clg-number-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-number-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":5,"max":5,"jsonPath":"$.count"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"count":12345}
      """
    Then the response status code should be 200

    # The number 1234 is 4 bytes, under the minimum of 5.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"count":1234}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # A value that is not a string or a number cannot be measured. The boolean true fails
  # extraction, and the request gets the guardrail's error.
  Scenario: Configure a JSONPath selecting a number or boolean (boolean)
    Given I generate a unique value from "clg-bool-path" and store it as "apiName"
    And I generate a unique API version from "clg-bool-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-bool-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":4,"max":4,"jsonPath":"$.flag"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"flag":true}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The path cannot select anything, so every checked request gets the guardrail's error. The
  # operation without the policy still answers afterwards.
  Scenario: Configure a invalid JSONPath
    Given I generate a unique value from "clg-bad-path" and store it as "apiName"
    And I generate a unique API version from "clg-bad-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-bad-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":50,"jsonPath":"$.[bad"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"hello"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get"
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
