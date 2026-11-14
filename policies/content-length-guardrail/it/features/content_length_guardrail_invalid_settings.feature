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
Feature: Content length guardrail policy with settings it cannot use
  As an API developer
  I want a content length guardrail configuration the policy cannot use to fail visibly
  So that I can enforce content size constraints and protect my backend services

  # Attachments that deploy but whose policy cannot be built. The policy schema allows each of
  # these configurations, so the API is created. The policy engine then cannot build the policy,
  # skips the route's policy chain, and answers every request to the route with 500.
  # Configurations rejected when the API is created are in
  # content_length_guardrail_validation.feature.
  #
  # The policy engine also answers 500 for a route whose policy chain it has not received yet,
  # so each API carries a control operation, /ready, with a valid attachment. The engine applies
  # every route of an update together: once /ready answers 200, /validate's attachment has been
  # processed, and its 500 can only come from its own configuration.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Configure neither request nor response
    Given I generate a unique value from "clg-no-sides" and store it as "apiName"
    And I generate a unique API version from "clg-no-sides" and store it as "apiVersion"
    And I generate a unique API context from "/clg-no-sides" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/ready","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":100,"jsonPath":""}}}]},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200 with body:
      """
      {"message":"ready"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"hello"}
      """
    Then the response status code should be 500
    And the response body should contain "Internal Server Error"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Configure min greater than max
    Given I generate a unique value from "clg-min-over-max" and store it as "apiName"
    And I generate a unique API version from "clg-min-over-max" and store it as "apiVersion"
    And I generate a unique API context from "/clg-min-over-max" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/ready","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":100,"jsonPath":""}}}]},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":20,"max":10}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200 with body:
      """
      {"message":"ready"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"hello"}
      """
    Then the response status code should be 500
    And the response body should contain "Internal Server Error"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Configure jsonPath or streamingJsonPath using a non-string value (streamingJsonPath)
    Given I generate a unique value from "clg-stream-path-number" and store it as "apiName"
    And I generate a unique API version from "clg-stream-path-number" and store it as "apiVersion"
    And I generate a unique API context from "/clg-stream-path-number" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/ready","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":100,"jsonPath":""}}}]},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10,"streamingJsonPath":5}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200 with body:
      """
      {"message":"ready"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"hello"}
      """
    Then the response status code should be 500
    And the response body should contain "Internal Server Error"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
