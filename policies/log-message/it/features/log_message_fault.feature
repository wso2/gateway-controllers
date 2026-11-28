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
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@log-message
Feature: Log message policy fault logging
  As an API operator
  I want each failure to be logged with its cause
  So that I can diagnose failures without exposing what was rejected

  # The policy attached as a fault policy, logging policy rejections. Fault policies exist only on
  # Gateway releases after 1.2.0, and older Gateways accept faultPolicies but ignore them, so this
  # runner runs only on later Gateways. Records reach the log late, but in the order they are
  # written. So each check ends with a fence: a later request whose records come last. Once they
  # appear, the records before them are final.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # regex-guardrail blocks a body that matches its pattern; its internal description names the
  # pattern, lm-fault-blocked, and showAssessment is left at false, so the error body does not carry
  # it. The /auth request is sent before the /guard requests, so the /guard fence also makes its
  # record final.
  Scenario Outline: Verify log access/observability during failures and security events (<case>)
    Given I generate a unique value from "lm-fault" and store it as "apiName"
    And I generate a unique API version from "lm-fault" and store it as "apiVersion"
    And I generate a unique API context from "/lm-fault" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.faultPolicies     | [{"name":"log-message","version":"v1","params":<fault>}] |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/auth","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]},{"method":"POST","path":"/guard","policies":[{"name":"regex-guardrail","version":"v1","params":{"request":{"jsonPath":"","regex":"(lm-fault-blocked)","invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-fault-auth"
    And I set header "API-Key" to "lm-fault-wrong-key"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/auth"
    Then the response status code should be 401
    And the JSON response field "message" should be "Valid API key required"

    When I set header "X-Request-Id" to "lm-fault-guard"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/guard" with body:
      """
      {"text":"lm-fault-blocked"}
      """
    Then the response status code should be 422
    And the JSON response field "message.interveningGuardrail" should be "regex-guardrail"

    When I set header "X-Request-Id" to "lm-fault-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/guard" with body:
      """
      {"text":"lm-fault-blocked again"}
      """
    Then the response status code should be 422
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/guard" should be:
      | mediation-flow | status | error-code | error-type | failing-policy  | record                          |
      | FAULT          | 422    | 906205     | guardrail  | regex-guardrail | [not contains lm-fault-blocked] |
      | FAULT          | 422    | 906205     | guardrail  | regex-guardrail | [not contains lm-fault-blocked] |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/auth" should be:
      | mediation-flow | status | error-code | error-type     | error-message          | failing-policy | payload                                                     | headers.content-type | record                            |
      | FAULT          | 401    | 900901     | authentication | Valid API key required | api-key-auth   | {"error":"Unauthorized","message":"Valid API key required"} | <content_type>       | [not contains lm-fault-wrong-key] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                  | fault                                                                       | content_type     |
      | error headers logged  | {"fault":{"payload":true,"headers":true}}                                   | application/json |
      | content type excluded | {"fault":{"payload":true,"headers":true,"excludeHeaders":["Content-Type"]}} | [absent]         |

  # fault is left at its defaults, so the record holds no payload or headers. The record should
  # carry the request id the client sent, but the policy reads it from the error response's
  # headers, which do not carry it, so the record wrongly holds <request-id-unavailable>.
  @known-issue
  Scenario: Verify log access/observability during failures and security events (request ID)
    Given I generate a unique value from "lm-fault-req-id" and store it as "apiName"
    And I generate a unique API version from "lm-fault-req-id" and store it as "apiVersion"
    And I generate a unique API context from "/lm-fault-req-id" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.faultPolicies     | [{"name":"log-message","version":"v1","params":{"fault":{}}}] |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/auth","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-fault-req-id"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/auth"
    Then the response status code should be 401

    When I set header "X-Request-Id" to "lm-fault-req-id-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/auth"
    Then the response status code should be 401
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/auth" should be:
      | mediation-flow | request-id            | payload  | headers  |
      | FAULT          | lm-fault-req-id       | [absent] | [absent] |
      | FAULT          | lm-fault-req-id-fence | [absent] | [absent] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
