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
Feature: Log message policy headers
  As an API operator
  I want header logging to leave out the headers I exclude and to mask credentials
  So that the logs do not expose secrets

  # Header exclusion and masking: header name casing and the values a log must not expose. The
  # backend echoes the request as JSON, so each scenario also shows the backend still receives every
  # header. Records reach the log late, but in the order they are written. So each check ends with a
  # fence: a later request whose records come last. Once they appear, the records before them are
  # final.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The raw request sends each header name spelled exactly as written. The excluded name is quoted
  # in the examples so its spaces are kept. The Authorization header, sent in upper case, is masked.
  Scenario Outline: Configure excluded header names using different casing and send mixed-case header variants (<case>)
    Given I generate a unique value from "lm-casing" and store it as "apiName"
    And I generate a unique API version from "lm-casing" and store it as "apiVersion"
    And I generate a unique API context from "/lm-casing" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true,"excludeHeaders":[<excluded>]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with headers:
      | X-Request-Id  | lm-casing |
      | <sent>        | lm-casing-excluded |
      | X-LM-Kept     | lm-casing-kept |
      | AUTHORIZATION | Bearer lm-casing-secret-token |
    Then the response status code should be 200
    And the response should contain echoed header "<sent>" with value "lm-casing-excluded"

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with headers:
      | X-Request-Id  | lm-casing-fence |
      | <sent>        | lm-casing-excluded |
      | X-LM-Kept     | lm-casing-kept |
      | AUTHORIZATION | Bearer lm-casing-secret-token |
    Then the response status code should be 200
    And the response should contain echoed header "<sent>" with value "lm-casing-excluded"
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id      | headers.x-lm-kept | headers.authorization | headers.x-lm-case | record                            | record                          |
      | REQUEST        | lm-casing       | lm-casing-kept    | ***                   | [absent]          | [not contains lm-casing-excluded] | [not contains lm-casing-secret] |
      | REQUEST        | lm-casing-fence | lm-casing-kept    | ***                   | [absent]          | [not contains lm-casing-excluded] | [not contains lm-casing-secret] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                                           | excluded      | sent      |
      | lower-case name, upper-case header             | "x-lm-case"   | X-LM-CASE |
      | upper-case name, mixed-case header             | "X-LM-CASE"   | x-Lm-cAsE |
      | mixed-case name with spaces, lower-case header | " X-Lm-Case " | x-lm-case |

  # The Authorization header is masked by default and the other two are excluded. The policy has
  # no payload masking, so the payload is logged as sent.
  Scenario: Send sensitive values in headers and payloads while exclusion/masking controls are configured
    Given I generate a unique value from "lm-sensitive" and store it as "apiName"
    And I generate a unique API version from "lm-sensitive" and store it as "apiVersion"
    And I generate a unique API context from "/lm-sensitive" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true,"excludeHeaders":["X-API-Key","Cookie"]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-sensitive"
    And I set header "Authorization" to "Bearer lm-sensitive-secret-token"
    And I set header "X-API-Key" to "lm-sensitive-secret-key"
    And I set header "Cookie" to "session=lm-sensitive-secret-cookie"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"note":"lm-sensitive-body"}
      """
    Then the response status code should be 200
    And the response should contain echoed header "Authorization" with value "Bearer lm-sensitive-secret-token"
    And the response should contain echoed header "X-Api-Key" with value "lm-sensitive-secret-key"
    And the response should contain echoed header "Cookie" with value "session=lm-sensitive-secret-cookie"

    When I set header "X-Request-Id" to "lm-sensitive-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"note":"lm-sensitive-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id         | headers.authorization | headers.x-api-key | headers.cookie | payload                       | record                             |
      | REQUEST        | lm-sensitive       | ***                   | [absent]          | [absent]       | [absent]                      | [not contains lm-sensitive-secret] |
      | REQUEST        | lm-sensitive       | [absent]              | [absent]          | [absent]       | {"note":"lm-sensitive-body"}  | [not contains lm-sensitive-secret] |
      | REQUEST        | lm-sensitive-fence | ***                   | [absent]          | [absent]       | [absent]                      | [not contains lm-sensitive-secret] |
      | REQUEST        | lm-sensitive-fence | [absent]              | [absent]          | [absent]       | {"note":"lm-sensitive-fence"} | [not contains lm-sensitive-secret] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # No header is excluded: the access token is kept out of the log by the default Authorization mask.
  Scenario: Inspect logs for access tokens, API keys, cookies, passwords, PII, or other secrets
    Given I generate a unique value from "lm-inspect" and store it as "apiName"
    And I generate a unique API version from "lm-inspect" and store it as "apiVersion"
    And I generate a unique API context from "/lm-inspect" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true},"response":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-inspect"
    And I set header "Authorization" to "Bearer lm-inspect-secret-token"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "Authorization" with value "Bearer lm-inspect-secret-token"

    When I set header "X-Request-Id" to "lm-inspect-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id       | headers.authorization | record                           |
      | REQUEST        | lm-inspect       | ***                   | [not contains lm-inspect-secret] |
      | RESPONSE       | lm-inspect       | [absent]              | [not contains lm-inspect-secret] |
      | REQUEST        | lm-inspect-fence | ***                   | [not contains lm-inspect-secret] |
      | RESPONSE       | lm-inspect-fence | [absent]              | [not contains lm-inspect-secret] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
