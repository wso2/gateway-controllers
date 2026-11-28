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
Feature: Log message policy
  As an API operator
  I want configured request and response data to be written to traffic logs
  So that API traffic can be diagnosed without changing the response

  # Request and response logging, the HTTP methods, header exclusion, a transformation before the
  # policy and large payloads. Unless a scenario says otherwise, the backend echoes the request as
  # JSON and options left out default to false. Each API waits on a path that has no policy. Records
  # reach the log late, but in the order they are written. So each check ends with a fence: a later
  # request whose records come last. Once they appear, the records before them are final. A check
  # that picks the records of one request by request id needs no fence.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The policy logs the headers in the header phase and the payload in the body phase, so one
  # request gives two records with the same request id.
  Scenario: Enable both request payload and header logging
    Given I generate a unique value from "lm-req-both" and store it as "apiName"
    And I generate a unique API version from "lm-req-both" and store it as "apiVersion"
    And I generate a unique API context from "/lm-req-both" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-req-both"
    And I set header "X-Lm-Marker" to "lm-req-both-header"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-req-both-body"}
      """
    Then the response status code should be 200
    And the JSON response field "json.marker" should be "lm-req-both-body"

    When I set header "X-Request-Id" to "lm-req-both-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-req-both-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id        | headers.x-lm-marker | payload                        |
      | REQUEST        | lm-req-both       | lm-req-both-header  | [absent]                       |
      | REQUEST        | lm-req-both       | [absent]            | {"marker":"lm-req-both-body"}  |
      | REQUEST        | lm-req-both-fence | lm-req-both-header  | [absent]                       |
      | REQUEST        | lm-req-both-fence | [absent]            | {"marker":"lm-req-both-fence"} |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Log response payload and headers
    Given I generate a unique value from "lm-resp-both" and store it as "apiName"
    And I generate a unique API version from "lm-resp-both" and store it as "apiVersion"
    And I generate a unique API context from "/lm-resp-both" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"response":{"payload":true,"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-resp-both-first"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should be valid JSON

    When I set header "X-Request-Id" to "lm-resp-both-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id         | headers.:status | payload                       |
      | RESPONSE       | lm-resp-both-first | 200             | [absent]                      |
      | RESPONSE       | lm-resp-both-first | [absent]        | [contains lm-resp-both-first] |
      | RESPONSE       | lm-resp-both-fence | 200             | [absent]                      |
      | RESPONSE       | lm-resp-both-fence | [absent]        | [contains lm-resp-both-fence] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Each phase writes its own record, in phase order. The response records take the request id
  # from the response headers, where the gateway returns it.
  Scenario: Configure logging on both request and response flows
    Given I generate a unique value from "lm-both-flows" and store it as "apiName"
    And I generate a unique API version from "lm-both-flows" and store it as "apiVersion"
    And I generate a unique API context from "/lm-both-flows" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true},"response":{"payload":true,"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-both-flows"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-both-flows-body"}
      """
    Then the response status code should be 200
    And the JSON response field "json.marker" should be "lm-both-flows-body"

    When I set header "X-Request-Id" to "lm-both-flows-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-both-flows-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id          | headers.:method | headers.:status | payload                          |
      | REQUEST        | lm-both-flows       | POST            | [absent]        | [absent]                         |
      | REQUEST        | lm-both-flows       | [absent]        | [absent]        | {"marker":"lm-both-flows-body"}  |
      | RESPONSE       | lm-both-flows       | [absent]        | 200             | [absent]                         |
      | RESPONSE       | lm-both-flows       | [absent]        | [absent]        | [contains lm-both-flows-body]    |
      | REQUEST        | lm-both-flows-fence | POST            | [absent]        | [absent]                         |
      | REQUEST        | lm-both-flows-fence | [absent]        | [absent]        | {"marker":"lm-both-flows-fence"} |
      | RESPONSE       | lm-both-flows-fence | [absent]        | 200             | [absent]                         |
      | RESPONSE       | lm-both-flows-fence | [absent]        | [absent]        | [contains lm-both-flows-fence]   |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # payload is left at its default, false, so the request gets one record, from the header phase.
  # The Authorization header is logged as ***.
  Scenario: Configure request header logging
    Given I generate a unique value from "lm-req-headers" and store it as "apiName"
    And I generate a unique API version from "lm-req-headers" and store it as "apiVersion"
    And I generate a unique API context from "/lm-req-headers" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-req-headers"
    And I set header "X-Lm-Marker" to "lm-req-headers-header"
    And I set header "Authorization" to "Bearer lm-req-headers-token"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Marker" with value "lm-req-headers-header"
    And the response should contain echoed header "Authorization" with value "Bearer lm-req-headers-token"

    When I set header "X-Request-Id" to "lm-req-headers-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id           | headers.x-lm-marker   | headers.authorization | payload  | record                              |
      | REQUEST        | lm-req-headers       | lm-req-headers-header | ***                   | [absent] | [not contains lm-req-headers-token] |
      | REQUEST        | lm-req-headers-fence | lm-req-headers-header | ***                   | [absent] | [not contains lm-req-headers-token] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # On /analytics-headers the reflecting backend adds X-Allowed-Response: allowed to its reply.
  # payload is left at its default, false.
  Scenario: Configure response header logging
    Given I generate a unique value from "lm-resp-headers" and store it as "apiName"
    And I generate a unique API version from "lm-resp-headers" and store it as "apiVersion"
    And I generate a unique API context from "/lm-resp-headers" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/analytics-headers","policies":[{"name":"log-message","version":"v1","params":{"response":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-resp-headers"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers"
    Then the response status code should be 200
    And the response header "X-Allowed-Response" should be "allowed"

    When I set header "X-Request-Id" to "lm-resp-headers-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers" should be:
      | mediation-flow | request-id            | headers.:status | headers.x-allowed-response | payload  |
      | RESPONSE       | lm-resp-headers       | 200             | allowed                    | [absent] |
      | RESPONSE       | lm-resp-headers-fence | 200             | allowed                    | [absent] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # headers is left at its default, false, so the record holds the payload only.
  Scenario: Configure Log Message on the request flow with payload logging enabled
    Given I generate a unique value from "lm-req-payload" and store it as "apiName"
    And I generate a unique API version from "lm-req-payload" and store it as "apiVersion"
    And I generate a unique API context from "/lm-req-payload" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-req-payload"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-req-payload-body"}
      """
    Then the response status code should be 200
    And the JSON response field "json.marker" should be "lm-req-payload-body"

    When I set header "X-Request-Id" to "lm-req-payload-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-req-payload-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id           | http-method | payload                           | headers  |
      | REQUEST        | lm-req-payload       | POST        | {"marker":"lm-req-payload-body"}  | [absent] |
      | REQUEST        | lm-req-payload-fence | POST        | {"marker":"lm-req-payload-fence"} | [absent] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Only response is configured, so the request gets no record.
  Scenario: Configure Log Message on the response flow with payload logging enabled
    Given I generate a unique value from "lm-resp-payload" and store it as "apiName"
    And I generate a unique API version from "lm-resp-payload" and store it as "apiVersion"
    And I generate a unique API context from "/lm-resp-payload" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"response":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-resp-payload"
    And I set header "X-Lm-Marker" to "lm-resp-payload-marker"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Marker" with value "lm-resp-payload-marker"

    When I set header "X-Request-Id" to "lm-resp-payload-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id            | payload                           | headers  |
      | RESPONSE       | lm-resp-payload       | [contains lm-resp-payload-marker] | [absent] |
      | RESPONSE       | lm-resp-payload-fence | [contains lm-resp-payload-fence]  | [absent] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Configure excluded headers such as Authorization, Cookie, and X-API-Key
    Given I generate a unique value from "lm-excluded" and store it as "apiName"
    And I generate a unique API version from "lm-excluded" and store it as "apiVersion"
    And I generate a unique API context from "/lm-excluded" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true,"excludeHeaders":["Authorization","Cookie","X-API-Key"]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-excluded"
    And I set header "Authorization" to "Bearer lm-excluded-secret-token"
    And I set header "Cookie" to "session=lm-excluded-secret-cookie"
    And I set header "X-API-Key" to "lm-excluded-secret-key"
    And I set header "X-Included-Request" to "kept-value"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "Authorization" with value "Bearer lm-excluded-secret-token"
    And the response should contain echoed header "Cookie" with value "session=lm-excluded-secret-cookie"
    And the response should contain echoed header "X-Api-Key" with value "lm-excluded-secret-key"
    And the response should contain echoed header "X-Included-Request" with value "kept-value"

    When I set header "X-Request-Id" to "lm-excluded-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id        | headers.x-included-request | headers.authorization | headers.cookie | headers.x-api-key | record                            |
      | REQUEST        | lm-excluded       | kept-value                 | [absent]              | [absent]       | [absent]          | [not contains lm-excluded-secret] |
      | REQUEST        | lm-excluded-fence | kept-value                 | [absent]              | [absent]       | [absent]          | [not contains lm-excluded-secret] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # On /analytics-headers the reflecting backend adds X-Allowed-Response: allowed,
  # X-Denied-Response: denied, X-Removed-Response: removed and X-Multi-Response twice (first,
  # second). A header sent more than once is logged as an array.
  Scenario: Exclude multiple headers and verify the rest of the headers
    Given I generate a unique value from "lm-multi-excl" and store it as "apiName"
    And I generate a unique API version from "lm-multi-excl" and store it as "apiVersion"
    And I generate a unique API context from "/lm-multi-excl" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/analytics-headers","policies":[{"name":"log-message","version":"v1","params":{"response":{"headers":true,"excludeHeaders":["Content-Type","X-Denied-Response","X-Removed-Response"]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-multi-excl"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers"
    Then the response status code should be 200
    And the response header "Content-Type" should be "application/json"
    And the response header "X-Denied-Response" should be "denied"
    And the response header "X-Removed-Response" should be "removed"

    When I set header "X-Request-Id" to "lm-multi-excl-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers" should be:
      | mediation-flow | request-id          | headers.x-allowed-response | headers.x-multi-response | headers.content-type | headers.x-denied-response | headers.x-removed-response |
      | RESPONSE       | lm-multi-excl       | allowed                    | ["first","second"]       | [absent]             | [absent]                  | [absent]                   |
      | RESPONSE       | lm-multi-excl-fence | allowed                    | ["first","second"]       | [absent]             | [absent]                  | [absent]                   |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Each set-headers changes one side only: the first the request, the last the response. The
  # response flow runs the policy chain backwards, so both run before the policy in their own
  # flow, and the records show the request and response with the change.
  Scenario: Place a transformation policy before Log Message
    Given I generate a unique value from "lm-xform-first" and store it as "apiName"
    And I generate a unique API version from "lm-xform-first" and store it as "apiVersion"
    And I generate a unique API context from "/lm-xform-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/combined","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Custom-Header","value":"CustomValue"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true},"response":{"headers":true}}},{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Added-Response","value":"lm-xform-first"}]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-xform-first"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/combined"
    Then the response status code should be 200
    And the response should contain echoed header "x-custom-header" with value "CustomValue"
    And the response header "X-Added-Response" should be "lm-xform-first"

    When I set header "X-Request-Id" to "lm-xform-first-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/combined"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/combined" should be:
      | mediation-flow | request-id           | headers.x-custom-header | headers.x-added-response |
      | REQUEST        | lm-xform-first       | CustomValue             | [absent]                 |
      | RESPONSE       | lm-xform-first       | [absent]                | lm-xform-first           |
      | REQUEST        | lm-xform-first-fence | CustomValue             | [absent]                 |
      | RESPONSE       | lm-xform-first-fence | [absent]                | lm-xform-first           |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send GET, POST, PUT, PATCH, and DELETE requests where supported (GET)
    Given I generate a unique value from "lm-method-get" and store it as "apiName"
    And I generate a unique API version from "lm-method-get" and store it as "apiVersion"
    And I generate a unique API context from "/lm-method-get" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-method-get"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-method-get-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id          | http-method | headers.:method |
      | REQUEST        | lm-method-get       | GET         | GET             |
      | REQUEST        | lm-method-get-fence | GET         | GET             |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send GET, POST, PUT, PATCH, and DELETE requests where supported (POST)
    Given I generate a unique value from "lm-method-post" and store it as "apiName"
    And I generate a unique API version from "lm-method-post" and store it as "apiVersion"
    And I generate a unique API context from "/lm-method-post" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-method-post"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"lm-method-post"}
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-method-post-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"lm-method-post-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id           | http-method | payload                           |
      | REQUEST        | lm-method-post       | POST        | [absent]                          |
      | REQUEST        | lm-method-post       | POST        | {"marker":"lm-method-post"}       |
      | REQUEST        | lm-method-post-fence | POST        | [absent]                          |
      | REQUEST        | lm-method-post-fence | POST        | {"marker":"lm-method-post-fence"} |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send GET, POST, PUT, PATCH, and DELETE requests where supported (PUT)
    Given I generate a unique value from "lm-method-put" and store it as "apiName"
    And I generate a unique API version from "lm-method-put" and store it as "apiVersion"
    And I generate a unique API context from "/lm-method-put" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"PUT","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true},"response":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-method-put-first"
    And I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"lm-method-put-first-body"}
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-method-put-fence"
    And I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"lm-method-put-fence-body"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id          | http-method | payload                               |
      | REQUEST        | lm-method-put-first | PUT         | {"marker":"lm-method-put-first-body"} |
      | RESPONSE       | lm-method-put-first | PUT         | [contains lm-method-put-first-body]   |
      | REQUEST        | lm-method-put-fence | PUT         | {"marker":"lm-method-put-fence-body"} |
      | RESPONSE       | lm-method-put-fence | PUT         | [contains lm-method-put-fence-body]   |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send GET, POST, PUT, PATCH, and DELETE requests where supported (PATCH)
    Given I generate a unique value from "lm-method-patch" and store it as "apiName"
    And I generate a unique API version from "lm-method-patch" and store it as "apiVersion"
    And I generate a unique API context from "/lm-method-patch" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"PATCH","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-method-patch"
    And I send a "PATCH" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"lm-method-patch"}
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-method-patch-fence"
    And I send a "PATCH" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"lm-method-patch-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id            | http-method | payload                            |
      | REQUEST        | lm-method-patch       | PATCH       | {"marker":"lm-method-patch"}       |
      | REQUEST        | lm-method-patch-fence | PATCH       | {"marker":"lm-method-patch-fence"} |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send GET, POST, PUT, PATCH, and DELETE requests where supported (DELETE)
    Given I generate a unique value from "lm-method-delete" and store it as "apiName"
    And I generate a unique API version from "lm-method-delete" and store it as "apiVersion"
    And I generate a unique API context from "/lm-method-delete" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"DELETE","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"response":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-method-delete"
    And I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-method-delete-fence"
    And I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id             | http-method | headers.:status |
      | RESPONSE       | lm-method-delete       | DELETE      | 200             |
      | RESPONSE       | lm-method-delete-fence | DELETE      | 200             |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # A 512 KiB request body is logged in full as one record. The echoed reply has no Content-Length,
  # so it reaches the policy in chunks and the policy logs one RESPONSE record per chunk. Their
  # number depends on timing, so the check joins them, and the joined payload must equal the reply
  # the client received.
  Scenario: Log very large request or response payloads (within the limit)
    Given I generate a unique value from "lm-large" and store it as "apiName"
    And I generate a unique API version from "lm-large" and store it as "apiVersion"
    And I generate a unique API context from "/lm-large" and store it as "apiContext"
    And I generate a value of 512 KiB of "a" and store it as "halfMiB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true},"response":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-large"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      ${CTX:halfMiB}
      """
    Then the response status code should be 200
    And the JSON response field "data" should contain "${CTX:halfMiB}"

    When I store the response body as "largeReply"
    And I set header "X-Request-Id" to "lm-large-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-large-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be, with response chunks joined:
      | mediation-flow | request-id     | payload                     |
      | REQUEST        | lm-large       | [length 524288]             |
      | RESPONSE       | lm-large       | ${CTX:largeReply}           |
      | REQUEST        | lm-large-fence | {"marker":"lm-large-fence"} |
      | RESPONSE       | lm-large-fence | [contains lm-large-fence]   |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Known issue: https://github.com/wso2/api-platform/issues/4061
  # Request payload logging makes the gateway buffer the body, and a 2 MiB body is over its 1 MiB
  # buffer limit, so it should be refused with 413. The next request's records are picked by
  # request id. The 413 is checked on Gateways later than 1.2.0 only.
  @known-issue
  Scenario: Log very large request or response payloads (over the limit)
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "lm-large-over" and store it as "apiName"
    And I generate a unique API version from "lm-large-over" and store it as "apiVersion"
    And I generate a unique API context from "/lm-large-over" and store it as "apiContext"
    And I generate a value of 1024 KiB of "b" and store it as "oneMiB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true},"response":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-large-over"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      ${CTX:oneMiB}${CTX:oneMiB}
      """
    Then the response status code should be 413

    When I set header "X-Request-Id" to "lm-large-after"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-large-after"}
      """
    Then the response status code should be 200
    And the JSON response field "json.marker" should be "lm-large-after"
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" with request id "lm-large-after" should be:
      | mediation-flow | request-id     | payload                     |
      | REQUEST        | lm-large-after | {"marker":"lm-large-after"} |
      | RESPONSE       | lm-large-after | [contains lm-large-after]   |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The API waits on /health, which has no policy.
  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails. The
  # records show the policy ran on the request; a GET has no body, so its payload records are empty.
  Scenario: log-message leaves a logged request and response unchanged
    Given I generate a unique value from "compat-logmsg" and store it as "apiName"
    And I generate a unique API version from "compat-logmsg" and store it as "apiVersion"
    And I generate a unique API context from "/compat-logmsg" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/json","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true},"response":{"payload":true,"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Request-Id" to "lm-compat"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/json"
    Then the response status code should be 200
    And the response should match the expected error response "log-message-request-response-flow"

    When I set header "X-Request-Id" to "lm-compat-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/json"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/json" should be:
      | mediation-flow | request-id      | payload                      |
      | REQUEST        | lm-compat       | [absent]                     |
      | REQUEST        | lm-compat       | [absent]                     |
      | RESPONSE       | lm-compat       | [absent]                     |
      | RESPONSE       | lm-compat       | [contains Sample Slide Show] |
      | REQUEST        | lm-compat-fence | [absent]                     |
      | REQUEST        | lm-compat-fence | [absent]                     |
      | RESPONSE       | lm-compat-fence | [absent]                     |
      | RESPONSE       | lm-compat-fence | [contains Sample Slide Show] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
