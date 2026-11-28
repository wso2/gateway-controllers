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
Feature: Log message policy payloads
  As an API operator
  I want any request payload to be logged safely and in full
  So that the logs stay readable and cannot be forged

  # Request payload logging: payload types, empty messages and forged log text. The backend echoes
  # the request as JSON. Records reach the log late, but in the order they are written. So each
  # check ends with a fence: a later request whose records come last. Once they appear, the records
  # before them are final.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The record's payload is compared after the record is decoded, so characters the log escapes
  # (<, >, &, quotes) are compared as sent.
  Scenario Outline: Send empty, JSON, XML, text, Unicode, and binary/non-text payloads where applicable (<case>)
    Given I generate a unique value from "lm-content" and store it as "apiName"
    And I generate a unique API version from "lm-content" and store it as "apiVersion"
    And I generate a unique API context from "/lm-content" and store it as "apiContext"
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

    When I set header "X-Request-Id" to "lm-content"
    And I set header "Content-Type" to "<type>"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <body>
      """
    Then the response status code should be 200
    And the JSON response field "data" should be:
      """
      <body>
      """

    When I set header "X-Request-Id" to "lm-content-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      lm-content-fence
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id       | payload          |
      | REQUEST        | lm-content       | <body>           |
      | REQUEST        | lm-content-fence | lm-content-fence |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case    | type                      | body                                                            |
      | JSON    | application/json          | {"marker":"lm-content-json","n":[1,2]}                          |
      | XML     | application/xml           | <?xml version="1.0"?><note id="lm-content-xml">a &amp; b</note> |
      | text    | text/plain                | lm-content-text: plain words, "quoted"                          |
      | Unicode | text/plain; charset=utf-8 | lm-content-unicode héllo ✓ 日本 😀                                 |

  # The echo backend answers /status/204 with no body. An empty message still gets a record, without
  # a payload field. The fence request on /orders also closes the /status/204 records.
  Scenario: Send an empty request or receive an empty response
    Given I generate a unique value from "lm-empty" and store it as "apiName"
    And I generate a unique API version from "lm-empty" and store it as "apiVersion"
    And I generate a unique API context from "/lm-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true},"response":{"payload":true}}}]},{"method":"GET","path":"/status/204","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true},"response":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-empty-req"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-empty-resp"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/status/204"
    Then the response status code should be 204
    And the response should be empty

    When I set header "X-Request-Id" to "lm-empty-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-empty-fence"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id     | payload                     |
      | REQUEST        | lm-empty-req   | [absent]                    |
      | RESPONSE       | lm-empty-req   | [any]                       |
      | REQUEST        | lm-empty-fence | {"marker":"lm-empty-fence"} |
      | RESPONSE       | lm-empty-fence | [contains lm-empty-fence]   |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/status/204" should be:
      | mediation-flow | request-id    | payload  |
      | REQUEST        | lm-empty-resp | [absent] |
      | RESPONSE       | lm-empty-resp | [absent] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The body's second line copies a whole log line of the policy, for this operation's path. If the
  # line breaks split the record, the log would hold a second record for the path, with request id
  # lm-forged-line.
  Scenario: Send malicious content containing CRLF/newlines or forged log-like text
    Given I generate a unique value from "lm-forged" and store it as "apiName"
    And I generate a unique API version from "lm-forged" and store it as "apiVersion"
    And I generate a unique API context from "/lm-forged" and store it as "apiContext"
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

    When I set header "X-Request-Id" to "lm-forged-real"
    And I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      lm-forged start
      [pol] time=2026-11-27T00:00:00.000Z level=INFO msg="{\"mediation-flow\":\"REQUEST\",\"request-id\":\"lm-forged-line\",\"http-method\":\"POST\",\"resource-path\":\"${CTX:apiContext}/${CTX:apiVersion}/orders\"}"
      lm-forged end
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-forged-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      lm-forged-fence
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id      | payload                    | payload                   | payload                  |
      | REQUEST        | lm-forged-real  | [contains lm-forged start] | [contains lm-forged-line] | [contains lm-forged end] |
      | REQUEST        | lm-forged-fence | lm-forged-fence            | [any]                     | [any]                    |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The body is the bytes 00 01 FF FE, then lm-content-bin, then 80, sent as application/octet-stream.
  # The log is JSON text, so the policy writes each byte that is not valid UTF-8 as the
  # replacement character U+FFFD. The echo writes the body it received the same way, so both
  # show FF, FE and 80 in place: content the policy cannot read as text is still logged and passed
  # on. The logged payload equals the body the echo received, 00 and 01 included: 19 characters,
  # the 17 the contains check names after the two control characters. This also covers content
  # that cannot be parsed.
  Scenario: Send empty, JSON, XML, text, Unicode, and binary/non-text payloads where applicable (binary)
    Given I generate a unique value from "lm-content-bin" and store it as "apiName"
    And I generate a unique API version from "lm-content-bin" and store it as "apiVersion"
    And I generate a unique API context from "/lm-content-bin" and store it as "apiContext"
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

    When I set header "X-Request-Id" to "lm-content-bin"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with the base64 body "AAH//mxtLWNvbnRlbnQtYmlugA=="
    Then the response status code should be 200
    And the JSON response field "data" should contain "��lm-content-bin�"

    When I store the JSON response field "data" as "binData"
    And I set header "X-Request-Id" to "lm-content-bin-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      lm-content-bin-fence
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id           | payload              | payload                      | payload     |
      | REQUEST        | lm-content-bin       | ${CTX:binData}       | [contains ��lm-content-bin�] | [length 19] |
      | REQUEST        | lm-content-bin-fence | lm-content-bin-fence | [any]                        | [any]       |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
