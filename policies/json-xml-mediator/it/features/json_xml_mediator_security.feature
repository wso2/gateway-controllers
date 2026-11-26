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

@json-xml-mediator
Feature: Json xml mediator policy limits and hostile input
  As an API developer
  I want the json-xml-mediator policy to refuse oversized, entity-laden and malformed input safely
  So that no request can exhaust the gateway or leak data through the conversion

  # Large and deeply nested payloads, external entities and DTDs, entity expansion, keys that look
  # like XML notation, and what errors and logs carry. The policy refuses documents deeper than 256
  # levels or with more than 100000 elements. Each API's upstream is the capture service under its
  # name, which records what reached it; a lookup answers 204 when nothing did.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The note is 512 KiB of "x". The deep document is 1024 nested arrays, [[[…1…]]], built from
  # 1 KiB of "[" and 1 KiB of "]". The last request shows the gateway still serves afterwards.
  Scenario: Send large or deeply nested JSON/XML payloads
    Given I generate a unique value from "jxm-large" and store it as "apiName"
    And I generate a unique API version from "jxm-large" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-large" and store it as "apiContext"
    And I generate a value of 512 KiB of "x" and store it as "big"
    And I generate a value of 1 KiB of "[" and store it as "open"
    And I generate a value of 1 KiB of "]" and store it as "close"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/large","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/deep","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/large" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/large" with body:
      """
      {"note":"${CTX:big}"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/large" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><note>${CTX:big}</note></root>
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/deep" with body:
      """
      ${CTX:open}1${CTX:close}
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "failed to convert JSON to XML format: payload is too complex to convert: exceeds the maximum nesting depth (256) or element count (100000)"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/deep" until status 204
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The first two documents declare an external entity and use it: one names a local file, the
  # other a URL on the capture service. The policy resolves neither, so both are refused, nothing
  # reaches the backend and nothing fetches the URL. The third declares the entity but does not
  # use it; the declaration is ignored and the document converts.
  Scenario: Send XML containing external entity or DTD-based payloads
    Given I generate a unique value from "jxm-xxe" and store it as "apiName"
    And I generate a unique API version from "jxm-xxe" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-xxe" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/json","body":"{\"status\":\"received\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><order>&xxe;</order>
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "failed to convert XML to JSON format: failed to parse XML: XML syntax error on line 1: invalid character entity &xxe;"
    And the response body should not contain "root:"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <!DOCTYPE order [<!ENTITY xxe SYSTEM "${CTX:captureUpstream}/${CTX:apiName}/xxe-fetch">]><order>&xxe;</order>
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "failed to convert XML to JSON format: failed to parse XML: XML syntax error on line 1: invalid character entity &xxe;"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/xxe-fetch" until status 204
    And I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><order><sku>W-1</sku></order>
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be:
      """
      {"order":{"sku":"W-1"}}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # lol2 is ten references to lol. The policy expands neither, so the document is refused. The
  # last request shows the gateway still serves afterwards.
  Scenario: Send malicious XML/JSON content containing entity expansion, extreme nesting, oversized arrays, or type-confusion patterns (entity expansion)
    Given I generate a unique value from "jxm-entities" and store it as "apiName"
    And I generate a unique API version from "jxm-entities" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-entities" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/json","body":"{\"status\":\"received\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "failed to convert XML to JSON format: failed to parse XML: XML syntax error on line 1: invalid character entity &lol2;"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <order><sku>W-1</sku></order>
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The document is 1024 nested <a> elements, from 3 KiB of "<a>" and 4 KiB of "</a>". The last
  # request shows the gateway still serves afterwards.
  Scenario: Send malicious XML/JSON content containing entity expansion, extreme nesting, oversized arrays, or type-confusion patterns (extreme nesting)
    Given I generate a unique value from "jxm-nesting" and store it as "apiName"
    And I generate a unique API version from "jxm-nesting" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-nesting" and store it as "apiContext"
    And I generate a value of 3 KiB of "<a>" and store it as "opens"
    And I generate a value of 4 KiB of "</a>" and store it as "closes"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/json","body":"{\"status\":\"received\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      ${CTX:opens}1${CTX:closes}
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "failed to convert XML to JSON format: payload is too complex to convert: exceeds the maximum nesting depth (256) or element count (100000)"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <order><sku>W-1</sku></order>
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The document is <r> holding 102400 <a/> elements, from 400 KiB of "<a/>". The last request
  # shows the gateway still serves afterwards.
  Scenario: Send malicious XML/JSON content containing entity expansion, extreme nesting, oversized arrays, or type-confusion patterns (oversized array)
    Given I generate a unique value from "jxm-big-array" and store it as "apiName"
    And I generate a unique API version from "jxm-big-array" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-big-array" and store it as "apiContext"
    And I generate a value of 400 KiB of "<a/>" and store it as "items"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/json","body":"{\"status\":\"received\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <r>${CTX:items}</r>
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "failed to convert XML to JSON format: payload is too complex to convert: exceeds the maximum nesting depth (256) or element count (100000)"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <order><sku>W-1</sku></order>
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Keys that look like the XML-to-JSON notation (@ for attributes, # for text) or are not XML
  # names become element names made safe with "_", and keep the original key in originalKey.
  Scenario: Send malicious XML/JSON content containing entity expansion, extreme nesting, oversized arrays, or type-confusion patterns (type confusion)
    Given I generate a unique value from "jxm-key-names" and store it as "apiName"
    And I generate a unique API version from "jxm-key-names" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-key-names" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"@id":"A-1","#text":"note","1st":"x","a b":"y"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><_id originalKey="@id">A-1</_id><_text originalKey="#text">note</_text><_1st originalKey="1st">x</_1st><a_b originalKey="a b">y</a_b></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The token values are markers. /orders gets malformed JSON holding one; /reply's backend answers
  # malformed XML holding the other. Neither error body, nor the runtime's log, may carry them, and
  # an error body is exactly the two fields error and message. /valid shows a converted payload
  # carries the client's fields and nothing else.
  Scenario: Inspect transformed payloads, logs, and error responses for sensitive data leakage
    Given I generate a unique value from "jxm-leak-check" and store it as "apiName"
    And I generate a unique API version from "jxm-leak-check" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-leak-check" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/reply","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/valid","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/reply" with body:
      """
      {"contentType":"application/xml","body":"<reply><token>jxm-upstream-token</token></repl>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/valid" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"token": "jxm-client-token", "name": }
      """
    Then the response status code should be 500
    And the response body should be:
      """
      {"error":"Internal Server Error","message":"failed to convert JSON to XML format: invalid character '}' looking for beginning of value"}
      """
    And the response body should not contain "jxm-client-token"
    And the response body should not contain ".go:"
    And the response body should not contain "goroutine"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 500
    And the response body should not contain "jxm-upstream-token"
    And the response body should not contain ".go:"
    And the response body should not contain "goroutine"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/valid" with body:
      """
      {"token":"jxm-valid-token"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/valid" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><token>jxm-valid-token</token></root>
      """
    And the "gateway-runtime" service logs should not contain "jxm-client-token"
    And the "gateway-runtime" service logs should not contain "jxm-upstream-token"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
