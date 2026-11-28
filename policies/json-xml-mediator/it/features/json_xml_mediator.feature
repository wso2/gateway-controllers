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
Feature: Json xml mediator policy
  As an API developer
  I want the json-xml-mediator policy to behave as documented
  So that a change to it is caught before it reaches a release

  # Request conversion: JSON to XML and XML to JSON, data types, arrays, empty and malformed
  # bodies, Content-Type and Content-Length. Each API's upstream is the capture service under the
  # API's name, which records what reached it; a lookup answers 204 when nothing did. A scenario
  # scripts the capture service's answer for a path when the policy must convert that answer back.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: json-xml-mediator rejects a request whose content type does not match the downstream format
    Given I generate a unique value from "compat-jxm-ctype" and store it as "apiName"
    And I generate a unique API version from "compat-jxm-ctype" and store it as "apiVersion"
    And I generate a unique API context from "/compat-jxm-ctype" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/convert","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/convert" with body:
      """
      plain text, not JSON
      """
    Then the response status code should be 500
    And the response should match the expected error response "json-xml-mediator-request-content-type"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/convert" until status 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The order is the policy doc's example. Each item of an array becomes one element named after
  # the array's key, and the keys of an object come out in any order, so the XML is compared
  # without regard to the order of differently named elements.
  Scenario: Configure downstream json and upstream xml, then send a valid JSON request
    Given I generate a unique value from "jxm-json-to-xml" and store it as "apiName"
    And I generate a unique API version from "jxm-json-to-xml" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-json-to-xml" and store it as "apiContext"
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
      {"orderId":"12345","customer":"John Doe","items":[{"name":"Widget","quantity":2},{"name":"Gadget","quantity":1}]}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"ack":"received"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><orderId>12345</orderId><customer>John Doe</customer><items><name>Widget</name><quantity>2</quantity></items><items><name>Gadget</name><quantity>1</quantity></items></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The user is the policy doc's example, with its XML declaration. The converted JSON is wrapped in
  # the root element's name, and its keys are sorted.
  Scenario: Configure downstream xml and upstream json, then send a valid XML request
    Given I generate a unique value from "jxm-xml-to-json" and store it as "apiName"
    And I generate a unique API version from "jxm-xml-to-json" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-xml-to-json" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/users","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/users" with body:
      """
      {"contentType":"application/json","body":"{\"status\":\"created\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      <?xml version="1.0" encoding="UTF-8"?><user><name>Jane Smith</name><email>jane@example.com</email><role>admin</role></user>
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/users" until status 200
    Then the JSON response field "body" should be:
      """
      {"user":{"email":"jane@example.com","name":"Jane Smith","role":"admin"}}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # null becomes an empty element and each array item an element named after the array's key.
  Scenario: Send JSON containing strings, numbers, booleans, nulls, nested objects, and arrays (small numbers)
    Given I generate a unique value from "jxm-types" and store it as "apiName"
    And I generate a unique API version from "jxm-types" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-types" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/products","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/products" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/products" with body:
      """
      {"name":"Widget","price":19.5,"quantity":2,"inStock":true,"discontinued":false,"note":null,"dimensions":{"width":10,"unit":"cm"},"tags":["new","sale"]}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/products" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><name>Widget</name><price>19.5</price><quantity>2</quantity><inStock>true</inStock><discontinued>false</discontinued><note></note><dimensions><width>10</width><unit>cm</unit></dimensions><tags>new</tags><tags>sale</tags></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # A number keeps the form it has in the JSON, as the policy doc's "all JSON data types" promises.
  @known-issue
  Scenario: Send JSON containing strings, numbers, booleans, nulls, nested objects, and arrays (large and small numbers)
    Given I generate a unique value from "jxm-types-num" and store it as "apiName"
    And I generate a unique API version from "jxm-types-num" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-types-num" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/stats","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/stats" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/stats" with body:
      """
      {"population":1234567,"ratio":0.00001}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/stats" until status 200
    # The policy writes numbers in exponent form, so it wrongly sends 1.234567e+06 and 1e-05.
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><population>1234567</population><ratio>0.00001</ratio></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Attributes become "@" keys, text beside attributes "#text", and repeated elements an array.
  # The text values are words, since the policy types digits and true or false.
  Scenario: Send XML containing nested elements, attributes, text values, and repeated elements
    Given I generate a unique value from "jxm-xml-shapes" and store it as "apiName"
    And I generate a unique API version from "jxm-xml-shapes" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-xml-shapes" and store it as "apiContext"
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
      <order id="A-7" status="new"><customer><name>Jane Smith</name></customer><item sku="W">Widget</item><item sku="G">Gadget</item><note>fragile</note></order>
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be:
      """
      {"order":{"@id":"A-7","@status":"new","customer":{"name":"Jane Smith"},"item":[{"#text":"Widget","@sku":"W"},{"#text":"Gadget","@sku":"G"}],"note":"fragile"}}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Each object in an array becomes an element named after the array's key, in array order. A
  # top-level array has no key, so its items become <root> elements inside <root>.
  Scenario: Send JSON arrays containing multiple objects
    Given I generate a unique value from "jxm-json-array" and store it as "apiName"
    And I generate a unique API version from "jxm-json-array" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-json-array" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/items","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/batch","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/items" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/batch" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"items":[{"name":"Widget","sku":"W-1"},{"name":"Gadget","sku":"G-2"},{"name":"Gizmo","sku":"Z-3"}]}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/items" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><items><name>Widget</name><sku>W-1</sku></items><items><name>Gadget</name><sku>G-2</sku></items><items><name>Gizmo</name><sku>Z-3</sku></items></root>
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/batch" with body:
      """
      [{"sku":"W-1"},{"sku":"G-2"}]
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/batch" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><root><sku>W-1</sku></root><root><sku>G-2</sku></root></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The first request has no body and a Content-Type the policy would reject, so the 200 shows
  # the policy left it alone. The second request sends a body with the same Content-Type, and its
  # rejection shows the policy is active on this operation.
  Scenario: Send an empty request body
    Given I generate a unique value from "jxm-empty-body" and store it as "apiName"
    And I generate a unique API version from "jxm-empty-body" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-empty-body" and store it as "apiContext"
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

    When I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response body should be:
      """
      {"ack":"received"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should not exist
    And the JSON response field "headers.Content-Type[0]" should be "text/plain"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      not empty
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "Content-Type must be application/json for downstream payload format json"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Verify Content-Type after JSON→XML conversion
    Given I generate a unique value from "jxm-ctype-xml" and store it as "apiName"
    And I generate a unique API version from "jxm-ctype-xml" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-ctype-xml" and store it as "apiContext"
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

    When I set header "Content-Type" to "application/json; charset=utf-8"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should be "application/json"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "headers.Content-Type[0]" should be "application/xml"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Verify Content-Type after XML→JSON conversion
    Given I generate a unique value from "jxm-ctype-json" and store it as "apiName"
    And I generate a unique API version from "jxm-ctype-json" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-ctype-json" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/users","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/users" with body:
      """
      {"contentType":"application/json","body":"{\"status\":\"created\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "text/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      <user><name>Jane</name></user>
      """
    Then the response status code should be 200
    And the response header "Content-Type" should be "application/xml"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/users" until status 200
    Then the JSON response field "headers.Content-Type[0]" should be "application/json"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The client sends 33 bytes and gets 29. The upstream receives the 50-byte
  # <root><sku>W-1</sku><name>Widget Pro</name></root> (the same length in either key order),
  # and its 36-byte <ack><status>received</status></ack> reaches the client as the 29-byte
  # {"ack":{"status":"received"}}.
  Scenario: Verify Content-Length before and after transformation
    Given I generate a unique value from "jxm-length" and store it as "apiName"
    And I generate a unique API version from "jxm-length" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-length" and store it as "apiContext"
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
      {"contentType":"application/xml","body":"<ack><status>received</status></ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1","name":"Widget Pro"}
      """
    Then the response status code should be 200
    And the response header "Content-Length" should be "29"
    And the response body should be:
      """
      {"ack":{"status":"received"}}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "headers.Content-Length[0]" should be "50"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send malformed JSON to a JSON→XML flow
    Given I generate a unique value from "jxm-bad-json" and store it as "apiName"
    And I generate a unique API version from "jxm-bad-json" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-bad-json" and store it as "apiContext"
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

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku": "W-1", "name": }
      """
    Then the response status code should be 500
    And the JSON response field "error" should be "Internal Server Error"
    And the JSON response field "message" should be "failed to convert JSON to XML format: invalid character '}' looking for beginning of value"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Send malformed XML to an XML→JSON flow
    Given I generate a unique value from "jxm-bad-xml" and store it as "apiName"
    And I generate a unique API version from "jxm-bad-xml" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-bad-xml" and store it as "apiContext"
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

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <order><sku>W-1</sku></orders>
      """
    Then the response status code should be 500
    And the JSON response field "error" should be "Internal Server Error"
    And the JSON response field "message" should be "failed to convert XML to JSON format: failed to parse XML: XML syntax error on line 1: element <order> closed by </orders>"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Two root elements make the document malformed, so none of it may reach the backend.
  @known-issue
  Scenario: Send malformed XML to an XML→JSON flow (content after the root element)
    Given I generate a unique value from "jxm-bad-xml-tail" and store it as "apiName"
    And I generate a unique API version from "jxm-bad-xml-tail" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-bad-xml-tail" and store it as "apiContext"
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

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <order><sku>W-1</sku></order><order><sku>G-2</sku></order>
      """
    # The policy reads only the first element and ignores the rest, so it wrongly answers 200 and
    # forwards {"order":{"sku":"W-1"}}.
    Then the response status code should be 500
    And the JSON response field "message" should contain "failed to convert XML to JSON format"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
