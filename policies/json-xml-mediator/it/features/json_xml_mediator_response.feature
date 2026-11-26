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
Feature: Json xml mediator policy response conversion
  As an API developer
  I want the json-xml-mediator policy to convert the backend's response back to the client's format
  So that a change to it is caught before it reaches a release

  # Response conversion: XML and JSON answers converted back, the backend's status kept, repeated
  # elements, empty answers, and malformed or non-matching answers. Each API's upstream is the
  # capture service under the API's name, and each scenario scripts the capture service's answer
  # (status, Content-Type and body) for the path it calls.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: Configure JSON→XML request mediation and return XML from the backend
    Given I generate a unique value from "jxm-xml-reply" and store it as "apiName"
    And I generate a unique API version from "jxm-xml-reply" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-xml-reply" and store it as "apiContext"
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
      {"status":201,"contentType":"application/xml","body":"<orderResponse><status>created</status><reference>A-12345</reference></orderResponse>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 201
    And the response header "Content-Type" should be "application/json"
    And the response body should be:
      """
      {"orderResponse":{"reference":"A-12345","status":"created"}}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The backend answers with a ZIP code and a version number whose zeros matter. Each must reach the
  # client unchanged, as text.
  @known-issue
  Scenario: Configure JSON→XML request mediation and return XML from the backend (numeric text)
    Given I generate a unique value from "jxm-xml-reply-num" and store it as "apiName"
    And I generate a unique API version from "jxm-xml-reply-num" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-xml-reply-num" and store it as "apiContext"
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
      {"contentType":"application/xml","body":"<order><zip>02134</zip><version>1.10</version></order>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200
    # The policy reads text that looks like a number as a number, so it wrongly returns
    # {"order":{"version":1.1,"zip":2134}}.
    And the response body should be:
      """
      {"order":{"version":"1.10","zip":"02134"}}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The policy writes a JSON object as children of a <root> element.
  Scenario: Configure XML→JSON request mediation and return JSON from the backend
    Given I generate a unique value from "jxm-json-reply" and store it as "apiName"
    And I generate a unique API version from "jxm-json-reply" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-json-reply" and store it as "apiContext"
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
      {"contentType":"application/json","body":"{\"user\":{\"id\":\"u-1\",\"status\":\"active\"}}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      <user><name>Jane</name></user>
      """
    Then the response status code should be 200
    And the response header "Content-Type" should be "application/xml"
    And the response body should be XML equivalent to:
      """
      <root><user><id>u-1</id><status>active</status></user></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The backend is scripted with the XML the request should convert to, so the client gets its
  # own data back under the root element. The values are words, two-item arrays, small integers
  # and a boolean, which the conversion keeps both ways.
  Scenario: Validate request and response conversion together in one API call
    Given I generate a unique value from "jxm-round-trip" and store it as "apiName"
    And I generate a unique API version from "jxm-round-trip" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-round-trip" and store it as "apiContext"
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
      {"contentType":"application/xml","body":"<root><customer>John Doe</customer><express>true</express><items><name>Widget</name><quantity>2</quantity></items><items><name>Gadget</name><quantity>1</quantity></items></root>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"customer":"John Doe","express":true,"items":[{"name":"Widget","quantity":2},{"name":"Gadget","quantity":1}]}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"root":{"customer":"John Doe","express":true,"items":[{"name":"Widget","quantity":2},{"name":"Gadget","quantity":1}]}}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><customer>John Doe</customer><express>true</express><items><name>Widget</name><quantity>2</quantity></items><items><name>Gadget</name><quantity>1</quantity></items></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # /catalog answers three <product> elements and /single answers one. Only repeated elements
  # become an array.
  Scenario: Return repeated XML elements from the backend
    Given I generate a unique value from "jxm-repeated" and store it as "apiName"
    And I generate a unique API version from "jxm-repeated" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-repeated" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/catalog","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"GET","path":"/single","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/catalog" with body:
      """
      {"contentType":"application/xml","body":"<catalog><product>Widget</product><product>Gadget</product><product>Gizmo</product></catalog>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/single" with body:
      """
      {"contentType":"application/xml","body":"<catalog><product>Widget</product></catalog>"}
      """
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/catalog"
    Then the response status code should be 200
    And the response body should be:
      """
      {"catalog":{"product":["Widget","Gadget","Gizmo"]}}
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/single"
    Then the response status code should be 200
    And the response body should be:
      """
      {"catalog":{"product":"Widget"}}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Both paths answer text/plain, which is not the XML the policy expects. /empty answers with no
  # body and passes untouched; /text answers with a body and is rejected, which shows the
  # response check is active on this API.
  Scenario: Backend returns an empty response body
    Given I generate a unique value from "jxm-empty-reply" and store it as "apiName"
    And I generate a unique API version from "jxm-empty-reply" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-empty-reply" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/empty","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"GET","path":"/text","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/empty" with body:
      """
      {"contentType":"text/plain"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/text" with body:
      """
      {"contentType":"text/plain","body":"not xml"}
      """
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/empty"
    Then the response status code should be 200
    And the response body should be empty

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/text"
    Then the response status code should be 500
    And the JSON response field "message" should be "Content-Type must be application/xml or text/xml in response for upstream payload format xml"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The backend answers 200 with XML whose closing tag is misspelled.
  Scenario: Backend returns malformed XML when XML→JSON response mediation is expected
    Given I generate a unique value from "jxm-bad-xml-reply" and store it as "apiName"
    And I generate a unique API version from "jxm-bad-xml-reply" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-bad-xml-reply" and store it as "apiContext"
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
      {"contentType":"application/xml","body":"<order><status>jxm-shipped</status></ordr>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 500
    And the JSON response field "error" should be "Internal Server Error"
    And the JSON response field "message" should be "failed to convert XML to JSON format: failed to parse XML: XML syntax error on line 1: element <order> closed by </ordr>"
    And the response body should not contain "jxm-shipped"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The backend answers 404 with an HTML page instead of XML.
  Scenario: Backend returns malformed XML when XML→JSON response mediation is expected (not an XML content type)
    Given I generate a unique value from "jxm-html-reply" and store it as "apiName"
    And I generate a unique API version from "jxm-html-reply" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-html-reply" and store it as "apiContext"
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
      {"status":404,"contentType":"text/html","body":"<html><body>jxm-not-found</body></html>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "Content-Type must be application/xml or text/xml in response for upstream payload format xml"
    And the response body should not contain "jxm-not-found"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The backend answers 200 with JSON that has a trailing comma and no closing brace.
  Scenario: Backend returns malformed JSON when JSON→XML response mediation is expected
    Given I generate a unique value from "jxm-bad-json-reply" and store it as "apiName"
    And I generate a unique API version from "jxm-bad-json-reply" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-bad-json-reply" and store it as "apiContext"
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
      {"contentType":"application/json","body":"{\"user\": {\"id\": \"jxm-u1\", }"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      <user><name>Jane</name></user>
      """
    Then the response status code should be 500
    And the JSON response field "error" should be "Internal Server Error"
    And the JSON response field "message" should be "failed to convert JSON to XML format: invalid character '}' looking for beginning of object key string"
    And the response body should not contain "jxm-u1"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
