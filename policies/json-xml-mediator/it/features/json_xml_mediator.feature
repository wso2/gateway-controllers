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
