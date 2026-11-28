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
Feature: Json xml mediator policy across gateway restarts
  As an API developer
  I want the json-xml-mediator policy to keep converting after the gateway restarts
  So that a restart never changes how an API's payloads are converted

  # Restarting the gateway runtime and the gateway controller, so these scenarios run on their own.
  # Gateway replicas are not covered: the test environment's replicas are independent gateways
  # that share no state. The upstream is the capture service under the API's name, which records
  # what reached it.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # Each request sends a different item, so each capture lookup shows that request's conversion.
  # After each restart the wait sends the order until it succeeds, and that first success is checked:
  # its answer is the backend's <ack>received</ack> converted to JSON.
  Scenario: Restart or scale gateway replicas while the mediator is configured
    Given I generate a unique value from "jxm-restart" and store it as "apiName"
    And I generate a unique API version from "jxm-restart" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-restart" and store it as "apiContext"
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
      {"sku":"W-1"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>W-1</sku></root>
      """

    When I restart the "gateway-runtime" service
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"sku":"G-2"}
      """
    Then the response body should be:
      """
      {"ack":"received"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>G-2</sku></root>
      """

    When I restart the "gateway-controller" service
    And I wait for the gateway controller health endpoint
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"sku":"Z-3"}
      """
    Then the response body should be:
      """
      {"ack":"received"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>Z-3</sku></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
