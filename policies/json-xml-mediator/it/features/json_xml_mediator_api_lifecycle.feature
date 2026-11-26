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
Feature: Json xml mediator policy attachment and API lifecycle
  As an API developer
  I want the json-xml-mediator policy to work at API and operation level, beside other policies and across updates
  So that a change to it is caught before it reaches a release

  # The policy at API level and per operation, beside authentication, rate limiting, request
  # rewriting and policies that change the request first, and across API updates. Each API's
  # upstream is the capture service under its name, which records what reached it (204 when
  # nothing did) and answers with what the scenario scripted for the path.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The policy is attached at API level, so it also applies to /ready, which is scripted to answer
  # XML like the order routes. The GET has no body to convert, but its answer is converted.
  Scenario: Apply the mediator at API level and invoke multiple operations
    Given I generate a unique value from "jxm-api-level" and store it as "apiName"
    And I generate a unique API version from "jxm-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-api-level" and store it as "apiContext"
    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/ready" with body:
      """
      {"contentType":"application/xml","body":"<order><status>stored</status></order>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/xml","body":"<order><status>stored</status></order>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders/A-1" with body:
      """
      {"contentType":"application/xml","body":"<order><status>stored</status></order>"}
      """
    Then the response status code should be 200

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.policies          | [{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}] |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders"},{"method":"PUT","path":"/orders/{id}"},{"method":"GET","path":"/orders/{id}"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"order":{"status":"stored"}}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>W-1</sku></root>
      """

    When I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/A-1" with body:
      """
      {"sku":"G-2"}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"order":{"status":"stored"}}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders/A-1" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>G-2</sku></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/A-1"
    Then the response status code should be 200
    And the response body should be:
      """
      {"order":{"status":"stored"}}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The operations follow the policy doc's operation-level example: one converts JSON to XML, one
  # XML to JSON, and one has no policy.
  Scenario: Apply different mediation directions to different operations
    Given I generate a unique value from "jxm-per-operation" and store it as "apiName"
    And I generate a unique API version from "jxm-per-operation" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-per-operation" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/xml-endpoint","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/json-endpoint","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]},{"method":"POST","path":"/passthrough"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/xml-endpoint" with body:
      """
      {"contentType":"application/xml","body":"<ack>xml</ack>"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/json-endpoint" with body:
      """
      {"contentType":"application/json","body":"{\"ack\":\"json\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/xml-endpoint" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"ack":"xml"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/xml-endpoint" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>W-1</sku></root>
      """

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/json-endpoint" with body:
      """
      <item><sku>G-2</sku></item>
      """
    Then the response status code should be 200
    And the response body should be XML equivalent to:
      """
      <root><ack>json</ack></root>
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/json-endpoint" until status 200
    Then the JSON response field "body" should be:
      """
      {"item":{"sku":"G-2"}}
      """

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/passthrough" with body:
      """
      {"sku":"P-3"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/passthrough" until status 200
    Then the JSON response field "body" should be:
      """
      {"sku":"P-3"}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # basic-auth runs before the mediator. The credential is jxm-user:jxm-pass. The first
  # request carries none and malformed JSON: a 401, not the mediator's 500, shows authentication
  # refuses it before the mediator reads the body, and it is never forwarded.
  Scenario: Combine JSON/XML Mediator with authentication, rate limiting, or request rewrite policies (authentication)
    Given I generate a unique value from "jxm-auth" and store it as "apiName"
    And I generate a unique API version from "jxm-auth" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"basic-auth","version":"v1","params":{"username":"jxm-user","password":"jxm-pass"}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/xml","body":"<ack>ok</ack>"}
      """
    Then the response status code should be 200

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":
      """
    Then the response status code should be 401

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204
    And I set header "Authorization" to "Basic anhtLXVzZXI6anhtLXBhc3M="
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

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # basic-ratelimit allows two requests an hour on /orders, before the mediator; /ready has no
  # limit, so waiting for the route spends none of it. The third request carries malformed JSON: a
  # 429, not the mediator's 500, shows the limit refuses it first. The capture service keeps the
  # last request per path, so after the third request it still holds the second.
  Scenario: Combine JSON/XML Mediator with authentication, rate limiting, or request rewrite policies (rate limiting)
    Given I generate a unique value from "jxm-ratelimit" and store it as "apiName"
    And I generate a unique API version from "jxm-ratelimit" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-ratelimit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/xml","body":"<ack>ok</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"n":"first"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"n":"second"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><n>second</n></root>
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"n":
      """
    Then the response status code should be 429

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><n>second</n></root>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # request-rewrite sends /orders to the upstream as /legacy/orders, before the mediator.
  Scenario: Combine JSON/XML Mediator with authentication, rate limiting, or request rewrite policies (request rewrite)
    Given I generate a unique value from "jxm-rewrite" and store it as "apiName"
    And I generate a unique API version from "jxm-rewrite" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-rewrite" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceFullPath","replaceFullPath":"/legacy/orders"}}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/legacy/orders" with body:
      """
      {"contentType":"application/xml","body":"<ack>ok</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/legacy/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>W-1</sku></root>
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # pii-masking-regex runs first and redacts the e-mail address in the note as *****. The XML the
  # upstream receives holds the redacted note, so the mediator converted the body the earlier
  # policy produced.
  Scenario: Apply a request transformation before JSON/XML Mediator (body rewritten)
    Given I generate a unique value from "jxm-masked" and store it as "apiName"
    And I generate a unique API version from "jxm-masked" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-masked" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"jsonPath":"$.note","redactPII":true}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
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
      {"sku":"W-1","note":"contact jane@example.com"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><note>contact *****</note><sku>W-1</sku></root>
      """
    And the response body should not contain "jane@example.com"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The client sends JSON labelled text/plain to both operations. On /fixed, set-headers sets
  # Content-Type: application/json first; /plain has only the mediator.
  Scenario: Apply a request transformation before JSON/XML Mediator (Content-Type set)
    Given I generate a unique value from "jxm-set-ctype" and store it as "apiName"
    And I generate a unique API version from "jxm-set-ctype" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-set-ctype" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/fixed","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"Content-Type","value":"application/json"}]}}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]},{"method":"POST","path":"/plain","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/fixed" with body:
      """
      {"contentType":"application/xml","body":"<ack>received</ack>"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/fixed" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/fixed" until status 200
    Then the JSON response field "body" should be XML equivalent to:
      """
      <root><sku>W-1</sku></root>
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/plain" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "Content-Type must be application/json for downstream payload format json"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The API first converts JSON to XML, then is updated to convert XML to JSON, then updated
  # without the policy. Each update is awaited with a request only the new configuration accepts,
  # and /orders is scripted to answer in the format the current upstream speaks.
  Scenario: Update or remove mediator configuration on a deployed API
    Given I generate a unique value from "jxm-update" and store it as "apiName"
    And I generate a unique API version from "jxm-update" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-update" and store it as "apiContext"
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

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "PUT" request to the "capture" service at "/test/responses?path=/${CTX:apiName}/orders" with body:
      """
      {"contentType":"application/json","body":"{\"ack\":\"received\"}"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      <item><sku>G-2</sku></item>
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be:
      """
      {"item":{"sku":"G-2"}}
      """

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"sku":"W-1"}
      """
    Then the response status code should be 500
    And the JSON response field "message" should be "Content-Type must be application/xml or text/xml for downstream payload format xml"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders"}] |
    Then the resource creation response should indicate successful deployment
    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"sku":"P-3"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders" until status 200
    Then the JSON response field "body" should be:
      """
      {"sku":"P-3"}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
