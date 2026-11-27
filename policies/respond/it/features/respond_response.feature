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

@respond
Feature: Respond status, body and headers
  As an API developer
  I want the configured status, body and headers returned by the gateway
  So that clients get the response the API defines without the backend being called

  # The upstream is the testbench capture service (${CTX:captureUpstream}/<API name>). It records
  # every request that reaches it, and its /test/captured query answers 204 for a path that
  # received nothing. RES01 uses it to prove that respond answers without calling the backend;
  # the other scenarios check the reply itself.
  # Most APIs also have a /ready operation without the policy, which the scenario polls until the
  # API is deployed; it answers 200 from the capture service.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # RES01, RES14: respond answers in the gateway. Twenty concurrent requests all receive the
  # configured status and body, and the capture service records none of them, while the /ready
  # operation, which has no policy, is recorded: the backend is reachable but never called.
  Scenario: Answer from the gateway without calling the backend
    Given I generate a unique value from "res-answer" and store it as "apiName"
    And I generate a unique API version from "res-answer" and store it as "apiVersion"
    And I generate a unique API context from "/res-answer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"served by the gateway"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "Content-Type" should be "text/plain"
    And the response body should be:
      """
      served by the gateway
      """

    When I send 20 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/orders" cycling through:
      | body | status | contains              |
      |      | 200    | served by the gateway |
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders"
    Then the response status code should be 204
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/ready"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES02, RES03, RES04: Success, redirect, client-error and server-error statuses, the highest the
  # schema accepts (599), and the default when none is configured (200). The client receives the
  # configured status and exactly the configured body. The 404 row's body differs from the
  # gateway's own 404, so it cannot pass on a missing route.
  Scenario Outline: Return the configured status and body (<case>)
    Given I generate a unique value from "res-status-<key>" and store it as "apiName"
    And I generate a unique API version from "res-status-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-status-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":<params>}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be <status>
    And the response body should be:
      """
      <reply>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                 | key     | params                                        | status | reply             |
      | no status configured | default | {"body":"default status"}                     | 200    | default status    |
      | 200                  | 200     | {"statusCode":200,"body":"OK"}                | 200    | OK                |
      | 201                  | 201     | {"statusCode":201,"body":"created"}           | 201    | created           |
      | 206                  | 206     | {"statusCode":206,"body":"partial"}           | 206    | partial           |
      | 301                  | 301     | {"statusCode":301,"body":"moved permanently"} | 301    | moved permanently |
      | 302                  | 302     | {"statusCode":302,"body":"found elsewhere"}   | 302    | found elsewhere   |
      | 400                  | 400     | {"statusCode":400,"body":"bad request"}       | 400    | bad request       |
      | 401                  | 401     | {"statusCode":401,"body":"sign in first"}     | 401    | sign in first     |
      | 403                  | 403     | {"statusCode":403,"body":"forbidden"}         | 403    | forbidden         |
      | 404                  | 404     | {"statusCode":404,"body":"no such order"}     | 404    | no such order     |
      | 410                  | 410     | {"statusCode":410,"body":"endpoint retired"}  | 410    | endpoint retired  |
      | 418                  | 418     | {"statusCode":418,"body":"teapot"}            | 418    | teapot            |
      | 429                  | 429     | {"statusCode":429,"body":"slow down"}         | 429    | slow down         |
      | 500                  | 500     | {"statusCode":500,"body":"internal error"}    | 500    | internal error    |
      | 503                  | 503     | {"statusCode":503,"body":"maintenance"}       | 503    | maintenance       |
      | 599                  | 599     | {"statusCode":599,"body":"highest status"}    | 599    | highest status    |

  # RES04: The response must match the one recorded from the policy before a change
  # (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: Return the recorded maintenance response unchanged
    Given I generate a unique value from "res-maintenance" and store it as "apiName"
    And I generate a unique API version from "res-maintenance" and store it as "apiVersion"
    And I generate a unique API context from "/res-maintenance" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/maintenance","policies":[{"name":"respond","version":"v1","params":{"statusCode":503,"body":"{\\"error\\":\\"Service Unavailable\\",\\"message\\":\\"System under maintenance.\\"}","headers":[{"name":"Content-Type","value":"application/json"},{"name":"Retry-After","value":"3600"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/maintenance"
    Then the response status code should be 503
    And the response should match the expected error response "respond-configured-503"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES05: An empty body, configured or left out, is returned as an empty body with no
  # Content-Type, and the gateway adds no error of its own.
  Scenario Outline: Return an empty body (<case>)
    Given I generate a unique value from "res-empty-<key>" and store it as "apiName"
    And I generate a unique API version from "res-empty-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-empty-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":<params>}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be <status>
    And the response body should be empty
    And the response header "Content-Type" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                   | key   | params                       | status |
      | 204 without a body     | 204   | {"statusCode":204}           | 204    |
      | 200 with an empty body | empty | {"statusCode":200,"body":""} | 200    |
      | no parameters          | none  | {}                           | 200    |

  # RES06, RES08: JSON, XML, HTML, plain-text, Unicode and special-character bodies come back
  # byte for byte with the configured Content-Type. A body without a configured Content-Type is
  # sent as text/plain.
  Scenario Outline: Return the configured content with its Content-Type (<case>)
    Given I generate a unique value from "res-content-<key>" and store it as "apiName"
    And I generate a unique API version from "res-content-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-content-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":<params>}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "Content-Type" should be "<contentType>"
    And the response body should be:
      """
      <reply>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                       | key     | params                                                                                                                                                     | contentType               | reply                                          |
      | JSON                       | json    | {"statusCode":200,"body":"{\\"id\\":42,\\"name\\":\\"Ada\\",\\"tags\\":[\\"a\\",\\"b\\"]}","headers":[{"name":"Content-Type","value":"application/json"}]} | application/json          | {"id":42,"name":"Ada","tags":["a","b"]}        |
      | XML                        | xml     | {"statusCode":200,"body":"<?xml version=\\"1.0\\"?><user><id>42</id></user>","headers":[{"name":"Content-Type","value":"application/xml"}]}                | application/xml           | <?xml version="1.0"?><user><id>42</id></user>  |
      | HTML                       | html    | {"statusCode":200,"body":"<html><body><h1>Maintenance</h1></body></html>","headers":[{"name":"Content-Type","value":"text/html; charset=utf-8"}]}          | text/html; charset=utf-8  | <html><body><h1>Maintenance</h1></body></html> |
      | plain text                 | text    | {"statusCode":200,"body":"Service is up","headers":[{"name":"Content-Type","value":"text/plain"}]}                                                         | text/plain                | Service is up                                  |
      | Unicode                    | unicode | {"statusCode":200,"body":"Grüße, 世界, مرحبا, 🚀","headers":[{"name":"Content-Type","value":"text/plain; charset=utf-8"}]}                                    | text/plain; charset=utf-8 | Grüße, 世界, مرحبا, 🚀                            |
      | special characters         | special | {"statusCode":200,"body":"<>&'\\" %20 \\\\u0041 $HOME \| ; # ?","headers":[{"name":"Content-Type","value":"text/plain"}]}                                  | text/plain                | <>&'" %20 \\u0041 $HOME \| ; # ?               |
      | no Content-Type configured | untyped | {"body":"no type set"}                                                                                                                                     | text/plain                | no type set                                    |

  # RES07: Every configured header reaches the client with its exact value beside the body,
  # including a name with an underscore, which the schema allows.
  Scenario: Return every configured header with the response
    Given I generate a unique value from "res-headers" and store it as "apiName"
    And I generate a unique API version from "res-headers" and store it as "apiVersion"
    And I generate a unique API context from "/res-headers" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":201,"body":"{\\"id\\":42}","headers":[{"name":"Content-Type","value":"application/json"},{"name":"Location","value":"/orders/42"},{"name":"Cache-Control","value":"public, max-age=86400"},{"name":"ETag","value":"W/abc123"},{"name":"Expires","value":"Tue, 28 Jan 2026 12:00:00 GMT"},{"name":"Access-Control-Allow-Origin","value":"*"},{"name":"X-Custom_Id","value":"custom-1"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 201
    And the response header "Content-Type" should be "application/json"
    And the response header "Location" should be "/orders/42"
    And the response header "Cache-Control" should be "public, max-age=86400"
    And the response header "ETag" should be "W/abc123"
    And the response header "Expires" should be "Tue, 28 Jan 2026 12:00:00 GMT"
    And the response header "Access-Control-Allow-Origin" should be "*"
    And the response header "X-Custom_Id" should be "custom-1"
    And the response body should be:
      """
      {"id":42}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
