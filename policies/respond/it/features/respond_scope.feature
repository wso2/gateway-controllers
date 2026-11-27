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
Feature: Respond scope and chaining
  As an API developer
  I want respond to apply where it is attached and in policy order
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

  # RES11: respond attached to the API answers every operation, whatever its method or path.
  Scenario: Answer every operation from an API-level respond
    Given I generate a unique value from "res-api-level" and store it as "apiName"
    And I generate a unique API version from "res-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/res-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.policies          | [{"name":"respond","version":"v1","params":{"statusCode":200,"body":"api level reply","headers":[{"name":"X-Reply-Scope","value":"api"}]}}] |
      | spec.operations        | [{"method":"GET","path":"/orders"},{"method":"POST","path":"/payments"},{"method":"DELETE","path":"/items/{id}"}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "X-Reply-Scope" should be "api"
    And the response body should be:
      """
      api level reply
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payments"
    Then the response status code should be 200
    And the response header "X-Reply-Scope" should be "api"
    And the response body should be:
      """
      api level reply
      """

    When I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/items/7"
    Then the response status code should be 200
    And the response header "X-Reply-Scope" should be "api"
    And the response body should be:
      """
      api level reply
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # RES12: Only the operation with the policy answers from the gateway. The other operation of the
  # same API follows the normal flow: the capture service answers it.
  Scenario: Answer only the operation that has the policy
    Given I generate a unique value from "res-one-op" and store it as "apiName"
    And I generate a unique API version from "res-one-op" and store it as "apiVersion"
    And I generate a unique API context from "/res-one-op" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/stubbed","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"stubbed reply"}}]},{"method":"GET","path":"/live"}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/stubbed"
    Then the response status code should be 200
    And the response body should be:
      """
      stubbed reply
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/live"
    Then the response status code should be 200
    And the JSON response field "path" should be "/${CTX:apiName}/live"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES13: Each operation returns its own configured status, body and Content-Type.
  Scenario: Return each operation's own reply
    Given I generate a unique value from "res-per-op" and store it as "apiName"
    And I generate a unique API version from "res-per-op" and store it as "apiVersion"
    And I generate a unique API context from "/res-per-op" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/json","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"{\\"format\\":\\"json\\"}","headers":[{"name":"Content-Type","value":"application/json"}]}}]},{"method":"GET","path":"/xml","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"<format>xml</format>","headers":[{"name":"Content-Type","value":"application/xml"}]}}]},{"method":"POST","path":"/created","policies":[{"name":"respond","version":"v1","params":{"statusCode":201,"body":"created","headers":[{"name":"Location","value":"/orders/1"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/json"
    Then the response status code should be 200
    And the response header "Content-Type" should be "application/json"
    And the response body should be:
      """
      {"format":"json"}
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/xml"
    Then the response status code should be 200
    And the response header "Content-Type" should be "application/xml"
    And the response body should be:
      """
      <format>xml</format>
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/created"
    Then the response status code should be 201
    And the response header "Location" should be "/orders/1"
    And the response body should be:
      """
      created
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES15: basic-auth runs before respond. A caller basic-auth accepts receives the configured
  # reply; any other caller receives basic-auth's 401 and none of the reply.
  Scenario Outline: Answer only callers that basic-auth accepts (<case>)
    Given I generate a unique value from "res-auth-<key>" and store it as "apiName"
    And I generate a unique API version from "res-auth-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-auth-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"basic-auth","version":"v1","params":{"username":"res-user","password":"res-secret"}},{"name":"respond","version":"v1","params":{"statusCode":200,"body":"protected reply"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    And I set header "Authorization" to "<authorization>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
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
      | case                  | key    | authorization                      | status | reply                                                        |
      | valid credentials     | valid  | Basic cmVzLXVzZXI6cmVzLXNlY3JldA== | 200    | protected reply                                              |
      | wrong password        | wrong  | Basic cmVzLXVzZXI6d3Jvbmctc2VjcmV0 | 401    | {"error":"Unauthorized","message":"Authentication required"} |
      | not Basic credentials | bearer | Bearer res-token                   | 401    | {"error":"Unauthorized","message":"Authentication required"} |

  # RES16: basic-ratelimit runs before respond and allows two requests an hour. The first two
  # receive the configured reply, and the third is throttled with 429 before respond runs.
  Scenario: Throttle requests before respond answers them
    Given I generate a unique value from "res-ratelimit" and store it as "apiName"
    And I generate a unique API version from "res-ratelimit" and store it as "apiVersion"
    And I generate a unique API context from "/res-ratelimit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}},{"name":"respond","version":"v1","params":{"statusCode":200,"body":"limited reply"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200


    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response body should be:
      """
      limited reply
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response body should be:
      """
      limited reply
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 429
    And the response body should not contain "limited reply"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES17: set-headers adds a request header, log-message logs the request headers, and then
  # respond answers. The log line holding the added value also names the header
  # (x-added-by-gateway; log-message writes names in lower case), so both earlier policies ran.
  # set-headers' response header is not added: an immediate reply skips the response phase of
  # every policy.
  Scenario: Run the request policies before respond
    Given I generate a unique value from "res-before" and store it as "apiName"
    And I generate a unique API version from "res-before" and store it as "apiVersion"
    And I generate a unique API context from "/res-before" and store it as "apiContext"
    And I generate a unique value from "res-added" and store it as "addedValue"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-By-Gateway","value":"${CTX:addedValue}"}]},"response":{"headers":[{"name":"X-Set-On-Response","value":"set"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true}}},{"name":"respond","version":"v1","params":{"statusCode":200,"body":"after the chain"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "X-Set-On-Response" should not exist
    And the response body should be:
      """
      after the chain
      """
    And the "gateway-runtime" service log event containing "${CTX:addedValue}" should contain "x-added-by-gateway"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES18: set-headers and log-message come after respond, so they never run: nothing is logged
  # for the request and set-headers' response header is missing. The /logged operation runs
  # log-message without respond; its line appears after the respond request was answered, so the
  # logs were read past the point where the skipped line would have been.
  Scenario: Skip the policies after respond
    Given I generate a unique value from "res-after" and store it as "apiName"
    And I generate a unique API version from "res-after" and store it as "apiVersion"
    And I generate a unique API context from "/res-after" and store it as "apiContext"
    And I generate a unique value from "res-skipped" and store it as "skippedValue"
    And I generate a unique value from "res-logged" and store it as "loggedValue"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"chain ends here"}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-By-Gateway","value":"${CTX:skippedValue}"}]},"response":{"headers":[{"name":"X-Set-On-Response","value":"set"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]},{"method":"GET","path":"/logged","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-By-Gateway","value":"${CTX:loggedValue}"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "X-Set-On-Response" should not exist
    And the response body should be:
      """
      chain ends here
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/logged"
    Then the response status code should be 200
    And the "gateway-runtime" service logs should contain "${CTX:loggedValue}"
    And the "gateway-runtime" service logs should not contain "${CTX:skippedValue}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
