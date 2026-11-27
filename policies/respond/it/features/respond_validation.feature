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
Feature: Respond configuration limits
  As an API developer
  I want an unusable respond configuration rejected or handled safely
  So that clients get the response the API defines without the backend being called

  # The gateway checks the policy's parameters against its schema when the API is created:
  # statusCode is an integer from 100 to 599, body a string of at most 1 MiB, and headers a list
  # of objects with only a name (1-256 characters of letters, digits, - and _) and a value (at
  # most 8192 characters). No other parameter is allowed.

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

  # RES23, RES24: A configuration the schema rejects (a wrong type, a missing or unknown field,
  # a status outside 100-599, a header name the pattern rejects, or a value over its length limit)
  # fails with 400, no API is created, and so no unintended reply is ever served.
  Scenario Outline: Reject an invalid respond configuration (<case>)
    Given I generate a unique value from "res-invalid-<key>" and store it as "apiName"
    And I generate a unique API version from "res-invalid-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-invalid-<key>" and store it as "apiContext"
    And I generate a value of 9 KiB of "QUFB" and store it as "nineKiB"
    And I generate a value of 1024 KiB of "QUFB" and store it as "oneMiB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response body should contain "<detail>"

    When I get the API "${CTX:apiName}"
    Then the response status should be 404

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                              | key             | params                                                                                                                                                                                                                                                                                                 | detail                                              |
      | status as a word                  | status-word     | {"statusCode":"abc"}                                                                                                                                                                                                                                                                                   | Invalid type. Expected: integer, given: string      |
      | status with a fraction            | status-fraction | {"statusCode":200.5}                                                                                                                                                                                                                                                                                   | Invalid type. Expected: integer, given: number      |
      | status below 100                  | status-low      | {"statusCode":99}                                                                                                                                                                                                                                                                                      | Must be greater than or equal to 100                |
      | status above 599                  | status-high     | {"statusCode":600}                                                                                                                                                                                                                                                                                     | Must be less than or equal to 599                   |
      | body not a string                 | body-type       | {"body":42}                                                                                                                                                                                                                                                                                            | Invalid type. Expected: string, given: integer      |
      | body over 1 MiB                   | body-long       | {"body":"${CTX:oneMiB}x"}                                                                                                                                                                                                                                                                              | String length must be less than or equal to 1048576 |
      | headers not an array              | headers-type    | {"headers":{"name":"X-A","value":"a"}}                                                                                                                                                                                                                                                                 | Invalid type. Expected: array, given: object        |
      | header not an object              | header-type     | {"headers":["X-A: a"]}                                                                                                                                                                                                                                                                                 | Invalid type. Expected: object, given: string       |
      | header without a name             | no-name         | {"headers":[{"value":"a"}]}                                                                                                                                                                                                                                                                            | name is required                                    |
      | header without a value            | no-value        | {"headers":[{"name":"X-A"}]}                                                                                                                                                                                                                                                                           | value is required                                   |
      | empty header name                 | empty-name      | {"headers":[{"name":"","value":"a"}]}                                                                                                                                                                                                                                                                  | String length must be greater than or equal to 1    |
      | header name with a space          | bad-name        | {"headers":[{"name":"X Bad","value":"a"}]}                                                                                                                                                                                                                                                             | Does not match pattern                              |
      | header name over 256 characters   | long-name       | {"headers":[{"name":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX","value":"a"}]} | String length must be less than or equal to 256     |
      | header value not a string         | value-type      | {"headers":[{"name":"X-A","value":1}]}                                                                                                                                                                                                                                                                 | Invalid type. Expected: string, given: integer      |
      | header value over 8192 characters | long-value      | {"headers":[{"name":"X-A","value":"${CTX:nineKiB}"}]}                                                                                                                                                                                                                                                  | String length must be less than or equal to 8192    |
      | unknown header field              | header-field    | {"headers":[{"name":"X-A","value":"a","append":true}]}                                                                                                                                                                                                                                                 | Additional property append is not allowed           |
      | unknown parameter                 | unknown         | {"status":200}                                                                                                                                                                                                                                                                                         | Additional property status is not allowed           |

  # RES24: A status written as a numeric string ("201") is accepted: the gateway converts it to
  # the number, and the client receives 201. A string that is not a number is rejected (RES23).
  # Gateway 1.2.0 added this conversion of policy parameters to their schema types
  # (wso2/api-platform#2934, for values written as template expressions); 1.1.0 rejects the
  # string with 400. The respond-validation-gw-1.1.0 runner skips this tag.
  @requires-gw-1.2.0
  Scenario: Accept a status written as a numeric string
    Given I generate a unique value from "res-status-text" and store it as "apiName"
    And I generate a unique API version from "res-status-text" and store it as "apiVersion"
    And I generate a unique API context from "/res-status-text" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":"201","body":"created from text"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 201
    And the response body should be:
      """
      created from text
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES25: A body of exactly 1 MiB, the schema's limit, is deployed and returned in full, and the
  # gateway keeps serving other operations afterwards. One byte more is rejected (see RES23).
  Scenario: Return a body at the size limit
    Given I generate a unique value from "res-large" and store it as "apiName"
    And I generate a unique API version from "res-large" and store it as "apiVersion"
    And I generate a unique API context from "/res-large" and store it as "apiContext"
    And I generate a value of 1024 KiB of "QUFB" and store it as "oneMiB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/large","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"${CTX:oneMiB}"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/large"
    Then the response status code should be 200
    And the response header "Content-Length" should be "1048576"
    And the response body should be:
      """
      ${CTX:oneMiB}
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
