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

@request-rewrite
Feature: Request rewrite of query parameters
  As an API developer
  I want query parameters rewritten by ordered rules
  So that the backend receives the request the API defines and nothing else changes

  # The backend is the testbench echo service at http://testbench:3002/anything. It returns the
  # request it received as JSON: "method", "path" (the upstream base path /anything followed by the
  # path the gateway forwarded), "args" (the query parameters; a repeated one is a list) and
  # "headers". The path, query and method assertions read these fields. A request whose forwarded
  # form is checked also sends page=2, a parameter no rule names, as a control that must reach the
  # backend unchanged.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RR07, RR08, RR09: One policy adds source=legacy, replaces the value of q, and removes debug. The
  # backend must receive the new parameter, the replaced value, no debug, and page unchanged.
  Scenario: Add, replace and remove query parameters
    Given I generate a unique value from "rr-query" and store it as "apiName"
    And I generate a unique API version from "rr-query" and store it as "apiVersion"
    And I generate a unique API context from "/rr-query" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/search","policies":[{"name":"request-rewrite","version":"v1","params":{"queryRewrite":{"rules":[{"action":"Add","name":"source","value":"legacy"},{"action":"Replace","name":"q","value":"new-value"},{"action":"Remove","name":"debug"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?q=old-value&debug=true&page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.source" should be "legacy"
    And the JSON response field "args.q" should be "new-value"
    And the JSON response field "args.debug" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search" until status 404

  # RR10: Append adds b to the end of the existing tags value, with the separator in between when
  # one is configured and directly when it is empty. When the client sends no tags, Append sets it
  # to b.
  Scenario Outline: Append to a query parameter (<case>)
    Given I generate a unique value from "rr-append-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-append-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-append-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/search","policies":[{"name":"request-rewrite","version":"v1","params":{"queryRewrite":{"rules":[{"action":"Append","name":"tags","value":"b","separator":"<separator>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?<query>" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.tags" should be "<forwardedTags>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search" until status 404

    Examples:
      | case                | key       | separator | query         | forwardedTags |
      | with a separator    | separator | -         | tags=a&page=2 | a-b           |
      | without a separator | plain     |           | tags=a&page=2 | ab            |
      | parameter absent    | absent    | -         | page=2        | b             |

  # RR11: ReplaceRegexMatch rewrites v2.5 to release-2-5 with two capture groups. A value the
  # pattern does not match is forwarded unchanged, and a request without the parameter does not get
  # one.
  Scenario: Rewrite a query parameter with a regular expression
    Given I generate a unique value from "rr-query-regex" and store it as "apiName"
    And I generate a unique API version from "rr-query-regex" and store it as "apiVersion"
    And I generate a unique API context from "/rr-query-regex" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/search","policies":[{"name":"request-rewrite","version":"v1","params":{"queryRewrite":{"rules":[{"action":"ReplaceRegexMatch","name":"version","pattern":"^v(\\\\d+)\\\\.(\\\\d+)$","substitution":"release-\\\\1-\\\\2"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?version=v2.5&page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.version" should be "release-2-5"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?version=beta&page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.version" should be "beta"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.version" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search" until status 404

  # RR12: Five rules run in order, each on the result of the ones before it: Add sets tag=a, Append
  # turns it into a-b, Replace sets mode=draft, ReplaceRegexMatch turns draft into final, and Remove
  # drops legacy. Only that order produces tag=a-b and mode=final.
  Scenario: Run query rules in the configured order
    Given I generate a unique value from "rr-query-order" and store it as "apiName"
    And I generate a unique API version from "rr-query-order" and store it as "apiVersion"
    And I generate a unique API context from "/rr-query-order" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/search","policies":[{"name":"request-rewrite","version":"v1","params":{"queryRewrite":{"rules":[{"action":"Add","name":"tag","value":"a"},{"action":"Append","name":"tag","value":"b","separator":"-"},{"action":"Replace","name":"mode","value":"draft"},{"action":"ReplaceRegexMatch","name":"mode","pattern":"^draft$","substitution":"final"},{"action":"Remove","name":"legacy"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?legacy=1&page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.tag" should be "a-b"
    And the JSON response field "args.mode" should be "final"
    And the JSON response field "args.legacy" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search" until status 404
