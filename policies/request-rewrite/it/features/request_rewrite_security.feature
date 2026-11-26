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
Feature: Request rewrite against hostile input
  As an API developer
  I want rewrites that a client cannot turn against the backend or the API's security controls
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

  # RR29: The client sends a plain request, and the query rules carry the delimiters. A value with &
  # and =, a value with CR LF and a header line, a substitution that appends &role=admin, and a
  # value that is already percent-encoded each stay inside their own parameter, as literal text: no
  # admin or role parameter and no X-Injected header reach the backend. A step string cannot hold
  # CR LF, so the note value is matched in the raw JSON, where the echo writes it as \r\n.
  Scenario: Keep delimiters in rewrite rule values inside the value
    Given I generate a unique value from "rr-rule-values" and store it as "apiName"
    And I generate a unique API version from "rr-rule-values" and store it as "apiVersion"
    And I generate a unique API context from "/rr-rule-values" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/search","policies":[{"name":"request-rewrite","version":"v1","params":{"queryRewrite":{"rules":[{"action":"Add","name":"tag","value":"a&admin=true"},{"action":"Add","name":"note","value":"a\\r\\nX-Injected: yes"},{"action":"ReplaceRegexMatch","name":"q","pattern":"^(.*)$","substitution":"\\\\1&role=admin"},{"action":"Add","name":"enc","value":"a%26admin%3Dtrue"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?q=x&page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/search"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.tag" should be "a&admin=true"
    And the JSON response field "args.q" should be "x&role=admin"
    And the JSON response field "args.enc" should be "a%26admin%3Dtrue"
    And the response body should match pattern "\x22note\x22:\x22a\\r\\nX-Injected: yes\x22"
    And the JSON response field "args.admin" should not exist
    And the JSON response field "args.role" should not exist
    And the response should not contain echoed header "X-Injected"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search" until status 404

  # RR30: The policy rewrites the request toward an admin route (DELETE /admin) before basic-auth
  # and basic-ratelimit run. The rewrite must not skip either: a client without credentials is
  # refused and nothing reaches the backend, an authenticated one reaches only /admin under the
  # API's own upstream, and the third request in the hour is throttled.
  Scenario: Keep security controls on rewritten traffic
    Given I generate a unique value from "rr-bypass" and store it as "apiName"
    And I generate a unique API version from "rr-bypass" and store it as "apiVersion"
    And I generate a unique API context from "/rr-bypass" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceFullPath","replaceFullPath":"/admin"},"methodRewrite":"DELETE"}},{"name":"basic-auth","version":"v1","params":{"username":"rr-user","password":"rr-secret"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2" until status 401
    Then the response body should not contain "/anything/admin"

    When I set header "Authorization" to "Basic cnItdXNlcjpyci1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/admin"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "method" should be "DELETE"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2"
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404
