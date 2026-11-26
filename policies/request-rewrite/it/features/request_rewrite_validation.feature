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
Feature: Request rewrite configuration errors
  As an API developer
  I want an unusable request-rewrite configuration rejected or handled safely
  So that the backend receives the request the API defines and nothing else changes

  # The gateway checks the policy's parameters against its schema when the API is created: at
  # least one of pathRewrite, queryRewrite and methodRewrite is required, types and actions come
  # from fixed lists, each needs its own value, paths start with / and are at most 2048
  # characters, and the method is one of GET, POST, PUT, DELETE, PATCH, HEAD and OPTIONS. Regular
  # expressions are only compiled when a request arrives.

  # The backend is the testbench echo service at http://testbench:3002/anything. It returns the
  # request it received as JSON: "method", "path" (the upstream base path /anything followed by the
  # path the gateway forwarded), "args" (the query parameters; a repeated one is a list) and
  # "headers". The path, query and method assertions read these fields. A request whose forwarded
  # form is checked also sends page=2, a parameter no rule names, as a control that must reach the
  # backend unchanged.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RR26: A configuration the schema rejects (no path, query or method rewrite, a missing or unknown
  # type or action, a missing value, a relative or over-long path, an empty rule list, an
  # unsupported or mistyped method, or an unknown parameter) fails with 400, and no API is created,
  # so nothing is ever forwarded with an unintended rewrite.
  Scenario Outline: Reject an invalid request-rewrite configuration (<case>)
    Given I generate a unique value from "rr-invalid-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-invalid-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-invalid-<key>" and store it as "apiContext"
    And I generate a value of 3 KiB of "QUFB" and store it as "padding"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.policies          | [{"name":"request-rewrite","version":"v1","params":<params>}] |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the response status code should be 400
    And the response body should contain "<detail>"

    When I get the API "${CTX:apiName}"
    Then the response status should be 404

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                                 | key            | params                                                                               | detail                                                   |
      | no rewrite configured                | none           | {}                                                                                   | pathRewrite is required                                  |
      | only a match condition               | match-only     | {"match":{"headers":[{"name":"X-Debug","type":"Present"}]}}                          | Must validate at least one schema (anyOf)                |
      | path rewrite without a type          | no-type        | {"pathRewrite":{"replacePrefixMatch":"/v2"}}                                         | type is required                                         |
      | unknown path rewrite type            | bad-type       | {"pathRewrite":{"type":"ReplaceAll","replacePrefixMatch":"/v2"}}                     | pathRewrite.type must be one of the following            |
      | prefix value missing                 | no-prefix      | {"pathRewrite":{"type":"ReplacePrefixMatch"}}                                        | replacePrefixMatch is required                           |
      | prefix without a leading slash       | relative       | {"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"v2"}}              | Does not match pattern '^/.*'                            |
      | regex rewrite without a substitution | no-sub         | {"pathRewrite":{"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/a"}}}   | substitution is required                                 |
      | full path over 2048 characters       | long-path      | {"pathRewrite":{"type":"ReplaceFullPath","replaceFullPath":"/${CTX:padding}"}}       | String length must be less than or equal to 2048         |
      | empty query rule list                | no-rules       | {"queryRewrite":{"rules":[]}}                                                        | Array must have at least 1 items                         |
      | unknown query action                 | bad-action     | {"queryRewrite":{"rules":[{"action":"Rename","name":"q","value":"x"}]}}              | queryRewrite.rules.0.action must be one of the following |
      | query value missing                  | no-value       | {"queryRewrite":{"rules":[{"action":"Replace","name":"q"}]}}                         | value is required                                        |
      | unsupported method                   | bad-method     | {"methodRewrite":"TRACE"}                                                            | methodRewrite must be one of the following               |
      | method of the wrong type             | method-type    | {"methodRewrite":123}                                                                | Invalid type. Expected: string, given: integer           |
      | header condition without a value     | no-match-value | {"match":{"headers":[{"name":"X-Client-Id","type":"Exact"}]},"methodRewrite":"POST"} | value is required                                        |
      | unknown parameter                    | unknown        | {"methodRewrite":"POST","rewriteHost":"backend.example"}                             | Additional property rewriteHost is not allowed           |

  # RR27: Patterns are not compiled when the API is created, so these configurations deploy. A path
  # pattern that does not compile, or a condition that cannot be evaluated, leaves the request
  # unchanged, and a substitution naming a group the pattern lacks inserts nothing. The gateway
  # keeps serving, and no request is rewritten in a way the configuration did not ask for.
  Scenario Outline: Safely handle a pattern or condition that cannot be used (<case>)
    Given I generate a unique value from "rr-unusable-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-unusable-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-unusable-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":<params>}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | case                                           | key           | params                                                                                                                                               | forwarded        |
      | path pattern that does not compile             | path-regex    | {"pathRewrite":{"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"(","substitution":"/x"}}}                                                 | /anything/api/v1 |
      | capture group the pattern lacks                | missing-group | {"pathRewrite":{"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/api/v1$","substitution":"/x\\\\9"}}}                                    | /anything/x      |
      | header condition pattern that does not compile | header-regex  | {"match":{"headers":[{"name":"X-Client-Id","type":"Regex","value":"("}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}} | /anything/api/v1 |
      | query condition pattern that does not compile  | query-regex   | {"match":{"queryParams":[{"name":"page","type":"Regex","value":"("}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}    | /anything/api/v1 |
      | blank header condition name                    | blank-header  | {"match":{"headers":[{"name":" ","type":"Present"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}                     | /anything/api/v1 |
      | blank query condition name                     | blank-query   | {"match":{"queryParams":[{"name":" ","type":"Present"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}                 | /anything/api/v1 |

  # RR27: A query rule that cannot run (a pattern that does not compile, or a blank parameter name)
  # refuses the request with 500 and a configuration error instead of forwarding it half rewritten.
  # The response must match the one recorded from the policy (resources/expected-error-responses),
  # so a change a client could observe fails. Another operation of the API keeps working.
  Scenario Outline: Refuse a request whose query rule cannot run (<case>)
    Given I generate a unique value from "rr-refused-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-refused-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-refused-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/search","policies":[{"name":"request-rewrite","version":"v1","params":{"queryRewrite":{"rules":<rules>}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/search?q=value&page=2"
    Then the response status code should be 500
    And the response should match the expected error response "<errorResponse>"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                                | key         | rules                                                                        | errorResponse                         |
      | query pattern that does not compile | query-regex | [{"action":"ReplaceRegexMatch","name":"q","pattern":"(","substitution":"x"}] | request-rewrite-invalid-query-regex   |
      | blank query rule name               | blank-rule  | [{"action":"Add","name":" ","value":"x"}]                                    | request-rewrite-blank-query-rule-name |
