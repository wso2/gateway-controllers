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
Feature: Request rewrite of the path
  As an API developer
  I want the request path rewritten as the policy configures
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

  # RR01: ReplacePrefixMatch replaces the operation's path prefix with /api/v2 and keeps whatever
  # follows it, so the backend receives /api/v2 followed by the rest of the request path, with the
  # query string unchanged.
  Scenario Outline: Replace the path prefix (<case>)
    Given I generate a unique value from "rr-prefix-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-prefix-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-prefix-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"<operation>","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>" until status 404

    Examples:
      | case                | key   | operation | request | forwarded        |
      | operation path only | exact | /api/v1   | /api/v1 | /anything/api/v2 |

    # Known issue on gateway 1.1.0: the route of an operation whose path ends in /* below the root
    # strips the operation's literal prefix along with the API context, so a path the policy
    # rewrites no longer matches the route's rewrite and reaches the backend with the API context
    # instead of the upstream base path (wso2/api-platform#2071, fixed in 1.2.0 by
    # wso2/api-platform#2072). The 1.1.0 runner skips @known-issue-gw-1.1.0.
    @known-issue-gw-1.1.0
    Examples:
      | case                | key       | operation | request          | forwarded                 |
      | remaining path kept | remainder | /api/v1/* | /api/v1/users/42 | /anything/api/v2/users/42 |

  # RR02: ReplaceFullPath replaces the whole relative path, whatever it was, with /fixed/path, and
  # keeps the query string.
  Scenario Outline: Replace the full path (<case>)
    Given I generate a unique value from "rr-full-path-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-full-path-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-full-path-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"<operation>","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceFullPath","replaceFullPath":"/fixed/path"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/fixed/path"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>" until status 404

    Examples:
      | case           | key   | operation | request |
      | operation path | exact | /api/v1   | /api/v1 |

    # Known issue on gateway 1.1.0: the route of an operation whose path ends in /* below the root
    # strips the operation's literal prefix along with the API context, so a path the policy
    # rewrites no longer matches the route's rewrite and reaches the backend with the API context
    # instead of the upstream base path (wso2/api-platform#2071, fixed in 1.2.0 by
    # wso2/api-platform#2072). The 1.1.0 runner skips @known-issue-gw-1.1.0.
    @known-issue-gw-1.1.0
    Examples:
      | case                      | key      | operation | request          |
      | any path under a wildcard | wildcard | /api/v1/* | /api/v1/users/42 |

  # RR03: ReplaceRegexMatch rewrites the relative path with an RE2 pattern and a substitution that
  # can refer to capture groups as \1, \2. An anchored pattern, reordered capture groups, the (?i)
  # flag, and a pattern that matches more than once (every match is replaced) are all covered.
  Scenario Outline: Rewrite the path with a regular expression (<case>)
    Given I generate a unique value from "rr-regex-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-regex-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-regex-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"<operation>","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":<rewrite>}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>" until status 404

    Examples:
      | case                     | key      | operation | rewrite                                                                                                                      | request              | forwarded                     |
      | anchored pattern         | anchored | /api/v1   | {"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/api/v1$","substitution":"/api/v2"}}                            | /api/v1              | /anything/api/v2              |
      | capture groups reordered | captures | /*        | {"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/service/([^/]+)(/.*)$","substitution":"\\\\2/instance/\\\\1"}} | /service/foo/v1/api  | /anything/v1/api/instance/foo |
      | case-insensitive flag    | case     | /*        | {"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"(?i)/xxx/","substitution":"/yyy/"}}                              | /aaa/XxX/bbb         | /anything/aaa/yyy/bbb         |
      | every match replaced     | all      | /*        | {"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"one","substitution":"two"}}                                      | /xxx/one/yyy/one/zzz | /anything/xxx/two/yyy/two/zzz |

  # RR04: The pattern only matches /orders/ followed by digits. A request whose path does not match
  # reaches the backend with its path unchanged, while a matching one is rewritten, which shows the
  # rule is live.
  Scenario: Leave a path that does not match the pattern unchanged
    Given I generate a unique value from "rr-regex-nomatch" and store it as "apiName"
    And I generate a unique API version from "rr-regex-nomatch" and store it as "apiVersion"
    And I generate a unique API context from "/rr-regex-nomatch" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/*","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/orders/([0-9]+)$","substitution":"/purchases/\\\\1"}}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/42?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/purchases/42"
    And the JSON response field "args.page" should be "2"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/abc?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/orders/abc"
    And the JSON response field "args.page" should be "2"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/42/items?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/orders/42/items"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/42" until status 404

  # RR05: The dynamic parts of a path, the segments a wildcard matches and the values of path
  # parameters, are kept or moved as the rule says.
  Scenario Outline: Rewrite paths that have path parameters and nested segments (<case>)
    Given I generate a unique value from "rr-dynamic-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-dynamic-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-dynamic-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"<operation>","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":<rewrite>}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<request>" until status 404

    Examples:
      | case                              | key    | operation                        | rewrite                                                                                                                                          | request            | forwarded                          |
      | path parameters as capture groups | params | /users/{userId}/orders/{orderId} | {"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/users/([^/]+)/orders/([^/]+)$","substitution":"/customers/\\\\1/purchases/\\\\2"}} | /users/42/orders/7 | /anything/customers/42/purchases/7 |

    # Known issue on gateway 1.1.0: the route of an operation whose path ends in /* below the root
    # strips the operation's literal prefix along with the API context, so a path the policy
    # rewrites no longer matches the route's rewrite and reaches the backend with the API context
    # instead of the upstream base path (wso2/api-platform#2071, fixed in 1.2.0 by
    # wso2/api-platform#2072). The 1.1.0 runner skips @known-issue-gw-1.1.0.
    @known-issue-gw-1.1.0
    Examples:
      | case                             | key      | operation | rewrite                                                         | request            | forwarded                       |
      | nested segments under a wildcard | wildcard | /users/*  | {"type":"ReplacePrefixMatch","replacePrefixMatch":"/customers"} | /users/42/orders/7 | /anything/customers/42/orders/7 |

  # RR06: The rewrite works on the path relative to the API context. A rule on the relative path
  # rewrites it, and a pattern that matches the context itself never matches, so that request is
  # forwarded unchanged. In both, the gateway replaces the context with the upstream base path as
  # usual, so the backend never receives the context.
  Scenario: Rewrite the relative path and keep the API context out of it
    Given I generate a unique value from "rr-context" and store it as "apiName"
    And I generate a unique API version from "rr-context" and store it as "apiVersion"
    And I generate a unique API context from "/rr-context" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/items/1","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^/items/(.*)$","substitution":"/products/\\\\1"}}}}]},{"method":"GET","path":"/context/1","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceRegexMatch","replaceRegexMatch":{"pattern":"^${CTX:apiContext}","substitution":"/leaked"}}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/1?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/products/1"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "url" should be "/anything/products/1?page=2"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/context/1?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/context/1"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "url" should be "/anything/context/1?page=2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/1" until status 404
