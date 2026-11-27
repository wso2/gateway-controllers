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
Feature: Request rewrite match conditions
  As an API developer
  I want rewrites to run only when their header and query conditions hold
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

  # RR16: The rewrite runs only when X-Client-Id is exactly client-123. A different value, the same
  # value in another case (values are compared exactly) or a missing header leave the path as
  # /api/v1.
  Scenario Outline: Rewrite only when a header has the exact value (<case>)
    Given I generate a unique value from "rr-exact-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-exact-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-exact-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"match":{"headers":[{"name":"X-Client-Id","type":"Exact","value":"client-123"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    And I set header "<header>" to "<value>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | case                  | key     | header      | value      | forwarded        |
      | matching value        | match   | X-Client-Id | client-123 | /anything/api/v2 |
      | different value       | other   | X-Client-Id | client-999 | /anything/api/v1 |
      | value in another case | case    | X-Client-Id | CLIENT-123 | /anything/api/v1 |
      | header missing        | missing | X-Other-Id  | client-123 | /anything/api/v1 |

  # RR17: The rewrite runs only when X-Client-Id matches the RE2 expression ^client-[0-9]+$. A value
  # outside it, including one that only contains a match, leaves the path as /api/v1.
  Scenario Outline: Rewrite only when a header matches a regular expression (<case>)
    Given I generate a unique value from "rr-header-regex-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-header-regex-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-header-regex-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"match":{"headers":[{"name":"X-Client-Id","type":"Regex","value":"^client-[0-9]+$"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    And I set header "<header>" to "<value>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | case                        | key     | header      | value        | forwarded        |
      | matching value              | match   | X-Client-Id | client-42    | /anything/api/v2 |
      | letters instead of digits   | letters | X-Client-Id | client-abc   | /anything/api/v1 |
      | match inside a longer value | inside  | X-Client-Id | my-client-42 | /anything/api/v1 |

  # RR18: The rewrite runs when X-Debug is sent, whatever its value, and not when it is missing.
  Scenario Outline: Rewrite only when a header is present (<case>)
    Given I generate a unique value from "rr-present-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-present-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-present-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"match":{"headers":[{"name":"X-Debug","type":"Present"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    And I set header "<header>" to "<value>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | case           | key     | header        | value    | forwarded        |
      | one value      | one     | X-Debug       | 1        | /anything/api/v2 |
      | another value  | other   | X-Debug       | anything | /anything/api/v2 |
      | header missing | missing | X-Other-Debug | 1        | /anything/api/v1 |

  # RR19: A query parameter condition of each type: Exact compares the value, Regex matches it
  # with RE2, and Present only needs the parameter, even with an empty value. The rewrite runs only
  # when the condition holds.
  Scenario Outline: Rewrite only when a query parameter condition holds (<case>)
    Given I generate a unique value from "rr-query-match-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-query-match-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-query-match-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"match":{"queryParams":[<matcher>]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?<query>"
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | case                        | key        | matcher                                               | query                  | forwarded        |
      | exact value matches         | exact      | {"name":"channel","type":"Exact","value":"beta"}      | channel=beta&page=2    | /anything/api/v2 |
      | exact value differs         | exact-no   | {"name":"channel","type":"Exact","value":"beta"}      | channel=stable&page=2  | /anything/api/v1 |
      | regex matches               | regex      | {"name":"channel","type":"Regex","value":"^v[0-9]+$"} | channel=v2&page=2      | /anything/api/v2 |
      | regex does not match        | regex-no   | {"name":"channel","type":"Regex","value":"^v[0-9]+$"} | channel=v2-beta&page=2 | /anything/api/v1 |
      | present with an empty value | present    | {"name":"channel","type":"Present"}                   | channel=&page=2        | /anything/api/v2 |
      | parameter missing           | present-no | {"name":"channel","type":"Present"}                   | page=2                 | /anything/api/v1 |

  # RR20: Two header conditions and a query condition together. The rewrite runs only when all of
  # them hold; any one failing leaves the path as /api/v1.
  Scenario Outline: Rewrite only when every condition holds (<case>)
    Given I generate a unique value from "rr-all-match-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-all-match-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-all-match-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"match":{"headers":[{"name":"X-Client-Id","type":"Exact","value":"client-123"},{"name":"X-Tenant","type":"Present"}],"queryParams":[{"name":"channel","type":"Exact","value":"beta"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    And I set header "X-Client-Id" to "<clientId>"
    And I set header "<tenantHeader>" to "tenant-a"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?channel=<channel>&page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "<forwarded>"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | case                  | key     | clientId   | tenantHeader   | channel | forwarded        |
      | every condition holds | all     | client-123 | X-Tenant       | beta    | /anything/api/v2 |
      | client differs        | client  | client-999 | X-Tenant       | beta    | /anything/api/v1 |
      | tenant header missing | tenant  | client-123 | X-Other-Tenant | beta    | /anything/api/v1 |
      | channel differs       | channel | client-123 | X-Tenant       | stable  | /anything/api/v1 |

  # RR21: Header names match without regard to case. The condition names the header as <configured>
  # and the client sends it, over a raw connection so the case is kept, as <sent>; the rewrite must
  # still run.
  Scenario Outline: Match a header name in any case (<configured> sent as <sent>)
    Given I generate a unique value from "rr-case-<key>" and store it as "apiName"
    And I generate a unique API version from "rr-case-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-case-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"match":{"headers":[{"name":"<configured>","type":"Exact","value":"client-123"}]},"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" with headers:
      | <sent> | client-123 |
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/api/v2"
    And the JSON response field "args.page" should be "2"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | configured  | sent        | key              |
      | X-Client-Id | x-client-id | lower            |
      | X-Client-Id | X-CLIENT-ID | upper            |
      | x-client-id | X-Client-Id | configured-lower |
      | X-CLIENT-ID | x-ClIeNt-iD | mixed            |
