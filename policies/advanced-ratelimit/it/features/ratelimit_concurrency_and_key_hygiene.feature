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

@ratelimit-concurrency
Feature: Advanced rate limit under concurrency and client-controlled key input
  As an API operator
  I want the quota boundary to hold under parallel load and for the key to resist manipulation
  So that a burst of requests cannot overrun a quota and the key is the same for the same client input

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Parallel requests around the quota boundary neither overrun nor under-use the quota
    Given I generate a unique value from "arl-concurrent" and store it as "apiName"
    And I generate a unique API version from "arl-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/arl-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"parallel","limits":[{"limit":10,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 25 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource" and exactly 10 should return 200 while 15 should return 429
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Parallel requests to a cost-weighted quota never admit more weight than the limit
    Given I generate a unique value from "arl-concurrent-weight" and store it as "apiName"
    And I generate a unique API version from "arl-concurrent-weight" and store it as "apiVersion"
    And I generate a unique API context from "/arl-concurrent-weight" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"parallel-weighted","limits":[{"limit":12,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # Every request costs 3 of 12, so exactly 4 fit however the 12 requests interleave.
    When I set header "X-Cost" to "3"
    And I send 12 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource" and exactly 4 should return 200 while 8 should return 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A header key is matched by name regardless of its casing
    Given I generate a unique value from "arl-key-name-case" and store it as "apiName"
    And I generate a unique API version from "arl-key-name-case" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-name-case" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"name-case","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-User-ID" to "bob"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I set header "x-user-id" to "bob"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I set header "X-USER-ID" to "bob"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Only the first address of X-Forwarded-For identifies the client
    Given I generate a unique value from "arl-key-xff-first" and store it as "apiName"
    And I generate a unique API version from "arl-key-xff-first" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-xff-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"xff-first","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"ip"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Forwarded-For" to "203.0.113.10, 198.51.100.1"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I set header "X-Forwarded-For" to "203.0.113.10, 198.51.100.2"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I set header "X-Forwarded-For" to "203.0.113.10, 198.51.100.3"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I set header "X-Forwarded-For" to "203.0.113.11"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A header sent twice yields one deterministic key
    Given I generate a unique value from "arl-key-duplicate" and store it as "apiName"
    And I generate a unique API version from "arl-key-duplicate" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-duplicate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"duplicate-header","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with headers:
      | X-User-ID | dup-a |
      | X-User-ID | dup-b |
    Then the response status code should be 200
    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with headers:
      | X-User-ID | dup-a |
      | X-User-ID | dup-b |
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An empty header value is treated like an absent header
    Given I generate a unique value from "arl-key-empty" and store it as "apiName"
    And I generate a unique API version from "arl-key-empty" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"empty-header","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with headers:
      | X-User-ID |  |
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A second X-Forwarded-For header line does not change the client's key
    Given I generate a unique value from "arl-key-xff-lines" and store it as "apiName"
    And I generate a unique API version from "arl-key-xff-lines" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-xff-lines" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"xff-lines","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"ip"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with headers:
      | X-Forwarded-For | 203.0.113.50 |
      | X-Forwarded-For | 198.51.100.1 |
    Then the response status code should be 200
    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with headers:
      | X-Forwarded-For | 203.0.113.50 |
      | X-Forwarded-For | 198.51.100.2 |
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A CEL key can bucket requests by a query parameter
    Given I generate a unique value from "arl-key-cel-query" and store it as "apiName"
    And I generate a unique API version from "arl-key-cel-query" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-cel-query" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"by-query","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"cel","expression":"request.Path.contains(\"user=a\") ? \"user-a\" : \"other\""}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource?user=a"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource?user=a"
    Then the response status code should be 429
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource?user=b"
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A CEL key that cannot be evaluated still enforces the quota in one shared bucket
    Given I generate a unique value from "arl-key-cel-error" and store it as "apiName"
    And I generate a unique API version from "arl-key-cel-error" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-cel-error" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"cel-error","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"cel","expression":"request.Headers[\"x-absent\"][0]"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
