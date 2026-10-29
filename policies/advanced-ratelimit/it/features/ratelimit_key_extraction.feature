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

@ratelimit-key-extraction
Feature: Advanced rate limit key extraction strategies
  As an API developer
  I want to scope quota buckets by user, IP, API, route, or a composite key
  So that different callers or resources are rate-limited independently

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: An apiname key scopes a quota across every route attaching it
    Given I generate a unique value from "arl-key-apiname" and store it as "apiName"
    And I generate a unique API version from "arl-key-apiname" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-apiname" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/route0"},{"method":"GET","path":"/route1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"api-quota","limits":[{"limit":10,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]},{"method":"GET","path":"/route2","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"api-quota","limits":[{"limit":10,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route0" until status 200

    When I send 5 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200

    When I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A header key scopes a quota per user
    Given I generate a unique value from "arl-key-header-user" and store it as "apiName"
    And I generate a unique API version from "arl-key-header-user" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-header-user" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/user","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-user-limit","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "X-User-ID" to "user-A"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/user"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-A"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/user"
    Then the response status code should be 429

    When I set header "X-User-ID" to "user-B"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/user"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/user"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An ip key scopes a quota per client IP
    Given I generate a unique value from "arl-key-ip" and store it as "apiName"
    And I generate a unique API version from "arl-key-ip" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-ip" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-ip-limit","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"ip"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "X-Forwarded-For" to "192.168.1.100"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-Forwarded-For" to "192.168.1.100"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I set header "X-Forwarded-For" to "192.168.1.200"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-Forwarded-For" to "192.168.1.200"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A composite key combines the API name and a header value
    Given I generate a unique value from "arl-key-composite" and store it as "apiName"
    And I generate a unique API version from "arl-key-composite" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-composite" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-user-per-api","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"apiname"},{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "X-User-ID" to "user-A"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-A"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I set header "X-User-ID" to "user-B"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Two different APIs using apiname keys never share a bucket
    Given I generate a unique value from "arl-key-apiname-iso-a" and store it as "apiNameA"
    And I generate a unique API version from "arl-key-apiname-iso-a" and store it as "apiVersionA"
    And I generate a unique API context from "/arl-key-apiname-iso-a" and store it as "apiContextA"
    And I generate a unique value from "arl-key-apiname-iso-b" and store it as "apiNameB"
    And I generate a unique API version from "arl-key-apiname-iso-b" and store it as "apiVersionB"
    And I generate a unique API context from "/arl-key-apiname-iso-b" and store it as "apiContextB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiNameA}                  |
      | spec.displayName       | ${CTX:apiNameA}                  |
      | spec.version           | ${CTX:apiVersionA}               |
      | spec.context           | ${CTX:apiContextA}/$version      |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"api-quota","limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/health" until status 200

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiNameB}                  |
      | spec.displayName       | ${CTX:apiNameB}                  |
      | spec.version           | ${CTX:apiVersionB}               |
      | spec.context           | ${CTX:apiContextB}/$version      |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"api-quota","limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContextB}/${CTX:apiVersionB}/health" until status 200

    When I send 5 "GET" requests to "${CTX:apiContextA}/${CTX:apiVersionA}/resource"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I send 5 "GET" requests to "${CTX:apiContextB}/${CTX:apiVersionB}/resource"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContextB}/${CTX:apiVersionB}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I send a "GET" request to "${CTX:apiContextA}/${CTX:apiVersionA}/resource"
    Then the response status code should be 429

    When I delete the API "${CTX:apiNameA}"
    Then the response should be successful

    When I delete the API "${CTX:apiNameB}"
    Then the response should be successful

  Scenario: A constant key groups selected routes into one shared bucket
    Given I generate a unique value from "arl-key-constant" and store it as "apiName"
    And I generate a unique API version from "arl-key-constant" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-constant" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/group-a-1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"apiname"},{"type":"constant","key":"group-A"}]}]}}]},{"method":"GET","path":"/group-a-2","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"apiname"},{"type":"constant","key":"group-A"}]}]}}]},{"method":"GET","path":"/group-b-1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"apiname"},{"type":"constant","key":"group-B"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/group-a-1"
    Then the response status code should be 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/group-a-2"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/group-a-1"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/group-a-2"
    Then the response status code should be 429

    When I send 5 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/group-b-1"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/group-b-1"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A CEL expression extracts a per-user key from a request header
    Given I generate a unique value from "arl-key-cel" and store it as "apiName"
    And I generate a unique API version from "arl-key-cel" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-cel" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-user-cel","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"cel","expression":"request.Headers[\"x-user-id\"][0]"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "X-User-ID" to "cel-user-A"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "cel-user-A"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I set header "X-User-ID" to "cel-user-B"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "cel-user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A CEL composite expression combines the API name and a header value
    Given I generate a unique value from "arl-key-cel-composite" and store it as "apiName"
    And I generate a unique API version from "arl-key-cel-composite" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-cel-composite" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-user-per-api-cel","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"cel","expression":"api.Name + \":\" + request.Headers[\"x-user-id\"][0]"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "X-User-ID" to "composite-user-A"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "composite-user-A"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I set header "X-User-ID" to "composite-user-B"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A CEL expression extracts cost from a request header
    Given I generate a unique value from "arl-key-cel-cost" and store it as "apiName"
    And I generate a unique API version from "arl-key-cel-cost" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-cel-cost" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"token-quota-cel","limits":[{"limit":100,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"request_cel","expression":"int(request.Headers[\"x-token-cost\"][0])"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Token-Cost" to "40"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "60"

    When I set header "X-Token-Cost" to "40"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "20"

    When I set header "X-Token-Cost" to "30"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A quota with no keyExtraction inherits the global key
    Given I generate a unique value from "arl-key-global-inherit" and store it as "apiName"
    And I generate a unique API version from "arl-key-global-inherit" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-global-inherit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"keyExtraction":[{"type":"header","key":"X-User-ID"}],"quotas":[{"name":"inherited-global-key-limit","limits":[{"limit":3,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-User-ID" to "user-A"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-A"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I set header "X-User-ID" to "user-B"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A quota-level key overrides the global key
    Given I generate a unique value from "arl-key-override" and store it as "apiName"
    And I generate a unique API version from "arl-key-override" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-override" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"keyExtraction":[{"type":"header","key":"X-User-ID"}],"quotas":[{"name":"override-key-limit","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"constant","key":"shared-group"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-User-ID" to "user-A"
    And I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A missing header key component still enforces the quota
    Given I generate a unique value from "arl-key-missing-header" and store it as "apiName"
    And I generate a unique API version from "arl-key-missing-header" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-missing-header" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"missing-header-quota","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An empty global keyExtraction defaults each route to its own bucket
    Given I generate a unique value from "arl-key-empty-global" and store it as "apiName"
    And I generate a unique API version from "arl-key-empty-global" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-empty-global" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/route1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"keyExtraction":[],"quotas":[{"name":"default-route-key","limits":[{"limit":2,"duration":"1h"}]}]}}]},{"method":"GET","path":"/route2","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"keyExtraction":[],"quotas":[{"name":"default-route-key","limits":[{"limit":2,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 429

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Global and per-quota key extraction are enforced independently
    Given I generate a unique value from "arl-key-mixed" and store it as "apiName"
    And I generate a unique API version from "arl-key-mixed" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-mixed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"keyExtraction":[{"type":"header","key":"X-User-ID"}],"quotas":[{"name":"per-user-quota","limits":[{"limit":2,"duration":"1h"}]},{"name":"shared-quota","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"constant","key":"shared"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-User-ID" to "user-A"
    And I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-User-ID" to "user-B"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An apiversion key still scopes independently per route-level policy
    Given I generate a unique value from "arl-key-apiversion" and store it as "apiName"
    And I generate a unique API version from "arl-key-apiversion" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-apiversion" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/route1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"version-shared-quota","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"apiversion"}]}]}}]},{"method":"GET","path":"/route2","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"version-shared-quota","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"apiversion"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200

    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An ip key prioritizes X-Forwarded-For over X-Real-IP
    Given I generate a unique value from "arl-key-ip-precedence" and store it as "apiName"
    And I generate a unique API version from "arl-key-ip-precedence" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-ip-precedence" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"ip-precedence-quota","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"ip"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    Given I set header "X-Forwarded-For" to "192.168.10.10"
    When I set header "X-Real-IP" to "10.0.0.1"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-Real-IP" to "10.0.0.2"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I set header "X-Real-IP" to "10.0.0.3"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A missing component in a composite key still enforces the quota
    Given I generate a unique value from "arl-key-missing-composite" and store it as "apiName"
    And I generate a unique API version from "arl-key-missing-composite" and store it as "apiVersion"
    And I generate a unique API context from "/arl-key-missing-composite" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"missing-composite-quota","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"apiname"},{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An apiname-scoped quota's state survives one sharing route switching to its own quota
    Given I generate a unique value from "arl-refcount" and store it as "apiName"
    And I generate a unique API version from "arl-refcount" and store it as "apiVersion"
    And I generate a unique API context from "/arl-refcount" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/route1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"shared-api-quota","limits":[{"limit":10,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]},{"method":"GET","path":"/route2","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"shared-api-quota","limits":[{"limit":10,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200
    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/route2"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route1"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "5"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/route1","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"route-specific-quota","limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"routename"}]}]}}]},{"method":"GET","path":"/route2","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"shared-api-quota","limits":[{"limit":10,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}]}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/route2" until status 200
    Then the response header "X-RateLimit-Remaining" should be "4"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A match condition limits a quota to requests whose header value matches
    Given I generate a unique value from "arl-match-header" and store it as "apiName"
    And I generate a unique API version from "arl-match-header" and store it as "apiVersion"
    And I generate a unique API context from "/arl-match-header" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/checkout","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"guest-and-partner-checkout","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-App-ID","match":{"type":"regex","value":"^(guest-.*\|channel-partner)$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    # A matching value is counted against its own bucket.
    When I set header "X-App-ID" to "guest-42"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    # Another matching value gets a separate bucket.
    When I set header "X-App-ID" to "channel-partner"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # A value that does not match skips the quota, so it is never throttled.
    When I set header "X-App-ID" to "internal-app-1"
    And I send 6 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Each quota counts only requests matching its own pattern, against its own limit
    Given I generate a unique value from "arl-match-per-customer" and store it as "apiName"
    And I generate a unique API version from "arl-match-per-customer" and store it as "apiVersion"
    And I generate a unique API context from "/arl-match-per-customer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/checkout","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"customer-abc","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-App-ID","match":{"type":"regex","value":"^abc-.*$"}}]},{"name":"customer-xyz","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-App-ID","match":{"type":"regex","value":"^xyz-.*$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    # customer-abc allows 2 requests.
    When I set header "X-App-ID" to "abc-1"
    And I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    # customer-xyz allows 3, unaffected by customer-abc being exhausted.
    When I set header "X-App-ID" to "xyz-1"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # customer-xyz's traffic did not touch customer-abc's bucket.
    When I set header "X-App-ID" to "abc-1"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # A value matching neither pattern is never throttled.
    When I set header "X-App-ID" to "internal-app-1"
    And I send 6 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # jwt-auth runs before advanced-ratelimit and puts the token's claims in the auth context,
  # where an authproperty key reads them.
  Scenario: A match condition on an authproperty key limits a quota to tokens whose claim matches
    Given I generate a unique value from "arl-match-authproperty" and store it as "apiName"
    And I generate a unique API version from "arl-match-authproperty" and store it as "apiVersion"
    And I generate a unique API context from "/arl-match-authproperty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/checkout","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"guest-and-partner-checkout","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"authproperty","key":"app_id","match":{"type":"regex","value":"^(guest-.*\|channel-partner)$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout" until status 401

    # A token whose app_id matches is counted against its own bucket.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "app_id=guest-42" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    # Another matching app_id gets a separate bucket.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "app_id=channel-partner" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # An app_id that does not match skips the quota, so it is never throttled.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "app_id=internal-app-1" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send 6 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: A match on one claim filters the quota while the bucket counts by another claim
    Given I generate a unique value from "arl-match-filter-count" and store it as "apiName"
    And I generate a unique API version from "arl-match-filter-count" and store it as "apiVersion"
    And I generate a unique API context from "/arl-match-filter-count" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/checkout","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"guests-per-user","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"authproperty","key":"app_id","match":{"type":"regex","value":"^123$"}},{"type":"authproperty","key":"user_id"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout" until status 401

    # app_id 123 matches, so alice's requests are counted.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "app_id=123,user_id=alice" and store it as "aliceToken"
    And I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    # bob has the same app_id but his own bucket.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "app_id=123,user_id=bob" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # bob's traffic did not touch alice's bucket.
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # app_id 456 does not match, so alice is not throttled there: a 4th request still passes,
    # which a separate bucket of 3 would not allow.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "app_id=456,user_id=alice" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200

    # The non-matching traffic did not touch alice's app_id 123 bucket either.
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
