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

@ratelimit-match
Feature: Advanced rate limit conditional quotas
  As an API developer
  I want a quota to apply only to requests whose key matches a pattern
  So that selected clients are throttled while every other client bypasses the quota entirely

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A header key with a match pattern limits only the matching values
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
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/checkout","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"guest-and-partner","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-App-ID","match":{"type":"regex","value":"^(guest-.*\|channel-partner)$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # A matching value is counted per bucket and throttled.
    When I set header "X-App-ID" to "guest-42"
    And I send 2 "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "2"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    # Another matching value has a bucket of its own.
    When I set header "X-App-ID" to "channel-partner"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "1"

    # A non-matching value bypasses the quota: never counted, never throttled, no rate limit headers.
    When I set header "X-App-ID" to "internal-app"
    And I send 6 "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist
    And the response header "RateLimit-Policy" should not exist

    # A missing header yields a placeholder that does not match either.
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send 3 "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Every component that declares a match must match for the quota to apply
    Given I generate a unique value from "arl-match-and" and store it as "apiName"
    And I generate a unique API version from "arl-match-and" and store it as "apiVersion"
    And I generate a unique API context from "/arl-match-and" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"acme-gold","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-Tenant","match":{"type":"regex","value":"^acme$"}},{"type":"header","key":"X-Tier","match":{"type":"regex","value":"^gold$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Tenant" to "acme"
    And I set header "X-Tier" to "silver"
    And I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist

    When I set header "X-Tenant" to "globex"
    And I set header "X-Tier" to "gold"
    And I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist

    When I set header "X-Tenant" to "acme"
    And I set header "X-Tier" to "gold"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "1"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A CEL key with a match pattern applies the same conditional rule in the body phase
    Given I generate a unique value from "arl-match-cel" and store it as "apiName"
    And I generate a unique API version from "arl-match-cel" and store it as "apiVersion"
    And I generate a unique API context from "/arl-match-cel" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"vip-only","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"cel","expression":"request.Headers[\"x-app-id\"][0]","match":{"type":"regex","value":"^vip-.*$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-App-ID" to "vip-1"
    And I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I set header "X-App-ID" to "regular-1"
    And I send 5 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
