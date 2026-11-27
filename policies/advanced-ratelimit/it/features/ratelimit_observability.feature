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

@ratelimit-observability
Feature: Advanced rate limit observability and failure handling
  As an API operator
  I want throttling to be visible without leaking internals
  So that I can diagnose it from responses and logs, and a failing backend still counts against the quota

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A throttled response names the quota but exposes no internal detail
    Given I generate a unique value from "arl-obs-429" and store it as "apiName"
    And I generate a unique API version from "arl-obs-429" and store it as "apiVersion"
    And I generate a unique API context from "/arl-obs-429" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"obs-quota","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-Obs-Key"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Obs-Key" to "obs-secret-marker-7f3a"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "obs-quota"
    And the response header "Retry-After" should exist
    And the response header "Content-Type" should contain "application/json"
    And the response body should not contain "obs-secret-marker-7f3a"
    And the response body should not contain "quota exceeded"
    And the response body should not contain "redis"
    And the response header "X-RateLimit-Remaining" should be "0"
    And the "gateway-runtime" service logs should not contain "obs-secret-marker-7f3a"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A missing key component is reported in the policy engine log
    Given I generate a unique value from "arl-obs-missing" and store it as "apiName"
    And I generate a unique API version from "arl-obs-missing" and store it as "apiVersion"
    And I generate a unique API context from "/arl-obs-missing" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"obs-missing","limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-Obs-Absent"},{"type":"authproperty","key":"obs_claim"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the "gateway-runtime" service logs should contain "_missing_header_X-Obs-Absent_"
    And the "gateway-runtime" service logs should contain "_missing_authproperty_obs_claim_"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Requests the backend fails still count against the quota and keep their status
    Given I generate a unique value from "arl-obs-backend-5xx" and store it as "apiName"
    And I generate a unique API version from "arl-obs-backend-5xx" and store it as "apiVersion"
    And I generate a unique API context from "/arl-obs-backend-5xx" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3002            |
      | spec.operations        | [{"method":"GET","path":"/ok"},{"method":"GET","path":"/status/{code}","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"backend-failures","limits":[{"limit":2,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ok" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/status/503"
    Then the response status code should be 503
    And the response header "X-RateLimit-Limit" should be "2"
    And the response header "X-RateLimit-Remaining" should be "1"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/status/500"
    Then the response status code should be 500
    And the response header "X-RateLimit-Remaining" should be "0"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/status/200"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
