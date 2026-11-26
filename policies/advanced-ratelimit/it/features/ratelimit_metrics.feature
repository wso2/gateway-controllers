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

@ratelimit-metrics
Feature: Advanced rate limit throttling in the policy engine metrics
  As an API operator
  I want throttled requests to be visible in the policy engine metrics
  So that I can alert on throttling without reading logs, and without the metrics exposing client keys

  # The gateway of this runner has the Prometheus metrics of the policy engine and the controller
  # switched on (overlays/metrics.toml). A throttle is an immediate response, which the policy
  # engine counts as a short circuit of the policy that produced it.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A throttled request is counted as a short circuit of the policy and exposes no key
    Given I generate a unique value from "arl-metrics" and store it as "apiName"
    And I generate a unique API version from "arl-metrics" and store it as "apiVersion"
    And I generate a unique API context from "/arl-metrics" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"metered","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-Metrics-Key"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    Given I note the policy engine counter "short_circuits_total" for series labelled {policy_name="advanced-ratelimit"}
    When I set header "X-Metrics-Key" to "metrics-secret-marker-5d1c"
    And I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    Then the policy engine counter "short_circuits_total" for series labelled {policy_name="advanced-ratelimit"} should have grown by at least 1
    When I send a "GET" request to the "policy-engine-metrics" service at "/metrics"
    Then the response status code should be 200
    And the response body should not contain "metrics-secret-marker-5d1c"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # Older gateways count a policy's immediate response only as a short circuit; the execution
  # status "short_circuited" is newer than gateway 1.2.0.
  Scenario: A throttled request is recorded as a short-circuited execution of the policy
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "arl-metrics-status" and store it as "apiName"
    And I generate a unique API version from "arl-metrics-status" and store it as "apiVersion"
    And I generate a unique API context from "/arl-metrics-status" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"metered-status","limits":[{"limit":1,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    Given I note the policy engine counter "policy_executions_total" for series labelled {policy_name="advanced-ratelimit",status="short_circuited"}
    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the policy engine counter "policy_executions_total" for series labelled {policy_name="advanced-ratelimit",status="short_circuited"} should have grown by at least 1

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
