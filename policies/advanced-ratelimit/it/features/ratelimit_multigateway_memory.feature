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

@ratelimit-multigateway-memory
Feature: Advanced rate limit counters of the in-memory backend across two gateway replicas
  As an API operator who runs more than one gateway replica behind one control plane
  I want to know the in-memory backend counts per replica
  So that I do not mistake it for a shared quota and choose Redis when I need one

  # The API and its policy reach each replica through the control plane (platform-api), so these
  # scenarios address "the first/second gateway" explicitly. The gateways use the default backend,
  # memory, whose counters live in each replica's own process.

  Background:
    Given the first gateway is running
    And the second gateway is running
    And I authenticate using basic auth as "admin"
    And I generate a unique resource name from "arl-mg-mem-project" and store it as "projectHandle"
    And I create a project "${CTX:projectHandle}" on the control plane

  Scenario: Each replica enforces its own full quota
    Given I generate a unique resource name from "arl-mg-mem" and store it as "apiHandle"
    And I generate a unique API context from "/arl-mg-mem" and store it as "apiCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:apiCtx}" and the advanced-ratelimit quotas:
      """
      [{"name":"per-replica","limits":[{"limit":2,"duration":"1h"}]}]
      """
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    And I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane
    Then I send a "GET" request to the first gateway "${CTX:apiCtx}/health" until status 200
    And I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200

    When I send 2 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200
    When I send 1 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429

    # The first replica is exhausted, the second one has counted nothing.
    When I send 2 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    When I send 1 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429

  Scenario: Restarting a replica drops its in-memory counters and leaves the other replica's untouched
    Given I generate a unique resource name from "arl-mg-mem-restart" and store it as "apiHandle"
    And I generate a unique API context from "/arl-mg-mem-restart" and store it as "apiCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:apiCtx}" and the advanced-ratelimit quotas:
      """
      [{"name":"per-replica-restart","limits":[{"limit":2,"duration":"1h"}]}]
      """
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    And I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane
    Then I send a "GET" request to the first gateway "${CTX:apiCtx}/health" until status 200
    And I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200
    When I send 2 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    And I send 2 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200

    When I restart the "gateway-runtime-2" service
    And I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200
    And I send 1 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200
    When I send 1 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429

