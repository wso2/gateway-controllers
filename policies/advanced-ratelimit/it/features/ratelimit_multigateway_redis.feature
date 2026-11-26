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

@ratelimit-multigateway-redis
Feature: Advanced rate limit quota shared by two gateway replicas through Redis
  As an API operator who runs more than one gateway replica behind one control plane
  I want one quota enforced across every replica
  So that the number of replicas never multiplies the limit, including for a replica that joins later

  # The API and its policy reach each replica through the control plane (platform-api). The
  # gateways use fixed-window over Redis (overlays/redis.toml).

  Background:
    Given the first gateway is running
    And the second gateway is running
    And I authenticate using basic auth as "admin"
    And I generate a unique resource name from "arl-mg-redis-project" and store it as "projectHandle"
    And I create a project "${CTX:projectHandle}" on the control plane

  Scenario: Requests through either replica draw on the same quota
    Given I generate a unique resource name from "arl-mg-shared" and store it as "apiHandle"
    And I generate a unique API context from "/arl-mg-shared" and store it as "apiCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:apiCtx}" and the advanced-ratelimit quotas:
      """
      [{"name":"shared","limits":[{"limit":4,"duration":"1h"}]}]
      """
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    And I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane
    Then I send a "GET" request to the first gateway "${CTX:apiCtx}/health" until status 200
    And I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200

    When I send 2 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "2"
    When I send 2 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"

    When I send 1 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429
    When I send 1 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429

  Scenario: A replica that receives the API later is bound by the quota already consumed
    Given I generate a unique resource name from "arl-mg-late" and store it as "apiHandle"
    And I generate a unique API context from "/arl-mg-late" and store it as "apiCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:apiCtx}" and the advanced-ratelimit quotas:
      """
      [{"name":"late-join","limits":[{"limit":2,"duration":"1h"}]}]
      """
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    Then I send a "GET" request to the first gateway "${CTX:apiCtx}/health" until status 200
    When I send 2 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200
    When I send 1 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429

    When I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane
    Then I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200
    # The replica has to see the count Redis already holds; polling tolerates the moment between a
    # route answering and its policy chain being loaded, when a request is not yet counted.
    When I send a "GET" request to the second gateway "${CTX:apiCtx}/limited" until status 429

  Scenario: Restarting one replica keeps its quota, which lives in Redis
    Given I generate a unique resource name from "arl-mg-restart" and store it as "apiHandle"
    And I generate a unique API context from "/arl-mg-restart" and store it as "apiCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:apiCtx}" and the advanced-ratelimit quotas:
      """
      [{"name":"restart-shared","limits":[{"limit":2,"duration":"1h"}]}]
      """
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    And I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane
    Then I send a "GET" request to the first gateway "${CTX:apiCtx}/health" until status 200
    And I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200
    When I send 2 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 200

    When I restart the "gateway-runtime-2" service
    And I send a "GET" request to the second gateway "${CTX:apiCtx}/health" until status 200
    And I send 1 "GET" requests to the second gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429
    When I send 1 "GET" requests to the first gateway "${CTX:apiCtx}/limited"
    Then the response status code should be 429
