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

@ratelimit-auth-context
Feature: Advanced rate limit combined with jwt-auth
  As an API developer
  I want quotas keyed on a verified JWT claim and enforced after authentication
  So that throttling never replaces authentication and buckets follow the authenticated application

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Throttling does not bypass authentication and a rejected request consumes no quota
    Given I generate a unique value from "arl-jwt-order" and store it as "apiName"
    And I generate a unique API version from "arl-jwt-order" and store it as "apiVersion"
    And I generate a unique API context from "/arl-jwt-order" and store it as "apiContext"
    And I generate a unique value from "arl-jwt-app" and store it as "appId"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-app","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"authproperty","key":"app_id"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,app_id=${CTX:appId}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,app_id=${CTX:appId}" and store it as "bobToken"

    # Unauthenticated and badly authenticated requests are refused by jwt-auth, never throttled.
    When I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response header "X-RateLimit-Limit" should not exist
    When I set header "Authorization" to "Bearer invalid.jwt.token"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    # The refused requests consumed nothing: the whole quota of two is still there, and two users of
    # the same application share it.
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "1"
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "per-app"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Applications with different claim values are throttled in separate buckets
    Given I generate a unique value from "arl-jwt-buckets" and store it as "apiName"
    And I generate a unique API version from "arl-jwt-buckets" and store it as "apiVersion"
    And I generate a unique API context from "/arl-jwt-buckets" and store it as "apiContext"
    And I generate a unique value from "arl-jwt-app-one" and store it as "appOne"
    And I generate a unique value from "arl-jwt-app-two" and store it as "appTwo"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-app","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"authproperty","key":"app_id"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,app_id=${CTX:appOne}" and store it as "oneToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,app_id=${CTX:appTwo}" and store it as "twoToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice" and store it as "noClaimToken"

    When I set header "Authorization" to "Bearer ${CTX:oneToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429

    When I set header "Authorization" to "Bearer ${CTX:twoToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    # A token without the claim falls into the placeholder bucket, which is limited as well.
    When I set header "Authorization" to "Bearer ${CTX:noClaimToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A quota on a JWT claim with a match pattern throttles only the matching applications
    Given I generate a unique value from "arl-jwt-match" and store it as "apiName"
    And I generate a unique API version from "arl-jwt-match" and store it as "apiVersion"
    And I generate a unique API context from "/arl-jwt-match" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/checkout","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"guest-and-partner","limits":[{"limit":2,"duration":"1h"}],"keyExtraction":[{"type":"authproperty","key":"app_id","match":{"type":"regex","value":"^(guest-.*\|channel-partner)$"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,app_id=guest-42" and store it as "guestToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,app_id=internal-app" and store it as "internalToken"

    When I set header "Authorization" to "Bearer ${CTX:guestToken}"
    And I send 2 "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "2"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 429

    When I set header "Authorization" to "Bearer ${CTX:internalToken}"
    And I send 6 "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/checkout"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # jwt-auth publishes the application identity of a verified token in the shared metadata, where a
  # metadata key can read it.
  Scenario: A metadata key buckets requests by the application identity jwt-auth published
    Given I generate a unique value from "arl-jwt-metadata" and store it as "apiName"
    And I generate a unique API version from "arl-jwt-metadata" and store it as "apiVersion"
    And I generate a unique API context from "/arl-jwt-metadata" and store it as "apiContext"
    And I generate a unique value from "arl-meta-app-one" and store it as "clientOne"
    And I generate a unique value from "arl-meta-app-two" and store it as "clientTwo"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-application","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"metadata","key":"x-wso2-application-id"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:clientOne}" and store it as "oneToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:clientOne}" and store it as "oneOtherUserToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:clientTwo}" and store it as "twoToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=dave" and store it as "noClientToken"

    When I set header "Authorization" to "Bearer ${CTX:oneToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    # Two users of one application share the bucket.
    When I set header "Authorization" to "Bearer ${CTX:oneOtherUserToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429
    When I set header "Authorization" to "Bearer ${CTX:twoToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    # A token without the claim has no application identity: it shares the placeholder bucket.
    When I set header "Authorization" to "Bearer ${CTX:noClientToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429
    And the "gateway-runtime" service logs should contain "_missing_metadata_x-wso2-application-id_"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
