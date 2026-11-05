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

# The key managers are in overlays/application-identity.toml and share the testbench issuer and
# keys: mock-jwks-appid reads the application identity from client_id, mock-jwks-wso2appid from
# wso2_app_id, and mock-jwks sets none. Controller calls clear the gateway headers first, so the
# admin's basic auth is the only credential they carry.
@jwt-auth-application-subscriptions
Feature: JWT application-based subscriptions
  As an API developer
  I want clients matched to their subscription through the application identity in their JWT
  So that they need no Subscription-Key header

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: a subscription matches the client_id of a validated token until it is revoked
    Given I generate a unique value from "jwt-app-sub" and store it as "apiName"
    And I generate a unique API version from "jwt-app-sub" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-sub" and store it as "apiContext"
    And I generate a unique value from "jwt-app-sub-client" and store it as "subscribedClient"
    And I generate a unique value from "jwt-app-sub-other" and store it as "otherClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-unused-token"}
      """
    Then the response status should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # The subscribed client is allowed once the subscription reaches the policy engine.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    # A client without a subscription to this API is rejected.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:otherClient}" and store it as "otherToken"
    And I set header "Authorization" to "Bearer ${CTX:otherToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403
    And the response body should contain "Subscription required for this API"

    # A token without the claim carries no application identity.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "noClaimToken"
    And I set header "Authorization" to "Bearer ${CTX:noClaimToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403
    And the response body should contain "no subscription token or application identity provided"

    # A revoked subscription rejects the client from the next request on.
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "PUT" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}" with body:
      """
      {"status":"REVOKED"}
      """
    Then the response status should be 200
    When I clear all headers
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: a Subscription-Key header is validated before the token's application identity
    Given I generate a unique value from "jwt-app-sub-key" and store it as "apiName"
    And I generate a unique API version from "jwt-app-sub-key" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-sub-key" and store it as "apiContext"
    And I generate a unique value from "jwt-app-sub-key-client" and store it as "subscribedClient"
    And I generate a unique value from "jwt-app-sub-key-other" and store it as "otherClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-key"}
      """
    Then the response status should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # A client with no subscription of its own is allowed through by a valid Subscription-Key.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:otherClient}" and store it as "otherToken"
    And I set header "Authorization" to "Bearer ${CTX:otherToken}"
    And I set header "Subscription-Key" to "${CTX:subscribedClient}-key"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    # A subscribed client presenting an unknown Subscription-Key is rejected: the key is checked
    # first and there is no fall back to the token's application identity.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I set header "Subscription-Key" to "not-a-subscription-key"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: a key manager without applicationIdClaim sets no application identity
    Given I generate a unique value from "jwt-app-sub-off" and store it as "apiName"
    And I generate a unique API version from "jwt-app-sub-off" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-sub-off" and store it as "apiContext"
    And I generate a unique value from "jwt-app-sub-off-client" and store it as "subscribedClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/with-claim","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-unused-token"}
      """
    Then the response status should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # The subscription is live: the operation whose key manager reads client_id allows the client.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/with-claim" until status 200

    # The same token on the operation whose key manager does not read the claim is rejected.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403
    And the response body should contain "no subscription token or application identity provided"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: each key manager reads only its own application identity claim
    Given I generate a unique value from "jwt-app-claim" and store it as "apiName"
    And I generate a unique API version from "jwt-app-claim" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-claim" and store it as "apiContext"
    And I generate a unique value from "jwt-app-claim-client" and store it as "subscribedClient"
    And I generate a unique value from "jwt-app-claim-other" and store it as "otherClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-wso2appid"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-unused-token"}
      """
    Then the response status code should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # mock-jwks-wso2appid reads wso2_app_id, so a token's client_id does not decide the match.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "wso2_app_id=${CTX:subscribedClient},client_id=${CTX:otherClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "wso2_app_id=${CTX:otherClient},client_id=${CTX:subscribedClient}" and store it as "otherToken"
    And I set header "Authorization" to "Bearer ${CTX:otherToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403
    And the response body should contain "Subscription required for this API"

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "clientIdOnlyToken"
    And I set header "Authorization" to "Bearer ${CTX:clientIdOnlyToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403
    And the response body should contain "no subscription token or application identity provided"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: the users of an application share its plan quota, and its Subscription-Key is counted apart
    Given I generate a unique value from "jwt-app-plan" and store it as "apiName"
    And I generate a unique API version from "jwt-app-plan" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-plan" and store it as "apiContext"
    And I generate a unique value from "jwt-app-plan-tier" and store it as "planName"
    And I generate a unique value from "jwt-app-plan-client" and store it as "subscribedClient"
    And I generate a unique value from "jwt-app-plan-other" and store it as "otherClient"
    When I send a "POST" request to the "gateway-controller" service at "/subscription-plans" with body:
      """
      {"planName":"${CTX:planName}","throttleLimitCount":3,"throttleLimitUnit":"Min","stopOnQuotaReach":true}
      """
    Then the response status code should be 201
    And I store the JSON response field "id" as "planId"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.subscriptionPlans | ["${CTX:planName}"]                |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionPlanId":"${CTX:planId}","subscriptionToken":"${CTX:subscribedClient}-key"}
      """
    Then the response status code should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # The plan allows 3 requests a minute for the application, whichever of its users sends them.
    # Rejected requests are not counted, so the first 200 below is the application's first request.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:subscribedClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:subscribedClient}" and store it as "bobToken"
    And I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429
    And the response body should contain "Subscription quota exceeded"

    # The subscription's key is counted under the key, not under the application.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:otherClient}" and store it as "otherToken"
    And I set header "Authorization" to "Bearer ${CTX:otherToken}"
    And I set header "Subscription-Key" to "${CTX:subscribedClient}-key"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
    When I send a "DELETE" request to the "gateway-controller" service at "/subscription-plans/${CTX:planId}"
    Then the response should be successful

  Scenario: an application is matched per API, and only while its subscription is active
    Given I generate a unique value from "jwt-app-apis" and store it as "apiName"
    And I generate a unique value from "jwt-app-apis-other" and store it as "otherApiName"
    And I generate a unique API version from "jwt-app-apis" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-apis" and store it as "apiContext"
    And I generate a unique API context from "/jwt-app-apis-other" and store it as "otherApiContext"
    And I generate a unique value from "jwt-app-apis-client" and store it as "subscribedClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:otherApiName}               |
      | spec.displayName       | ${CTX:otherApiName}               |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:otherApiContext}/$version   |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/protected","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "GET" request to "${CTX:otherApiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-unused-token"}
      """
    Then the response status code should be 201
    And I store the JSON response field "id" as "subscriptionId"

    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200
    And I send a "GET" request to "${CTX:otherApiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 403
    And the response body should contain "Subscription required for this API"

    # An inactive subscription rejects the application until it is active again.
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "PUT" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}" with body:
      """
      {"status":"INACTIVE"}
      """
    Then the response status code should be 200
    When I clear all headers
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "PUT" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}" with body:
      """
      {"status":"ACTIVE"}
      """
    Then the response status code should be 200
    When I clear all headers
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I delete the API "${CTX:otherApiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: the authentication policy that runs last sets the application identity
    Given I generate a unique value from "jwt-app-apikey" and store it as "apiName"
    And I generate a unique API version from "jwt-app-apikey" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-apikey" and store it as "apiContext"
    And I generate a unique value from "jwt-app-apikey-client" and store it as "subscribedClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/key-then-jwt","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"subscription-validation","version":"v1"}]},{"method":"GET","path":"/jwt-then-key","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # An API key created through the gateway controller belongs to no application.
    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"jwt-app-apikey-caller"}
      """
    Then the response status code should be 201
    And I store the JSON response field "apiKey.apiKey" as "callerKey"
    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-unused-token"}
      """
    Then the response status code should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # jwt-auth runs after api-key-auth and replaces the key's empty application with client_id.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Bearer ${CTX:subscribedToken}"
    And I set header "API-Key" to "${CTX:callerKey}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/key-then-jwt" until status 200

    # api-key-auth runs last and overwrites the identity with the key's empty application.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/jwt-then-key"
    Then the response status code should be 403
    And the response body should contain "no subscription token or application identity provided"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: basic-auth sets no application identity, and jwt-auth beside it does
    Given I generate a unique value from "jwt-app-basic" and store it as "apiName"
    And I generate a unique API version from "jwt-app-basic" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-basic" and store it as "apiContext"
    And I generate a unique value from "jwt-app-basic-client" and store it as "subscribedClient"
    And I generate a unique value from "jwt-app-basic-other" and store it as "otherClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/basic-only","policies":[{"name":"basic-auth","version":"v1","params":{"username":"svc","password":"svc-pass"}},{"name":"subscription-validation","version":"v1"}]},{"method":"GET","path":"/basic-then-jwt","policies":[{"name":"basic-auth","version":"v1","params":{"username":"svc","password":"svc-pass"}},{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"],"headerName":"X-JWT"}},{"name":"subscription-validation","version":"v1"}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName}","applicationId":"${CTX:subscribedClient}","subscriptionToken":"${CTX:subscribedClient}-unused-token"}
      """
    Then the response status code should be 201
    And I store the JSON response field "id" as "subscriptionId"

    # The JWT travels in X-JWT because basic-auth reads Authorization. "c3ZjOnN2Yy1wYXNz" is svc:svc-pass.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:subscribedClient}" and store it as "subscribedToken"
    And I set header "Authorization" to "Basic c3ZjOnN2Yy1wYXNz"
    And I set header "X-JWT" to "Bearer ${CTX:subscribedToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/basic-then-jwt" until status 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/basic-only"
    Then the response status code should be 403
    And the response body should contain "no subscription token or application identity provided"

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "client_id=${CTX:otherClient}" and store it as "otherToken"
    And I set header "X-JWT" to "Bearer ${CTX:otherToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/basic-then-jwt"
    Then the response status code should be 403
    And the response body should contain "Subscription required for this API"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "DELETE" request to the "gateway-controller" service at "/subscriptions/${CTX:subscriptionId}"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
