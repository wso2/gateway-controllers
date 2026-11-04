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

# The mock-jwks-appid key manager (overlays/gateway.toml) reads the application identity from the
# client_id claim; mock-jwks, with the same issuer and keys, does not. Controller calls clear the
# Bearer header first, so the admin's basic auth is the only credential they carry.
@jwt-auth-application-subscriptions
Feature: JWT application-based subscriptions
  As an API developer
  I want clients matched to their subscription through the application identity in their JWT
  So that they need no Subscription-Key header

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  @gateway-v1.2
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

  @gateway-v1.2
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

  @gateway-v1.2
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
