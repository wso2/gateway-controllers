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

@azure-authentication
Feature: Azure Authentication policy
  As an API developer
  I want the gateway to call Entra ID-protected Azure services with a token for its workload identity
  So that no Azure key needs to be stored on the API or LLM provider

  # Obtaining a Microsoft Entra ID token for the gateway's Azure Workload Identity and sending it
  # upstream: token delivery and sharing, parameters, failures and recovery, policy changes on a
  # deployed API, and LLM providers. Rejected configurations, gateway restarts and an unreadable
  # federated token are in the other azure_authentication_*.feature files.
  #
  # The gateway runtime's identity is tenant 7f3c2a10-4b5e-4c6d-8e9f-0a1b2c3d4e5f and client
  # 5d6e7f80-91a2-4b3c-8d4e-5f6a7b8c9d0e, its authority is the testbench entra service at
  # https://testbench:3028/ and its federated token is "testbench-federated-identity-token".
  # The entra service issues tokens at /<tenant>/oauth2/v2.0/token and records every token request
  # at /<tenant>/test/requests. Its Entra-protected resources, http://testbench:3027/<tenant>/foundry
  # (audience https://ai.azure.com) and .../cognitive (audience https://cognitiveservices.azure.com),
  # answer a valid token with a chat completion echoing the request headers, anything else with
  # 401, and report the token they received in the X-Testbench-Entra-Token, -Tid and -Aud response
  # headers.
  #
  # Every scenario that counts token requests or picks a failure mode names its own tenant through
  # the tenantId parameter; the tenant is also its partition and its key in the policy's token cache.
  # A tenant prefix picks the failure: invalid-client- (401, AADSTS700213), reject-once-,
  # throttle-once- (429 with Retry-After), error-once- (500), unavailable- (503), slow- (3 seconds)
  # and refresh-soon- (a first token due for refresh after 2 seconds).
  #
  # The federated token is "testbench-federated-identity-token" and every issued token starts with
  # "testbench-entra.", so a response or log without either discloses no credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The gateway's own identity and the default scope: the upstream receives a token for
  # https://ai.azure.com issued to the runtime's tenant and client. The scenario counts nothing,
  # because every scenario that omits tenantId shares the runtime's tenant.
  Scenario: The upstream receives an Entra token for the gateway's identity and the default scope
    Given I generate a unique value from "az-default" and store it as "apiName"
    And I generate a unique API version from "az-default" and store it as "apiVersion"
    And I generate a unique API context from "/az-default" and store it as "apiContext"
    And I generate a unique resource name from "az-res" and store it as "resourcePartition"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                                                                            |
      | name                   | ${CTX:apiName}                                                                                       |
      | spec.displayName       | ${CTX:apiName}                                                                                       |
      | spec.version           | ${CTX:apiVersion}                                                                                    |
      | spec.context           | ${CTX:apiContext}/$version                                                                           |
      | spec.upstream.main.url | http://testbench:3027/${CTX:resourcePartition}/foundry                                               |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}]                                                       |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Aud" should be "https://ai.azure.com"
    And the response header "X-Testbench-Entra-Tid" should be "7f3c2a10-4b5e-4c6d-8e9f-0a1b2c3d4e5f"
    And the JSON response field "token.appid" should be "5d6e7f80-91a2-4b3c-8d4e-5f6a7b8c9d0e"
    And the response should contain echoed header "Authorization" containing "Bearer testbench-entra."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
