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
Feature: Azure Authentication policy configuration validation
  As an API developer
  I want invalid Azure Authentication configurations to be rejected
  So that an API that could never obtain a token is never deployed

  # Configurations the gateway rejects when the API is created: policy parameters or a policy
  # version that do not match the policy definition. Parameters given through an LLM provider's
  # upstream.auth are not validated when the provider is created; that case is in
  # azure_authentication.feature. A rejected API is not stored, so the controller has no API of
  # that name afterwards.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The controller validates the policy reference and its parameters against the policy
  # definition: authenticationType is a required string, workload-identity or managed-identity,
  # scope ends in /.default, clientId is a GUID, tenantId a GUID or domain name, headerName an HTTP
  # token, tokenRequestTimeout whole seconds up to 30s or milliseconds up to 30000ms, valuePrefix has
  # no control characters, and the policy version must be a major version the gateway has loaded.
  Scenario Outline: Validate invalid policy configuration, including missing or unsupported authentication type, malformed identity, scope, header, prefix and timeout, and unsupported policy version (<case>)
    Given I generate a unique value from "az-invalid-config" and store it as "apiName"
    And I generate a unique API version from "az-invalid-config" and store it as "apiVersion"
    And I generate a unique API context from "/az-invalid-config" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                                                      |
      | name                   | ${CTX:apiName}                                                                 |
      | spec.displayName       | ${CTX:apiName}                                                                 |
      | spec.version           | ${CTX:apiVersion}                                                              |
      | spec.context           | ${CTX:apiContext}/$version                                                     |
      | spec.upstream.main.url | http://testbench:3027/az-invalid-config/foundry                                |
      | spec.policies          | [{"name":"azure-authentication","version":"<version>","params":{<params>}}]   |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}]                                 |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<error>"
    And the response body should contain "<field>"

    When I get the API "${CTX:apiName}"
    Then the response status code should be 404

    Examples:
      | case                                 | version | params                                                                                   | error                                                      | field                      |
      | missing authentication type          | v0      | "scope":"https://ai.azure.com/.default"                                                  | authenticationType is required                             | authenticationType         |
      | unsupported authentication type      | v0      | "authenticationType":"client-secret"                                                     | authenticationType must be one of the following            | params.authenticationType  |
      | scope as an array                    | v0      | "authenticationType":"workload-identity","scope":["https://ai.azure.com/.default"]       | Invalid type. Expected: string, given: array               | params.scope               |
      | scope without /.default              | v0      | "authenticationType":"workload-identity","scope":"https://ai.azure.com"                  | Does not match pattern                                     | params.scope               |
      | client ID that is not a GUID         | v0      | "authenticationType":"workload-identity","clientId":"not-a-guid"                         | Does not match pattern                                     | params.clientId            |
      | tenant ID with a slash               | v0      | "authenticationType":"workload-identity","tenantId":"tenant/evil"                        | Does not match pattern                                     | params.tenantId            |
      | header name with a space             | v0      | "authenticationType":"workload-identity","headerName":"Bad Header"                       | Does not match pattern                                     | params.headerName          |
      | token request timeout over 30s       | v0      | "authenticationType":"workload-identity","tokenRequestTimeout":"45s"                     | Does not match pattern                                     | params.tokenRequestTimeout |
      | token request timeout in minutes     | v0      | "authenticationType":"workload-identity","tokenRequestTimeout":"1m"                      | Does not match pattern                                     | params.tokenRequestTimeout |
      | value prefix with a line break       | v0      | "authenticationType":"workload-identity","valuePrefix":"Bearer\\r\\nX-Injected: 1"       | Does not match pattern                                     | params.valuePrefix         |
      | unsupported policy version           | v99     | "authenticationType":"workload-identity"                                                 | major version 'v99' not found in loaded policy definitions | v99                        |
