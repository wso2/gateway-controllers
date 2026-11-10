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
Feature: Azure Authentication policy across gateway restarts
  As an API developer
  I want APIs using Azure Authentication to keep working when gateway services restart
  So that a restart does not interrupt access to Azure services

  # Restarting the gateway controller and the gateway runtime. It runs in a block of its own,
  # because a restart would interrupt any runner beside it. The testbench entra service records
  # every token request for the scenario's tenant at /<tenant>/test/requests; see
  # azure_authentication.feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The token cache lives in the gateway runtime: a controller restart leaves it in place, so no new
  # token is requested, and a runtime restart starts with an empty cache, so exactly one is.
  Scenario: Restart the controller and the runtime with Azure Authentication
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-restart" and store it as "apiName"
    And I generate a unique API version from "az-restart" and store it as "apiVersion"
    And I generate a unique API context from "/az-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    When I send a "GET" request to the "entra" service at "/${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 1

    When I restart the "gateway-controller" service
    And I wait for the gateway controller health endpoint
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"
    When I send a "GET" request to the "entra" service at "/${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 1

    When I restart the "gateway-runtime" service
    And I send a GET request to the router ready endpoint until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"
    When I send a "GET" request to the "entra" service at "/${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
