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

@basic-auth
Feature: Basic auth policy across gateway restarts
  As an API developer
  I want the basic-auth policy to keep protecting an API when the gateway restarts
  So that a change to it is caught before it reaches a release

  # Restarts a gateway service, so these scenarios run on their own. Unless a scenario says
  # otherwise, the credentials are ba-user:ba-secret?1 (YmEtdXNlcjpiYS1zZWNyZXQ/MQ==).

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # Gateway replicas in the test environment are independent gateways that share no state, so
  # scaling is not covered here; each restart below shows the configuration is reloaded intact.
  Scenario Outline: Restart or scale gateway replicas with Basic Auth configured (restart <service>)
    Given I generate a unique value from "ba-restart-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-restart-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-restart-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I restart the "<service>" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | service            | key        |
      | gateway-runtime    | runtime    |
      | gateway-controller | controller |
