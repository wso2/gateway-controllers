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
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@interceptor-service
Feature: Interceptor service policy failures in the gateway logs
  As an API developer
  I want interceptor failures to show in the gateway logs without the client's credentials
  So that I can investigate a failing interceptor safely

  # Runs alone, so the gateway's log holds only this file's interceptor failures. The scenarios run
  # in file order: the timeout scenario stays first, so its log check sees only its own failures.
  #
  # "request":{} turns on request-phase interception with its defaults: the request headers and
  # body go to the interceptor, and a failed call returns 500.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The interceptor answers after 2 seconds, past /short's 500 ms timeout. passthroughOnError is
  # left at its default, false, so each timed-out call returns 500. The concurrent step sends 20
  # requests to /short, each with the one Authorization value in its table, and checks that every
  # response is the 500 in that row; the log must then hold the failure but not the credential.
  Scenario: Send slow/high-volume interceptor traffic and inspect logs/audit behavior
    Given I generate a unique value from "is-r30" and store it as "apiName"
    And I generate a unique API version from "is-r30" and store it as "apiVersion"
    And I generate a unique API context from "/is-r30" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/short","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{},"timeoutMillis":500}}]},{"method":"GET","path":"/long","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{},"timeoutMillis":5000}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Request-Delay-Ms" to "2000"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I send 20 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/short" alternating the "Authorization" header:
      | Bearer is-log-secret-0123456789abcdef | 500 |

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/long"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200
    And the "gateway-runtime" service logs should contain "InterceptorService: returning 500 to client"
    And the "gateway-runtime" service logs should not contain "is-log-secret-0123456789abcdef"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The interceptor answers 503, so the call fails and the policy returns its 500. The first
  # scenario's failures are timeouts, which log a different error, so exactly one line names
  # status 503. None of the client's credentials may appear in the error response or the logs.
  Scenario: Verify handling of sensitive data such as Authorization, cookies, API keys, and interceptor credentials (failures)
    Given I generate a unique value from "is-r28f" and store it as "apiName"
    And I generate a unique API version from "is-r28f" and store it as "apiVersion"
    And I generate a unique API context from "/is-r28f" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/fail","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Request-Status" to "503"
    And I set header "Authorization" to "Bearer is-r28-log-token-0123456789"
    And I set header "Cookie" to "session=is-r28-log-cookie"
    And I set header "X-API-Key" to "is-r28-log-key"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/fail"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | InterceptorService: returning 500 to client |
      | interceptor returned status 503             |
    And the "gateway-runtime" service logs should not contain "is-r28-log-token-0123456789"
    And the "gateway-runtime" service logs should not contain "is-r28-log-cookie"
    And the "gateway-runtime" service logs should not contain "is-r28-log-key"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
