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

@log-message
Feature: Log message policy restart
  As an API operator
  I want logging to resume after the gateway restarts
  So that no traffic goes unlogged after a restart

  # Restarting gateway services, so these scenarios run on their own. Gateway replicas are not
  # covered: the test environment's replicas are independent gateways that share no state. Records
  # reach the log late, but in the order they are written. So each check ends with a fence: a later
  # request whose records come last. Once they appear, the records before them are final.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # Requests that fail while the runtime restarts never reach the policy chain, so the first
  # success, with request id lm-restart-after, has exactly one record.
  Scenario: Restart or scale gateway replicas while logging is enabled (restart gateway-runtime)
    Given I generate a unique value from "lm-restart" and store it as "apiName"
    And I generate a unique API version from "lm-restart" and store it as "apiVersion"
    And I generate a unique API context from "/lm-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-restart-before"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id        |
      | REQUEST        | lm-restart-before |

    When I restart the "gateway-runtime" service
    And I set header "X-Request-Id" to "lm-restart-after"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" with request id "lm-restart-after" should be:
      | mediation-flow | request-id       |
      | REQUEST        | lm-restart-after |

    When I set header "X-Request-Id" to "lm-restart-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id        |
      | REQUEST        | lm-restart-before |
      | REQUEST        | lm-restart-after  |
      | REQUEST        | lm-restart-fence  |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The controller reloads the API from its database when it restarts, and the restarted runtime
  # loads its configuration from the controller. Requests that fail during the restarts never reach
  # the policy chain. After both restarts the records keep their shape: the excluded header stays out
  # of the log, and the request payload and response status are still logged.
  Scenario: Restart or scale gateway replicas while logging is enabled (restart gateway-controller, then gateway-runtime)
    Given I generate a unique value from "lm-restart-controller" and store it as "apiName"
    And I generate a unique API version from "lm-restart-controller" and store it as "apiVersion"
    And I generate a unique API context from "/lm-restart-controller" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true,"excludeHeaders":["X-Lm-Hidden"]},"response":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-restart-controller-before"
    And I set header "X-Lm-Kept" to "lm-restart-controller-kept"
    And I set header "X-Lm-Hidden" to "lm-restart-controller-hidden"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-restart-controller-before"}
      """
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Hidden" with value "lm-restart-controller-hidden"
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id                   | headers.x-lm-kept          | headers.x-lm-hidden | headers.:status | payload                                   |
      | REQUEST        | lm-restart-controller-before | lm-restart-controller-kept | [absent]            | [absent]        | [absent]                                  |
      | REQUEST        | lm-restart-controller-before | [absent]                   | [absent]            | [absent]        | {"marker":"lm-restart-controller-before"} |
      | RESPONSE       | lm-restart-controller-before | [absent]                   | [absent]            | 200             | [absent]                                  |

    When I restart the "gateway-controller" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I restart the "gateway-runtime" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I set header "X-Request-Id" to "lm-restart-controller-after"
    And I set header "X-Lm-Kept" to "lm-restart-controller-kept"
    And I set header "X-Lm-Hidden" to "lm-restart-controller-hidden"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"marker":"lm-restart-controller-after"}
      """
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Hidden" with value "lm-restart-controller-hidden"
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" with request id "lm-restart-controller-after" should be:
      | mediation-flow | request-id                  | headers.x-lm-kept          | headers.x-lm-hidden | headers.:status | payload                                  |
      | REQUEST        | lm-restart-controller-after | lm-restart-controller-kept | [absent]            | [absent]        | [absent]                                 |
      | REQUEST        | lm-restart-controller-after | [absent]                   | [absent]            | [absent]        | {"marker":"lm-restart-controller-after"} |
      | RESPONSE       | lm-restart-controller-after | [absent]                   | [absent]            | 200             | [absent]                                 |

    When I set header "X-Request-Id" to "lm-restart-controller-fence"
    And I set header "X-Lm-Kept" to "lm-restart-controller-kept"
    And I set header "X-Lm-Hidden" to "lm-restart-controller-hidden"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-restart-controller-fence"}
      """
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Hidden" with value "lm-restart-controller-hidden"
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id                   | headers.x-lm-kept          | headers.x-lm-hidden | headers.:status | payload                                   |
      | REQUEST        | lm-restart-controller-before | lm-restart-controller-kept | [absent]            | [absent]        | [absent]                                  |
      | REQUEST        | lm-restart-controller-before | [absent]                   | [absent]            | [absent]        | {"marker":"lm-restart-controller-before"} |
      | RESPONSE       | lm-restart-controller-before | [absent]                   | [absent]            | 200             | [absent]                                  |
      | REQUEST        | lm-restart-controller-after  | lm-restart-controller-kept | [absent]            | [absent]        | [absent]                                  |
      | REQUEST        | lm-restart-controller-after  | [absent]                   | [absent]            | [absent]        | {"marker":"lm-restart-controller-after"}  |
      | RESPONSE       | lm-restart-controller-after  | [absent]                   | [absent]            | 200             | [absent]                                  |
      | REQUEST        | lm-restart-controller-fence  | lm-restart-controller-kept | [absent]            | [absent]        | [absent]                                  |
      | REQUEST        | lm-restart-controller-fence  | [absent]                   | [absent]            | [absent]        | {"marker":"lm-restart-controller-fence"}  |
      | RESPONSE       | lm-restart-controller-fence  | [absent]                   | [absent]            | 200             | [absent]                                  |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
