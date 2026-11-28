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
Feature: Log message policy attachment and API lifecycle
  As an API operator
  I want logging to follow where and in which order the policy is attached
  So that the logs match the API as it is deployed

  # Attachment level and order, other policies in the policy chain, updates, removal and concurrent
  # traffic. The backend echoes the request as JSON. Records reach the log late, but in the order
  # they are written. So each check ends with a fence: a later request whose records come last. Once
  # they appear, the records before them are final.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # /on logs request headers and is called after /off, so once its record is in the log, a record
  # for /off would be there too.
  Scenario Outline: Disable payload and header logging (<case>)
    Given I generate a unique value from "lm-disabled" and store it as "apiName"
    And I generate a unique API version from "lm-disabled" and store it as "apiVersion"
    And I generate a unique API context from "/lm-disabled" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/off","policies":[{"name":"log-message","version":"v1","params":<params>}]},{"method":"GET","path":"/on","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-disabled"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/off" with body:
      """
      {"marker":"lm-disabled"}
      """
    Then the response status code should be 200
    And the JSON response field "json.marker" should be "lm-disabled"

    When I set header "X-Request-Id" to "lm-disabled-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/on"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/on" should be:
      | mediation-flow | request-id        |
      | REQUEST        | lm-disabled-fence |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/off" should be none

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                           | params                                                                                     |
      | all options false              | {"request":{"payload":false,"headers":false},"response":{"payload":false,"headers":false}} |
      | options left at their defaults | {"request":{},"response":{}}                                                               |

  # The fence request on /items comes last, so the /orders and /archive records are already in the log.
  Scenario: Apply Log Message at API level and invoke multiple operations
    Given I generate a unique value from "lm-api-level" and store it as "apiName"
    And I generate a unique API version from "lm-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/lm-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.policies          | [{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}] |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items"},{"method":"POST","path":"/orders"},{"method":"DELETE","path":"/archive"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-api-level-1"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-api-level-2"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"marker":"lm-api-level"}
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-api-level-3"
    And I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/archive"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-api-level-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id         | http-method |
      | REQUEST        | lm-api-level-1     | GET         |
      | REQUEST        | lm-api-level-fence | GET         |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id     | http-method |
      | REQUEST        | lm-api-level-2 | POST        |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/archive" should be:
      | mediation-flow | request-id     | http-method |
      | REQUEST        | lm-api-level-3 | DELETE      |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  Scenario: Apply Log Message only to a selected operation
    Given I generate a unique value from "lm-one-op" and store it as "apiName"
    And I generate a unique API version from "lm-one-op" and store it as "apiVersion"
    And I generate a unique API context from "/lm-one-op" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/plain"},{"method":"GET","path":"/logged","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-one-op-plain"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/plain"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-one-op"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/logged"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-one-op-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/logged"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/logged" should be:
      | mediation-flow | request-id      |
      | REQUEST        | lm-one-op       |
      | REQUEST        | lm-one-op-fence |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/plain" should be none

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # Each set-headers changes one side only: the first the response, the last the request. The
  # response flow runs the policy chain backwards, so both run after the policy in their own
  # flow, and the records show the request and response as they were before the change.
  Scenario: Place Log Message before a transformation policy
    Given I generate a unique value from "lm-xform-after" and store it as "apiName"
    And I generate a unique API version from "lm-xform-after" and store it as "apiVersion"
    And I generate a unique API context from "/lm-xform-after" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Added-Response","value":"lm-xform-after"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true},"response":{"headers":true}}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-Request","value":"lm-xform-after"}]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-xform-after"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "X-Added-Request" with value "lm-xform-after"
    And the response header "X-Added-Response" should be "lm-xform-after"

    When I set header "X-Request-Id" to "lm-xform-after-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id           | headers.x-added-request | headers.x-added-response |
      | REQUEST        | lm-xform-after       | [absent]                | [absent]                 |
      | RESPONSE       | lm-xform-after       | [absent]                | [absent]                 |
      | REQUEST        | lm-xform-after-fence | [absent]                | [absent]                 |
      | RESPONSE       | lm-xform-after-fence | [absent]                | [absent]                 |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The second attachment excludes X-Lm-Second, so each record shows which attachment wrote it.
  Scenario: Attach the Log Message policy multiple times to the same flow
    Given I generate a unique value from "lm-twice" and store it as "apiName"
    And I generate a unique API version from "lm-twice" and store it as "apiVersion"
    And I generate a unique API context from "/lm-twice" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true,"excludeHeaders":["X-Lm-Second"]}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-twice"
    And I set header "X-Lm-Second" to "lm-twice-second"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-twice-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id     | headers.x-lm-second |
      | REQUEST        | lm-twice       | lm-twice-second     |
      | REQUEST        | lm-twice       | [absent]            |
      | REQUEST        | lm-twice-fence | lm-twice-second     |
      | REQUEST        | lm-twice-fence | [absent]            |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # /secured runs api-key-auth, a limit of two requests an hour, then the policy; /audited runs the
  # policy first, excluding API-Key, then api-key-auth. Polling for the new key gets 401s, which
  # api-key-auth answers before the limit counts. A request a policy rejects before the logging
  # policy gets no record; api-key-auth removes the key before the policy sees the request.
  Scenario: Combine Log Message with authentication and rate limiting
    Given I generate a unique value from "lm-auth-rl" and store it as "apiName"
    And I generate a unique API version from "lm-auth-rl" and store it as "apiVersion"
    And I generate a unique API context from "/lm-auth-rl" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/secured","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}},{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]},{"method":"GET","path":"/audited","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true,"excludeHeaders":["API-Key"]}}},{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]},{"method":"GET","path":"/fence","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-auth-rl-nokey"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/secured"
    Then the response status code should be 401
    And the JSON response field "message" should be "Valid API key required"

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"lm-auth-rl-key"}
      """
    Then the response status should be 201

    When I store the JSON response field "apiKey.apiKey" as "lmKey"
    And I set header "API-Key" to "${CTX:lmKey}"
    And I set header "X-Request-Id" to "lm-auth-rl-a"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/secured" until status 200
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-auth-rl-b"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/secured"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-auth-rl-c"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/secured"
    Then the response status code should be 429

    When I set header "API-Key" to "lm-auth-rl-wrong"
    And I set header "X-Request-Id" to "lm-auth-rl-audited"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/audited"
    Then the response status code should be 401

    When I set header "X-Request-Id" to "lm-auth-rl-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/fence"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/fence" should be:
      | mediation-flow | request-id       |
      | REQUEST        | lm-auth-rl-fence |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/secured" should be:
      | mediation-flow | request-id   | headers.api-key |
      | REQUEST        | lm-auth-rl-a | [absent]        |
      | REQUEST        | lm-auth-rl-b | [absent]        |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/audited" should be:
      | mediation-flow | request-id         | headers.api-key | record                          |
      | REQUEST        | lm-auth-rl-audited | [absent]        | [not contains lm-auth-rl-wrong] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The update adds the exclusion and a new operation, /added. A request sent right after the update
  # call can still use the old configuration, so the scenario waits until /added answers. The two
  # requests after it check that each later request uses the new exclusion.
  Scenario: Update logging options or excluded headers on a deployed API
    Given I generate a unique value from "lm-update" and store it as "apiName"
    And I generate a unique API version from "lm-update" and store it as "apiVersion"
    And I generate a unique API context from "/lm-update" and store it as "apiContext"
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

    When I set header "X-Request-Id" to "lm-update-before"
    And I set header "X-Lm-Upd" to "lm-update-before"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true,"excludeHeaders":["X-Lm-Upd"]}}}]},{"method":"GET","path":"/added"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/added" until status 200

    When I set header "X-Request-Id" to "lm-update-after-1"
    And I set header "X-Lm-Upd" to "lm-update-after-1"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Upd" with value "lm-update-after-1"

    When I set header "X-Request-Id" to "lm-update-after-2"
    And I set header "X-Lm-Upd" to "lm-update-after-2"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response should contain echoed header "X-Lm-Upd" with value "lm-update-after-2"
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id        | headers.x-lm-upd |
      | REQUEST        | lm-update-before  | lm-update-before |
      | REQUEST        | lm-update-after-1 | [absent]         |
      | REQUEST        | lm-update-after-2 | [absent]         |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The update removes the policy from /items and adds /added; the scenario waits until /added
  # answers. /fence keeps the policy, and its record, written after the last /items request, shows the
  # log is read late enough to hold a record for that request.
  Scenario: Remove Log Message from a deployed API
    Given I generate a unique value from "lm-remove" and store it as "apiName"
    And I generate a unique API version from "lm-remove" and store it as "apiVersion"
    And I generate a unique API context from "/lm-remove" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]},{"method":"GET","path":"/fence","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-remove-before"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/items"},{"method":"GET","path":"/fence","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]},{"method":"GET","path":"/added"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/added" until status 200

    When I set header "X-Request-Id" to "lm-remove-after"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-remove-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/fence"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/fence" should be:
      | mediation-flow | request-id      |
      | REQUEST        | lm-remove-fence |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/items" should be:
      | mediation-flow | request-id       |
      | REQUEST        | lm-remove-before |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # pii-masking-regex replaces each e-mail address with a placeholder before the policy runs.
  Scenario: Combine PII masking/redaction before Log Message and verify resulting logs
    Given I generate a unique value from "lm-pii" and store it as "apiName"
    And I generate a unique API version from "lm-pii" and store it as "apiVersion"
    And I generate a unique API context from "/lm-pii" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"pii-masking-regex","version":"v1","params":{"customPIIEntities":[{"piiEntity":"EMAIL","piiRegex":"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}"}],"jsonPath":"","redactPII":false}},{"name":"log-message","version":"v1","params":{"request":{"payload":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I set header "X-Request-Id" to "lm-pii"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"note":"contact lm-pii.jane@example.com now"}
      """
    Then the response status code should be 200

    When I set header "X-Request-Id" to "lm-pii-fence"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"note":"contact lm-pii.fence@example.com now"}
      """
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should be:
      | mediation-flow | request-id   | payload                             | record                                  |
      | REQUEST        | lm-pii       | {"note":"contact [EMAIL_0000] now"} | [not contains lm-pii.jane@example.com]  |
      | REQUEST        | lm-pii-fence | {"note":"contact [EMAIL_0000] now"} | [not contains lm-pii.fence@example.com] |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # The concurrent step sends 50 requests, 25 at a time; request i carries lm-concurrent-i-end and its
  # response must be 200 and contain it. Each request must then have one REQUEST and one RESPONSE
  # record with its own request id, both carrying its own marker.
  Scenario: Send high-concurrency/high-volume traffic with logging enabled
    Given I generate a unique value from "lm-concurrent" and store it as "apiName"
    And I generate a unique API version from "lm-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/lm-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"log-message","version":"v1","params":{"request":{"payload":true},"response":{"payload":true}}}]},{"method":"GET","path":"/fence","policies":[{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send 50 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/orders" cycling through:
      | body                          | status | contains              |
      | {"n":"lm-concurrent-{i}-end"} | 200    | lm-concurrent-{i}-end |

    When I set header "X-Request-Id" to "lm-concurrent-fence"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/fence"
    Then the response status code should be 200
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/fence" should be:
      | mediation-flow | request-id          |
      | REQUEST        | lm-concurrent-fence |
    And the log-message records for "${CTX:apiContext}/${CTX:apiVersion}/orders" should pair 50 requests by request id, each carrying "lm-concurrent-{i}-end"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
