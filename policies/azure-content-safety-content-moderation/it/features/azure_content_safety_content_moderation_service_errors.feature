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

@azure-content-safety-content-moderation
Feature: Azure Content Safety content moderation policy when Azure fails
  As an API developer
  I want unusable answers from Azure Content Safety to block or pass traffic as configured
  So that an Azure failure never lets content through unchecked unless I allow it

  # Azure answers, but not with a usable analysis, or does not answer at all. With
  # passthroughOnError false the policy blocks with 422 ("Error calling Azure Content Safety API");
  # with it true the content passes unchanged. Apart from the unreachable-Azure scenarios, the
  # scenarios from "Azure returns HTTP 400, 401, or 403" on send the policy's Azure calls through
  # the fault-injection service, which scripts failures and counts calls.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The content-safety service answers "simulate malformed json", "simulate missing analysis" and
  # "simulate invalid analysis" with 200 and a truncated body, no categoriesAnalysis, or a
  # categoriesAnalysis that is not an array.
  Scenario Outline: Azure returns malformed JSON or a response without a valid categoriesAnalysis array and passthrough is disabled (<case>)
    Given I generate a unique value from "acs-unusable-answer" and store it as "apiName"
    And I generate a unique API version from "acs-unusable-answer" and store it as "apiVersion"
    And I generate a unique API context from "/acs-unusable-answer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"<message>"}
      """
    Then the JSON response field "type" should be "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments[0]" should contain "<reason>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                                | message                   | reason                                                                    |
      | malformed JSON                      | Simulate malformed JSON   | failed to decode response body                                            |
      | no categoriesAnalysis               | Simulate missing analysis | categoriesAnalysis missing or invalid in Azure Content Safety API response |
      | categoriesAnalysis that is no array | Simulate invalid analysis | categoriesAnalysis missing or invalid in Azure Content Safety API response |

  Scenario Outline: Azure returns malformed JSON or a response without a valid categoriesAnalysis array and passthrough is enabled (<case>)
    Given I generate a unique value from "acs-unusable-answer-passthrough" and store it as "apiName"
    And I generate a unique API version from "acs-unusable-answer-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/acs-unusable-answer-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","passthroughOnError":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"<message>"}
      """
    Then the JSON response field "json.message" should be "<message>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                                | message                   |
      | malformed JSON                      | Simulate malformed JSON   |
      | no categoriesAnalysis               | Simulate missing analysis |
      | categoriesAnalysis that is no array | Simulate invalid analysis |

  # The fault-injection service answers 404 until the scenario stores its script, so the requests
  # that wait for the API are not counted. The policy makes up to five attempts, one second apart.
  # It retries only a failed connection or a 5xx answer. The script has no steps, so it passes
  # each call on to the content-safety service, which answers 400 or 403 for the simulated text and
  # 401 for the attachment's wrong subscription key. The script counts one call, so the policy did
  # not retry the 4xx answer. The response never carries the wrong subscription key.
  Scenario Outline: Azure returns HTTP 400, 401, or 403 (<status>, passthroughOnError false)
    Given I generate a unique value from "acs-client-error" and store it as "apiName"
    And I generate a unique API version from "acs-client-error" and store it as "apiVersion"
    And I generate a unique API context from "/acs-client-error" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}",<key>"request":{"jsonPath":"$.message","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"<message>"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"<message>"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments[0]" should contain "non-200 status code: <status>"
    And the response body should not contain "wrong-subscription-key"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | status | key                                               | message                        |
      | 400    |                                                   | Simulate bad request           |
      | 401    | "azureContentSafetyKey":"wrong-subscription-key", | What is the capital of France? |
      | 403    |                                                   | Simulate forbidden             |

  # As above, but passthroughOnError lets the content through; the echo upstream returns the
  # message it received unchanged. The script again counts one call.
  Scenario Outline: Azure returns HTTP 400, 401, or 403 (<status>, passthroughOnError true)
    Given I generate a unique value from "acs-client-error-passthrough" and store it as "apiName"
    And I generate a unique API version from "acs-client-error-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/acs-client-error-passthrough" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}",<key>"request":{"jsonPath":"$.message","passthroughOnError":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"<message>"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"<message>"}
      """
    Then the response status code should be 200
    And the JSON response field "json.message" should be "<message>"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | status | key                                               | message                        |
      | 400    |                                                   | Simulate bad request           |
      | 401    | "azureContentSafetyKey":"wrong-subscription-key", | What is the capital of France? |
      | 403    |                                                   | Simulate forbidden             |

  # 429 is a 4xx answer, so the policy does not retry it: the script answers one call.
  Scenario: Azure returns HTTP 429 (passthroughOnError false)
    Given I generate a unique value from "acs-rate-limited" and store it as "apiName"
    And I generate a unique API version from "acs-rate-limited" and store it as "apiVersion"
    And I generate a unique API context from "/acs-rate-limited" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}","request":{"jsonPath":"$.message","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[{"status":429}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"
    And the JSON response field "message.assessments[0]" should contain "non-200 status code: 429"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # As above; passthroughOnError lets the content through unchanged.
  Scenario: Azure returns HTTP 429 (passthroughOnError true)
    Given I generate a unique value from "acs-rate-limited-passthrough" and store it as "apiName"
    And I generate a unique API version from "acs-rate-limited-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/acs-rate-limited-passthrough" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}","request":{"jsonPath":"$.message","passthroughOnError":true,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[{"status":429}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 200
    And the JSON response field "json.message" should be "What is the capital of France?"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Two retryable answers, then the content-safety service analyses the text: the third attempt
  # succeeds and its analysis blocks the violating message as a moderation verdict, not a failed
  # call.
  Scenario Outline: Azure returns HTTP 500 or another retryable server error and later succeeds (<status>)
    Given I generate a unique value from "acs-retry-succeeds" and store it as "apiName"
    And I generate a unique API version from "acs-retry-succeeds" and store it as "apiVersion"
    And I generate a unique API context from "/acs-retry-succeeds" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}","request":{"jsonPath":"$.message","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[{"status":<status>},{"status":<status>}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 3

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | status |
      | 500    |
      | 503    |

  # Every attempt gets a 500. The policy makes five attempts in all (the first call and four
  # retries), so the script counts 5.
  Scenario: Azure repeatedly returns a retryable error until retries are exhausted (passthroughOnError false)
    Given I generate a unique value from "acs-retries-exhausted" and store it as "apiName"
    And I generate a unique API version from "acs-retries-exhausted" and store it as "apiVersion"
    And I generate a unique API context from "/acs-retries-exhausted" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}","request":{"jsonPath":"$.message","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[{"status":500},{"status":500},{"status":500},{"status":500},{"status":500}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"
    And the JSON response field "message.assessments[0]" should contain "non-200 status code: 500"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 5

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # As above; passthroughOnError lets the content through unchanged.
  Scenario: Azure repeatedly returns a retryable error until retries are exhausted (passthroughOnError true)
    Given I generate a unique value from "acs-retries-exhausted-passthrough" and store it as "apiName"
    And I generate a unique API version from "acs-retries-exhausted-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/acs-retries-exhausted-passthrough" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}","request":{"jsonPath":"$.message","passthroughOnError":true,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[{"status":500},{"status":500},{"status":500},{"status":500},{"status":500}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 200
    And the JSON response field "json.message" should be "What is the capital of France?"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 5

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Nothing listens on testbench port 3099, so every attempt fails to connect and the policy gives
  # up after its fifth. A reset connection takes the same path in the policy as a refused one, so it
  # is not tested separately. A timed-out call is not tested: the policy waits 30 seconds for
  # Azure, as long as the suite's HTTP client waits for the gateway.
  Scenario: Azure is unreachable, resets the connection, or exceeds the request timeout (passthroughOnError false)
    Given I generate a unique value from "acs-unreachable" and store it as "apiName"
    And I generate a unique API version from "acs-unreachable" and store it as "apiVersion"
    And I generate a unique API context from "/acs-unreachable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"http://testbench:3099","request":{"jsonPath":"$.message","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"
    And the JSON response field "message.assessments[0]" should contain "failed to call Azure Content Safety API after 5 attempts"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # As above; passthroughOnError lets the content through unchanged.
  Scenario: Azure is unreachable, resets the connection, or exceeds the request timeout (passthroughOnError true)
    Given I generate a unique value from "acs-unreachable-passthrough" and store it as "apiName"
    And I generate a unique API version from "acs-unreachable-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/acs-unreachable-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"http://testbench:3099","request":{"jsonPath":"$.message","passthroughOnError":true,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 200
    And the JSON response field "json.message" should be "What is the capital of France?"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
