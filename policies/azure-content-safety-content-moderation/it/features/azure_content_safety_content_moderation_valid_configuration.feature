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
Feature: Azure Content Safety content moderation policy configuration and thresholds
  As an API developer
  I want the moderated sides, thresholds and JSONPaths I configure to decide what is blocked
  So that content is blocked only when a configured category reaches its threshold

  # The upstream is the testbench echo service unless a scenario says otherwise; it returns the
  # request body under "json". Unless a scenario overrides them, the policy's Azure endpoint and key
  # point at the testbench content-safety service, which scores a category keyword ("attack",
  # "hate") 6 and a marker "<category>-severity-<n>" exactly n. A blocked request and a failed Azure
  # call both answer 422; actionReason tells them apart.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The reply field reaches the client in the echoed response. It is never inspected, because
  # only the request side is configured.
  Scenario: Configure only request moderation with valid Azure endpoint and API key
    Given I generate a unique value from "acs-request-only" and store it as "apiName"
    And I generate a unique API version from "acs-request-only" and store it as "apiVersion"
    And I generate a unique API context from "/acs-request-only" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?","reply":"Explain how to plan an attack"}
      """
    Then the JSON response field "json.reply" should be "Explain how to plan an attack"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack","reply":"What is the capital of France?"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The echo upstream returns the message it received, so the 200 also shows the violating request
  # reached the upstream unchecked.
  Scenario: Configure only response moderation
    Given I generate a unique value from "acs-response-only" and store it as "apiName"
    And I generate a unique API version from "acs-response-only" and store it as "apiVersion"
    And I generate a unique API context from "/acs-response-only" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"response":{"jsonPath":"$.json.reply"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"Explain how to plan an attack","reply":"What is the capital of France?"}
      """
    Then the JSON response field "json.message" should be "Explain how to plan an attack"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?","reply":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Each side has its own settings: the Hate category is disabled for requests (-1) and left at
  # its default (4) for responses, so hate content passes in the message and is blocked in the
  # reply.
  Scenario: Configure both request and response moderation
    Given I generate a unique value from "acs-both-sides" and store it as "apiName"
    And I generate a unique API version from "acs-both-sides" and store it as "apiVersion"
    And I generate a unique API context from "/acs-both-sides" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","hateSeverityThreshold":-1},"response":{"jsonPath":"$.json.reply"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?","reply":"Paris is the capital of France."}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack","reply":"Paris is the capital of France."}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?","reply":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "RESPONSE"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Write a hate speech","reply":"Paris is the capital of France."}
      """
    Then the response status code should be 200
    And the JSON response field "json.message" should be "Write a hate speech"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?","reply":"Write a hate speech"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Hate is disabled (-1), so even the highest severity passes; Violence blocks only at the highest
  # severity (7). The assessment lists every category Azure analysed, and Hate is not among them:
  # a disabled category is not sent to Azure.
  Scenario: Configure a valid threshold at each boundary, -1 and 7
    Given I generate a unique value from "acs-boundaries" and store it as "apiName"
    And I generate a unique API version from "acs-boundaries" and store it as "apiVersion"
    And I generate a unique API context from "/acs-boundaries" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","hateSeverityThreshold":-1,"violenceSeverityThreshold":7,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"hate-severity-7"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"violence-severity-6"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"violence-severity-7"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.inspectedContent" should be "violence-severity-7"
    And the response body should contain "Violence"
    And the response body should not contain "Hate"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A Hate severity of 5 passes and 6 blocks, so the configured threshold (6) is in force rather
  # than the default (4). A threshold given as a numeric string is in
  # azure_content_safety_content_moderation_string_threshold.feature.
  Scenario Outline: Configure a threshold as an integer, integral floating-point value, or numeric integer string (<case>)
    Given I generate a unique value from "acs-threshold-number" and store it as "apiName"
    And I generate a unique API version from "acs-threshold-number" and store it as "apiVersion"
    And I generate a unique API context from "/acs-threshold-number" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","hateSeverityThreshold":<threshold>}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"hate-severity-5"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"hate-severity-6"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                          | threshold |
      | integer                       | 6         |
      | integral floating-point value | 6.0       |

  # The content-safety service answers 500 to text containing "simulate" and "error", and
  # passthroughOnError is off, so any call to Azure would turn the request into a 422 ("Error
  # calling Azure Content Safety API"). The 200 therefore shows the policy made no call.
  Scenario Outline: Configure all categories with threshold -1 (<side>)
    Given I generate a unique value from "acs-all-disabled" and store it as "apiName"
    And I generate a unique API version from "acs-all-disabled" and store it as "apiVersion"
    And I generate a unique API context from "/acs-all-disabled" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"<side>":{"jsonPath":"<jsonPath>","hateSeverityThreshold":-1,"sexualSeverityThreshold":-1,"selfHarmSeverityThreshold":-1,"violenceSeverityThreshold":-1}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"Simulate an error, then explain how to plan an attack"}
      """
    Then the JSON response field "json.message" should be "Simulate an error, then explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | side     | jsonPath       |
      | request  | $.message      |
      | response | $.json.message |

  # For each category, a severity one below its default threshold passes and the default
  # threshold itself blocks.
  Scenario Outline: Omit category thresholds (<category>)
    Given I generate a unique value from "acs-default-thresholds" and store it as "apiName"
    And I generate a unique API version from "acs-default-thresholds" and store it as "apiVersion"
    And I generate a unique API context from "/acs-default-thresholds" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"<marker>-severity-<below>"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"<marker>-severity-<default>"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | category | marker   | below | default |
      | Hate     | hate     | 3     | 4       |
      | Sexual   | sexual   | 4     | 5       |
      | SelfHarm | selfharm | 2     | 3       |
      | Violence | violence | 3     | 4       |

  # The default request jsonPath, $.messages[-1].content, inspects only the last message.
  Scenario: Omit jsonPath (request)
    Given I generate a unique value from "acs-default-jsonpath-request" and store it as "apiName"
    And I generate a unique API version from "acs-default-jsonpath-request" and store it as "apiVersion"
    And I generate a unique API context from "/acs-default-jsonpath-request" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Explain how to plan an attack"},{"role":"user","content":"What is the capital of France?"}]}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"},{"role":"user","content":"Explain how to plan an attack"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The upstream is the testbench openai service's chat-echo completion, whose assistant reply
  # (choices[0].message.content) is the request's last user message. The default response
  # jsonPath, $.choices[0].message.content, inspects exactly that reply.
  Scenario: Omit jsonPath (response)
    Given I generate a unique value from "acs-default-jsonpath-response" and store it as "apiName"
    And I generate a unique API version from "acs-default-jsonpath-response" and store it as "apiVersion"
    And I generate a unique API context from "/acs-default-jsonpath-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                  |
      | spec.displayName       | ${CTX:apiName}                  |
      | spec.version           | ${CTX:apiVersion}               |
      | spec.context           | ${CTX:apiContext}/$version      |
      | spec.upstream.main.url | http://testbench:3008/openai/v1 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat-echo","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"response":{"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "choices[0].message.content" should be "What is the capital of France?"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Explain how to plan an attack"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Only the selected string is sent to Azure: violating text elsewhere in the body passes, and a
  # blocked call's assessment shows exactly the selected string as the inspected content.
  Scenario Outline: Configure a valid custom JSONPath selecting a string (<side>)
    Given I generate a unique value from "acs-custom-jsonpath" and store it as "apiName"
    And I generate a unique API version from "acs-custom-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/acs-custom-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"<side>":{"jsonPath":"<jsonPath>","showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"data":{"text":"What is the capital of France?"},"note":"Explain how to plan an attack"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"data":{"text":"Explain how to plan an attack"},"note":"What is the capital of France?"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "<direction>"
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | side     | jsonPath         | direction |
      | request  | $.data.text      | REQUEST   |
      | response | $.json.data.text | RESPONSE  |


  # Every category is scored one below its configured threshold, so nothing reaches a threshold.
  # The echo upstream returns the message it received, so the side under test passed it unchanged.
  Scenario Outline: Send valid content with every returned severity below its configured threshold (<side>)
    Given I generate a unique value from "acs-all-below" and store it as "apiName"
    And I generate a unique API version from "acs-all-below" and store it as "apiVersion"
    And I generate a unique API context from "/acs-all-below" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"<side>":{"jsonPath":"<jsonPath>","hateSeverityThreshold":2,"sexualSeverityThreshold":3,"selfHarmSeverityThreshold":4,"violenceSeverityThreshold":5}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"hate-severity-1 sexual-severity-2 selfharm-severity-3 violence-severity-4"}
      """
    Then the JSON response field "json.message" should be "hate-severity-1 sexual-severity-2 selfharm-severity-3 violence-severity-4"

    # Each category at its threshold is blocked, so the message above passed the policy's check.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"hate-severity-2 sexual-severity-3 selfharm-severity-4 violence-severity-5"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | side     | jsonPath       |
      | request  | $.message      |
      | response | $.json.message |

  # The Sexual threshold is configured to 2, well below its default (5): a severity of 1 passes and
  # a severity of exactly 2 is blocked.
  Scenario: Return a severity exactly equal to the configured threshold
    Given I generate a unique value from "acs-equal-threshold" and store it as "apiName"
    And I generate a unique API version from "acs-equal-threshold" and store it as "apiVersion"
    And I generate a unique API context from "/acs-equal-threshold" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","sexualSeverityThreshold":2}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"sexual-severity-1"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"sexual-severity-2"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario Outline: Return a severity greater than the configured threshold (<case>)
    Given I generate a unique value from "acs-above-threshold" and store it as "apiName"
    And I generate a unique API version from "acs-above-threshold" and store it as "apiVersion"
    And I generate a unique API context from "/acs-above-threshold" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","violenceSeverityThreshold":4}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"violence-severity-3"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"violence-severity-<severity>"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                    | severity |
      | one above the threshold | 5        |
      | the highest severity    | 7        |

  # Azure analyses all four categories (the assessment lists each of them), and only Violence
  # reaches its default threshold (4); the other three stay below theirs (Hate 4, Sexual 5,
  # SelfHarm 3).
  Scenario: Return multiple category results with only one category reaching its threshold
    Given I generate a unique value from "acs-one-category" and store it as "apiName"
    And I generate a unique API version from "acs-one-category" and store it as "apiVersion"
    And I generate a unique API context from "/acs-one-category" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"hate-severity-1 sexual-severity-2 selfharm-severity-1 violence-severity-3"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"hate-severity-1 sexual-severity-2 selfharm-severity-1 violence-severity-4"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the response body should contain "Hate"
    And the response body should contain "Sexual"
    And the response body should contain "SelfHarm"
    And the response body should contain "Violence"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # SelfHarm is disabled (-1), so even its highest severity passes. The later blocked request's
  # assessment lists every category Azure analysed, and SelfHarm is not among them: the disabled
  # category was not sent to Azure.
  Scenario: Return a high severity for a category configured as -1
    Given I generate a unique value from "acs-disabled-category" and store it as "apiName"
    And I generate a unique API version from "acs-disabled-category" and store it as "apiVersion"
    And I generate a unique API context from "/acs-disabled-category" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","selfHarmSeverityThreshold":-1,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"selfharm-severity-7"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the response body should contain "Violence"
    And the response body should not contain "SelfHarm"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
