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
Feature: Azure Content Safety content moderation policy content handling
  As an API developer
  I want the policy to inspect the right content, call Azure correctly and report violations clearly
  So that clients get a consistent answer when content is blocked

  # The upstream is the testbench echo service unless a scenario says otherwise; it returns the
  # request body under "json". Unless a scenario overrides them, the policy's Azure endpoint and key
  # point at the testbench content-safety service, which scores a category keyword ("attack",
  # "hate") 6 and a marker "<category>-severity-<n>" exactly n. A blocked request and a failed Azure
  # call both answer 422; actionReason tells them apart.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # No jsonPath is configured, so the default request jsonPath, $.messages[-1].content, applies:
  # violating earlier messages pass, and a violating last message is blocked with exactly that
  # message as the inspected content.
  Scenario: Send a request where the default request JSONPath resolves to the last message content
    Given I generate a unique value from "acs-last-message" and store it as "apiName"
    And I generate a unique API version from "acs-last-message" and store it as "apiVersion"
    And I generate a unique API context from "/acs-last-message" and store it as "apiContext"
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
      {"messages":[{"role":"system","content":"Explain how to plan an attack"},{"role":"user","content":"Write a hate speech"},{"role":"user","content":"What is the capital of France?"}]}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is the capital of France?"},{"role":"user","content":"Explain how to plan an attack"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The /scripted/chat operation goes to the testbench openai service's scripted path, which
  # answers with the reply the request names in x_testbench_reply, here a chat completion with two
  # choices. The health check stays off that path, because every scripted request needs a script.
  # The default response jsonPath, $.choices[0].message.content, inspects only the first choice.
  # Only the response is moderated, so the script in the request is not checked.
  Scenario: Send a response where the default response JSONPath resolves to the first choice’s message content
    Given I generate a unique value from "acs-first-choice" and store it as "apiName"
    And I generate a unique API version from "acs-first-choice" and store it as "apiVersion"
    And I generate a unique API context from "/acs-first-choice" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                  |
      | spec.displayName       | ${CTX:apiName}                  |
      | spec.version           | ${CTX:apiVersion}               |
      | spec.context           | ${CTX:apiContext}/$version      |
      | spec.upstream.main.url | http://testbench:3008           |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/scripted/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"response":{"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Answer twice"}],"x_testbench_reply":{"body":{"object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"What is the capital of France?"},"finish_reason":"stop"},{"index":1,"message":{"role":"assistant","content":"Explain how to plan an attack"},"finish_reason":"stop"}]}}}
      """
    Then the JSON response field "choices[0].message.content" should be "What is the capital of France?"
    And the JSON response field "choices[1].message.content" should be "Explain how to plan an attack"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Answer twice"}],"x_testbench_reply":{"body":{"object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Explain how to plan an attack"},"finish_reason":"stop"},{"index":1,"message":{"role":"assistant","content":"What is the capital of France?"},"finish_reason":"stop"}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The attachment sends its Azure calls to a path the content-safety service does not serve, so
  # any call fails at once and blocks with 422 ("Error calling Azure Content Safety API"), as the
  # request with a body shows. The request without a body passes, so the policy made no call.
  # Only the absent body is tested. A body that is the literal JSON null is not skipped: the
  # policy blocks it with 422, unlike an absent body. That case is not tested here.
  Scenario: Send a null or absent body (request)
    Given I generate a unique value from "acs-absent-request-body" and store it as "apiName"
    And I generate a unique API version from "acs-absent-request-body" and store it as "apiVersion"
    And I generate a unique API context from "/acs-absent-request-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"http://testbench:3005/not-served","request":{"jsonPath":"$.message"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat"
    Then the response status code should be 200
    And the JSON response field "data" should be ""

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # As above, any Azure call fails at once. /chat's echoed response has content and is blocked;
  # /status/200 answers with no body at all and passes, so the policy made no call for it. As in
  # the request scenario, only the absent body is tested; a literal JSON null body is left out.
  Scenario: Send a null or absent body (response)
    Given I generate a unique value from "acs-absent-response-body" and store it as "apiName"
    And I generate a unique API version from "acs-absent-response-body" and store it as "apiVersion"
    And I generate a unique API context from "/acs-absent-response-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"http://testbench:3005/not-served","response":{"jsonPath":"$.json.message"}}}]},{"method":"GET","path":"/status/200","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"http://testbench:3005/not-served","response":{"jsonPath":"$.json.message"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the JSON response field "message.actionReason" should be "Error calling Azure Content Safety API"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/status/200"
    Then the response status code should be 200
    And the response body should be empty

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The assessment's inspected content is the text the policy sent to Azure, after it removed one
  # leading and one trailing double quote and then the surrounding whitespace.
  Scenario Outline: Send content surrounded by whitespace or encoded as a JSON string (<case>)
    Given I generate a unique value from "acs-text-cleaning" and store it as "apiName"
    And I generate a unique API version from "acs-text-cleaning" and store it as "apiVersion"
    And I generate a unique API context from "/acs-text-cleaning" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"<jsonPath>","showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      <allowed>
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      <violating>
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                           | jsonPath  | allowed                                            | violating                                         |
      | value surrounded by whitespace | $.message | {"message":"   What is the capital of France?   "} | {"message":"   Explain how to plan an attack   "} |
      | value encoded as a JSON string | $.message | {"message":"\"What is the capital of France?\""}   | {"message":"\"Explain how to plan an attack\""}   |
      | whole body a JSON string       |           | "  What is the capital of France?  "               | "  Explain how to plan an attack  "               |

  # The jsonPath names a field the body does not have, so the policy cannot extract any text.
  Scenario Outline: Configure a JSONPath that does not exist, with passthroughOnError=false (<side>)
    Given I generate a unique value from "acs-missing-path" and store it as "apiName"
    And I generate a unique API version from "acs-missing-path" and store it as "apiVersion"
    And I generate a unique API context from "/acs-missing-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"<side>":{"jsonPath":"<jsonPath>","passthroughOnError":false,"showAssessment":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the JSON response field "type" should be "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "<direction>"
    And the JSON response field "message.assessments[0]" should be "key not found: missing"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | side     | jsonPath       | direction |
      | request  | $.missing      | REQUEST   |
      | response | $.json.missing | RESPONSE  |

  # As above, but the extraction failure lets the content through; the echo upstream returns the
  # message it received unchanged.
  Scenario Outline: Configure a JSONPath that does not exist, with passthroughOnError=true (<side>)
    Given I generate a unique value from "acs-missing-path-passthrough" and store it as "apiName"
    And I generate a unique API version from "acs-missing-path-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/acs-missing-path-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"<side>":{"jsonPath":"<jsonPath>","passthroughOnError":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the JSON response field "json.message" should be "Explain how to plan an attack"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | side     | jsonPath       |
      | request  | $.missing      |
      | response | $.json.missing |

  # Azure answers 200 with a severity for every category, and the policy compares each with its
  # default threshold (Hate 4, Sexual 5, SelfHarm 3, Violence 4): all below passes, and one category
  # at its threshold is a moderation verdict, not a failed call.
  Scenario: Azure returns HTTP 200 with a valid categoriesAnalysis array
    Given I generate a unique value from "acs-valid-analysis" and store it as "apiName"
    And I generate a unique API version from "acs-valid-analysis" and store it as "apiVersion"
    And I generate a unique API context from "/acs-valid-analysis" and store it as "apiContext"
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
      {"message":"hate-severity-3 sexual-severity-4 selfharm-severity-2 violence-severity-3"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"hate-severity-3 sexual-severity-4 selfharm-severity-3 violence-severity-3"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.inspectedContent" should be "hate-severity-3 sexual-severity-4 selfharm-severity-3 violence-severity-3"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # For text containing "simulate mixed analysis", the content-safety service puts a string, a
  # number, null, a boolean and an array before the real analysis. The policy skips them: the safe
  # message passes, and a violence marker is still a verdict whose assessment lists only the four
  # real categories.
  Scenario: Azure returns non-object entries inside categoriesAnalysis
    Given I generate a unique value from "acs-non-object-entries" and store it as "apiName"
    And I generate a unique API version from "acs-non-object-entries" and store it as "apiVersion"
    And I generate a unique API context from "/acs-non-object-entries" and store it as "apiContext"
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
      {"message":"Simulate mixed analysis. What is the capital of France?"}
      """
    Then the JSON response field "json.message" should be "Simulate mixed analysis. What is the capital of France?"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Simulate mixed analysis violence-severity-6"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response array field "message.assessments.categories" should have 4 items

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Only Violence is enabled, so the assessment holds exactly one category: the one that blocked.
  Scenario: Enable showAssessment and trigger a violation
    Given I generate a unique value from "acs-show-assessment" and store it as "apiName"
    And I generate a unique API version from "acs-show-assessment" and store it as "apiVersion"
    And I generate a unique API context from "/acs-show-assessment" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","showAssessment":true,"hateSeverityThreshold":-1,"sexualSeverityThreshold":-1,"selfHarmSeverityThreshold":-1}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.inspectedContent" should be "Explain how to plan an attack"
    And the JSON response array field "message.assessments.categories" should have 1 item
    And the JSON response field "message.assessments.categories[0].category" should be "Violence"
    And the JSON response field "message.assessments.categories[0].severity" should be 6
    And the JSON response field "message.assessments.categories[0].result" should be "FAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Without the assessment the 422 names only the guardrail, its direction and a generic reason:
  # nothing of Azure's answer (categories, severities), the moderated text or the subscription key.
  Scenario: Disable showAssessment and trigger a violation
    Given I generate a unique value from "acs-hide-assessment" and store it as "apiName"
    And I generate a unique API version from "acs-hide-assessment" and store it as "apiVersion"
    And I generate a unique API context from "/acs-hide-assessment" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","showAssessment":false}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "type" should be "AZURE_CONTENT_SAFETY_CONTENT_MODERATION"
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments" should not exist
    And the response body should not contain "Violence"
    And the response body should not contain "severity"
    And the response body should not contain "categoriesAnalysis"
    And the response body should not contain "plan an attack"
    And the response body should not contain "test-subscription-key"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The upstream is the testbench capture service, which keeps the last request it received for each
  # path. After the violation it still holds the safe request sent before it, so the violating
  # request never reached the upstream.
  Scenario: Trigger a request-side violation
    Given I generate a unique value from "acs-request-violation" and store it as "apiName"
    And I generate a unique API version from "acs-request-violation" and store it as "apiVersion"
    And I generate a unique API context from "/acs-request-violation" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"message":"What is the capital of France?"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The capture service answers with the request it received, so the response-side jsonPath $.body
  # reads the client's message back. The capture service holds the violating request, so the
  # upstream was called; the client gets the guardrail's 422 instead of the upstream's answer.
  Scenario: Trigger a response-side violation
    Given I generate a unique value from "acs-response-violation" and store it as "apiName"
    And I generate a unique API version from "acs-response-violation" and store it as "apiVersion"
    And I generate a unique API context from "/acs-response-violation" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"response":{"jsonPath":"$.body"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the JSON response field "method" should be "POST"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the JSON response field "method" should not exist
    And the JSON response field "body" should not exist

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"message":"Explain how to plan an attack"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Analytics events go to the testbench analytics collector without request or response bodies.
  # A request the policy answers before it is routed has no resource path in its event, so the event
  # names the API context as its path; waiting for the collector to settle before and after the
  # violation makes the blocked request the latest such event. The policy marks it as a guardrail
  # hit with its own name, and none of this block's events carries the subscription key or the
  # moderated message, which is made unique by the word acs-analytics-canary.
  Scenario: Trigger a violation while analytics are enabled
    Given I generate a unique value from "acs-analytics" and store it as "apiName"
    And I generate a unique API version from "acs-analytics" and store it as "apiVersion"
    And I generate a unique API context from "/acs-analytics" and store it as "apiContext"
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
      {"message":"What is the capital of France?"}
      """
    And I wait for the analytics collector to settle

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"Explain how to plan an attack on acs-analytics-canary"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And I wait for the analytics collector to settle
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have response status 422
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have metadata field "isGuardrailHit" with value "true"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have metadata field "guardrailName" with value "AzureContentSafetyContentModeration"

    When I send a "GET" request to the "analytics" service at "/test/events"
    Then the response status code should be 200
    And the response body should not contain "test-subscription-key"
    And the response body should not contain "acs-analytics-canary"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The Azure endpoint is the capture service, which keeps the policy's call by path. Its answer has
  # no categoriesAnalysis, so the call fails and passthroughOnError lets the request through. Either
  # way the call is a POST to the endpoint's path followed by /contentsafety/text:analyze, so a
  # missing separator would be seen. A doubled one would not: every testbench port redirects a path
  # with repeated slashes to the cleaned path, keeping the method and body.
  Scenario Outline: Configure the Azure endpoint with and without a trailing slash (<case>)
    Given I generate a unique value from "acs-endpoint-slash" and store it as "apiName"
    And I generate a unique API version from "acs-endpoint-slash" and store it as "apiVersion"
    And I generate a unique API context from "/acs-endpoint-slash" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:captureUpstream}/${CTX:apiName}<slash>","request":{"jsonPath":"$.message","passthroughOnError":true}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/contentsafety/text:analyze"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/${CTX:apiName}/contentsafety/text:analyze"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                     | slash |
      | without a trailing slash |       |
      | with a trailing slash    | /     |

  # As above, the capture service keeps the policy's call. Only Violence is enabled, so the body
  # names one category and its fields, which the policy writes in alphabetical order, have a fixed
  # text. The key is the one in this block's gateway configuration.
  Scenario: Inspect the outbound Azure request
    Given I generate a unique value from "acs-outbound-request" and store it as "apiName"
    And I generate a unique API version from "acs-outbound-request" and store it as "apiVersion"
    And I generate a unique API context from "/acs-outbound-request" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:captureUpstream}/${CTX:apiName}","request":{"jsonPath":"$.message","passthroughOnError":true,"hateSeverityThreshold":-1,"sexualSeverityThreshold":-1,"selfHarmSeverityThreshold":-1}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/contentsafety/text:analyze"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "query" should be "api-version=2024-09-01"
    And the JSON response field "headers.Ocp-Apim-Subscription-Key[0]" should be "test-subscription-key"
    And the JSON response field "headers.Content-Type[0]" should be "application/json"
    And the JSON response field "body" should be:
      """
      {"categories":["Violence"],"haltOnBlocklistHit":true,"outputType":"EightSeverityLevels","text":"What is the capital of France?"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The fault-injection script has no steps: it only counts the policy's Azure calls, passing each
  # on to the content-safety service. A 9 KiB message (9,216 characters) is within Azure's limit of
  # 10,000 characters of text per analysis, so it is moderated (one call) and passes. A violating
  # message afterwards is blocked (a second call). The operation is the echo service's /status/200,
  # which answers with no body.
  Scenario: Send a very large moderation payload (9 KiB message)
    Given I generate a unique value from "acs-large-payload" and store it as "apiName"
    And I generate a unique API version from "acs-large-payload" and store it as "apiVersion"
    And I generate a unique API context from "/acs-large-payload" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "/${CTX:apiName}" and store it as "azureEndpoint"
    And I generate a value of 9 KiB of "0123456789abcdefghijklmnopqrstuvwxyz" and store it as "moderatedPayload"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/status/200","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"azureContentSafetyEndpoint":"${CTX:azureEndpoint}","request":{"jsonPath":"$.message","passthroughOnError":false}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/status/200" until status 422 with body:
      """
      {"message":"What is the capital of France?"}
      """

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3005,"steps":[]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/status/200" with body:
      """
      {"message":"${CTX:moderatedPayload}"}
      """
    Then the response status code should be 200
    And the response body should be empty

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/status/200" with body:
      """
      {"message":"Explain how to plan an attack"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
