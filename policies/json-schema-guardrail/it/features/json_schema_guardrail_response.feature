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

@json-schema-guardrail
Feature: JSON Schema guardrail policy on responses
  As an API developer
  I want upstream and LLM responses checked against a JSON Schema before they reach the client
  So that responses that break the contract are not returned

  # Response validation: violating responses, both phases together, the LLM content path, unusable
  # JSONPaths, and malformed, error and streamed upstream bodies. A "response" object turns response
  # validation on, since "enabled" defaults to true there. The LLM mock replies with the body or raw
  # text named in the request's x_testbench_reply field.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # showAssessment is left at its default, false, so the error body does not carry the upstream
  # value.
  Scenario: Return a response that violates the configured schema
    Given I generate a unique value from "jsg-response-invalid" and store it as "apiName"
    And I generate a unique API version from "jsg-response-invalid" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-response-invalid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"POST","path":"/reply","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"status\":{\"enum\":[\"approved\"]}},\"required\":[\"status\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{"status":"approved"}}}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" with body:
      """
      {"x_testbench_reply":{"body":{"status":"jsg-r04-unapproved"}}}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response header "Content-Type" should be "application/json"
    And the response body should not contain "jsg-r04-unapproved"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 404

  # The request schema needs a question and the response schema an answer, so each content passes
  # only its own schema.
  Scenario: Configure the guardrail on both request and response flows
    Given I generate a unique value from "jsg-both-flows" and store it as "apiName"
    And I generate a unique API version from "jsg-both-flows" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-both-flows" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"POST","path":"/reply","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"question\":{\"type\":\"string\"}},\"required\":[\"question\"]}"},"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"answer\":{\"type\":\"string\"}},\"required\":[\"answer\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 200 with body:
      """
      {"question":"What is the capital of France?","x_testbench_reply":{"body":{"answer":"Paris"}}}
      """
    Then the JSON response field "answer" should be "Paris"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" with body:
      """
      {"x_testbench_reply":{"body":{"answer":"Paris"}}}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" with body:
      """
      {"question":"What is the capital of France?","x_testbench_reply":{"body":{"question":"echo"}}}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 404

  # On chat-echo the LLM mock replies with the last user message as choices[0].message.content. The
  # jsonPath selects the whole message object, whose content must start with "ANSWER: ". The default
  # path would select the content string, which this schema rejects. showAssessment is left at its
  # default, false, so the error body does not carry the content.
  Scenario: Configure JSONPath on the response and validate a nested LLM response field
    Given I generate a unique value from "jsg-llm-response" and store it as "apiName"
    And I generate a unique API version from "jsg-llm-response" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-llm-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/openai/v1 |
      | spec.operations        | [{"method":"POST","path":"/chat-echo","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"$.choices[0].message","schema":"{\"type\":\"object\",\"properties\":{\"content\":{\"type\":\"string\",\"pattern\":\"^ANSWER: \"}},\"required\":[\"content\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"ANSWER: Paris"}]}
      """
    Then the JSON response field "choices[0].message.content" should be "ANSWER: Paris"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"No idea about jsg-r12-marker"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response body should not contain "jsg-r12-marker"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" until status 404

  Scenario: Configure an invalid or non-matching JSONPath (response)
    Given I generate a unique value from "jsg-bad-jsonpath-response" and store it as "apiName"
    And I generate a unique API version from "jsg-bad-jsonpath-response" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-bad-jsonpath-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"POST","path":"/reply","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"$.output.text","schema":"{\"type\":\"string\"}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 422 with body:
      """
      {"x_testbench_reply":{"body":{"answer":"jsg-r13-marker"}}}
      """
    Then the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response body should not contain "jsg-r13-marker"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 404

  Scenario Outline: Return malformed JSON from the backend/LLM (<case>)
    Given I generate a unique value from "jsg-malformed-response" and store it as "apiName"
    And I generate a unique API version from "jsg-malformed-response" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-malformed-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"POST","path":"/reply","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"<jsonPath>","schema":"{\"type\":\"object\"}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 422 with body:
      """
      {"x_testbench_reply":{"raw":"<raw>"}}
      """
    Then the JSON response field "message.actionReason" should be "<reason>"
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response body should not contain "jsg-r15-marker"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 404

    Examples:
      | case           | jsonPath | raw                            | reason                               |
      | truncated JSON |          | {\"answer\":\"jsg-r15-marker\" | Error validating schema              |
      | HTML           | $.answer | <html>jsg-r15-marker</html>    | Error extracting value from JSONPath |

  # The backend's ?statusCode=500 answers 500 with its JSON description of the request, which has
  # no status field.
  Scenario: Response validation replaces an upstream error body
    Given I generate a unique value from "jsg-upstream-error-body" and store it as "apiName"
    And I generate a unique API version from "jsg-upstream-error-body" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-upstream-error-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/fail","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"status\":{\"enum\":[\"approved\"]}},\"required\":[\"status\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/fail?statusCode=500" until status 422
    Then the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/fail" until status 404

  # The jsonPath is left at its default, $.choices[0].message.content. With "stream": true the LLM
  # mock sends its reply as server-sent events, which are not JSON, so that path cannot be read.
  Scenario: A streamed response is blocked by response validation
    Given I generate a unique value from "jsg-streamed-response" and store it as "apiName"
    And I generate a unique API version from "jsg-streamed-response" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-streamed-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/openai/v1 |
      | spec.operations        | [{"method":"POST","path":"/chat-echo","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"schema":"{\"type\":\"string\"}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello there"}]}
      """
    Then the JSON response field "choices[0].message.content" should be "Hello there"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" with body:
      """
      {"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Hello there"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-echo" until status 404
