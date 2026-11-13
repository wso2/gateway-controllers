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

@aws-bedrock-guardrail
Feature: AWS Bedrock guardrail policy JSONPath and guardrail settings
  As an API developer
  I want the guardrail to check the content at the configured JSONPath with the configured guardrail
  So that the content checked and the guardrail that checks it are the ones the API names

  # Each API forwards to a capture service that records what reaches it. The Bedrock mock blocks
  # violence, "investment advice", "contraband" and "secret recipe", finds example.com emails,
  # phone numbers and SSNs as PII, and answers only requests signed with a fixture credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # Only the last message is checked, so the same content in an earlier message is forwarded.
  Scenario: Configure a valid request JSONPath and send content at the configured location
    Given I generate a unique value from "bedrock-valid-jsonpath" and store it as "apiName"
    And I generate a unique API version from "bedrock-valid-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-valid-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Tell me about Paris."},{"role":"assistant","content":"Paris is the capital of France."},{"role":"user","content":"Now describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"},{"role":"assistant","content":"I cannot help with that."},{"role":"user","content":"Then tell me about Paris."}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"},{"role":"assistant","content":"I cannot help with that."},{"role":"user","content":"Then tell me about Paris."}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The API deploys with any jsonPath; extracting the content then fails on every request.
  Scenario Outline: Configure an invalid/non-matching JSONPath (<case>, passthroughOnError false)
    Given I generate a unique value from "bedrock-jsonpath-error" and store it as "apiName"
    And I generate a unique API version from "bedrock-jsonpath-error" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-jsonpath-error" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"<jsonPath>","passthroughOnError":false}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case         | jsonPath              |
      | non-matching | $.prompt              |
      | invalid      | $.messages[x].content |

  Scenario Outline: Configure an invalid/non-matching JSONPath (<case>, passthroughOnError true)
    Given I generate a unique value from "bedrock-jsonpath-passthrough" and store it as "apiName"
    And I generate a unique API version from "bedrock-jsonpath-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-jsonpath-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"<jsonPath>","passthroughOnError":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case         | jsonPath              |
      | non-matching | $.prompt              |
      | invalid      | $.messages[x].content |

  # After the failed extraction, the next well-formed request on the same API is served normally.
  Scenario Outline: Send malformed JSON or a payload where the configured JSONPath resolves to an unexpected type (<case>)
    Given I generate a unique value from "bedrock-bad-payload" and store it as "apiName"
    And I generate a unique API version from "bedrock-bad-payload" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-bad-payload" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      <body>
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                | body                                                      |
      | malformed JSON      | {"messages":[{"role":"user","content":"Hello"}            |
      | top-level array     | [{"role":"user","content":"Hello"}]                       |
      | object at the path  | {"messages":[{"role":"user","content":{"text":"Hello"}}]} |
      | array at the path   | {"messages":[{"role":"user","content":["Hello"]}]}        |
      | boolean at the path | {"messages":[{"role":"user","content":true}]}             |

  # The gateway always calls the mock's us-east-1 endpoint, so a wrong region shows only in the
  # signature, which the mock rejects.
  Scenario Outline: Configure an incorrect AWS region, guardrail ID, or guardrail version (<case>)
    Given I generate a unique value from "bedrock-wrong-guardrail" and store it as "apiName"
    And I generate a unique API version from "bedrock-wrong-guardrail" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-wrong-guardrail" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{<guardrail>,"awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    And the JSON response field "message.assessments[0]" should be "Error calling AWS Bedrock Guardrail"
    And the response body should not contain "ApplyGuardrail API call failed"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                      | guardrail                                                                           |
      | another region            | "region":"eu-west-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT"    |
      | unknown guardrail ID      | "region":"us-east-1","guardrailID":"unknown-guardrail-id","guardrailVersion":"DRAFT" |
      | unknown guardrail version | "region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"99"       |

  # Version 1 is the draft before "secret recipe" was added to it, so only DRAFT blocks the phrase.
  Scenario: Use DRAFT guardrail version and then switch to a numbered production version
    Given I generate a unique value from "bedrock-guardrail-version" and store it as "apiName"
    And I generate a unique API version from "bedrock-guardrail-version" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-guardrail-version" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"guardrailVersion":"DRAFT","request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe"}]}
      """
    Then the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "secret recipe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"guardrailVersion":"1","request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe"}]}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Ship the contraband tonight"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "contraband"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404
