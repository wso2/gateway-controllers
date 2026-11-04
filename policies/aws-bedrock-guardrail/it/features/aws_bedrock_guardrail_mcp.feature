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
Feature: AWS Bedrock guardrail policy on MCP routes
  As an API developer
  I want MCP tool-call arguments and tool results checked with AWS Bedrock Guardrails
  So that harmful content and PII are blocked or masked for MCP traffic

  # The scripted MCP server (testbench/services/mcpscripted, http://testbench:3021/<partition>/mcp)
  # returns the "text" argument of a tools/call as the tool result, as JSON or, with
  # "shape":"events", as server-sent events. It records every request it receives. The testbench
  # Bedrock mock blocks text with "violence" and anonymizes "mask-...@example.com" addresses.
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Every tool argument of a clean tool call is checked and the call reaches the MCP server
    Given I generate a unique resource name from "bedrock-mcp-req-pass" and store it as "mcpName"
    And I generate a unique value from "bedrock-mcp-req-pass" and store it as "mcpDisplayName"
    And I generate a unique API version from "bedrock-mcp-req-pass" and store it as "mcpVersion"
    And I generate a unique API context from "/bedrock-mcp-req-pass" and store it as "mcpContext"
    And I generate a unique resource name from "bedrock-mcp-req-pass" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"enabled":true,"jsonPath":"$.params.arguments"},"response":{"enabled":false}}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    # initialize has no tool arguments or tool result, so the policy has nothing to check in it.
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/list"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup","arguments":{"text":"Order 42 shipped.","note":"Leave it at the front desk."}}}
      """
    Then the response status code should be 200
    And the JSON response field "id" should be 2
    And the JSON response field "result.content[0].text" should be "Order 42 shipped."

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: Violating content in any tool argument blocks the call before the MCP server
    Given I generate a unique resource name from "bedrock-mcp-req-block" and store it as "mcpName"
    And I generate a unique value from "bedrock-mcp-req-block" and store it as "mcpDisplayName"
    And I generate a unique API version from "bedrock-mcp-req-block" and store it as "mcpVersion"
    And I generate a unique API context from "/bedrock-mcp-req-block" and store it as "mcpContext"
    And I generate a unique resource name from "bedrock-mcp-req-block" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"enabled":true,"jsonPath":"$.params.arguments"},"response":{"enabled":false}}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    # initialize has no tool arguments or tool result, so the policy has nothing to check in it.
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lookup","arguments":{"text":"Order 42 shipped.","note":"This note contains violence"}}}
      """
    Then the response status code should be 422
    And the response should be valid JSON
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the response status code should be 200
    And the response body should contain "initialize"
    And the response body should not contain "tools/call"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: PII in a tool argument is masked before it reaches the MCP server
    Given I generate a unique resource name from "bedrock-mcp-req-mask" and store it as "mcpName"
    And I generate a unique value from "bedrock-mcp-req-mask" and store it as "mcpDisplayName"
    And I generate a unique API version from "bedrock-mcp-req-mask" and store it as "mcpVersion"
    And I generate a unique API context from "/bedrock-mcp-req-mask" and store it as "mcpContext"
    And I generate a unique resource name from "bedrock-mcp-req-mask" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"enabled":true,"jsonPath":"$.params.arguments"},"response":{"enabled":false}}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    # initialize has no tool arguments or tool result, so the policy has nothing to check in it.
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"lookup","arguments":{"text":"Reach me at mask-ana@example.com"}}}
      """
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should contain "Reach me at EMAIL_"
    And the response body should not contain "mask-ana@example.com"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the response status code should be 200
    And the response body should contain "tools/call"
    And the response body should contain "Reach me at EMAIL_"
    And the response body should not contain "mask-ana@example.com"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: PII in a JSON tool result is masked and violating content in it is blocked
    Given I generate a unique resource name from "bedrock-mcp-resp-json" and store it as "mcpName"
    And I generate a unique value from "bedrock-mcp-resp-json" and store it as "mcpDisplayName"
    And I generate a unique API version from "bedrock-mcp-resp-json" and store it as "mcpVersion"
    And I generate a unique API context from "/bedrock-mcp-resp-json" and store it as "mcpContext"
    And I generate a unique resource name from "bedrock-mcp-resp-json" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"enabled":false},"response":{"enabled":true,"jsonPath":"$.result.content[*].text"}}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    # initialize has no tool arguments or tool result, so the policy has nothing to check in it.
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/list"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"lookup","arguments":{"text":"Contact mask-ana@example.com for help."}}}
      """
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should be "Contact {EMAIL} for help."
    And the response body should not contain "mask-ana@example.com"

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"lookup","arguments":{"text":"This result contains violence"}}}
      """
    Then the response status code should be 422
    And the response should be valid JSON
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A Server-Sent Events tool result is checked and keeps its events
    Given I generate a unique resource name from "bedrock-mcp-resp-sse" and store it as "mcpName"
    And I generate a unique value from "bedrock-mcp-resp-sse" and store it as "mcpDisplayName"
    And I generate a unique API version from "bedrock-mcp-resp-sse" and store it as "mcpVersion"
    And I generate a unique API context from "/bedrock-mcp-resp-sse" and store it as "mcpContext"
    And I generate a unique resource name from "bedrock-mcp-resp-sse" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"enabled":false},"response":{"enabled":true,"jsonPath":"$.result.content[*].text"}}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    # initialize has no tool arguments or tool result, so the policy has nothing to check in it.
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"lookup","arguments":{"shape":"events","text":"Order 42 shipped."},"_meta":{"progressToken":"bedrock-sse"}}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should match pattern "(?s)notifications/progress.*notifications/progress.*id.:7.*Order 42 shipped\."

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"lookup","arguments":{"shape":"events","text":"Contact mask-ana@example.com for help."}}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "event: message"
    And the response body should contain "Contact {EMAIL} for help."
    And the response body should not contain "mask-ana@example.com"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: Violating content in a Server-Sent Events tool result is blocked
    Given I generate a unique resource name from "bedrock-mcp-resp-sse-block" and store it as "mcpName"
    And I generate a unique value from "bedrock-mcp-resp-sse-block" and store it as "mcpDisplayName"
    And I generate a unique API version from "bedrock-mcp-resp-sse-block" and store it as "mcpVersion"
    And I generate a unique API context from "/bedrock-mcp-resp-sse-block" and store it as "mcpContext"
    And I generate a unique resource name from "bedrock-mcp-resp-sse-block" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"enabled":false},"response":{"enabled":true,"jsonPath":"$.result.content[*].text"}}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    # initialize has no tool arguments or tool result, so the policy has nothing to check in it.
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"lookup","arguments":{"shape":"events","text":"This result contains violence"}}}
      """
    Then the response status code should be 422
    And the response should be valid JSON
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
