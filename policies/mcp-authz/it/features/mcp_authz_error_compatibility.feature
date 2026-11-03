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

@mcp-authz
Feature: Mcp authz policy
  As an API developer
  I want the mcp-authz policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: mcp-authz rejects a governed tool call with no authenticated identity
    Given I generate a unique resource name from "compat-mcp-authz-anon" and store it as "mcpName"
    And I generate a unique value from "compat-mcp-authz-anon" and store it as "mcpDisplayName"
    And I generate a unique API version from "compat-mcp-authz-anon" and store it as "mcpVersion"
    And I generate a unique API context from "/compat-mcp-authz-anon" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["compat-add-scope"]}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set request host to "compat-mcp.example.com"
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"add","arguments":{"a":40,"b":60}}}
      """
    Then the response status code should be 401
    And the response should match the expected error response "mcp-authz-unauthenticated"
