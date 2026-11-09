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

@mcp-acl-list
Feature: mcp-acl-list rejection of malformed requests
  As an API developer
  I want mcp-acl-list to refuse a request it cannot read
  So that a malformed request never reaches the MCP server behind the proxy

  # Every scenario sends handshake-style requests (initialize first, specVersion 2025-06-18)
  # and builds its upstream URL with ${CTX:gatewayMCPUpstreamPath}, so it runs on gateways
  # 1.1.0, 1.2.0 and latest. A gateway version that answers a row differently gets its own
  # expected-error file under resources/expected-error-responses/<version>/.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # ---- Malformed requests ---------------------------------------------------------------

  # The upstream is the MCP mock (testbench port 3009). The policy must read a request before
  # it can decide on it, so a request it cannot read is refused by the policy itself. A valid
  # call goes first and carries x-envoy-upstream-service-time, which the gateway adds only to
  # an answer that came from the mock; the malformed request's answer must not carry it, so it
  # never reached the mock. Each answer is held to its recorded expected-error file.
  Scenario Outline: A malformed request is rejected by the policy (<case>)
    Given I generate a unique resource name from "mcp-acl-malformed" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-malformed" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-malformed" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-malformed" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-acl-list","version":"v1","params":{"tools":{"mode":"deny","exceptions":["add"]}}}] |
    Then the resource creation response should indicate successful deployment
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp" until successful

    When I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."
    And the response header "x-envoy-upstream-service-time" should exist

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <body>
      """
    Then the response status code should be 400
    And the response should match the expected error response "<error>"
    And the response header "x-envoy-upstream-service-time" should not exist

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: malformed requests
      | case                                | body                                                                | error                       |
      # MAC #18: a body that is not valid JSON at all; 400 with -32700 Invalid JSON and "id":null.
      # The second row is a valid call cut short: it carries "id":7, and the answer still says
      # null, because nothing in a body that cannot be read is trusted.
      | not JSON at all                     | {not json                                                           | mcp-acl-list-invalid-json   |
      | a call cut short, carrying an id    | {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"add" | mcp-acl-list-invalid-json   |
      | plain text                          | hello                                                               | mcp-acl-list-invalid-json   |
