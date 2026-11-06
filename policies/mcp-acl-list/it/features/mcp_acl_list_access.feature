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
Feature: mcp-acl-list access decisions
  As an API developer
  I want mcp-acl-list to let through only the MCP capabilities its configuration permits
  So that a client can use exactly the tools, resources and prompts it is allowed to use

  # Every scenario sends handshake-style requests (initialize first, specVersion 2025-06-18)
  # and builds its upstream URL with ${CTX:gatewayMCPUpstreamPath}, so it runs on gateways
  # 1.1.0, 1.2.0 and latest. The scenarios that need the newer 2026-07-28 requests are in
  # mcp_acl_list.feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # ---- Tool calls -----------------------------------------------------------------------

  # The upstream is the scripted MCP server (testbench port 3021). It answers "ok" to a call
  # for any tool and records every request it receives under the scenario's own partition,
  # so its request log proves that a denied call never reached the backend. The denied call
  # uses id 21 so its response can be held to the recorded mcp-acl-list-tool-denied.json.
  Scenario Outline: A tools/call is decided by the tools block (<case>)
    Given I generate a unique resource name from "mcp-acl-call" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-call" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-call" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-call" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-acl-call" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-acl-list","version":"v1","params":{"tools":<tools>}}] |
    Then the resource creation response should indicate successful deployment
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp" until successful

    When I use the MCP Client to send "<allowed>" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "ok"

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"<denied>","arguments":{}}}
      """
    Then the response status code should be 400
    And the response should match the expected error response "mcp-acl-list-tool-denied"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the response should be successful
    And the JSON response array "requests" should contain an item with "tool" equal to "<allowed>"
    And the JSON response array "requests" should not contain an item with "tool" equal to "<denied>"

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: tools
      | case                                                  | tools                                       | allowed | denied  |
      # MAC #1: deny mode with T1 as the only exception; T1 runs, T2 is denied.
      | deny mode with one exception                          | {"mode":"deny","exceptions":["add"]}        | add     | echo    |
      # MAC #2: allow mode with T1 as the only exception; T2 runs, T1 is denied.
      | allow mode with one exception                         | {"mode":"allow","exceptions":["add"]}       | echo    | add     |
      # MAC #3: deny mode with several exceptions; every listed tool runs, an unlisted tool is denied.
      # One row per listed tool, so each listed tool is shown to run with the same configuration.
      | deny mode with several exceptions, first listed tool  | {"mode":"deny","exceptions":["add","echo"]} | add     | headers |
      | deny mode with several exceptions, second listed tool | {"mode":"deny","exceptions":["add","echo"]} | echo    | headers |
      # MAC #21: exceptions but no mode; the block is accepted and the mode defaults to deny,
      # so the listed tool runs and an unlisted tool is denied (allow would swap the verdicts).
      | no mode, defaults to deny                             | {"exceptions":["add"]}                      | add     | echo    |
