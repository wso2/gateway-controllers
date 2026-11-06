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

  # ---- Tool lists -----------------------------------------------------------------------

  # The upstream is the MCP mock (testbench port 3009), which serves three real tools: add,
  # echo and headers. The tools/list answer is checked for its JSON-RPC envelope and for the
  # number of tools left after filtering; "should have N items" fails if result.tools is null
  # or missing, so a count of 0 proves an empty array. The denied tool must be missing from the
  # list as well as refused when called. The call uses id 21 so its response can be held to the
  # recorded mcp-acl-list-tool-denied.json.
  Scenario Outline: A tools/list keeps only the tools the tools block permits (<case>)
    Given I generate a unique resource name from "mcp-acl-list" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-list" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-list" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-list" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-acl-list","version":"v1","params":{"tools":<tools>}}] |
    Then the resource creation response should indicate successful deployment
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp" until successful

    When I use the MCP Client to send a tools/list request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "jsonrpc" should be "2.0"
    And the JSON response field "id" should be 3
    And the JSON response field "error" should not exist
    And the JSON response array field "result.tools" should have <listed> items
    And the JSON response array "result.tools" should not contain an item with "name" equal to "<denied>"

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"<denied>","arguments":{}}}
      """
    Then the response status code should be 400
    And the response should match the expected error response "mcp-acl-list-tool-denied"

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    # The same tools/list sent straight to the mock, without the gateway, still lists all
    # three tools, so a shorter list above was made by the policy. The mock answers in SSE,
    # which the JSON steps cannot read, so each tool is matched by its description. The
    # mock rejects a request whose Accept header does not offer both content types.
    When I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to the "mcp" service at "/mcp" with body:
      """
      {"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}
      """
    Then the response should be successful
    And the response body should contain "Adds two numbers"
    And the response body should contain "Echoes back the input"
    And the response body should contain "Reports the value of a header"

    Examples: tools
      | case                                             | tools                                | listed | denied  |
      # MAC #10: deny mode with no exceptions is a full lockdown; the list is an empty array and
      # every call is denied. One row per tool, so each of the mock's three tools is shown denied.
      | deny mode with no exceptions, add is denied      | {"mode":"deny","exceptions":[]}      | 0      | add     |
      | deny mode with no exceptions, echo is denied     | {"mode":"deny","exceptions":[]}      | 0      | echo    |
      | deny mode with no exceptions, headers is denied  | {"mode":"deny","exceptions":[]}      | 0      | headers |
      # MAC #7: deny mode with T1 as the only exception; the list holds exactly T1. One row per
      # unlisted tool, so with a count of 1 and both other tools missing, the one left is add.
      # The scenario after this outline checks that add's fields are unchanged.
      | deny mode with one exception, echo is removed    | {"mode":"deny","exceptions":["add"]} | 1      | echo    |
      | deny mode with one exception, headers is removed | {"mode":"deny","exceptions":["add"]} | 1      | headers |

  # MAC #7: the entry the policy keeps reaches the client with its fields unchanged. The policy
  # decodes the list, removes the denied entries and encodes it again, so the keys come back in
  # a different order; the values are what must not change. Each value below is the 3009 mock's
  # own definition of add, which the outline above shows the mock serves without the gateway.
  # cacheScope and ttlMs sit next to the list and must survive the filter too.
  Scenario: A tools/list keeps the fields of a permitted tool unchanged
    Given I generate a unique resource name from "mcp-acl-fields" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-fields" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-fields" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-fields" and store it as "mcpContext"
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

    When I use the MCP Client to send a tools/list request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "error" should not exist
    And the JSON response array field "result.tools" should have 1 item
    And the JSON response field "result.tools[0].name" should be "add"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "description" equal to "Adds two numbers"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.type" equal to "object"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.properties.a.type" equal to "number"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.properties.a.description" equal to "First number"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.properties.b.type" equal to "number"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.properties.b.description" equal to "Second number"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.required[0]" equal to "a"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.required[1]" equal to "b"
    And the JSON response array "result.tools" item with "name" equal to "add" should not have field "inputSchema.required[2]"
    And the JSON response array "result.tools" item with "name" equal to "add" should have "inputSchema.additionalProperties" equal to "false"
    And the JSON response field "result.cacheScope" should be "public"
    And the JSON response field "result.ttlMs" should be 0

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAC #11: allow mode with no exceptions; the full discovery and call sequence behaves as if
  # no policy were attached.
  # Two proxies point at the same MCP mock (testbench port 3009): one without any policy, which
  # gives the baseline, and one with the policy. Each answer from the baseline is stored and the
  # same request through the policy must return exactly the same bytes. The baseline answers are
  # first checked for real content (three tools, real tool results), so the comparison cannot
  # pass by matching two errors. Only well-formed requests are compared: the policy still
  # rejects a malformed request itself, which the malformed-request scenarios cover.
  Scenario: Allow mode with no exceptions behaves as if no policy were attached
    Given I generate a unique resource name from "mcp-acl-baseline" and store it as "baselineName"
    And I generate a unique value from "mcp-acl-baseline" and store it as "baselineDisplayName"
    And I generate a unique API version from "mcp-acl-baseline" and store it as "baselineVersion"
    And I generate a unique API context from "/mcp-acl-baseline" and store it as "baselineContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:baselineName} |
      | displayName       | ${CTX:baselineDisplayName} |
      | version           | ${CTX:baselineVersion} |
      | context           | ${CTX:baselineContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
    Then the resource creation response should indicate successful deployment
    And I use the MCP Client to send an initialize request to "${CTX:baselineContext}/mcp" until successful

    Given I generate a unique resource name from "mcp-acl-allow-all" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-allow-all" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-allow-all" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-allow-all" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-acl-list","version":"v1","params":{"tools":{"mode":"allow","exceptions":[]}}}] |
    Then the resource creation response should indicate successful deployment
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp" until successful

    # Discovery: the full list of three tools, unchanged.
    When I use the MCP Client to send a tools/list request to "${CTX:baselineContext}/mcp"
    Then the response should be successful
    And the JSON response array field "result.tools" should have 3 items
    And I store the response body as "baselineList"
    When I use the MCP Client to send a tools/list request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response body should be:
      """
      ${CTX:baselineList}
      """

    # Calls: every tool in the list runs and returns the same result as without the policy.
    When I use the MCP Client to send "add" tools/call request to "${CTX:baselineContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."
    And I store the response body as "baselineAdd"
    When I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response body should be:
      """
      ${CTX:baselineAdd}
      """

    When I use the MCP Client to send "echo" tools/call request to "${CTX:baselineContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "Echo: Hello, World!"
    And I store the response body as "baselineEcho"
    When I use the MCP Client to send "echo" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response body should be:
      """
      ${CTX:baselineEcho}
      """

    When I use the MCP Client to send "headers" tools/call request to "${CTX:baselineContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should contain "Authorization:"
    And I store the response body as "baselineHeaders"
    When I use the MCP Client to send "headers" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response body should be:
      """
      ${CTX:baselineHeaders}
      """

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
    When I delete the MCP proxy "${CTX:baselineName}"
    Then the response should be successful
