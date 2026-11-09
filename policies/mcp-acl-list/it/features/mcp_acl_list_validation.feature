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
  # The policy checks a request's params only for a capability type that has a block in its
  # configuration, so all three blocks are configured. The resources and prompts blocks deny
  # everything; that does not matter here, because a malformed request is refused before the
  # policy looks at the mode.
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
      | spec.policies     | [{"name":"mcp-acl-list","version":"v1","params":{"tools":{"mode":"deny","exceptions":["add"]},"resources":{"mode":"deny","exceptions":[]},"prompts":{"mode":"deny","exceptions":[]}}}] |
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
      | case                                | body                                                                                       | error                                |
      # MAC #18: a body that is not valid JSON at all; 400 with -32700 Invalid JSON and "id":null.
      # The second row is a valid call cut short: it carries "id":7, and the answer still says
      # null, because nothing in a body that cannot be read is trusted.
      | not JSON at all                     | {not json                                                                                  | mcp-acl-list-invalid-json            |
      | a call cut short, carrying an id    | {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"add"                       | mcp-acl-list-invalid-json            |
      | plain text                          | hello                                                                                      | mcp-acl-list-invalid-json            |
      # MAC #17: the key that names the target differs per capability type (resources/read uses
      # params.uri, prompts/get uses params.name), so a request carrying the other key has no
      # name; 400 with -32602 and a message naming the type. The body was readable, so its id
      # is echoed.
      | resources/read carrying params.name | {"jsonrpc":"2.0","id":31,"method":"resources/read","params":{"name":"file:///readme.txt"}} | mcp-acl-list-missing-resources-name  |
      | prompts/get carrying params.uri     | {"jsonrpc":"2.0","id":32,"method":"prompts/get","params":{"uri":"greeting"}}               | mcp-acl-list-missing-prompts-name    |
      # MAC #16: tools/call whose params is missing or not an object (400, -32602 Invalid MCP
      # request params), or whose name is unusable (400, -32602 Missing MCP tools name). Rows
      # that give the same answer share an id, so they share an expected-error file.
      # Gateway latest reads the body with its request resolver before the policy sees it, and
      # answers differently, so it has its own files under expected-error-responses/latest/:
      # a missing or non-object params answers Missing MCP tools name, and a name that is not
      # a string answers -32600 "Request body has a member of the wrong type" with id null.
      | tools/call without params           | {"jsonrpc":"2.0","id":41,"method":"tools/call"}                                            | mcp-acl-list-invalid-params          |
      | tools/call with params a string     | {"jsonrpc":"2.0","id":41,"method":"tools/call","params":"add"}                             | mcp-acl-list-invalid-params          |
      | tools/call with params an array     | {"jsonrpc":"2.0","id":41,"method":"tools/call","params":["add"]}                           | mcp-acl-list-invalid-params          |
      | tools/call without a name           | {"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"arguments":{"a":1,"b":2}}}       | mcp-acl-list-missing-tools-name      |
      | tools/call with a blank name        | {"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":""}}                       | mcp-acl-list-missing-tools-name      |
      | tools/call with a whitespace name   | {"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"   "}}                    | mcp-acl-list-missing-tools-name      |
      | tools/call with a number as name    | {"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":123}}                      | mcp-acl-list-tools-name-not-a-string |

  # ---- Method casing (known gap) --------------------------------------------------------

  # MAC #19: a tools/call whose method is cased differently (Tools/Call, TOOLS/CALL) is not
  # recognised as an MCP method, so the policy checks neither the call nor its tool name and
  # forwards the request as it is. This is a known gap: a server that matched method names
  # without regard to case would run a tool the policy denies. The scenario pins the current
  # behaviour, so a fix shows up as a deliberate change to it.
  # The upstream is the scripted MCP server (testbench port 3021). It compares method names
  # exactly, so it answers the odd casing with its own -32601, and it records every request
  # it receives under the scenario's partition, method spelled as sent. The same call in the
  # normal casing is denied first, which shows echo is a tool the policy blocks. The log must
  # hold the allowed add call and not a tools/call for echo, so it is the right log and records
  # only what passed the policy.
  @security
  Scenario: A tools/call with the method cased differently is forwarded without a check
    Given I generate a unique resource name from "mcp-acl-casing" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-casing" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-casing" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-casing" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-acl-casing" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-acl-list","version":"v1","params":{"tools":{"mode":"deny","exceptions":["add"]}}}] |
    Then the resource creation response should indicate successful deployment
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp" until successful

    # The normal casing: echo is denied by the policy.
    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"echo","arguments":{}}}
      """
    Then the response status code should be 400
    And the response should match the expected error response "mcp-acl-list-tool-denied"
    And the response header "x-envoy-upstream-service-time" should not exist

    # The same call in other casings passes the policy and is answered by the server.
    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":51,"method":"Tools/Call","params":{"name":"echo","arguments":{}}}
      """
    Then the response should be successful
    And the JSON response field "error.message" should be "method not found: Tools/Call"
    And the response header "x-envoy-upstream-service-time" should exist
    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":52,"method":"TOOLS/CALL","params":{"name":"echo","arguments":{}}}
      """
    Then the response should be successful
    And the JSON response field "error.message" should be "method not found: TOOLS/CALL"
    And the response header "x-envoy-upstream-service-time" should exist

    # The allowed tool in the normal casing, so the log has a call that passed the policy.
    When I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "ok"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the response should be successful
    And the JSON response array "requests" should contain an item with "method" equal to "Tools/Call"
    And the JSON response array "requests" should contain an item with "method" equal to "TOOLS/CALL"
    And the JSON response array "requests" should contain an item with "tool" equal to "add"
    And the JSON response array "requests" should not contain an item with "tool" equal to "echo"

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # ---- Invalid configurations -----------------------------------------------------------

  # The gateway controller validates the policy reference and its params against the policy's
  # definition before it creates the proxy, so an invalid configuration is refused at deploy
  # time: 400 with status "error", and a message that names what is wrong. The MCP proxy API
  # writes "configuration validation failed" in lower case where the REST API capitalises it,
  # so the message is matched without regard to case. The proxy is then read back and must not
  # exist, so the policy was never attached as a no-op.
  Scenario Outline: An invalid policy configuration is refused at deploy time (<case>)
    Given I generate a unique resource name from "mcp-acl-invalid" and store it as "mcpName"
    And I generate a unique value from "mcp-acl-invalid" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-acl-invalid" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-acl-invalid" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-acl-list","version":"<version>","params":<params>}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should match pattern "(?i)configuration validation failed"
    And the response body should contain "<message>"

    When I get the MCP proxy "${CTX:mcpName}"
    Then the response status code should be 404

    Examples: invalid configurations
      | case         | version | params | message                 |
      # MAC #20: params with no tools, resources or prompts block; the definition requires at
      # least one, so a policy that would check nothing cannot be attached.
      | empty params | v1      | {}     | spec.policies[0].params |
