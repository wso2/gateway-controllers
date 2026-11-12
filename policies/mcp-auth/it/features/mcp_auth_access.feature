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

@mcp-auth-access
Feature: mcp-auth access decisions by group and exceptions
  As an API developer
  I want each MCP request decided by its own group's enabled flag and exceptions
  So that I can open some capabilities to callers without a token and protect the rest

  # mcp-auth puts every request in one group by its JSON-RPC method: tools/call in tools (matched
  # by params.name), resources/read in resources (params.uri), prompts/get in prompts
  # (params.name), and every other method in methods (the method name). Exceptions invert the
  # group's decision and match names exactly:
  #   enabled, not an exception   -> a token is needed
  #   enabled, an exception       -> open
  #   disabled, not an exception  -> open
  #   disabled, an exception      -> a token is needed
  # Every row sends one request that passes without a token and one that is refused, and the
  # scripted mock's log then holds exactly the one that passed: proof that the refused request
  # never reached the backend and that the passing one did. The scenarios send handshake-style
  # requests and build their upstream URL with ${CTX:gatewayMCPUpstreamPath}, so they run on
  # gateways 1.1.0, 1.2.0 and latest.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: A tool call is decided by the tools group and its exceptions (<case>)
    Given I generate a unique resource name from "mcp-auth-access" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-access" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-access" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-access" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-access" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":<params>}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"<passes>","arguments":{}}}
      """
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should be "ok"

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <refused>
      """
    Then the response status code should be 401
    And the response should match the expected error response "mcp-auth-access-denied"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 1 item
    And the JSON response array "requests" should contain an item with "tool" equal to "<passes>"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: tools group
      | case                      | params                                           | passes | refused                                                                                |
      # MAN #14: tools enabled with add as the exception; add passes without a token, echo is refused.
      | exception under enabled   | {"tools":{"enabled":true,"exceptions":["add"]}}  | add    | {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}} |
      # MAN #23: exceptions match exactly, so ADD is not the exception add and fails closed under an enabled group.
      | case variant fails closed | {"tools":{"enabled":true,"exceptions":["add"]}}  | add    | {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ADD","arguments":{}}}  |
      # MAN #15 and #21: tools disabled lets every tool call in without a token, but tools/list belongs to the methods group and stays protected.
      | disabled group            | {"tools":{"enabled":false}}                      | echo   | {"jsonrpc":"2.0","id":2,"method":"tools/list"}                                         |
      # MAN #16: tools disabled with add as the exception; the exception inverts the decision, so add is refused and echo passes.
      | exception under disabled  | {"tools":{"enabled":false,"exceptions":["add"]}} | echo   | {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{}}}  |

    # A known gap: under a disabled group the same exact match fails open, so a case variant of a
    # protected tool escapes the inverted protection and reaches the backend without a token. The
    # row asserts today's behaviour, so it keeps running and fails once the policy closes the gap.
    @known-gap @security
    Examples: tools group, known gap
      | case                    | params                                           | passes | refused                                                                               |
      # MAN #24: tools disabled with add as the exception; ADD passes without a token while add is refused.
      | case variant fails open | {"tools":{"enabled":false,"exceptions":["add"]}} | ADD    | {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{}}} |

  # The other three groups follow the same rule as tools, each with its own match: resources by
  # the full params.uri, prompts by params.name, and methods by the full JSON-RPC method name.
  # The mock's log records only the method of these requests, so the log check names the method.
  Scenario Outline: A request is decided by its own group and its exceptions (<case>)
    Given I generate a unique resource name from "mcp-auth-access" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-access" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-access" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-access" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-access" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":<params>}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <passes>
      """
    Then the response status code should be 200

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <refused>
      """
    Then the response status code should be 401
    And the response should match the expected error response "mcp-auth-access-denied"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 1 item
    And the JSON response array "requests" should contain an item with "method" equal to "<method>"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: resources group
      | case                      | params                                                                              | method         | passes                                                                                        | refused                                                                                      |
      # MAN #17: resource exceptions match the full params.uri. readme's URI is an exception, so it passes; guide.txt is listed only as a bare file name, which never matches a URI, so guide's read is refused.
      | exception is the full URI | {"resources":{"enabled":true,"exceptions":["file:///docs/readme.txt","guide.txt"]}} | resources/read | {"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///docs/readme.txt"}} | {"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///docs/guide.txt"}} |

    Examples: prompts group
      | case                         | params                                                 | method      | passes                                                                       | refused                                                                      |
      # MAN #18: prompts enabled with greeting as the exception; greeting passes without a token, farewell is refused.
      | exception is the prompt name | {"prompts":{"enabled":true,"exceptions":["greeting"]}} | prompts/get | {"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greeting"}} | {"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"farewell"}} |

    Examples: methods group
      | case                         | params                                                   | method     | passes                                         | refused                                  |
      # MAN #20: methods enabled with tools/list as the exception, matched by the full method name; tools/list passes, ping is refused.
      | exception is the method name | {"methods":{"enabled":true,"exceptions":["tools/list"]}} | tools/list | {"jsonrpc":"2.0","id":1,"method":"tools/list"} | {"jsonrpc":"2.0","id":2,"method":"ping"} |
