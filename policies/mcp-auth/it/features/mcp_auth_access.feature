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

  # MAN #19: with the methods group disabled, the handshake and the other method-level requests
  # are public, while tools/call stays protected by the tools group (enabled by default). This is
  # the "handshake open, capabilities protected" pattern. The mock's log then holds exactly the
  # three method-level requests and no tools/call.
  Scenario: With methods disabled the handshake is public and tool calls still need a token
    Given I generate a unique resource name from "mcp-auth-open-handshake" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-open-handshake" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-open-handshake" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-access" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-open-handshake" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"methods":{"enabled":false}}}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"it","version":"1.0"}}}
      """
    Then the response status code should be 200

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","method":"notifications/initialized"}
      """
    Then the response status code should be 202

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":1,"method":"ping"}
      """
    Then the response status code should be 200

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 401
    And the response should match the expected error response "mcp-auth-access-denied"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 3 items
    And the JSON response array "requests" should contain an item with "method" equal to "initialize"
    And the JSON response array "requests" should contain an item with "method" equal to "notifications/initialized"
    And the JSON response array "requests" should contain an item with "method" equal to "ping"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAN #22: the four groups set differently in one policy: tools enabled, resources disabled,
  # prompts enabled with greeting as the exception, methods disabled. Each request follows only
  # its own group: the tool call and the non-exception prompt need a token, while the resource
  # read, the excepted prompt and ping pass. The mock's log holds exactly those three, so the
  # refused prompt never reached it although the excepted one did.
  Scenario: Each group decides only its own requests when the four groups are set differently
    Given I generate a unique resource name from "mcp-auth-mixed-groups" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-mixed-groups" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-mixed-groups" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-access" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-mixed-groups" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"tools":{"enabled":true},"resources":{"enabled":false},"prompts":{"enabled":true,"exceptions":["greeting"]},"methods":{"enabled":false}}}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 401
    And the response should match the expected error response "mcp-auth-access-denied"

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///docs/readme.txt"}}
      """
    Then the response status code should be 200

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"greeting"}}
      """
    Then the response status code should be 200

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"farewell"}}
      """
    Then the response status code should be 401
    And the response should match the expected error response "mcp-auth-access-denied"

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":5,"method":"ping"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 3 items
    And the JSON response array "requests" should contain an item with "method" equal to "resources/read"
    And the JSON response array "requests" should contain an item with "method" equal to "prompts/get"
    And the JSON response array "requests" should contain an item with "method" equal to "ping"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAN #25: an exception that names a tool the backend does not have is accepted, never matches a
  # real tool, and changes no real verdict. The stateless MCP mock (port 3009) has only add, echo
  # and headers. The excepted name itself does pass mcp-auth without a token, and the backend then
  # answers it with its own "unknown tool" error, so nothing real is exposed.
  Scenario: An exception for a tool the backend does not have changes no real verdict
    Given I generate a unique resource name from "mcp-auth-missing-tool" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-missing-tool" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-missing-tool" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-missing-tool" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"tools":{"enabled":true,"exceptions":["no_such_tool"]}}}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 401
    And the response should match the expected error response "mcp-auth-missing-tool-denied"

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}
      """
    Then the response status code should be 200
    And the JSON response field "error.code" should be "-32602"
    And the response body should contain "unknown tool"

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAN #33: a policy change takes effect on the deployed proxy without redeploying it. Version 1
  # protects everything (empty params), version 2 disables the tools group, and version 3 removes
  # mcp-auth. Each step polls until the new behaviour shows: a tool call passes without a token
  # from version 2 on, tools/list (methods group) passes only once the policy is gone, and the
  # metadata endpoint, which mcp-auth serves, disappears with it.
  Scenario: Updating the proxy changes its protection without a redeploy
    Given I generate a unique resource name from "mcp-auth-update" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-update" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-update" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-update" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":40,"b":60}}}
      """

    # Version 2: tools disabled. A tool call passes without a token; tools/list still needs one.
    When I authenticate using basic auth as "admin"
    And I update MCP proxy "${CTX:mcpName}" from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"tools":{"enabled":false}}}] |
    Then the response should be successful
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":40,"b":60}}}
      """
    And I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/list"}
      """
    Then the response status code should be 401

    # Version 3: no policy. The endpoint is fully open and the metadata endpoint is gone.
    When I authenticate using basic auth as "admin"
    And I update MCP proxy "${CTX:mcpName}" from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [] |
    Then the response should be successful
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/list"}
      """
    When I clear all headers
    And I send a "GET" request to "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    Then the response status code should be 404

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
