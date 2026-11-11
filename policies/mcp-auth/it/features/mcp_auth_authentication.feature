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

@mcp-auth-authentication
Feature: mcp-auth authentication of MCP requests
  As an API developer
  I want mcp-auth to check a valid token on every MCP request
  So that only callers with a trusted token reach the MCP server

  # Every scenario sends handshake-style requests (specVersion 2025-06-18) and builds its upstream
  # URL with ${CTX:gatewayMCPUpstreamPath}, so it runs on gateways 1.1.0, 1.2.0 and latest. The
  # block's overlay (overlays/gateway.toml) configures the key managers; the tokens come from the
  # testbench JWKS service with the mock-jwks issuer.
  #
  # MAN #6 (with default settings, initialize without a token is refused) is already covered on
  # every gateway by mcp_auth_error_compatibility.feature, so it has no scenario of its own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # ---- Sessions ---------------------------------------------------------------------------

  # The upstream is the MCP mock that issues sessions (testbench port 3014, mcp-legacy), which
  # keeps its sessions per partition. The proxy uses the default settings (empty params), so every
  # request needs a token.
  # MAN #7: a valid token on initialize reaches the backend and a session is issued. (200 with a
  # token is already covered elsewhere; what is new here is the session.)
  # MAN #11: two calls on that session with the token both succeed, while the same session without
  # the token is refused: mcp-auth checks every request and keeps no session state of its own. A
  # call with an unknown session id gets the mock's own 404, which shows that the successful calls
  # really used the live session.
  Scenario: Every request on an MCP session needs its own valid token
    Given I generate a unique resource name from "mcp-auth-session" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-session" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-session" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-session" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-session" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3014/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{}}] |
    Then the resource creation response should indicate successful deployment

    # Polling until the 401 waits until the proxy's routes are live.
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # MAN #7: with a valid token, initialize reaches the backend and the backend issues a session.
    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response header "x-envoy-upstream-service-time" should exist
    And the JSON response field "result.serverInfo.name" should be "everything"
    And I store the response header "Mcp-Session-Id" as "mcpSession"

    # MAN #11: two calls on the session with the token both succeed.
    When I set header "Mcp-Session-Id" to "${CTX:mcpSession}"
    And I use the MCP Client to send a notifications/initialized notification to "${CTX:mcpContext}/mcp"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."
    When I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."

    # MAN #11: the same session without the token is refused; the open session is no free pass.
    When I clear all headers
    And I set header "Mcp-Session-Id" to "${CTX:mcpSession}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    And the response header "Mcp-Session-Id" should be "${CTX:mcpSession}"

    # Control: the token with a session id the backend never issued gets the backend's own 404.
    When I set header "Authorization" to "Bearer ${CTX:token}"
    And I set header "Mcp-Session-Id" to "no-such-session"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 404
    And the response body should contain "session not found"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # ---- Empty params -----------------------------------------------------------------------

  # MAN #30: empty params are accepted, and every group then defaults to enabled, so every kind
  # of MCP request needs a token (unlike mcp-acl-list, whose empty params are refused at deploy).
  # The upstream is the scripted MCP mock (testbench port 3021), which answers any request
  # without a handshake and records every request it receives under the scenario's partition.
  # Each row sends one kind of request without a token: it is refused and the log stays empty.
  # The same request with a token then reaches the mock and is logged, which shows the empty log
  # could have been otherwise. The 401's exact shape is pinned by mcp_auth_error_compatibility.
  Scenario Outline: With empty params every kind of MCP request needs a token (<method>)
    Given I generate a unique resource name from "mcp-auth-empty" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-empty" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-empty" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-empty" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-empty" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{}}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <body>
      """
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 0 items

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <body>
      """
    Then the response status code should be <status>
    When I clear all headers
    And I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 1 item
    And the JSON response array "requests" should contain an item with "method" equal to "<method>"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: request kinds
      | method                    | status | body                                                                                                                                                  |
      # MAN #30: every kind of MCP request below is refused without a token under empty params.
      | initialize                | 200    | {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"it","version":"1.0"}}} |
      | notifications/initialized | 202    | {"jsonrpc":"2.0","method":"notifications/initialized"}                                                                                                |
      | ping                      | 200    | {"jsonrpc":"2.0","id":1,"method":"ping"}                                                                                                              |
      | tools/list                | 200    | {"jsonrpc":"2.0","id":2,"method":"tools/list"}                                                                                                        |
      | tools/call                | 200    | {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{}}}                                                                 |
      | resources/read            | 200    | {"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///docs/readme.txt"}}                                                         |
      | prompts/get               | 200    | {"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"greeting"}}                                                                          |

  # MAN #30: with empty params every configured key manager is trusted, so a token from each one
  # gets in. The tool name in each call marks which token reached the mock's request log.
  # (oidc-km is tested with MAN #8, which adds the step that mints its tokens.)
  Scenario Outline: With empty params a token from each configured key manager gets in (<keyManager>)
    Given I generate a unique resource name from "mcp-auth-every-km" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-every-km" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-every-km" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-every-km" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-every-km" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I get a JWT token from the mock JWKS server with issuer "<issuer>" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "<keyManager>" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the JSON response field "result.content[0].text" should be "ok"
    When I clear all headers
    And I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array "requests" should contain an item with "tool" equal to "<keyManager>"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: key managers
      | keyManager      | issuer                      |
      # MAN #30: the token's issuer belongs to mock-jwks.
      | mock-jwks       | http://testbench:3001/token |
      # MAN #30: the token's issuer belongs to wrong-issuer-km.
      | wrong-issuer-km | http://expected-issuer.com  |

  # A request with no JSON-RPC body names no method, tool, resource or prompt, so the exception
  # lists cannot apply to it: mcp-auth checks the token in the header phase instead. The control
  # sends the same request with a valid token and proves it reaches the mock (the router's
  # x-envoy-upstream-service-time header), so the first 401 came from mcp-auth and not from a
  # missing route. The mock accepts only POST, so it answers GET and DELETE with 405, and it
  # answers an empty POST with 400 parse error. A named tools/call sent without a token shows
  # how the proxy treats a request the exception lists can match: protected under default
  # params (401), open with every group disabled (200), while the bodiless request stays 401.
  Scenario Outline: A request that names no capability is checked on the transport (<method>)
    Given I generate a unique resource name from "mcp-auth-transport" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-transport" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-transport" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-transport" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-transport" and store it as "partition"
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

    When I clear all headers
    And I send a "<method>" request to "${CTX:mcpContext}/mcp" until status 401
    Then the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    And the response header "x-envoy-upstream-service-time" should not exist

    When I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be <namedStatus>

    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "<method>" request to "${CTX:mcpContext}/mcp"
    Then the response status code should be <tokenStatus>
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: transport requests
      | method | params                                                                                                            | namedStatus | tokenStatus |
      # MAN #26: default configuration; GET /mcp without a token is rejected in the header phase.
      | GET    | {}                                                                                                                | 401         | 405         |
      # MAN #26: default configuration; DELETE /mcp without a token is rejected in the header phase.
      | DELETE | {}                                                                                                                | 401         | 405         |
      # MAN #12: every group disabled, so a named call passes without a token, yet an empty POST is still rejected.
      | POST   | {"tools":{"enabled":false},"resources":{"enabled":false},"prompts":{"enabled":false},"methods":{"enabled":false}} | 200         | 400         |
