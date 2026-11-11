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

@mcp-auth-custom-token
Feature: mcp-auth with a custom token header, scheme and failure status
  As a gateway operator
  I want to choose where clients put their token and which status a failed authentication gets
  So that mcp-auth fits clients and gateways that do not use the defaults

  # These settings live in the gateway's configuration, not in a proxy's params (gateway 1.2.0
  # rejects them there), so this file has its own block and overlay
  # (overlays/mcp-auth-custom-token.toml): the token goes in X-MCP-Token with the scheme Token,
  # and a failed authentication answers 403. The scenarios send handshake-style requests and build
  # their upstream URL with ${CTX:gatewayMCPUpstreamPath}, so they run on gateways 1.1.0, 1.2.0
  # and latest.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # MAN #13: with onFailureStatusCode 403, a request without a token gets 403 instead of 401. The
  # recorded answer has the same keys as the default 401 (mcp-auth-missing-token): only the error
  # word changes, to "Forbidden", and the WWW-Authenticate challenge is the same. A token in the
  # configured header and scheme gets in, and the mock's log holds only that call.
  Scenario: A failed authentication answers with the configured status 403
    Given I generate a unique resource name from "mcp-auth-status-403" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-status-403" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-status-403" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-status-403" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-status-403" and store it as "partition"
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

    # Polling an empty POST until 403 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 403

    When I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 403
    And the response should match the expected error response "mcp-auth-failure-status-403"

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "X-MCP-Token" to "Token ${CTX:token}"
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should be "ok"
    When I clear all headers
    And I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 1 item

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAN #10 and #9: on this gateway the token goes in X-MCP-Token with the scheme Token. Each row
  # first sends a correctly shaped token (200), so the refusal is about the shape alone, then the
  # wrong shape (403, this gateway's failure status). The mock's log holds only the first call,
  # so the refused one never reached it.

  Scenario Outline: Only a token in the configured header and scheme gets in (<case>)
    Given I generate a unique resource name from "mcp-auth-custom-shape" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-custom-shape" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-custom-shape" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-custom-shape" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-custom-shape" and store it as "partition"
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
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 403

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "X-MCP-Token" to "Token ${CTX:token}"
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 200

    When I clear all headers
    And I set header "<header>" to "<value>"
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"

    When I clear all headers
    And I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 1 item

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: wrong header or shape
      | case                 | header        | value               |
      # MAN #10: a valid token in Authorization does not authenticate when headerName is X-MCP-Token.
      | Authorization header | Authorization | Bearer ${CTX:token} |
      # MAN #9: the scheme is enforced per authHeaderScheme; Bearer is rejected when it is Token.
      | Bearer scheme        | X-MCP-Token   | Bearer ${CTX:token} |
      # MAN #9: the token without the Token prefix is rejected.
      | no scheme            | X-MCP-Token   | ${CTX:token}        |
      # MAN #9: the configured header present but empty is rejected.
      | empty header         | X-MCP-Token   |                     |
