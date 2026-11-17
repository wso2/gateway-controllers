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

@mcp-auth-validation
Feature: mcp-auth refuses malformed requests and invalid configurations
  As an API developer
  I want a malformed MCP body and an invalid mcp-auth configuration to be refused clearly
  So that neither a client nor an operator mistake is silently accepted

  # The scenarios send handshake-style requests and build their upstream URL with
  # ${CTX:gatewayMCPUpstreamPath}, so they run on gateways 1.1.0, 1.2.0 and latest. Gateway latest
  # reads the body with its own resolver before the policy, so its answer to a malformed body has
  # other data text and its own recorded file (expected-error-responses/latest/).

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # MAN #27: a body that is valid JSON but not one JSON-RPC request object is refused with 400 and
  # -32600 Invalid Request. The methods group is disabled, so a single ping passes without a token
  # (the control), and the batch row is made only of pings: if a batch were evaluated per element,
  # its pings would pass. The mock's log holds only the control ping, so the batch is refused
  # whole and never reaches the backend.
  Scenario Outline: A body that is not one JSON-RPC request object is refused (<case>)
    Given I generate a unique resource name from "mcp-auth-bad-body" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-bad-body" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-bad-body" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-bad-body" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-bad-body" and store it as "partition"
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
      {"jsonrpc":"2.0","id":1,"method":"ping"}
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      <body>
      """
    Then the response status code should be 400
    And the response should match the expected error response "mcp-auth-invalid-request"

    When I clear all headers
    And I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response array field "requests" should have 1 item
    And the JSON response array "requests" should contain an item with "method" equal to "ping"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: bodies that are not one request object
      | case           | body                                                                                |
      # MAN #27: a spec-legal batch (a top-level array) of public pings is refused whole.
      | batch of pings | [{"jsonrpc":"2.0","id":2,"method":"ping"},{"jsonrpc":"2.0","id":3,"method":"ping"}] |
      # MAN #27: a JSON string is refused.
      | string         | "ping"                                                                              |
      # MAN #27: a JSON number is refused.
      | number         | 42                                                                                  |

  # MAN #31: the controller validates mcp-auth's parameters against its schema at deploy, so an
  # invalid configuration gets 400 with the reason and the proxy is not created. Each row's
  # expected text is the part of the message only that mistake produces.
  Scenario Outline: An invalid mcp-auth configuration is rejected at deploy (<case>)
    Given I generate a unique resource name from "mcp-auth-bad-params" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-bad-params" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-bad-params" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-bad-params" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":<params>}] |
    Then the response status code should be 400
    And the JSON response field "status" should be "error"
    And the response body should contain "<expected>"
    When I get the MCP proxy "${CTX:mcpName}"
    Then the response status should be 404

    Examples: invalid configurations
      | case                    | params                                         | expected                                                              |
      # MAN #31: exceptions misspelt as exception inside a group.
      | misspelt key in a group | {"tools":{"enabled":true,"exception":["add"]}} | params.tools: Additional property exception is not allowed            |
      # MAN #31: a group given as a string instead of an object.
      | group as a string       | {"tools":"enabled"}                            | params.tools: Invalid type. Expected: object, given: string           |
      # MAN #31: exceptions given as a string instead of a list.
      | exceptions as a string  | {"tools":{"enabled":true,"exceptions":"add"}}  | params.tools.exceptions: Invalid type. Expected: array, given: string |

  # MAN #31: an unknown top-level parameter is accepted and ignored, because the top of mcp-auth's
  # parameter schema allows additional properties (policy-definition.yaml, line 8). The spreadsheet
  # expected 400; the team confirmed (2026-11-12) that accepting it is the intended behaviour, as
  # gateways 1.1.0 and latest do. Gateway 1.2.0 rejecting it is a known issue of that release, so
  # each row runs only on the gateway it names and the scenario is skipped on 1.2.0. The tag marks
  # that difference; no runner filters on it.
  @known-issue-1.2.0
  Scenario Outline: An unknown top-level mcp-auth parameter is accepted (<case>)
    Given the gateway version satisfies "<gate>"
    And I generate a unique resource name from "mcp-auth-unknown-param" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-unknown-param" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-unknown-param" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-unknown-param" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"foo":true}}] |
    Then the resource creation response should indicate successful deployment

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: gateways where accepting it is the intended behaviour
      | case          | gate   |
      # MAN #31: gateway 1.1.0 accepts {"foo":true}.
      | gateway 1.1.0 | <1.2.0 |
      # MAN #31: gateway latest accepts {"foo":true}.
      | latest        | >1.2.0 |
