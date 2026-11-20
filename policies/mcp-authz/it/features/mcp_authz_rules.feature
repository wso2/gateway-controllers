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

@mcp-authz-rules
Feature: mcp-authz rules decide which callers may use a tool
  As an API developer
  I want each mcp-authz rule to let through only callers whose token meets it
  So that a tool is used only by callers with the permissions I chose

  # Every scenario puts mcp-auth in front of mcp-authz: mcp-auth checks the token and hands its
  # scopes to mcp-authz, which compares them with the rule on the tool add. The scenarios send
  # handshake-style requests and build their upstream URL with ${CTX:gatewayMCPUpstreamPath}, so
  # they run on gateways 1.1.0, 1.2.0 and latest. Some rows overlap scenarios of
  # mcp_authz.feature, which runs on latest only.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # A token that meets the rule reaches the MCP server. Each row of the refused outline below
  # has a row here with the same rule, which shows that rule can be met at all.
  Scenario Outline: A token that meets the scope rule may call the tool (<case>)
    Given I generate a unique resource name from "mcp-authz-scope-allowed" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-scope-allowed" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-scope-allowed" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-scope-allowed" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[<rule>]}}] |
    Then the resource creation response should indicate successful deployment

    # Polling without a token until mcp-auth's 401 waits until the route and its policies are live.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401
    And I wait until the router can forward "${CTX:mcpContext}/mcp" to its upstream

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "<token scopes>" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: tokens that meet the rule
      | case                         | rule                                                                     | token scopes |
      # MAZ #7: a token with the one scope the rule needs.
      | the required scope           | {"name":"add","scopes":{"allOf":["maz-add"]}}                            | maz-add      |
      # MAZ #10: an allOf rule and a token with both of its scopes.
      | allOf, both scopes           | {"name":"add","scopes":{"allOf":["maz-a","maz-b"]}}                      | maz-a maz-b  |
      # MAZ #11: an anyOf rule and a token with one of its scopes.
      | anyOf, one scope             | {"name":"add","scopes":{"anyOf":["maz-a","maz-b"]}}                      | maz-b        |
      # MAZ #12 (control): allOf and anyOf together, and a token that meets both lists.
      | allOf and anyOf, both met    | {"name":"add","scopes":{"allOf":["maz-a"],"anyOf":["maz-b","maz-c"]}}    | maz-a maz-c  |
      # MAZ #13: the deprecated requiredScopes needs any one of its scopes.
      | requiredScopes, one scope    | {"name":"add","requiredScopes":["maz-a","maz-b"]}                        | maz-a        |
      # MAZ #14 (control): scopes next to requiredScopes, and a token that meets scopes.
      | scopes wins, scopes met      | {"name":"add","scopes":{"allOf":["maz-x"]},"requiredScopes":["maz-y"]}   | maz-x        |

  # A token that does not meet the rule gets mcp-authz's 403 without reaching the MCP server, and
  # WWW-Authenticate names the scopes that would let it through: for an unmet allOf only the
  # missing ones, for an unmet anyOf the whole list. When it names two, their order changes from
  # call to call, so the pattern accepts both orders. \x22 is a double quote, which a step's
  # quoted text cannot hold.
  Scenario Outline: A token that does not meet the scope rule is refused (<case>)
    Given I generate a unique resource name from "mcp-authz-scope-refused" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-scope-refused" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-scope-refused" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-scope-refused" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[<rule>]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "<token scopes>" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the JSON response field "message" should be "Forbidden: insufficient permissions to access this MCP resource"
    And the response header "WWW-Authenticate" should match pattern "error=\x22insufficient_scope\x22"
    And the response header "WWW-Authenticate" should match pattern "scope=\x22<named scopes>\x22,"
    And the response header "x-envoy-upstream-service-time" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: tokens that do not meet the rule
      | case                         | rule                                                                     | token scopes | named scopes                |
      # MAZ #10: an allOf rule and a token with only one of its scopes; only the missing one is named.
      | allOf, one scope missing     | {"name":"add","scopes":{"allOf":["maz-a","maz-b"]}}                      | maz-a        | maz-b                       |
      # MAZ #11: an anyOf rule and a token with none of its scopes; both are named.
      | anyOf, no scope              | {"name":"add","scopes":{"anyOf":["maz-a","maz-b"]}}                      | maz-c        | (maz-a maz-b\|maz-b maz-a)  |
      # MAZ #12: allOf and anyOf together, and a token that meets only allOf; the anyOf list is named.
      | allOf met, anyOf not         | {"name":"add","scopes":{"allOf":["maz-a"],"anyOf":["maz-b","maz-c"]}}    | maz-a        | (maz-b maz-c\|maz-c maz-b)  |
      # MAZ #13 (control): requiredScopes is still enforced; a token with none of its scopes.
      | requiredScopes, no scope     | {"name":"add","requiredScopes":["maz-a","maz-b"]}                        | maz-c        | (maz-a maz-b\|maz-b maz-a)  |
      # MAZ #14: scopes next to requiredScopes, and a token that meets only requiredScopes; scopes wins.
      | scopes wins, old field met   | {"name":"add","scopes":{"allOf":["maz-x"]},"requiredScopes":["maz-y"]}   | maz-y        | maz-x                       |
