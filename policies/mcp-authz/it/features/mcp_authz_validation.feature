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

@mcp-authz-validation
Feature: mcp-authz rule sets are checked when a proxy is deployed
  As an API developer
  I want a broken mcp-authz rule set refused when I deploy it
  So that a mistake in an access rule is caught before it guards real traffic

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The gateway controller checks mcp-authz's parameters against the policy's schema
  # (policy-definition.yaml) before it creates the proxy, so an invalid rule set gets 400 with
  # the reason and no proxy is created. Each row's expected text is the part of the message only
  # that mistake produces. For the two anyOf rows the checker also names just the first allowed
  # choice ("tools is required", "requiredClaims is required"), so those rows check the anyOf line.
  Scenario Outline: An invalid mcp-authz rule set is rejected at deploy (<case>)
    Given I generate a unique resource name from "mcp-authz-bad-rules" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-bad-rules" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-bad-rules" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-bad-rules" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":<params>}] |
    Then the response status code should be 400
    And the JSON response field "status" should be "error"
    And the response body should contain "<expected>"
    When I get the MCP proxy "${CTX:mcpName}"
    Then the response status should be 404

    Examples: rule sets the schema refuses
      | case                     | params                                                                  | expected                                                             |
      # MAZ #2: none of tools, resources, prompts or methods is set.
      | no rule list             | {}                                                                      | params: Must validate at least one schema (anyOf)                    |
      # MAZ #3: a rule with a name but no scope or claim condition.
      | rule without a condition | {"tools":[{"name":"add"}]}                                              | params.tools.0: Must validate at least one schema (anyOf)            |
      # MAZ #4: a rule without a name.
      | rule without a name      | {"tools":[{"scopes":{"allOf":["maz-add"]}}]}                            | params.tools.0: name is required                                     |
      # MAZ #4: an empty rule list.
      | empty rule list          | {"tools":[]}                                                            | params.tools: Array must have at least 1 items                       |
      # MAZ #4: a field the rule schema does not define.
      | unknown rule field       | {"tools":[{"name":"add","scopes":{"allOf":["maz-add"]},"foo":"bar"}]}   | params.tools.0: Additional property foo is not allowed               |
      # MAZ #4: a rule name of 257 characters, one over the limit.
      | name of 257 characters   | {"tools":[{"name":"ttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt","scopes":{"allOf":["maz-add"]}}]} | params.tools.0.name: String length must be less than or equal to 256 |

  # A rule name of exactly 256 characters deploys, which keeps the 257-character rejection above
  # honest: the limit is exactly 256. "Deployed" is only the controller's view, so the scenario
  # also sends traffic: the governed tool gets mcp-authz's own 401 (no mcp-auth is attached, so no
  # identity exists) without reaching the backend, and a tool no rule names reaches the backend.
  # A valid rule with an ordinary name (MAZ #1) is shown by every scenario of mcp_authz.feature.
  Scenario Outline: A valid mcp-authz rule set deploys and is enforced (<case>)
    Given I generate a unique resource name from "mcp-authz-valid-rules" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-valid-rules" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-valid-rules" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-valid-rules" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"<tool>","scopes":{"allOf":["maz-add"]}}]}}] |
    Then the resource creation response should indicate successful deployment

    # Clear the admin login first, so the traffic carries no credentials at all.
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"<tool>","arguments":{"a":2,"b":3}}}
      """
    Then the JSON response field "message" should be "Unauthorized: authentication required for this MCP capability"
    And the response header "x-envoy-upstream-service-time" should not exist

    When I wait until the router can forward "${CTX:mcpContext}/mcp" to its upstream
    And I use the MCP Client to send "echo" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should be "Echo: Hello, World!"
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: rule sets the schema accepts
      | case                   | tool     |
      # MAZ #4: a rule name of exactly 256 characters is still accepted.
      | name of 256 characters | tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt |

  # MAZ #6: the deprecated requiredScopes and requiredClaims still deploy. The policy logs a
  # warning when the gateway runtime loads it (once per route of the proxy), and the warning says
  # the old field is ignored when its new counterpart is also set. The warning names no proxy, so
  # the scenario reads only the runtime log written after its own deploy request; the scenarios of
  # this block run one at a time, so no other deploy writes there meanwhile.
  Scenario Outline: A deprecated mcp-authz rule field deploys with a warning (<case>)
    Given I generate a unique resource name from "mcp-authz-deprecated" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-deprecated" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-deprecated" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-deprecated" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":<params>}] |
    Then the resource creation response should indicate successful deployment
    And the "gateway-runtime" log since the latest request should contain "<warning>"

    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: deprecated rule fields
      | case                       | params                                                                                                             | warning                                                                       |
      # MAZ #6: requiredScopes alone.
      | requiredScopes alone       | {"tools":[{"name":"add","requiredScopes":["maz-old"]}]}                                                            | rule 'requiredScopes' is deprecated; migrate to 'scopes' (allOf/anyOf).       |
      # MAZ #6: requiredScopes next to scopes, which takes precedence.
      | requiredScopes with scopes | {"tools":[{"name":"add","requiredScopes":["maz-old"],"scopes":{"allOf":["maz-new"]}}]}                             | rule 'requiredScopes' is deprecated and ignored where 'scopes' is configured |
      # MAZ #6: requiredClaims alone.
      | requiredClaims alone       | {"tools":[{"name":"add","requiredClaims":{"team":"red"}}]}                                                         | rule 'requiredClaims' is deprecated; migrate to 'claims' (allOf/anyOf).       |
      # MAZ #6: requiredClaims next to claims, which takes precedence.
      | requiredClaims with claims | {"tools":[{"name":"add","requiredClaims":{"team":"red"},"claims":{"allOf":[{"claim":"team","values":["blue"]}]}}]} | rule 'requiredClaims' is deprecated and ignored where 'claims' is configured |
