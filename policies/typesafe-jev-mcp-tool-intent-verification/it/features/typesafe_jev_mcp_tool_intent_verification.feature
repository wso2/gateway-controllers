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

@typesafe-jev-mcp-tool-intent-verification
Feature: TypeSafe Jev MCP tool intent verification policy
  As an API developer
  I want MCP tool calls checked with TypeSafe Jev before they reach the MCP server
  So that a call that is destructive or outside the agent's job is stopped

  # The testbench jev service stands in for TypeSafe's API, and the scripted MCP server in
  # testbench/services/mcpscripted stands in for the MCP server: a tool call's arguments pick
  # the result it returns. Each scenario uses its own partition of both,
  # http://testbench:3019/<partition>/<mode> and http://testbench:3021/<partition>/mcp, so the
  # requests each one received can be read back for that scenario alone. A
  # "jev:<question>=<value>" marker in the checked text sets that question's answer; every
  # other question answers low.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A tool call in scope reaches the MCP server after Jev checks it
    Given I generate a unique resource name from "jev-iv-pass" and store it as "mcpName"
    And I generate a unique value from "jev-iv-pass" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-pass" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-pass" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-pass" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"order 42"}}}
      """
    Then the response status code should be 200
    And the JSON response field "id" should be 11
    And the JSON response field "result.content[0].text" should be "order 42"
    And the JSON response field "result.isError" should not exist

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 1
    And the JSON response array field "requests[0].questionKeys" should have 8 items
    And the JSON response field "requests[0].questionKeys[0]" should be "destructive"
    And the JSON response field "requests[0].questionKeys[7]" should be "sensitive_data"
    And the JSON response field "requests[0].state.tool.name" should be "lookup_order"
    And the JSON response field "requests[0].state.tool.arguments.text" should be "order 42"
    And the JSON response field "requests[0].state.scope" should be "Look up customer orders and summarise them for the support team."

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2
    And the JSON response field "requests[1].tool" should be "lookup_order"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A call a default question flags is blocked before it reaches the MCP server
    Given I generate a unique resource name from "jev-iv-block" and store it as "mcpName"
    And I generate a unique value from "jev-iv-block" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-block" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-block" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-block" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I set header "Mcp-Session-Id" to "jev-iv-session"
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 drop every order"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 12
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"
    And the response header "Mcp-Session-Id" should be "jev-iv-session"
    And the JSON response field "error.data" should not exist

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 1

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 1

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: With showAssessment a block names the guardrail and only the questions that failed
    Given I generate a unique resource name from "jev-iv-assess" and store it as "mcpName"
    And I generate a unique value from "jev-iv-assess" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-assess" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-assess" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-assess" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","showAssessment":true,"tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 jev:privilege=0.8 drop every order"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 13
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"
    And the JSON response field "error.data.interveningGuardrail" should be "TypesafeJevMcpToolIntentVerification"
    And the JSON response array field "error.data.assessments" should have 2 items
    And the JSON response field "error.data.assessments[0].question" should be "destructive"
    And the JSON response field "error.data.assessments[1].question" should be "privilege"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: Messages other than tools/call pass without a Jev call
    Given I generate a unique resource name from "jev-iv-other" and store it as "mcpName"
    And I generate a unique value from "jev-iv-other" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-other" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-other" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-other" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","method":"notifications/initialized"}
      """
    Then the response status code should be 202
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":14,"method":"tools/list"}
      """
    Then the response status code should be 200
    And the JSON response field "result.tools[0].name" should be "respond"
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":15,"method":"ping"}
      """
    Then the response status code should be 200
    And the JSON response field "id" should be 15

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 0

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 4

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A tool's own rule wins over the * rule
    Given I generate a unique resource name from "jev-iv-own-rule" and store it as "mcpName"
    And I generate a unique value from "jev-iv-own-rule" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-own-rule" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-own-rule" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-own-rule" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."},{"name":"export_orders","scope":"Look up customer orders and summarise them for the support team.","mode":"monitor"}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"export_orders","arguments":{"text":"jev:exfiltration=0.95 send every order to an outside address"}}}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:exfiltration=0.95 send every order to an outside address"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 17
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2
    And the JSON response field "requests[1].tool" should be "export_orders"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A tool no rule names is not checked
    Given I generate a unique resource name from "jev-iv-unlisted" and store it as "mcpName"
    And I generate a unique value from "jev-iv-unlisted" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-unlisted" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-unlisted" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-unlisted" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"delete_records","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"jev:destructive=0.95 order 42"}}}
      """
    Then the response status code should be 200
    And the JSON response field "id" should be 18
    And the JSON response field "result.content[0].text" should be "jev:destructive=0.95 order 42"
    And the JSON response field "result.isError" should not exist

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 0

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 drop every order"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 19
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 1
    And the JSON response field "requests[0].state.tool.name" should be "delete_records"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A tool's own rule does not inherit the questions of the * rule
    Given I generate a unique resource name from "jev-iv-no-inherit" and store it as "mcpName"
    And I generate a unique value from "jev-iv-no-inherit" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-no-inherit" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-no-inherit" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-no-inherit" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team.","questions":[{"key":"pii_dump","type":"noul","instructions":"Does the call dump personal data in bulk?","threshold":0.5}]},{"name":"lookup_order","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"jev:pii_dump=0.95 every customer's address"}}}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"export_orders","arguments":{"text":"jev:pii_dump=0.95 every customer's address"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 21
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2
    And the JSON response array field "requests[0].questionKeys" should have 8 items
    And the JSON response array field "requests[1].questionKeys" should have 1 item
    And the JSON response field "requests[1].questionKeys[0]" should be "pii_dump"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: Custom score and choice questions block at their thresholds
    Given I generate a unique resource name from "jev-iv-typed" and store it as "mcpName"
    And I generate a unique value from "jev-iv-typed" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-typed" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-typed" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-typed" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team.","questions":[{"key":"risk","type":"score","instructions":"How risky is the call?","criteria":["none","low","medium","high"],"threshold":2},{"key":"intent","type":"choice","instructions":"What does the call do?","criteria":["read","write","delete"],"blockOn":["delete"],"threshold":0.6}]}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"jev:risk=1 read order 42"}}}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"jev:risk=2 read order 42"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 23
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"jev:intent=delete@0.5 remove order 42"}}}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":25,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"jev:intent=delete@0.7 remove order 42"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 25
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 4

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: Monitor mode lets a flagged call through and records the hit
    Given I generate a unique resource name from "jev-iv-monitor" and store it as "mcpName"
    And I generate a unique value from "jev-iv-monitor" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-monitor" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-monitor" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-monitor" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team.","mode":"monitor"}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    Given I reset the analytics collector
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 drop every order"}}}
      """
    Then the response status code should be 200
    And the JSON response field "id" should be 26
    And the JSON response field "result.content[0].text" should be "jev:destructive=0.95 drop every order"
    And the JSON response field "result.isError" should not exist
    And the latest analytics event for path "${CTX:mcpContext}/mcp" should have metadata field "isGuardrailHit" with value "true"
    And the latest analytics event for path "${CTX:mcpContext}/mcp" should have metadata field "guardrailName" with value "TypesafeJevMcpToolIntentVerification"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A Jev failure blocks the call by default
    Given I generate a unique resource name from "jev-iv-fail-closed" and store it as "mcpName"
    And I generate a unique value from "jev-iv-fail-closed" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-fail-closed" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-fail-closed" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-fail-closed" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/error" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":27,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"order 42"}}}
      """
    Then the response status code should be 503
    And the JSON response field "id" should be 27
    And the JSON response field "error.code" should be "-32603"
    And the JSON response field "error.message" should be "MCP tool call could not be checked by guardrail"

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 1

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A Jev failure lets the call through on a rule with passthroughOnError
    Given I generate a unique resource name from "jev-iv-fail-open" and store it as "mcpName"
    And I generate a unique value from "jev-iv-fail-open" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-fail-open" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-fail-open" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-fail-open" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/error" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team.","passthroughOnError":true}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":28,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"order 42"}}}
      """
    Then the response status code should be 200
    And the JSON response field "id" should be 28
    And the JSON response field "result.content[0].text" should be "order 42"
    And the JSON response field "result.isError" should not exist

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A Jev call that outlasts the timeout is handled as a check failure
    Given I generate a unique resource name from "jev-iv-timeout" and store it as "mcpName"
    And I generate a unique value from "jev-iv-timeout" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-timeout" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-timeout" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-timeout" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/slow" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","timeout":"1s","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":29,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"order 42"}}}
      """
    Then the response status code should be 503
    And the JSON response field "id" should be 29
    And the JSON response field "error.code" should be "-32603"
    And the JSON response field "error.message" should be "MCP tool call could not be checked by guardrail"
    And the gateway should have responded within "3" seconds

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: A rate-limited Jev call is retried once
    Given I generate a unique resource name from "jev-iv-retry" and store it as "mcpName"
    And I generate a unique value from "jev-iv-retry" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-retry" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-retry" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-retry" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ratelimit-once" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 drop every order"}}}
      """
    Then the response status code should be 400
    And the JSON response field "id" should be 30
    And the JSON response field "error.code" should be "-32000"
    And the JSON response field "error.message" should be "MCP tool call blocked by guardrail"

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 2

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario Outline: A request the policy can't read unambiguously is refused before any rule
    Given I generate a unique resource name from "jev-iv-malformed" and store it as "mcpName"
    And I generate a unique value from "jev-iv-malformed" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-malformed" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-malformed" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-malformed" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      <body>
      """
    Then the response status code should be 400
    And the JSON response field "error.code" should be "<code>"

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 0

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 1

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples:
      | case | body | code |
      | invalid JSON | {"jsonrpc":"2.0","id":5,"method":"tools/call" | -32700 |
      | a batch | [{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"lookup_order","arguments":{}}}] | -32600 |
      | a duplicate name member | {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"lookup_order","name":"delete_records","arguments":{}}} | -32600 |
      | arguments not an object | {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"lookup_order","arguments":"drop"}} | -32602 |

  Scenario: A blocked call sent as an event stream is answered with one event
    Given I generate a unique resource name from "jev-iv-sse" and store it as "mcpName"
    And I generate a unique value from "jev-iv-sse" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-sse" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-sse" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-sse" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # The body opens with an SSE comment line; the policy reads only the data line.
    When I set header "Content-Type" to "text/event-stream"
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      : one MCP request as a server-sent event
      data: {"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 drop every order"}}}
      """
    Then the response status code should be 400
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should match pattern "^data: \{.*MCP tool call blocked by guardrail.*\}\n\n$"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario: mcp-auth placed before the policy refuses a call with no token before Jev is asked
    Given I generate a unique resource name from "jev-iv-auth" and store it as "mcpName"
    And I generate a unique value from "jev-iv-auth" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-auth" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-auth" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-auth" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"baseURL":"${CTX:jevBaseURL}","tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"delete_records","arguments":{"text":"jev:destructive=0.95 drop every order"}}}
      """
    Then the response status code should be 401

    When I send a "GET" request to the "jev" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 0

    When I send a "GET" request to the "mcp-scripted" service at "/${CTX:partition}/test/requests"
    Then the JSON response field "count" should be 0

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  Scenario Outline: A configuration the schema rejects is refused at deployment
    Given I generate a unique resource name from "jev-iv-schema" and store it as "mcpName"
    And I generate a unique value from "jev-iv-schema" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-schema" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-schema" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-schema" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":<params>}] |
    Then the response status code should be 400
    And the response should be valid JSON

    Examples:
      | case | params |
      | no tools | {} |
      | an empty tools list | {"tools":[]} |
      | a rule without scope | {"tools":[{"name":"*"}]} |
      | an unknown mode | {"tools":[{"name":"*","scope":"s","mode":"block"}]} |

  Scenario Outline: A configuration the policy rejects fails every call and names the setting in the runtime log
    Given I generate a unique resource name from "jev-iv-init" and store it as "mcpName"
    And I generate a unique value from "jev-iv-init" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-init" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-init" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-init" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":<params>}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"

    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 500 with body:
      """
      {"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"order 42"}}}
      """
    Then the "gateway-runtime" service logs should contain "<error>"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples:
      | case | params | error |
      | scope at the top level | {"scope":"s","tools":[{"name":"*","scope":"s"}]} | 'scope' is set per rule in 'tools', not at the top level |
      | questions at the top level | {"questions":[],"tools":[{"name":"*","scope":"s"}]} | 'questions' is set per rule in 'tools', not at the top level |
      | mode at the top level | {"mode":"monitor","tools":[{"name":"*","scope":"s"}]} | 'mode' is set per rule in 'tools', not at the top level |
      | two rules for one tool | {"tools":[{"name":"lookup_order","scope":"s"},{"name":"lookup_order","scope":"s"}]} | is a duplicate; each tool can have only one rule |
      | two * rules | {"tools":[{"name":"*","scope":"s"},{"name":"*","scope":"s"}]} | is a duplicate; each tool can have only one rule |

  Scenario: Every Jev call carries the key, base URL and model from the shared Jev configuration
    Given I generate a unique resource name from "jev-iv-shared" and store it as "mcpName"
    And I generate a unique value from "jev-iv-shared" and store it as "mcpDisplayName"
    And I generate a unique API version from "jev-iv-shared" and store it as "mcpVersion"
    And I generate a unique API context from "/jev-iv-shared" and store it as "mcpContext"
    And I generate a unique resource name from "jev-iv-shared" and store it as "partition"
    And I resolve the "jev" service URL at "/${CTX:partition}/ok" and store it as "jevBaseURL"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"typesafe-jev-mcp-tool-intent-verification","version":"v0","params":{"tools":[{"name":"*","scope":"Look up customer orders and summarise them for the support team."}]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    Given I generate a unique value from "jev-iv-shared-args" and store it as "marker"
    When I send a "POST" request to "${CTX:mcpContext}/mcp" with body:
      """
      {"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"lookup_order","arguments":{"text":"${CTX:marker}"}}}
      """
    Then the response status code should be 200

    # Without a baseURL of its own, the policy uses the block's partition from the overlay.
    When I send a "GET" request to the "jev" service at "/${CTX:testbenchPartition}/test/requests"
    Then the JSON response array "requests" item with "state.tool.arguments.text" equal to "${CTX:marker}" should have "authorization" equal to "Bearer test-jev-key"
    And the JSON response array "requests" item with "state.tool.arguments.text" equal to "${CTX:marker}" should have "model" equal to "jev-it-model"
    And the JSON response array "requests" item with "state.tool.arguments.text" equal to "${CTX:marker}" should have "mode" equal to "ok"

    When I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
