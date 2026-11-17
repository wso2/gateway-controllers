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

@mcp-auth-km-blank-issuer
Feature: mcp-auth with a key manager with a blank issuer
  As a gateway operator
  I want a broken key manager setting to fail the protected-resource metadata loudly
  So that a client never gets a partly filled list of authorization servers

  # MAN #32 tests three broken key manager settings. Each needs the gateway itself configured
  # wrongly, which no proxy setting can do, so each has its own feature file, block and overlay
  # (overlays/mcp-auth-km-blank-issuer.toml); a feature file can belong to only one runner. The
  # scenario sends handshake-style requests and builds its upstream URL with
  # ${CTX:gatewayMCPUpstreamPath}, so it runs on gateways 1.1.0, 1.2.0 and latest.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # MAN #32: one key manager entry has a blank issuer. The metadata fails with 500 and names the problem, even though the
  # proxy names only the valid mock-jwks entry, instead of answering a partly filled document.
  # Token checks still work: a mock-jwks token reaches the backend.
  Scenario: The metadata fails when a key manager has a blank issuer
    Given I generate a unique resource name from "mcp-auth-km-blank-issuer" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-km-blank-issuer" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-km-blank-issuer" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-km-blank-issuer" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}}] |
    Then the resource creation response should indicate successful deployment

    # Polling until 500 waits until the proxy's routes are live.
    When I clear all headers
    And I send a "GET" request to "${CTX:mcpContext}/.well-known/oauth-protected-resource" until status 500
    Then the response should match the expected error response "mcp-auth-invalid-key-manager"

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
