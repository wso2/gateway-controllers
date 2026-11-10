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

@mcp-auth-metadata
Feature: mcp-auth protected-resource metadata
  As an MCP client developer
  I want the protected-resource metadata to list the authorization servers a proxy trusts
  So that a client knows where to get a token the proxy will accept

  # Every scenario sends handshake-style requests (specVersion 2025-06-18) and builds its upstream
  # URL with ${CTX:gatewayMCPUpstreamPath}, so it runs on gateways 1.1.0, 1.2.0 and latest. The
  # block's overlay (overlays/gateway.toml) configures the key managers mock-jwks (issuer
  # http://testbench:3001/token) and wrong-issuer-km (issuer http://expected-issuer.com), and the
  # gatewayurl that the metadata's resource URL is built from.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # ---- Issuers ----------------------------------------------------------------------------

  # A client refused with 401 finds the metadata address in the WWW-Authenticate challenge, then
  # asks that address, without a token, where to get one. Each row deploys the policy with its own
  # issuers and compares the whole metadata document, so the row proves the exact list (no other
  # key manager's issuer, no key manager name) and that no scopes_supported member is sent while
  # requiredScopes is unset. The answer must not carry x-envoy-upstream-service-time, which the
  # gateway adds only to an answer from the backend: mcp-auth answers this request itself.
  # Already covered elsewhere: authorization_servers[0] (mcp_auth.feature, latest only, and
  # mcp_auth_gateway_host.feature, whose block has one key manager) and the resource URL
  # (mcp_gateway_url_precedence.feature, latest only).
  Scenario Outline: The metadata lists the issuer URL of each trusted key manager (<case>)
    Given I generate a unique resource name from "mcp-auth-metadata" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-metadata" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-metadata" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-metadata" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":<params>}] |
    Then the resource creation response should indicate successful deployment

    # The proxy itself needs a token. Polling until the 401 also waits until its routes are live.
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """
    Then the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"

    # The metadata answers without a token.
    When I clear all headers
    And I send a "GET" request to "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    Then the response status code should be 200
    And the response header "x-envoy-upstream-service-time" should not exist
    And the response body should be:
      """
      {"resource":"https://mcp-e2e-gatewayurl.example.com:7777${CTX:mcpContext}/mcp","authorization_servers":<servers>}
      """

    # The control for the header check above: with a token from the listed issuer, initialize
    # reaches the backend, and that answer does carry x-envoy-upstream-service-time.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: issuers
      | case                          | params                    | servers                         |
      # MAN #2: issuers names only KM1 while KM1 and KM2 exist; only ISS1 is listed, as its issuer URL.
      # It also holds MAN #1's checks: the metadata answers without a token, with the resource URL.
      | issuers names one key manager | {"issuers":["mock-jwks"]} | ["http://testbench:3001/token"] |
