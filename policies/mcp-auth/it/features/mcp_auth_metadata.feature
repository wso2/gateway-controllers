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
  # block's overlay (overlays/gateway.toml) configures three key managers, in this order: mock-jwks
  # (issuer http://testbench:3001/token), wrong-issuer-km (issuer http://expected-issuer.com) and
  # oidc-km (issuer https://testbench:3015/oauth2/token). It also sets the gatewayurl that the
  # metadata's resource URL is built from.

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
      | case                          | params                    | servers                                                                                            |
      # MAN #2: issuers names only KM1 while KM1 and KM2 exist; only ISS1 is listed, as its issuer URL.
      # It also holds MAN #1's checks: the metadata answers without a token, with the resource URL.
      | issuers names one key manager | {"issuers":["mock-jwks"]} | ["http://testbench:3001/token"]                                                                    |
      # MAN #3: issuers left out; every configured key manager's issuer is listed, in config order.
      | issuers left out              | {}                        | ["http://testbench:3001/token","http://expected-issuer.com","https://testbench:3015/oauth2/token"] |
      # MAN #3: issuers given as an empty list; an empty list also means every key manager.
      | issuers is an empty list      | {"issuers":[]}            | ["http://testbench:3001/token","http://expected-issuer.com","https://testbench:3015/oauth2/token"] |

  # MAN #2: issuers also limits which tokens the proxy accepts, not only what the metadata lists.
  # With issuers naming only mock-jwks, a token from wrong-issuer-km, which the gateway has
  # configured but the proxy did not select, is refused. The same kind of token gets in under
  # empty params (MAN #30), so the refusal comes from issuers alone. A mock-jwks token is the
  # control, and the scripted mock's log holds only its call.
  Scenario: A token from a configured key manager that issuers leaves out is refused
    Given I generate a unique resource name from "mcp-auth-unselected-km" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-unselected-km" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-unselected-km" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-unselected-km" and store it as "mcpContext"
    And I generate a unique resource name from "mcp-auth-unselected-km" and store it as "partition"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3021/${CTX:partition}${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}}] |
    Then the resource creation response should indicate successful deployment

    # Polling an empty POST until 401 waits until the routes are live; it never reaches the mock.
    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I get a JWT token from the mock JWKS server with issuer "http://expected-issuer.com" and store it as "otherToken"
    And I set header "Authorization" to "Bearer ${CTX:otherToken}"
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{}}}
      """
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"

    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
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

  # MAN #4: issuers names only a key manager the gateway does not have, so the proxy trusts no
  # issuer at all. The metadata then fails with the failure status (401 by default) instead of
  # listing an empty authorization_servers. That answer is built by mcp-auth itself and carries no
  # WWW-Authenticate challenge (held to the recorded mcp-auth-no-matching-issuers.json), unlike
  # the 401 for a token, which does. A valid mock-jwks token is refused too: nobody is trusted.
  Scenario: The metadata fails when issuers names no key manager the gateway has
    Given I generate a unique resource name from "mcp-auth-no-issuer" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-no-issuer" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-no-issuer" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-no-issuer" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["no-such-km"]}}] |
    Then the resource creation response should indicate successful deployment

    # Polling until 401 waits until the proxy's routes are live.
    When I clear all headers
    And I send a "GET" request to "${CTX:mcpContext}/.well-known/oauth-protected-resource" until status 401
    Then the response should match the expected error response "mcp-auth-no-matching-issuers"
    And the response header "WWW-Authenticate" should not exist

    # A valid mock-jwks token is refused, and that refusal does carry the challenge, which shows
    # the header check above could have failed.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # ---- Scopes -----------------------------------------------------------------------------

  # MAN #5: requiredScopes is advertised only. The scopes appear in the 401 challenge's scope
  # parameter (held to the recorded mcp-auth-required-scopes-challenge.json, since a step's text
  # cannot contain the quotes around them) and in the metadata's scopes_supported, but mcp-auth
  # removes requiredScopes before jwt-auth checks the token, so a token without them still gets in.
  # The token below asks the testbench for the scope "default", which is neither of the two.
  Scenario: requiredScopes are advertised in the challenge and the metadata but not enforced
    Given I generate a unique resource name from "mcp-auth-scopes" and store it as "mcpName"
    And I generate a unique value from "mcp-auth-scopes" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-auth-scopes" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-auth-scopes" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"requiredScopes":["mcp:read","mcp:write"]}}] |
    Then the resource creation response should indicate successful deployment

    # A failure names both scopes, space-separated, in the challenge. Polling until the 401 also
    # waits until the proxy's routes are live.
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """
    Then the response header "WWW-Authenticate" should contain "mcp:read mcp:write"
    And the response should match the expected error response "mcp-auth-required-scopes-challenge"

    # The metadata lists both scopes in scopes_supported, after every key manager's issuer.
    When I clear all headers
    And I send a "GET" request to "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    Then the response status code should be 200
    And the response body should be:
      """
      {"resource":"https://mcp-e2e-gatewayurl.example.com:7777${CTX:mcpContext}/mcp","authorization_servers":["http://testbench:3001/token","http://expected-issuer.com","https://testbench:3015/oauth2/token"],"scopes_supported":["mcp:read","mcp:write"]}
      """

    # A token holding neither scope still reaches the backend.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "default" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
