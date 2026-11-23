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

@mcp-authz-policy
Feature: MCP proxies governed by mcp-authz
  As an API developer
  I want mcp-authz to decide which identity may invoke which capability
  So that a token that authenticates is not automatically a token that authorizes

  # Both protocol eras are here, and deliberately so: this policy's whole behaviour should be
  # readable in one place. A scenario whose steps say "declaring MCP version" sends a 2026-07-28
  # request, which mirrors the method and capability name into headers; the others send
  # handshake-era requests, which mirror nothing.
  #
  # The handshake-era scenarios run on gateways 1.1.0, 1.2.0 and latest: they build their upstream
  # URL with ${CTX:gatewayMCPUpstreamPath}. The modern scenario needs the operation resolver, which
  # no released 1.2.0 carries, so it starts with a gateway-version step and runs on latest only.
  #
  # A "# MAZ #N" line above a scenario names the row of the MAZ test-scenario sheet it covers.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # MAZ #8: a token without the required scope gets 403, and WWW-Authenticate names the scope.
  Scenario: An MCP proxy with mcp-authz returns 403 for unauthorized access
    Given I generate a unique resource name from "mcp-authz" and store it as "mcpName"
    And I generate a unique value from "mcp-authz" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["add-scope"]},{"name":"echo","requiredScopes":["echo-scope"]}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should contain "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    And the response header "WWW-Authenticate" should contain "add-scope"

    When I clear all headers
    And I send a "GET" request to "${CTX:mcpContext}/.well-known/oauth-protected-resource"
    Then the response should be successful
    And the JSON response field "authorization_servers[0]" should be "http://testbench:3001/token"

    Given I authenticate using basic auth as "admin"
    When I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #7: a token with the required scope reaches the MCP server.
  Scenario: An MCP proxy with mcp-authz allows access with a token holding the required scope
    Given I generate a unique resource name from "mcp-authz-valid" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-valid" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-valid" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-valid" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["add-scope"]},{"name":"echo","requiredScopes":["echo-scope"]}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "add-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #1: a rule with a name and the scopes field deploys and is enforced.
  # MAZ #10: allOf needs every scope; a token missing s-deploy gets 403 naming s-deploy.
  # MAZ #12: allOf met but no anyOf scope gets 403; both lists must be met.
  @gateway-v1.2
  Scenario: mcp-authz new scopes format (allOf and anyOf) is enforced
    Given I generate a unique resource name from "mcp-authz-scopes" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-scopes" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-scopes" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-scopes" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","scopes":{"allOf":["s-read","s-deploy"],"anyOf":["s-write","s-update"]}}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # allOf satisfied AND one anyOf present -> authorized
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "s-read s-deploy s-write" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # allOf satisfied but no anyOf scope present -> 403. The challenge names the whole anyOf list,
    # in either order (\x22 is a double quote, which a step's quoted text cannot hold).
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "s-read s-deploy" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should match pattern "scope=\x22(s-write s-update|s-update s-write)\x22,"

    # anyOf present but allOf incomplete (missing s-deploy) -> 403. The challenge names only the
    # missing allOf scope.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "s-read s-write" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should match pattern "scope=\x22s-deploy\x22,"

    # neither allOf nor anyOf satisfied -> 403
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "unrelated" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #15: every listed claim must match; one differing value (department=sales) gets 403.
  # MAZ #16: a claim with several allowed values (role is admin or superadmin); any one of several
  # different claims is a separate row.
  # MAZ #17: a token without a required claim (department) gets 403.
  @gateway-v1.2
  Scenario: mcp-authz new claims format (allOf and anyOf) is enforced
    Given I generate a unique resource name from "mcp-authz-claims" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-claims" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-claims" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-claims" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","claims":{"allOf":[{"claim":"department","values":["platform"]}],"anyOf":[{"claim":"role","values":["admin","superadmin"]}]}}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # department=platform AND role in {admin, superadmin} -> authorized
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=platform,role=admin" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # anyOf claim not matched (role=viewer) -> 403
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=platform,role=viewer" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403

    # allOf claim not matched (department=sales) -> 403
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=sales,role=admin" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403

    # required claim entirely absent (no department) -> 403 (fail-closed)
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "role=admin" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #14: scopes wins over requiredScopes; a token meeting only requiredScopes gets 403 naming
  # the scopes scope.
  @gateway-v1.2
  Scenario: mcp-authz new scopes take precedence over deprecated requiredScopes
    Given I generate a unique resource name from "mcp-authz-scope-prec" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-scope-prec" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-scope-prec" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-scope-prec" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["old-scope"],"scopes":{"allOf":["new-scope"]}}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # Token has the new scope -> authorized (new format enforced)
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "new-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # Token satisfies only the deprecated requiredScopes -> 403 (deprecated is ignored, new wins).
    # The challenge names only new-scope, never old-scope.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "old-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should match pattern "scope=\x22new-scope\x22,"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #21: claims wins over requiredClaims; a token meeting only requiredClaims gets 403.
  @gateway-v1.2
  Scenario: mcp-authz new claims take precedence over deprecated requiredClaims
    Given I generate a unique resource name from "mcp-authz-claim-prec" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-claim-prec" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-claim-prec" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-claim-prec" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredClaims":{"department":"platform"},"claims":{"allOf":[{"claim":"department","values":["engineering"]}]}}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # Token satisfies the new claim (department=engineering) -> authorized
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=engineering" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # Token satisfies only the deprecated requiredClaims (department=platform) -> 403 (new wins)
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "department=platform" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #24: a specific rule and a * rule both apply, and both must pass.
  # MAZ #25: when both rules fail on different scopes, the 403 names the missing scope of each.
  @gateway-v1.2
  Scenario: mcp-authz requires all matching rules to pass (specific rule and wildcard rule)
    Given I generate a unique resource name from "mcp-authz-multirule" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-multirule" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-multirule" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-multirule" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"*","scopes":{"allOf":["base-scope"]}},{"name":"add","scopes":{"allOf":["add-scope"]}}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # Both the wildcard rule and the specific rule are satisfied -> authorized
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "base-scope add-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # Specific rule passes but the wildcard rule fails (no base-scope) -> 403
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "add-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should contain "base-scope"

    # Wildcard rule passes but the specific rule fails (no add-scope) -> 403
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "base-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should contain "add-scope"

    # Both rules fail (no base-scope, no add-scope) -> 403, and the challenge names the missing
    # scope of each rule, in either order (\x22 is a double quote, which a step's quoted text
    # cannot hold).
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "unrelated" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should match pattern "scope=\x22(base-scope add-scope|add-scope base-scope)\x22,"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # MAZ #22: claims and scopes on one rule; both failures get 403, and only the scope failure names
  # a scope.
  @gateway-v1.2
  Scenario: mcp-authz mixes new scopes with deprecated requiredClaims on one rule
    Given I generate a unique resource name from "mcp-authz-mixed" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-mixed" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-mixed" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-mixed" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","scopes":{"allOf":["api:read"]},"requiredClaims":{"department":"platform"}}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # Both the new scope and the deprecated claim are satisfied -> authorized
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token", scope "api:read" and claims "department=platform" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # Scope satisfied but the deprecated claim fails (department=sales) -> 403. A new scope would not
    # help, so the challenge names none: no scope= part, unlike the scope failure below.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token", scope "api:read" and claims "department=sales" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should contain "insufficient_scope"
    And the response header "WWW-Authenticate" should not contain "scope="

    # Claim satisfied but the new scope fails (no api:read) -> 403
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token", scope "unrelated" and claims "department=platform" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the response header "WWW-Authenticate" should contain "api:read"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # Scope rules the scenarios above leave out: an anyOf rule lets a token through with any one of
  # its scopes (above, the token held the first), and the deprecated requiredScopes needs only one
  # of its scopes (above, it lists one). mcp-auth sits in front of mcp-authz, and each row calls the
  # tool add with a token holding the row's scopes. The admin login is cleared before any traffic,
  # and polling without a token until mcp-auth's 401 waits until the route and its policies are
  # live. Each refused row of the next outline has a row here with the same rule, which shows that
  # rule can be met at all.
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
      | case                      | rule                                                | token scopes |
      # MAZ #11: an anyOf rule and a token with only its second scope; any one is enough.
      | anyOf, one scope          | {"name":"add","scopes":{"anyOf":["maz-a","maz-b"]}} | maz-b        |
      # MAZ #13: the deprecated requiredScopes needs any one of its scopes.
      | requiredScopes, one scope | {"name":"add","requiredScopes":["maz-a","maz-b"]}   | maz-a        |

  # A token that does not meet the rule gets mcp-authz's 403 without reaching the MCP server, and
  # WWW-Authenticate names every scope of the unmet anyOf list (requiredScopes works like anyOf),
  # since any one of them would let the token through. Their order changes from call to call, so the
  # pattern accepts both orders. \x22 is a double quote, which a step's quoted text cannot hold.
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
      | case                     | rule                                                | token scopes | named scopes               |
      # MAZ #11: an anyOf rule and a token with none of its scopes; both are named.
      | anyOf, no scope          | {"name":"add","scopes":{"anyOf":["maz-a","maz-b"]}} | maz-c        | (maz-a maz-b\|maz-b maz-a) |
      # MAZ #13 (control): requiredScopes is still enforced; a token with none of its scopes.
      | requiredScopes, no scope | {"name":"add","requiredScopes":["maz-a","maz-b"]}   | maz-c        | (maz-a maz-b\|maz-b maz-a) |

  # Claim rules the scenarios above leave out: any one of several different claims, the standard
  # claims sub, iss and aud, a list claim, and number and true/false claims. The mock JWKS server
  # can only sign text claims, so these tokens come from the testbench OIDC provider, which signs
  # any JSON; mcp-auth trusts it through the oidc-km key manager. The provider adds iss itself, so
  # a token with no claims still has the provider's issuer. Each refused row of the next outline
  # has a row here with the same rule, which shows that rule can be met at all.
  Scenario Outline: A token whose claims meet the claim rule may call the tool (<case>)
    Given I generate a unique resource name from "mcp-authz-claim-allowed" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-claim-allowed" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-claim-allowed" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-claim-allowed" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["oidc-km"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[<rule>]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401
    And I wait until the router can forward "${CTX:mcpContext}/mcp" to its upstream

    When I mint a JWT token from the testbench OIDC provider expiring in 300 seconds and store it as "token" with claims:
      """
      <claims>
      """
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 200
    And the JSON response field "result.content[0].text" should be "The sum of 40 and 60 is 100."
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: tokens whose claims meet the rule
      | case                         | rule                                                                                                          | claims                         |
      # MAZ #16: anyOf over two different claims; team does not match but dept does.
      | anyOf, the second claim      | {"name":"add","claims":{"anyOf":[{"claim":"team","values":["red"]},{"claim":"dept","values":["sales"]}]}}    | {"team":"blue","dept":"sales"} |
      # MAZ #18: the subject matches.
      | sub matches                  | {"name":"add","claims":{"allOf":[{"claim":"sub","values":["alice"]}]}}                                       | {"sub":"alice"}                |
      # MAZ #18: the issuer matches; the provider adds its own iss.
      | iss matches                  | {"name":"add","claims":{"allOf":[{"claim":"iss","values":["https://testbench:3015/oauth2/token"]}]}}         | {}                             |
      # MAZ #18: one audience of the token's aud list matches.
      | one audience matches         | {"name":"add","claims":{"allOf":[{"claim":"aud","values":["api-b"]}]}}                                       | {"aud":["api-a","api-b"]}      |
      # MAZ #19: the new claims field finds b in the list claim groups.
      | list claim, claims field     | {"name":"add","claims":{"allOf":[{"claim":"groups","values":["b"]}]}}                                        | {"groups":["a","b"]}           |
      # MAZ #19 (control): the old requiredClaims field matches a single text value.
      | single value, requiredClaims | {"name":"add","requiredClaims":{"groups":"b"}}                                                                | {"groups":"b"}                 |
      # MAZ #20: a number claim and a true/false claim match the rule's text values "5" and "true".
      | number and true/false        | {"name":"add","claims":{"allOf":[{"claim":"level","values":["5"]},{"claim":"admin","values":["true"]}]}}     | {"level":5,"admin":true}       |

  # A token whose claims do not meet the rule gets mcp-authz's 403 without reaching the MCP server.
  # A new scope would not help, so the challenge names none: it has error="insufficient_scope" but
  # no scope= part.
  Scenario Outline: A token whose claims do not meet the claim rule is refused (<case>)
    Given I generate a unique resource name from "mcp-authz-claim-refused" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-claim-refused" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-claim-refused" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-claim-refused" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["oidc-km"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[<rule>]}}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401

    When I mint a JWT token from the testbench OIDC provider expiring in 300 seconds and store it as "token" with claims:
      """
      <claims>
      """
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 403
    And the JSON response field "message" should be "Forbidden: insufficient permissions to access this MCP resource"
    And the response header "WWW-Authenticate" should contain "insufficient_scope"
    And the response header "WWW-Authenticate" should not contain "scope="
    And the response header "x-envoy-upstream-service-time" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: tokens whose claims do not meet the rule
      | case                        | rule                                                                                                          | claims                       |
      # MAZ #16: anyOf over two different claims; neither matches.
      | anyOf, no claim             | {"name":"add","claims":{"anyOf":[{"claim":"team","values":["red"]},{"claim":"dept","values":["sales"]}]}}    | {"team":"blue","dept":"hr"}  |
      # MAZ #18: the subject differs.
      | sub differs                 | {"name":"add","claims":{"allOf":[{"claim":"sub","values":["alice"]}]}}                                       | {"sub":"bob"}                |
      # MAZ #18 (control): a rule naming another issuer refuses the same kind of token.
      | iss differs                 | {"name":"add","claims":{"allOf":[{"claim":"iss","values":["https://other.example/token"]}]}}                 | {}                           |
      # MAZ #18: no audience of the token's aud list matches.
      | no audience matches         | {"name":"add","claims":{"allOf":[{"claim":"aud","values":["api-b"]}]}}                                       | {"aud":["api-a"]}            |
      # MAZ #19 (control): the list claim groups does not hold b.
      | list claim without b        | {"name":"add","claims":{"allOf":[{"claim":"groups","values":["b"]}]}}                                        | {"groups":["a"]}             |
      # MAZ #19: the old requiredClaims field cannot look inside the list claim groups.
      | list claim, requiredClaims  | {"name":"add","requiredClaims":{"groups":"b"}}                                                                | {"groups":["a","b"]}         |
      # MAZ #20 (control): the number 4 is not "5".
      | different number            | {"name":"add","claims":{"allOf":[{"claim":"level","values":["5"]},{"claim":"admin","values":["true"]}]}}     | {"level":4,"admin":true}     |

  # Which rules apply to a call. Here mcp-authz runs alone, with no mcp-auth, so no caller ever has
  # an identity: a call some rule names gets mcp-authz's own 401 before the MCP server, and a call no
  # rule names passes to the server. The answer therefore shows whether a rule applied, with no
  # token needed. Each row sends its request as written JSON, so tool, resource and prompt calls
  # share one outline. An initialize polled until 200 waits until the route is live and the server
  # is reachable; initialize is a method, which these rules do not govern.
  Scenario Outline: A call a rule names is governed (<case>)
    Given I generate a unique resource name from "mcp-authz-governed" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-governed" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-governed" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-governed" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":<rules>}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <request>
      """
    Then the response status code should be 401
    And the JSON response field "message" should be "Unauthorized: authentication required for this MCP capability"
    And the response header "x-envoy-upstream-service-time" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: calls a rule names
      | case                            | rules                                                                        | request                                                                                              |
      # MAZ #23: a * tool rule governs add.
      | * rule, add                     | {"tools":[{"name":"*","scopes":{"allOf":["maz-all"]}}]}                      | {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3}}}     |
      # MAZ #23: the same * rule governs echo.
      | * rule, echo                    | {"tools":[{"name":"*","scopes":{"allOf":["maz-all"]}}]}                      | {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}} |
      # MAZ #23: the same * rule governs headers.
      | * rule, headers                 | {"tools":[{"name":"*","scopes":{"allOf":["maz-all"]}}]}                      | {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"headers","arguments":{"name":"Accept"}}} |
      # MAZ #27 (control): the rule Add governs a call to Add, so the rule is live.
      | rule Add, call Add              | {"tools":[{"name":"Add","scopes":{"allOf":["maz-x"]}}]}                      | {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Add","arguments":{"a":2,"b":3}}}     |
      # MAZ #27 (control): the resource rule file:///docs/* governs a read of exactly file:///docs/*.
      | rule file:///docs/*, same URI   | {"resources":[{"name":"file:///docs/*","scopes":{"allOf":["maz-x"]}}]}       | {"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///docs/*"}}                 |
      # MAZ #28 (control): the tool rule greeting governs a tool call named greeting.
      | tool rule greeting, tool call   | {"tools":[{"name":"greeting","scopes":{"allOf":["maz-x"]}}]}                 | {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"greeting","arguments":{}}}           |

  # A call no rule names passes to the MCP server. Each row has a control row above with the same
  # rules, which shows those rules are live: the 200 here comes from the name not matching, not from
  # a rule that never loaded.
  Scenario Outline: A call no rule names passes to the MCP server (<case>)
    Given I generate a unique resource name from "mcp-authz-ungoverned" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-ungoverned" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-ungoverned" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-ungoverned" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName} |
      | displayName       | ${CTX:mcpDisplayName} |
      | version           | ${CTX:mcpVersion} |
      | context           | ${CTX:mcpContext} |
      | specVersion       | 2025-06-18 |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":<rules>}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """
    And I use the MCP Client to send this request to "${CTX:mcpContext}/mcp":
      """
      <request>
      """
    Then the response status code should be 200
    And the JSON response should have field "result"
    And the response header "x-envoy-upstream-service-time" should exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

    Examples: calls no rule names
      | case                            | rules                                                                        | request                                                                                              |
      # MAZ #27: the rule Add does not govern add; names must match exactly, case included.
      | rule Add, call add              | {"tools":[{"name":"Add","scopes":{"allOf":["maz-x"]}}]}                      | {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3}}}     |
      # MAZ #27: a * inside a rule name is plain text, not a pattern, so file:///docs/readme.txt is not governed.
      | rule file:///docs/*, other URI  | {"resources":[{"name":"file:///docs/*","scopes":{"allOf":["maz-x"]}}]}       | {"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///docs/readme.txt"}}        |
      # MAZ #28: a tool rule does not govern a prompt with the same name.
      | tool rule greeting, prompt      | {"tools":[{"name":"greeting","scopes":{"allOf":["maz-x"]}}]}                 | {"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greeting","arguments":{"name":"Maz"}}} |

  # mcp-authz must decide governance by rule matching BEFORE consulting identity. A capability
  # no rule targets is not governed and passes through untouched, even with no authenticated
  # context, while a governed capability still fails closed. Here mcp-authz alone (no
  # mcp-auth) governs "add" only.
  # MAZ #26: a tool no rule names passes, even without a token.
  # MAZ #9: with no mcp-auth there is no identity, so the governed tool gets 401.
  @gateway-v1.2
  Scenario: mcp-authz passes through capabilities no rule targets and fails closed on governed ones
    Given I generate a unique resource name from "mcp-authz-passthrough" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-passthrough" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-passthrough" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-passthrough" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["add-scope"]}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # Handshake and an untargeted capability pass through without any authentication.
    When I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And I use the MCP Client to send "echo" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # The governed capability ("add") still fails closed with 401 when no identity is present.
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # A capability the mcp-auth policy excludes from authentication (tools.exceptions) and that
  # mcp-authz does not govern must not be blocked by mcp-authz - it legitimately arrives with
  # no auth context. The protected, governed capability must still be enforced.
  # MAZ #26: with mcp-auth attached, a tool mcp-auth skips and no rule names passes without a token.
  @gateway-v1.2
  Scenario: mcp-authz does not block an mcp-auth-excluded tool while still enforcing governed tools
    Given I generate a unique resource name from "mcp-authz-excluded" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-excluded" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-excluded" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-excluded" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"],"methods":{"enabled":false},"tools":{"exceptions":["echo"]}}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["add-scope"]}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 200 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warmup","version":"1.0.0"}}}
      """

    # Handshake works unauthenticated (methods.enabled: false).
    When I use the MCP Client to send an initialize request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # "echo" is auth-excluded in mcp-auth and not governed by mcp-authz -> passes through unauthenticated.
    And I use the MCP Client to send "echo" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    # "add" is protected -> 401 without a token (backward compatibility preserved).
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response status code should be 401

    # "add" with a token carrying the required scope -> authorized.
    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "add-scope" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I use the MCP Client to send "add" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # The rule targets a tool by name, and on a modern request that name comes from the header.
  # Both halves matter: refusing without the scope shows the rule was found, and allowing with
  # it shows the request still completes at the upstream.
  # MAZ #45: a tool named by a plain Mcp-Name header; the base64 form is a separate row.
  Scenario: mcp-authz governs a tool named by the mirrored header
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique resource name from "mcp-authz-modern" and store it as "mcpName"
    And I generate a unique value from "mcp-authz-modern" and store it as "mcpDisplayName"
    And I generate a unique API version from "mcp-authz-modern" and store it as "mcpVersion"
    And I generate a unique API context from "/mcp-authz-modern" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}            |
      | displayName       | ${CTX:mcpDisplayName}     |
      | version           | ${CTX:mcpVersion}         |
      | context           | ${CTX:mcpContext}         |
      | specVersion       | 2026-07-28                |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"mcp-authz","version":"v1","params":{"tools":[{"name":"add","requiredScopes":["add-scope"]}]}}] |
    Then the response should be successful

    And I set header "Content-Type" to "application/json"
    And I set header "Accept" to "application/json, text/event-stream"
    And I set header "MCP-Protocol-Version" to "2026-07-28"
    And I set header "Mcp-Method" to "tools/call"
    And I set header "Mcp-Name" to "add"
    And I send a "POST" request to "${CTX:mcpContext}/mcp" until status 401 with body:
      """
      {"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"add","arguments":{"a":1,"b":2},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"warmup","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}
      """
    And I clear all headers

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "plainToken"
    And I set header "Authorization" to "Bearer ${CTX:plainToken}"
    And I use the MCP Client to send a "tools/call" request for "add" to "${CTX:mcpContext}/mcp" declaring MCP version "2026-07-28"
    Then the response status code should be 403

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and scope "add-scope" and store it as "scopedToken"
    And I set header "Authorization" to "Bearer ${CTX:scopedToken}"
    And I use the MCP Client to send a "tools/call" request for "add" to "${CTX:mcpContext}/mcp" declaring MCP version "2026-07-28"
    Then the response should be successful
    And the JSON response should have field "result"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful
