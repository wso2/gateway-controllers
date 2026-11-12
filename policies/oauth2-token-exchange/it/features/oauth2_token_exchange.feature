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

# The "I get a JWT token from the mock JWKS server" step stands in for a token already issued by
# the gateway's own IdP, which is exactly the credential this policy exchanges for one the
# backend's own authorization server, the testbench "oauth2" service, will accept.

@oauth2-token-exchange
Feature: OAuth2 token exchange
  As an API developer
  I want the gateway to exchange my caller's own credential for a backend-specific token
  So that my backend can require a token from its own authorization server without my caller ever holding one

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "oauth2" service URL at "/oauth2/token" and store it as "oauthTokenEndpoint"
    And I send a "POST" request to the "oauth2" service at "/debug/reset" with body:
      """
      {}
      """

  # The "oauth2" service issues a real RS256-signed JWT for the token-exchange and jwt-bearer
  # grants (client_credentials/password keep the older opaque "mock-token-" string, which other
  # scenarios elsewhere still assert on) - so the exchanged-token assertions below match a JWT's
  # three-dot-separated shape rather than a literal prefix.
  Scenario: Token-exchange grant exchanges the caller's token for a backend token
    Given I generate a unique resource name from "oauth2-token-exchange-happy" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-happy" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-happy" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 200
    And the response body should match pattern "Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    And the response body should not contain "${CTX:token}"
    When I send a "GET" request to the "oauth2" service at "/debug/stats"
    Then the response body should contain "urn:ietf:params:oauth:grant-type:token-exchange"
    And I store the masked preview of context value "token" as "tokenPreview"
    And the response body should contain "${CTX:tokenPreview}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: JwtBearer grant exchanges the caller's token for a backend token
    Given I generate a unique resource name from "oauth2-token-exchange-jwtbearer" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-jwtbearer" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-jwtbearer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"grantType":"JwtBearer","tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 200
    And the response body should match pattern "Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    When I send a "GET" request to the "oauth2" service at "/debug/stats"
    Then the response body should contain "urn:ietf:params:oauth:grant-type:jwt-bearer"
    And I store the masked preview of context value "token" as "tokenPreview"
    And the response body should contain "${CTX:tokenPreview}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A request without the caller's credential is rejected
    Given I generate a unique resource name from "oauth2-token-exchange-nocred" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-nocred" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-nocred" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    And I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data" until status 401
    And the JSON response field "error" should be "unauthorized"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Invalid client credentials return Bad Gateway
    Given I generate a unique resource name from "oauth2-token-exchange-badclient" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-badclient" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-badclient" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"definitely-the-wrong-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 502

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An unreachable token endpoint returns Bad Gateway
    Given I generate a unique resource name from "oauth2-token-exchange-unreachable" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-unreachable" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-unreachable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"http://oauth2-does-not-exist:9601/oauth2/token","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 502

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  # The authorization server rejecting the subject token itself (as opposed to the gateway's own
  # client credentials, or an unreachable endpoint) is a third, distinct failure path. The mock
  # oauth2 service never validates a subject_token cryptographically, so it only ever rejects the
  # literal sentinel value "invalid-subject-token" - good enough to prove this path is handled the
  # same way as the others (Bad Gateway, no upstream detail leaked), without needing a real
  # malformed-signature JWT.
  Scenario: The authorization server rejecting the subject token returns Bad Gateway
    Given I generate a unique resource name from "oauth2-token-exchange-rejected" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-rejected" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-rejected" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Authorization" to "Bearer invalid-subject-token"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 502

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A backend token is cached across repeated requests
    Given I generate a unique resource name from "oauth2-token-exchange-cache" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-cache" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-cache" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}?ttl=3600","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send 5 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 200
    When I send a "GET" request to the "oauth2" service at "/debug/stats"
    Then the JSON response field "tokenRequestCount" should be 1

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Configured audiences, scopes, and resources reach the token endpoint
    Given I generate a unique resource name from "oauth2-token-exchange-params" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-params" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-params" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret","audiences":["it-suite-audience"],"scopes":["it-suite-scope"],"resources":["https://backend.example.com"]}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 200
    When I send a "GET" request to the "oauth2" service at "/debug/stats"
    Then the response body should contain "it-suite-audience"
    And the response body should contain "it-suite-scope"
    And the response body should contain "backend.example.com"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  # jwt-auth validates the caller's own gateway-issued JWT and forwards it under a different
  # header (rather than leaving it on Authorization); oauth2-token-exchange must be told to read
  # from that same header, or it has nothing to exchange. This is the correctly-wired version of
  # the chain; the next scenario is its negative counterpart.
  Scenario: jwt-auth forwards the caller's token for oauth2-token-exchange to exchange
    Given I generate a unique resource name from "oauth2-token-exchange-chain" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-chain" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-chain" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"forwardToken":true,"forwardedTokenHeader":"x-forwarded-authorization"}},{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret","subjectTokenSource":{"type":"header","name":"x-forwarded-authorization","prefix":"Bearer "}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 200
    And the response body should match pattern "Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    And the response body should not contain "${CTX:token}"
    When I send a "GET" request to the "oauth2" service at "/debug/stats"
    Then the response body should contain "urn:ietf:params:oauth:grant-type:token-exchange"
    And I store the masked preview of context value "token" as "tokenPreview"
    And the response body should contain "${CTX:tokenPreview}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  # mcp-auth delegates its own token validation to jwt-auth internally, and the same
  # forwardToken/forwardedTokenHeader wiring applies: configured this way, it forwards the
  # caller's token under a different header instead of leaving it on Authorization, so
  # oauth2-token-exchange must be told to read from that header, same as the REST/jwt-auth chain
  # above. This is also the scenario oauth2-token-exchange's own policy-definition.yaml calls out
  # by name as the reason its header phase defers to the body phase on a missing subject token:
  # mcp-auth is a body-phase auth policy on routes with no operation resolver, so the caller's
  # token can still be missing from the forwarded header when oauth2-token-exchange's header phase
  # runs, and only appears once mcp-auth's own body-phase processing has forwarded it.
  Scenario: mcp-auth forwards the caller's token for oauth2-token-exchange to exchange
    Given I generate a unique resource name from "oauth2-token-exchange-mcp-chain" and store it as "mcpName"
    And I generate a unique value from "oauth2-token-exchange-mcp-chain" and store it as "mcpDisplayName"
    And I generate a unique API version from "oauth2-token-exchange-mcp-chain" and store it as "mcpVersion"
    And I generate a unique API context from "/oauth2-token-exchange-mcp-chain" and store it as "mcpContext"
    When I create MCP proxy from "resources/templates/mcp.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion} |
      | name              | ${CTX:mcpName}                    |
      | displayName       | ${CTX:mcpDisplayName}             |
      | version           | ${CTX:mcpVersion}                 |
      | context           | ${CTX:mcpContext}                 |
      | specVersion       | 2025-06-18                         |
      | spec.upstream.url | http://testbench:3009${CTX:gatewayMCPUpstreamPath} |
      | spec.policies     | [{"name":"mcp-auth","version":"v1","params":{"issuers":["mock-jwks"],"forwardToken":true,"forwardedTokenHeader":"x-forwarded-authorization"}},{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret","subjectTokenSource":{"type":"header","name":"x-forwarded-authorization","prefix":"Bearer "}}}] |
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
    Then the response should be successful

    # The testbench MCP backend's own "headers" tool reports back the Authorization header it
    # received, so this is the backend itself confirming the exchanged token arrived - not just
    # the gateway's response status - the same proof the REST/jwt-auth chain scenario above gets
    # from its echo backend reflecting the request it received.
    When I use the MCP Client to send "headers" tools/call request to "${CTX:mcpContext}/mcp"
    Then the response should be successful
    And the response body should match pattern "Authorization: Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    And the response body should not contain "${CTX:token}"

    When I send a "GET" request to the "oauth2" service at "/debug/stats"
    Then the response body should contain "urn:ietf:params:oauth:grant-type:token-exchange"
    And I store the masked preview of context value "token" as "tokenPreview"
    And the response body should contain "${CTX:tokenPreview}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the MCP proxy "${CTX:mcpName}"
    Then the response should be successful

  # The same chain as above, but oauth2-token-exchange is left at its default subjectTokenSource
  # (the Authorization header) instead of being pointed at x-forwarded-authorization. jwt-auth has
  # already moved the caller's token there, so Authorization is empty by the time
  # oauth2-token-exchange runs and it has no credential to exchange - a misconfiguration that must
  # fail closed, not silently let the request through unexchanged.
  Scenario: Leaving oauth2-token-exchange at its default header misses a token jwt-auth forwarded elsewhere
    Given I generate a unique resource name from "oauth2-token-exchange-miswired" and store it as "apiName"
    And I generate a unique API version from "oauth2-token-exchange-miswired" and store it as "apiVersion"
    And I generate a unique API context from "/oauth2-token-exchange-miswired" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002             |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/data","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"],"forwardToken":true,"forwardedTokenHeader":"x-forwarded-authorization"}},{"name":"oauth2-token-exchange","version":"v0","params":{"tokenEndpoint":"${CTX:oauthTokenEndpoint}","clientId":"test-client","clientSecret":"test-secret"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and store it as "token"
    And I set header "Authorization" to "Bearer ${CTX:token}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
