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

# The policies that read the application identity jwt-auth sets (x-wso2-application-id). The key
# managers are in overlays/application-identity.toml: mock-jwks-appid reads the identity from
# client_id, and mock-jwks sets none. The testbench echo backend (3002) returns the request body
# under "json", so each request's body decides the token counts and the model the LLM policies see.
@jwt-auth-application-identity-policies
Feature: Policies that act on the application identity from a JWT
  As an API developer
  I want rate limits and cached responses scoped to the application a JWT identifies
  So that all users of an application share them and other applications do not

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: consumerBased token-based-ratelimit counts each application separately
    Given I generate a unique resource name from "jwt-app-tbrl-template" and store it as "templateName"
    And I generate a unique value from "jwt-app-tbrl-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "jwt-app-tbrl" and store it as "providerName"
    And I generate a unique value from "jwt-app-tbrl" and store it as "providerDisplayName"
    And I generate a unique API version from "jwt-app-tbrl" and store it as "providerVersion"
    And I generate a unique API context from "/jwt-app-tbrl" and store it as "providerContext"
    And I generate a unique value from "jwt-app-tbrl-alpha" and store it as "alphaClient"
    And I generate a unique value from "jwt-app-tbrl-beta" and store it as "betaClient"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion}                                     |
      | name              | ${CTX:templateName}                                           |
      | displayName       | ${CTX:templateDisplayName}                                    |
      | spec.totalTokens  | {"location":"payload","identifier":"$.json.usage.total_tokens"} |
      | spec.requestModel | {"location":"payload","identifier":"$.json.model"}            |
      | spec.responseModel | {"location":"payload","identifier":"$.json.model"}           |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}    |
      | template           | ${CTX:templateName}       |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3002     |
      | accessControl.mode | allow_all                 |
      | spec.policies      | [{"name":"jwt-auth","version":"v1","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"issuers":["mock-jwks-appid"]}}]},{"name":"token-based-ratelimit","version":"v1","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"consumerBased":true,"totalTokenLimits":[{"count":20,"duration":"1m"}]}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/chat/completions" until status 200

    # Each reply reports 10 tokens and each counter allows 20, so a counter takes two requests.
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=grace" and store it as "graceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=heidi" and store it as "heidiToken"
    And I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    Then the response status code should be 200

    # bob belongs to alice's application, so alice's two requests used up his counter too.
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    Then the response status code should be 200

    # Tokens without client_id carry no application and share the default counter.
    When I set header "Authorization" to "Bearer ${CTX:graceToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    Then the response status code should be 200
    When I set header "Authorization" to "Bearer ${CTX:heidiToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    Then the response status code should be 200
    When I set header "Authorization" to "Bearer ${CTX:graceToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","usage":{"total_tokens":10}}
      """
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I delete the LLM provider template "${CTX:templateName}"
    Then the response should be successful

  # Excluded with the runner's ~@known-issue, like the enforcement scenarios of
  # llm-cost-based-ratelimit's own suite: on the integration gateways llm-cost prices the reply
  # ($0.001 here), but the charge never reaches the budget, so no request is ever rejected.
  @known-issue
  Scenario: consumerBased llm-cost-based-ratelimit gives each application its own budget
    Given I generate a unique resource name from "jwt-app-cost-template" and store it as "templateName"
    And I generate a unique value from "jwt-app-cost-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "jwt-app-cost" and store it as "providerName"
    And I generate a unique value from "jwt-app-cost" and store it as "providerDisplayName"
    And I generate a unique API version from "jwt-app-cost" and store it as "providerVersion"
    And I generate a unique API context from "/jwt-app-cost" and store it as "providerContext"
    And I generate a unique value from "jwt-app-cost-alpha" and store it as "alphaClient"
    And I generate a unique value from "jwt-app-cost-beta" and store it as "betaClient"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                          |
      | name                  | ${CTX:templateName}                                                |
      | displayName           | ${CTX:templateDisplayName}                                         |
      | spec.promptTokens     | {"location":"payload","identifier":"$.json.usage.prompt_tokens"}     |
      | spec.completionTokens | {"location":"payload","identifier":"$.json.usage.completion_tokens"} |
      | spec.requestModel     | {"location":"payload","identifier":"$.json.model"}                 |
      | spec.responseModel    | {"location":"payload","identifier":"$.json.model"}                 |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}    |
      | template           | ${CTX:templateName}       |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3002     |
      | accessControl.mode | allow_all                 |
      | spec.policies      | [{"name":"jwt-auth","version":"v1","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"issuers":["mock-jwks-appid"]}}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"consumerBased":true,"budgetLimits":[{"amount":0.002,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/chat/completions","methods":["POST"]}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/chat/completions" until status 200

    # gpt-4.1-2025-04-14: 100 prompt x $2/1M + 100 completion x $8/1M = $0.001 a request, so the
    # $0.002 budget of an application takes two requests.
    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    And I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","usage":{"prompt_tokens":100,"completion_tokens":100}}
      """
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","usage":{"prompt_tokens":100,"completion_tokens":100}}
      """
    Then the response status code should be 200

    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","usage":{"prompt_tokens":100,"completion_tokens":100}}
      """
    Then the response status code should be 429

    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","usage":{"prompt_tokens":100,"completion_tokens":100}}
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I delete the LLM provider template "${CTX:templateName}"
    Then the response should be successful

  Scenario: an advanced-ratelimit quota keyed on the application identity counts each application separately
    Given I generate a unique value from "jwt-app-adv" and store it as "apiName"
    And I generate a unique API version from "jwt-app-adv" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-adv" and store it as "apiContext"
    And I generate a unique value from "jwt-app-adv-alpha" and store it as "alphaClient"
    And I generate a unique value from "jwt-app-adv-beta" and store it as "betaClient"
    And I store the value "metadata" as "keyType"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"per-application","limits":[{"limit":2,"duration":"1m"}],"keyExtraction":[{"type":"${CTX:keyType}","key":"x-wso2-application-id"}]}]}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I clear all headers
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    And I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 429

    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: semantic-cache shares a cached response among the users of one application only
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "jwt-app-cache" and store it as "apiName"
    And I generate a unique API version from "jwt-app-cache" and store it as "apiVersion"
    And I generate a unique API context from "/jwt-app-cache" and store it as "apiContext"
    And I generate a unique value from "jwt-app-cache-alpha" and store it as "alphaClient"
    And I generate a unique value from "jwt-app-cache-beta" and store it as "betaClient"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks-appid"]}},{"name":"semantic-cache","version":"v1","params":{"similarityThreshold":0.9}}]},{"method":"POST","path":"/chat-per-user","policies":[{"name":"jwt-auth","version":"v1","params":{"issuers":["mock-jwks"]}},{"name":"semantic-cache","version":"v1","params":{"similarityThreshold":0.9}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"

    # alice's response is cached for her application, so bob, a user of the same application,
    # receives it and carol, of another application, does not.
    And I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"prompt":"application cache prompt about tidal pools"}
      """
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until header "X-Cache-Status" is "HIT" with body:
      """
      {"prompt":"application cache prompt about tidal pools"}
      """
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"prompt":"application cache prompt about tidal pools"}
      """
    Then the response status code should be 200
    And the response header "X-Cache-Status" should be "HIT"
    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"prompt":"application cache prompt about tidal pools"}
      """
    Then the response status code should be 200
    And the response header "X-Cache-Status" should not exist

    # mock-jwks sets no application identity, so the cache stays per user.
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-per-user" until status 200 with body:
      """
      {"prompt":"per user cache prompt about glaciers"}
      """
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-per-user" until header "X-Cache-Status" is "HIT" with body:
      """
      {"prompt":"per user cache prompt about glaciers"}
      """
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat-per-user" with body:
      """
      {"prompt":"per user cache prompt about glaciers"}
      """
    Then the response status code should be 200
    And the response header "X-Cache-Status" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
