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

# The testbench has no switchyard-server, so these scenarios cover what the policy does when no
# usable decision arrives. Each API points switchyardEndpoint at a testbench address that fails in a
# known way: port 1 refuses the connection, and the echo service (port 3002) answers /status/<code>
# with that status and /json with JSON that is not a decision. The echo service is also the
# upstream, so the response shows the request the policy sent on, including its model.

@nvidia-switchyard-router
Feature: Switchyard router policy
  As an API developer
  I want the nvidia-switchyard-router policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Routes to the fallback model when switchyard-server is unreachable
    Given I generate a unique value from "sy-fallback" and store it as "apiName"
    And I generate a unique API version from "sy-fallback" and store it as "apiVersion"
    And I generate a unique API context from "/sy-fallback" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"model","model":"capable-model"},"switchyardEndpoint":"http://testbench:1/v1/decision","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "capable-model"
    And the response header "x-switchyard-outcome" should be "fallback"
    And the response header "x-switchyard-error" should be "unavailable"
    And the response header "x-switchyard-tier" should be "capable"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario Outline: Records why no decision was made: <reason>
    Given I generate a unique value from "sy-<reason>" and store it as "apiName"
    And I generate a unique API version from "sy-<reason>" and store it as "apiVersion"
    And I generate a unique API context from "/sy-<reason>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"model","model":"efficient-model"},"switchyardEndpoint":"<endpoint>","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "efficient-model"
    And the response header "x-switchyard-outcome" should be "fallback"
    And the response header "x-switchyard-error" should be "<reason>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | reason            | endpoint                              |
      | unavailable       | http://testbench:3002/status/503      |
      | profile_not_found | http://testbench:3002/status/404      |
      | invalid_decision  | http://testbench:3002/json            |

  Scenario: Rejects the request when the fallback mode is error
    Given I generate a unique value from "sy-reject" and store it as "apiName"
    And I generate a unique API version from "sy-reject" and store it as "apiVersion"
    And I generate a unique API context from "/sy-reject" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"error"},"switchyardEndpoint":"http://testbench:1/v1/decision","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 503
    And the response should match the expected error response "nvidia-switchyard-router-decision-failed"
    And the response header "x-switchyard-outcome" should be "rejected"
    And the response header "x-switchyard-error" should be "unavailable"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Leaves the request unchanged in observe-only mode when no decision is made
    Given I generate a unique value from "sy-observe" and store it as "apiName"
    And I generate a unique API version from "sy-observe" and store it as "apiVersion"
    And I generate a unique API context from "/sy-observe" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","mode":"observe_only","modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"error"},"switchyardEndpoint":"http://testbench:1/v1/decision","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "client-model"
    And the response header "x-switchyard-outcome" should be "decision_failed"
    And the response header "x-switchyard-error" should be "unavailable"
    And the response header "x-switchyard-tier" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Falls back without asking the server when the path has no known LLM format
    Given I generate a unique value from "sy-format" and store it as "apiName"
    And I generate a unique API version from "sy-format" and store it as "apiVersion"
    And I generate a unique API context from "/sy-format" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"model","model":"efficient-model"},"switchyardEndpoint":"http://testbench:1/v1/decision","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "efficient-model"
    And the response header "x-switchyard-outcome" should be "fallback"
    And the response header "x-switchyard-error" should be "unknown_format"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Passes a body that is not a JSON object through unchanged
    Given I generate a unique value from "sy-passthrough" and store it as "apiName"
    And I generate a unique API version from "sy-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/sy-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"error"},"switchyardEndpoint":"http://testbench:1/v1/decision","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      not json
      """
    Then the response status code should be 200
    And the JSON response field "data" should be "not json"
    And the response header "x-switchyard-outcome" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Omits the routing headers when responseHeaders is false
    Given I generate a unique value from "sy-noheaders" and store it as "apiName"
    And I generate a unique API version from "sy-noheaders" and store it as "apiVersion"
    And I generate a unique API context from "/sy-noheaders" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents","responseHeaders":false,"modelPool":[{"model":"efficient-model","tier":"efficient"},{"model":"capable-model","tier":"capable"}],"fallback":{"mode":"model","model":"capable-model"},"switchyardEndpoint":"http://testbench:1/v1/decision","switchyardTimeout":"2s","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "capable-model"
    And the response header "x-switchyard-outcome" should not exist
    And the response header "x-switchyard-tier" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Rejects a configuration without a model pool
    Given I generate a unique value from "sy-nopool" and store it as "apiName"
    And I generate a unique API version from "sy-nopool" and store it as "apiVersion"
    And I generate a unique API context from "/sy-nopool" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat/completions","policies":[{"name":"nvidia-switchyard-router","version":"v0","params":{"profile":"coding-agents"}}]}] |
    Then the response should be a client error
