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

@json-schema-guardrail
Feature: JSON Schema guardrail policy across API configurations
  As an API developer
  I want the guardrail to apply where it is attached, alongside other policies and through updates
  So that schema validation is enforced consistently over the life of an API

  # The guardrail across API configurations: API-wide and per operation, beside authentication,
  # rate limiting and transformation policies, through updates, under concurrent requests, and in
  # logs and error bodies. Request validation is on only with "enabled": true. Where the upstream is
  # the capture service under the API's name, a lookup shows what reached the backend.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # Every operation sends a body: with the policy on the API, a request without one would get 422.
  Scenario: Apply the guardrail globally/API-wide and invoke multiple operations
    Given I generate a unique value from "jsg-api-wide" and store it as "apiName"
    And I generate a unique API version from "jsg-api-wide" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-api-wide" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.policies          | [{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}] |
      | spec.operations        | [{"method":"POST","path":"/orders"},{"method":"PUT","path":"/profile"},{"method":"POST","path":"/customers"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/profile" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/profile" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/customers" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/customers" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  Scenario: Apply the guardrail only to a selected operation/resource
    Given I generate a unique value from "jsg-one-operation" and store it as "apiName"
    And I generate a unique API version from "jsg-one-operation" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-one-operation" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"POST","path":"/validated","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]},{"method":"POST","path":"/open"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/open" until status 200 with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validated" with body:
      """
      {"name":"jsg-r21-ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/validated"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/open" with body:
      """
      {"name":"jsg-r21-ann"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/open"
    Then the response status code should be 200
    And the JSON response field "body" should contain "jsg-r21-ann"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/open" until status 404

  # The credentials are jsg-user / jsg-pass-22. basic-auth and the limit of 4 requests an hour act
  # on headers, so they run before the guardrail. The limit also counts blocked requests: after 422,
  # 200, 200 and 422, a valid request gets 429.
  Scenario: Combine JSON Schema Guardrail with authentication, rate limiting, and transformation policies (authentication and rate limiting)
    Given I generate a unique value from "jsg-auth-ratelimit" and store it as "apiName"
    And I generate a unique API version from "jsg-auth-ratelimit" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-auth-ratelimit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"POST","path":"/orders","policies":[{"name":"basic-auth","version":"v1","params":{"username":"jsg-user","password":"jsg-pass-22"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":4,"duration":"1h"}]}},{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 401 with body:
      """
      {"name":"Ann"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 401
    And the response body should not contain "JSON_SCHEMA_GUARDRAIL"

    When I set header "Authorization" to "Basic anNnLXVzZXI6anNnLXBhc3MtMjI="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # prompt-decorator runs first and appends " Reply in English.". The guardrail's jsonPath is left
  # at its default, $.messages[-1].content: that message must end with the sentence and be at most
  # 40 characters. "What is 2+2?" passes only once decorated (30). "Translate: Reply in English."
  # (28) would pass as sent, but decorated it is 46.
  Scenario: Transform the request before JSON Schema Guardrail execution
    Given I generate a unique value from "jsg-transform-before" and store it as "apiName"
    And I generate a unique API version from "jsg-transform-before" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-transform-before" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"prompt-decorator","version":"v1","params":{"promptDecoratorConfig":{"text":"Reply in English."},"jsonPath":"$.messages[-1].content","append":true}},{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"schema":"{\"type\":\"string\",\"pattern\":\"Reply in English[.]$\",\"maxLength\":40}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"What is 2+2?"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "What is 2+2? Reply in English."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Translate: Reply in English."}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The guardrail runs first, with its jsonPath left at the default, $.messages[-1].content, and
  # allows at most 20 characters there. prompt-decorator then appends " Answer at length with every
  # detail.", so the backend gets content the guardrail never checked. After the blocked request,
  # the capture service still holds the first one.
  Scenario: Modify the payload after JSON Schema validation
    Given I generate a unique value from "jsg-transform-after" and store it as "apiName"
    And I generate a unique API version from "jsg-transform-after" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-transform-after" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"schema":"{\"type\":\"string\",\"maxLength\":20}"}}},{"name":"prompt-decorator","version":"v1","params":{"promptDecoratorConfig":{"text":"Answer at length with every detail."},"jsonPath":"$.messages[-1].content","append":true}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"What is 2+2?"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "What is 2+2? Answer at length with every detail."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Please explain quantum physics in detail"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the response body should not contain "quantum"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The schema first requires name, then title. The poll waits until a request shows the new schema.
  # The two requests after it check that every later request does too, and none falls back to the
  # old schema.
  Scenario: Update the JSON Schema or JSONPath on an already deployed API (schema)
    Given I generate a unique value from "jsg-update-schema" and store it as "apiName"
    And I generate a unique API version from "jsg-update-schema" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-update-schema" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"required\":[\"name\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"title":"T"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"required\":[\"title\"]}"}}}]}] |
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"title":"T"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"name":"N"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"name":"N"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The path first selects "first", then "second"; the schema allows at most 5 characters. The poll
  # waits until a request shows the new path. The two requests after it check that every later
  # request does too, and none falls back to the old path.
  Scenario: Update the JSON Schema or JSONPath on an already deployed API (JSONPath)
    Given I generate a unique value from "jsg-update-jsonpath" and store it as "apiName"
    And I generate a unique API version from "jsg-update-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-update-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.first","schema":"{\"type\":\"string\",\"maxLength\":5}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"first":"ok","second":"far too long"}
      """
    Then the response status code should be 200

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.second","schema":"{\"type\":\"string\",\"maxLength\":5}"}}}]}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 422 with body:
      """
      {"first":"ok","second":"far too long"}
      """
    Then the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"first":"far too long","second":"ok"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"first":"far too long","second":"ok"}
      """
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The step sends 30 requests at once, cycling through the rows, and checks every response for its
  # row's status and text, with the request's own number. A response with another number fails it.
  Scenario: Send concurrent requests containing valid and invalid payloads
    Given I generate a unique value from "jsg-concurrent" and store it as "apiName"
    And I generate a unique API version from "jsg-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 30 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/orders" cycling through:
      | body                                              | status | contains                |
      | {"name":"user-{i}","email":"user{i}@example.com"} | 200    | user{i}@example.com     |
      | {"name":"user-{i}"}                               | 422    | {"name":"user-{i}"}     |
      | {"name":"user-{i}"                                | 422    | Error validating schema |

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # showAssessment is left at its default, false, so error bodies carry no assessment. The marker
  # jsg-r30-secret-marker is used only here. The logs are the whole gateway's, at its default info
  # level.
  Scenario: Inspect logs and client-facing validation errors for failed requests/responses
    Given I generate a unique value from "jsg-exposure" and store it as "apiName"
    And I generate a unique API version from "jsg-exposure" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-exposure" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/whole","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]},{"method":"POST","path":"/selected","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.input","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/whole" with body:
      """
      {"name":"jsg-r30-secret-marker"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the response body should not contain "jsg-r30-secret-marker"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/whole" with body:
      """
      {"name":"jsg-r30-secret-marker"
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error validating schema"
    And the response body should not contain "jsg-r30-secret-marker"
    And the response body should not contain "unexpected EOF"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/selected" with body:
      """
      {"name":"jsg-r30-secret-marker"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the response body should not contain "jsg-r30-secret-marker"
    And the response body should not contain "key not found"
    And the "gateway-runtime" service logs should not contain "jsg-r30-secret-marker"
    And the "gateway-controller" service logs should not contain "jsg-r30-secret-marker"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
