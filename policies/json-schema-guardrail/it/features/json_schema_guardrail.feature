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
Feature: JSON schema guardrail policy
  As an API developer
  I want to validate request and response payloads against a JSON Schema
  So that I can enforce structural and type contracts on API traffic

  # Request and response validation, schema keywords, JSONPath, malformed JSON, invert mode and
  # assessment details. Request validation is on only with "enabled": true. A "response" object
  # turns response validation on, since "enabled" defaults to true there. A capture lookup shows
  # what reached the backend, and 204 means nothing did. The LLM mock replies with the body named in
  # the request's x_testbench_reply field.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Configure a valid JSON Schema Guardrail on the request flow and send a payload matching the schema
    Given I generate a unique value from "jsg-request-valid" and store it as "apiName"
    And I generate a unique API version from "jsg-request-valid" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-request-valid" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"jsg-r01@example.com"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders"
    Then the response status code should be 200
    And the JSON response field "body" should contain "jsg-r01@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Send a request payload that violates the configured schema
    Given I generate a unique value from "jsg-request-invalid" and store it as "apiName"
    And I generate a unique API version from "jsg-request-invalid" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-request-invalid" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the response header "Content-Type" should be "application/json"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Validate required fields by sending payloads with all required fields and then omitting one
    Given I generate a unique value from "jsg-required" and store it as "apiName"
    And I generate a unique API version from "jsg-required" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-required" and store it as "apiContext"
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

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"jsg-r06@example.com"}
      """
    Then the response status code should be 200
    And the JSON response field "body" should contain "jsg-r06@example.com"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "(root)"
    And the JSON response field "message.assessments[0].description" should be "email is required"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Wrong type fails validation
    Given I generate a unique value from "jsg-wrong-type" and store it as "apiName"
    And I generate a unique API version from "jsg-wrong-type" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-wrong-type" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"age\":{\"type\":\"integer\"}},\"required\":[\"name\",\"age\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"name": "John", "age": "thirty"}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Configure the guardrail on the response flow and return a response matching the schema
    Given I generate a unique value from "jsg-response-valid" and store it as "apiName"
    And I generate a unique API version from "jsg-response-valid" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-response-valid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"POST","path":"/reply","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"status\":{\"enum\":[\"approved\"]}},\"required\":[\"status\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{"status":"approved"}}}
      """
    Then the JSON response field "status" should be "approved"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/reply" until status 404

  Scenario: Both request and response are validated against their own schemas
    Given I generate a unique value from "jsg-both-validation" and store it as "apiName"
    And I generate a unique API version from "jsg-both-validation" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-both-validation" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"input\":{\"type\":\"string\"}},\"required\":[\"input\"]}"},"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"method\":{\"type\":\"string\"}},\"required\":[\"method\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"input": "test data"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"other": "test data"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The schema forbids extra fields, so the fields outside "order" would fail it if they were
  # validated. The assessment's field is relative to the selected section.
  Scenario: Configure JSONPath to validate only a selected section of the request payload
    Given I generate a unique value from "jsg-jsonpath-section" and store it as "apiName"
    And I generate a unique API version from "jsg-jsonpath-section" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-jsonpath-section" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.order","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"},\"quantity\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"id\",\"quantity\"],\"additionalProperties\":false}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"order":{"id":"A-1","quantity":2},"note":12345,"extra":{"anything":true}}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"order":{"id":"A-1","quantity":0},"note":"ok"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "quantity"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: JSONPath extraction with invalid data
    Given I generate a unique value from "jsg-jsonpath-invalid" and store it as "apiName"
    And I generate a unique API version from "jsg-jsonpath-invalid" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-jsonpath-invalid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.user","schema":"{\"type\":\"object\",\"properties\":{\"age\":{\"type\":\"integer\",\"minimum\":18}},\"required\":[\"age\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"user": {"age": 15}, "other": "data"}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Validate nested object with JSONPath
    Given I generate a unique value from "jsg-nested-jsonpath" and store it as "apiName"
    And I generate a unique API version from "jsg-nested-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-nested-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"$.order.shippingAddress","schema":"{\"type\":\"object\",\"properties\":{\"street\":{\"type\":\"string\"},\"city\":{\"type\":\"string\"},\"zipCode\":{\"type\":\"string\"}},\"required\":[\"street\",\"city\",\"zipCode\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"order": {"shippingAddress": {"street": "123 Main St", "city": "Boston", "zipCode": "02101"}}}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"order": {"shippingAddress": {"street": "123 Main St", "city": "Boston"}}}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Invert logic passes when schema validation fails
    Given I generate a unique value from "jsg-invert-pass" and store it as "apiName"
    And I generate a unique API version from "jsg-invert-pass" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-invert-pass" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"dangerousCommand\":{\"type\":\"string\",\"pattern\":\"^(rm\|delete\|drop).*\"}},\"required\":[\"dangerousCommand\"]}","invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"safeCommand": "list files"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"dangerousCommand": "rm -rf /tmp"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Configure invertDecision=true
    Given I generate a unique value from "jsg-invert-true" and store it as "apiName"
    And I generate a unique API version from "jsg-invert-true" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-invert-true" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}","invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"jsg-r17-ann"}
      """
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders"
    Then the response status code should be 200
    And the JSON response field "body" should contain "jsg-r17-ann"

    # Invert flips only the schema verdict. A body that cannot be validated is still blocked.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error validating schema"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Inverted schema targeting a malicious pattern passes safe content
    Given I generate a unique value from "jsg-block-malicious" and store it as "apiName"
    And I generate a unique API version from "jsg-block-malicious" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-block-malicious" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"pattern\":\".*DROP TABLE.*\"}}}","invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"query": "SELECT * FROM users"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"query": "DROP TABLE users"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Enable guardrail assessment details and trigger a validation failure
    Given I generate a unique value from "jsg-assessment-on" and store it as "apiName"
    And I generate a unique API version from "jsg-assessment-on" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-assessment-on" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/users","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":12}},\"required\":[\"name\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      {"name":"jsg-r18-19"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "name"
    And the JSON response field "message.assessments[0].description" should be "String length must be greater than or equal to 12"
    And the JSON response field "message.assessments[0].value" should be "jsg-r18-19"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Disable assessment details and trigger the same failure
    Given I generate a unique value from "jsg-assessment-off" and store it as "apiName"
    And I generate a unique API version from "jsg-assessment-off" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-assessment-off" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/users","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":false,"schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":12}},\"required\":[\"name\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      {"name":"jsg-r18-19"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments" should not exist
    And the response body should not contain "jsg-r18-19"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The first two payloads sit exactly on the lower and upper bounds. The third breaks one
  # constraint.
  Scenario Outline: Validate field constraints such as minLength, maxLength, minimum, maximum, and enum (<case>)
    Given I generate a unique value from "jsg-constraints" and store it as "apiName"
    And I generate a unique API version from "jsg-constraints" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-constraints" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"username\":{\"type\":\"string\",\"minLength\":3,\"maxLength\":8},\"quantity\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":100},\"color\":{\"enum\":[\"red\",\"green\"]}},\"required\":[\"username\",\"quantity\",\"color\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"username":"abc","quantity":1,"color":"red"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"username":"abcdefgh","quantity":100,"color":"green"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      <payload>
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "<field>"
    And the JSON response field "message.assessments[0].description" should contain "<description>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case      | payload                                             | field    | description                                      |
      | minLength | {"username":"ab","quantity":1,"color":"red"}        | username | String length must be greater than or equal to 3 |
      | maxLength | {"username":"abcdefghi","quantity":1,"color":"red"} | username | String length must be less than or equal to 8    |
      | minimum   | {"username":"abc","quantity":0,"color":"red"}       | quantity | Must be greater than or equal to 1               |
      | maximum   | {"username":"abc","quantity":101,"color":"red"}     | quantity | Must be less than or equal to 100                |
      | enum      | {"username":"abc","quantity":1,"color":"blue"}      | color    | color must be one of the following               |

  Scenario: Validate numeric range constraints
    Given I generate a unique value from "jsg-numeric-range" and store it as "apiName"
    And I generate a unique API version from "jsg-numeric-range" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-numeric-range" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"price\":{\"type\":\"number\",\"minimum\":0,\"maximum\":10000}},\"required\":[\"price\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"price": -5}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Validate array constraints
    Given I generate a unique value from "jsg-array-constraints" and store it as "apiName"
    And I generate a unique API version from "jsg-array-constraints" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-array-constraints" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"tags\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"minItems\":1,\"maxItems\":5}},\"required\":[\"tags\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"tags": []}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Validate enum constraints
    Given I generate a unique value from "jsg-enum-constraints" and store it as "apiName"
    And I generate a unique API version from "jsg-enum-constraints" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-enum-constraints" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"status\":{\"type\":\"string\",\"enum\":[\"pending\",\"processing\",\"completed\",\"cancelled\"]}},\"required\":[\"status\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"status": "invalid-status"}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Validate pattern constraints
    Given I generate a unique value from "jsg-pattern-constraints" and store it as "apiName"
    And I generate a unique API version from "jsg-pattern-constraints" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-pattern-constraints" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"email\":{\"type\":\"string\",\"pattern\":\"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\\\\\.[a-zA-Z]{2,}$\"}},\"required\":[\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"email": "invalid-email"}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario Outline: Validate nested JSON objects against a nested schema (<case>)
    Given I generate a unique value from "jsg-nested" and store it as "apiName"
    And I generate a unique API version from "jsg-nested" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-nested" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/customers","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"customer\":{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"object\",\"properties\":{\"city\":{\"type\":\"string\"}},\"required\":[\"city\"]}},\"required\":[\"address\"]}},\"required\":[\"customer\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/customers" with body:
      """
      {"customer":{"address":{"city":"Colombo"}}}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/customers" with body:
      """
      <payload>
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "<field>"
    And the JSON response field "message.assessments[0].description" should be "<description>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                 | payload                             | field                 | description                                    |
      | invalid nested field | {"customer":{"address":{"city":7}}} | customer.address.city | Invalid type. Expected: string, given: integer |
      | invalid structure    | {"customer":{"address":"Colombo"}}  | customer.address      | Invalid type. Expected: object, given: string  |

  Scenario: Validate array of objects
    Given I generate a unique value from "jsg-array-objects" and store it as "apiName"
    And I generate a unique API version from "jsg-array-objects" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-array-objects" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"items\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"productId\":{\"type\":\"string\"},\"quantity\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"productId\",\"quantity\"]}}},\"required\":[\"items\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"items": [{"productId": "123", "quantity": 2}, {"productId": "456", "quantity": 0}]}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Handle empty request body
    Given I generate a unique value from "jsg-empty-body" and store it as "apiName"
    And I generate a unique API version from "jsg-empty-body" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-empty-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\"}},\"required\":[\"data\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The valid body after the malformed one shows the gateway still serves.
  Scenario Outline: Send malformed JSON in the request (<case>)
    Given I generate a unique value from "jsg-malformed-request" and store it as "apiName"
    And I generate a unique API version from "jsg-malformed-request" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-malformed-request" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"<jsonPath>","schema":"{\"type\":\"object\"}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"order":{"name":"Ann"
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "<reason>"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"order":{"name":"Ann"}}
      """
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case          | jsonPath | reason                               |
      | whole payload |          | Error validating schema              |
      | JSONPath      | $.order  | Error extracting value from JSONPath |

  Scenario Outline: Configure an invalid or non-matching JSONPath (<case>)
    Given I generate a unique value from "jsg-bad-jsonpath" and store it as "apiName"
    And I generate a unique API version from "jsg-bad-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-bad-jsonpath" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"<jsonPath>","schema":"{\"type\":\"string\"}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case         | jsonPath              |
      | non-matching | $.prompt              |
      | invalid      | $.messages[x].content |

  Scenario: User registration with comprehensive validation
    Given I generate a unique value from "jsg-registration" and store it as "apiName"
    And I generate a unique API version from "jsg-registration" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-registration" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"username\":{\"type\":\"string\",\"minLength\":3,\"maxLength\":20,\"pattern\":\"^[a-zA-Z0-9_]+$\"},\"email\":{\"type\":\"string\",\"pattern\":\"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\\\\\.[a-zA-Z]{2,}$\"},\"password\":{\"type\":\"string\",\"minLength\":8},\"age\":{\"type\":\"integer\",\"minimum\":13},\"termsAccepted\":{\"type\":\"boolean\",\"enum\":[true]}},\"required\":[\"username\",\"email\",\"password\",\"age\",\"termsAccepted\"]}","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"username": "john_doe", "email": "john@example.com", "password": "SecurePass123", "age": 25, "termsAccepted": true}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"username": "j", "email": "john@example.com", "password": "SecurePass123", "age": 25, "termsAccepted": true}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "username"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Block SQL injection patterns
    Given I generate a unique value from "jsg-sql-injection" and store it as "apiName"
    And I generate a unique API version from "jsg-sql-injection" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-sql-injection" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"pattern\":\".*((DROP\|DELETE\|INSERT\|UPDATE\|SELECT).*(TABLE\|FROM\|WHERE)).*\"}}}","invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"query": "normal search term"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"query": "SELECT * FROM users WHERE id = 1"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: E-commerce order validation
    Given I generate a unique value from "jsg-ecommerce-order" and store it as "apiName"
    And I generate a unique API version from "jsg-ecommerce-order" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-ecommerce-order" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"customerId\":{\"type\":\"string\",\"minLength\":1},\"items\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"productId\":{\"type\":\"string\"},\"quantity\":{\"type\":\"integer\",\"minimum\":1},\"price\":{\"type\":\"number\",\"minimum\":0}},\"required\":[\"productId\",\"quantity\",\"price\"]},\"minItems\":1},\"shippingAddress\":{\"type\":\"object\",\"properties\":{\"street\":{\"type\":\"string\"},\"city\":{\"type\":\"string\"},\"zipCode\":{\"type\":\"string\",\"pattern\":\"^[0-9]{5}$\"}},\"required\":[\"street\",\"city\",\"zipCode\"]},\"paymentMethod\":{\"type\":\"string\",\"enum\":[\"credit_card\",\"paypal\",\"bank_transfer\"]}},\"required\":[\"customerId\",\"items\",\"shippingAddress\",\"paymentMethod\"]}","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"customerId": "C123", "items": [{"productId": "P456", "quantity": 2, "price": 29.99}], "shippingAddress": {"street": "123 Main St", "city": "Boston", "zipCode": "02101"}, "paymentMethod": "credit_card"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"customerId": "C123", "items": [{"productId": "P456", "quantity": 2, "price": 29.99}], "shippingAddress": {"street": "123 Main St", "city": "Boston", "zipCode": "02101"}, "paymentMethod": "cash"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].field" should be "paymentMethod"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # /echo-status requires a status field, which the backend's reflected request never has.
  Scenario: API response contract enforcement
    Given I generate a unique value from "jsg-response-contract" and store it as "apiName"
    And I generate a unique API version from "jsg-response-contract" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-response-contract" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}       |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/echo","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"method\":{\"type\":\"string\"},\"path\":{\"type\":\"string\"},\"headers\":{\"type\":\"object\"}},\"required\":[\"method\",\"path\",\"headers\"]}","showAssessment":true}}}]},{"method":"GET","path":"/echo-status","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"response":{"jsonPath":"","schema":"{\"type\":\"object\",\"required\":[\"status\"]}","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/echo"
    Then the response status code should be 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/echo-status"
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: json-schema-guardrail rejects a request missing a required field
    Given I generate a unique value from "compat-jsg-invalid" and store it as "apiName"
    And I generate a unique API version from "compat-jsg-invalid" and store it as "apiVersion"
    And I generate a unique API context from "/compat-jsg-invalid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"age\":{\"type\":\"integer\"}},\"required\":[\"name\",\"age\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"name": "John Doe"}
      """
    Then the response status code should be 422
    And the response should match the expected error response "json-schema-guardrail-request-invalid"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
