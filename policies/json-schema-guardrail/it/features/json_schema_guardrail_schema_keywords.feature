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
Feature: JSON Schema guardrail policy with schema keywords
  As an API developer
  I want the common JSON Schema keywords enforced on request payloads
  So that required fields, types, constraints and structure are checked

  # JSON Schema keywords on the request body: types, string and number bounds, enums, patterns,
  # arrays, nested objects and additionalProperties, alone and in larger schemas. Every API
  # validates the whole body, and the backend reflects the request as JSON. With showAssessment on,
  # the error names the field and the rule that failed.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Validate data types such as string, number, boolean, object, and array fields (<case>)
    Given I generate a unique value from "jsg-types" and store it as "apiName"
    And I generate a unique API version from "jsg-types" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-types" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/products","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"title\":{\"type\":\"string\"},\"price\":{\"type\":\"number\"},\"inStock\":{\"type\":\"boolean\"},\"dimensions\":{\"type\":\"object\"},\"tags\":{\"type\":\"array\"}},\"required\":[\"title\",\"price\",\"inStock\",\"dimensions\",\"tags\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/products" with body:
      """
      {"title":"Desk","price":120.5,"inStock":true,"dimensions":{"width":120},"tags":["office"]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/products" with body:
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
      | case    | payload                                                                                      | field      | description                                    |
      | string  | {"title":5,"price":120.5,"inStock":true,"dimensions":{"width":120},"tags":["office"]}        | title      | Invalid type. Expected: string, given: integer |
      | number  | {"title":"Desk","price":"120.5","inStock":true,"dimensions":{"width":120},"tags":["office"]} | price      | Invalid type. Expected: number, given: string  |
      | boolean | {"title":"Desk","price":120.5,"inStock":"true","dimensions":{"width":120},"tags":["office"]} | inStock    | Invalid type. Expected: boolean, given: string |
      | object  | {"title":"Desk","price":120.5,"inStock":true,"dimensions":"120x60","tags":["office"]}        | dimensions | Invalid type. Expected: object, given: string  |
      | array   | {"title":"Desk","price":120.5,"inStock":true,"dimensions":{"width":120},"tags":"office"}     | tags       | Invalid type. Expected: array, given: string   |

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

  Scenario: Validate additional/unknown fields when additionalProperties is restricted
    Given I generate a unique value from "jsg-additional" and store it as "apiName"
    And I generate a unique API version from "jsg-additional" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-additional" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/users","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","showAssessment":true,"schema":"{\"type\":\"object\",\"properties\":{\"role\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}},\"additionalProperties\":false}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      {"role":"viewer","name":"Ann"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/users" with body:
      """
      {"role":"viewer","name":"Ann","isAdmin":true}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."
    And the JSON response field "message.assessments[0].description" should be "Additional property isAdmin is not allowed"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

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
