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

@error-response-formatter
Feature: Error response formatter policy
  As an API developer
  I want the error-response-formatter policy to behave as documented
  So that a change to it is caught before it reaches a release

  # Every scenario attaches api-key-auth to /protected and sends no key, so the failure is
  # always the same: api-key-auth's 401 with fault code 900902 and message
  # "Valid API key required". The formatter is attached under faultPolicies and renders it.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: The openai preset renders the failure and leaves a successful response alone
    Given I generate a unique value from "erf-openai" and store it as "apiName"
    And I generate a unique API version from "erf-openai" and store it as "apiVersion"
    And I generate a unique API context from "/erf-openai" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}            |
      | spec.displayName       | ${CTX:apiName}            |
      | spec.version           | ${CTX:apiVersion}         |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000     |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
      | spec.faultPolicies     | [{"name":"error-response-formatter","version":"v1","params":{"preset":"openai"}}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And the JSON response field "error" should not exist

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    Then the response header "Content-Type" should contain "application/json"
    And the JSON response field "error.code" should be "900902"
    And the JSON response field "error.type" should be "authentication_error"
    And the JSON response field "error.message" should be "Valid API key required"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A structured template renders typed values and sets headers from the failure
    Given I generate a unique value from "erf-template" and store it as "apiName"
    And I generate a unique API version from "erf-template" and store it as "apiVersion"
    And I generate a unique API context from "/erf-template" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}            |
      | spec.displayName       | ${CTX:apiName}            |
      | spec.version           | ${CTX:apiVersion}         |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000     |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
      | spec.faultPolicies     | [{"name":"error-response-formatter","version":"v1","params":{"template":{"fault":{"code":"${Code}","kind":"${Type}","detail":"${Message}","policy":"${Policy}"},"status":"${Status}"},"headersToSet":[{"name":"x-error-code","value":"${Code}"}]}}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    Then the JSON response field "fault.code" should be "900902"
    And the JSON response field "fault.kind" should be "authentication"
    And the JSON response field "fault.detail" should be "Valid API key required"
    And the JSON response field "fault.policy" should be "api-key-auth"
    And the JSON response field "status" should be 401
    And the response header "x-error-code" should be "900902"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: The soap11 preset renders a SOAP 1.1 fault
    Given I generate a unique value from "erf-soap" and store it as "apiName"
    And I generate a unique API version from "erf-soap" and store it as "apiVersion"
    And I generate a unique API context from "/erf-soap" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}            |
      | spec.displayName       | ${CTX:apiName}            |
      | spec.version           | ${CTX:apiVersion}         |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000     |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
      | spec.faultPolicies     | [{"name":"error-response-formatter","version":"v1","params":{"preset":"soap11"}}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    Then the response header "Content-Type" should contain "text/xml"
    And the response body should contain "<faultcode>soapenv:Client</faultcode>"
    And the response body should contain "<faultstring>Valid API key required</faultstring>"
    And the response body should contain "<errorcode>900902</errorcode>"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: statusCode changes the status only for the failures its executionCondition selects
    Given I generate a unique value from "erf-status" and store it as "apiName"
    And I generate a unique API version from "erf-status" and store it as "apiVersion"
    And I generate a unique API context from "/erf-status" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}            |
      | spec.displayName       | ${CTX:apiName}            |
      | spec.version           | ${CTX:apiVersion}         |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000     |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
      | spec.faultPolicies     | [{"name":"error-response-formatter","version":"v1","params":{"preset":"canonical"}},{"name":"error-response-formatter","version":"v1","executionCondition":"fault.Code == \"900902\"","params":{"preset":"canonical","statusCode":400}},{"name":"error-response-formatter","version":"v1","executionCondition":"fault.Code == \"900800\"","params":{"preset":"canonical","statusCode":503}}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 400
    Then the JSON response field "code" should be "900902"
    And the JSON response field "type" should be "authentication"
    And the JSON response field "message" should be "Valid API key required"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An invalid template still deploys and leaves the error unformatted
    Given I generate a unique value from "erf-invalid" and store it as "apiName"
    And I generate a unique API version from "erf-invalid" and store it as "apiVersion"
    And I generate a unique API context from "/erf-invalid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}            |
      | spec.displayName       | ${CTX:apiName}            |
      | spec.version           | ${CTX:apiVersion}         |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000     |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"GET","path":"/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}}]}] |
      | spec.faultPolicies     | [{"name":"error-response-formatter","version":"v1","params":{"template":{"error":"${NotAPlaceholder}"}}}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    Then the response body should not contain "NotAPlaceholder"
    And the JSON response field "message" should be "Valid API key required"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
