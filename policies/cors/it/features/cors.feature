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
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@cors
Feature: CORS policy behavior
  As an API developer
  I want CORS policy decisions to control cross-origin requests
  So that allowed requests receive the correct headers and disallowed requests do not

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"


  Scenario: Preflight request allows configured origin, methods, and headers
    Given I generate a unique value from "cors-1" and store it as "apiName1"
    And I generate a unique API context from "/cors-1" and store it as "apiContext1"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName1}                  |
      | spec.displayName       | CORS Preflight API                |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext1}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com","http://localhost:5000"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Content-Type-Options"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I set header "Access-Control-Request-Method" to "POST"
    And I set header "Access-Control-Request-Headers" to "Content-Type"
    And I send a "OPTIONS" request to "${CTX:apiContext1}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should be "http://example.com"
    And the response header "Access-Control-Allow-Methods" should contain "GET"
    And the response header "Access-Control-Allow-Methods" should contain "POST"
    And the response header "Access-Control-Allow-Headers" should contain "Content-Type"
    When I delete the API "${CTX:apiName1}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/test/test" until status 404


  Scenario: Preflight request fails for disallowed origin
    Given I generate a unique value from "cors-2" and store it as "apiName2"
    And I generate a unique API context from "/cors-2" and store it as "apiContext2"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName2}                  |
      | spec.displayName       | CORS Preflight API                |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext2}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com","http://localhost:5000"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Content-Type-Options"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://evil.com"
    And I set header "Access-Control-Request-Method" to "GET"
    And I set header "Access-Control-Request-Headers" to "Content-Type"
    And I send a "OPTIONS" request to "${CTX:apiContext2}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should not exist
    And the response header "Access-Control-Allow-Methods" should not exist
    And the response header "Access-Control-Allow-Headers" should not exist
    When I delete the API "${CTX:apiName2}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/test/test" until status 404


  Scenario: Preflight request fails for disallowed method
    Given I generate a unique value from "cors-3" and store it as "apiName3"
    And I generate a unique API context from "/cors-3" and store it as "apiContext3"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName3}                  |
      | spec.displayName       | CORS Preflight API                |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext3}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com","http://localhost:5000"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Content-Type-Options"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext3}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I set header "Access-Control-Request-Method" to "PUT"
    And I set header "Access-Control-Request-Headers" to "Content-Type"
    And I send a "OPTIONS" request to "${CTX:apiContext3}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should not exist
    And the response header "Access-Control-Allow-Methods" should not exist
    And the response header "Access-Control-Allow-Headers" should not exist
    When I delete the API "${CTX:apiName3}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext3}/v1.0/test/test" until status 404


  Scenario: Preflight request fails for disallowed header
    Given I generate a unique value from "cors-4" and store it as "apiName4"
    And I generate a unique API context from "/cors-4" and store it as "apiContext4"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName4}                  |
      | spec.displayName       | CORS Preflight API                |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext4}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com","http://localhost:5000"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Content-Type-Options"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I set header "Access-Control-Request-Method" to "GET"
    And I set header "Access-Control-Request-Headers" to "Authorization"
    And I send a "OPTIONS" request to "${CTX:apiContext4}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should not exist
    And the response header "Access-Control-Allow-Methods" should not exist
    And the response header "Access-Control-Allow-Headers" should not exist
    When I delete the API "${CTX:apiName4}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/test/test" until status 404


  Scenario: Simple GET from allowed origin gets CORS response headers
    Given I generate a unique value from "cors-5" and store it as "apiName5"
    And I generate a unique API context from "/cors-5" and store it as "apiContext5"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName5}                  |
      | spec.displayName       | CORS Simple Request API           |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext5}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should be "http://example.com"
    When I delete the API "${CTX:apiName5}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/test/test" until status 404


  Scenario: Simple GET from disallowed origin has upstream CORS headers stripped
    Given I generate a unique value from "cors-6" and store it as "apiName6"
    And I generate a unique API context from "/cors-6" and store it as "apiContext6"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName6}                  |
      | spec.displayName       | CORS Simple Request API           |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext6}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://evil.com"
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should not exist
    When I delete the API "${CTX:apiName6}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/test/test" until status 404


  Scenario: Simple GET without Origin header gets no CORS headers
    Given I generate a unique value from "cors-7" and store it as "apiName7"
    And I generate a unique API context from "/cors-7" and store it as "apiContext7"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName7}                  |
      | spec.displayName       | CORS Simple Request API           |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext7}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext7}/v1.0/test/test" until status 200

    When I send a "GET" request to "${CTX:apiContext7}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should not exist
    When I delete the API "${CTX:apiName7}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext7}/v1.0/test/test" until status 404


  Scenario: Simple GET from allowed origin gets Vary header
    Given I generate a unique value from "cors-8" and store it as "apiName8"
    And I generate a unique API context from "/cors-8" and store it as "apiContext8"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName8}                  |
      | spec.displayName       | CORS Simple Request API           |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext8}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext8}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I send a "GET" request to "${CTX:apiContext8}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Vary" should be "Origin"
    When I delete the API "${CTX:apiName8}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext8}/v1.0/test/test" until status 404


  Scenario: Simple GET from allowed origin gets Allow-Credentials header
    Given I generate a unique value from "cors-9" and store it as "apiName9"
    And I generate a unique API context from "/cors-9" and store it as "apiContext9"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName9}                  |
      | spec.displayName       | CORS Simple Request API           |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext9}/$version      |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext9}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I send a "GET" request to "${CTX:apiContext9}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Credentials" should be "true"
    When I delete the API "${CTX:apiName9}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext9}/v1.0/test/test" until status 404


  Scenario: Simple GET from allowed origin gets Expose-Headers
    Given I generate a unique value from "cors-10" and store it as "apiName10"
    And I generate a unique API context from "/cors-10" and store it as "apiContext10"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName10}                 |
      | spec.displayName       | CORS Simple Request API           |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext10}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext10}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I send a "GET" request to "${CTX:apiContext10}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Expose-Headers" should be "X-Custom-Header"
    When I delete the API "${CTX:apiName10}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext10}/v1.0/test/test" until status 404


  Scenario: Simple GET with wildcard origin gets CORS headers
    Given I generate a unique value from "cors-11" and store it as "apiName11"
    And I generate a unique API context from "/cors-11" and store it as "apiContext11"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName11}                 |
      | spec.displayName       | CORS Simple Wildcard API          |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext11}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["*"],"allowedMethods":["GET","POST"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext11}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://anysite.com"
    And I send a "GET" request to "${CTX:apiContext11}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should be "*"
    When I delete the API "${CTX:apiName11}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext11}/v1.0/test/test" until status 404


  Scenario: Preflight request allows origin matching a Go regex pattern
    Given I generate a unique value from "cors-12" and store it as "apiName12"
    And I generate a unique API context from "/cors-12" and store it as "apiContext12"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName12}                 |
      | spec.displayName       | CORS Regex Preflight API          |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext12}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://*.example.com","http://localhost:[0-9]+"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext12}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://localhost:5173"
    And I set header "Access-Control-Request-Method" to "POST"
    And I set header "Access-Control-Request-Headers" to "Content-Type"
    And I send a "OPTIONS" request to "${CTX:apiContext12}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should be "http://localhost:5173"
    And the response header "Access-Control-Allow-Methods" should contain "POST"
    When I delete the API "${CTX:apiName12}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext12}/v1.0/test/test" until status 404


  Scenario: Simple GET from origin matching a Go regex pattern gets CORS response headers
    Given I generate a unique value from "cors-13" and store it as "apiName13"
    And I generate a unique API context from "/cors-13" and store it as "apiContext13"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName13}                 |
      | spec.displayName       | CORS Regex Simple Request API     |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext13}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://[a-z]+-[0-9]+[.]regex[.]example[.]org"],"allowedMethods":["GET","POST"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/test/test" until status 200

    When I set header "Origin" to "https://qa-1.regex.example.org"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should be "https://qa-1.regex.example.org"
    And the response header "Vary" should contain "Origin"
    When I delete the API "${CTX:apiName13}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/test/test" until status 404


  Scenario: Simple GET from origin not matching a Go regex pattern has upstream CORS headers stripped
    Given I generate a unique value from "cors-14" and store it as "apiName14"
    And I generate a unique API context from "/cors-14" and store it as "apiContext14"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName14}                 |
      | spec.displayName       | CORS Regex Simple Request API     |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext14}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","https://[a-z]+-[0-9]+[.]regex[.]example[.]org"],"allowedMethods":["GET","POST"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext14}/v1.0/test/test" until status 200

    When I set header "Origin" to "https://qa-1.regex.example.org.evil.io"
    And I send a "GET" request to "${CTX:apiContext14}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should not exist
    When I delete the API "${CTX:apiName14}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext14}/v1.0/test/test" until status 404


  # Restores the regex preflight case removed from the api-platform suite by wso2/api-platform#2787.
  # The "\\\\." in the table cell reaches the policy as "\." (Gherkin unescapes "\\" to "\", then YAML
  # unescapes "\\" to "\"), which also exercises a backslash-escaped regex surviving API deployment.
  Scenario: Preflight request allows configured origin based on regex
    Given I generate a unique value from "cors-15" and store it as "apiName15"
    And I generate a unique API context from "/cors-15" and store it as "apiContext15"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName15}                 |
      | spec.displayName       | CORS Regex Preflight API          |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext15}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","^https://[^.]+\\\\.example\\\\.com$","http://localhost:5000"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Content-Type-Options"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext15}/v1.0/test/test" until status 200

    When I set header "Origin" to "https://app.example.com"
    And I set header "Access-Control-Request-Method" to "GET"
    And I set header "Access-Control-Request-Headers" to "Content-Type"
    And I send a "OPTIONS" request to "${CTX:apiContext15}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should be "https://app.example.com"
    And the response header "Access-Control-Allow-Methods" should contain "GET"
    And the response header "Access-Control-Allow-Methods" should contain "POST"
    And the response header "Access-Control-Allow-Headers" should contain "Content-Type"
    When I delete the API "${CTX:apiName15}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext15}/v1.0/test/test" until status 404


  # Restores the regex simple-request case removed from the api-platform suite by wso2/api-platform#2787.
  Scenario: Simple GET matching regex origin gets CORS headers
    Given I generate a unique value from "cors-16" and store it as "apiName16"
    And I generate a unique API context from "/cors-16" and store it as "apiContext16"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName16}                 |
      | spec.displayName       | CORS Regex Simple Request API     |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext16}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","^https://[^.]+\\\\.example\\\\.com$"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Custom-Header"],"allowCredentials":true}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext16}/v1.0/test/test" until status 200

    When I set header "Origin" to "https://app.example.com"
    And I send a "GET" request to "${CTX:apiContext16}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should be "https://app.example.com"
    And the response header "Vary" should contain "Origin"
    And the response header "Access-Control-Allow-Credentials" should be "true"
    And the response header "Access-Control-Expose-Headers" should be "X-Custom-Header"
    When I delete the API "${CTX:apiName16}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext16}/v1.0/test/test" until status 404


  # Guards against the regex being mangled on its way to the policy: if "\." arrived as ".", the
  # origin below would be allowed; if it arrived as "\\.", no subdomain would match at all.
  Scenario: Preflight request fails for origin that only matches when regex escapes are lost
    Given I generate a unique value from "cors-17" and store it as "apiName17"
    And I generate a unique API context from "/cors-17" and store it as "apiContext17"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName17}                 |
      | spec.displayName       | CORS Regex Preflight API          |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext17}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["http://example.com","^https://[^.]+\\\\.example\\\\.com$","http://localhost:5000"],"allowedMethods":["GET","POST"],"allowedHeaders":["Content-Type"],"exposedHeaders":["X-Content-Type-Options"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"},{"method":"GET","path":"/alerts/active"},{"method":"OPTIONS","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext17}/v1.0/test/test" until status 200

    When I set header "Origin" to "https://appXexample.com"
    And I set header "Access-Control-Request-Method" to "GET"
    And I set header "Access-Control-Request-Headers" to "Content-Type"
    And I send a "OPTIONS" request to "${CTX:apiContext17}/v1.0/us/seattle"
    Then the response status code should be 204
    And the response header "Access-Control-Allow-Origin" should not exist
    And the response header "Access-Control-Allow-Methods" should not exist
    And the response header "Access-Control-Allow-Headers" should not exist
    When I delete the API "${CTX:apiName17}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext17}/v1.0/test/test" until status 404


  # A value that looks like a regex but does not compile was accepted as an exact origin by v1.0.2.
  # The API must still deploy and serve the other configured origins.
  Scenario: API with an invalid regex origin still deploys and serves its other origins
    Given I generate a unique value from "cors-18" and store it as "apiName18"
    And I generate a unique API context from "/cors-18" and store it as "apiContext18"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName18}                 |
      | spec.displayName       | CORS Invalid Regex API            |
      | spec.version           | v1.0                              |
      | spec.context           | ${CTX:apiContext18}/$version     |
      | spec.upstream.main.url | http://testbench:3000/api/v1     |
      | spec.policies          | [{"name":"cors","version":"v1","params":{"allowedOrigins":["https://(broken.example.com","http://example.com"],"allowedMethods":["GET","POST"]}}] |
      | spec.operations        | [{"method":"GET","path":"/{country_code}/{city}"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/test/test" until status 200

    When I set header "Origin" to "http://example.com"
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/us/seattle"
    Then the response status code should be 200
    And the response header "Access-Control-Allow-Origin" should be "http://example.com"
    When I delete the API "${CTX:apiName18}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/test/test" until status 404
