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

@basic-auth
Feature: Basic auth policy
  As an API developer
  I want the basic-auth policy to admit only requests with the configured credentials
  So that a change to it is caught before it reaches a release

  # Each API forwards to a capture service that records what reaches it, so a scenario can show a
  # rejected request never reached the backend. Unless a scenario says otherwise, the credentials
  # are ba-user:ba-secret?1 (YmEtdXNlcjpiYS1zZWNyZXQ/MQ==). Rejected configurations, restarts, and
  # the checks of logs and analytics have feature files of their own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The policy forwards the request unchanged, so the backend also receives the client's
  # Authorization header.
  Scenario: Invoke a protected API with a valid username and password
    Given I generate a unique value from "ba-valid" and store it as "apiName"
    And I generate a unique API version from "ba-valid" and store it as "apiVersion"
    And I generate a unique API context from "/ba-valid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    And the JSON response field "path" should be "/${CTX:apiName}/protected"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 200
    And the JSON response field "headers.Authorization[0]" should be "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The response must match the expected error response recorded from the policy
  # (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: Invoke without an Authorization header
    Given I generate a unique value from "ba-no-header" and store it as "apiName"
    And I generate a unique API version from "ba-no-header" and store it as "apiVersion"
    And I generate a unique API context from "/ba-no-header" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The credentials are wrong-user:ba-secret?1.
  Scenario: Invoke with an invalid username
    Given I generate a unique value from "ba-bad-user" and store it as "apiName"
    And I generate a unique API version from "ba-bad-user" and store it as "apiVersion"
    And I generate a unique API context from "/ba-bad-user" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic d3JvbmctdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The credentials are ba-user:wrong-secret.
  Scenario: Invoke with a valid username but incorrect password
    Given I generate a unique value from "ba-bad-pass" and store it as "apiName"
    And I generate a unique API version from "ba-bad-pass" and store it as "apiVersion"
    And I generate a unique API context from "/ba-bad-pass" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The credentials are wrong-user:wrong-secret.
  Scenario: Invoke with both username and password incorrect
    Given I generate a unique value from "ba-bad-both" and store it as "apiName"
    And I generate a unique API version from "ba-bad-both" and store it as "apiVersion"
    And I generate a unique API context from "/ba-bad-both" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic d3JvbmctdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The credentials decode to <decoded>. The configured username and password are never empty, so
  # an empty one cannot match.
  Scenario Outline: Send an empty username or empty password (<case>)
    Given I generate a unique value from "ba-empty-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-empty-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-empty-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic <credentials>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case           | key  | decoded      | credentials      |
      | empty username | user | :ba-secret?1 | OmJhLXNlY3JldD8x |
      | empty password | pass | ba-user:     | YmEtdXNlcjo=     |

  # With allowUnauthenticated, failed authentication still reaches the backend. The credentials
  # decode to :ba-secret?1.
  Scenario: Send an empty username or empty password (allowed by configuration)
    Given I generate a unique value from "ba-empty-allowed" and store it as "apiName"
    And I generate a unique API version from "ba-empty-allowed" and store it as "apiVersion"
    And I generate a unique API context from "/ba-empty-allowed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1","allowUnauthenticated":true}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    When I clear all headers
    And I set header "Authorization" to "Basic OmJhLXNlY3JldD8x"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 200
    And the JSON response field "headers.Authorization[0]" should be "Basic OmJhLXNlY3JldD8x"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  Scenario: Send Authorization: Basic without credential data
    Given I generate a unique value from "ba-no-data" and store it as "apiName"
    And I generate a unique API version from "ba-no-data" and store it as "apiVersion"
    And I generate a unique API context from "/ba-no-data" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  Scenario Outline: Send invalid/non-Base64 credential data (<case>)
    Given I generate a unique value from "ba-bad-b64-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-bad-b64-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-bad-b64-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic <credentials>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case                            | key   | credentials               |
      | characters outside the alphabet | chars | %%%%                      |
      | truncated                       | short | YmEtdXNlcjpiYS1zZWNyZXQ/M |
      | padding only                    | pad   | ====                      |

  # The credentials decode to "ba-user ba-secret?1": no colon separates the username from the password.
  Scenario: Send valid Base64 that does not decode to username:password
    Given I generate a unique value from "ba-no-colon" and store it as "apiName"
    And I generate a unique API version from "ba-no-colon" and store it as "apiVersion"
    And I generate a unique API context from "/ba-no-colon" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlciBiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The credentials are the UTF-8 bytes of <username>:<password>. The policy splits them at the first
  # colon, so a password may contain one.
  Scenario Outline: Verify usernames/passwords containing supported special characters and Unicode (<case>)
    Given I generate a unique value from "ba-chars-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-chars-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-chars-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"<username>","password":"<password>"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic <credentials>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case                               | key     | username | password      | credentials                          |
      | Unicode username                   | unicode | ユーザー-ü   | ba-secret?1   | 44Om44O844K244O8LcO8OmJhLXNlY3JldD8x |
      | special characters in the password | special | ba-user  | p@ss#$%&*()!~ | YmEtdXNlcjpwQHNzIyQlJiooKSF+         |
      | colons in the password             | colon   | ba-user  | ba:secret:1   | YmEtdXNlcjpiYTpzZWNyZXQ6MQ==         |

  # The credentials decode to <decoded>, which differs from the configured ones only in case.
  Scenario Outline: Verify case sensitivity of username and password (<case>)
    Given I generate a unique value from "ba-case-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-case-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-case-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic <credentials>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case                   | key  | decoded             | credentials                  |
      | username in upper case | user | BA-USER:ba-secret?1 | QkEtVVNFUjpiYS1zZWNyZXQ/MQ== |
      | password in upper case | pass | ba-user:BA-SECRET?1 | YmEtdXNlcjpCQS1TRUNSRVQ/MQ== |

  # The request is written to the socket as it is here, so the header name reaches the gateway in
  # this case. HTTP header names are case-insensitive.
  Scenario Outline: Use different casing for the Authorization header name (<case>)
    Given I generate a unique value from "ba-hdr-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-hdr-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-hdr-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" with headers:
      | <header> | Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ== |
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case       | key   | header        |
      | lower case | lower | authorization |
      | upper case | upper | AUTHORIZATION |
      | mixed case | mixed | aUtHoRiZaTiOn |

  # The value after the scheme is the valid Basic credential, so only the scheme is wrong.
  Scenario Outline: Send a different authentication scheme such as Bearer, Digest, or ApiKey (<scheme>)
    Given I generate a unique value from "ba-scheme-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-scheme-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-scheme-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "<scheme> YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | scheme | key    |
      | Bearer | bearer |
      | Digest | digest |
      | ApiKey | apikey |

  # The gateway joins repeated Authorization headers into one comma-separated value before the
  # policy reads it. That value is not valid base64, so the request is rejected whatever the order,
  # even when both headers carry the valid credentials. The other credentials decode to
  # wrong-user:wrong-secret.
  Scenario Outline: Send multiple/conflicting Authorization headers (<case>)
    Given I generate a unique value from "ba-dup-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-dup-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-dup-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" with headers:
      | Authorization | Basic <first>  |
      | Authorization | Basic <second> |
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case                    | key           | first                            | second                           |
      | valid first             | valid-first   | YmEtdXNlcjpiYS1zZWNyZXQ/MQ==     | d3JvbmctdXNlcjp3cm9uZy1zZWNyZXQ= |
      | invalid first           | invalid-first | d3JvbmctdXNlcjp3cm9uZy1zZWNyZXQ= | YmEtdXNlcjpiYS1zZWNyZXQ/MQ==     |
      | valid credentials twice | valid-twice   | YmEtdXNlcjpiYS1zZWNyZXQ/MQ==     | YmEtdXNlcjpiYS1zZWNyZXQ/MQ==     |

  # The policy is attached to the API, so it applies to every operation.
  Scenario: Apply Basic Auth at API level and invoke multiple operations
    Given I generate a unique value from "ba-api-level" and store it as "apiName"
    And I generate a unique API version from "ba-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/ba-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.policies          | [{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"POST","path":"/orders"},{"method":"DELETE","path":"/orders"}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 401

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 401
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    When I clear all headers
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 401
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    When I clear all headers
    And I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 401
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # /open has no policy. /team-a and /team-b each have their own basic-auth configuration, with
  # user-a:secret-a (dXNlci1hOnNlY3JldC1h) and user-b:secret-b (dXNlci1iOnNlY3JldC1i).
  Scenario: Apply Basic Auth only to a selected operation
    Given I generate a unique value from "ba-op-level" and store it as "apiName"
    And I generate a unique API version from "ba-op-level" and store it as "apiVersion"
    And I generate a unique API context from "/ba-op-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/open"},{"method":"GET","path":"/team-a","policies":[{"name":"basic-auth","version":"v1","params":{"username":"user-a","password":"secret-a"}}]},{"method":"GET","path":"/team-b","policies":[{"name":"basic-auth","version":"v1","params":{"username":"user-b","password":"secret-b"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/team-a" until status 401

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/open"
    Then the response status code should be 200
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/team-b"
    Then the response status code should be 401
    When I clear all headers
    And I set header "Authorization" to "Basic dXNlci1hOnNlY3JldC1h"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/team-a"
    Then the response status code should be 200
    When I clear all headers
    And I set header "Authorization" to "Basic dXNlci1hOnNlY3JldC1h"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/team-b"
    Then the response status code should be 401
    When I clear all headers
    And I set header "Authorization" to "Basic dXNlci1iOnNlY3JldC1i"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/team-b"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/open" until status 404

  Scenario Outline: Invoke GET, POST, PUT, PATCH, and DELETE protected operations (<method>)
    Given I generate a unique value from "ba-method-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-method-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-method-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"<method>","path":"/resource","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the JSON response field "method" should be "<method>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 404

    Examples:
      | method | key    |
      | GET    | get    |
      | POST   | post   |
      | PUT    | put    |
      | PATCH  | patch  |
      | DELETE | delete |

  Scenario: Send valid credentials together with request body, query parameters, and custom headers
    Given I generate a unique value from "ba-content" and store it as "apiName"
    And I generate a unique API version from "ba-content" and store it as "apiVersion"
    And I generate a unique API context from "/ba-content" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"POST","path":"/orders","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I set header "X-Custom" to "kept"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?item=book&qty=2" with body:
      """
      {"note":"basic-auth keeps the body"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/orders"
    Then the response status code should be 200
    And the JSON response field "query" should be "item=book&qty=2"
    And the JSON response field "headers.X-Custom[0]" should be "kept"
    And the JSON response field "body" should contain "basic-auth keeps the body"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # basic-auth runs before a rate limit of 2 requests an hour. The rejected requests (wrong
  # password) and the readiness poll never reach the rate limit, so both authenticated requests
  # pass and only the third is limited.
  Scenario: Combine Basic Auth with rate limiting or other downstream policies
    Given I generate a unique value from "ba-ratelimit" and store it as "apiName"
    And I generate a unique API version from "ba-ratelimit" and store it as "apiVersion"
    And I generate a unique API context from "/ba-ratelimit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/limited","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 401
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 401

    When I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited" until status 404

  # set-headers adds X-Policy-Order before or after basic-auth. Either way, a request without
  # credentials is rejected and never reaches the backend, and an authenticated one arrives with the header.
  Scenario Outline: Place another transformation/header policy before or after Basic Auth (<side>)
    Given I generate a unique value from "ba-order-<side>" and store it as "apiName"
    And I generate a unique API version from "ba-order-<side>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-order-<side>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | <operations> |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 200
    And the JSON response field "headers.X-Policy-Order[0]" should be "<side>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | side   | operations                                                                                                                                                                                                                                                            |
      | before | [{"method":"GET","path":"/protected","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Policy-Order","value":"before"}]}}},{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
      | after  | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Policy-Order","value":"after"}]}}}]}]  |

  # The API first answers without credentials. After the update adds basic-auth, the same request is
  # rejected once the change reaches the gateway.
  Scenario: Add Basic Auth to an already deployed unsecured API
    Given I generate a unique value from "ba-add" and store it as "apiName"
    And I generate a unique API version from "ba-add" and store it as "apiVersion"
    And I generate a unique API context from "/ba-add" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected"}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    And the response should match the expected error response "basic-auth-unauthorized"
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The update changes the password to ba-rotated-2 (YmEtdXNlcjpiYS1yb3RhdGVkLTI=). The old
  # credentials stop working and the new ones work.
  Scenario: Remove or update Basic Auth configuration on a deployed API (update)
    Given I generate a unique value from "ba-update" and store it as "apiName"
    And I generate a unique API version from "ba-update" and store it as "apiVersion"
    And I generate a unique API context from "/ba-update" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-rotated-2"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1yb3RhdGVkLTI="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  Scenario: Remove or update Basic Auth configuration on a deployed API (remove)
    Given I generate a unique value from "ba-remove" and store it as "apiName"
    And I generate a unique API version from "ba-remove" and store it as "apiVersion"
    And I generate a unique API context from "/ba-remove" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected"}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # Requests alternate between the valid credentials, a wrong password and an empty header, and each
  # must get its own result. An invalid request that reached the backend would answer 200.
  Scenario: Send concurrent/high-volume requests containing valid and invalid credentials
    Given I generate a unique value from "ba-concurrent" and store it as "apiName"
    And I generate a unique API version from "ba-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/ba-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I send 100 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/protected" alternating the "Authorization" header:
      | Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ== | 200 |
      | Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ= | 401 |
      |                                    | 401 |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The policy itself does not limit attempts: every wrong password is rejected, none reaches the
  # backend, and the gateway keeps serving. The next scenario adds a rate limit in front of it.
  Scenario: Attempt brute-force authentication using repeated incorrect passwords (repeated wrong passwords)
    Given I generate a unique value from "ba-brute" and store it as "apiName"
    And I generate a unique API version from "ba-brute" and store it as "apiVersion"
    And I generate a unique API context from "/ba-brute" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send 50 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204
    When I check the health of all gateway services
    Then all services should report healthy status
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # A rate limit of 3 requests an hour runs before basic-auth, so it counts failed attempts too.
  # After three wrong passwords, even the right one is limited until the window ends.
  Scenario: Attempt brute-force authentication using repeated incorrect passwords (rate limit before authentication)
    Given I generate a unique value from "ba-brute-limited" and store it as "apiName"
    And I generate a unique API version from "ba-brute-limited" and store it as "apiVersion"
    And I generate a unique API context from "/ba-brute-limited" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":3,"duration":"1h"}]}},{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    And I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 429
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  # The value is written to the socket as it is here, with \r, \n, \x00 and \xC3\xA9 as the bytes
  # they name. A line break cannot slip the valid credentials in after wrong ones: the policy
  # rejects the request with 401. A NUL byte makes the gateway close the connection. In every case
  # nothing reaches the backend, and the gateway keeps serving.
  Scenario Outline: Send CRLF, malformed, oversized, or unusual values in the Authorization header (<case>)
    Given I generate a unique value from "ba-malformed-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-malformed-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-malformed-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" with headers:
      | Authorization | Basic <value> |
    Then the gateway should have refused the raw request <refusal>
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204
    When I check the health of all gateway services
    Then all services should report healthy status
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case            | key  | value                                                                               | refusal                   |
      | carriage return | cr   | d3JvbmctdXNlcjp3cm9uZy1zZWNyZXQ=\rAuthorization: Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ== | with status 401           |
      | line feed       | lf   | d3JvbmctdXNlcjp3cm9uZy1zZWNyZXQ=\nAuthorization: Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ== | with status 401           |
      | NUL byte        | nul  | YmEtdXNlcjpiYS1zZWNyZXQ/MQ==\x00                                                    | by closing the connection |
      | non-ASCII bytes | utf8 | \xC3\xA9YmEtdXNlcjpiYS1zZWNyZXQ/MQ==                                                | with status 401           |

  # The padding is valid base64 of a long run of "A" with no colon, so the policy rejects the
  # smaller value. The larger one is over the gateway's header size limit, and the gateway closes
  # the connection without answering.
  Scenario Outline: Send CRLF, malformed, oversized, or unusual values in the Authorization header (<size> KiB value)
    Given I generate a unique value from "ba-oversized-<size>" and store it as "apiName"
    And I generate a unique API version from "ba-oversized-<size>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-oversized-<size>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I generate a value of <size> KiB of "QUFB" and store it as "padding"
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" with headers:
      | Authorization | Basic ${CTX:padding} |
    Then the gateway should have refused the raw request <refusal>
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204
    When I check the health of all gateway services
    Then all services should report healthy status
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | size | refusal                   |
      | 4    | with status 401           |
      | 80   | by closing the connection |

  # Each value carries the valid credentials in a form the policy does not accept: it requires the
  # scheme "Basic" with one space, then standard padded base64. Duplicate Authorization headers have
  # a scenario of their own.
  Scenario Outline: Attempt credential smuggling using duplicate headers, whitespace variations, or unusual Base64 formatting (<case>)
    Given I generate a unique value from "ba-smuggle-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-smuggle-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-smuggle-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "<value>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 204

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

    Examples:
      | case                         | key     | value                                                                  |
      | two spaces after the scheme  | spaces  | Basic  YmEtdXNlcjpiYS1zZWNyZXQ/MQ==                                    |
      | scheme in lower case         | lower   | basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ==                                     |
      | URL-safe alphabet            | urlsafe | Basic YmEtdXNlcjpiYS1zZWNyZXQ_MQ==                                     |
      | padding removed              | nopad   | Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ                                       |
      | space inside the base64      | inner   | Basic YmEtdXNl cjpiYS1zZWNyZXQ/MQ==                                    |
      | two credentials in one value | joined  | Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ==, Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ== |

  # The policy authenticates the same way on both listeners. It does not require TLS: serving
  # Basic Auth only over HTTPS is the operator's choice, as the policy documentation advises.
  Scenario: Invoke the API over unsecured HTTP versus HTTPS where both are technically available
    Given I generate a unique value from "ba-transport" and store it as "apiName"
    And I generate a unique API version from "ba-transport" and store it as "apiVersion"
    And I generate a unique API context from "/ba-transport" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1zZWNyZXQ/MQ=="
    And I send a "GET" request over HTTPS to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request over HTTPS to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  Scenario: A custom realm is returned in the WWW-Authenticate header
    Given I generate a unique value from "ba-realm" and store it as "apiName"
    And I generate a unique API version from "ba-realm" and store it as "apiVersion"
    And I generate a unique API context from "/ba-realm" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1","realm":"Basic Auth IT"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response header "WWW-Authenticate" should match pattern "^Basic realm=\x22Basic Auth IT\x22$"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404

  Scenario: Wrong credentials are forwarded when allowUnauthenticated is true
    Given I generate a unique value from "ba-allow-wrong" and store it as "apiName"
    And I generate a unique API version from "ba-allow-wrong" and store it as "apiVersion"
    And I generate a unique API context from "/ba-allow-wrong" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-secret?1","allowUnauthenticated":true}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 200
    And the response header "WWW-Authenticate" should not exist
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/protected"
    Then the response status code should be 200
    And the JSON response field "headers.Authorization[0]" should be "Basic YmEtdXNlcjp3cm9uZy1zZWNyZXQ="

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404
