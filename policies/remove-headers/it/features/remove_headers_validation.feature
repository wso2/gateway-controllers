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

@remove-headers
Feature: Remove headers policy validation
  As an API developer
  I want an invalid header removal configuration rejected when the API is created
  So that headers the backend or the client must not see never reach them

  # The gateway checks the policy's parameters against its schema when the API is created: at
  # least one of request and response is required, each needs a headers array of objects, and
  # each name is a string of 1 to 256 letters, digits, hyphens and underscores.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RH24: A configuration the schema rejects (no request or response, no header list, or a
  # parameter of the wrong type) fails with 400 and no API is created. An empty header list is
  # valid under the schema, so the API is created and serves traffic with every header unchanged.
  # In both cases the API ends up deleted, so its route returns 404.
  Scenario Outline: Reject or safely handle an empty, missing or mistyped header list (<case>)
    Given I generate a unique value from "rh-invalid-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-invalid-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-invalid-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.policies          | [{"name":"remove-headers","version":"v1","params":<params>}] |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the response status code should be <createStatus>
    And the response body should contain "<detail>"

    When I get the API "${CTX:apiName}"
    Then the response status should be <getStatus>

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status <trafficStatus>

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response status should be <deleteStatus>
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples: safely handled
      | case              | key        | params                     | createStatus | detail  | getStatus | trafficStatus | deleteStatus |
      | empty header list | empty-list | {"request":{"headers":[]}} | 201          | RestApi | 200       | 200           | 200          |

    Examples: rejected
      | case                          | key       | params                                                             | createStatus | detail                                   | getStatus | trafficStatus | deleteStatus |
      | missing request and response  | missing   | {}                                                                 | 400          | spec.policies[0].params                  | 404       | 404           | 404          |
      | missing header list           | no-list   | {"request":{}}                                                     | 400          | spec.policies[0].params.request          | 404       | 404           | 404          |
      | header list of the wrong type | list-type | {"response":{"headers":"X-Internal-Token"}}                        | 400          | spec.policies[0].params.response.headers | 404       | 404           | 404          |
      | header name of the wrong type | name-type | {"request":{"headers":[{"name":123}]}}                             | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | unknown parameter             | unknown   | {"request":{"headers":[{"name":"X-Internal-Token"}],"mode":"all"}} | 400          | spec.policies[0].params.request          | 404       | 404           | 404          |

  # RH25: A header name must be 1 to 256 letters, digits, hyphens and underscores. A malformed
  # name is rejected when the API is created, and no API is created.
  Scenario Outline: Reject a malformed header name (<case>)
    Given I generate a unique value from "rh-invalid-name-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-invalid-name-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-invalid-name-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.policies          | [{"name":"remove-headers","version":"v1","params":<params>}] |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the response status code should be 400
    And the JSON response field "status" should be "error"
    And the JSON response field "message" should be "Configuration validation failed"
    And the response body should contain "<field>"

    When I get the API "${CTX:apiName}"
    Then the response status should be 404

    Examples:
      | case                            | key      | params                                                                                                                                                                                                                                                                                                  | field                                    |
      | empty name                      | empty    | {"request":{"headers":[{"name":""}]}}                                                                                                                                                                                                                                                                   | spec.policies[0].params.request.headers  |
      | name with a space               | space    | {"request":{"headers":[{"name":"X Internal Token"}]}}                                                                                                                                                                                                                                                   | spec.policies[0].params.request.headers  |
      | name with a colon               | colon    | {"request":{"headers":[{"name":"X-Internal-Token:"}]}}                                                                                                                                                                                                                                                  | spec.policies[0].params.request.headers  |
      | name longer than 256 characters | too-long | {"response":{"headers":[{"name":"X-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}} | spec.policies[0].params.response.headers |
