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

@set-headers
Feature: Set headers policy validation
  As an API developer
  I want an invalid set-headers configuration rejected when the API is created
  So that the backend and the client receive exactly the headers the API defines

  # The gateway checks the policy's parameters against its schema when the API is created: at
  # least one of request and response is required, each needs a headers array of objects with a
  # name and a value, each name is 1 to 256 letters, digits, hyphens and underscores, each value
  # is at most 8192 characters, and mode is "set" or "append".

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # SH25: A configuration the schema rejects (no request or response, no header list, a missing or
  # mistyped name or value, a malformed name, a value over 8192 characters, an unknown mode or an
  # unknown parameter) fails with 400 and no API is created. An empty header list is valid under
  # the schema, so the API is created and serves traffic unchanged. In both cases the API ends up
  # deleted, so its route returns 404.
  Scenario Outline: Reject or safely handle an invalid set-headers configuration (<case>)
    Given I generate a unique value from "sh-invalid-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-invalid-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-invalid-<key>" and store it as "apiContext"
    And I generate a value of 9 KiB of "QUFB" and store it as "padding"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.policies          | [{"name":"set-headers","version":"v1","params":<params>}] |
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
      | case                              | key        | params                                                                                    | createStatus | detail                                   | getStatus | trafficStatus | deleteStatus |
      | missing request and response      | missing    | {}                                                                                        | 400          | spec.policies[0].params                  | 404       | 404           | 404          |
      | missing header list               | no-list    | {"request":{}}                                                                            | 400          | spec.policies[0].params.request          | 404       | 404           | 404          |
      | header list of the wrong type     | list-type  | {"response":{"headers":"X-Gateway-Response"}}                                             | 400          | spec.policies[0].params.response.headers | 404       | 404           | 404          |
      | missing header name               | no-name    | {"request":{"headers":[{"value":"tenant-a"}]}}                                            | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | missing header value              | no-value   | {"request":{"headers":[{"name":"X-Gateway-Tenant"}]}}                                     | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | header name of the wrong type     | name-type  | {"request":{"headers":[{"name":123,"value":"tenant-a"}]}}                                 | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | header value of the wrong type    | value-type | {"request":{"headers":[{"name":"X-Gateway-Tenant","value":5}]}}                           | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | malformed header name             | bad-name   | {"request":{"headers":[{"name":"X Gateway Tenant","value":"tenant-a"}]}}                  | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | header value over 8192 characters | long-value | {"request":{"headers":[{"name":"X-Gateway-Tenant","value":"${CTX:padding}"}]}}            | 400          | spec.policies[0].params.request.headers  | 404       | 404           | 404          |
      | unknown mode                      | bad-mode   | {"mode":"replace","request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]}} | 400          | spec.policies[0].params.mode             | 404       | 404           | 404          |
      | unknown parameter                 | unknown    | {"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}],"extra":true}}     | 400          | spec.policies[0].params.request          | 404       | 404           | 404          |
