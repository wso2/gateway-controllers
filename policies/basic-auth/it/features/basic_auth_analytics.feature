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
Feature: Basic auth policy with the gateway's default analytics header capture
  As an API developer
  I want credentials sent to the basic-auth policy to stay out of gateway logs, analytics and errors
  So that a change to it is caught before it reaches a release

  # The gateway here captures no request or response headers for analytics, which is its default.
  # The other feature files run on a gateway that captures every header.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The password ba-log-marker-29 and the wrong one, ba-log-wrong-29, appear in no other scenario, so
  # finding either, or its base64 form, in a gateway log means this scenario's credentials leaked.
  # The collector is cleared before each request, so each analytics check reads that request's event.
  Scenario: Inspect gateway logs, analytics, and error responses after successful and failed authentication attempts
    Given I generate a unique value from "ba-observe" and store it as "apiName"
    And I generate a unique API version from "ba-observe" and store it as "apiVersion"
    And I generate a unique API context from "/ba-observe" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"ba-user","password":"ba-log-marker-29"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 401
    And I wait for the analytics collector to settle
    And I reset the analytics collector

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1sb2ctbWFya2VyLTI5"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 200
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/protected" should have response status 200
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/protected" should not contain request header "authorization"
    And I wait for the analytics collector to settle
    And I reset the analytics collector

    When I clear all headers
    And I set header "Authorization" to "Basic YmEtdXNlcjpiYS1sb2ctd3JvbmctMjk="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And the response should match the expected error response "basic-auth-unauthorized"
    And the response body should not contain "ba-log"
    # The gateway records a request the policy chain rejects under the API's context, without
    # the operation path. If it starts recording the full path, these two checks need /protected.
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have response status 401
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should not contain request header "authorization"
    And I wait for the analytics collector to settle
    And the "gateway-runtime" service logs should not contain "ba-log-marker-29"
    And the "gateway-runtime" service logs should not contain "YmEtdXNlcjpiYS1sb2ctbWFya2VyLTI5"
    And the "gateway-runtime" service logs should not contain "ba-log-wrong-29"
    And the "gateway-runtime" service logs should not contain "YmEtdXNlcjpiYS1sb2ctd3JvbmctMjk="
    And the "gateway-controller" service logs should not contain "ba-log-marker-29"
    And the "gateway-controller" service logs should not contain "YmEtdXNlcjpiYS1sb2ctbWFya2VyLTI5"
    And the "gateway-controller" service logs should not contain "ba-log-wrong-29"
    And the "gateway-controller" service logs should not contain "YmEtdXNlcjpiYS1sb2ctd3JvbmctMjk="

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected" until status 404
