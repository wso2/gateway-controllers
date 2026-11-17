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

@dynamic-endpoint
Feature: Dynamic endpoint routing across gateway replicas
  As an API developer running more than one gateway behind one control plane
  I want every gateway that receives the same API to route to the same named upstream
  So that which gateway answers a request never changes where it goes

  # The API and its named upstreams are created through the control plane (platform-api) and
  # deployed to the first and the second gateway explicitly.
  Background:
    Given the first gateway is running
    And the second gateway is running
    And I authenticate using basic auth as "admin"
    And I generate a unique resource name from "de-multigateway-project" and store it as "projectHandle"
    And I create a project "${CTX:projectHandle}" on the control plane

  # Known failure: the control plane (platform-api) does not accept or keep upstreamDefinitions, so
  # a named upstream never reaches a gateway.
  @known-issue @de-15
  Scenario: Both gateways route each operation to the same configured named upstream
    Given I generate a unique resource name from "de-s15" and store it as "apiHandle"
    And I generate a unique API context from "/de-s15" and store it as "deCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:deCtx}" and named upstream routing
    Then the control plane should keep the named upstreams "upstream-a,upstream-e" of REST API "${CTX:apiHandle}"
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    And I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane

    When I clear all headers
    And I send a "GET" request to the first gateway "${CTX:deCtx}/l15/one" until the JSON field "path" is "/aaa/l15/one"
    And I send a "GET" request to the second gateway "${CTX:deCtx}/l15/one" until the JSON field "path" is "/aaa/l15/one"
    And I send a "GET" request to the first gateway "${CTX:deCtx}/l15/two" until the JSON field "path" is "/eee/l15/two"
    And I send a "GET" request to the second gateway "${CTX:deCtx}/l15/two" until the JSON field "path" is "/eee/l15/two"
    And I send a "GET" request to the first gateway "${CTX:deCtx}/l15/plain" until the JSON field "path" is "/l15/plain"
    And I send a "GET" request to the second gateway "${CTX:deCtx}/l15/plain" until the JSON field "path" is "/l15/plain"

  Scenario: Both gateways serve an operation that selects no named upstream from the main upstream
    Given I generate a unique resource name from "de-main" and store it as "apiHandle"
    And I generate a unique API context from "/de-main" and store it as "deCtx"
    When I create a REST API "${CTX:apiHandle}" via the control plane in project "${CTX:projectHandle}" with context "${CTX:deCtx}" and named upstream routing
    And I deploy the "RestApi" "${CTX:apiHandle}" to the first gateway via the control plane
    And I deploy the "RestApi" "${CTX:apiHandle}" to the second gateway via the control plane

    When I clear all headers
    And I send a "GET" request to the first gateway "${CTX:deCtx}/l15/plain" until the JSON field "path" is "/l15/plain"
    And I send a "GET" request to the second gateway "${CTX:deCtx}/l15/plain" until the JSON field "path" is "/l15/plain"
