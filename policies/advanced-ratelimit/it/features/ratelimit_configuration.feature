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

@ratelimit-configuration
Feature: Advanced rate limit configuration validation and lifecycle
  As an API developer
  I want an invalid policy configuration to be refused and a changed one to take effect cleanly
  So that a misconfigured quota never reaches traffic

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: An invalid quota configuration is refused at deployment
    Given I generate a unique value from "arl-invalid-config" and store it as "apiName"
    And I generate a unique API version from "arl-invalid-config" and store it as "apiVersion"
    And I generate a unique API context from "/arl-invalid-config" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/limited","policies":[{"name":"advanced-ratelimit","version":"v1","params":<params>}]}] |
    Then the response should be a client error

    Examples:
      | reason                          | params |
      | zero limit                      | {"quotas":[{"limits":[{"limit":0,"duration":"1h"}]}]} |
      | missing duration                | {"quotas":[{"limits":[{"limit":5}]}]} |
      | malformed duration              | {"quotas":[{"limits":[{"limit":5,"duration":"soon"}]}]} |
      | no quotas                       | {"quotas":[]} |
      | header key without a name       | {"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"header"}]}]} |
      | cel key without an expression  | {"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"cel"}]}]} |
      | unknown key type                | {"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"cookie","key":"sid"}]}]} |
      | unsupported match type          | {"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-A","match":{"type":"glob","value":"a*"}}]}]} |
      | status code outside 400-599    | {"quotas":[{"limits":[{"limit":5,"duration":"1h"}]}],"onRateLimitExceeded":{"statusCode":200}} |

  # A pattern that is valid JSON schema but not a valid regular expression is only caught when the
  # policy engine builds the policy. The route must then refuse traffic rather than serve it
  # without the quota.
  Scenario: A match pattern that is not a valid regular expression never leaves the route unthrottled
    Given I generate a unique value from "arl-invalid-regex" and store it as "apiName"
    And I generate a unique API version from "arl-invalid-regex" and store it as "apiVersion"
    And I generate a unique API context from "/arl-invalid-regex" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/limited","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"bad-regex","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-App-ID","match":{"type":"regex","value":"(unclosed"}}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited" until status 500
    Then the response body should not contain "unclosed"
    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 500

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # The documentation requires sources once cost extraction is enabled, but the schema accepts a
  # quota without any and the policy silently charges the default cost.
  @known-issue
  Scenario: Cost extraction that is enabled without any source is refused at deployment
    Given I generate a unique value from "arl-cost-no-sources" and store it as "apiName"
    And I generate a unique API version from "arl-cost-no-sources" and store it as "apiVersion"
    And I generate a unique API context from "/arl-cost-no-sources" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/limited","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"limits":[{"limit":5,"duration":"1h"}],"costExtraction":{"enabled":true}}]}}]}] |
    Then the response should be a client error

  Scenario: Raising a limit takes effect and removing the policy lifts the limit
    Given I generate a unique value from "arl-lifecycle" and store it as "apiName"
    And I generate a unique API version from "arl-lifecycle" and store it as "apiVersion"
    And I generate a unique API context from "/arl-lifecycle" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/limited","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"lifecycle","limits":[{"limit":1,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 429

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/limited"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited" until status 200

    When I send 5 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
