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

@json-xml-mediator
Feature: Json xml mediator policy validation
  As an API developer
  I want an invalid json-xml-mediator configuration to be rejected when the API is created
  So that a misconfigured API never deploys

  # Configurations rejected when the API is created, from the policy's parameter schema: both
  # formats are required, each must be xml or json, and the two must differ. The client's format
  # is spelled downsteamPayloadFormat, as the schema names it; the spelling
  # downstreamPayloadFormat is rejected as an unknown parameter.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Configure the same downstream and upstream format, such as JSON→JSON (<case>)
    Given I generate a unique value from "jxm-same-format" and store it as "apiName"
    And I generate a unique API version from "jxm-same-format" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-same-format" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"<format>","upstreamPayloadFormat":"<format>"}}]}] |
    Then the response status code should be 400
    And the response body should contain "Configuration validation failed"

    Examples:
      | case | format |
      | json | json   |
      | xml  | xml    |

  Scenario Outline: Configure unsupported format values or missing required parameters (<case>)
    Given I generate a unique value from "jxm-bad-config" and store it as "apiName"
    And I generate a unique API version from "jxm-bad-config" and store it as "apiVersion"
    And I generate a unique API context from "/jxm-bad-config" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"POST","path":"/orders","policies":[{"name":"json-xml-mediator","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<param>"

    Examples:
      | case                      | params                                                          | param                  |
      | unsupported value         | {"downsteamPayloadFormat":"json","upstreamPayloadFormat":"yaml"} | upstreamPayloadFormat  |
      | upstream format missing   | {"downsteamPayloadFormat":"json"}                               | upstreamPayloadFormat  |
      | downstream format missing | {"upstreamPayloadFormat":"xml"}                                 | downsteamPayloadFormat |
      | non-string value          | {"downsteamPayloadFormat":"json","upstreamPayloadFormat":1}     | upstreamPayloadFormat  |
