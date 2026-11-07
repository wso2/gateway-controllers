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

@aws-authentication
Feature: AWS Authentication policy
  As an API developer
  I want the gateway to sign requests to AWS-hosted backends with AWS Signature Version 4
  So that those backends accept requests proxied through the gateway

  # Signing requests to an AWS-hosted backend: credential types, service and region values,
  # request shapes, other policies, failures and recovery. Rejected configurations, gateway
  # workload credentials, credential timeouts and gateway restarts are in the other
  # aws_authentication_*.feature files.
  #
  # The upstream is the testbench aws service at http://testbench/execute-api/<region>. It verifies
  # each request's SigV4 signature, and reflects a verified request as JSON with its access key ID
  # in the X-Aws-Access-Key-Id response header. It rejects any other request with 403 and an AWS
  # error code, and answers 404 for resources under /nonexistent.
  #
  # Fixture keys are named for their kind: AKIATESTPERMANENT001 and 002 are permanent,
  # AKIATESTRESTRICTED01 may use only /items, ASIATESTTEMPORARY001 is temporary and
  # ASIATESTEXPIRED00001 has expired. STS issues ASIASTS keys valid for 15 seconds. The role
  # testbench-sts-unavailable always fails, testbench-sts-intermittent fails for the first 10
  # seconds of every 20, and testbench-sts-short-lived issues 3-second keys. Every secret, fixture
  # or issued by STS, contains "SecretAccessKey000" and every session token "SessionToken0001", so
  # a response or log without them discloses no secret.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Configure AWS Authentication with valid service, region, and credentials, then invoke the API
    Given I generate a unique value from "aws-auth-valid" and store it as "apiName"
    And I generate a unique API version from "aws-auth-valid" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-valid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"POST","path":"/items"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "service" should be "execute-api"
    And the JSON response field "region" should be "us-east-1"
    And the JSON response field "path" should be "/execute-api/us-east-1/items"

    # SigV4 signs a hash of the body, so a request with a body is accepted only if the body
    # reached the backend unchanged.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"item":"one"}
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "method" should be "POST"
    And the JSON response field "body" should be:
      """
      {"item":"one"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The gateway accepts these configurations. A backend that rejects the signature or the key
  # answers with its own 403. A missing or whitespace-only credential cannot create the policy,
  # so the gateway answers every request with its generic 500 and never forwards it unsigned.
  # Empty credentials, which the gateway rejects outright, are in
  # aws_authentication_validation.feature.
  Scenario Outline: Validate permanent IAM credentials with valid, invalid, missing, and empty access key/secret combinations (<case>)
    Given I generate a unique value from "aws-auth-iam" and store it as "apiName"
    And I generate a unique API version from "aws-auth-iam" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-iam" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key"<credentials>}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status <status>
    Then the response body should contain "<result>"
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

    Examples:
      | case                                 | credentials                                                                                                  | status | result                |
      | valid credentials                    | ,"awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001" | 200    | AKIATESTPERMANENT001  |
      | an invalid secret access key         | ,"awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testWrongSecretAccessKey0000000000000001" | 403    | SignatureDoesNotMatch |
      | an invalid access key ID             | ,"awsAccessKeyID":"AKIATESTUNKNOWN00001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001" | 403    | InvalidClientTokenId  |
      | a missing access key ID              | ,"awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"                                          | 500    | Internal Server Error |
      | a missing secret access key          | ,"awsAccessKeyID":"AKIATESTPERMANENT001"                                                                  | 500    | Internal Server Error |
      | a whitespace-only access key ID      | ,"awsAccessKeyID":"   ","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"                  | 500    | Internal Server Error |
      | a whitespace-only secret access key  | ,"awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"   "                                       | 500    | Internal Server Error |

  # The API configures no credentials, so the gateway signs with whatever the AWS SDK default
  # credential chain resolves in the gateway runtime. Here the runtime has no AWS credentials,
  # so the gateway answers with its own 502 instead of forwarding the request unsigned.
  Scenario: Validate default-credential-chain with valid workload credentials and with no credentials available (no credentials available)
    Given I generate a unique value from "aws-auth-chain" and store it as "apiName"
    And I generate a unique API version from "aws-auth-chain" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-chain" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"default-credential-chain"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 502
    Then the response header "Content-Type" should contain "application/json"
    And the response body should contain "failed to authenticate request to upstream AWS service"
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The backend accepts a temporary access key only together with its own session token, and
  # rejects one whose credentials have expired.
  Scenario Outline: Validate temporary AWS credentials with valid session token, missing token, expired credentials, and refreshed credentials (<case>)
    Given I generate a unique value from "aws-auth-temporary" and store it as "apiName"
    And I generate a unique API version from "aws-auth-temporary" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-temporary" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key"<credentials>}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status <status>
    Then the response body should contain "<result>"
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

    Examples:
      | case                    | credentials                                                                                                                                                          | status | result               |
      | a valid session token   | ,"awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001" | 200    | ASIATESTTEMPORARY001 |
      | a missing session token | ,"awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001"                                                         | 403    | InvalidClientTokenId |
      | expired credentials     | ,"awsAccessKeyID":"ASIATESTEXPIRED00001","awsSecretAccessKey":"testExpiredSecretAccessKey00000000000001","awsSessionToken":"testExpiredSessionToken0001"     | 403    | ExpiredToken         |

  # The gateway obtains temporary credentials from STS AssumeRole and caches them. The testbench
  # STS issues credentials that expire after 15 seconds, so the gateway must request new ones,
  # with a different access key ID, and keep signing successfully once the first ones expire.
  Scenario: Validate temporary AWS credentials with valid session token, missing token, expired credentials, and refreshed credentials (refreshed credentials)
    Given I generate a unique value from "aws-auth-refresh" and store it as "apiName"
    And I generate a unique API version from "aws-auth-refresh" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-refresh" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001","awsRoleARN":"arn:aws:iam::123456789012:role/aws-authentication-it"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"
    And I store the response header "X-Aws-Access-Key-Id" as "firstAccessKeyId"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until header "X-Aws-Access-Key-Id" is not "${CTX:firstAccessKeyId}"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The rotation follows the usual AWS order: the API switches to AKIATESTPERMANENT002 while
  # AKIATESTPERMANENT001 is still active, and AKIATESTPERMANENT001 is deactivated only once the
  # new key is in use. The X-Testbench-Revoked-Access-Keys request header tells the backend to
  # reject that key, so any later request still signed with it fails.
  Scenario: Rotate AWS credentials after successful invocation
    Given I generate a unique value from "aws-auth-rotate" and store it as "apiName"
    And I generate a unique API version from "aws-auth-rotate" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-rotate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT002","awsSecretAccessKey":"testPermanentSecretAccessKey000000000002"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until header "X-Aws-Access-Key-Id" is "AKIATESTPERMANENT002"
    Then the response status code should be 200

    # Deactivate the old key: the header names the key the backend must now reject, and nothing
    # is signed with it. Each request below succeeds only if the gateway signs it with the new
    # key, since one signed with the old key would be rejected with 403. This is how the
    # scenario shows that the old credentials stop working.
    When I set header "X-Testbench-Revoked-Access-Keys" to "AKIATESTPERMANENT001"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT002"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT002"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT002"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The backend's own signing service is execute-api. A signature scoped to any other service
  # is rejected, even when the credentials are valid.
  Scenario Outline: Configure the correct and incorrect AWS service values for the same backend (<case>)
    Given I generate a unique value from "aws-auth-service" and store it as "apiName"
    And I generate a unique API version from "aws-auth-service" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-service" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"<service>","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status <status>
    Then the response body should contain "<result>"
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

    Examples:
      | case              | service     | status | result                                         |
      | correct service   | execute-api | 200    | AKIATESTPERMANENT001                           |
      | incorrect service | lambda      | 403    | Credential should be scoped to correct service |

  # The backend is in us-east-1. A signature scoped to any other region is rejected, even when
  # the credentials are valid.
  Scenario Outline: Configure the correct and incorrect AWS region values and invoke the backend (<case>)
    Given I generate a unique value from "aws-auth-region" and store it as "apiName"
    And I generate a unique API version from "aws-auth-region" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-region" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"<region>","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status <status>
    Then the response body should contain "<result>"
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

    Examples:
      | case             | region    | status | result                                        |
      | matching region  | us-east-1 | 200    | AKIATESTPERMANENT001                          |
      | incorrect region | us-west-2 | 403    | Credential should be scoped to a valid region |

  # The backend moves from us-east-1 to eu-west-1: the upstream is updated first, while the
  # policy still signs for us-east-1, and the policy's region is updated after it.
  Scenario: Move the backend to another AWS region and update the policy accordingly
    Given I generate a unique value from "aws-auth-move" and store it as "apiName"
    And I generate a unique API version from "aws-auth-move" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-move" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "region" should be "us-east-1"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/eu-west-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 403
    Then the response body should contain "Credential should be scoped to a valid region"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/eu-west-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"eu-west-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "region" should be "eu-west-1"
    And the JSON response field "path" should be "/execute-api/eu-west-1/items"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The HTTP method is part of the signed request, so a request signed for any method other than
  # the one the backend receives is rejected with 403.
  Scenario: Invoke GET, POST, PUT, and DELETE operations through the AWS Authentication policy
    Given I generate a unique value from "aws-auth-methods" and store it as "apiName"
    And I generate a unique API version from "aws-auth-methods" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-methods" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"POST","path":"/items"},{"method":"PUT","path":"/items"},{"method":"DELETE","path":"/items"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "method" should be "GET"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"item":"created"}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "method" should be "POST"
    And the JSON response field "body" should be:
      """
      {"item":"created"}
      """

    When I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"item":"replaced"}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "method" should be "PUT"
    And the JSON response field "body" should be:
      """
      {"item":"replaced"}
      """

    When I send a "DELETE" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "method" should be "DELETE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # Each request succeeds only if the backend receives the body unchanged, because the signature
  # covers the body's SHA-256 hash. The X-Amz-Content-Sha256 header checks also show that the
  # gateway signed the hash of this exact payload, not a placeholder such as UNSIGNED-PAYLOAD.
  # Each expected value is the SHA-256 of the body sent; for the empty body it is the hash of
  # zero bytes defined by SigV4.
  #
  # The large payload is 512 KiB: large enough that the gateway receives it in several chunks
  # and must buffer all of them before signing, and well below the gateway's default 1 MiB
  # buffer limit, beyond which the request is rejected before it is signed.
  Scenario: Validate request signing for empty, normal JSON, large, and Unicode/special-character payloads
    Given I generate a unique value from "aws-auth-payload" and store it as "apiName"
    And I generate a unique API version from "aws-auth-payload" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-payload" and store it as "apiContext"
    And I generate a value of 512 KiB of "0123456789abcdefghijklmnopqrstuvwxyz" and store it as "largePayload"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "body" should not exist
    And the response should contain echoed header "X-Amz-Content-Sha256" with value "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"id":42,"name":"widget","tags":["blue","large"],"price":19.99,"active":true}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "body" should be:
      """
      {"id":42,"name":"widget","tags":["blue","large"],"price":19.99,"active":true}
      """
    And the response should contain echoed header "X-Amz-Content-Sha256" with value "5c544736ff731bfd672564a9110a589c169fff1add6a09ef966f88a75f3b24f5"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"data":"${CTX:largePayload}"}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "body" should be:
      """
      {"data":"${CTX:largePayload}"}
      """
    And the response should contain echoed header "X-Amz-Content-Sha256" with value "66c8a93a119cb3b6b5ac2de59fa3cd78cdf46b3925ca75fffd1895f627cc1127"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"greeting":"Grüße, こんにちは, привет 👋","symbols":"<>&'%+=?#;:/@!*()[]{}|^~`\\ \"quoted\""}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "body" should be:
      """
      {"greeting":"Grüße, こんにちは, привет 👋","symbols":"<>&'%+=?#;:/@!*()[]{}|^~`\\ \"quoted\""}
      """
    And the response should contain echoed header "X-Amz-Content-Sha256" with value "93d78f9da6e5c56f2147f85365294a9d2e5753be376e72b159b186907e1a24a3"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # SigV4 signs the path and query string in canonical form: query parameters sorted by name
  # and then by value, and reserved characters percent-encoded. The backend rebuilds that form
  # from the request it receives, so each request succeeds only if the gateway signed the path
  # and query that reached the backend, in whatever order and encoding the client sent them.
  # The query field is the query string exactly as the backend received it.
  Scenario: Validate request signing with query parameters, reordered query parameters, URL encoding, and path parameters
    Given I generate a unique value from "aws-auth-query" and store it as "apiName"
    And I generate a unique API version from "aws-auth-query" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-query" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items/{id}"}]      |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42?b=2&a=1" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "path" should be "/execute-api/us-east-1/items/42"
    And the JSON response field "query" should be "b=2&a=1"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42?a=1&b=2"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "query" should be "a=1&b=2"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42?tag=zeta&tag=alpha&a=1"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "query" should be "tag=zeta&tag=alpha&a=1"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/caf%C3%A9%20menu?q=caf%C3%A9%20au%20lait&filter=a%2Fb%3Dc%2Bd"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "path" should be "/execute-api/us-east-1/items/café menu"
    And the JSON response field "query" should be "q=caf%C3%A9%20au%20lait&filter=a%2Fb%3Dc%2Bd"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42" until status 404

  # The client sends Content-Type, which an AWS service expects with a request, and its own
  # application headers. The gateway signs Content-Type, so SignedHeaders lists it, and forwards
  # the application headers unsigned. The X-Amz-Target operation header is in the next scenario.
  Scenario: Send required AWS headers and custom application headers with the request
    Given I generate a unique value from "aws-auth-headers" and store it as "apiName"
    And I generate a unique API version from "aws-auth-headers" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-headers" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I set header "Content-Type" to "application/json; charset=utf-8"
    And I set header "X-Correlation-Id" to "aws-auth-headers-correlation-1"
    And I set header "X-Custom-Header" to "custom application value"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"item":"one"}
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the response should contain echoed header "Content-Type" with value "application/json; charset=utf-8"
    And the response should contain echoed header "X-Correlation-Id" with value "aws-auth-headers-correlation-1"
    And the response should contain echoed header "X-Custom-Header" with value "custom application value"
    And the JSON response field "headers.Authorization[0]" should contain "AWS4-HMAC-SHA256 Credential=AKIATESTPERMANENT001/"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,"
    And the JSON response field "body" should be:
      """
      {"item":"one"}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404


  # The client also sends X-Amz-Target, the operation header of AWS JSON APIs. SigV4 requires every
  # x-amz-* header to be signed, and the backend rejects a request with an unsigned one with 403
  # AccessDenied. The policy forwards the client's X-Amz-Target unsigned, so this scenario is a
  # known issue until the policy signs it: https://github.com/wso2/api-platform/issues/4096
  @known-issue
  Scenario: Send required AWS headers and custom application headers with the request (X-Amz-Target)
    Given I generate a unique value from "aws-auth-amz-target" and store it as "apiName"
    And I generate a unique API version from "aws-auth-amz-target" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-amz-target" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I set header "Content-Type" to "application/json; charset=utf-8"
    And I set header "X-Amz-Target" to "OrdersService.CreateOrder"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"item":"one"}
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "headers.Authorization[0]" should contain "AWS4-HMAC-SHA256 Credential=AKIATESTPERMANENT001/"
    And the response should contain echoed header "X-Amz-Target" with value "OrdersService.CreateOrder"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target,"
    And the JSON response field "body" should be:
      """
      {"item":"one"}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The policy sets Authorization, X-Amz-Date and, with temporary credentials, X-Amz-Security-Token
  # on every request, so these credentials cover all three headers. The client sends its own
  # value for each: a signature for another access key, a date in 2020 and another session token.
  # The backend must receive only the gateway's value of each header, with no client value next
  # to it; it would reject the client's date as expired and its token as invalid.
  Scenario: Send client-supplied Authorization, X-Amz-Date, or X-Amz-Security-Token headers
    Given I generate a unique value from "aws-auth-spoof" and store it as "apiName"
    And I generate a unique API version from "aws-auth-spoof" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-spoof" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I set header "Authorization" to "AWS4-HMAC-SHA256 Credential=AKIATESTPERMANENT002/20200101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000"
    And I set header "X-Amz-Date" to "20200101T000000Z"
    And I set header "X-Amz-Security-Token" to "clientSuppliedSessionToken"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "ASIATESTTEMPORARY001"
    And the JSON response field "headers.Authorization[0]" should contain "AWS4-HMAC-SHA256 Credential=ASIATESTTEMPORARY001/"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"
    And the JSON response field "headers.X-Amz-Date[0]" should not equal "20200101T000000Z"
    And the response should contain echoed header "X-Amz-Security-Token" with value "testTemporarySessionToken0001"
    And the JSON response field "headers.Authorization[1]" should not exist
    And the JSON response field "headers.X-Amz-Date[1]" should not exist
    And the JSON response field "headers.X-Amz-Security-Token[1]" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # A permanent credential is signed without a session token. SignedHeaders lists the headers
  # the gateway signs. The backend verifies the signature and its credential scope, and accepts
  # X-Amz-Date only within five minutes of its own clock, so a successful request also shows
  # the signature is valid and the date is current. X-Amz-Content-Sha256 is the SHA-256 of the
  # empty GET body.
  Scenario: Verify outbound SigV4 headers for permanent and temporary credentials (permanent credentials)
    Given I generate a unique value from "aws-auth-sigv4-permanent" and store it as "apiName"
    And I generate a unique API version from "aws-auth-sigv4-permanent" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-sigv4-permanent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "headers.Authorization[0]" should contain "AWS4-HMAC-SHA256 Credential=AKIATESTPERMANENT001/"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=host;x-amz-content-sha256;x-amz-date,"
    And the JSON response should have field "headers.X-Amz-Date[0]"
    And the response should contain echoed header "X-Amz-Content-Sha256" with value "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    And the response should not contain echoed header "X-Amz-Security-Token"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # A temporary credential is signed together with its session token, which the gateway sends in
  # X-Amz-Security-Token and lists in SignedHeaders. X-Amz-Content-Sha256 is the SHA-256 of the
  # empty GET body.
  Scenario: Verify outbound SigV4 headers for permanent and temporary credentials (temporary credentials)
    Given I generate a unique value from "aws-auth-sigv4-temporary" and store it as "apiName"
    And I generate a unique API version from "aws-auth-sigv4-temporary" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-sigv4-temporary" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "ASIATESTTEMPORARY001"
    And the JSON response field "headers.Authorization[0]" should contain "AWS4-HMAC-SHA256 Credential=ASIATESTTEMPORARY001/"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"
    And the JSON response should have field "headers.X-Amz-Date[0]"
    And the response should contain echoed header "X-Amz-Content-Sha256" with value "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    And the response should contain echoed header "X-Amz-Security-Token" with value "testTemporarySessionToken0001"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # set-headers replaces the request's Content-Type before the AWS Authentication policy signs
  # it. Header policies run before body policies such as AWS Authentication, so the gateway
  # signs the replaced Content-Type, and the backend accepts the request only if that is the
  # value it receives.
  Scenario: Apply request transformation before AWS Authentication (header transformation)
    Given I generate a unique value from "aws-auth-transform-header" and store it as "apiName"
    And I generate a unique API version from "aws-auth-transform-header" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-transform-header" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"Content-Type","value":"application/vnd.orders+json"}]}}},{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"item":"one"}
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the response should contain echoed header "Content-Type" with value "application/vnd.orders+json"
    And the JSON response field "headers.Authorization[0]" should contain "AWS4-HMAC-SHA256 Credential=AKIATESTPERMANENT001/"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # json-xml-mediator converts the client's XML body to JSON before the AWS Authentication policy
  # signs it, so the backend receives {"order":{"item":"widget","quantity":2}} as
  # application/json. The X-Amz-Content-Sha256 value is the SHA-256 of that converted body, which
  # shows the gateway signed the transformed body rather than the client's XML.
  #
  # The mediator also converts the backend's JSON response to XML for the client, so the
  # backend's reflection of the request is checked in that XML. downsteamPayloadFormat is the
  # parameter name as json-xml-mediator defines it.
  Scenario: Apply request transformation before AWS Authentication (body transformation)
    Given I generate a unique value from "aws-auth-transform-body" and store it as "apiName"
    And I generate a unique API version from "aws-auth-transform-body" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-transform-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}},{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      <order><item>widget</item><quantity>2</quantity></order>
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the response header "Content-Type" should contain "application/xml"
    And the response body should contain "<Content-Type>application/json</Content-Type>"
    And the response body should contain "<X-Amz-Content-Sha256>5937e20fe89f4813cae1f241d71271f9034936f6e86c342f3ac3bc26d528ab21</X-Amz-Content-Sha256>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The gateway runs every policy's request header phase before any policy's request body phase,
  # and the AWS Authentication policy signs in the body phase, so a header policy runs before
  # signing even when it is listed after this policy; only a body policy can change a request
  # after it is signed. json-xml-mediator, listed after the AWS Authentication policy, converts
  # the client's XML body to JSON and replaces Content-Type, both of which the signature covers.
  # The backend rejects the stale signature.
  #
  # The mediator also converts the backend's JSON error to XML for the client, so the error code
  # is checked as text. downsteamPayloadFormat is the parameter name as json-xml-mediator defines
  # it.
  Scenario: Modify signed content or signed headers after AWS Authentication
    Given I generate a unique value from "aws-auth-modify-body" and store it as "apiName"
    And I generate a unique API version from "aws-auth-modify-body" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-modify-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"xml","upstreamPayloadFormat":"json"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I set header "Content-Type" to "application/xml"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 403 with body:
      """
      <order><item>widget</item><quantity>2</quantity></order>
      """
    Then the response body should contain "SignatureDoesNotMatch"
    And the response header "X-Aws-Access-Key-Id" should not exist
    And the response body should not contain "SecretAccessKey000"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The API combines rate limiting (three requests an hour), a header transformation, request
  # logging and AWS Authentication. The first three requests are signed and carry the added
  # header, which the gateway forwards unsigned, and the gateway records them for analytics. The
  # fourth is rejected by the rate limit before it is signed or forwarded, so the backend never
  # answers it.
  #
  # log-message writes each request's headers and body to the gateway runtime log, where the
  # body marker identifies them. No fixture secret appears in that log or in a response.
  Scenario: Configure AWS Authentication with other policies such as rate limiting, logging, analytics, or transformation
    Given I generate a unique value from "aws-auth-policies" and store it as "apiName"
    And I generate a unique API version from "aws-auth-policies" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-policies" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":3,"duration":"1h"}]}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Request-Source","value":"aws-auth-gateway"}]}}},{"name":"log-message","version":"v1","params":{"request":{"payload":true,"headers":true}}},{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"POST","path":"/items"}]          |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"marker":"aws-auth-policies-log-marker"}
      """
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the response should contain echoed header "X-Request-Source" with value "aws-auth-gateway"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,"
    And the JSON response field "body" should be:
      """
      {"marker":"aws-auth-policies-log-marker"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"aws-auth-policies-log-marker"}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"aws-auth-policies-log-marker"}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/items" should have response status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"marker":"aws-auth-policies-log-marker"}
      """
    Then the response status code should be 429
    And the response header "X-Aws-Access-Key-Id" should not exist
    And the response body should not contain "SecretAccessKey000"
    And the "gateway-runtime" service logs should contain "aws-auth-policies-log-marker"
    And the "gateway-runtime" service logs should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The policy is attached to the API, so the gateway signs every operation's requests.
  Scenario: Apply AWS Authentication at API level and operation level (API level)
    Given I generate a unique value from "aws-auth-api-level" and store it as "apiName"
    And I generate a unique API version from "aws-auth-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"GET","path":"/orders"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "path" should be "/execute-api/us-east-1/items"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "path" should be "/execute-api/us-east-1/orders"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The policy is attached to GET /items only. The gateway forwards GET /orders unsigned, which
  # the backend rejects as it would any request without a signature. That request is sent without
  # the scenario's management credentials, which the gateway would otherwise forward in the
  # Authorization header.
  Scenario: Apply AWS Authentication at API level and operation level (operation level)
    Given I generate a unique value from "aws-auth-operation-level" and store it as "apiName"
    And I generate a unique API version from "aws-auth-operation-level" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-operation-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}]},{"method":"GET","path":"/orders"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    And the JSON response field "path" should be "/execute-api/us-east-1/items"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 403
    And the response body should contain "MissingAuthenticationToken"
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The API is deployed without the policy, so the backend rejects its unsigned requests. Each
  # update then adds the policy, changes its access key, and removes it. Every check waits for the
  # update's own outcome, which differs from the previous configuration's, so a stale policy would
  # fail it. Unsigned requests are sent without the scenario's management credentials, which the
  # gateway would otherwise forward in the Authorization header.
  Scenario: Add, remove, or modify AWS Authentication on an already deployed API
    Given I generate a unique value from "aws-auth-redeploy" and store it as "apiName"
    And I generate a unique API version from "aws-auth-redeploy" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-redeploy" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 403
    Then the response body should contain "MissingAuthenticationToken"

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until header "X-Aws-Access-Key-Id" is "AKIATESTPERMANENT001"
    Then the response status code should be 200

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT002","awsSecretAccessKey":"testPermanentSecretAccessKey000000000002"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until header "X-Aws-Access-Key-Id" is "AKIATESTPERMANENT002"
    Then the response status code should be 200

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 403
    Then the response body should contain "MissingAuthenticationToken"
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # AKIATESTRESTRICTED01 is a valid key whose permissions cover only /items, like an IAM policy
  # that allows execute-api:Invoke on that resource alone. The backend verifies a signature
  # before it checks permissions, as AWS does, so the AccessDeniedException for /orders also
  # shows that the request was correctly signed: a bad signature would be rejected with
  # SignatureDoesNotMatch instead.
  Scenario: Invoke using valid AWS credentials that lack permission to access the target resource
    Given I generate a unique value from "aws-auth-denied" and store it as "apiName"
    And I generate a unique API version from "aws-auth-denied" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-denied" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTRESTRICTED01","awsSecretAccessKey":"testRestrictedSecretAccessKey00000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"GET","path":"/orders"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTRESTRICTED01"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 403
    And the response should be valid JSON
    And the JSON response field "code" should be "AccessDeniedException"
    And the response body should contain "is not authorized to perform"
    And the response body should not contain "SecretAccessKey000"
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # A backend failure reaches the client as that failure, without the request's signing
  # material or any configured secret. Invalid credentials are covered by the permanent IAM
  # credentials outline above, which asserts 403 SignatureDoesNotMatch and InvalidClientTokenId
  # and that no secret is disclosed.
  #
  # An upstream that refuses connections (testbench port 1) stands for an AWS service that is
  # unavailable, and the gateway answers 503 itself.
  Scenario: Validate backend-side failures such as unavailable AWS service, invalid/non-existent resource, and invalid credentials (unavailable AWS service)
    Given I generate a unique value from "aws-auth-unavailable" and store it as "apiName"
    And I generate a unique API version from "aws-auth-unavailable" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-unavailable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench:1/execute-api/us-east-1     |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 503
    Then the response body should contain "upstream connect error"
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "Signature="
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The backend has no resources under /nonexistent, so a correctly signed request for one gets
  # the backend's 404 ResourceNotFoundException, passed through. The gateway also answers 404
  # while the API is not yet deployed, so the scenario first waits for /items, which exists, to
  # succeed; that also shows the request for /nonexistent is signed like any other.
  Scenario: Validate backend-side failures such as unavailable AWS service, invalid/non-existent resource, and invalid credentials (non-existent resource)
    Given I generate a unique value from "aws-auth-nonexistent" and store it as "apiName"
    And I generate a unique API version from "aws-auth-nonexistent" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-nonexistent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"GET","path":"/nonexistent"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/nonexistent"
    Then the response status code should be 404
    And the response should be valid JSON
    And the JSON response field "code" should be "ResourceNotFoundException"
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "Signature="
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The clock skew is simulated. Containers share the host's clock, so the gateway's clock
  # cannot be skewed on its own. Instead, the X-Testbench-Signer-Clock-Skew request header makes
  # the backend judge X-Amz-Date as if the gateway's clock ran that far ahead of, or behind, its
  # own. AWS only sees the difference between the two clocks, so the backend decides as AWS
  # would. The gateway's requests are the same throughout; only the backend's judgement changes.
  # The backend accepts a request only while the clocks agree within five minutes, so a
  # 10-minute skew is rejected with RequestExpired. A skew of 0s is a corrected clock, and the
  # gateway signs each request with the time it is sent, so the next request succeeds.
  Scenario Outline: Introduce clock skew on the gateway and then correct the system time (<case>)
    Given I generate a unique value from "aws-auth-clock" and store it as "apiName"
    And I generate a unique API version from "aws-auth-clock" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-clock" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"

    When I set header "X-Testbench-Signer-Clock-Skew" to "<skew>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 403
    And the response body should contain "RequestExpired"
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I set header "X-Testbench-Signer-Clock-Skew" to "0s"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

    Examples:
      | case                 | skew |
      | gateway clock ahead  | 10m  |
      | gateway clock behind | -10m |

  # Each burst sends 100 POST requests at once, each to its own path with its own body. The
  # backend verifies every signature against the path, body and session token it receives, so a
  # request carrying a signature, payload hash or credential computed for another request would
  # be rejected with 403, and every request in a burst must succeed. The gateway signs with
  # temporary credentials from STS AssumeRole, which the testbench STS issues for this role with
  # a 3-second lifetime. The scenario waits for a refresh between the bursts, so the second burst
  # starts with refreshed credentials, and a burst that outlasts its credentials is refreshed
  # while its requests are in flight.
  Scenario: Run high-concurrency traffic with different paths, payloads, and temporary credential refresh
    Given I generate a unique value from "aws-auth-concurrency" and store it as "apiName"
    And I generate a unique API version from "aws-auth-concurrency" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-concurrency" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001","awsRoleARN":"arn:aws:iam::123456789012:role/testbench-sts-short-lived"}}] |
      | spec.operations        | [{"method":"POST","path":"/items/{id}"}]     |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items/0" until status 200 with body:
      """
      {"order":0}
      """
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"
    And I store the response header "X-Aws-Access-Key-Id" as "firstAccessKeyId"
    # Fails unless all 100 requests succeed; a mis-signed request gets 403.
    When I send 100 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/items/{i}" with per-request body:
      """
      {"order":{i},"note":"aws-auth-concurrency-{i}"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items/0" until header "X-Aws-Access-Key-Id" is not "${CTX:firstAccessKeyId}" with body:
      """
      {"order":0}
      """
    Then the response status code should be 200
    And the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"
    # The same check, with the refreshed credentials.
    When I send 100 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/items/{i}" with per-request body:
      """
      {"order":{i},"note":"aws-auth-concurrency-{i}"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/0" until status 404

  # Successful and failed requests, each handled by a different part of the gateway: a request
  # the backend accepts, one it rejects because the access key is deactivated for that request,
  # one the gateway fails because STS is unavailable for its role, one whose policy cannot be
  # created because awsRoleARN is missing, and an API definition the controller rejects. Every
  # API is configured with the temporary credentials and their session token. Neither the
  # responses to these requests and to the rejected definition, nor anything the gateway
  # controller or the gateway runtime (router and policy engine) has logged, contains a
  # configured secret access key or session token. The logs are the whole gateway's, so they
  # also cover the scenarios that ran before this one, including the credentials STS issued.
  #
  # The backend reflects the headers it receives, so a successful response contains the session
  # token the gateway sent upstream, which a real AWS backend does not return. The session token
  # is therefore checked in the failed responses and in the logs.
  Scenario: Inspect gateway/controller/policy logs and client responses for successful and failed requests
    Given I generate a unique value from "aws-auth-exposure" and store it as "apiName"
    And I generate a unique API version from "aws-auth-exposure" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-exposure" and store it as "apiContext"
    And I generate a unique value from "aws-auth-exposure-sts" and store it as "stsApiName"
    And I generate a unique API version from "aws-auth-exposure-sts" and store it as "stsApiVersion"
    And I generate a unique API context from "/aws-auth-exposure-sts" and store it as "stsApiContext"
    And I generate a unique value from "aws-auth-exposure-broken" and store it as "brokenApiName"
    And I generate a unique API version from "aws-auth-exposure-broken" and store it as "brokenApiVersion"
    And I generate a unique API context from "/aws-auth-exposure-broken" and store it as "brokenApiContext"
    And I generate a unique value from "aws-auth-exposure-rejected" and store it as "rejectedApiName"
    And I generate a unique API version from "aws-auth-exposure-rejected" and store it as "rejectedApiVersion"
    And I generate a unique API context from "/aws-auth-exposure-rejected" and store it as "rejectedApiContext"

    # The region is an array, which the policy definition does not allow.
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:rejectedApiName}                       |
      | spec.displayName       | ${CTX:rejectedApiName}                       |
      | spec.version           | ${CTX:rejectedApiVersion}                    |
      | spec.context           | ${CTX:rejectedApiContext}/$version           |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":["us-east-1"],"authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response status code should be 400
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "SessionToken0001"

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:stsApiName}                            |
      | spec.displayName       | ${CTX:stsApiName}                            |
      | spec.version           | ${CTX:stsApiVersion}                         |
      | spec.context           | ${CTX:stsApiContext}/$version                |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001","awsRoleARN":"arn:aws:iam::123456789012:role/testbench-sts-unavailable"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:brokenApiName}                         |
      | spec.displayName       | ${CTX:brokenApiName}                         |
      | spec.version           | ${CTX:brokenApiVersion}                      |
      | spec.context           | ${CTX:brokenApiContext}/$version             |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "ASIATESTTEMPORARY001"
    And the response body should not contain "SecretAccessKey000"

    When I set header "X-Testbench-Revoked-Access-Keys" to "ASIATESTTEMPORARY001"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 403
    And the response body should contain "InvalidClientTokenId"
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "SessionToken0001"

    When I clear all headers
    And I send a "GET" request to "${CTX:stsApiContext}/${CTX:stsApiVersion}/items" until status 502
    Then the response body should contain "failed to authenticate request to upstream AWS service"
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "SessionToken0001"

    When I send a "GET" request to "${CTX:brokenApiContext}/${CTX:brokenApiVersion}/items" until status 500
    Then the response body should contain "Internal Server Error"
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "SessionToken0001"

    Then the "gateway-controller" service logs should not contain "SecretAccessKey000"
    And the "gateway-controller" service logs should not contain "SessionToken0001"
    And the "gateway-runtime" service logs should not contain "SecretAccessKey000"
    And the "gateway-runtime" service logs should not contain "SessionToken0001"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
    When I delete the API "${CTX:stsApiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:stsApiContext}/${CTX:stsApiVersion}/items" until status 404
    When I delete the API "${CTX:brokenApiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:brokenApiContext}/${CTX:brokenApiVersion}/items" until status 404

  # The gateway obtains temporary credentials from STS AssumeRole before it signs, and the
  # testbench STS answers every request to assume this role with 503 ServiceUnavailable. The
  # gateway answers 502 itself instead of forwarding the request unsigned: the backend would
  # reflect a forwarded request with the X-Aws-Access-Key-Id header, or reject an unsigned one
  # with 403. A credential retrieval that times out is in
  # aws_authentication_policy_timeout.feature. A policy that cannot run at all is covered by the
  # permanent IAM credentials outline above: a whitespace-only credential prevents the policy
  # from being created, and the gateway answers every request with its generic 500.
  Scenario: Make credential retrieval or policy execution unavailable or force a timeout (credential retrieval unavailable)
    Given I generate a unique value from "aws-auth-sts-unavailable" and store it as "apiName"
    And I generate a unique API version from "aws-auth-sts-unavailable" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-sts-unavailable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001","awsRoleARN":"arn:aws:iam::123456789012:role/testbench-sts-unavailable"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 502
    Then the response header "Content-Type" should contain "application/json"
    And the response body should contain "failed to authenticate request to upstream AWS service"
    And the response header "X-Aws-Access-Key-Id" should not exist
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The testbench STS is unavailable for this role during the first 10 seconds of every 20, and
  # otherwise issues credentials for it that expire after 3 seconds. The gateway signs with its
  # cached credentials until they expire, so it must refresh them early in each outage; when it
  # cannot, it answers 502 without forwarding the request. Once STS is available again, with no change to the API, the
  # gateway obtains new credentials and signs with them: the request succeeds with an access key
  # ID other than the one used before the outage. Credentials that had expired would be rejected
  # with 403 ExpiredToken.
  Scenario: Restore authentication components after failure
    Given I generate a unique value from "aws-auth-sts-restore" and store it as "apiName"
    And I generate a unique API version from "aws-auth-sts-restore" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-sts-restore" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001","awsRoleARN":"arn:aws:iam::123456789012:role/testbench-sts-intermittent"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"
    And I store the response header "X-Aws-Access-Key-Id" as "accessKeyIdBeforeOutage"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 502
    Then the response body should contain "failed to authenticate request to upstream AWS service"
    And the response header "X-Aws-Access-Key-Id" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"
    And the response header "X-Aws-Access-Key-Id" should not be "${CTX:accessKeyIdBeforeOutage}"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The API is deleted and then created again with the same name, context and version. The first
  # one signs for us-east-1 with temporary credentials and their session token; the second one
  # signs for eu-west-1, where its backend is, with a permanent key and no session token. The
  # first request the second API serves is checked, so anything kept from the deleted API shows
  # at once: its access key ID, its session token, or a signature for us-east-1, which the
  # eu-west-1 backend would reject.
  Scenario: Delete and recreate an API using AWS Authentication
    Given I generate a unique value from "aws-auth-recreate" and store it as "apiName"
    And I generate a unique API version from "aws-auth-recreate" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-recreate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "ASIATESTTEMPORARY001"
    And the response should contain echoed header "X-Amz-Security-Token" with value "testTemporarySessionToken0001"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
    And I wait for the config dump to stop containing a route with base path "${CTX:apiContext}"

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/eu-west-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"eu-west-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT002","awsSecretAccessKey":"testPermanentSecretAccessKey000000000002"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT002"
    And the JSON response field "headers.Authorization[0]" should contain "/eu-west-1/execute-api/aws4_request,"
    And the JSON response field "headers.Authorization[0]" should contain "SignedHeaders=host;x-amz-content-sha256;x-amz-date,"
    And the response should not contain echoed header "X-Amz-Security-Token"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
