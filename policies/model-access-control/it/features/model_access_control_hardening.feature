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

@model-access-control-hardening
Feature: Model access control cannot be bypassed by the shape of a request
  As an API developer
  I want every request that names a model checked, however the client writes it
  So that no request reaches the provider with a model the rule does not permit

  Each scenario sends requests that an upstream parser could read differently from the policy:
  a JSON body under another content type, form fields in another case or behind another
  separator, repeated keys, control characters and over-long names. The providers forward to the
  capture service, and a 204 from its read-back proves that none of them reached the provider.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A JSON body is checked whatever content type the client gives it
    Given I generate a unique resource name from "mac-ctype-provider" and store it as "providerName"
    And I generate a unique value from "mac-ctype-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-ctype-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-ctype-provider" and store it as "providerContext"
    # skip is the easiest attachment to slip past: whatever the policy does not take for a model
    # request is forwarded.
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"],"onMissingModel":"skip"}}}]}] |
    Then the response status code should be 201

    When I set header "Content-Type" to "application/x-www-form-urlencoded"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 404 and the response body contains "model_not_found" with body:
      """
      {"model":"unlisted-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I set header "Content-Type" to "application/octet-stream"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
         {"model":"unlisted-model","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I set header "Content-Type" to "multipart/form-data; boundary=b"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"unlisted-model","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"unlisted-model","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    # JSON a lenient parser accepts but a strict one does not: never skipped.
    When I set header "Content-Type" to "application/octet-stream"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"unlisted-model","messages":[],}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # Text the policy cannot read is not skipped either: an upstream might find a model in it.
    When I set header "Content-Type" to "text/plain"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      use the unlisted-model model
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    # A permitted model under an unusual content type is forwarded byte for byte.
    When I set header "Content-Type" to "application/octet-stream"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the JSON response field "body" should be:
      """
      {"model":"gpt-4o","messages":[]}
      """

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Form and multipart bodies are checked, and any field a parser could read as the model counts
    Given I generate a unique resource name from "mac-form-provider" and store it as "providerName"
    And I generate a unique value from "mac-form-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-form-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-form-provider" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/audio/transcriptions","methods":["POST"],"params":{"access":{"mode":"allow","models":["whisper-1"],"onMissingModel":"skip"},"fallback":{"mappingPatterns":[{"fromPattern":"whisper-large","to":"whisper-1"}]}}}]}] |
    Then the response status code should be 201

    When I set header "Content-Type" to "application/x-www-form-urlencoded"
    And I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" until status 404 and the response body contains "model_not_found" with body:
      """
      model=unlisted-model&language=en
      """
    Then the response should match the expected error response "model-access-control-denied"

    # A field name in another case is the model to a case-insensitive form binder.
    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      MODEL=unlisted-model
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # Some parsers also split pairs on a semicolon.
    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      language=en;model=unlisted-model
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      model=whisper-1&model=unlisted-model
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I set header "Content-Type" to "multipart/form-data; boundary=mac-b"
    And I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      --mac-b
      Content-Disposition: form-data; name="model"

      unlisted-model
      --mac-b--
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      --mac-b
      Content-Disposition: form-data; name="model"

      whisper-1
      --mac-b
      Content-Disposition: form-data; name="Model"

      unlisted-model
      --mac-b--
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # Parsers disagree on a part with its name given twice, so no reading of it is trusted.
    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      --mac-b
      Content-Disposition: form-data; name="file"; name="model"

      unlisted-model
      --mac-b--
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # A decoder would read "unlisted-model" from this quoted-printable part.
    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      --mac-b
      Content-Disposition: form-data; name="model"
      Content-Transfer-Encoding: quoted-printable

      =75nlisted-model
      --mac-b--
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/audio/transcriptions"
    Then the response status code should be 204

    # A mapped model is rewritten in its part; the file part reaches the provider unchanged.
    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      --mac-b
      Content-Disposition: form-data; name="file"; filename="clip.wav"
      Content-Type: audio/wav

      RIFF-mac-audio-bytes
      --mac-b
      Content-Disposition: form-data; name="model"

      whisper-large
      --mac-b--
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/audio/transcriptions"
    Then the response status code should be 200
    And the response body should contain "whisper-1"
    And the response body should contain "RIFF-mac-audio-bytes"
    And the response body should not contain "whisper-large"

    # A form without a model field, such as a file upload, is skipped.
    When I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      --mac-b
      Content-Disposition: form-data; name="purpose"

      batch
      --mac-b--
      """
    Then the response status code should be 200

    When I set header "Content-Type" to "application/x-www-form-urlencoded"
    And I send a "POST" request to "${CTX:providerContext}/audio/transcriptions" with body:
      """
      model=whisper-1&language=en
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/audio/transcriptions"
    Then the JSON response field "body" should be "model=whisper-1&language=en"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Repeated keys, control characters and over-long names cannot slip past a deny list
    Given I generate a unique resource name from "mac-deny-provider" and store it as "providerName"
    And I generate a unique value from "mac-deny-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-deny-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-deny-provider" and store it as "providerContext"
    And I generate a value of 2 KiB of "a" and store it as "longModel"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"deny","models":["gpt-4-32k"],"modelPatterns":[".*-preview"]}}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 404 and the response body contains "model_not_found" with body:
      """
      {"model":"  GPT-4-32K\t","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    # Model patterns ignore case too.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"GPT-5-PREVIEW","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    # The key written with an escape is still the model key.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4-32k","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","MODEL":"gpt-4-32k","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","model":"gpt-4-32k","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # A name no list holds, but an upstream that strips the NUL reads the denied model.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4-32k\u0000","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"${CTX:longModel}","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      [{"model":"gpt-4-32k","messages":[]}]
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o"}{"model":"gpt-4-32k"}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4-32k-turbo","messages":[]}
      """
    Then the response status code should be 200

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A query parameter or header cannot carry a second model past the policy
    Given I generate a unique resource name from "mac-qh-query-template" and store it as "queryTemplateName"
    And I generate a unique value from "mac-qh-query-template" and store it as "queryTemplateDisplayName"
    And I generate a unique resource name from "mac-qh-header-template" and store it as "headerTemplateName"
    And I generate a unique value from "mac-qh-header-template" and store it as "headerTemplateDisplayName"
    And I generate a unique resource name from "mac-qh-query-provider" and store it as "queryProviderName"
    And I generate a unique value from "mac-qh-query-provider" and store it as "queryProviderDisplayName"
    And I generate a unique API version from "mac-qh-query-provider" and store it as "queryProviderVersion"
    And I generate a unique API context from "/mac-qh-query-provider" and store it as "queryProviderContext"
    And I generate a unique resource name from "mac-qh-header-provider" and store it as "headerProviderName"
    And I generate a unique value from "mac-qh-header-provider" and store it as "headerProviderDisplayName"
    And I generate a unique API version from "mac-qh-header-provider" and store it as "headerProviderVersion"
    And I generate a unique API context from "/mac-qh-header-provider" and store it as "headerProviderContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion}                      |
      | name              | ${CTX:queryTemplateName}                       |
      | displayName       | ${CTX:queryTemplateDisplayName}                |
      | spec.requestModel | {"location":"queryParam","identifier":"model"} |
    Then the response status code should be 201
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion}                         |
      | name              | ${CTX:headerTemplateName}                         |
      | displayName       | ${CTX:headerTemplateDisplayName}                  |
      | spec.requestModel | {"location":"header","identifier":"x-model-name"} |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                       |
      | name               | ${CTX:queryProviderName}                        |
      | displayName        | ${CTX:queryProviderDisplayName}                 |
      | version            | ${CTX:queryProviderVersion}                     |
      | template           | ${CTX:queryTemplateName}                        |
      | spec.context       | ${CTX:queryProviderContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:queryProviderName} |
      | accessControl.mode | allow_all                                       |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"],"onMissingModel":"skip"}}}]}] |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                        |
      | name               | ${CTX:headerProviderName}                        |
      | displayName        | ${CTX:headerProviderDisplayName}                 |
      | version            | ${CTX:headerProviderVersion}                     |
      | template           | ${CTX:headerTemplateName}                        |
      | spec.context       | ${CTX:headerProviderContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:headerProviderName} |
      | accessControl.mode | allow_all                                        |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"deny","models":["gpt-4-32k"]}}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:queryProviderContext}/chat/completions?model=unlisted-model" until status 404 and the response body contains "model_not_found" with body:
      """
      {"messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    # Each of these is a second model to some query parser, so none of them is skipped.
    When I send a "POST" request to "${CTX:queryProviderContext}/chat/completions?model=gpt-4o&MODEL=unlisted-model" with body:
      """
      {"messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"
    When I send a "POST" request to "${CTX:queryProviderContext}/chat/completions?model=gpt-4o;model=unlisted-model" with body:
      """
      {"messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"
    When I send a "POST" request to "${CTX:queryProviderContext}/chat/completions?Model=unlisted-model" with body:
      """
      {"messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"
    When I send a "POST" request to "${CTX:queryProviderContext}/chat/completions?model%5B%5D=unlisted-model" with body:
      """
      {"messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:queryProviderName}/chat/completions"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:queryProviderContext}/chat/completions?model=gpt-4o&api-version=1" with body:
      """
      {"messages":[]}
      """
    Then the response status code should be 200
    And the JSON response field "query" should be "model=gpt-4o&api-version=1"

    # A proxy in front may join two model headers into one value with a comma.
    When I set header "x-model-name" to "gpt-4o, gpt-4-32k"
    And I send a "POST" request to "${CTX:headerProviderContext}/chat/completions" until status 400 with body:
      """
      {"messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:headerProviderName}/chat/completions"
    Then the response status code should be 204

    When I set header "x-model-name" to "gpt-4o"
    And I send a "POST" request to "${CTX:headerProviderContext}/chat/completions" with body:
      """
      {"messages":[]}
      """
    Then the response status code should be 200
    And the response should contain echoed header "x-model-name" with value "gpt-4o"

    When I delete the LLM provider "${CTX:queryProviderName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:headerProviderName}"
    Then the response should be successful
    When I delete the LLM provider template "${CTX:queryTemplateName}"
    Then the response should be successful
    When I delete the LLM provider template "${CTX:headerTemplateName}"
    Then the response should be successful
