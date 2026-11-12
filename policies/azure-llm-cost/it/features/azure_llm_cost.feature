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

@azure-llm-cost
Feature: Azure LLM Cost policy
  As an API developer
  I want each Azure OpenAI and Azure AI Foundry call priced from the model and tier it really used
  So that cost-aware policies and analytics see what the call cost

  # Costs follow from the test rates in overlays/pricing/model_prices.json. The LLM mock answers
  # each request with the reply named in its x_testbench_reply field.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The gateway's pricing file holds azure/broken-entry, whose input rate is a string. The policy skips
  # that entry when it loads the file and keeps the rest, so the gateway starts and prices normally.
  # azure/gpt-4.1: 1000 input x 0.000002 + 500 output x 0.000008 = 0.006
  Scenario: Supply a pricing file where some azure/ entries are structurally invalid
    Given I generate a unique resource name from "alc-invalid-entry" and store it as "providerName"
    And I generate a unique value from "alc-invalid-entry" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-invalid-entry" and store it as "providerVersion"
    And I generate a unique API context from "/alc-invalid-entry" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-41","model":"gpt-4.1"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/valid/chat/completions" with body:
      """
      {"model":"chat-41","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"model":"gpt-4.1","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"model":"gpt-4.1","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/valid/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/valid/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/valid/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/valid/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"
    # The skipped entry was never loaded, so a response naming it goes unpriced.

    When I send a "POST" request to "${CTX:providerContext}/scripted/broken/chat/completions" with body:
      """
      {"model":"broken-entry","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"model":"broken-entry","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"model":"broken-entry","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/broken/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"
    And the "gateway-runtime" service logs should contain "skipping invalid pricing entry"
    And the "gateway-runtime" service logs should contain "azure/broken-entry"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # A whitespace-only deployment passes the schema's minLength, so the policy's own check rejects it
  # when the gateway builds the route's policy chain. The gateway skips that route only, and answers
  # its requests with its generic error. The schema cases are in azure_llm_cost_validation.feature.
  Scenario: Configure modelMappings as a non-array, with a non-object entry, or with a blank/missing deployment or model (whitespace-only deployment)
    Given I generate a unique resource name from "alc-blank-deploy" and store it as "providerName"
    And I generate a unique value from "alc-blank-deploy" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-blank-deploy" and store it as "providerVersion"
    And I generate a unique API context from "/alc-blank-deploy" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"   ","model":"gpt-4o"}]}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" until status 500 with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"model":"gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response body should be:
      """
      {"error":"Internal Server Error"}
      """
    And the response header "X-Testbench-Scripted" should not exist
    And the "gateway-runtime" service logs should contain "invalid modelMappings: entry 1: both 'deployment' and 'model' are required"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" until status 404

  # The mapping's deployment carries spaces and capitals and its model carries spaces; the request
  # names the deployment in capitals, and the response names no model. The policy trims and
  # lowercases the deployment and trims the model, so the request still resolves through the
  # mapping, and the region picks the tier entry. With no tier entry for global-standard, Global
  # Standard bills the base azure/ rate.
  # Rates for 1000 input and 500 output tokens: base 0.000001/0.000004 = 0.003; us 0.000002/0.000008
  # = 0.006; eu 0.000003/0.000012 = 0.009; apac 0.000004/0.000016 = 0.012; regional
  # 0.000005/0.00002 = 0.015
  Scenario Outline: Configure valid modelMappings with surrounding whitespace, mixed-case deployment names, and each region enum value (<case>)
    Given I generate a unique resource name from "alc-region-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-region-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-region-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-region-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":<mapping>}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"CHAT-MINI","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"resp-alc","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"resp-alc","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "<cost>"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case            | slug      | mapping                                                                               | cost  | key                        |
      | global-standard | gs        | [{"deployment":"  Chat-Mini  ","model":"  gpt-4o-mini  ","region":"global-standard"}] | 0.003 | azure/gpt-4o-mini          |
      | us              | us        | [{"deployment":"  Chat-Mini  ","model":"  gpt-4o-mini  ","region":"us"}]              | 0.006 | azure/us/gpt-4o-mini       |
      | eu              | eu        | [{"deployment":"  Chat-Mini  ","model":"  gpt-4o-mini  ","region":"eu"}]              | 0.009 | azure/eu/gpt-4o-mini       |
      | apac            | apac      | [{"deployment":"  Chat-Mini  ","model":"  gpt-4o-mini  ","region":"apac"}]            | 0.012 | azure/apac/gpt-4o-mini     |
      | regional        | regional  | [{"deployment":"  Chat-Mini  ","model":"  gpt-4o-mini  ","region":"regional"}]        | 0.015 | azure/regional/gpt-4o-mini |
      | region absent   | no-region | [{"deployment":"  Chat-Mini  ","model":"  gpt-4o-mini  "}]                            | 0.003 | azure/gpt-4o-mini          |

  # azure/gpt-4o-mini: 1000 input x 0.000001 + 500 output x 0.000004 = 0.003
  Scenario: Route an Azure OpenAI chat completion where the kernel records template_handle as azure-openai
    Given I generate a unique resource name from "alc-openai" and store it as "providerName"
    And I generate a unique value from "alc-openai" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-openai" and store it as "providerVersion"
    And I generate a unique API context from "/alc-openai" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # azure_ai/deepseek-v3.1: 1000 input x 0.0000012 + 500 output x 0.000005 = 0.0037
  Scenario: Route an Azure AI Foundry call where the kernel records template_handle as azureai-foundry
    Given I generate a unique resource name from "alc-foundry" and store it as "providerName"
    And I generate a unique value from "alc-foundry" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-foundry" and store it as "providerVersion"
    And I generate a unique API context from "/alc-foundry" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-deepseek","model":"deepseek-v3.1"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/models/chat/completions" with body:
      """
      {"model":"my-deepseek","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"deepseek-v3.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"deepseek-v3.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.0037"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The provider uses the OpenAI template, so the policy does not know which Azure catalogue
  # applies and leaves the request unpriced rather than guess. The same request twice: the policy
  # warns once per template.
  Scenario: Route a request whose template_handle names a non-Azure provider, is empty, or whose SharedContext carries no metadata at all (non-Azure template)
    Given I generate a unique resource name from "alc-openai-template" and store it as "providerName"
    And I generate a unique value from "alc-openai-template" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-openai-template" and store it as "providerVersion"
    And I generate a unique API context from "/alc-openai-template" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai                     |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | route does not use an Azure provider template, not pricing request |
      | template_handle=openai |

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # A REST API is not an LLM provider, so the gateway records no template for its routes. The policy
  # leaves the request unpriced, and with no model or provider to report, the analytics event carries
  # no AI metadata at all.
  Scenario: Route a request whose template_handle names a non-Azure provider, is empty, or whose SharedContext carries no metadata at all (no template)
    Given I generate a unique value from "alc-rest" and store it as "apiName"
    And I generate a unique API version from "alc-rest" and store it as "apiVersion"
    And I generate a unique API context from "/alc-rest" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}     |
      | name                   | ${CTX:apiName}                |
      | spec.displayName       | ${CTX:apiName}                |
      | spec.version           | ${CTX:apiVersion}             |
      | spec.context           | ${CTX:apiContext}/$version    |
      | spec.upstream.main.url | http://testbench:3008          |
      | spec.operations        | [{"method":"POST","path":"/scripted/chat","policies":[{"name":"azure-llm-cost","version":"v1","params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" until status 200 with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" should not have metadata field "aiMetadata"
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | route does not use an Azure provider template, not pricing request |
      | template_handle=""                                                 |

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" until status 404
    And I wait for the config dump to stop containing a route with base path "${CTX:apiContext}"

  # The schema needs at least one mapping, so the mappings here describe another deployment only.
  # Chat completions report the model that really ran, so the call still prices from the response
  # alone, at Global Standard rates since nothing maps the deployment to a tier.
  # azure/gpt-4o-mini: 1000 input x 0.000001 + 500 output x 0.000004 = 0.003
  Scenario: Send an Azure OpenAI chat completion, the one endpoint that reports the real model name, with no modelMappings configured at all (mapping list omits the called deployment)
    Given I generate a unique resource name from "alc-no-mapping" and store it as "providerName"
    And I generate a unique value from "alc-no-mapping" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-no-mapping" and store it as "providerVersion"
    And I generate a unique API context from "/alc-no-mapping" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"other-deployment","model":"gpt-4.1"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"unmapped-chat","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # azure/gpt-4.1 through the request's deployment: 1000 x 0.000002 + 500 x 0.000008 = 0.006
  Scenario: Send a response whose body carries no model field, while the request body names the deployment
    Given I generate a unique resource name from "alc-request-model" and store it as "providerName"
    And I generate a unique value from "alc-request-model" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-request-model" and store it as "providerVersion"
    And I generate a unique API context from "/alc-request-model" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-41","model":"gpt-4.1"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-41","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The legacy surface names the deployment only in the path. Neither body names a model. The last
  # example puts the query string right after the deployment, so the policy must stop there.
  # azure/gpt-4.1 through the path's deployment: 1000 x 0.000002 + 500 x 0.000008 = 0.006
  Scenario Outline: Send a legacy /openai/deployments/{deployment}/... request where neither body names a model (<case>)
    Given I generate a unique resource name from "alc-legacy-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-legacy-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-legacy-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-legacy-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"legacy-41","model":"gpt-4.1"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/deployments/legacy-41<tail>" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/legacy-41<tail>" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/legacy-41<tail>" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/legacy-41<tail>" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/legacy-41<tail>" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                                    | slug        | tail                                     |
      | no query string                         | no-query    | /chat/completions                        |
      | query string                            | query       | /chat/completions?api-version=2024-10-21 |
      | query string right after the deployment | query-early | ?api-version=2024-10-21                  |

  # The deployment is called gpt-4o but runs gpt-4o-mini, and the response echoes the deployment
  # name. The mapping wins, so the call is billed as gpt-4o-mini (0.003), not gpt-4o (0.03).
  Scenario: Name a deployment identically to a real, differently-priced catalogued model, and map it to the model it actually runs
    Given I generate a unique resource name from "alc-collision" and store it as "providerName"
    And I generate a unique value from "alc-collision" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-collision" and store it as "providerVersion"
    And I generate a unique API context from "/alc-collision" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"gpt-4o","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The mapping points at a model the pricing file does not carry. The policy warns and falls back to
  # the deployment name, which is itself a catalogued model.
  # azure/gpt-4.1: 1000 x 0.000002 + 500 x 0.000008 = 0.006
  Scenario: Map a deployment to a model name that has no entry in the pricing file, while the deployment name itself is catalogued
    Given I generate a unique resource name from "alc-dead-mapping" and store it as "providerName"
    And I generate a unique value from "alc-dead-mapping" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-dead-mapping" and store it as "providerVersion"
    And I generate a unique API context from "/alc-dead-mapping" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"gpt-4.1","model":"gpt-4.1-unlisted"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"
    And the "gateway-runtime" service logs should contain "mapped model has no pricing entry"
    And the "gateway-runtime" service logs should contain "gpt-4.1-unlisted"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # Neither the response's model nor the request's deployment has a pricing entry or a mapping, so
  # nothing resolves. The gateway log lists the names the policy tried, in order. Each example names
  # its own deployment, so its line is the only one with those candidates.
  Scenario Outline: Send a response whose model is unknown to the catalogue, and separately a response body that is not valid JSON (<case>)
    Given I generate a unique resource name from "alc-unknown-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-unknown-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-unknown-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-unknown-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"<deployment>","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":<reply>}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      <body>
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | model not found for costing, request not priced |
      | candidates=<candidates>                         |

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case          | slug     | deployment        | candidates                   | reply                                                                                     | body                                                                             |
      | unknown model | model    | unlisted-model    | gpt-9-preview,unlisted-model | {"body":{"model":"gpt-9-preview","usage":{"prompt_tokens":1000,"completion_tokens":500}}} | {"model":"gpt-9-preview","usage":{"prompt_tokens":1000,"completion_tokens":500}} |
      | not JSON      | not-json | unlisted-not-json | unlisted-not-json            | {"raw":"upstream said no"}                                                                | upstream said no                                                                 |

  # deepseek-v3.1 is catalogued only under azure_ai/, and an Azure OpenAI route reads azure/ alone.
  Scenario: Route a Foundry-native model name through an azure-openai template
    Given I generate a unique resource name from "alc-foundry-on-openai" and store it as "providerName"
    And I generate a unique value from "alc-foundry-on-openai" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-foundry-on-openai" and store it as "providerVersion"
    And I generate a unique API context from "/alc-foundry-on-openai" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-deepseek","model":"deepseek-v3.1"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"my-deepseek","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"deepseek-v3.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"deepseek-v3.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # mistral-large-latest is catalogued under both. Foundry checks azure_ai/ first:
  # 1000 x 0.000002 + 500 x 0.000006 = 0.005 (the azure/ entry would give 0.01).
  Scenario: Route a model catalogued under both azure_ai/ and azure/ at different rates through an azureai-foundry template
    Given I generate a unique resource name from "alc-both-catalogues" and store it as "providerName"
    And I generate a unique value from "alc-both-catalogues" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-both-catalogues" and store it as "providerVersion"
    And I generate a unique API context from "/alc-both-catalogues" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-mistral","model":"mistral-large-latest"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/models/chat/completions" with body:
      """
      {"model":"my-mistral","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"mistral-large-latest","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"mistral-large-latest","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.005"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # gpt-4o-mini is catalogued only under azure/; Foundry falls back to it.
  # 1000 x 0.000001 + 500 x 0.000004 = 0.003
  Scenario: Serve an Azure OpenAI model through a Foundry resource, where the model is catalogued only under azure/
    Given I generate a unique resource name from "alc-foundry-openai-model" and store it as "providerName"
    And I generate a unique value from "alc-foundry-openai-model" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-foundry-openai-model" and store it as "providerVersion"
    And I generate a unique API context from "/alc-foundry-openai-model" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"foundry-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/models/chat/completions" with body:
      """
      {"model":"foundry-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The pricing file has no azure/eu/gpt-4.1 entry, so the EU Data Zone deployment is billed at the
  # base rate. The same request twice: the policy warns about the missing tier key once.
  # azure/gpt-4.1: 1000 x 0.000002 + 500 x 0.000008 = 0.006
  Scenario: Configure a Data Zone tier for a model that has no tier-specific pricing entry
    Given I generate a unique resource name from "alc-missing-tier" and store it as "providerName"
    And I generate a unique value from "alc-missing-tier" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-missing-tier" and store it as "providerVersion"
    And I generate a unique API context from "/alc-missing-tier" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"eu-41","model":"gpt-4.1","region":"eu"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"eu-41","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"eu-41","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | no pricing entry for the configured tier, billing at the base rate |
      | missing_key=azure/eu/gpt-4.1 |

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The pricing file carries gpt-4o-mini but not these names, and the request's deployment is not
  # mapped, so nothing matches exactly.
  Scenario Outline: Send a model name that is a near neighbour of a catalogued key, such as an unlisted dated snapshot or a suffixed variant (<case>)
    Given I generate a unique resource name from "alc-near-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-near-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-near-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-near-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"near-deployment","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"model":"<model>","usage":{"prompt_tokens":1000,"completion_tokens":500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"model":"<model>","usage":{"prompt_tokens":1000,"completion_tokens":500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                    | slug     | model                  |
      | unlisted dated snapshot | snapshot | gpt-4o-mini-2025-01-01 |
      | suffixed variant        | suffixed | gpt-4o-mini-high       |

  # Both deployments run gpt-4o-mini; one is a US Data Zone deployment, the other Global Standard.
  # US: 1000 x 0.000002 + 500 x 0.000008 = 0.006. Global Standard (base): 0.003.
  Scenario: Configure two deployments of the same model with different deployment types and send a request to each
    Given I generate a unique resource name from "alc-per-deployment" and store it as "providerName"
    And I generate a unique value from "alc-per-deployment" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-per-deployment" and store it as "providerVersion"
    And I generate a unique API context from "/alc-per-deployment" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"dz-us","model":"gpt-4o-mini","region":"us"},{"deployment":"gs-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/us/chat/completions" with body:
      """
      {"model":"dz-us","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/us/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/us/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/us/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/us/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I send a "POST" request to "${CTX:providerContext}/scripted/gs/chat/completions" with body:
      """
      {"model":"gs-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/gs/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/gs/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/gs/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/gs/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The body names an EU deployment and the path a US one: the body's tier wins (0.009). With no
  # model in the body, the path's tier applies (0.006). Both deployments run gpt-4o-mini.
  Scenario: Send a request whose body names a mapped deployment while the path names a different, also-mapped deployment
    Given I generate a unique resource name from "alc-body-vs-path" and store it as "providerName"
    And I generate a unique value from "alc-body-vs-path" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-body-vs-path" and store it as "providerVersion"
    And I generate a unique API context from "/alc-body-vs-path" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"body-eu","model":"gpt-4o-mini","region":"eu"},{"deployment":"path-us","model":"gpt-4o-mini","region":"us"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/deployments/path-us/chat/completions" with body:
      """
      {"model":"body-eu","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.009"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/deployments/path-us/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/deployments/path-us/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The request names a deployment no mapping lists, so the tier falls back to Global Standard. The
  # same request twice: the policy warns about the deployment once. azure/gpt-4o-mini: 0.003
  Scenario: Send a request naming a deployment that is absent from modelMappings, and separately configure a tier on a Foundry route (unmapped deployment)
    Given I generate a unique resource name from "alc-unmapped" and store it as "providerName"
    And I generate a unique value from "alc-unmapped" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-unmapped" and store it as "providerVersion"
    And I generate a unique API context from "/alc-unmapped" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"stray-deployment","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"stray-deployment","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | deployment not found in modelMappings, billing at global standard rates |
      | deployment=stray-deployment |

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The Foundry deployment is mapped to the EU tier, but azure_ai/ keys carry no tier, so the
  # Foundry entry prices it: 1000 x 0.000002 + 500 x 0.000006 = 0.005. The pricing file also holds
  # azure/eu/ (0.02) and azure_ai/eu/ (0.0075) entries for the model, so trying the EU tier first or
  # applying it to azure_ai/ keys would bill a different cost.
  Scenario: Send a request naming a deployment that is absent from modelMappings, and separately configure a tier on a Foundry route (tier on a Foundry route)
    Given I generate a unique resource name from "alc-foundry-tier" and store it as "providerName"
    And I generate a unique value from "alc-foundry-tier" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-foundry-tier" and store it as "providerVersion"
    And I generate a unique API context from "/alc-foundry-tier" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"eu-mistral","model":"mistral-large-latest","region":"eu"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/models/chat/completions" with body:
      """
      {"model":"eu-mistral","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"mistral-large-latest","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"mistral-large-latest","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.005"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/models/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
