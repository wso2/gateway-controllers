/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package azurellmcost

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
)

// resolvePricing takes the model name from the first source that resolves:
//
//  1. response body's model   real model on chat completions, deployment on v1 /responses
//  2. request body's model    deployment name, v1 surface
//  3. deployment path segment legacy surface only
//
// Each is tried through its mapping first, so an operator can correct a
// deployment whose name collides with a real model. Candidates are returned for
// logging when nothing resolves.
func (p *AzureLLMCostPolicy) resolvePricing(responseBody, requestBody []byte, requestPath, templateHandle string) (ModelPricing, string, []string, bool) {
	return p.resolvePricingForRegion(responseBody, requestBody, requestPath, templateHandle,
		p.regionForRequest(requestBody, requestPath))
}

// resolvePricingForRegion is resolvePricing with the deployment's tier already
// worked out, so a caller that needs the tier itself reads it only once.
func (p *AzureLLMCostPolicy) resolvePricingForRegion(responseBody, requestBody []byte, requestPath, templateHandle string, region azureRegion) (ModelPricing, string, []string, bool) {
	if !isAzureTemplate(templateHandle) {
		logNonAzureTemplate(templateHandle)
		return ModelPricing{}, "", nil, false
	}
	prefixes := namespacesFor(templateHandle, region)

	var candidates []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		for _, existing := range candidates {
			if strings.EqualFold(existing, name) {
				return
			}
		}
		candidates = append(candidates, name)
	}
	add(extractModelName(responseBody))
	add(extractModelName(requestBody))
	add(deploymentFromPath(requestPath))

	for _, name := range candidates {
		if mapped, ok := p.modelMappings[strings.ToLower(name)]; ok {
			if pricing, key, found := lookupPricingWithKey(p.pricingMap, mapped.model, prefixes); found {
				return pricing, key, candidates, true
			}
			slog.Warn("azure-llm-cost: mapped model has no pricing entry",
				"deployment", name, "mapped_model", mapped.model)
		}
		if pricing, key, found := lookupPricingWithKey(p.pricingMap, name, prefixes); found {
			return pricing, key, candidates, true
		}
	}
	return ModelPricing{}, "", candidates, false
}

// regionForRequest returns the deployment's tier, or Global Standard.
func (p *AzureLLMCostPolicy) regionForRequest(requestBody []byte, requestPath string) azureRegion {
	var unmapped []string
	for _, deployment := range []string{extractModelName(requestBody), deploymentFromPath(requestPath)} {
		deployment = strings.ToLower(strings.TrimSpace(deployment))
		if deployment == "" {
			continue
		}
		if m, ok := p.modelMappings[deployment]; ok {
			return m.region
		}
		unmapped = append(unmapped, deployment)
	}
	for _, deployment := range unmapped {
		logUnmappedDeployment(deployment)
	}
	return regionGlobalStandard
}

// nonAzureTemplateSeen keeps logNonAzureTemplate to once per handle.
var nonAzureTemplateSeen sync.Map

// logNonAzureTemplate warns that the route names neither Azure template, so the
// request is left unpriced rather than billed from a guessed catalog.
func logNonAzureTemplate(templateHandle string) {
	if _, seen := nonAzureTemplateSeen.LoadOrStore(templateHandle, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: route does not use an Azure provider template, not pricing request",
		"template_handle", templateHandle,
		"expected", templateAzureOpenAI+" or "+templateAzureAI)
}

// unmappedDeploymentSeen keeps logUnmappedDeployment to once per deployment.
var unmappedDeploymentSeen sync.Map

// logUnmappedDeployment warns that no mapping matched, so the tier fell back to
// Global Standard.
func logUnmappedDeployment(deployment string) {
	if _, seen := unmappedDeploymentSeen.LoadOrStore(deployment, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: deployment not found in modelMappings, "+
		"billing at global standard rates",
		"deployment", deployment)
}

// extractModelName reads $.model, or $.message.model for Anthropic streams,
// or $.response.model for the Responses API stream envelope.
func extractModelName(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var probe struct {
		Model   string `json:"model"`
		Message *struct {
			Model string `json:"model"`
		} `json:"message"`
		Response *struct {
			Model string `json:"model"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	if probe.Model != "" {
		return probe.Model
	}
	if probe.Message != nil && probe.Message.Model != "" {
		return probe.Message.Model
	}
	if probe.Response != nil {
		return probe.Response.Model
	}
	return ""
}

// deploymentFromPath reads {deployment} from /openai/deployments/{deployment}/...
func deploymentFromPath(requestPath string) string {
	const marker = "/deployments/"
	i := strings.Index(requestPath, marker)
	if i < 0 {
		return ""
	}
	rest := requestPath[i+len(marker):]
	if end := strings.IndexAny(rest, "/?"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}
