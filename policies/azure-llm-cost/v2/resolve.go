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
	"log/slog"
	"strings"
	"sync"

	"github.com/wso2/api-platform/sdk/ai/llmusage"
)

// resolvePricing takes the model name from the first source that resolves: the
// candidates the template located in the response and request, then the
// deployment in the URL, which only the legacy surface carries.
//
// Each is tried through the mapping first, so an operator can correct a
// deployment whose name collides with a real model.
func (p *AzureLLMCostPolicy) resolvePricing(usage llmusage.Usage, requestPath string, v vendor) (ModelPricing, string, []string, bool) {
	prefixes := v.namespaces(p.regionForRequest(usage, requestPath))

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
	for _, name := range usage.ModelCandidates {
		add(name)
	}
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

// regionForRequest returns the deployment's tier, or Global Standard. The
// deployment is the request-side name: the body's model on the v1 surface, the
// URL segment on the legacy one.
func (p *AzureLLMCostPolicy) regionForRequest(usage llmusage.Usage, requestPath string) azureRegion {
	var unmapped []string
	for _, deployment := range append(requestSideNames(usage), deploymentFromPath(requestPath)) {
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

// requestSideNames is every candidate after the first, which the template read
// from the response.
func requestSideNames(usage llmusage.Usage) []string {
	if len(usage.ModelCandidates) < 2 {
		return nil
	}
	return usage.ModelCandidates[1:]
}

var unmappedDeploymentSeen sync.Map

func logUnmappedDeployment(deployment string) {
	if _, seen := unmappedDeploymentSeen.LoadOrStore(deployment, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: deployment not found in modelMappings, "+
		"billing at global standard rates",
		"deployment", deployment)
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
