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
)

// Handles of the templates shipped for each product. The kernel records the
// route's template under template_handle.
const (
	templateAzureOpenAI = "azure-openai"
	templateAzureAI     = "azureai-foundry"
)

// vendor supplies the pricing namespaces a product's models are catalogued
// under. A new Foundry vendor is a new implementation plus its own template.
type vendor interface {
	namespaces(region azureRegion) []string
}

// selectVendor returns nil for a route that names neither Azure template, which
// leaves the request unpriced rather than billed from a guessed catalog.
func selectVendor(templateHandle string) vendor {
	switch strings.ToLower(strings.TrimSpace(templateHandle)) {
	case templateAzureOpenAI:
		return azureOpenAI{}
	case templateAzureAI:
		return azureAIFoundry{}
	}
	logNonAzureTemplate(templateHandle)
	return nil
}

var nonAzureTemplateSeen sync.Map

func logNonAzureTemplate(templateHandle string) {
	if _, seen := nonAzureTemplateSeen.LoadOrStore(templateHandle, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: route does not use an Azure provider template, not pricing request",
		"template_handle", templateHandle,
		"expected", templateAzureOpenAI+" or "+templateAzureAI)
}

// azureOpenAI prices from the azure/ catalog. It cannot serve a Foundry-native
// model, so it never reads azure_ai/.
type azureOpenAI struct{}

func (azureOpenAI) namespaces(region azureRegion) []string {
	return azureNamespaces(region)
}

// azureAIFoundry prices from azure_ai/ first. Foundry also serves the OpenAI
// models, which are catalogued only under azure/, so it falls back there.
type azureAIFoundry struct{}

func (azureAIFoundry) namespaces(region azureRegion) []string {
	return append([]string{"azure_ai/"}, azureNamespaces(region)...)
}

// azureNamespaces tries the deployment's tier first, then the base entry.
func azureNamespaces(region azureRegion) []string {
	if region == "" {
		region = regionGlobalStandard
	}
	return []string{"azure/" + string(region) + "/", "azure/"}
}
