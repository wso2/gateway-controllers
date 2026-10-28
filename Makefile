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

.PHONY: generate-catalog validate-catalog it it-unit it-standards it-scaffold

generate-catalog: ## Generate docs/README.md policy catalog from metadata.json files
	python3 scripts/generate-policy-catalog.py

validate-catalog: ## Verify docs/README.md is up to date (used in CI)
	python3 scripts/generate-policy-catalog.py --validate

# Policy integration tests. Each policy owns a suite in policies/<name>/it, a Go module of its own,
# and the targets below run those suites. They need Docker and run against a released gateway image:
#   make it POLICIES=time-based-model-routing GATEWAY_VERSION=1.2.0
# POLICIES is a comma-separated list and defaults to every policy that has a suite. DB limits the run
# to one database (sqlite, postgres or sqlserver); GATEWAY_HOST replaces the image repository prefix.
# One run builds the gateway once, on the base images of GATEWAY_VERSION, and every selected suite
# boots that build. It carries every policy of the repository; GATEWAY_POLICIES, a comma-separated
# list, narrows it. BLOCK_PARALLEL is the number of blocks, each with its own gateway, testbench and
# database, that run at once across all selected suites: as soon as one ends, the next starts.
# IT_TIMELINE, a file path, makes the run write how long each block took to that file, as JSON.
GATEWAY_VERSION ?= 1.2.0
ifeq ($(strip $(BLOCK_PARALLEL)),)
override BLOCK_PARALLEL := 12
endif
IT_TIMELINE ?=
comma := ,
space := $(subst ,, )
IT_POLICIES = $(if $(POLICIES),$(subst $(comma),$(space),$(POLICIES)),$(patsubst policies/%/it/it-suite.yaml,%,$(wildcard policies/*/it/it-suite.yaml)))
IT_STANDARDS_IMPORTS = github.com/wso2/gateway-controllers/tests/it/

it: ## Build the gateway once, then run the integration suites of the selected policies against it
	@test -n "$(IT_POLICIES)" || { echo "no policy has an integration suite"; exit 2; }
	@test "$(BLOCK_PARALLEL)" -ge 1 2>/dev/null || { echo "BLOCK_PARALLEL must be a whole number of at least 1"; exit 2; }
	@envfile=$$(mktemp); \
	(cd tests/it && go run ./cmd/build-gateway -policies-dir ../../policies -version $(GATEWAY_VERSION) \
		$(if $(GATEWAY_HOST),-host $(GATEWAY_HOST)) $(if $(GATEWAY_POLICIES),-policies "$(GATEWAY_POLICIES)") \
		-env-file "$$envfile") || { rm -f "$$envfile"; exit 1; }; \
	set -a; . "$$envfile"; set +a; rm -f "$$envfile"; \
	cd tests/it && go run ./cmd/run-suites -policies-dir ../../policies -policies "$(subst $(space),$(comma),$(IT_POLICIES))" \
		-version $(GATEWAY_VERSION) $(if $(GATEWAY_HOST),-host $(GATEWAY_HOST)) $(if $(DB),-db $(DB)) \
		$(if $(BLOCK_PARALLEL),-block-parallel $(BLOCK_PARALLEL)) $(if $(IT_TIMELINE),-timeline "$(abspath $(IT_TIMELINE))")

it-unit: ## Run the unit tests of the shared steps and of the selected policies' own steps
	cd tests/it && go test ./... -count=1
	@for policy in $(IT_POLICIES); do \
		(cd policies/$$policy/it && go test ./steps/... -count=1) || exit 1; \
	done

it-standards: ## Check the shared steps and the selected policies' suites against the framework standards
	cd tests/it && go tool standards -root common -unit-root common -steps common/steps \
		-scripts "" -suites "" -docs "" -approved-imports $(IT_STANDARDS_IMPORTS)
	@for policy in $(IT_POLICIES); do \
		(cd tests/it && go tool standards -root "" -unit-root "" -steps ../../policies/$$policy/it/steps \
			-features ../../policies/$$policy/it/features -suites ../../policies/$$policy/it/it-suite.yaml \
			-scripts "" -docs "" -approved-imports $(IT_STANDARDS_IMPORTS)) || exit 1; \
	done

it-scaffold: ## Create the integration suite skeleton for POLICY (policies/<POLICY>/it)
	@test -n "$(POLICY)" || { echo "usage: make it-scaffold POLICY=<policy name>"; exit 2; }
	python3 scripts/it/scaffold.py $(POLICY)
