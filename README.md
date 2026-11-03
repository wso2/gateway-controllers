# Gateway Controllers — Policy Hub

Centralized repository to store, version, and manage reusable gateway policies for the WSO2 API Platform.

## Overview

This repository contains the source code and documentation for all gateway policies published to the **API Platform Policy Hub**. Policies are versioned independently and can be included in custom gateway builds via the `ap` CLI tool.

For the full policy catalog with descriptions and links, see [docs/README.md](./docs/README.md).

## API Platform

The [WSO2 API Platform](https://github.com/wso2/api-platform) is a complete API management and gateway system for managing, securing, and routing traffic to backend services. It supports REST APIs, AI/LLM APIs, and MCP (Model Context Protocol) servers.

| Component | Purpose |
|-----------|---------|
| **Gateway Controller** | Control plane that manages API configurations and dynamically configures the router |
| **Gateway Runtime** | Data plane (Envoy Proxy) that routes HTTP/HTTPS traffic and processes requests through policies |
| **Policy Builder** | Build-time tooling for compiling custom policy implementations into gateway images |
| **`ap` CLI** | Command-line interface for managing gateways, APIs, MCP proxies, and custom builds |

## What is a Policy?

A policy is a pluggable unit of behavior that runs in the gateway request or response pipeline. Policies can be applied at the API level (all operations) or at individual operation level, and can run on requests, responses, or both.

Policies handle cross-cutting concerns such as authentication, rate limiting, header manipulation, payload transformation, content moderation, and LLM-specific controls (prompt decoration, semantic caching, token limits, guardrails). Multiple policies can be chained together on the same API or operation.

Each policy in this repository is versioned independently. When a new version is published, older versions remain available so existing deployments are not affected.

## Creating Custom Policies

The `ap` CLI lets you build a custom gateway image that includes any combination of hub policies (from this repository) and local policies (your own implementations).

See [Customizing Gateway Policies](https://github.com/wso2/api-platform/blob/main/docs/cli/customizing-gateway-policies.md) in the API Platform documentation for full instructions.

## Integration Tests

Each policy can own an integration test suite in `policies/<name>/it/`, with its own scenarios and step definitions on the shared steps in `tests/it/common`. Every pull request runs the suites of all policies against gateway 1.2.0, 1.1.0 and the latest gateway image. See [tests/it/CLAUDE.md](tests/it/CLAUDE.md) for how to add and run them.

## Policy Catalog

See [docs/README.md](./docs/README.md) for the full list of available policies organized by category, with descriptions and links to the latest documentation for each.
