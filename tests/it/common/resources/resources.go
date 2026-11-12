/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package resources holds the files every policy suite shares: the canonical resource templates,
// and the Platform API files the framework module does not embed. A suite that needs a different
// template puts a file of the same name in its own resources/templates directory; that file
// replaces the shared one.
package resources

import "embed"

// Templates holds the canonical templates under templates/, one per resource kind.
//
//go:embed templates/*.yaml
var Templates embed.FS

// PlatformAPI holds the files the framework reads from the workspace to run the platform-api
// component, for the latest platform-api image. The configuration and role-to-scope mapping are
// those of api-platform main at commit 54862c582; refresh them when the image's needs change.
//
//go:embed platformapi
var PlatformAPI embed.FS

// PlatformAPIFiles maps each file of PlatformAPI to the workspace path the framework reads it from.
var PlatformAPIFiles = map[string]string{
	"docker-compose.yaml":        "tests/framework/core/catalog/platformapi/docker-compose.yaml",
	"config.toml":                "platform-api/config/config.toml",
	"role-to-scope-mapping.yaml": "platform-api/resources/role-to-scope-mapping.yaml",
}
