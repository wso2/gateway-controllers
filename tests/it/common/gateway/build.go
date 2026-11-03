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

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/wso2/api-platform/tests/framework/core/builder"
	"github.com/wso2/api-platform/tests/framework/core/catalog/platformgateway"
	"github.com/wso2/api-platform/tests/framework/core/catalog/shared"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

const (
	// EnvController and EnvRuntime name the environment variables through which the framework
	// takes the gateway controller and runtime images a suite boots.
	EnvController = shared.EnvImageGatewayController
	EnvRuntime    = shared.EnvImageGatewayRuntime

	controllerRepository = "local/apip-it-gateway-controller"
	runtimeRepository    = "local/apip-it-gateway-runtime"
)

// Images are the gateway controller and runtime images a suite boots.
type Images struct {
	Controller string
	Runtime    string
}

// Environment returns the variables that make the framework boot these images.
func (i Images) Environment() map[string]string {
	return map[string]string{EnvController: i.Controller, EnvRuntime: i.Runtime}
}

// Prebuilt returns the images the environment names, and whether it names both.
func Prebuilt() (Images, bool) {
	images := Images{
		Controller: strings.TrimSpace(os.Getenv(EnvController)),
		Runtime:    strings.TrimSpace(os.Getenv(EnvRuntime)),
	}
	return images, images.Controller != "" && images.Runtime != ""
}

// CheckVersion reports an error unless both images carry the tag of the gateway version a run
// selects. The framework rewrites an image's tag to that version, so an image tagged otherwise is
// never the one the gateway boots.
func (i Images) CheckVersion(version string) error {
	version = normalizeVersion(version)
	for _, ref := range []string{i.Controller, i.Runtime} {
		if tag(ref) != version {
			return fmt.Errorf("the prebuilt gateway image %q is not tagged %q, the version this run selects", ref, version)
		}
	}
	return nil
}

// BuildOptions describe one gateway build.
type BuildOptions struct {
	// PoliciesDir is the folder that holds the policy folders. Required.
	PoliciesDir string

	// Policies names the policies to build into the gateway. Empty means every policy of PoliciesDir.
	Policies []string

	// Version is the released gateway the policies are built on, or latest. Required.
	Version string

	// Host replaces the image repository prefix of the gateway's base images. Empty means
	// the release registry.
	Host string

	// Runner runs the docker commands. Empty means the host's docker.
	Runner builder.Runner
}

// Build builds the gateway controller and runtime images that carry the selected policies, on
// the base images of opts.Version, and tags them with that version so the framework boots them
// for a run that selects it.
func Build(ctx context.Context, opts BuildOptions) (Images, error) {
	version := normalizeVersion(opts.Version)
	if version == "" {
		return Images{}, fmt.Errorf("the gateway version to build on is required")
	}
	if strings.TrimSpace(opts.PoliciesDir) == "" {
		return Images{}, fmt.Errorf("the policies folder is required")
	}
	names := uniqueSorted(opts.Policies)
	if len(opts.Policies) == 0 {
		all, err := PolicyNames(opts.PoliciesDir)
		if err != nil {
			return Images{}, err
		}
		names = all
	}
	if len(names) == 0 {
		return Images{}, errNoPolicies
	}
	runner := opts.Runner
	if runner == nil {
		runner = builder.ExecRunner{}
	}

	workspace, err := os.MkdirTemp("", "gateway-policies-")
	if err != nil {
		return Images{}, err
	}
	defer os.RemoveAll(workspace)
	if _, err := Stage(opts.PoliciesDir, workspace, names...); err != nil {
		return Images{}, err
	}

	registry := strings.TrimRight(strings.TrimSpace(opts.Host), "/")
	if registry == "" {
		registry = shared.GatewayReleaseRegistry
	}
	derived, err := platformgateway.BuildVersionedWithPolicies(ctx, workspace, version, "policies",
		registry+"/gateway-controller:"+version, registry+"/gateway-runtime:"+version, runner, false)
	if err != nil {
		return Images{}, err
	}

	images := Images{Controller: controllerRepository + ":" + version, Runtime: runtimeRepository + ":" + version}
	for source, target := range map[string]string{derived.Controller: images.Controller, derived.Runtime: images.Runtime} {
		if err := runner.Run(ctx, builder.Command{Directory: workspace, Args: []string{"docker", "tag", source, target}}); err != nil {
			return Images{}, fmt.Errorf("tagging %s: %w", target, err)
		}
	}
	return images, nil
}

// normalizeVersion trims a gateway version and spells latest the way the framework does.
func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if strings.EqualFold(version, topology.LatestGatewayVersion) {
		return topology.LatestGatewayVersion
	}
	return version
}

// tag returns the tag of an image reference.
func tag(ref string) string {
	slash := strings.LastIndexByte(ref, '/')
	colon := strings.LastIndexByte(ref, ':')
	if colon <= slash {
		return ""
	}
	return ref[colon+1:]
}
