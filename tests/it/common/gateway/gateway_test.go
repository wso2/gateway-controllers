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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/builder"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func writePolicy(t *testing.T, policiesDir, name string) {
	t.Helper()
	writeFile(t, filepath.Join(policiesDir, name, "policy-definition.yaml"), "name: "+name+"\nversion: v1.0.0\n")
	writeFile(t, filepath.Join(policiesDir, name, "it", "it-suite.yaml"), "suite: "+name+"\n")
}

func TestStageCopiesEachNamedPolicyExceptItsIntegrationTests(t *testing.T) {
	policies := t.TempDir()
	writePolicy(t, policies, "sample-policy")
	writePolicy(t, policies, "set-headers")
	writePolicy(t, policies, "unused")
	writeFile(t, filepath.Join(policies, "sample-policy", "internal", "logic.go"), "package internal\n")
	workspace := t.TempDir()

	// A policy named twice is staged once.
	tree, err := Stage(policies, workspace, "sample-policy", "set-headers", "sample-policy")
	require.NoError(t, err)

	require.Equal(t, filepath.Join(workspace, "policies"), tree)
	entries, err := os.ReadDir(tree)
	require.NoError(t, err)
	require.Len(t, entries, 2, "the staged tree holds only the named policies")
	require.FileExists(t, filepath.Join(tree, "sample-policy", "internal", "logic.go"))
	require.NoDirExists(t, filepath.Join(tree, "sample-policy", "it"))
	require.NoDirExists(t, filepath.Join(tree, "set-headers", "it"))
}

func TestStageRejectsWhatIsNotAPolicyFolder(t *testing.T) {
	policies := t.TempDir()
	writeFile(t, filepath.Join(policies, "not-a-policy", "README.md"), "x\n")

	_, err := Stage(policies, t.TempDir(), "not-a-policy")
	require.ErrorContains(t, err, "not a policy folder")
}

func TestStageRefusesSymlinks(t *testing.T) {
	policies := t.TempDir()
	writePolicy(t, policies, "sample-policy")
	require.NoError(t, os.Symlink(filepath.Join(policies, "sample-policy", "policy-definition.yaml"),
		filepath.Join(policies, "sample-policy", "link.yaml")))

	_, err := Stage(policies, t.TempDir(), "sample-policy")
	require.ErrorContains(t, err, "symlink")
}

func TestPolicyNamesListsTheFoldersThatHoldAPolicyDefinition(t *testing.T) {
	policies := t.TempDir()
	writePolicy(t, policies, "b-policy")
	writePolicy(t, policies, "a-policy")
	writeFile(t, filepath.Join(policies, "docs", "README.md"), "x\n")
	writeFile(t, filepath.Join(policies, "stray-file"), "x\n")

	names, err := PolicyNames(policies)
	require.NoError(t, err)
	require.Equal(t, []string{"a-policy", "b-policy"}, names)
}

func TestPrebuiltNeedsBothImages(t *testing.T) {
	t.Setenv(EnvController, "")
	t.Setenv(EnvRuntime, "")
	_, ok := Prebuilt()
	require.False(t, ok)

	t.Setenv(EnvController, "local/controller:1.2.0")
	_, ok = Prebuilt()
	require.False(t, ok)

	t.Setenv(EnvRuntime, "local/runtime:1.2.0")
	images, ok := Prebuilt()
	require.True(t, ok)
	require.Equal(t, Images{Controller: "local/controller:1.2.0", Runtime: "local/runtime:1.2.0"}, images)
}

func TestCheckVersionRequiresTheTagTheFrameworkWillBoot(t *testing.T) {
	images := Images{Controller: "registry:5000/controller:1.2.0", Runtime: "local/runtime:1.2.0"}

	require.NoError(t, images.CheckVersion("1.2.0"))
	require.ErrorContains(t, images.CheckVersion("1.1.0"), "is not tagged")
	require.ErrorContains(t, images.CheckVersion("latest"), "is not tagged")
	require.NoError(t, Images{Controller: "local/c:latest", Runtime: "local/r:latest"}.CheckVersion(" LATEST "))
	require.Error(t, Images{Controller: "local/c", Runtime: "local/r"}.CheckVersion("1.2.0"))
}

type recordingRunner struct{ commands []builder.Command }

func (r *recordingRunner) Run(_ context.Context, command builder.Command) error {
	r.commands = append(r.commands, command)
	return nil
}

func (r *recordingRunner) joined() []string {
	lines := make([]string, len(r.commands))
	for i, command := range r.commands {
		lines[i] = strings.Join(command.Args, " ")
	}
	return lines
}

func TestBuildBuildsOneImageSetAndTagsItWithTheVersion(t *testing.T) {
	policies := t.TempDir()
	for _, name := range []string{"a-policy", "b-policy"} {
		writePolicy(t, policies, name)
	}
	runner := &recordingRunner{}

	images, err := Build(context.Background(), BuildOptions{
		PoliciesDir: policies, Version: "1.1.0", Host: "docker.io/example/", Runner: runner,
	})
	require.NoError(t, err)

	require.Equal(t, Images{
		Controller: "local/apip-it-gateway-controller:1.1.0",
		Runtime:    "local/apip-it-gateway-runtime:1.1.0",
	}, images)
	lines := runner.joined()
	require.Contains(t, lines[0], "docker.io/example/gateway-builder:1.1.0")
	require.Contains(t, lines[0], "-gateway-controller-base-image docker.io/example/gateway-controller:1.1.0")
	require.Contains(t, lines[0], "-gateway-runtime-base-image docker.io/example/gateway-runtime:1.1.0")
	require.Len(t, lines, 5, "the builder run, two image builds and two tags")
	tagged := strings.Join(lines[len(lines)-2:], "\n")
	require.Contains(t, tagged, "local/apip-it-gateway-controller:1.1.0")
	require.Contains(t, tagged, "local/apip-it-gateway-runtime:1.1.0")
}

func TestBuildRequiresAVersionAndPolicies(t *testing.T) {
	policies := t.TempDir()
	_, err := Build(context.Background(), BuildOptions{PoliciesDir: policies, Runner: &recordingRunner{}})
	require.ErrorContains(t, err, "version")

	_, err = Build(context.Background(), BuildOptions{PoliciesDir: policies, Version: "1.2.0", Runner: &recordingRunner{}})
	require.ErrorIs(t, err, errNoPolicies)
}
