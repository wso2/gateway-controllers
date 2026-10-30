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

// Package gateway builds the gateway image set the integration suites boot. One build holds every
// policy a run needs, so a run of many suites builds the gateway once instead of once per suite.
package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// IntegrationDir is the folder inside a policy that holds its integration tests. A gateway built
// from a policy leaves it out.
const IntegrationDir = "it"

// policyDefinition marks a folder as a policy.
const policyDefinition = "policy-definition.yaml"

// PolicyNames returns the policies of policiesDir, the folders that hold a policy-definition.yaml,
// in name order.
func PolicyNames(policiesDir string) ([]string, error) {
	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(policiesDir, entry.Name(), policyDefinition)); err == nil {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// Stage copies each named policy of policiesDir to <workspace>/policies/<policy>, leaving out its
// it folder, and returns the staged policy tree. The framework builds the gateway from every
// policy in a tree, so the tree holds exactly the policies the gateway should carry. A name given
// twice is staged once.
func Stage(policiesDir, workspace string, names ...string) (string, error) {
	tree := filepath.Join(workspace, "policies")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		return "", err
	}
	staged := map[string]bool{}
	for _, name := range names {
		if staged[name] {
			continue
		}
		staged[name] = true
		source := filepath.Join(policiesDir, name)
		if _, err := os.Stat(filepath.Join(source, policyDefinition)); err != nil {
			return "", fmt.Errorf("%q is not a policy folder: %w", source, err)
		}
		if err := CopyTree(source, filepath.Join(tree, name)); err != nil {
			return "", err
		}
	}
	return tree, nil
}

// CopyTree copies source to destination, leaving out a top-level it folder and refusing symlinks.
func CopyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == IntegrationDir {
			return filepath.SkipDir
		}
		target := filepath.Join(destination, relative)
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("symlink %q is not allowed in a policy", path)
		case entry.IsDir():
			return os.MkdirAll(target, 0o755)
		default:
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, content, 0o644)
		}
	})
}

// uniqueSorted returns names without repeats, in name order.
func uniqueSorted(names []string) []string {
	out := slices.Clone(names)
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

var errNoPolicies = errors.New("no policies to build the gateway from")
