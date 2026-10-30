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

package runsuites

import (
	"errors"
	"strings"

	"github.com/wso2/api-platform/tests/framework/core/components"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

// Block is one block of a suite, a matrix variant when the suite declares a database matrix.
type Block struct {
	// Name is the name a run selects the block by, for example "basic-auth/postgres".
	Name string

	// Runners is the number of runners the block executes one after the other.
	Runners int

	// Database is the engine of the block's gateway: the matrix variant, or else the database the
	// suite declares for the platform-gateway component. It is empty when neither names one.
	Database string
}

// Blocks returns the blocks the suite in suiteFile boots under selection: its blocks with their
// database matrices expanded, less the variants and runners the selected gateway version excludes.
// It resolves the suite the way the suite's own run does, against registry. A suite the selection
// leaves nothing to run has no blocks and no error.
func Blocks(registry *components.Registry, suiteFile string, selection topology.Selection) ([]Block, error) {
	resolved, err := topology.LoadFile(suiteFile, registry)
	if err != nil {
		return nil, err
	}
	applied, err := selection.Apply(resolved)
	if nothingToRun(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	blocks := make([]Block, len(applied.Blocks))
	for i, block := range applied.Blocks {
		blocks[i] = Block{Name: block.Name, Runners: len(block.Runners), Database: database(block)}
	}
	return blocks, nil
}

// OnlyDatabase keeps the blocks whose gateway runs on the named database, whether the suite names it
// in a matrix or declares it once for the block. An empty name keeps every block.
func OnlyDatabase(blocks []Block, name string) []Block {
	if name == "" {
		return blocks
	}
	var kept []Block
	for _, block := range blocks {
		if block.Database == name {
			kept = append(kept, block)
		}
	}
	return kept
}

// database returns the engine the block's gateway runs on.
func database(block topology.ResolvedBlock) string {
	if block.DB != "" {
		return string(block.DB)
	}
	for _, component := range block.Components {
		if component.Def != nil && component.Def.Name == "platform-gateway" {
			return string(component.DB)
		}
	}
	return ""
}

// nothingToRun reports whether err says the selection left no block or runner to execute. The
// framework reports that as ErrNothingToRun only for a selection by policy name, which a suite of
// declared runners never uses; otherwise it returns a plain error.
func nothingToRun(err error) bool {
	return errors.Is(err, topology.ErrNothingToRun) ||
		err != nil && (strings.Contains(err.Error(), "the selection has no compatible blocks") ||
			strings.Contains(err.Error(), "the selection has no compatible runners"))
}
