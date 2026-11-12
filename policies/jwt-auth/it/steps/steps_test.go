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

package steps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

func TestRegisterBindsThePolicySteps(t *testing.T) {
	dir := t.TempDir()
	feature := "Feature: the policy steps\n  Scenario: the store step is bound\n" +
		"    Given I store the value \"metadata\" as \"keyType\"\n"
	if err := os.WriteFile(filepath.Join(dir, "steps.feature"), []byte(feature), 0o600); err != nil {
		t.Fatal(err)
	}
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) { Register(sc, nil) },
		Options:             &godog.Options{Format: "progress", Paths: []string{dir}, Strict: true, NoColors: true},
	}
	// The step is bound, so the scenario fails on the missing runner context rather than as
	// undefined, which Strict would report with a different status.
	if status := suite.Run(); status != 1 {
		t.Fatalf("expected the bound step to fail without runner context, status %d", status)
	}
}

func TestStoreValue(t *testing.T) {
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("runner"))
	if err := storeValue(ctx, "metadata", " keyType "); err != nil {
		t.Fatal(err)
	}
	if got, err := tcontext.ResolveString(ctx, "keyType"); err != nil || got != "metadata" {
		t.Fatalf("stored value = %q, %v; want %q", got, err, "metadata")
	}
}

func TestStoreValueRejectsAnEmptyKey(t *testing.T) {
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("runner"))
	if err := storeValue(ctx, "metadata", "  "); err == nil {
		t.Fatal("expected an error for an empty key")
	}
}

func TestStoreValueNeedsARunnerContext(t *testing.T) {
	if err := storeValue(context.Background(), "metadata", "keyType"); err == nil {
		t.Fatal("expected an error without runner context")
	}
}
