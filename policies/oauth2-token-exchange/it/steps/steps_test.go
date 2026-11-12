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
	feature := "Feature: the policy steps\n  Scenario: the masked preview step is bound\n" +
		"    Given I store the masked preview of context value \"missing\" as \"preview\"\n"
	if err := os.WriteFile(filepath.Join(dir, "steps.feature"), []byte(feature), 0o600); err != nil {
		t.Fatal(err)
	}
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) { Register(sc, nil) },
		Options:             &godog.Options{Format: "progress", Paths: []string{dir}, Strict: true, NoColors: true},
	}
	// The step is bound, so the scenario fails on the missing context value rather than as
	// undefined, which Strict would report with a different status.
	if status := suite.Run(); status != 1 {
		t.Fatalf("expected the bound step to fail on the missing value, status %d", status)
	}
}

func TestStoreMaskedPreviewKeepsTheFirstAndLastFourCharacters(t *testing.T) {
	local := tcontext.NewLocal("runner")
	local.Set("token", "eyJhbGciOi.payload.signature1234")
	ctx := tcontext.WithLocal(context.Background(), local)

	if err := newPolicySteps(nil).storeMaskedPreview(ctx, "token", "preview"); err != nil {
		t.Fatal(err)
	}
	got, ok := tcontext.Get(ctx, "preview")
	if !ok || got != "eyJh...1234" {
		t.Fatalf("preview = %v, %v; want eyJh...1234", got, ok)
	}
}

func TestStoreMaskedPreviewRejectsUnusableInput(t *testing.T) {
	local := tcontext.NewLocal("runner")
	local.Set("short", "12345678")
	local.Set("token", "a-long-enough-token")
	ctx := tcontext.WithLocal(context.Background(), local)
	steps := newPolicySteps(nil)

	for name, args := range map[string][2]string{
		"too short": {"short", "preview"},
		"missing":   {"missing", "preview"},
		"empty key": {"token", " "},
	} {
		if err := steps.storeMaskedPreview(ctx, args[0], args[1]); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
