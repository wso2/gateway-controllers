/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package mistralmoderation

import (
	"fmt"
	"sort"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Category names exactly as mistral-moderation-2603 returns them in category_scores.
// The older dangerous_and_criminal_content category of mistral-moderation-2411 is split into
// dangerous and criminal in 2603, and jailbreaking is new.
const (
	categorySexual                = "sexual"
	categoryHateAndDiscrimination = "hate_and_discrimination"
	categoryViolenceAndThreats    = "violence_and_threats"
	categoryDangerous             = "dangerous"
	categoryCriminal              = "criminal"
	categorySelfHarm              = "selfharm"
	categoryHealth                = "health"
	categoryFinancial             = "financial"
	categoryLaw                   = "law"
	categoryPII                   = "pii"
	categoryJailbreaking          = "jailbreaking"
)

// supportedCategories is every category the policy accepts a threshold for, in the order
// they are evaluated and reported.
var supportedCategories = []string{
	categorySexual,
	categoryHateAndDiscrimination,
	categoryViolenceAndThreats,
	categoryDangerous,
	categoryCriminal,
	categorySelfHarm,
	categoryHealth,
	categoryFinancial,
	categoryLaw,
	categoryPII,
	categoryJailbreaking,
}

// defaultCategoryThresholds applies to the harmful-content categories that correspond to the
// four Azure Content Safety categories. Every other category is evaluated only when the API
// developer gives it a threshold.
var defaultCategoryThresholds = map[string]float64{
	categorySexual:                0.5,
	categoryHateAndDiscrimination: 0.5,
	categoryViolenceAndThreats:    0.5,
	categorySelfHarm:              0.5,
}

func isSupportedCategory(name string) bool {
	for _, c := range supportedCategories {
		if c == name {
			return true
		}
	}
	return false
}

// guardrailCodeFor maps the category that decided a rejection onto the SDK guardrail code
// for it, so a fault policy can branch on the code instead of parsing a message. health,
// financial and law flag unqualified advice, which the SDK vocabulary does not name, so they
// take the content-safety group's own generic code.
func guardrailCodeFor(category string) string {
	switch category {
	case categorySexual:
		return policy.GuardrailCodeSexual
	case categoryHateAndDiscrimination:
		return policy.GuardrailCodeHate
	case categoryViolenceAndThreats:
		return policy.GuardrailCodeViolence
	case categorySelfHarm:
		return policy.GuardrailCodeSelfHarm
	case categoryDangerous, categoryCriminal:
		return policy.GuardrailCodeDangerousActivity
	case categoryJailbreaking:
		return policy.GuardrailCodePromptInjection
	case categoryPII:
		return policy.GuardrailCodePII
	default:
		return policy.GuardrailCodeUnsafeContent
	}
}

// categoryViolation is one category whose score reached its threshold.
type categoryViolation struct {
	Category  string
	Score     float64
	Threshold float64
	// Flagged is Mistral's own boolean for the category. It is reported, not enforced.
	Flagged bool
}

// evaluation is the outcome of comparing a verdict with the configured thresholds.
type evaluation struct {
	// Violations is ordered by score, highest first, so Violations[0] decides the fault code.
	Violations []categoryViolation
}

func (e evaluation) violated() bool { return len(e.Violations) > 0 }

func (e evaluation) categoryNames() []string {
	names := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		names = append(names, v.Category)
	}
	return names
}

// evaluateThresholds compares each enabled category's score with its threshold. A category
// violates when its score is greater than or equal to its threshold. Mistral's boolean
// categories are not used to decide: they reflect Mistral's own fixed thresholds, which the
// operator can neither see nor tune.
//
// A category that is enabled but absent from category_scores is an error rather than a pass:
// the policy cannot vouch for content it did not get a score for (for example after the
// gateway administrator switches to a model with a different category set).
func evaluateThresholds(thresholds map[string]float64, result *moderationResult) (evaluation, error) {
	var eval evaluation
	for _, category := range supportedCategories {
		threshold, enabled := thresholds[category]
		if !enabled {
			continue
		}
		score, ok := result.CategoryScores[category]
		if !ok {
			return evaluation{}, fmt.Errorf("category_scores has no score for enabled category %q", category)
		}
		if score >= threshold {
			eval.Violations = append(eval.Violations, categoryViolation{
				Category:  category,
				Score:     score,
				Threshold: threshold,
				Flagged:   result.Categories[category],
			})
		}
	}
	sort.SliceStable(eval.Violations, func(i, j int) bool {
		return eval.Violations[i].Score > eval.Violations[j].Score
	})
	return eval, nil
}
