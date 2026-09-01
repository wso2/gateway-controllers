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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package timebasedrouting

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type target struct {
	Model    string
	Provider string
}

type schedule struct {
	Name       string
	FromMinute int
	ToMinute   int
	Days       map[time.Weekday]struct{}
	Target     target
}

type requestModelConfig struct {
	Location       string
	Identifier     string
	PathExpression *regexp.Regexp
	PathModelGroup int
}

type config struct {
	Timezone     *time.Location
	Schedules    []schedule
	Default      *target
	RequestModel requestModelConfig
}

func parseConfig(params map[string]interface{}) (config, error) {
	result := config{Timezone: time.UTC}

	if raw, exists := params["timezone"]; exists {
		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return result, fmt.Errorf("'timezone' must be a non-empty string")
		}
		location, err := time.LoadLocation(strings.TrimSpace(value))
		if err != nil {
			return result, fmt.Errorf("'timezone' is invalid: %w", err)
		}
		result.Timezone = location
	}

	schedulesRaw, ok := params["schedules"].([]interface{})
	if !ok || len(schedulesRaw) == 0 {
		return result, fmt.Errorf("'schedules' must be a non-empty array")
	}
	result.Schedules = make([]schedule, 0, len(schedulesRaw))
	for i, raw := range schedulesRaw {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return result, fmt.Errorf("'schedules[%d]' must be an object", i)
		}
		parsed, err := parseSchedule(item, i)
		if err != nil {
			return result, err
		}
		result.Schedules = append(result.Schedules, parsed)
	}
	if err := validateNonOverlappingSchedules(result.Schedules); err != nil {
		return result, err
	}

	if raw, exists := params["default"]; exists {
		parsed, err := parseTarget(raw, "default")
		if err != nil {
			return result, err
		}
		result.Default = &parsed
	}

	requestModelRaw, ok := params["requestModel"].(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("'requestModel' system parameter is required")
	}
	location, ok := requestModelRaw["location"].(string)
	if !ok {
		return result, fmt.Errorf("'requestModel.location' must be a string")
	}
	if location == "body" {
		location = "payload"
	}
	switch location {
	case "payload", "header", "queryParam", "pathParam":
	default:
		return result, fmt.Errorf("'requestModel.location' must be one of payload, header, queryParam, or pathParam")
	}
	identifier, ok := requestModelRaw["identifier"].(string)
	if !ok || strings.TrimSpace(identifier) == "" {
		return result, fmt.Errorf("'requestModel.identifier' must be a non-empty string")
	}
	result.RequestModel = requestModelConfig{Location: location, Identifier: strings.TrimSpace(identifier)}
	if location == "pathParam" {
		expression, group, err := compilePathModelExpression(result.RequestModel.Identifier)
		if err != nil {
			return result, fmt.Errorf("'requestModel.identifier' is not a valid model path expression: %w", err)
		}
		result.RequestModel.PathExpression = expression
		result.RequestModel.PathModelGroup = group
	}

	return result, nil
}

func parseSchedule(item map[string]interface{}, index int) (schedule, error) {
	result := schedule{}
	if raw, exists := item["name"]; exists {
		name, ok := raw.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return result, fmt.Errorf("'schedules[%d].name' must be a non-empty string", index)
		}
		result.Name = strings.TrimSpace(name)
	}

	from, ok := item["from"].(string)
	if !ok {
		return result, fmt.Errorf("'schedules[%d].from' must be a string", index)
	}
	fromMinute, err := parseClockMinute(from)
	if err != nil {
		return result, fmt.Errorf("'schedules[%d].from' is invalid: %w", index, err)
	}
	to, ok := item["to"].(string)
	if !ok {
		return result, fmt.Errorf("'schedules[%d].to' must be a string", index)
	}
	toMinute, err := parseClockMinute(to)
	if err != nil {
		return result, fmt.Errorf("'schedules[%d].to' is invalid: %w", index, err)
	}
	if fromMinute == toMinute {
		return result, fmt.Errorf("'schedules[%d]' must not have the same from and to time", index)
	}
	result.FromMinute = fromMinute
	result.ToMinute = toMinute

	if raw, exists := item["days"]; exists {
		values, ok := raw.([]interface{})
		if !ok || len(values) == 0 {
			return result, fmt.Errorf("'schedules[%d].days' must be a non-empty array of strings", index)
		}
		result.Days = make(map[time.Weekday]struct{}, len(values))
		for dayIndex, value := range values {
			day, ok := value.(string)
			if !ok {
				return result, fmt.Errorf("'schedules[%d].days[%d]' must be a string", index, dayIndex)
			}
			weekday, err := parseWeekday(day)
			if err != nil {
				return result, fmt.Errorf("'schedules[%d].days[%d]' is invalid: %w", index, dayIndex, err)
			}
			if _, duplicate := result.Days[weekday]; duplicate {
				return result, fmt.Errorf("'schedules[%d].days[%d]' duplicates '%s'", index, dayIndex, day)
			}
			result.Days[weekday] = struct{}{}
		}
	}

	parsedTarget, err := parseTarget(item["target"], fmt.Sprintf("schedules[%d].target", index))
	if err != nil {
		return result, err
	}
	result.Target = parsedTarget
	return result, nil
}

func parseTarget(raw interface{}, field string) (target, error) {
	item, ok := raw.(map[string]interface{})
	if !ok {
		return target{}, fmt.Errorf("'%s' must be an object", field)
	}
	model, ok := item["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return target{}, fmt.Errorf("'%s.model' must be a non-empty string", field)
	}
	result := target{Model: strings.TrimSpace(model)}
	if rawProvider, exists := item["provider"]; exists {
		provider, ok := rawProvider.(string)
		if !ok || strings.TrimSpace(provider) == "" {
			return target{}, fmt.Errorf("'%s.provider' must be a non-empty string", field)
		}
		result.Provider = strings.TrimSpace(provider)
	}
	return result, nil
}

func parseClockMinute(value string) (int, error) {
	trimmed := strings.TrimSpace(value)
	parsed, err := time.Parse("15:04", trimmed)
	if err != nil {
		return 0, fmt.Errorf("expected HH:MM in 24-hour time")
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func parseWeekday(value string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	default:
		return time.Sunday, fmt.Errorf("expected weekday name")
	}
}

func validateNonOverlappingSchedules(schedules []schedule) error {
	for i := range schedules {
		for j := i + 1; j < len(schedules); j++ {
			if schedulesOverlap(schedules[i], schedules[j]) {
				return fmt.Errorf("'schedules[%d]' overlaps 'schedules[%d]'", i, j)
			}
		}
	}
	return nil
}

func schedulesOverlap(left, right schedule) bool {
	for _, leftRange := range expandWeekRanges(left) {
		for _, rightRange := range expandWeekRanges(right) {
			if leftRange[0] < rightRange[1] && rightRange[0] < leftRange[1] {
				return true
			}
		}
	}
	return false
}

func scheduleStartAppliesOn(item schedule, day time.Weekday) bool {
	if len(item.Days) == 0 {
		return true
	}
	_, ok := item.Days[day]
	return ok
}

func expandWeekRanges(item schedule) [][2]int {
	const minutesPerDay = 24 * 60
	const minutesPerWeek = 7 * minutesPerDay

	ranges := make([][2]int, 0, 14)
	for day := time.Sunday; day <= time.Saturday; day++ {
		if !scheduleStartAppliesOn(item, day) {
			continue
		}
		start := int(day)*minutesPerDay + item.FromMinute
		end := int(day)*minutesPerDay + item.ToMinute
		if item.FromMinute > item.ToMinute {
			end += minutesPerDay
		}
		if end <= minutesPerWeek {
			ranges = append(ranges, [2]int{start, end})
			continue
		}
		ranges = append(ranges, [2]int{start, minutesPerWeek})
		ranges = append(ranges, [2]int{0, end - minutesPerWeek})
	}
	return ranges
}

// compilePathModelExpression compiles a provider-template model expression once
// when the policy is attached. Expressions with a capture group replace the
// first captured value. Expressions with no capture group replace the complete
// match. A simple leading positive lookbehind is normalized because Go's RE2
// engine intentionally does not support lookbehind.
func compilePathModelExpression(expression string) (*regexp.Regexp, int, error) {
	const lookbehindPrefix = "(?<="
	normalized := expression
	modelGroupName := ""
	if strings.HasPrefix(expression, lookbehindPrefix) {
		closing := strings.Index(expression[len(lookbehindPrefix):], ")")
		if closing < 0 {
			return nil, 0, fmt.Errorf("unterminated positive lookbehind")
		}
		closing += len(lookbehindPrefix)
		prefix := expression[len(lookbehindPrefix):closing]
		suffix := expression[closing+1:]
		if prefix == "" || suffix == "" {
			return nil, 0, fmt.Errorf("positive lookbehind must contain a prefix and a model expression")
		}
		modelGroupName = "time_routing_model"
		normalized = "(?:" + prefix + ")(?P<" + modelGroupName + ">" + suffix + ")"
	}

	compiled, err := regexp.Compile(normalized)
	if err != nil {
		return nil, 0, err
	}
	if modelGroupName != "" {
		return compiled, compiled.SubexpIndex(modelGroupName), nil
	}
	if compiled.NumSubexp() > 0 {
		return compiled, 1, nil
	}
	return compiled, 0, nil
}
