/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * Licensed under the Apache License, Version 2.0.
 */

package contextbasedrouting

import (
	"fmt"
	"strings"
	"unicode/utf8"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

var defaultInputJSONPaths = []string{"$.messages", "$.prompt", "$.input", "$.contents", "$.system", "$.tools", "$.functions"}

func estimateInputTokens(payload map[string]interface{}, charsPerToken int64, inputJSONPaths []string) (int64, error) {
	var characters int64
	found := false
	for _, jsonPath := range inputJSONPaths {
		value, err := utils.ExtractValueFromJsonpath(payload, jsonPath)
		if err != nil {
			continue
		}
		found = true
		characters += countStringCharacters(value)
	}
	if !found {
		return 0, fmt.Errorf("none of the configured input JSONPaths matched the request payload")
	}
	if characters == 0 {
		return 0, nil
	}
	return (characters + charsPerToken - 1) / charsPerToken, nil
}

func countStringCharacters(value interface{}) int64 {
	switch typed := value.(type) {
	case string:
		// Multimodal requests can embed megabytes of binary image/audio data in
		// base64 data URLs. Those bytes are not text tokens and must not force a
		// request into an oversized-context route.
		if isEmbeddedDataURL(typed) {
			return 0
		}
		return int64(utf8.RuneCountInString(typed))
	case []interface{}:
		var total int64
		for _, item := range typed {
			total += countStringCharacters(item)
		}
		return total
	case map[string]interface{}:
		var total int64
		for _, item := range typed {
			total += countStringCharacters(item)
		}
		return total
	default:
		return 0
	}
}

func isEmbeddedDataURL(value string) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "data:") {
		return false
	}
	header, _, found := strings.Cut(value, ",")
	return found && strings.Contains(strings.ToLower(header), ";base64")
}
