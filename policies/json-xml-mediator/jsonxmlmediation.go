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

package jsonxmlmediation

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	upstreamPayloadFormatXML  = "xml"
	upstreamPayloadFormatJSON = "json"
)

// JSONXMLMediationPolicy mediates request/response payloads between JSON and XML.
type JSONXMLMediationPolicy struct {
	upstreamPayloadFormat   string
	downstreamPayloadFormat string
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	upstreamPayloadFormat, err := getUpstreamPayloadFormat(params)
	if err != nil {
		return nil, err
	}

	downstreamPayloadFormat, err := getDownstreamPayloadFormat(params)
	if err != nil {
		return nil, err
	}
	if downstreamPayloadFormat == upstreamPayloadFormat {
		return nil, fmt.Errorf("Invalid policy configuration: downsteamPayloadFormat must be different from upstreamPayloadFormat")
	}

	return &JSONXMLMediationPolicy{
		upstreamPayloadFormat:   upstreamPayloadFormat,
		downstreamPayloadFormat: downstreamPayloadFormat,
	}, nil
}

// Mode returns the processing mode for this policy.
func (p *JSONXMLMediationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequest applies conversion to match the configured upstream payload format.
func (p *JSONXMLMediationPolicy) OnRequest(ctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if ctx.Body == nil || !ctx.Body.Present || len(ctx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	contentType := getFirstHeader(ctx.Headers, "content-type")

	if !matchesContentType(contentType, p.downstreamPayloadFormat) {
		return p.handleInternalServerError(fmt.Sprintf(
			"Content-Type must be %s for downstream payload format %s",
			expectedContentTypeMessage(p.downstreamPayloadFormat),
			p.downstreamPayloadFormat,
		))
	}

	if p.downstreamPayloadFormat == p.upstreamPayloadFormat {
		return policy.UpstreamRequestModifications{}
	}

	convertedBody, convertedContentType, convErr := p.convertBetweenFormats(
		ctx.Body.Content,
		p.downstreamPayloadFormat,
		p.upstreamPayloadFormat,
	)
	if convErr != nil {
		return p.handleInternalServerError(convErr.Error())
	}

	return policy.UpstreamRequestModifications{
		Body: convertedBody,
		SetHeaders: map[string]string{
			"content-type":   convertedContentType,
			"content-length": fmt.Sprintf("%d", len(convertedBody)),
		},
	}
}

// OnResponse mediates the upstream response to the configured downstream payload format.
func (p *JSONXMLMediationPolicy) OnResponse(ctx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if ctx.ResponseBody == nil || !ctx.ResponseBody.Present || len(ctx.ResponseBody.Content) == 0 {
		return policy.UpstreamResponseModifications{}
	}

	contentType := getFirstHeader(ctx.ResponseHeaders, "content-type")

	if !matchesContentType(contentType, p.upstreamPayloadFormat) {
		return p.handleInternalServerErrorResponse(fmt.Sprintf(
			"Content-Type must be %s in response for upstream payload format %s",
			expectedContentTypeMessage(p.upstreamPayloadFormat),
			p.upstreamPayloadFormat,
		))
	}

	if p.upstreamPayloadFormat == p.downstreamPayloadFormat {
		return policy.UpstreamResponseModifications{}
	}

	convertedBody, convertedContentType, convErr := p.convertBetweenFormats(
		ctx.ResponseBody.Content,
		p.upstreamPayloadFormat,
		p.downstreamPayloadFormat,
	)
	if convErr != nil {
		return p.handleInternalServerErrorResponse(convErr.Error())
	}

	return policy.UpstreamResponseModifications{
		Body: convertedBody,
		SetHeaders: map[string]string{
			"content-type":   convertedContentType,
			"content-length": fmt.Sprintf("%d", len(convertedBody)),
		},
	}
}

func getUpstreamPayloadFormat(params map[string]interface{}) (string, error) {
	upstreamPayloadFormat, _, err := getPayloadFormat(params, "upstreamPayloadFormat", true)
	return upstreamPayloadFormat, err
}

func getDownstreamPayloadFormat(params map[string]interface{}) (string, error) {
	downstreamPayloadFormat, _, err := getPayloadFormat(params, "downsteamPayloadFormat", true)
	return downstreamPayloadFormat, err
}

func getPayloadFormat(params map[string]interface{}, key string, required bool) (string, bool, error) {
	if params == nil {
		if required {
			return "", false, fmt.Errorf("Invalid policy configuration: %s must be a non-empty string", key)
		}
		return "", false, nil
	}

	payloadFormatRaw, ok := params[key]
	if !ok {
		if required {
			return "", false, fmt.Errorf("Invalid policy configuration: %s must be a non-empty string", key)
		}
		return "", false, nil
	}

	payloadFormat, ok := payloadFormatRaw.(string)
	if !ok || strings.TrimSpace(payloadFormat) == "" {
		return "", true, fmt.Errorf("Invalid policy configuration: %s must be a non-empty string", key)
	}

	normalized := strings.ToLower(strings.TrimSpace(payloadFormat))
	if normalized != upstreamPayloadFormatXML && normalized != upstreamPayloadFormatJSON {
		return "", true, fmt.Errorf("Invalid policy configuration: %s must be one of [xml, json]", key)
	}

	return normalized, true, nil
}

func getFirstHeader(headers *policy.Headers, key string) string {
	if headers == nil {
		return ""
	}

	vals := headers.Get(key)
	if len(vals) == 0 {
		return ""
	}

	return strings.ToLower(vals[0])
}

func matchesContentType(contentType, payloadFormat string) bool {
	switch payloadFormat {
	case upstreamPayloadFormatXML:
		return strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml")
	case upstreamPayloadFormatJSON:
		return strings.Contains(contentType, "application/json")
	default:
		return false
	}
}

func expectedContentTypeMessage(payloadFormat string) string {
	switch payloadFormat {
	case upstreamPayloadFormatXML:
		return "application/xml or text/xml"
	case upstreamPayloadFormatJSON:
		return "application/json"
	default:
		return "a supported content type"
	}
}

func canonicalContentType(payloadFormat string) string {
	if payloadFormat == upstreamPayloadFormatXML {
		return "application/xml"
	}
	return "application/json"
}

func (p *JSONXMLMediationPolicy) convertBetweenFormats(body []byte, sourceFormat, targetFormat string) ([]byte, string, error) {
	switch {
	case sourceFormat == upstreamPayloadFormatJSON && targetFormat == upstreamPayloadFormatXML:
		xmlData, err := p.convertJSONBytesToXML(body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to convert JSON to XML format: %w", err)
		}
		return xmlData, canonicalContentType(targetFormat), nil
	case sourceFormat == upstreamPayloadFormatXML && targetFormat == upstreamPayloadFormatJSON:
		jsonData, err := p.convertXMLToJSON(body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to convert XML to JSON format: %w", err)
		}
		return jsonData, canonicalContentType(targetFormat), nil
	default:
		return nil, "", fmt.Errorf("unsupported payload mediation from %s to %s", sourceFormat, targetFormat)
	}
}

func (p *JSONXMLMediationPolicy) handleInternalServerError(message string) policy.RequestAction {
	errorResponse := map[string]interface{}{
		"error":   "Internal Server Error",
		"message": message,
	}
	bodyBytes, _ := json.Marshal(errorResponse)

	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"content-type":   "application/json",
			"content-length": fmt.Sprintf("%d", len(bodyBytes)),
		},
		Body: bodyBytes,
	}
}

func (p *JSONXMLMediationPolicy) handleInternalServerErrorResponse(message string) policy.ResponseAction {
	errorResponse := map[string]interface{}{
		"error":   "Internal Server Error",
		"message": message,
	}
	bodyBytes, _ := json.Marshal(errorResponse)

	statusCode := 500
	return policy.UpstreamResponseModifications{
		StatusCode: &statusCode,
		Body:       bodyBytes,
		SetHeaders: map[string]string{
			"content-type":   "application/json",
			"content-length": fmt.Sprintf("%d", len(bodyBytes)),
		},
	}
}

func (p *JSONXMLMediationPolicy) convertJSONBytesToXML(body []byte) ([]byte, error) {
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return nil, err
	}
	return p.convertJSONToXML(jsonData)
}

func (p *JSONXMLMediationPolicy) convertJSONToXML(jsonData interface{}) ([]byte, error) {
	xmlStruct := p.buildXMLStruct(jsonData, "root")
	xmlData, err := xml.MarshalIndent(xmlStruct, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to XML: %w", err)
	}
	return xmlData, nil
}

func (p *JSONXMLMediationPolicy) buildXMLStruct(data interface{}, tagName string) XMLElement {
	sanitizedTagName := p.sanitizeTagName(tagName)
	element := XMLElement{XMLName: xml.Name{Local: sanitizedTagName}}

	if sanitizedTagName != tagName && tagName != "root" {
		element.OriginalKey = tagName
	}

	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if arr, isArray := value.([]interface{}); isArray {
				for _, item := range arr {
					childElement := p.buildXMLStruct(item, key)
					element.Children = append(element.Children, childElement)
				}
			} else {
				childElement := p.buildXMLStruct(value, key)
				element.Children = append(element.Children, childElement)
			}
		}
	case []interface{}:
		for _, item := range v {
			childElement := p.buildXMLStruct(item, tagName)
			element.Children = append(element.Children, childElement)
		}
	case string:
		element.Content = v
	case float64:
		element.Content = fmt.Sprintf("%g", v)
	case bool:
		element.Content = fmt.Sprintf("%t", v)
	case nil:
		element.Content = ""
	default:
		element.Content = fmt.Sprintf("%v", v)
	}

	return element
}

func (p *JSONXMLMediationPolicy) sanitizeTagName(name string) string {
	if name == "" {
		return "empty"
	}

	runes := []rune(name)
	result := make([]rune, 0, len(runes))

	for i, r := range runes {
		if i == 0 {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || unicode.IsLetter(r) {
				result = append(result, r)
			} else {
				result = append(result, '_')
				if isValidNCNameChar(r) {
					result = append(result, r)
				}
			}
		} else {
			if isValidNCNameChar(r) {
				result = append(result, r)
			} else {
				result = append(result, '_')
			}
		}
	}

	if len(result) == 0 {
		return "element"
	}

	return string(result)
}

func isValidNCNameChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '_' ||
		r == '-' ||
		r == '.' ||
		unicode.IsLetter(r)
}

func (p *JSONXMLMediationPolicy) convertXMLToJSON(xmlData []byte) ([]byte, error) {
	var node XMLNode
	err := xml.Unmarshal(xmlData, &node)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	jsonData := p.nodeToMap(node)

	result, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	return result, nil
}

func (p *JSONXMLMediationPolicy) nodeToMap(node XMLNode) interface{} {
	result := make(map[string]interface{})
	result[node.XMLName.Local] = p.processXMLNode(node)
	return result
}

func (p *JSONXMLMediationPolicy) processXMLNode(node XMLNode) interface{} {
	if len(node.Nodes) == 0 && len(node.Attrs) == 0 {
		content := strings.TrimSpace(node.Content)
		if content == "" {
			return nil
		}
		return p.parseValue(content)
	}

	result := make(map[string]interface{})

	for _, attr := range node.Attrs {
		result["@"+attr.Name.Local] = p.parseAttributeValue(attr.Value)
	}

	childGroups := make(map[string][]XMLNode)
	for _, child := range node.Nodes {
		name := child.XMLName.Local
		childGroups[name] = append(childGroups[name], child)
	}

	for name, children := range childGroups {
		if len(children) == 1 {
			result[name] = p.processXMLNode(children[0])
		} else {
			array := make([]interface{}, len(children))
			for i, child := range children {
				array[i] = p.processXMLNode(child)
			}
			result[name] = array
		}
	}

	content := strings.TrimSpace(node.Content)
	if content != "" && len(result) > 0 {
		result["#text"] = p.parseValue(content)
	} else if content != "" && len(result) == 0 {
		return p.parseValue(content)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func (p *JSONXMLMediationPolicy) parseAttributeValue(value string) interface{} {
	return p.parseValue(value)
}

func (p *JSONXMLMediationPolicy) parseValue(value string) interface{} {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if value == "true" {
		return true
	}
	if value == "false" {
		return false
	}

	if intVal, err := strconv.Atoi(value); err == nil {
		return intVal
	}
	if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
		if strings.Contains(value, ".") {
			return floatVal
		}
	}

	return value
}

// XMLElement represents a generic XML element for marshaling.
type XMLElement struct {
	XMLName     xml.Name     `xml:""`
	OriginalKey string       `xml:"originalKey,attr,omitempty"`
	Content     string       `xml:",chardata"`
	Children    []XMLElement `xml:",any"`
}

// XMLNode represents a generic XML node for parsing.
type XMLNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Content string     `xml:",chardata"`
	Nodes   []XMLNode  `xml:",any"`
}
