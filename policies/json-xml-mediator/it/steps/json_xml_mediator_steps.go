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
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

// maxReportedDifferences bounds how many differences one failed comparison lists.
const maxReportedDifferences = 10

// maxQuotedDocument bounds how much of each document a failure message quotes.
const maxQuotedDocument = 512

// register binds the steps below. Add a step here only when no shared step expresses the
// behaviour, and give it a unit test in steps_test.go.
func register(sc *godog.ScenarioContext) {
	sc.Step(`^the response body should be XML equivalent to:$`, responseBodyXMLEquivalent)
	sc.Step(`^the JSON response field "([^"]*)" should be XML equivalent to:$`, jsonFieldXMLEquivalent)
}

// responseBodyXMLEquivalent asserts the published response body is the expected XML document,
// compared as xmlEquivalent describes.
func responseBodyXMLEquivalent(ctx context.Context, want *godog.DocString) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	expected, err := stepscommon.Expand(ctx, want.Content)
	if err != nil {
		return err
	}
	if err := xmlEquivalent(expected, resp.Text()); err != nil {
		return fmt.Errorf("response body: %w (%s)", err, resp.Describe())
	}
	return nil
}

// jsonFieldXMLEquivalent asserts a string field of the published JSON response, such as the
// body a capture lookup reports, is the expected XML document.
func jsonFieldXMLEquivalent(ctx context.Context, field string, want *godog.DocString) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	got, err := jsonStringField(resp.Body, field)
	if err != nil {
		return fmt.Errorf("%w (%s)", err, resp.Describe())
	}
	expected, err := stepscommon.Expand(ctx, want.Content)
	if err != nil {
		return err
	}
	if err := xmlEquivalent(expected, got); err != nil {
		return fmt.Errorf("JSON field %q: %w (%s)", field, err, resp.Describe())
	}
	return nil
}

// xmlElement is one element of a parsed document: its name, its attributes, its text and its
// child elements in document order. An element without children keeps its text exactly; an
// element with children keeps its text trimmed, so the whitespace that lays out a document does
// not count.
type xmlElement struct {
	name     string
	attrs    map[string]string
	text     string
	children []*xmlElement
}

// xmlEquivalent reports whether got is the document want describes. Both must be one
// well-formed element, optionally after an XML declaration, with nothing but whitespace and
// comments around it. Element names, attributes (in any order, each at most once) and text must
// match; the text of an element without children is compared exactly. Children with the same
// name must sit next to each other and match in order, as the policy writes a JSON array's items;
// groups with different names may come in any order, because the policy writes a JSON object's
// keys in no fixed order.
func xmlEquivalent(want, got string) error {
	wantRoot, err := parseXMLDocument(want)
	if err != nil {
		return fmt.Errorf("the expected document is not usable: %w", err)
	}
	gotRoot, err := parseXMLDocument(got)
	if err != nil {
		return fmt.Errorf("not a well-formed XML document: %w; got %s", err, quote(got))
	}
	differences := xmlDifferences(wantRoot, gotRoot, "", -1)
	if len(differences) == 0 {
		return nil
	}
	if len(differences) > maxReportedDifferences {
		omitted := len(differences) - maxReportedDifferences
		differences = append(differences[:maxReportedDifferences], fmt.Sprintf("%d more", omitted))
	}
	return fmt.Errorf("XML differs: %s; want %s, got %s",
		strings.Join(differences, "; "), quote(want), quote(got))
}

// parseXMLDocument reads one root element with the strict decoder, refusing anything but
// whitespace and comments outside it, and processing instructions other than a leading XML
// declaration.
func parseXMLDocument(document string) (*xmlElement, error) {
	decoder := xml.NewDecoder(strings.NewReader(document))
	var root *xmlElement
	var open []*xmlElement
	var text []*strings.Builder
	for first := true; ; first = false {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.ProcInst:
			if !first || t.Target != "xml" {
				return nil, fmt.Errorf("processing instruction <?%s?> is not supported here", t.Target)
			}
		case xml.StartElement:
			if len(open) == 0 && root != nil {
				return nil, fmt.Errorf("element <%s> after the root element", t.Name.Local)
			}
			element := &xmlElement{name: qualifiedName(t.Name), attrs: map[string]string{}}
			for _, attr := range t.Attr {
				name := qualifiedName(attr.Name)
				if _, repeated := element.attrs[name]; repeated {
					return nil, fmt.Errorf("attribute %s repeated on <%s>", name, element.name)
				}
				element.attrs[name] = attr.Value
			}
			if len(open) == 0 {
				root = element
			} else {
				parent := open[len(open)-1]
				parent.children = append(parent.children, element)
			}
			open = append(open, element)
			text = append(text, &strings.Builder{})
		case xml.EndElement:
			last := len(open) - 1
			open[last].text = text[last].String()
			if len(open[last].children) > 0 {
				open[last].text = strings.TrimSpace(open[last].text)
			}
			open, text = open[:last], text[:last]
		case xml.CharData:
			if len(open) == 0 {
				if len(bytes.TrimSpace(t)) > 0 {
					return nil, fmt.Errorf("text %q outside the root element", string(t))
				}
				continue
			}
			text[len(text)-1].Write(t)
		case xml.Directive:
			return nil, fmt.Errorf("directive <!%s> is not supported", string(t))
		}
	}
	if root == nil {
		return nil, fmt.Errorf("no root element")
	}
	return root, nil
}

// qualifiedName keeps the namespace so that elements differing only by namespace differ.
func qualifiedName(name xml.Name) string {
	if name.Space == "" {
		return name.Local
	}
	return "{" + name.Space + "}" + name.Local
}

// xmlDifferences lists how got differs from want, each entry naming the element's path. index is
// the element's position among its same-name siblings, or -1 when it has none.
func xmlDifferences(want, got *xmlElement, parent string, index int) []string {
	path := parent + "/" + want.name
	if index >= 0 {
		path = fmt.Sprintf("%s[%d]", path, index)
	}
	if want.name != got.name {
		return []string{fmt.Sprintf("%s: element is <%s>", path, got.name)}
	}
	var differences []string
	for _, name := range slices.Sorted(maps.Keys(want.attrs)) {
		value, ok := got.attrs[name]
		switch {
		case !ok:
			differences = append(differences, fmt.Sprintf("%s: attribute %s missing", path, name))
		case value != want.attrs[name]:
			differences = append(differences, fmt.Sprintf("%s: attribute %s is %q, want %q", path, name, value, want.attrs[name]))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(got.attrs)) {
		if _, ok := want.attrs[name]; !ok {
			differences = append(differences, fmt.Sprintf("%s: unexpected attribute %s", path, name))
		}
	}
	if want.text != got.text {
		differences = append(differences, fmt.Sprintf("%s: text is %s, want %s", path, quote(got.text), quote(want.text)))
	}

	for _, name := range scatteredNames(got) {
		differences = append(differences, fmt.Sprintf("%s: <%s> elements are not next to each other", path, name))
	}
	wantGroups, gotGroups := childrenByName(want), childrenByName(got)
	for _, name := range slices.Sorted(maps.Keys(wantGroups)) {
		wantChildren, gotChildren := wantGroups[name], gotGroups[name]
		if len(wantChildren) != len(gotChildren) {
			differences = append(differences, fmt.Sprintf("%s: %d <%s> elements, want %d", path, len(gotChildren), name, len(wantChildren)))
			continue
		}
		for i := range wantChildren {
			childIndex := -1
			if len(wantChildren) > 1 {
				childIndex = i
			}
			differences = append(differences, xmlDifferences(wantChildren[i], gotChildren[i], path, childIndex)...)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(gotGroups)) {
		if _, ok := wantGroups[name]; !ok {
			differences = append(differences, fmt.Sprintf("%s: unexpected <%s> elements (%d)", path, name, len(gotGroups[name])))
		}
	}
	return differences
}

// scatteredNames lists, in order, the names whose same-name children another name separates.
func scatteredNames(element *xmlElement) []string {
	closed := map[string]bool{}
	var scattered []string
	for i, child := range element.children {
		if closed[child.name] && !slices.Contains(scattered, child.name) {
			scattered = append(scattered, child.name)
		}
		if i+1 < len(element.children) && element.children[i+1].name != child.name {
			closed[child.name] = true
		}
	}
	return scattered
}

// childrenByName groups an element's children by name, keeping document order in each group.
func childrenByName(element *xmlElement) map[string][]*xmlElement {
	groups := map[string][]*xmlElement{}
	for _, child := range element.children {
		groups[child.name] = append(groups[child.name], child)
	}
	return groups
}

// jsonStringField returns the string at a dotted path ("body", "a.b", "items[0].name") of a JSON
// object.
func jsonStringField(body []byte, field string) (string, error) {
	var current any
	if err := json.Unmarshal(body, &current); err != nil {
		return "", fmt.Errorf("the response is not JSON: %w", err)
	}
	for _, segment := range strings.Split(field, ".") {
		if segment == "" {
			return "", fmt.Errorf("JSON field %q has an empty segment", field)
		}
		name, indices := stepscommon.SplitIndices(segment)
		if name != "" {
			object, ok := current.(map[string]any)
			if !ok {
				return "", fmt.Errorf("JSON field %q: %q is not inside an object", field, name)
			}
			if current, ok = object[name]; !ok {
				return "", fmt.Errorf("JSON field %q is absent", field)
			}
		}
		for _, index := range indices {
			array, ok := current.([]any)
			if !ok || index < 0 || index >= len(array) {
				return "", fmt.Errorf("JSON field %q: index %d is out of range", field, index)
			}
			current = array[index]
		}
	}
	text, ok := current.(string)
	if !ok {
		return "", fmt.Errorf("JSON field %q holds %T, not a string", field, current)
	}
	return text, nil
}

// quote renders a value for a failure message, cut to maxQuotedDocument bytes.
func quote(value string) string {
	if len(value) > maxQuotedDocument {
		return fmt.Sprintf("%q… (%d bytes)", value[:maxQuotedDocument], len(value))
	}
	return fmt.Sprintf("%q", value)
}
