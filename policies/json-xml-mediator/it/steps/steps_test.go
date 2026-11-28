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
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

func TestXMLEquivalentAcceptsTheSameDocument(t *testing.T) {
	for name, pair := range map[string][2]string{
		"identical":                  {`<root><a>1</a></root>`, `<root><a>1</a></root>`},
		"different names reordered":  {`<root><a>1</a><b>2</b></root>`, `<root><b>2</b><a>1</a></root>`},
		"declaration on one side":    {`<?xml version="1.0" encoding="UTF-8"?><root/>`, `<root></root>`},
		"layout whitespace":          {"\n<root>\n  <a>1</a>\n  <b> </b>\n</root>\n", `<root><b> </b><a>1</a></root>`},
		"attributes reordered":       {`<a x="1" y="2"/>`, `<a y="2" x="1"/>`},
		"empty element forms":        {`<root><note/></root>`, `<root><note></note></root>`},
		"escaped and literal text":   {`<a>&lt;b&gt;&amp;</a>`, `<a><![CDATA[<b>&]]></a>`},
		"comment outside the root":   {`<!-- c --><a/>`, `<a/>`},
		"groups reordered, in order": {`<r><i>1</i><i>2</i><n>x</n></r>`, `<r><n>x</n><i>1</i><i>2</i></r>`},
	} {
		if err := xmlEquivalent(pair[0], pair[1]); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestXMLEquivalentRejectsADifferentDocument(t *testing.T) {
	for name, tc := range map[string]struct{ want, got, message string }{
		"root name":                {`<root/>`, `<other/>`, "/root: element is <other>"},
		"text":                     {`<r><a>1</a></r>`, `<r><a>2</a></r>`, `/r/a: text is "2", want "1"`},
		"missing child":            {`<r><a/><b/></r>`, `<r><a/></r>`, "/r: 0 <b> elements, want 1"},
		"extra child":              {`<r><a/></r>`, `<r><a/><b/></r>`, "/r: unexpected <b> elements (1)"},
		"same names out of order":  {`<r><i>1</i><i>2</i></r>`, `<r><i>2</i><i>1</i></r>`, `/r/i[0]: text is "2", want "1"`},
		"second of a group":        {`<r><i>1</i><i>2</i></r>`, `<r><i>1</i><i>3</i></r>`, `/r/i[1]: text is "3", want "2"`},
		"padded text":              {`<r><a>x</a></r>`, `<r><a> x </a></r>`, `/r/a: text is " x ", want "x"`},
		"newline for empty":        {`<r><a/></r>`, "<r><a>\n</a></r>", `/r/a: text is "\n", want ""`},
		"group split":              {`<r><i>1</i><i>2</i><n/></r>`, `<r><i>1</i><n/><i>2</i></r>`, "/r: <i> elements are not next to each other"},
		"duplicate attribute":      {`<a x="2"/>`, `<a x="1" x="2"/>`, "attribute x repeated on <a>"},
		"declaration after root":   {`<a/>`, `<a/><?xml version="1.0"?>`, "processing instruction <?xml?> is not supported here"},
		"instruction in the root":  {`<a/>`, `<a><?pi x?></a>`, "processing instruction <?pi?> is not supported here"},
		"leading instruction":      {`<a/>`, `<?pi x?><a/>`, "processing instruction <?pi?> is not supported here"},
		"repeat count":             {`<r><i/><i/></r>`, `<r><i/></r>`, "/r: 1 <i> elements, want 2"},
		"missing attribute":        {`<a x="1"/>`, `<a/>`, "/a: attribute x missing"},
		"extra attribute":          {`<a/>`, `<a x="1"/>`, "/a: unexpected attribute x"},
		"attribute value":          {`<a x="1"/>`, `<a x="2"/>`, `/a: attribute x is "2", want "1"`},
		"nested path":              {`<r><o><p>1</p></o></r>`, `<r><o><p>2</p></o></r>`, `/r/o/p: text is "2", want "1"`},
		"text beside children":     {`<r>t<a/></r>`, `<r><a/></r>`, `/r: text is "", want "t"`},
		"namespace":                {`<a xmlns="urn:x"/>`, `<a/>`, "element is <a>"},
		"malformed":                {`<a/>`, `<a>`, "not a well-formed XML document"},
		"second root":              {`<a/>`, `<a/><b/>`, "element <b> after the root element"},
		"text after the root":      {`<a/>`, `<a/>tail`, `text "tail" outside the root element`},
		"text before the root":     {`<a/>`, `head<a/>`, `text "head" outside the root element`},
		"empty document":           {`<a/>`, ``, "no root element"},
		"JSON instead of XML":      {`<a/>`, `{"a":1}`, "outside the root element"},
		"doctype":                  {`<a/>`, `<!DOCTYPE a><a/>`, "directive"},
		"unusable expected":        {`<a>`, `<a/>`, "the expected document is not usable"},
		"undefined entity":         {`<a/>`, `<a>&x;</a>`, "not a well-formed XML document"},
		"closing tag mismatch":     {`<a/>`, `<a></b>`, "not a well-formed XML document"},
		"empty versus whitespace":  {`<a>x</a>`, `<a> </a>`, `/a: text is " ", want "x"`},
		"child versus text":        {`<a><b/></a>`, `<a>b</a>`, "/a: 0 <b> elements, want 1"},
		"different element counts": {`<r><a/><a/><a/></r>`, `<r><a/><a/></r>`, "/r: 2 <a> elements, want 3"},
	} {
		err := xmlEquivalent(tc.want, tc.got)
		if err == nil {
			t.Errorf("%s: no error for want %q got %q", name, tc.want, tc.got)
			continue
		}
		if !strings.Contains(err.Error(), tc.message) {
			t.Errorf("%s: error %q does not contain %q", name, err, tc.message)
		}
	}
}

func TestXMLEquivalentBoundsItsFailureMessage(t *testing.T) {
	var want, got strings.Builder
	want.WriteString("<r>")
	got.WriteString("<r>")
	for range 15 {
		want.WriteString("<a>1</a>")
	}
	for range 15 {
		got.WriteString("<b>1</b>")
	}
	for range 200 {
		got.WriteString("<c>" + strings.Repeat("x", 10) + "</c>")
	}
	want.WriteString("</r>")
	got.WriteString("</r>")

	err := xmlEquivalent(want.String(), got.String())
	if err == nil {
		t.Fatal("no error for different documents")
	}
	if !strings.Contains(err.Error(), "… (") {
		t.Errorf("the long document is not truncated: %d bytes", len(err.Error()))
	}
	if len(err.Error()) > 4*maxQuotedDocument {
		t.Errorf("the message is %d bytes, want at most %d", len(err.Error()), 4*maxQuotedDocument)
	}
}

func TestXMLEquivalentReportsAtMostTheDifferenceLimit(t *testing.T) {
	var want, got strings.Builder
	want.WriteString("<r>")
	got.WriteString("<r>")
	for i := range maxReportedDifferences + 5 {
		name := "e" + strings.Repeat("x", i)
		want.WriteString("<" + name + ">1</" + name + ">")
		got.WriteString("<" + name + ">2</" + name + ">")
	}
	want.WriteString("</r>")
	got.WriteString("</r>")

	err := xmlEquivalent(want.String(), got.String())
	if err == nil {
		t.Fatal("no error for different documents")
	}
	if !strings.Contains(err.Error(), "; 5 more") {
		t.Errorf("error does not say how many differences were left out: %v", err)
	}
}

func TestJSONStringField(t *testing.T) {
	body := []byte(`{"body":"<a/>","nested":{"inner":"x"},"items":[{"name":"n0"}],"count":3,"none":null}`)
	for field, want := range map[string]string{"body": "<a/>", "nested.inner": "x", "items[0].name": "n0"} {
		got, err := jsonStringField(body, field)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", field, got, err, want)
		}
	}
	for field, message := range map[string]string{
		"missing":       "is absent",
		"count":         "not a string",
		"none":          "not a string",
		"nested":        "not a string",
		"items[3].name": "out of range",
		"body.inner":    "is not inside an object",
		"nested..inner": "empty segment",
	} {
		_, err := jsonStringField(body, field)
		if err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: error %v, want one containing %q", field, err, message)
		}
	}
	if _, err := jsonStringField([]byte("<a/>"), "body"); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("non-JSON body: error %v", err)
	}
}

func newScenarioContext(t *testing.T, body string) context.Context {
	t.Helper()
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("test-runner"))
	funnel := httpx.NewFunnel(httpx.NewClient(httpx.Options{}), 0, 0)
	if err := funnel.Publish(ctx, &httpx.Response{StatusCode: 200, Body: []byte(body), Method: "GET", URL: "http://test"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return ctx
}

func TestResponseBodyXMLEquivalentReadsThePublishedResponse(t *testing.T) {
	ctx := newScenarioContext(t, `<root><b>2</b><a>1</a></root>`)
	if err := responseBodyXMLEquivalent(ctx, &godog.DocString{Content: `<root><a>1</a><b>2</b></root>`}); err != nil {
		t.Errorf("equivalent body: %v", err)
	}
	if err := responseBodyXMLEquivalent(ctx, &godog.DocString{Content: `<root><a>9</a><b>2</b></root>`}); err == nil {
		t.Error("no error for a different body")
	}
}

func TestResponseBodyXMLEquivalentFailsWithoutAPublishedResponse(t *testing.T) {
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("test-runner"))
	if err := responseBodyXMLEquivalent(ctx, &godog.DocString{Content: `<a/>`}); err == nil {
		t.Error("no error without a published response")
	}
}

func TestJSONFieldXMLEquivalentReadsTheFieldAndExpandsContextValues(t *testing.T) {
	ctx := newScenarioContext(t, `{"body":"<root><note>xxxx</note><sku>W-1</sku></root>"}`)
	if err := tcontext.Set(ctx, "big", "xxxx"); err != nil {
		t.Fatalf("set context value: %v", err)
	}
	if err := jsonFieldXMLEquivalent(ctx, "body", &godog.DocString{Content: `<root><sku>W-1</sku><note>${CTX:big}</note></root>`}); err != nil {
		t.Errorf("equivalent field: %v", err)
	}
	err := jsonFieldXMLEquivalent(ctx, "body", &godog.DocString{Content: `<root><sku>G-2</sku><note>xxxx</note></root>`})
	if err == nil || !strings.Contains(err.Error(), `JSON field "body"`) || !strings.Contains(err.Error(), "http://test") {
		t.Errorf("different field: error %v, want the field and the request it came from", err)
	}
	if err := jsonFieldXMLEquivalent(ctx, "missing", &godog.DocString{Content: `<a/>`}); err == nil {
		t.Error("no error for a missing field")
	}
}
