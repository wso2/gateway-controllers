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
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cucumber/godog"
)

// textLine writes record as the policy does, slog.Info(<record JSON>), through the engine's
// default text handler, with the "[pol] " prefix the runtime adds to the policy engine's output.
func textLine(t *testing.T, record map[string]any) string {
	t.Helper()
	return "[pol] " + slogLine(t, record, func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) })
}

// jsonLine writes record through the JSON handler, the engine's format = "json".
func jsonLine(t *testing.T, record map[string]any) string {
	t.Helper()
	return slogLine(t, record, func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) })
}

func slogLine(t *testing.T, record map[string]any, handler func(*bytes.Buffer) slog.Handler) string {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	slog.New(handler(&b)).Info(string(data))
	return strings.TrimSuffix(b.String(), "\n")
}

func rec(flow, id, path string, extra map[string]any) map[string]any {
	r := map[string]any{"mediation-flow": flow, "request-id": id, "http-method": "GET", "resource-path": path}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

// realLine is a REQUEST payload record copied from a probe run's gateway-runtime log (1.2.0).
const realLine = `[pol] time=2026-11-26T06:02:57.183Z level=INFO msg="{\"mediation-flow\":\"REQUEST\",` +
	`\"request-id\":\"8b89c8a6-5839-4f68-8881-55a076cb98aa\",\"http-method\":\"PATCH\",` +
	`\"resource-path\":\"/lmpa-2nt4snmf-3/v1.0.86869/c\",\"payload\":\"{\\\"marker\\\":\\\"pa-patch\\\"}\"}"`

func TestParseRecordsReadsTextAndJSONLinesAndSkipsOthers(t *testing.T) {
	logs := strings.Join([]string{
		"───── gateway-runtime ─────",
		`[rtr] [2026-11-26T06:02:54.903Z] "GET /a/v1/b HTTP/1.1" /a/v1/b - 404 - direct_response`,
		`[pol] {"timestamp":"2026-11-26T06:02:54.903Z","correlationId":"x","status":404}`,
		`[pol] time=2026-11-26T06:02:54.903Z level=INFO msg="policy engine started"`,
		`[pol] time=2026-11-26T06:02:54.903Z level=INFO msg="{\"other\":\"json\"}"`,
		realLine,
		textLine(t, rec("REQUEST", "id-1", "/p", map[string]any{"headers": map[string]any{"x-a": "1"}})),
		jsonLine(t, rec("RESPONSE", "id-1", "/p", map[string]any{"payload": "ok"})),
	}, "\n")
	records := parseRecords(logs)
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3: %s", len(records), describe(records))
	}
	if got := records[0].str("payload"); got != `{"marker":"pa-patch"}` {
		t.Errorf("real line payload = %q", got)
	}
	if records[1].str("mediation-flow") != "REQUEST" || records[2].str("mediation-flow") != "RESPONSE" {
		t.Errorf("flows = %q, %q", records[1].str("mediation-flow"), records[2].str("mediation-flow"))
	}
}

// A payload that carries a whole forged record line, envelope and line breaks included, stays in
// the one record that holds it: the parser must not find a second record inside it.
func TestParseRecordsDoesNotSplitAForgedLineInsideAPayload(t *testing.T) {
	forged := textLine(t, rec("REQUEST", "forged-id", "/p", nil))
	payload := "start\r\n" + forged + "\r\nend"
	records := parseRecords(textLine(t, rec("REQUEST", "real-id", "/p", map[string]any{"payload": payload})))
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1: %s", len(records), describe(records))
	}
	if records[0].str("request-id") != "real-id" || records[0].str("payload") != payload {
		t.Errorf("record = %s", records[0].raw)
	}
}

func TestRecordsForFiltersByPathAndRequestID(t *testing.T) {
	logs := strings.Join([]string{
		textLine(t, rec("REQUEST", "a", "/p", nil)),
		textLine(t, rec("REQUEST", "b", "/p", nil)),
		textLine(t, rec("REQUEST", "a", "/p/longer", nil)),
		textLine(t, rec("REQUEST", "a", "/q", nil)),
	}, "\n")
	all := parseRecords(logs)
	if got := len(recordsFor(all, "/p", "")); got != 2 {
		t.Errorf("records for /p = %d, want 2", got)
	}
	if got := recordsFor(all, "/p", "b"); len(got) != 1 || got[0].str("request-id") != "b" {
		t.Errorf("records for /p, b = %s", describe(got))
	}
}

func TestFieldValueRendersEachKind(t *testing.T) {
	r := parseRecords(textLine(t, rec("FAULT", "id", "/p", map[string]any{
		"status":  401,
		"payload": `<b>&`,
		"headers": map[string]any{"x-multi": []string{"first", "second"}, ":status": "200"},
	})))[0]
	cases := []struct {
		column, want string
		present      bool
	}{
		{"status", "401", true},
		{"payload", `<b>&`, true},
		{"headers.x-multi", `["first","second"]`, true},
		{"headers.:status", "200", true},
		{"headers.x-missing", "", false},
		{"error-code", "", false},
	}
	for _, c := range cases {
		got, present := fieldValue(r, c.column)
		if got != c.want || present != c.present {
			t.Errorf("%s = %q, %v; want %q, %v", c.column, got, present, c.want, c.present)
		}
	}
	noHeaders := parseRecords(textLine(t, rec("REQUEST", "id", "/p", nil)))[0]
	if _, present := fieldValue(noHeaders, "headers.x-a"); present {
		t.Error("a header of a record without headers is present")
	}
	if raw, _ := fieldValue(r, "record"); !strings.Contains(raw, `"mediation-flow":"FAULT"`) {
		t.Errorf("record = %q", raw)
	}
}

func TestParseCellAndCheck(t *testing.T) {
	cases := []struct {
		cell, value string
		present     bool
		ok          bool
	}{
		{"REQUEST", "REQUEST", true, true},
		{"REQUEST", "RESPONSE", true, false},
		{"REQUEST", "", false, false},
		{"[absent]", "", false, true},
		{"[absent]", "x", true, false},
		{"[any]", "x", true, true},
		{"[any]", "", false, false},
		{"[length 3]", "héé", true, true},
		{"[length 3]", "abcd", true, false},
		{"[contains b]", "abc", true, true},
		{"[contains z]", "abc", true, false},
		{"[contains z]", "", false, false},
		{"[not contains z]", "abc", true, true},
		{"[not contains b]", "abc", true, false},
		{"[not contains b]", "", false, false},
		{"[unknown]", "[unknown]", true, true},
		{`["first","second"]`, `["first","second"]`, true, true},
	}
	for _, c := range cases {
		e, err := parseCell(c.cell)
		if err != nil {
			t.Fatalf("%s: %v", c.cell, err)
		}
		why := e.check(c.value, c.present)
		if (why == "") != c.ok {
			t.Errorf("%s on %q (present %v): %q, want ok=%v", c.cell, c.value, c.present, why, c.ok)
		}
	}
	if _, err := parseCell("[length x]"); err == nil {
		t.Error("[length x] parsed")
	}
}

// table builds a godog table through its JSON form, so the test needs no messages import.
func table(rows ...[]string) *godog.Table {
	type cell struct {
		Value string `json:"value"`
	}
	type row struct {
		Cells []cell `json:"cells"`
	}
	payload := struct {
		Rows []row `json:"rows"`
	}{}
	for _, values := range rows {
		r := row{}
		for _, v := range values {
			r.Cells = append(r.Cells, cell{Value: v})
		}
		payload.Rows = append(payload.Rows, r)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	out := &godog.Table{}
	if err := json.Unmarshal(raw, out); err != nil {
		panic(err)
	}
	return out
}

func mustTable(t *testing.T, rows ...[]string) recordsTable {
	t.Helper()
	parsed, err := parseRecordsTable(context.Background(), table(rows...))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestParseRecordsTableRejectsBadTables(t *testing.T) {
	if _, err := parseRecordsTable(context.Background(), table([]string{"mediation-flow"})); err == nil {
		t.Error("a table with no record row was accepted")
	}
	if _, err := parseRecordsTable(context.Background(), table([]string{"payload", "status"}, []string{"1"})); err == nil {
		t.Error("a row with too few cells was accepted")
	}
	for _, column := range []string{"", "mediation_flow", "Headers", "headers.", "headers.Authorization", "headers.X-Lm-Case"} {
		if _, err := parseRecordsTable(context.Background(), table([]string{column}, []string{"[absent]"})); err == nil {
			t.Errorf("column %q was accepted", column)
		}
	}
	for _, column := range []string{"record", "mediation-flow", "original-status", "failing-policy", "headers", "headers.:status", "headers.x-lm-case"} {
		if _, err := parseRecordsTable(context.Background(), table([]string{column}, []string{"[any]"})); err != nil {
			t.Errorf("column %q was refused: %v", column, err)
		}
	}
}

func TestJudgeRecordsNeedsTheExactRecordsInOrder(t *testing.T) {
	logs := strings.Join([]string{
		textLine(t, rec("REQUEST", "id", "/p", map[string]any{"headers": map[string]any{"x-a": "1"}})),
		textLine(t, rec("REQUEST", "id", "/p", map[string]any{"payload": "body"})),
	}, "\n")
	records := parseRecords(logs)
	good := mustTable(t,
		[]string{"mediation-flow", "headers.x-a", "payload"},
		[]string{"REQUEST", "1", "[absent]"},
		[]string{"REQUEST", "[absent]", "body"},
	)
	if err := judgeRecords(records, good); err != nil {
		t.Errorf("matching records rejected: %v", err)
	}
	swapped := mustTable(t,
		[]string{"mediation-flow", "headers.x-a", "payload"},
		[]string{"REQUEST", "[absent]", "body"},
		[]string{"REQUEST", "1", "[absent]"},
	)
	if err := judgeRecords(records, swapped); err == nil {
		t.Error("records in the wrong order accepted")
	}
	fewer := mustTable(t, []string{"mediation-flow"}, []string{"REQUEST"})
	if err := judgeRecords(records, fewer); err == nil || !strings.Contains(err.Error(), "found 2") {
		t.Errorf("an extra record accepted: %v", err)
	}
	more := mustTable(t, []string{"mediation-flow"}, []string{"REQUEST"}, []string{"REQUEST"}, []string{"RESPONSE"})
	if err := judgeRecords(records, more); err == nil {
		t.Error("a missing record accepted")
	}
}

func pairLogs(t *testing.T, entries [][3]string) []record {
	t.Helper()
	var lines []string
	for _, e := range entries {
		lines = append(lines, textLine(t, rec(e[0], e[1], "/p", map[string]any{"payload": e[2]})))
	}
	return parseRecords(strings.Join(lines, "\n"))
}

func TestJudgePairs(t *testing.T) {
	const marker = "m-{i}-end"
	good := pairLogs(t, [][3]string{
		{"REQUEST", "a", `{"n":"m-1-end"}`}, {"REQUEST", "b", `{"n":"m-2-end"}`},
		{"RESPONSE", "b", `echo m-2-end`}, {"RESPONSE", "a", `echo m-1-end`},
	})
	if err := judgePairs(good, 2, marker); err != nil {
		t.Errorf("good pairs rejected: %v", err)
	}
	bad := map[string][][3]string{
		"missing response": {
			{"REQUEST", "a", "m-1-end"}, {"REQUEST", "b", "m-2-end"}, {"RESPONSE", "a", "m-1-end"},
		},
		"duplicate request record": {
			{"REQUEST", "a", "m-1-end"}, {"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "m-1-end"},
			{"REQUEST", "b", "m-2-end"}, {"RESPONSE", "b", "m-2-end"},
		},
		"response of another request": {
			{"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "m-2-end"},
			{"REQUEST", "b", "m-2-end"}, {"RESPONSE", "b", "m-1-end"},
		},
		"response carrying another request's marker too": {
			{"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "echo m-1-end m-2-end"},
			{"REQUEST", "b", "m-2-end"}, {"RESPONSE", "b", "m-2-end"},
		},
		"same marker twice": {
			{"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "m-1-end"},
			{"REQUEST", "b", "m-1-end"}, {"RESPONSE", "b", "m-1-end"},
		},
		"one request id too few": {
			{"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "m-1-end"},
		},
		"a fault record": {
			{"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "m-1-end"},
			{"REQUEST", "b", "m-2-end"}, {"FAULT", "b", "m-2-end"},
		},
	}
	for name, entries := range bad {
		if err := judgePairs(pairLogs(t, entries), 2, marker); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ambiguous := pairLogs(t, [][3]string{{"REQUEST", "a", "m-1"}, {"RESPONSE", "a", "m-1"}})
	if err := judgePairs(ambiguous, 1, "m-{i}"); err != nil {
		t.Errorf("a single unambiguous marker rejected: %v", err)
	}
	prefix := pairLogs(t, make([][3]string, 0))
	for i := 1; i <= 11; i++ {
		id := fmt.Sprint(i)
		prefix = append(prefix, pairLogs(t, [][3]string{{"REQUEST", id, "m-" + id}, {"RESPONSE", id, "m-" + id}})...)
	}
	if err := judgePairs(prefix, 11, "m-{i}"); err == nil || !strings.Contains(err.Error(), "fixed suffix") {
		t.Errorf("a marker that is a prefix of another was not reported: %v", err)
	}
	noID := pairLogs(t, [][3]string{
		{"REQUEST", "a", "m-1-end"}, {"RESPONSE", "a", "m-1-end"}, {"REQUEST", "", "m-2-end"}, {"RESPONSE", "", "m-2-end"},
	})
	if err := judgePairs(noID, 2, marker); err == nil || !strings.Contains(err.Error(), "2 record(s) have no request id") {
		t.Errorf("records without a request id were not named: %v", err)
	}
}

func TestParseRecordsNeedsExactlyOneJSONObject(t *testing.T) {
	for _, msg := range []string{`{"mediation-flow":"REQUEST"}}`, `{"mediation-flow":"REQUEST"} {"x":1}`, `{"mediation-flow":"REQUEST"}]`} {
		line := "[pol] time=2026-11-27T00:00:00Z level=INFO msg=" + strconv.Quote(msg)
		if got := parseRecords(line); len(got) != 0 {
			t.Errorf("%s: read as %d record(s)", msg, len(got))
		}
	}
	line := "[pol] time=2026-11-27T00:00:00Z level=INFO msg=" + strconv.Quote(`{"mediation-flow":"REQUEST"} `)
	if got := parseRecords(line); len(got) != 1 {
		t.Errorf("one object with trailing space: read as %d record(s)", len(got))
	}
}

func TestAwaitInKeepsTheWaitsReadWhenTheLastReadFails(t *testing.T) {
	good := stackLogs("gateway-runtime", textLine(t, rec("REQUEST", "req-1", "/p", nil)))
	reads := 0
	logs := runtimeLog{service: "gateway-runtime", logs: func(context.Context) string {
		reads++
		if reads == 1 {
			return good
		}
		return stackLogs("gateway-runtime", "(log read failed: closed)")
	}}
	records, err := awaitIn(context.Background(), logs, "/p", "", 1, false)
	if err != nil || len(records) != 1 {
		t.Errorf("got %d records and error %v, want the wait's one record", len(records), err)
	}
	fresh := stackLogs("gateway-runtime", textLine(t, rec("REQUEST", "req-1", "/p", nil))+"\n"+textLine(t, rec("REQUEST", "req-2", "/p", nil)))
	reads = 0
	logs.logs = func(context.Context) string {
		reads++
		if reads == 1 {
			return good
		}
		return fresh
	}
	if records, err := awaitIn(context.Background(), logs, "/p", "", 1, false); err != nil || len(records) != 2 {
		t.Errorf("got %d records and error %v, want the fresh read's two", len(records), err)
	}
}

// stackLogs builds the output of the framework's stack Logs: each service's log under its own
// "───── <service> ─────" line.
func stackLogs(sections ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(sections); i += 2 {
		fmt.Fprintf(&b, "───── %s ─────\n%s\n", sections[i], sections[i+1])
	}
	return b.String()
}

func fixedLog(logs string) runtimeLog {
	return runtimeLog{logs: func(context.Context) string { return logs }, service: "gateway-runtime"}
}

func TestReadRecordsKeepsOnlyTheRuntimeSection(t *testing.T) {
	runtimeLine := textLine(t, rec("REQUEST", "req-1", "/p", nil))
	controllerLine := textLine(t, rec("REQUEST", "c1", "/p", nil))
	logs := stackLogs("gateway-controller", controllerLine, "gateway-runtime", runtimeLine, "router", controllerLine)
	records, err := readRecords(context.Background(), fixedLog(logs), "/p", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].str("request-id") != "req-1" {
		t.Errorf("got %d records (%v), want only the runtime's req-1", len(records), records)
	}
}

func TestReadRecordsRefusesALogThatWasNotRead(t *testing.T) {
	cases := map[string]string{
		"no stack":        "(no stack to read logs from)",
		"no section":      stackLogs("gateway-controller", "started"),
		"not located":     stackLogs("gateway-runtime", "(could not locate service: gone)"),
		"not read":        stackLogs("gateway-runtime", "(could not read logs: closed)"),
		"over the limit":  stackLogs("gateway-runtime", "(log read failed: log exceeds the 64 MiB limit)"),
		"empty log input": "",
	}
	for name, logs := range cases {
		if _, err := readRecords(context.Background(), fixedLog(logs), "/p", ""); err == nil {
			t.Errorf("%s: an unread log was accepted as a log with no records", name)
		}
	}
	// A note in another service's section does not hide the runtime's records.
	logs := stackLogs("gateway-controller", "(could not read logs: closed)", "gateway-runtime", textLine(t, rec("REQUEST", "req-1", "/p", nil)))
	if records, err := readRecords(context.Background(), fixedLog(logs), "/p", ""); err != nil || len(records) != 1 {
		t.Errorf("got %d records and error %v, want the runtime's one record", len(records), err)
	}
}

func TestJoinResponseChunksJoinsOneResponsesChunksOnly(t *testing.T) {
	payload := func(p string) map[string]any { return map[string]any{"payload": p} }
	logs := strings.Join([]string{
		textLine(t, rec("REQUEST", "a", "/p", payload("q1"))),
		textLine(t, rec("REQUEST", "a", "/p", payload("q2"))),
		textLine(t, rec("RESPONSE", "a", "/p", payload("r1"))),
		textLine(t, rec("RESPONSE", "a", "/p", payload("r2"))),
		textLine(t, rec("RESPONSE", "a", "/p", payload("r3"))),
		textLine(t, rec("RESPONSE", "a", "/p", map[string]any{"headers": map[string]any{":status": "200"}})),
		textLine(t, rec("RESPONSE", "b", "/p", payload("s1"))),
		textLine(t, rec("RESPONSE", "b", "/p", payload("s2"))),
		textLine(t, rec("RESPONSE", "a", "/p", payload("late"))),
	}, "\n")
	got := joinResponseChunks(parseRecords(logs))
	var flat []string
	for _, r := range got {
		value, _ := fieldValue(r, "payload")
		flat = append(flat, r.str("mediation-flow")+" "+r.str("request-id")+" "+value)
	}
	want := []string{"REQUEST a q1", "REQUEST a q2", "RESPONSE a r1r2r3", "RESPONSE a ", "RESPONSE b s1s2", "RESPONSE a late"}
	if strings.Join(flat, "|") != strings.Join(want, "|") {
		t.Errorf("joined records:\n%s\nwant:\n%s", strings.Join(flat, "\n"), strings.Join(want, "\n"))
	}
	var joined map[string]any
	if err := json.Unmarshal([]byte(got[2].raw), &joined); err != nil || joined["payload"] != "r1r2r3" || joined["http-method"] != "GET" {
		t.Errorf("the joined record's raw form is %q (%v)", got[2].raw, err)
	}
	// A record with another field differing is not a chunk of the same response.
	other := parseRecords(strings.Join([]string{
		textLine(t, rec("RESPONSE", "a", "/p", payload("r1"))),
		textLine(t, rec("RESPONSE", "a", "/q", payload("r2"))),
	}, "\n"))
	if n := len(joinResponseChunks(other)); n != 2 {
		t.Errorf("records of two paths joined into %d", n)
	}
}

func TestAwaitInCountsJoinedChunksOnlyWhenAsked(t *testing.T) {
	logs := fixedLog(stackLogs("gateway-runtime", strings.Join([]string{
		textLine(t, rec("REQUEST", "a", "/p", map[string]any{"payload": "q"})),
		textLine(t, rec("RESPONSE", "a", "/p", map[string]any{"payload": "r1"})),
		textLine(t, rec("RESPONSE", "a", "/p", map[string]any{"payload": "r2"})),
	}, "\n")))
	if records, err := awaitIn(context.Background(), logs, "/p", "", 3, false); err != nil || len(records) != 3 {
		t.Errorf("without join: got %d records and error %v, want 3", len(records), err)
	}
	records, err := awaitIn(context.Background(), logs, "/p", "", 2, true)
	if err != nil || len(records) != 2 || records[1].str("payload") != "r1r2" {
		t.Errorf("with join: got %d records and error %v, want the request and one joined response", len(records), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := awaitIn(ctx, logs, "/p", "", 3, true); err == nil {
		t.Error("with join, the wait counted the chunks: three raw records met a wait for three joined ones")
	}
}

func TestALiteralFailureShortensALongExpectedValue(t *testing.T) {
	e := expectation{kind: "literal", value: strings.Repeat("a", 5000)}
	why := e.check("short", true)
	if len(why) > 1000 || !strings.Contains(why, "…(5000 bytes)") {
		t.Errorf("the failure message is %d bytes: %.120q", len(why), why)
	}
}

func TestAContainsFailureShortensALongExpectedValue(t *testing.T) {
	e := expectation{kind: "contains", value: strings.Repeat("a", 5000)}
	why := e.check("short", true)
	if len(why) > 1000 || !strings.Contains(why, "…(5000 bytes)") {
		t.Errorf("the failure message is %d bytes: %.120q", len(why), why)
	}
}

func TestTruncateCutsAtACharacterBoundary(t *testing.T) {
	s := strings.Repeat("a", 399) + strings.Repeat("é", 10)
	got := truncate(s)
	if !utf8.ValidString(got) {
		t.Errorf("truncate split a character: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 399)+"…") {
		t.Errorf("truncate(%q) = %q", s, got)
	}
	if truncate("short") != "short" {
		t.Error("truncate changed a short string")
	}
}
