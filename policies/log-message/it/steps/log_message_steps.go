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
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cucumber/godog"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/util/retry"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

// runtimeService is the gateway service whose log holds the policy engine's output.
const runtimeService = "gateway-runtime"

// policySteps holds what the log-message policy's steps share within one runner.
type policySteps struct {
	topo *frameworkruntime.Topology
}

func newPolicySteps(topo *frameworkruntime.Topology) *policySteps {
	return &policySteps{topo: topo}
}

// register binds the steps below. Add a step here only when no shared step expresses the
// behaviour, and give it a unit test in steps_test.go.
func (s *policySteps) register(sc *godog.ScenarioContext) {
	sc.Step(`^the log-message records for "([^"]*)"(?: with request id "([^"]*)")? should be:$`, s.recordsShouldBe)
	sc.Step(`^the log-message records for "([^"]*)" should be none$`, s.noRecords)
	sc.Step(`^the log-message records for "([^"]*)" should pair (\d+) requests by request id, each carrying "([^"]*)"$`,
		s.recordsShouldPair)
}

// record is one log-message record: the decoded fields and the record's JSON as the policy wrote it.
type record struct {
	fields map[string]any
	raw    string
}

func (r record) str(field string) string {
	v, _ := r.fields[field].(string)
	return v
}

// parseRecords returns every log-message record in a service log, in log order. The policy writes
// a record as the message of an slog line: `[pol] time=… level=INFO msg="<record JSON>"` with the
// engine's default text handler, or a JSON line whose "msg" holds the record with the JSON
// handler. A message counts as a record only when it decodes to an object with "mediation-flow".
func parseRecords(logs string) []record {
	var out []record
	for _, line := range strings.Split(logs, "\n") {
		msg, ok := slogMessage(line)
		if !ok {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(msg))
		decoder.UseNumber()
		var fields map[string]any
		var extra any
		if decoder.Decode(&fields) != nil || decoder.Decode(&extra) != io.EOF {
			continue // not exactly one JSON object
		}
		if _, ok := fields["mediation-flow"].(string); !ok {
			continue
		}
		out = append(out, record{fields: fields, raw: msg})
	}
	return out
}

// slogMessage returns the msg of one slog line in the text or the JSON form.
func slogMessage(line string) (string, bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "[pol]"))
	if strings.HasPrefix(trimmed, "{") {
		var entry map[string]any
		if json.Unmarshal([]byte(trimmed), &entry) != nil {
			return "", false
		}
		msg, ok := entry["msg"].(string)
		return msg, ok
	}
	if !strings.HasPrefix(trimmed, "time=") {
		return "", false
	}
	i := strings.Index(trimmed, " msg=\"")
	if i < 0 {
		return "", false
	}
	quoted, err := strconv.QuotedPrefix(trimmed[i+len(" msg="):])
	if err != nil {
		return "", false
	}
	msg, err := strconv.Unquote(quoted)
	if err != nil {
		return "", false
	}
	return msg, true
}

// recordsFor keeps the records of one resource path and, when requestID is not empty, one request.
func recordsFor(records []record, path, requestID string) []record {
	var out []record
	for _, r := range records {
		if r.str("resource-path") != path {
			continue
		}
		if requestID != "" && r.str("request-id") != requestID {
			continue
		}
		out = append(out, r)
	}
	return out
}

// fieldValue renders a record field for comparison. "record" is the whole record as written;
// "headers.<name>" is one logged header; any other column is a top-level field. Strings compare
// as they are, numbers in their JSON form, arrays and objects as compact JSON.
func fieldValue(r record, column string) (string, bool) {
	if column == "record" {
		return r.raw, true
	}
	var v any
	var ok bool
	if name, isHeader := strings.CutPrefix(column, "headers."); isHeader {
		headers, isMap := r.fields["headers"].(map[string]any)
		if !isMap {
			return "", false
		}
		v, ok = headers[name]
	} else {
		v, ok = r.fields[column]
	}
	if !ok {
		return "", false
	}
	switch typed := v.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	default:
		var b bytes.Buffer
		encoder := json.NewEncoder(&b)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(typed); err != nil {
			return fmt.Sprint(typed), true
		}
		return strings.TrimSuffix(b.String(), "\n"), true
	}
}

// expectation is one cell of the records table.
type expectation struct {
	kind  string // literal, absent, any, length, contains, not-contains
	value string
	n     int
}

// parseCell reads a cell: [absent], [any], [length N], [contains X], [not contains X], or a
// literal. Square brackets keep the keywords apart from Scenario Outline placeholders; a literal
// that only looks like one, such as a JSON array, is compared as it is.
func parseCell(cell string) (expectation, error) {
	if !strings.HasPrefix(cell, "[") || !strings.HasSuffix(cell, "]") {
		return expectation{kind: "literal", value: cell}, nil
	}
	inner := cell[1 : len(cell)-1]
	switch {
	case inner == "absent":
		return expectation{kind: "absent"}, nil
	case inner == "any":
		return expectation{kind: "any"}, nil
	case strings.HasPrefix(inner, "length "):
		n, err := strconv.Atoi(strings.TrimPrefix(inner, "length "))
		if err != nil || n < 0 {
			return expectation{}, fmt.Errorf("cell %q: [length N] needs a whole number", cell)
		}
		return expectation{kind: "length", n: n}, nil
	case strings.HasPrefix(inner, "not contains "):
		return expectation{kind: "not-contains", value: strings.TrimPrefix(inner, "not contains ")}, nil
	case strings.HasPrefix(inner, "contains "):
		return expectation{kind: "contains", value: strings.TrimPrefix(inner, "contains ")}, nil
	}
	return expectation{kind: "literal", value: cell}, nil
}

// check reports why a field does not meet the expectation, or "" when it does.
func (e expectation) check(value string, present bool) string {
	switch e.kind {
	case "absent":
		if present {
			return fmt.Sprintf("is %q, want it absent", truncate(value))
		}
		return ""
	}
	if !present {
		return "is absent"
	}
	switch e.kind {
	case "any":
		return ""
	case "length":
		if got := utf8.RuneCountInString(value); got != e.n {
			return fmt.Sprintf("has %d characters, want %d", got, e.n)
		}
	case "contains":
		if !strings.Contains(value, e.value) {
			return fmt.Sprintf("is %q, want it to contain %q", truncate(value), e.value)
		}
	case "not-contains":
		if strings.Contains(value, e.value) {
			return fmt.Sprintf("contains %q", e.value)
		}
	default:
		if value != e.value {
			return fmt.Sprintf("is %q, want %q", truncate(value), e.value)
		}
	}
	return ""
}

// recordFields are the fields a log-message record can have (LogRecord in logmessage.go).
var recordFields = map[string]bool{
	"mediation-flow": true, "request-id": true, "http-method": true, "resource-path": true,
	"payload": true, "headers": true, "status": true, "original-status": true, "error-code": true,
	"error-type": true, "error-message": true, "failing-policy": true,
}

// checkColumn refuses a column the policy never writes, so a misspelt column cannot pass as
// [absent]. Header names are logged in lower case, so a header column must be lower case too.
func checkColumn(name string) error {
	if name == "" {
		return fmt.Errorf("the records table has an empty column name")
	}
	if name == "record" || recordFields[name] {
		return nil
	}
	header, isHeader := strings.CutPrefix(name, "headers.")
	if !isHeader {
		return fmt.Errorf("column %q is not a log-message record field, \"record\" or \"headers.<name>\"", name)
	}
	if header == "" || header != strings.ToLower(header) {
		return fmt.Errorf("column %q: the policy logs header names in lower case", name)
	}
	return nil
}

// recordsTable is the parsed records table: the columns and one row of expectations per record.
type recordsTable struct {
	columns []string
	rows    [][]expectation
}

func parseRecordsTable(ctx context.Context, table *godog.Table) (recordsTable, error) {
	if table == nil || len(table.Rows) < 2 {
		return recordsTable{}, fmt.Errorf("the records table needs a header row and at least one record row; " +
			"use \"the log-message records for <path> should be none\" for none")
	}
	var t recordsTable
	for _, cell := range table.Rows[0].Cells {
		name := strings.TrimSpace(cell.Value)
		if err := checkColumn(name); err != nil {
			return recordsTable{}, err
		}
		t.columns = append(t.columns, name)
	}
	for i, row := range table.Rows[1:] {
		if len(row.Cells) != len(t.columns) {
			return recordsTable{}, fmt.Errorf("record row %d has %d cells, want %d", i+1, len(row.Cells), len(t.columns))
		}
		var expectations []expectation
		for _, cell := range row.Cells {
			value, err := stepscommon.Expand(ctx, cell.Value)
			if err != nil {
				return recordsTable{}, err
			}
			e, err := parseCell(value)
			if err != nil {
				return recordsTable{}, err
			}
			expectations = append(expectations, e)
		}
		t.rows = append(t.rows, expectations)
	}
	return t, nil
}

// judgeRecords checks that records match the table exactly: the same number, in order, each
// record meeting every expectation in its row.
func judgeRecords(records []record, t recordsTable) error {
	if len(records) != len(t.rows) {
		return fmt.Errorf("found %d log-message record(s), want %d:\n%s", len(records), len(t.rows), describe(records))
	}
	var problems []string
	for i, r := range records {
		for j, e := range t.rows[i] {
			value, present := fieldValue(r, t.columns[j])
			if why := e.check(value, present); why != "" {
				problems = append(problems, fmt.Sprintf("record %d %s %s", i+1, t.columns[j], why))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s\nrecords:\n%s", strings.Join(problems, "\n"), describe(records))
	}
	return nil
}

// judgePairs checks that the records of one path are n requests, told apart by request id, each
// with exactly one REQUEST and one RESPONSE record. Each request's REQUEST payload carries the
// marker with {i} replaced by one value of 1..n, each value used once, and its RESPONSE payload
// carries the same marker, so no record was lost, duplicated or attributed to another request.
func judgePairs(records []record, n int, marker string) error {
	type pair struct{ request, response []record }
	byID := map[string]*pair{}
	var order []string
	for _, r := range records {
		id := r.str("request-id")
		p, ok := byID[id]
		if !ok {
			p = &pair{}
			byID[id] = p
			order = append(order, id)
		}
		switch r.str("mediation-flow") {
		case "REQUEST":
			p.request = append(p.request, r)
		case "RESPONSE":
			p.response = append(p.response, r)
		default:
			return fmt.Errorf("request %q has a %q record", id, r.str("mediation-flow"))
		}
	}
	if p, ok := byID[""]; ok {
		return fmt.Errorf("%d record(s) have no request id", len(p.request)+len(p.response))
	}
	if len(order) != n {
		return fmt.Errorf("found %d request ids, want %d", len(order), n)
	}
	used := map[int]string{}
	for _, id := range order {
		p := byID[id]
		if len(p.request) != 1 || len(p.response) != 1 {
			return fmt.Errorf("request %q has %d REQUEST and %d RESPONSE records, want one of each",
				id, len(p.request), len(p.response))
		}
		requestPayload, responsePayload := p.request[0].str("payload"), p.response[0].str("payload")
		found := 0
		for i := 1; i <= n; i++ {
			if !strings.Contains(requestPayload, strings.ReplaceAll(marker, "{i}", strconv.Itoa(i))) {
				continue
			}
			if found != 0 {
				return fmt.Errorf("request %q carries the markers of %d and %d; make the marker end with a fixed suffix", id, found, i)
			}
			found = i
		}
		if found == 0 {
			return fmt.Errorf("request %q REQUEST payload %q carries no marker", id, truncate(requestPayload))
		}
		if other, dup := used[found]; dup {
			return fmt.Errorf("requests %q and %q both carry marker %d", other, id, found)
		}
		used[found] = id
		if want := strings.ReplaceAll(marker, "{i}", strconv.Itoa(found)); !strings.Contains(responsePayload, want) {
			return fmt.Errorf("request %q RESPONSE payload does not carry %q, its REQUEST marker: %q", id, want, truncate(responsePayload))
		}
	}
	return nil
}

// unreadLogNotes are the notes the framework's stack Logs writes in a service's section in place
// of a log it could not read. Such a log holds no records, so it would pass for "no records" if it
// were not refused. With no stack at all, Logs writes no section, which serviceLog refuses too.
var unreadLogNotes = []string{
	"(could not locate service: ",
	"(could not read logs: ",
	"(log read failed: ",
}

// serviceLog returns the section of one service in the output of the stack's Logs, which writes
// every service of the stack under a "───── <service> ─────" line. It fails when the section is
// missing or holds a note that the log could not be read.
func serviceLog(logs, service string) (string, error) {
	lines := strings.Split(logs, "\n")
	header := "───── " + service + " ─────"
	start := -1
	for i, line := range lines {
		if line == header {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", fmt.Errorf("cannot read the %s log: the stack logs have no %s section", service, service)
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "───── ") && strings.HasSuffix(lines[i], " ─────") {
			end = i
			break
		}
	}
	section := lines[start:end]
	for _, line := range section {
		for _, note := range unreadLogNotes {
			if strings.HasPrefix(line, note) {
				return "", fmt.Errorf("cannot read the %s log: %s", service, line)
			}
		}
	}
	return strings.Join(section, "\n"), nil
}

// runtimeLog reads the logs of the stack that runs the gateway runtime. service is the runtime's
// name in that stack, which can carry a suffix.
type runtimeLog struct {
	logs    func(context.Context) string
	service string
}

// logReader resolves the gateway runtime once, so an error there fails the step at once instead
// of being retried as a slow log.
func (s *policySteps) logReader() (runtimeLog, error) {
	stack, service, err := s.topo.ServiceControl(runtimeService)
	if err != nil {
		return runtimeLog{}, err
	}
	return runtimeLog{logs: stack.Logs, service: service}, nil
}

// readRecords reads the runtime log and returns the records of path (and request id).
func readRecords(ctx context.Context, logs runtimeLog, path, requestID string) ([]record, error) {
	log, err := serviceLog(logs.logs(ctx), logs.service)
	if err != nil {
		return nil, err
	}
	return recordsFor(parseRecords(log), path, requestID), nil
}

// awaitRecords waits until at least want records of path (and request id) are in the log, then
// reads the log once more and returns that read. Records reach the container log late when they
// are large, so the wait polls; the fresh read is what the caller judges. The caller makes the
// count final by ending the expected records with those of a later request (a fence): records of
// one process reach the log in the order they were written.
func (s *policySteps) awaitRecords(ctx context.Context, path, requestID string, want int) ([]record, error) {
	logs, err := s.logReader()
	if err != nil {
		return nil, err
	}
	return awaitIn(ctx, logs, path, requestID, want)
}

// awaitIn is awaitRecords on a resolved runtime log.
func awaitIn(ctx context.Context, logs runtimeLog, path, requestID string, want int) ([]record, error) {
	var last []record
	err := retry.Await(ctx, retry.Options{Interval: 200 * time.Millisecond, Fast: true},
		func(ctx context.Context) (recordSet, error) {
			records, err := readRecords(ctx, logs, path, requestID)
			if err != nil {
				return nil, retry.Transient(err)
			}
			last = records
			return records, nil
		},
		func(records recordSet) bool { return len(records) >= want },
		fmt.Sprintf("waiting for %d log-message record(s) for %s", want, describeFilter(path, requestID)))
	if err != nil {
		return last, err
	}
	records, err := readRecords(ctx, logs, path, requestID)
	if err != nil {
		// The wait already read enough records; a read failing now must not fail a passing step.
		return last, nil
	}
	return records, nil
}

// recordSet is one read of the records; Describe keeps a timeout message readable.
type recordSet []record

// Describe lists the records read.
func (r recordSet) Describe() string { return describe(r) }

func (s *policySteps) recordsShouldBe(ctx context.Context, path, requestID string, table *godog.Table) error {
	path, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	requestID, err = stepscommon.Expand(ctx, requestID)
	if err != nil {
		return err
	}
	t, err := parseRecordsTable(ctx, table)
	if err != nil {
		return err
	}
	records, err := s.awaitRecords(ctx, path, requestID, len(t.rows))
	if err != nil {
		return err
	}
	if err := judgeRecords(records, t); err != nil {
		return fmt.Errorf("log-message records for %s: %w", describeFilter(path, requestID), err)
	}
	return nil
}

// noRecords checks the log once. Use it after a later request's records were seen, so the log
// already holds anything this path would have logged. A log that could not be read fails the
// step: it would hold no records whatever the policy wrote.
func (s *policySteps) noRecords(ctx context.Context, path string) error {
	path, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	logs, err := s.logReader()
	if err != nil {
		return err
	}
	records, err := readRecords(ctx, logs, path, "")
	if err != nil {
		return err
	}
	if len(records) > 0 {
		return fmt.Errorf("found %d log-message record(s) for %s, want none:\n%s", len(records), path, describe(records))
	}
	return nil
}

// recordsShouldPair judges one read of the log, so a duplicate written after it is not seen. Use
// it after a later request's records were seen (a fence), so every record of path is already in.
func (s *policySteps) recordsShouldPair(ctx context.Context, path string, n int, marker string) error {
	path, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	if n < 1 || !strings.Contains(marker, "{i}") {
		return fmt.Errorf("the pairing step needs a request count of at least 1 and a marker with {i}")
	}
	records, err := s.awaitRecords(ctx, path, "", 2*n)
	if err != nil {
		return err
	}
	if err := judgePairs(records, n, marker); err != nil {
		return fmt.Errorf("log-message records for %s: %w\nrecords:\n%s", path, err, describe(records))
	}
	return nil
}

func describeFilter(path, requestID string) string {
	if requestID == "" {
		return path
	}
	return fmt.Sprintf("%s with request id %s", path, requestID)
}

// describe lists records one per line, long values shortened, for failure messages.
func describe(records []record) string {
	if len(records) == 0 {
		return "  (none)"
	}
	var b strings.Builder
	for i, r := range records {
		fmt.Fprintf(&b, "  %d: %s\n", i+1, truncate(r.raw))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// truncate shortens s to about 400 bytes, cut at a character boundary.
func truncate(s string) string {
	const max = 400
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s…(%d bytes)", s[:cut], len(s))
}
