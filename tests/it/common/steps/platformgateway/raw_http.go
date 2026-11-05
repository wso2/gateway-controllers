/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package platformgateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	incompleteRequestTimeout = 20 * time.Second
	rawRequestTimeout        = 30 * time.Second
	maxRawResponseBodyBytes  = 10 << 20
)

func (g *Gateway) registerRawHTTPSteps(sc *godog.ScenarioContext) {
	sc.Step(`^I send an incomplete HTTP request to "([^"]*)"$`, g.sendIncompleteHTTP)
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		tcontext.Remove(ctx, keyRawClosedWithoutResponse)
		return ctx, nil
	})
	sc.Step(`^I send a raw "([^"]*)" request to "([^"]*)" with headers:$`, g.sendRawHTTP)
	sc.Step(`^the gateway should have refused the raw request (with status (\d+)|by closing the connection)$`,
		rawRequestRefused)
}

// keyRawClosedWithoutResponse records that the gateway closed the connection of the latest raw
// request without answering it.
const keyRawClosedWithoutResponse = "rawClosedWithoutResponse"

// errClosedWithoutResponse is returned when the gateway accepted the connection but closed it
// without sending a response.
var errClosedWithoutResponse = errors.New("the gateway closed the connection without a response")

// rawRequestRefused checks how the gateway refused the latest raw request: "with status N"
// requires an answer with that 4xx status, and "by closing the connection" requires the gateway
// to have closed the connection without answering. Any other outcome fails, so a routing 404 or
// a forwarded request cannot pass for a refusal.
func rawRequestRefused(ctx context.Context, how, status string) error {
	closed := false
	if v, ok := tcontext.Get(ctx, keyRawClosedWithoutResponse); ok {
		closed, _ = v.(bool)
	}
	response, publishErr := httpx.Published(ctx)
	if status == "" {
		if closed {
			return nil
		}
		if publishErr != nil {
			return fmt.Errorf("no raw request was sent: %w", publishErr)
		}
		return fmt.Errorf("expected the gateway to close the connection, got %s", response.Describe())
	}
	want, err := strconv.Atoi(status)
	if err != nil || want < 400 || want > 499 {
		return fmt.Errorf("a refusal status must be a 4xx status, got %q", status)
	}
	if closed {
		return fmt.Errorf("expected status %d, but the gateway closed the connection without a response", want)
	}
	if publishErr != nil {
		return fmt.Errorf("no raw request was sent: %w", publishErr)
	}
	if response.StatusCode != want {
		return fmt.Errorf("expected the gateway to refuse the request %s, got %s", how, response.Describe())
	}
	return nil
}

// sendRawHTTP writes an HTTP/1.1 request over a plain socket, one "<name>: <value>" line per
// table row exactly as given, and publishes the gateway's response. It exists for requests the
// HTTP client cannot send: header names in any case, repeated headers, and values with control
// characters. Only Host, the table's headers and "Connection: close" are sent; the scenario's
// headers are not.
func (g *Gateway) sendRawHTTP(ctx context.Context, method, path string, table *godog.Table) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	headerLines, err := rawHeaderLines(ctx, table)
	if err != nil {
		return err
	}
	base, err := g.topo.URL("platform-gateway", "http")
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("parse gateway endpoint %q: %w", base, err)
	}
	if endpoint.Host == "" {
		return fmt.Errorf("gateway endpoint %q has no host", base)
	}
	host := g.base.RequestHost(ctx)
	if host == "" {
		host = endpoint.Hostname()
	}
	method = strings.ToUpper(method)
	httpx.ClearPublished(ctx)
	response, err := rawHTTPExchange(ctx, endpoint.Host, method, rawHTTPRequest(method, resolved, host, headerLines))
	if errors.Is(err, errClosedWithoutResponse) {
		return tcontext.Set(ctx, keyRawClosedWithoutResponse, true)
	}
	if err != nil {
		return err
	}
	if err := tcontext.Set(ctx, keyRawClosedWithoutResponse, false); err != nil {
		return err
	}
	response.URL = base + resolved
	return g.funnel.Publish(ctx, response)
}

// rawHeaderLines turns a table of header names and values into header lines. In a cell, \r,
// \n, \t, \\ and \xNN stand for the byte they name, so a header can carry bytes a feature
// file cannot hold. ${CTX:…} is expanded first.
func rawHeaderLines(ctx context.Context, table *godog.Table) ([]string, error) {
	if table == nil || len(table.Rows) == 0 {
		return nil, fmt.Errorf("a table of header names and values is required")
	}
	lines := make([]string, 0, len(table.Rows))
	for i, row := range table.Rows {
		if row == nil || len(row.Cells) != 2 {
			return nil, fmt.Errorf("raw header row %d must contain exactly two cells", i+1)
		}
		var cells [2]string
		for j, cell := range row.Cells {
			expanded, err := stepscommon.Expand(ctx, cell.Value)
			if err != nil {
				return nil, err
			}
			decoded, err := decodeRawEscapes(expanded)
			if err != nil {
				return nil, fmt.Errorf("raw header row %d: %w", i+1, err)
			}
			cells[j] = decoded
		}
		if strings.TrimSpace(cells[0]) == "" {
			return nil, fmt.Errorf("raw header row %d has an empty header name", i+1)
		}
		lines = append(lines, cells[0]+": "+cells[1])
	}
	return lines, nil
}

// decodeRawEscapes replaces the escapes \r, \n, \t, \\ and \xNN with the bytes they name.
func decodeRawEscapes(line string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] != '\\' {
			out.WriteByte(line[i])
			continue
		}
		if i+1 >= len(line) {
			return "", fmt.Errorf("a line cannot end with a lone backslash")
		}
		i++
		switch line[i] {
		case 'r':
			out.WriteByte('\r')
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case '\\':
			out.WriteByte('\\')
		case 'x':
			if i+2 >= len(line) {
				return "", fmt.Errorf(`\x needs two hex digits`)
			}
			b, err := strconv.ParseUint(line[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf(`\x needs two hex digits, got %q`, line[i+1:i+3])
			}
			out.WriteByte(byte(b))
			i += 2
		default:
			return "", fmt.Errorf(`unknown escape \%c`, line[i])
		}
	}
	return out.String(), nil
}

// rawHTTPRequest builds the request bytes: the request line, Host, the header lines verbatim,
// and Connection: close so the response ends with the connection.
func rawHTTPRequest(method, path, host string, headerLines []string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	for _, line := range headerLines {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	return []byte(b.String())
}

// rawHTTPExchange sends the request bytes to address and reads one response. When the gateway
// accepts the connection but closes or resets it before sending any of a response, it returns
// errClosedWithoutResponse. A connection that cannot be made, or a response cut off part way,
// is an ordinary error. Cancelling ctx ends the exchange.
func rawHTTPExchange(ctx context.Context, address, method string, request []byte) (*httpx.Response, error) {
	started := time.Now()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to gateway endpoint %q: %w", address, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(rawRequestTimeout))
	// Registered after the deadline above, so a cancelled ctx is never overwritten by it: the
	// callback moves the deadline to now, which ends a blocked write or read at once.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(request); err != nil {
		if closedByPeer(err) {
			return nil, errClosedWithoutResponse
		}
		return nil, fmt.Errorf("send raw request: %w", err)
	}
	// Only a connection closed before the first byte of a response is a refusal. A response cut
	// off part way is an ordinary error, so it can never pass for a closed connection.
	reader := bufio.NewReader(conn)
	if _, err := reader.Peek(1); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("read raw-request response: %w", ctxErr)
		}
		if closedByPeer(err) {
			return nil, errClosedWithoutResponse
		}
		return nil, fmt.Errorf("read raw-request response: %w", err)
	}
	resp, err := http.ReadResponse(reader, &http.Request{Method: method})
	if err != nil {
		return nil, fmt.Errorf("read raw-request response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRawResponseBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read raw-request response body: %w", err)
	}
	return &httpx.Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header,
		Method:     method,
		Elapsed:    time.Since(started),
	}, nil
}

// sendIncompleteHTTP leaves the header block unterminated and records the gateway response.
func (g *Gateway) sendIncompleteHTTP(ctx context.Context, path string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	base, err := g.topo.URL("platform-gateway", "http")
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("parse gateway endpoint %q: %w", base, err)
	}
	if endpoint.Host == "" {
		return fmt.Errorf("gateway endpoint %q has no host", base)
	}

	started := time.Now()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint.Host)
	if err != nil {
		return fmt.Errorf("connect to gateway endpoint %q: %w", endpoint.Host, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(incompleteRequestTimeout))

	host := g.base.RequestHost(ctx)
	if host == "" {
		host = endpoint.Hostname()
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n", resolved, host); err != nil {
		return fmt.Errorf("send incomplete request: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read incomplete-request response: %w", err)
	}
	status, err := parseHTTPStatusLine(line)
	if err != nil {
		return err
	}
	response := &httpx.Response{
		StatusCode: status,
		Method:     "GET",
		URL:        base + resolved,
		Elapsed:    time.Since(started),
	}
	if err := g.funnel.Publish(ctx, response); err != nil {
		return err
	}
	return nil
}

func parseHTTPStatusLine(line string) (int, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, fmt.Errorf("invalid HTTP status line %q", strings.TrimSpace(line))
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 999 {
		return 0, fmt.Errorf("invalid HTTP status code in %q", strings.TrimSpace(line))
	}
	return status, nil
}

// closedByPeer reports whether err means the other side closed or reset the connection.
func closedByPeer(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}
