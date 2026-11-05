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
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	rawRequestTimeout = 20 * time.Second

	// maxResponseBodyBytes matches the funnel client's cap on a response body.
	maxResponseBodyBytes = 10 << 20
)

func (s *Steps) registerDataPlane(sc *godog.ScenarioContext) {
	sc.Step(`^the response should be a server error$`, s.responseServerError)
	sc.Step(`^I generate a (\d+)-character value from "([^"]*)" and store it as "([^"]*)"$`, s.generateSizedValue)
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" expecting rejection$`, s.sendRequestExpectingRejection)
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" over HTTP/2$`, s.sendRequestOverHTTP2)
	sc.Step(`^I send a raw "([^"]*)" request to "([^"]*)" with headers:$`, s.sendRawRequestWithHeaders)
	s.registerConcurrentRequests(sc)
}

func (s *Steps) responseServerError(ctx context.Context) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode < 500 || resp.StatusCode >= 600 {
		return fmt.Errorf("expected a server error response, got %s", resp.Describe())
	}
	return nil
}

func (s *Steps) generateSizedValue(ctx context.Context, size int, seed, key string) error {
	if size <= 0 {
		return fmt.Errorf("sized value length must be positive, got %d", size)
	}
	resolvedSeed, err := stepscommon.Expand(ctx, seed)
	if err != nil {
		return err
	}
	if resolvedSeed == "" {
		return fmt.Errorf("sized value seed must not be empty")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("cannot store a sized value with an empty key")
	}
	repeated := strings.Repeat(resolvedSeed, size/len(resolvedSeed)+1)[:size]
	return tcontext.Set(ctx, key, repeated)
}

// sendRequestExpectingRejection accepts a client error or a connection the gateway ended before
// answering. Any other transport failure fails the step, so a hung gateway is not taken for a
// rejecting one.
func (s *Steps) sendRequestExpectingRejection(ctx context.Context, method, path string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	resp, err := s.funnel.Send(ctx, httpx.Request{
		Method:  strings.ToUpper(method),
		URL:     target,
		Headers: s.base.ScenarioHeaders(ctx),
		Host:    s.base.RequestHost(ctx),
	})
	if err == nil {
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			return fmt.Errorf("expected the gateway to reject the request, got %s", resp.Describe())
		}
		return nil
	}
	if isConnectionRejection(err) {
		return nil
	}
	return fmt.Errorf("invoking %s %s: %w", method, target, err)
}

func isConnectionRejection(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset")
}

// sendRequestOverHTTP2 fails unless the gateway answers on HTTP/2. The funnel's client speaks
// only HTTP/1.1, so the request uses a client of its own and the response is published through
// the funnel.
func (s *Steps) sendRequestOverHTTP2(ctx context.Context, method, path string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := s.base.GatewayURL(resolved)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("parsing the gateway URL %q: %w", target, err)
	}

	request := &http.Request{
		Method: strings.ToUpper(method),
		URL:    parsed,
		Host:   s.base.RequestHost(ctx),
		Header: make(http.Header),
	}
	for name, value := range s.base.ScenarioHeaders(ctx) {
		request.Header.Set(name, value)
	}

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: &protocols}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:       requestTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	httpx.ClearPublished(ctx)
	started := time.Now()
	resp, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("sending %s %s over HTTP/2: %w (the gateway may not accept unencrypted HTTP/2)",
			request.Method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		return fmt.Errorf("expected an HTTP/2 response from %s %s, got protocol %q", request.Method, target, resp.Proto)
	}
	body, err := readBody(resp.Body)
	if err != nil {
		return fmt.Errorf("reading the body of %s %s: %w", request.Method, target, err)
	}
	return s.funnel.Publish(ctx, &httpx.Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header.Clone(),
		Method:     request.Method,
		URL:        target,
		Elapsed:    time.Since(started),
	})
}

// tableRows returns the two cells of each row of a two-column table.
func tableRows(table *godog.Table) ([][2]string, error) {
	if table == nil || len(table.Rows) == 0 {
		return nil, fmt.Errorf("table must not be empty")
	}
	rows := make([][2]string, 0, len(table.Rows))
	for i, row := range table.Rows {
		if row == nil || len(row.Cells) != 2 {
			return nil, fmt.Errorf("table row %d must contain exactly two cells", i+1)
		}
		rows = append(rows, [2]string{row.Cells[0].Value, row.Cells[1].Value})
	}
	return rows, nil
}

func readBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds the %d-byte limit", maxResponseBodyBytes)
	}
	return body, nil
}

type rawHeader struct {
	name  string
	value string
}

// sendRawRequestWithHeaders writes the header rows to the wire as given, for requests the
// standard client cannot express: preserved casing, unnormalized values, duplicate headers.
func (s *Steps) sendRawRequestWithHeaders(ctx context.Context, method, path string, table *godog.Table) error {
	rows, err := tableRows(table)
	if err != nil {
		return err
	}
	return s.sendRawRequest(ctx, method, path, rows)
}

func (s *Steps) sendRawRequest(ctx context.Context, method, path string, rows [][2]string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	method = strings.ToUpper(method)

	headers, err := rawHeaderLines(ctx, rows)
	if err != nil {
		return err
	}

	base, err := s.topo.URL("platform-gateway", "http")
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
	host := s.base.RequestHost(ctx)
	if host == "" {
		host = endpoint.Hostname()
	}

	httpx.ClearPublished(ctx)
	started := time.Now()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint.Host)
	if err != nil {
		return fmt.Errorf("connect to gateway endpoint %q: %w", endpoint.Host, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(rawRequestTimeout))

	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\n", method, resolved)
	fmt.Fprintf(&request, "Host: %s\r\n", host)
	for _, header := range headers {
		fmt.Fprintf(&request, "%s: %s\r\n", header.name, header.value)
	}
	request.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(request.String())); err != nil {
		return fmt.Errorf("send raw request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		return fmt.Errorf("read raw response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read raw response body of %s %s: %w", method, resolved, err)
	}
	return s.funnel.Publish(ctx, &httpx.Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header,
		Method:     method,
		URL:        base + resolved,
		Elapsed:    time.Since(started),
	})
}

func rawHeaderLines(ctx context.Context, rows [][2]string) ([]rawHeader, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("raw request headers table must not be empty")
	}
	headers := make([]rawHeader, 0, len(rows))
	for i, row := range rows {
		name := strings.TrimSpace(row[0])
		if name == "" {
			return nil, fmt.Errorf("raw request headers row %d has an empty header name", i+1)
		}
		expanded, err := stepscommon.Expand(ctx, row[1])
		if err != nil {
			return nil, err
		}
		headers = append(headers, rawHeader{name: name, value: decodeRawHeaderValue(expanded)})
	}
	return headers, nil
}

// decodeRawHeaderValue resolves \t, \r, \n, \\ and \xHH, leaving any other escape as written.
func decodeRawHeaderValue(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			b.WriteByte(value[i])
			continue
		}
		switch value[i+1] {
		case 't':
			b.WriteByte('\t')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case '\\':
			b.WriteByte('\\')
			i++
		case 'x':
			if i+3 < len(value) {
				if n, err := strconv.ParseUint(value[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(n))
					i += 3
					continue
				}
			}
			b.WriteByte(value[i])
		default:
			b.WriteByte(value[i])
		}
	}
	return b.String()
}
