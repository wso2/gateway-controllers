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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	// http2RequestTimeout bounds one request sent over HTTP/2.
	http2RequestTimeout = 30 * time.Second
	// maxHTTP2ResponseBodyBytes matches the funnel client's cap on a response body.
	maxHTTP2ResponseBodyBytes = 10 << 20
)

// sendRequestOverHTTP2 invokes a data-plane path once over unencrypted HTTP/2 (prior knowledge)
// and publishes the response, so the usual response assertions apply to it. It fails unless the
// gateway answers on HTTP/2. The funnel's client speaks only HTTP/1.1, so the request uses a
// client of its own. The scenario's headers are sent, and the request host, when one is set,
// becomes the request's :authority.
func (b *Base) sendRequestOverHTTP2(ctx context.Context, method, path string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := b.gatewayURL(resolved)
	if err != nil {
		return err
	}
	httpx.ClearPublished(ctx)
	resp, err := sendOverHTTP2(ctx, strings.ToUpper(method), target, b.requestHost(ctx), b.scenarioHeaders(ctx))
	if err != nil {
		return err
	}
	return b.funnel.Publish(ctx, resp)
}

// sendOverHTTP2 sends one request over unencrypted HTTP/2 and returns its response. Any
// response that is not HTTP/2 is an error.
func sendOverHTTP2(
	ctx context.Context, method, target, host string, headers map[string]string,
) (*httpx.Response, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parsing the gateway URL %q: %w", target, err)
	}
	request := &http.Request{
		Method: method,
		URL:    parsed,
		Host:   host,
		Header: make(http.Header),
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: &protocols}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:       http2RequestTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	started := time.Now()
	resp, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("sending %s %s over HTTP/2: %w (the gateway may not accept unencrypted HTTP/2)",
			method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		return nil, fmt.Errorf("expected an HTTP/2 response from %s %s, got protocol %q", method, target, resp.Proto)
	}
	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the body of %s %s: %w", method, target, err)
	}
	return &httpx.Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header.Clone(),
		Method:     method,
		URL:        target,
		Elapsed:    time.Since(started),
	}, nil
}

// readLimitedBody reads a response body, failing when it exceeds maxHTTP2ResponseBodyBytes.
func readLimitedBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxHTTP2ResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxHTTP2ResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds the %d-byte limit", maxHTTP2ResponseBodyBytes)
	}
	return body, nil
}
