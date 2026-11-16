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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/catalog/shared"
	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

// policySteps holds what the mcp-auth policy's steps share within one runner.
type policySteps struct {
	topo *frameworkruntime.Topology
	now  func() time.Time
}

func newPolicySteps(topo *frameworkruntime.Topology) *policySteps {
	return &policySteps{topo: topo, now: time.Now}
}

// register binds the steps below. Add a step here only when no shared step expresses the
// behaviour, and give it a unit test in steps_test.go.
func (s *policySteps) register(sc *godog.ScenarioContext) {
	sc.Step(`^I mint a JWT token from the testbench OIDC provider expiring in (-?\d+) seconds and store it as "([^"]*)" with claims:$`,
		s.mintOIDCToken)
}

// mintOIDCToken asks the testbench OIDC provider to sign a token with the given claims and stores
// it under key. The provider signs with the key the oidc-km key manager trusts, so a token minted
// with no extra claims is valid, and each test token can differ from it in exactly one claim. The
// step sets exp to the given number of seconds from now (negative for a token that has already
// expired) and iat to one hour before exp, so the claims must not set them.
func (s *policySteps) mintOIDCToken(ctx context.Context, expiresIn int, key string, claims *godog.DocString) error {
	resolved, err := stepscommon.Expand(ctx, claims.Content)
	if err != nil {
		return err
	}
	base, err := s.topo.URL("testbench", "oidc")
	if err != nil {
		return err
	}
	client, err := identityProviderClient()
	if err != nil {
		return err
	}
	token, err := mintToken(ctx, client, base, resolved, s.now().Add(time.Duration(expiresIn)*time.Second))
	if err != nil {
		return err
	}
	local, ok := tcontext.LocalOf(ctx)
	if !ok || local == nil {
		return fmt.Errorf("cannot store a JWT token without runner context")
	}
	local.Set(key, token)
	return nil
}

// identityProviderClient trusts only the certificate the framework gives the testbench OIDC
// provider, instead of skipping certificate checks.
func identityProviderClient() (*httpx.Client, error) {
	tlsConfig, err := identityProviderTLSConfig(shared.IdentityProviderTLS().CertPEM)
	if err != nil {
		return nil, err
	}
	return httpx.NewClient(httpx.Options{
		Timeout: 15 * time.Second, MaxRetries: 3, RetryDelay: time.Second, TLSClientConfig: tlsConfig,
	}), nil
}

// identityProviderTLSConfig trusts only the given certificate.
func identityProviderTLSConfig(certPEM []byte) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("loading the identity provider certificate")
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}

// mintToken posts the claims, with exp and iat added, to <base>/mint and returns the signed token.
func mintToken(ctx context.Context, client *httpx.Client, base, claimsJSON string, exp time.Time) (string, error) {
	claims := map[string]any{}
	if strings.TrimSpace(claimsJSON) != "" {
		if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
			return "", fmt.Errorf("parsing the claims: %w", err)
		}
	}
	for _, reserved := range []string{"exp", "iat"} {
		if _, ok := claims[reserved]; ok {
			return "", fmt.Errorf("the claims must not set %q: the step sets it from the expiry", reserved)
		}
	}
	claims["exp"] = exp.Unix()
	claims["iat"] = exp.Add(-time.Hour).Unix()
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(ctx, httpx.Request{
		Method: http.MethodPost, URL: strings.TrimSuffix(base, "/") + "/mint",
		Body: body, ContentType: "application/json",
	}, 0, 0)
	if err != nil {
		return "", fmt.Errorf("minting a JWT token: %w", err)
	}
	raw := resp.Body
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("minting a JWT token failed: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("the mint answer has no token: %s", strings.TrimSpace(string(raw)))
	}
	return out.Token, nil
}
