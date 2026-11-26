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
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/actor"
	controlplane "github.com/wso2/api-platform/tests/framework/core/catalog/platformapi"
	"github.com/wso2/api-platform/tests/framework/core/catalog/shared"
	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/unique"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	controlPlaneAPIBase = "/api/v0.9"

	upstreamURL = "http://testbench:3000"

	deploymentSeparator = "\x00"
)

// A lower order is deleted first: a deployment, then its API, then its project.
var (
	deploymentKind = cleanup.Kind{Name: "platform-api-deployment", Order: 40}
	restAPIKind    = cleanup.Kind{Name: "platform-api-rest-api", Order: 50}
	projectKind    = cleanup.Kind{Name: "platform-api-project", Order: 100}
)

// controlPlane lazily builds the client that trusts the generated control plane CA.
type controlPlane struct {
	once   sync.Once
	client *httpx.Client
	err    error
}

func (s *Steps) registerControlPlane(sc *godog.ScenarioContext) {
	sc.Step(`^I create a project "([^"]*)" on the control plane$`, s.createProject)
	sc.Step(`^I create a REST API "([^"]*)" via the control plane in project "([^"]*)" with context "([^"]*)" and the advanced-ratelimit quotas:$`,
		s.createRestAPIWithQuotas)
	sc.Step(`^I deploy the "RestApi" "([^"]*)" to the (first|second) gateway via the control plane$`,
		s.deployRestAPIAt)
}

func controlPlaneTLSConfig(caPEM []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("loading the generated control plane CA certificate")
	}
	return &tls.Config{RootCAs: roots, ServerName: "platform-api"}, nil
}

func (s *Steps) controlPlaneClient() (*httpx.Client, error) {
	s.controlPlane.once.Do(func() {
		tlsConfig, err := controlPlaneTLSConfig(shared.ControlPlaneCrypto()["certs/cert.pem"])
		if err != nil {
			s.controlPlane.err = err
			return
		}
		s.controlPlane.client = httpx.NewClient(httpx.Options{
			Timeout: requestTimeout, MaxRetries: 3, RetryDelay: 2 * time.Second, TLSClientConfig: tlsConfig,
		})
	})
	return s.controlPlane.client, s.controlPlane.err
}

func (s *Steps) authed(ctx context.Context) (base, bearer string, err error) {
	base, err = s.topo.URL("platform-api", "https")
	if err != nil {
		return "", "", err
	}
	admin := actor.Administrator()
	bearer, err = controlplane.ControlPlaneLogin(ctx, base, admin.Username, admin.Password)
	if err != nil {
		return "", "", fmt.Errorf("authenticating to the control plane: %w", err)
	}
	return base, bearer, nil
}

func (s *Steps) do(ctx context.Context, method, base, bearer, path string, payload any) (*httpx.Response, error) {
	client, err := s.controlPlaneClient()
	if err != nil {
		return nil, err
	}
	request := httpx.Request{
		Method:  method,
		URL:     base + controlPlaneAPIBase + path,
		Headers: map[string]string{"Authorization": "Bearer " + bearer},
	}
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		request.Body = body
		request.ContentType = "application/json"
	}
	return client.Do(ctx, request, 0, 0)
}

func (s *Steps) postJSON(ctx context.Context, base, bearer, path string, payload, out any) error {
	resp, err := s.do(ctx, http.MethodPost, base, bearer, path, payload)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	if !resp.Succeeded() {
		return fmt.Errorf("POST %s failed: %s", path, resp.Describe())
	}
	if out != nil {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("decoding response from POST %s: %w", path, err)
		}
	}
	return nil
}

func (s *Steps) registerResource(ctx context.Context, kind cleanup.Kind, id, path string) error {
	registry, err := cleanup.Of(ctx)
	if err != nil {
		return err
	}
	if err := registry.RegisterDeleter(kind, func(ctx context.Context, res cleanup.Resource) error {
		base, bearer, err := s.authed(ctx)
		if err != nil {
			return err
		}
		resp, err := s.do(ctx, http.MethodDelete, base, bearer, path+"/"+res.ID, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusNotFound && !resp.Succeeded() {
			// The control plane keeps the last project of an organization.
			if kind == projectKind && isLastProjectValidation(resp) {
				return nil
			}
			return fmt.Errorf("deleting %s: %s", res.ID, resp.Describe())
		}
		return nil
	}); err != nil {
		return err
	}
	return registry.Register(cleanup.Resource{Kind: kind, ID: id, Actor: "admin", Description: "created via platform-api"})
}

func isLastProjectValidation(resp *httpx.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		return false
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return false
	}
	return body.Code == "VALIDATION_FAILED" && body.Message == "Organization must have at least one project"
}

func (s *Steps) registerDeployment(ctx context.Context, handle, deploymentID, gatewayID string) error {
	registry, err := cleanup.Of(ctx)
	if err != nil {
		return err
	}
	if err := registry.RegisterDeleter(deploymentKind, func(ctx context.Context, res cleanup.Resource) error {
		parts := strings.Split(res.ID, deploymentSeparator)
		if len(parts) != 3 {
			return fmt.Errorf("invalid platform deployment cleanup record")
		}
		base, bearer, err := s.authed(ctx)
		if err != nil {
			return err
		}
		path := "/rest-apis/" + parts[0] + "/deployments/" + parts[1] + "/undeploy?gatewayId=" + parts[2]
		resp, err := s.do(ctx, http.MethodPost, base, bearer, path, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusNotFound && !resp.Succeeded() {
			return fmt.Errorf("undeploying platform resource: %s", resp.Describe())
		}
		return nil
	}); err != nil {
		return err
	}
	id := strings.Join([]string{handle, deploymentID, gatewayID}, deploymentSeparator)
	return registry.Register(cleanup.Resource{Kind: deploymentKind, ID: id, Actor: "admin", Description: "deployed via platform-api"})
}

func (s *Steps) createProject(ctx context.Context, handle string) error {
	resolved, err := stepscommon.Expand(ctx, handle)
	if err != nil {
		return err
	}
	base, bearer, err := s.authed(ctx)
	if err != nil {
		return err
	}
	if err := s.postJSON(ctx, base, bearer, "/projects",
		map[string]any{"id": resolved, "displayName": resolved}, nil); err != nil {
		return fmt.Errorf("creating control-plane project %q: %w", resolved, err)
	}
	return s.registerResource(ctx, projectKind, resolved, "/projects")
}

// limitedPath is the operation that carries the policy; healthPath carries none.
const (
	limitedPath = "/limited"
	healthPath  = "/health"
)

// parseQuotas decodes the policy's quotas parameter, which must be a non-empty JSON array.
func parseQuotas(raw string) ([]any, error) {
	var quotas []any
	if err := json.Unmarshal([]byte(raw), &quotas); err != nil {
		return nil, fmt.Errorf("the quotas DocString is not a JSON array: %w", err)
	}
	if len(quotas) == 0 {
		return nil, fmt.Errorf("the quotas DocString holds no quota")
	}
	return quotas, nil
}

// restAPIPayload builds a REST API with an unprotected /health operation and a /limited
// operation carrying the advanced-ratelimit policy at operation level.
func restAPIPayload(id, projectID, apiContext string, quotas []any) map[string]any {
	limit := []map[string]any{{
		"name": "advanced-ratelimit", "version": "v1", "params": map[string]any{"quotas": quotas},
	}}
	return map[string]any{
		"displayName": id,
		"context":     apiContext,
		"version":     "v1",
		"projectId":   projectID,
		"upstream":    map[string]any{"main": map[string]any{"url": upstreamURL}},
		"operations": []map[string]any{
			{"request": map[string]any{"method": "GET", "path": healthPath}},
			{"request": map[string]any{"method": "GET", "path": limitedPath, "policies": limit}},
		},
	}
}

func (s *Steps) createRestAPIWithQuotas(ctx context.Context, id, projectHandle, apiContext string, quotasDoc *godog.DocString) error {
	if quotasDoc == nil {
		return fmt.Errorf("the step needs a DocString holding the quotas JSON array")
	}
	resolvedID, err := stepscommon.Expand(ctx, id)
	if err != nil {
		return err
	}
	resolvedProject, err := stepscommon.Expand(ctx, projectHandle)
	if err != nil {
		return err
	}
	resolvedContext, err := stepscommon.Expand(ctx, apiContext)
	if err != nil {
		return err
	}
	resolvedQuotas, err := stepscommon.Expand(ctx, quotasDoc.Content)
	if err != nil {
		return err
	}
	quotas, err := parseQuotas(resolvedQuotas)
	if err != nil {
		return err
	}
	base, bearer, err := s.authed(ctx)
	if err != nil {
		return err
	}

	var created struct {
		ID     string `json:"id"`
		Handle string `json:"handle"`
		UUID   string `json:"uuid"`
	}
	if err := s.postJSON(ctx, base, bearer, "/rest-apis",
		restAPIPayload(resolvedID, resolvedProject, resolvedContext, quotas), &created); err != nil {
		return err
	}
	if err := checkAssignedHandle(created.Handle, created.ID, created.UUID, resolvedID); err != nil {
		return err
	}
	return s.registerResource(ctx, restAPIKind, resolvedID, "/rest-apis")
}

// checkAssignedHandle fails when the control plane named the API differently from the requested
// handle, because a later deploy would then address the wrong resource.
func checkAssignedHandle(handle, id, uuid, want string) error {
	if handle == "" {
		handle = id
	}
	if handle == "" {
		handle = uuid
	}
	if handle != "" && handle != want {
		return fmt.Errorf("control plane assigned REST API handle %q, expected %q: a later deploy would address the wrong resource", handle, want)
	}
	return nil
}

func gatewayHandleAt(ordinal string) (string, error) {
	switch ordinal {
	case "first":
		return "it-gateway-1", nil
	case "second":
		return "it-gateway-2", nil
	default:
		return "", fmt.Errorf("unknown gateway ordinal %q", ordinal)
	}
}

func (s *Steps) gatewayIDAt(ctx context.Context, base, bearer, ordinal string) (string, error) {
	handle, err := gatewayHandleAt(ordinal)
	if err != nil {
		return "", err
	}
	resp, err := s.do(ctx, http.MethodGet, base, bearer, "/gateways", nil)
	if err != nil {
		return "", fmt.Errorf("listing control-plane gateways: %w", err)
	}
	if !resp.Succeeded() {
		return "", fmt.Errorf("listing control-plane gateways: %s", resp.Describe())
	}
	var doc struct {
		List []struct {
			ID   string `json:"id"`
			UUID string `json:"uuid"`
		} `json:"list"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return "", fmt.Errorf("decoding the control-plane gateway list: %w", err)
	}
	for _, gateway := range doc.List {
		if gateway.ID == handle {
			if gateway.UUID != "" {
				return gateway.UUID, nil
			}
			return gateway.ID, nil
		}
	}
	return "", fmt.Errorf("control plane has no registered gateway with handle %q", handle)
}

func (s *Steps) deployRestAPIAt(ctx context.Context, handle, ordinal string) error {
	resolvedHandle, err := stepscommon.Expand(ctx, handle)
	if err != nil {
		return err
	}
	base, bearer, err := s.authed(ctx)
	if err != nil {
		return err
	}
	gatewayID, err := s.gatewayIDAt(ctx, base, bearer, ordinal)
	if err != nil {
		return err
	}

	// Attaching a gateway that is already attached is not a conflict.
	if err := s.postJSON(ctx, base, bearer, "/rest-apis/"+resolvedHandle+"/gateways",
		[]map[string]string{{"gatewayId": gatewayID}}, nil); err != nil {
		return fmt.Errorf("attaching gateway to REST API %q: %w", resolvedHandle, err)
	}

	deploymentName, err := unique.Unique(ctx, "dep")
	if err != nil {
		return err
	}
	var deployed struct {
		DeploymentID string `json:"deploymentId"`
	}
	if err := s.postJSON(ctx, base, bearer, "/rest-apis/"+resolvedHandle+"/deployments", map[string]any{
		"name":      deploymentName,
		"base":      "current",
		"gatewayId": gatewayID,
	}, &deployed); err != nil {
		return fmt.Errorf("deploying REST API %q: %w", resolvedHandle, err)
	}
	if deployed.DeploymentID == "" {
		return fmt.Errorf("deploying REST API %q: control plane returned no deployment id", resolvedHandle)
	}
	return s.registerDeployment(ctx, resolvedHandle, deployed.DeploymentID, gatewayID)
}
