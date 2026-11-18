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

package platformgateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/retry"
	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

// Fail-fast waits. An observation either satisfies the wait, is one of the wait's listed
// in-between states, or contradicts it. Only the listed states are polled through; anything
// else ends the wait at once with what was observed.

// tolerated reports an in-between state the wait keeps polling through.
func tolerated(format string, args ...any) error {
	return retry.Transient(fmt.Errorf(format, args...))
}

// awaitState polls observe until it returns nil. A tolerated error keeps polling until the
// propagation ceiling and is logged, so in-between states stay countable; any other error
// fails the wait immediately.
func awaitState(ctx context.Context, what string, observe func(context.Context) error) error {
	return awaitStateWith(ctx, retry.Options{}, what, observe)
}

// awaitReadState is awaitState for a wait whose polls only read logs, listings, metrics or the
// listener's handshake, so it polls at retry.FastInterval.
func awaitReadState(ctx context.Context, what string, observe func(context.Context) error) error {
	return awaitStateWith(ctx, retry.Options{Fast: true}, what, observe)
}

func awaitStateWith(ctx context.Context, opts retry.Options, what string, observe func(context.Context) error) error {
	return retry.Await(ctx, opts,
		func(ctx context.Context) (bool, error) {
			if err := observe(ctx); err != nil {
				if retry.IsTransient(err) {
					slog.Info("wait tolerated an in-between state", "wait", what, "observed", err.Error())
				}
				return false, err
			}
			return true, nil
		},
		func(done bool) bool { return done },
		what)
}

// describe renders an observed response for a fail-fast or timeout message.
func describe(resp *httpx.Response) string {
	if resp == nil {
		return "no response"
	}
	return fmt.Sprintf("%s (upstream service time %q)", resp.Describe(), resp.Headers.Get(headerUpstreamServiceTime))
}

// headerUpstreamServiceTime is set by Envoy on every response an upstream produced and never
// on a reply Envoy generated itself, such as a request that matched no route.
const headerUpstreamServiceTime = "X-Envoy-Upstream-Service-Time"

// fromUpstream reports whether a response came from the upstream rather than from Envoy.
func fromUpstream(resp *httpx.Response) bool {
	return resp.Headers.Get(headerUpstreamServiceTime) != ""
}

// noRouteBody is the body of the gateway's own reply to a request that matched no route.
const noRouteBody = `{"error":"Not Found"}`

// policyChainMissingBody is the body of the policy engine's 500 for a route whose policy chain
// it has not received yet.
const policyChainMissingBody = `{"error":"Internal Server Error"}`

// routeInBetween names the replies a data-plane route gives while it is not live yet: the
// gateway's own no-route 404 before the route exists, the policy engine's 500 until it holds
// the route's policy chain (wso2/api-platform#3621) and, for a route that forwards, Envoy's
// own 503 while the upstream cluster warms.
func routeInBetween(resp *httpx.Response, allowWarmingUpstream bool) (string, bool) {
	if fromUpstream(resp) {
		return "", false
	}
	switch {
	case resp.StatusCode == http.StatusNotFound && strings.TrimSpace(resp.Text()) == noRouteBody:
		return "Envoy has no route yet", true
	case resp.StatusCode == http.StatusInternalServerError && strings.TrimSpace(resp.Text()) == policyChainMissingBody:
		return "the policy engine has no policy chain for the route yet", true
	case resp.StatusCode == http.StatusServiceUnavailable && allowWarmingUpstream:
		return "the upstream cluster is still warming", true
	default:
		return "", false
	}
}

// sendUntilRouteAnswers polls a data-plane path until its route is live and answers want.
// Waiting for 200 tolerates Envoy's no-route 404, the policy engine's missing-chain 500 and Envoy's
// 503 while the upstream warms. Waiting for 401, the rejection an authenticating policy gives, or
// for 503, the answer of a route whose upstream cannot be reached, tolerates only the first two,
// so a 200 fails at once. Any other answer fails at once too.
func (g *Gateway) sendUntilRouteAnswers(ctx context.Context, method, path string, want int) error {
	if want != http.StatusOK && want != http.StatusUnauthorized && want != http.StatusServiceUnavailable {
		return fmt.Errorf("waiting for a route supports status 200, 401 or 503, not %d", want)
	}
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	url, err := g.gatewayURL(resolved)
	if err != nil {
		return err
	}
	method = strings.ToUpper(method)
	headers := g.scenarioHeaders(ctx)
	return awaitState(ctx, fmt.Sprintf("waiting for %s %s to answer %d", method, url, want),
		func(ctx context.Context) error {
			resp, sendErr := g.funnel.Send(ctx, httpx.Request{Method: method, URL: url, Headers: headers, Host: g.requestHost(ctx)})
			if sendErr != nil {
				return tolerated("the gateway did not answer: %v", sendErr)
			}
			if resp.StatusCode == want {
				return nil
			}
			if state, ok := routeInBetween(resp, want == http.StatusOK); ok {
				return tolerated("%s: %s", state, describe(resp))
			}
			return fmt.Errorf("expected %d once the route is live, got %s", want, describe(resp))
		})
}

// envoyRouteDump is the part of Envoy's dynamic_route_configs dump that says where a path goes.
type envoyRouteDump struct {
	Configs []struct {
		RouteConfig struct {
			VirtualHosts []struct {
				Routes []envoyRoute `json:"routes"`
			} `json:"virtual_hosts"`
		} `json:"route_config"`
	} `json:"configs"`
}

type envoyRoute struct {
	Match struct {
		Prefix              string `json:"prefix"`
		Path                string `json:"path"`
		PathSeparatedPrefix string `json:"path_separated_prefix"`
		SafeRegex           struct {
			Regex string `json:"regex"`
		} `json:"safe_regex"`
	} `json:"match"`
	Route *struct {
		Cluster          string `json:"cluster"`
		ClusterHeader    string `json:"cluster_header"`
		WeightedClusters *struct {
			Clusters []struct {
				Name string `json:"name"`
			} `json:"clusters"`
		} `json:"weighted_clusters"`
	} `json:"route"`
}

// matches reports whether the route's path match takes path. Header and method matchers are
// ignored, so every route that could serve the path counts.
func (r envoyRoute) matches(path string) (bool, error) {
	m := r.Match
	switch {
	case m.Path != "":
		return path == m.Path, nil
	case m.SafeRegex.Regex != "":
		re, err := regexp.Compile(`^(?:` + m.SafeRegex.Regex + `)$`)
		if err != nil {
			return false, fmt.Errorf("Envoy route regex %q: %w", m.SafeRegex.Regex, err)
		}
		return re.MatchString(path), nil
	case m.PathSeparatedPrefix != "":
		p := m.PathSeparatedPrefix
		return path == p || strings.HasPrefix(path, p+"/"), nil
	case m.Prefix != "":
		return strings.HasPrefix(path, m.Prefix), nil
	default:
		return false, nil
	}
}

// routeClusters returns the clusters of every forwarding route that serves path, sorted, and
// reports whether any forwarding route matched. Routes Envoy answers itself are skipped: the
// gateway's health routes and its catch-all "no-api-found" route, whose prefix "/" matches every
// path and answers the no-route 404 until an API's own route exists. A forwarding route that
// picks its cluster per request fails, since its cluster cannot be known in advance.
func routeClusters(dump envoyRouteDump, path string) ([]string, bool, error) {
	clusters := map[string]bool{}
	matched := false
	for _, config := range dump.Configs {
		for _, host := range config.RouteConfig.VirtualHosts {
			for _, route := range host.Routes {
				if route.Route == nil {
					continue
				}
				ok, err := route.matches(path)
				if err != nil {
					return nil, false, err
				}
				if !ok {
					continue
				}
				matched = true
				switch {
				case route.Route.Cluster != "":
					clusters[route.Route.Cluster] = true
				case route.Route.WeightedClusters != nil && len(route.Route.WeightedClusters.Clusters) > 0:
					for _, c := range route.Route.WeightedClusters.Clusters {
						clusters[c.Name] = true
					}
				default:
					return nil, true, fmt.Errorf("the Envoy route for %s picks its cluster per request, so it cannot be checked", path)
				}
			}
		}
	}
	return sortedKeys(clusters), matched, nil
}

// upstreamReadiness decides, from the route's clusters and Envoy's warming and active cluster
// lists, whether a request on the route would reach its upstream. Every in-between state is
// tolerated: no route yet, a cluster still warming, or a cluster not yet added.
func upstreamReadiness(path string, clusters []string, matched bool, warming, active []string) error {
	if !matched {
		return tolerated("Envoy has no route that forwards %s yet", path)
	}
	isWarming := map[string]bool{}
	for _, name := range warming {
		isWarming[name] = true
	}
	isActive := map[string]bool{}
	for _, name := range active {
		isActive[name] = true
	}
	for _, name := range clusters {
		if isWarming[name] {
			return tolerated("the upstream cluster %s of %s is still warming", name, path)
		}
		if !isActive[name] {
			return tolerated("the upstream cluster %s of %s is not active yet", name, path)
		}
	}
	return nil
}

// envoyActiveClusters lists the names of the dynamic clusters Envoy is using.
func (g *Gateway) envoyActiveClusters(ctx context.Context) ([]string, error) {
	var dump struct {
		Configs []struct {
			Cluster struct {
				Name string `json:"name"`
			} `json:"cluster"`
		} `json:"configs"`
	}
	if err := g.readJSON(ctx, "envoy-admin", "/config_dump?resource=dynamic_active_clusters", &dump); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(dump.Configs))
	for _, c := range dump.Configs {
		names = append(names, c.Cluster.Name)
	}
	return names, nil
}

// awaitUpstreamForwarding waits until Envoy would forward a request on path to a warm upstream,
// reading only Envoy's admin endpoint, so it sends nothing to the route or its backend. A policy's
// own rejection (an authenticating policy's 401) proves the route and its policy chain are live,
// but it is answered before the upstream, so it says nothing about the upstream cluster. Each
// backend address has one cluster, which Envoy drops when the last API using it is deleted and
// warms again when the next one is created; until it is warm, a forwarded request gets Envoy's
// 503 with an empty body.
func (g *Gateway) awaitUpstreamForwarding(ctx context.Context, path string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	if i := strings.IndexByte(resolved, '?'); i >= 0 {
		resolved = resolved[:i]
	}
	return awaitReadState(ctx, fmt.Sprintf("waiting for Envoy to forward %s to a warm upstream", resolved),
		func(ctx context.Context) error {
			var routes envoyRouteDump
			if err := g.readJSON(ctx, "envoy-admin", "/config_dump?resource=dynamic_route_configs", &routes); err != nil {
				return err
			}
			clusters, matched, err := routeClusters(routes, resolved)
			if err != nil {
				return err
			}
			if !matched {
				return upstreamReadiness(resolved, nil, false, nil, nil)
			}
			warming, err := g.envoyWarmingClusters(ctx)
			if err != nil {
				return err
			}
			active, err := g.envoyActiveClusters(ctx)
			if err != nil {
				return err
			}
			return upstreamReadiness(resolved, clusters, true, warming, active)
		})
}

func (g *Gateway) registerWaitSteps(sc *godog.ScenarioContext) {
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" until the route answers (\d+)$`, g.sendUntilRouteAnswers)
	sc.Step(`^I wait until the router can forward "([^"]*)" to its upstream$`, g.awaitUpstreamForwarding)
}
