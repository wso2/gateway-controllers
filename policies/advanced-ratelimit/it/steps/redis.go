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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/catalog/infrastructure"
	"github.com/wso2/api-platform/tests/framework/core/util/retry"

	stepscommon "github.com/wso2/gateway-controllers/tests/it/common/steps/common"
)

const (
	redisComponent = "redis"
	redisEndpoint  = "redis"

	// dockerTimeout bounds one docker command; stopping Redis takes well under a second.
	dockerTimeout = 30 * time.Second

	// redisKeyPrefix is the policy's default Redis key prefix; the overlays do not change it.
	redisKeyPrefix = "ratelimit:v1:"
)

// redisKeyFragment is what a scenario may ask for in a counter key. It becomes part of a Redis
// glob pattern, so no glob character is allowed.
var redisKeyFragment = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func (s *Steps) registerRedis(sc *godog.ScenarioContext) {
	sc.Step(`^the "([^"]*)" service logs should not contain the Redis password$`, s.logsHideRedisPassword)
	sc.Step(`^I stop the Redis component$`, s.stopRedis)
	sc.Step(`^I start the Redis component$`, s.startRedis)
	sc.Step(`^the Redis counter for "([^"]*)" should reach (\d+)$`, s.redisCounterReaches)
	// A scenario that fails while Redis is down must not leave it down for the next one.
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if s.stoppedRedis == "" {
			return ctx, nil
		}
		return ctx, s.startRedis(ctx)
	})
}

// logsHideRedisPassword checks the log of a service as it stands for the password the framework
// gave the Redis component. A log only grows, so absence is checked once.
func (s *Steps) logsHideRedisPassword(ctx context.Context, service string) error {
	if s.topo == nil {
		return fmt.Errorf("the scenario has no topology to read the %q logs from", service)
	}
	stack, _, err := s.topo.ServiceControl(service)
	if err != nil {
		return err
	}
	return secretAbsent(stack.Logs(ctx), infrastructure.RedisPassword, service)
}

// secretAbsent returns an error when the text holds the secret. The secret itself is never part
// of the error, so a failure does not write it to the test output. An empty secret is refused,
// because every text contains it.
func secretAbsent(text, secret, service string) error {
	if secret == "" {
		return fmt.Errorf("there is no secret to look for in the %q logs", service)
	}
	if strings.Contains(text, secret) {
		return fmt.Errorf("the %q logs contain the Redis password", service)
	}
	return nil
}

// stopRedis stops the block's Redis container. The framework runs Redis as a plain container, not
// a compose service, so the shared service-control steps cannot reach it; the container is found
// by the host port the framework published for it, which no other block shares.
func (s *Steps) stopRedis(ctx context.Context) error {
	if s.stoppedRedis != "" {
		return fmt.Errorf("Redis is already stopped in this scenario")
	}
	id, err := s.redisContainerID(ctx)
	if err != nil {
		return err
	}
	if _, err := s.docker(ctx, "stop", "--time", "1", id); err != nil {
		return err
	}
	s.stoppedRedis = id
	return nil
}

// redisContainerID finds the block's Redis container by the host port the framework published
// for it, and remembers it: once Redis has been stopped and started the port no longer matches.
func (s *Steps) redisContainerID(ctx context.Context) (string, error) {
	if s.redisID != "" {
		return s.redisID, nil
	}
	port, err := s.redisHostPort()
	if err != nil {
		return "", err
	}
	out, err := s.docker(ctx, "ps", "--quiet", "--filter", "publish="+strconv.Itoa(port))
	if err != nil {
		return "", err
	}
	id, err := soleContainerID(out, port)
	if err != nil {
		return "", err
	}
	s.redisID = id
	return id, nil
}

// redisCounterReaches waits until a rate limit counter whose key holds the fragment has counted
// at least want requests. It reads Redis without touching the quota, so it shows what a gateway
// has flushed to the shared store, which a request to the gateway cannot do without consuming
// that quota.
func (s *Steps) redisCounterReaches(ctx context.Context, fragment string, want int) error {
	resolved, err := stepscommon.Expand(ctx, fragment)
	if err != nil {
		return err
	}
	if !redisKeyFragment.MatchString(resolved) {
		return fmt.Errorf("the counter key fragment %q must hold only letters, digits, '.', '_' and '-'", resolved)
	}
	id, err := s.redisContainerID(ctx)
	if err != nil {
		return err
	}
	return retry.Await[int64](ctx, retry.Options{Fast: true},
		func(ctx context.Context) (int64, error) {
			highest, readErr := s.highestCounter(ctx, id, resolved)
			if readErr != nil {
				return 0, retry.Transient(readErr)
			}
			return highest, nil
		},
		func(highest int64) bool { return highest >= int64(want) },
		fmt.Sprintf("waiting for the Redis counter for %q to reach %d", resolved, want))
}

// highestCounter returns the largest value among the rate limit counters whose key holds the
// fragment, or zero when there is none.
func (s *Steps) highestCounter(ctx context.Context, container, fragment string) (int64, error) {
	cli := func(args ...string) (string, error) {
		// The password travels in the environment of the exec, not on a command line.
		full := append([]string{"exec", "-e", "REDISCLI_AUTH=" + infrastructure.RedisPassword, container, "redis-cli"}, args...)
		return s.docker(ctx, full...)
	}
	keys, err := cli("--scan", "--pattern", redisKeyPrefix+"*"+fragment+"*")
	if err != nil {
		return 0, err
	}
	var highest int64
	for _, key := range strings.Fields(keys) {
		raw, err := cli("GET", key)
		if err != nil {
			return 0, err
		}
		value, err := parseCounter(raw)
		if err != nil {
			return 0, err
		}
		highest = max(highest, value)
	}
	return highest, nil
}

// parseCounter reads the output of redis-cli GET. A key that expired between the scan and the
// read prints nothing, which counts as zero.
func parseCounter(out string) (int64, error) {
	text := strings.TrimSpace(out)
	if text == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("a Redis counter holds %q, not a number", text)
	}
	return value, nil
}

// startRedis starts the container stopRedis stopped.
func (s *Steps) startRedis(ctx context.Context) error {
	if s.stoppedRedis == "" {
		return fmt.Errorf("Redis was not stopped in this scenario")
	}
	if _, err := s.docker(ctx, "start", s.stoppedRedis); err != nil {
		return err
	}
	s.stoppedRedis = ""
	return nil
}

func (s *Steps) redisHostPort() (int, error) {
	if s.topo == nil {
		return 0, fmt.Errorf("the scenario has no topology to find Redis in")
	}
	instance, err := s.topo.Component(redisComponent)
	if err != nil {
		return 0, err
	}
	return instance.MappedPort(redisEndpoint)
}

// soleContainerID reads the output of `docker ps --quiet` and requires exactly one container.
func soleContainerID(out string, port int) (string, error) {
	ids := strings.Fields(out)
	if len(ids) != 1 {
		return "", fmt.Errorf("expected one container publishing port %d, found %d", port, len(ids))
	}
	return ids[0], nil
}

// runDocker runs the docker CLI, which uses the same daemon the framework's containers run on.
func runDocker(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
