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
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/catalog/infrastructure"
)

const (
	redisComponent = "redis"
	redisEndpoint  = "redis"

	// dockerTimeout bounds one docker command; stopping Redis takes well under a second.
	dockerTimeout = 30 * time.Second
)

func (s *Steps) registerRedis(sc *godog.ScenarioContext) {
	sc.Step(`^the "([^"]*)" service logs should not contain the Redis password$`, s.logsHideRedisPassword)
	sc.Step(`^I stop the Redis component$`, s.stopRedis)
	sc.Step(`^I start the Redis component$`, s.startRedis)
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
	port, err := s.redisHostPort()
	if err != nil {
		return err
	}
	out, err := s.docker(ctx, "ps", "--quiet", "--filter", "publish="+strconv.Itoa(port))
	if err != nil {
		return err
	}
	id, err := soleContainerID(out, port)
	if err != nil {
		return err
	}
	if _, err := s.docker(ctx, "stop", "--time", "1", id); err != nil {
		return err
	}
	s.stoppedRedis = id
	return nil
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
