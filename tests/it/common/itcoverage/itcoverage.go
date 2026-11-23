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

// Package itcoverage collects the coverage counters of the gateways the integration suites boot.
//
// The policy engine of a coverage build writes its counters to /coverage when it stops, and the
// framework stops and removes a block's containers at the end of the block, taking the counters
// with them. Its own collector only works for gateways it builds from source, so this one does
// not depend on the framework's: while the suites run, it watches for gateway runtime containers
// and starts a small helper container beside each that mounts the runtime's /coverage volume.
// Removing the runtime container leaves the volume, because the helper still uses it. When the run
// ends the counters are copied out of the helpers, which are then removed with the volumes. Only
// that volume is mounted: sharing everything of the runtime would carry its bind mounts, whose
// sources the framework deletes, and docker then cannot copy out of the helper.
package itcoverage

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// guestDir is the folder in the runtime container that holds the counters.
const guestDir = "/coverage"

// labelKey and labelValue mark the helper containers, so a stray one can be found and removed and
// so the collector can tell a helper's start from a runtime's: the helper is created from the
// runtime image, so its start matches the same event filter.
const (
	labelKey   = "gateway-controllers.it-coverage"
	labelValue = "helper"
	label      = labelKey + "=" + labelValue
)

// Docker runs a docker command and returns its standard output.
type Docker func(ctx context.Context, args ...string) ([]byte, error)

// ExecDocker runs the docker of the host.
func ExecDocker(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return out, fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(string(exit.Stderr)))
		}
	}
	return out, err
}

// Collector keeps the counters of every runtime container started while it runs.
type Collector struct {
	image  string
	out    string
	docker Docker
	logf   func(format string, args ...any)

	mu      sync.Mutex
	seen    map[string]bool
	helpers []helper
	errs    []error

	cancel context.CancelFunc
	events *exec.Cmd
	wg     sync.WaitGroup
}

// helper is a container that keeps the /coverage volume of one runtime.
type helper struct{ id, volume string }

// Start begins watching for containers of image and returns the collector. Counters are copied
// into folders beneath out by Collect. logf receives progress and problems.
func Start(ctx context.Context, image, out string, logf func(string, ...any)) (*Collector, error) {
	if strings.TrimSpace(image) == "" || strings.TrimSpace(out) == "" {
		return nil, errors.New("itcoverage: the runtime image and the output folder are required")
	}
	c := newCollector(image, out, ExecDocker, logf)

	watchCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.events = exec.CommandContext(watchCtx, "docker", eventsArgs(image)...)
	c.events.Stderr = os.Stderr
	stdout, err := c.events.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := c.events.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("itcoverage: watching docker events: %w", err)
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.watch(watchCtx, stdout)
	}()
	return c, nil
}

// eventsArgs is the docker command that prints, for every container of image as it starts, its id
// and, for a helper, its helper label.
func eventsArgs(image string) []string {
	return []string{"events", "--filter", "type=container", "--filter", "event=start",
		"--filter", "image=" + image, "--format", `{{.Actor.ID}} {{index .Actor.Attributes "` + labelKey + `"}}`}
}

func newCollector(image, out string, docker Docker, logf func(string, ...any)) *Collector {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Collector{image: image, out: out, docker: docker, logf: logf, seen: map[string]bool{}}
}

// watch attaches a helper to every container id read from the event stream.
func (c *Collector) watch(ctx context.Context, events io.Reader) {
	var attaching sync.WaitGroup
	defer attaching.Wait()
	scanner := bufio.NewScanner(events)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// An id alone is a runtime; an id with the helper label is one of ours.
		if len(fields) != 1 {
			continue
		}
		id := fields[0]
		attaching.Add(1)
		go func() {
			defer attaching.Done()
			c.attach(ctx, id)
		}()
	}
}

// attach starts the helper that keeps the /coverage volume of container id alive. A container that
// starts again, as a restarted runtime does, is attached once.
func (c *Collector) attach(ctx context.Context, id string) {
	c.mu.Lock()
	if c.seen[id] {
		c.mu.Unlock()
		return
	}
	c.seen[id] = true
	c.mu.Unlock()

	out, err := c.docker(ctx, "inspect", "-f",
		`{{range .Mounts}}{{if eq .Destination "`+guestDir+`"}}{{.Name}}{{end}}{{end}}`, id)
	volume := strings.TrimSpace(string(out))
	if err == nil && volume == "" {
		err = fmt.Errorf("it has no %s volume, so its image was not built for coverage", guestDir)
	}
	if err != nil {
		c.fail(fmt.Errorf("attaching to the runtime %s: %w", short(id), err))
		return
	}
	out, err = c.docker(ctx, "run", "-d", "-u", "0", "--label", label, "-v", volume+":"+guestDir,
		"--entrypoint", "sleep", c.image, "infinity")
	if err != nil {
		c.fail(fmt.Errorf("attaching to the runtime %s: %w", short(id), err))
		return
	}
	h := helper{id: strings.TrimSpace(string(out)), volume: volume}
	c.mu.Lock()
	c.helpers = append(c.helpers, h)
	c.mu.Unlock()
	c.logf("coverage: following runtime %s with helper %s\n", short(id), short(h.id))
}

func (c *Collector) fail(err error) {
	c.mu.Lock()
	c.errs = append(c.errs, err)
	c.mu.Unlock()
	c.logf("coverage: %v\n", err)
}

// Collect stops watching, copies the counters of every runtime out of its helper and removes the
// helpers and their volumes. It returns how many runtimes' counters were copied. Call it once,
// after every suite has ended and so every runtime has stopped and written its counters.
func (c *Collector) Collect(ctx context.Context) (int, error) {
	if c.cancel != nil {
		// Closing the event stream first and waiting makes sure no helper is still being started.
		c.cancel()
		_ = c.events.Wait()
		c.wg.Wait()
	}
	c.mu.Lock()
	helpers := append([]helper(nil), c.helpers...)
	errs := append([]error(nil), c.errs...)
	c.mu.Unlock()

	copied := 0
	for i, h := range helpers {
		dst := filepath.Join(c.out, strconv.Itoa(i+1))
		if err := os.MkdirAll(dst, 0o755); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := c.docker(ctx, "cp", h.id+":"+guestDir, dst); err != nil {
			errs = append(errs, fmt.Errorf("copying the counters of helper %s: %w", short(h.id), err))
		} else {
			copied++
		}
		if _, err := c.docker(ctx, "rm", "-f", h.id); err != nil {
			errs = append(errs, fmt.Errorf("removing helper %s: %w", short(h.id), err))
		}
		// The volume was made by the runtime container; once no container uses it, it is removed.
		if _, err := c.docker(ctx, "volume", "rm", "-f", h.volume); err != nil {
			errs = append(errs, fmt.Errorf("removing volume %s: %w", short(h.volume), err))
		}
	}
	return copied, errors.Join(errs...)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
