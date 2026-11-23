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
	"slices"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

const keyStoppedProcesses = "stoppedProcesses"

func (s *Steps) registerProcessSignals(sc *godog.ScenarioContext) {
	sc.Step(`^I send signal "(STOP|CONT|KILL)" to the "([^"]*)" process in the "([^"]*)" service$`,
		s.sendProcessSignal)

	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		s.resumeStoppedProcesses(ctx)
		return ctx, nil
	})
}

type stoppedProcess struct {
	service string
	process string
}

func (s *Steps) stoppedProcessList(ctx context.Context) ([]stoppedProcess, error) {
	stored, ok := tcontext.Get(ctx, keyStoppedProcesses)
	if !ok {
		return nil, nil
	}
	list, ok := stored.([]stoppedProcess)
	if !ok {
		return nil, fmt.Errorf("stopped-process list has an unexpected type %T", stored)
	}
	return list, nil
}

func (s *Steps) rememberStoppedProcess(ctx context.Context, service, process string) error {
	list, err := s.stoppedProcessList(ctx)
	if err != nil {
		return err
	}
	return tcontext.Set(ctx, keyStoppedProcesses, append(slices.Clone(list), stoppedProcess{service: service, process: process}))
}

func (s *Steps) forgetStoppedProcess(ctx context.Context, service, process string) error {
	list, err := s.stoppedProcessList(ctx)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(list), func(p stoppedProcess) bool {
		return p.service == service && p.process == process
	})
	return tcontext.Set(ctx, keyStoppedProcesses, kept)
}

// processSignalScript scans /proc because the gateway images package neither pkill nor pgrep.
//
// It signals every process of that name, not the first one it finds, and then waits until the
// signal has taken effect: a STOPped process is in state T, a CONTinued one is not, and a KILLed one
// is gone. A signal is delivered asynchronously, so a request sent straight after "kill" returns
// can still reach a process that has not stopped yet, and a scenario that expects the hang would
// read an answer from a live process instead.
func processSignalScript(signal, process string) string {
	return fmt.Sprintf(`state() {
  local stat
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || { echo gone; return; }
  stat=${stat##*) }
  echo "${stat:0:1}"
}
pids=""
for p in /proc/[0-9]*; do
  pid=$(basename "$p")
  if [ -r "$p/cmdline" ] && tr '\0' '\n' < "$p/cmdline" 2>/dev/null | head -n1 | grep -q '/%[1]s$'; then
    pids="$pids $pid"
  fi
done
if [ -z "$pids" ]; then
  echo "no process named %[1]s found" >&2
  exit 1
fi
for pid in $pids; do
  kill -%[2]s "$pid" || exit 1
done
for pid in $pids; do
  settled=""
  for _ in $(seq 1 100); do
    s=$(state "$pid")
    case "%[2]s" in
      STOP) [ "$s" = T ] && settled=1 ;;
      CONT) [ "$s" != T ] && settled=1 ;;
      KILL) { [ "$s" = gone ] || [ "$s" = Z ]; } && settled=1 ;;
    esac
    [ -n "$settled" ] && break
    sleep 0.05
  done
  if [ -z "$settled" ]; then
    echo "process $pid of %[1]s did not react to %[2]s" >&2
    exit 1
  fi
done`, process, signal)
}

func (s *Steps) sendProcessSignal(ctx context.Context, signal, process, service string) error {
	stack, resolved, err := s.topo.ServiceControl(service)
	if err != nil {
		return err
	}
	if _, err := stack.Exec(ctx, resolved, []string{"bash", "-c", processSignalScript(signal, process)}); err != nil {
		return fmt.Errorf("sending %s to process %q in service %q: %w", signal, process, service, err)
	}
	switch signal {
	case "STOP":
		return s.rememberStoppedProcess(ctx, service, process)
	case "CONT":
		return s.forgetStoppedProcess(ctx, service, process)
	default:
		return nil
	}
}

// resumeStoppedProcesses clears the list too, which outlives the scenario in the runner's context.
func (s *Steps) resumeStoppedProcesses(ctx context.Context) {
	list, err := s.stoppedProcessList(ctx)
	if err != nil {
		return
	}
	for _, p := range list {
		stack, resolved, err := s.topo.ServiceControl(p.service)
		if err != nil {
			continue
		}
		_, _ = stack.Exec(ctx, resolved, []string{"bash", "-c", processSignalScript("CONT", p.process)})
	}
	_ = tcontext.Set(ctx, keyStoppedProcesses, []stoppedProcess(nil))
}
