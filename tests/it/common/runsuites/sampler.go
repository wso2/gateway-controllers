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

package runsuites

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	procStat    = "/proc/stat"
	procMeminfo = "/proc/meminfo"
)

// Sample is the load of the whole machine at one moment of a run. The blocks that run at the same
// time share the machine, so a sample cannot be told apart by block.
type Sample struct {
	// AtMs is when the sample was taken, counted from the start of the run.
	AtMs int64 `json:"atMs"`

	// CPUPercent is the share of the machine's processor time that was busy since the sample
	// before, from 0 to 100 across all cores.
	CPUPercent float64 `json:"cpuPercent"`

	// MemUsedMB is the memory in use: the machine's total less what is available.
	MemUsedMB  int64 `json:"memUsedMb"`
	MemTotalMB int64 `json:"memTotalMb"`
}

// cpuTimes is the machine's processor time since boot, in the units /proc/stat reports.
type cpuTimes struct {
	busy  uint64
	total uint64
}

// readCPU reads the machine's processor time from the first line of /proc/stat. The time spent
// idle, and waiting for input and output, is not busy time.
func readCPU(r io.Reader) (cpuTimes, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return cpuTimes{}, err
	}
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("unexpected processor line %q", strings.TrimSpace(line))
	}
	var total, idle uint64
	for i, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("processor time %q: %w", field, err)
		}
		// Fields: user nice system idle iowait irq softirq steal guest guestnice. The guest times
		// are already part of user and nice.
		if i >= 8 {
			break
		}
		total += value
		if i == 3 || i == 4 {
			idle += value
		}
	}
	return cpuTimes{busy: total - idle, total: total}, nil
}

// cpuPercent returns the share of processor time that was busy between two readings.
func cpuPercent(before, after cpuTimes) float64 {
	if after.total <= before.total || after.busy < before.busy {
		return 0
	}
	return 100 * float64(after.busy-before.busy) / float64(after.total-before.total)
}

// readMemory reads the machine's total and available memory, in megabytes, from /proc/meminfo.
func readMemory(r io.Reader) (totalMB, availableMB int64, err error) {
	var found int
	scanner := bufio.NewScanner(r)
	for scanner.Scan() && found < 2 {
		name, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok || (name != "MemTotal" && name != "MemAvailable") {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, 0, fmt.Errorf("no value for %s", name)
		}
		kilobytes, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("%s %q: %w", name, fields[0], err)
		}
		if name == "MemTotal" {
			totalMB = kilobytes / 1024
		} else {
			availableMB = kilobytes / 1024
		}
		found++
	}
	if found < 2 {
		return 0, 0, fmt.Errorf("memory information is incomplete")
	}
	return totalMB, availableMB, nil
}

// takeSample reads the machine's load now. before is the processor time of the previous reading;
// the returned cpuTimes is this reading, for the next call.
func takeSample(statPath, meminfoPath string, before cpuTimes, at time.Duration) (Sample, cpuTimes, error) {
	stat, err := os.Open(statPath)
	if err != nil {
		return Sample{}, before, err
	}
	defer stat.Close()
	after, err := readCPU(stat)
	if err != nil {
		return Sample{}, before, err
	}
	meminfo, err := os.Open(meminfoPath)
	if err != nil {
		return Sample{}, before, err
	}
	defer meminfo.Close()
	total, available, err := readMemory(meminfo)
	if err != nil {
		return Sample{}, before, err
	}
	return Sample{
		AtMs:       at.Milliseconds(),
		CPUPercent: cpuPercent(before, after),
		MemUsedMB:  total - available,
		MemTotalMB: total,
	}, after, nil
}

// StartSampling records the machine's load every interval until the returned function is called.
// Where the load cannot be read, which is anywhere but Linux, it records nothing.
func (r *Recorder) StartSampling(interval time.Duration) (stop func()) {
	return r.startSampling(procStat, procMeminfo, interval)
}

func (r *Recorder) startSampling(statPath, meminfoPath string, interval time.Duration) (stop func()) {
	_, before, err := takeSample(statPath, meminfoPath, cpuTimes{}, 0)
	if err != nil {
		return func() {}
	}
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				sample, after, err := takeSample(statPath, meminfoPath, before, time.Since(r.start))
				if err != nil {
					continue
				}
				before = after
				r.mu.Lock()
				r.samples = append(r.samples, sample)
				r.mu.Unlock()
			}
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}
