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

// Package runsuites runs the blocks of the integration suites of several policies at once, keeping
// the number of blocks that run at the same time at a limit until none is left to start. A suite
// is a process of its own, so the framework's -block-parallel bounds the blocks of one suite only;
// the limit across suites is kept here, with every block run as a job of its own.
package runsuites

import (
	"sort"
	"sync"
)

// Job is one block to run. It takes one slot while it runs.
type Job struct {
	// Name identifies the block in the output and in the list of failures.
	Name string

	// Priority orders the jobs: a job with a higher priority starts before a job with a lower
	// one. The number of runners a block executes is a good priority, since it keeps the longest
	// blocks from finishing last on their own.
	Priority int

	// Slot is the number of the runner that ran the job, counted from 1. Schedule sets it before it
	// calls run; a runner is one of the limit workers, and takes the next job when it ends the last.
	Slot int
}

// Schedule runs every job through run, at most limit at a time, and returns the names of the jobs
// whose run returned an error, in name order. A job starts as soon as a runner is free, so limit jobs
// are running until fewer than limit are left. A limit below one counts as one.
func Schedule(jobs []Job, limit int, run func(Job) error) []string {
	limit = max(limit, 1)
	queue := ordered(jobs)

	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
		next   = make(chan Job)
	)
	for slot := 1; slot <= min(limit, len(queue)); slot++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range next {
				job.Slot = slot
				if err := run(job); err != nil {
					mu.Lock()
					failed = append(failed, job.Name)
					mu.Unlock()
				}
			}
		}()
	}
	for _, job := range queue {
		next <- job
	}
	close(next)
	wg.Wait()
	sort.Strings(failed)
	return failed
}

// ordered returns a copy of jobs with the highest priority first, and in the given order among
// equal priorities.
func ordered(jobs []Job) []Job {
	out := append([]Job(nil), jobs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })
	return out
}
