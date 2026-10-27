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

// Package runsuites runs the integration suites of several policies at once while keeping the
// number of blocks they boot at the same time under one limit. Each suite is a process of its own,
// so the framework's -block-parallel bounds the blocks of one suite only; the limit across suites
// is kept here.
package runsuites

import (
	"slices"
	"sort"
	"sync"
)

// Job is one suite to run and the number of blocks it boots at once.
type Job struct {
	// Name identifies the suite, usually the policy it belongs to.
	Name string

	// Weight is the number of blocks the suite runs at the same time. A weight below one counts
	// as one, and a weight above the limit counts as the limit.
	Weight int
}

// Schedule runs every job through run and returns the names of the jobs whose run returned an
// error, in name order. A job starts as soon as the weights of the running jobs plus its own stay
// within limit, so when the weights of all jobs fit, they all run at once. The heaviest jobs start
// first and lighter ones fill the room they leave. A limit below one counts as one, which runs the
// jobs one at a time.
func Schedule(jobs []Job, limit int, run func(Job) error) []string {
	limit = max(limit, 1)
	pending := ordered(jobs, limit)

	var (
		mu     sync.Mutex
		wake   = sync.NewCond(&mu)
		used   int
		failed []string
		wg     sync.WaitGroup
	)
	for len(pending) > 0 {
		mu.Lock()
		next := firstFit(pending, limit-used)
		for next < 0 {
			wake.Wait()
			next = firstFit(pending, limit-used)
		}
		job := pending[next]
		pending = slices.Delete(pending, next, next+1)
		used += job.Weight
		mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := run(job)
			mu.Lock()
			defer mu.Unlock()
			used -= job.Weight
			if err != nil {
				failed = append(failed, job.Name)
			}
			wake.Broadcast()
		}()
	}
	wg.Wait()
	sort.Strings(failed)
	return failed
}

// ordered returns a copy of jobs with every weight clamped to 1..limit, heaviest first and in the
// given order among equal weights.
func ordered(jobs []Job, limit int) []Job {
	out := make([]Job, len(jobs))
	for i, job := range jobs {
		job.Weight = min(max(job.Weight, 1), limit)
		out[i] = job
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Weight > out[j].Weight })
	return out
}

// firstFit returns the index of the first job whose weight is at most room, or -1.
func firstFit(jobs []Job, room int) int {
	for i, job := range jobs {
		if job.Weight <= room {
			return i
		}
	}
	return -1
}
