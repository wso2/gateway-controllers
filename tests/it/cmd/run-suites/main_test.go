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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisplayNameKeepsABlockNamedAfterItsPolicy(t *testing.T) {
	require.Equal(t, "backend-jwt-policy-key", displayName("backend-jwt", "backend-jwt-policy-key"))
	require.Equal(t, "backend-jwt-v2-claim-types", displayName("backend-jwt/v2", "backend-jwt-v2-claim-types"))
	require.Equal(t, "cors/sqlite", displayName("cors", "sqlite"))
}

func TestJobNameIsUniqueAcrossSuites(t *testing.T) {
	items := map[string]item{}
	first := jobName(items, "backend-jwt", "backend-jwt-claims")
	items[first] = item{policy: "backend-jwt", block: "backend-jwt-claims"}

	// The same display name from a second suite must not replace the first suite's job.
	second := jobName(items, "backend-jwt", "backend-jwt-claims")
	require.NotEqual(t, first, second)
	require.Equal(t, "backend-jwt/backend-jwt-claims", second)
}

type fakeCollector struct {
	copied int
	err    error
}

func (f fakeCollector) Collect(context.Context) (int, error) { return f.copied, f.err }

func TestAnIncompleteCoverageCollectionIsReportedAsAFailure(t *testing.T) {
	var said, stderr bytes.Buffer
	say := func(format string, args ...any) { fmt.Fprintf(&said, format, args...) }

	incomplete := finishCoverage(fakeCollector{copied: 3, err: errors.New("copying the counters of helper abc: no space")}, "out", say, &stderr)

	require.True(t, incomplete, "the run must not pass with a partial report")
	require.Contains(t, said.String(), "collected the counters of 3 gateway runtimes into out", "the partial counters are still reported")
	require.Contains(t, stderr.String(), "no space")
}

func TestACompleteCoverageCollectionIsNotAFailure(t *testing.T) {
	var said, stderr bytes.Buffer
	say := func(format string, args ...any) { fmt.Fprintf(&said, format, args...) }

	require.False(t, finishCoverage(fakeCollector{copied: 5}, "out", say, &stderr))
	require.Empty(t, stderr.String())
}

func TestBlockOwnersMapsEachBlockToItsPolicy(t *testing.T) {
	owners, err := blockOwners(map[string]item{
		"basic-auth":            {policy: "basic-auth", block: "basic-auth"},
		"basic-auth-restart":    {policy: "basic-auth", block: "basic-auth-restart"},
		"backend-jwt/v2/claims": {policy: "backend-jwt/v2", block: "claims"},
	})

	require.NoError(t, err)
	require.Equal(t, map[string]string{"basic-auth": "basic-auth", "basic-auth-restart": "basic-auth", "claims": "backend-jwt/v2"}, owners)
}

func TestBlockOwnersRefusesABlockNameTwoSuitesShare(t *testing.T) {
	_, err := blockOwners(map[string]item{
		"a/shared": {policy: "a", block: "shared"},
		"b/shared": {policy: "b", block: "shared"},
	})

	require.ErrorContains(t, err, `both have a block named "shared"`)
}

func TestBootWatcherFlagsOnlyABootFailureOnAContainerRuntimeError(t *testing.T) {
	runtimeBoot := "runtime.go:143: block \"x/sqlite\" failed to boot after 31s: compose up: " +
		"failed to create shim task: DeadlineExceeded\n"
	cases := map[string]struct {
		output []string
		want   bool
	}{
		"runtime error while booting":      {[]string{runtimeBoot}, true},
		"signature split across writes":    {[]string{"failed to boot after 3s: failed to create sh", "im task\n"}, true},
		"host port taken by another block": {[]string{"failed to boot after 29s: start container: Bind for 0.0.0.0:34307 failed: port is already allocated\n"}, true},
		"boot failure from the gateway":    {[]string{"failed to boot after 3s: gateway unhealthy\n"}, false},
		"runtime error during a scenario":  {[]string{"suite.go:640: restart: failed to create shim task\n"}, false},
		"clean run":                        {[]string{"=== passed in 90s ===\n"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var sink bytes.Buffer
			w := &bootWatcher{Writer: &sink}
			for _, chunk := range tc.output {
				n, err := w.Write([]byte(chunk))
				require.NoError(t, err)
				require.Equal(t, len(chunk), n)
			}
			require.Equal(t, tc.want, w.sawBootFailure())
			require.False(t, w.sawBootFailure(), "the verdict is forgotten once read")
			require.Equal(t, len(sink.String()), len(joined(tc.output)), "the output passes through unchanged")
		})
	}
}

func joined(chunks []string) string {
	var all string
	for _, c := range chunks {
		all += c
	}
	return all
}
