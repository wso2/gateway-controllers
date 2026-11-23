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

package itcoverage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeDocker struct {
	mu    sync.Mutex
	calls [][]string
	fail  map[string]error
}

func (f *fakeDocker) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	if err := f.fail[args[0]]; err != nil {
		return nil, err
	}
	switch args[0] {
	case "inspect":
		return []byte("vol-" + args[len(args)-1] + "\n"), nil
	case "run":
		// run -d -u 0 --label L -v vol:/coverage ...
		volume, _, _ := strings.Cut(args[7], ":")
		return []byte("helper-" + strings.TrimPrefix(volume, "vol-") + "\n"), nil
	}
	return nil, nil
}

func (f *fakeDocker) joined() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = strings.Join(c, " ")
	}
	return out
}

func TestEveryRuntimeGetsAHelperThatSharesItsVolume(t *testing.T) {
	docker := &fakeDocker{}
	c := newCollector("local/runtime:latest", t.TempDir(), docker.run, nil)

	c.watch(context.Background(), strings.NewReader("abc\n\ndef\n"))

	calls := strings.Join(docker.joined(), "\n")
	for _, id := range []string{"abc", "def"} {
		require.Contains(t, calls, "inspect -f")
		require.Contains(t, calls,
			"run -d -u 0 --label "+label+" -v vol-"+id+":/coverage --entrypoint sleep local/runtime:latest infinity")
	}
	require.NotContains(t, calls, "--volumes-from", "only the coverage volume is mounted, not the runtime's bind mounts")
}

func TestCollectCopiesTheCountersOutOfEachHelperAndRemovesThemWithTheirVolumes(t *testing.T) {
	out := t.TempDir()
	docker := &fakeDocker{}
	c := newCollector("local/runtime:latest", out, docker.run, nil)
	c.watch(context.Background(), strings.NewReader("abc\ndef\n"))
	docker.calls = nil

	copied, err := c.Collect(context.Background())

	require.NoError(t, err)
	require.Equal(t, 2, copied)
	calls := strings.Join(docker.joined(), "\n")
	for _, helper := range []string{"helper-abc", "helper-def"} {
		require.Contains(t, calls, "cp "+helper+":/coverage ")
		require.Contains(t, calls, "rm -f "+helper)
		require.Contains(t, calls, "volume rm -f vol-"+strings.TrimPrefix(helper, "helper-"))
	}
	for _, n := range []string{"1", "2"} {
		info, err := os.Stat(filepath.Join(out, n))
		require.NoError(t, err)
		require.True(t, info.IsDir())
	}
}

func TestAHelperThatCannotBeStartedIsReportedAndTheOthersStillCollect(t *testing.T) {
	docker := &fakeDocker{fail: map[string]error{"run": errors.New("no such container")}}
	c := newCollector("local/runtime:latest", t.TempDir(), docker.run, nil)
	c.watch(context.Background(), strings.NewReader("abc\n"))

	copied, err := c.Collect(context.Background())

	require.Zero(t, copied)
	require.ErrorContains(t, err, "attaching to the runtime abc")
}

func TestStartNeedsAnImageAndAFolder(t *testing.T) {
	_, err := Start(context.Background(), "", "out", nil)
	require.Error(t, err)
	_, err = Start(context.Background(), "image", " ", nil)
	require.Error(t, err)
}

func TestEventsArePrintedAsContainerIds(t *testing.T) {
	args := strings.Join(eventsArgs("local/runtime:latest"), " ")
	require.Contains(t, args, "--filter image=local/runtime:latest")
	require.Contains(t, args, "--filter event=start")
	// Not {{.ID}}: the event message has no such field, and docker rejects the format.
	require.Contains(t, args, `--format {{.Actor.ID}} {{index .Actor.Attributes "`+labelKey+`"}}`)
}

func TestAHelperStartingIsNotFollowedAsARuntime(t *testing.T) {
	docker := &fakeDocker{}
	c := newCollector("local/runtime:latest", t.TempDir(), docker.run, nil)

	// The helper is made from the runtime image, so its own start is in the stream too.
	c.watch(context.Background(), strings.NewReader("abc \nhelper-abc "+labelValue+"\n"))

	calls := strings.Join(docker.joined(), "\n")
	require.Contains(t, calls, "-v vol-abc:/coverage")
	require.NotContains(t, calls, "helper-abc")
}

func TestARuntimeThatStartsAgainIsFollowedOnce(t *testing.T) {
	docker := &fakeDocker{}
	c := newCollector("local/runtime:latest", t.TempDir(), docker.run, nil)

	c.watch(context.Background(), strings.NewReader("abc \nabc \n"))

	runs := 0
	for _, call := range docker.joined() {
		if strings.HasPrefix(call, "run ") {
			runs++
		}
	}
	require.Equal(t, 1, runs)
}

func TestARuntimeWithoutACoverageVolumeIsReported(t *testing.T) {
	docker := &fakeDocker{}
	c := newCollector("local/runtime:latest", t.TempDir(), func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "inspect" {
			return []byte("\n"), nil
		}
		return docker.run(ctx, args...)
	}, nil)
	c.watch(context.Background(), strings.NewReader("abc \n"))

	_, err := c.Collect(context.Background())

	require.ErrorContains(t, err, "has no /coverage volume")
}
