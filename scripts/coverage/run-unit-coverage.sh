#!/usr/bin/env bash
# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------
# Runs the unit tests of every policy module and collects Go coverage profiles.
#
# Every policy is a Go module of its own (policies/<name>, and policies/<name>/v<N> for a major
# version released beside v1), so there is no single `go test ./...` for the repository. The
# integration suites under policies/*/it are separate modules and are not run here.
#
# Output, under $COVERAGE_OUT (default: <repo>/coverage):
#   profiles/<policy>.txt   one Go coverage profile per policy module
#   coverage.txt            all profiles merged into one file, the report Codecov uploads
#
# -coverpkg=./... instruments every package of the module, so a policy that has no tests still
# reports its statements, at 0%, instead of silently dropping out of the totals.
#
# A failing module does not stop the others: every module runs, then the script exits non-zero
# listing the modules that failed.
#
# Usage:
#   scripts/coverage/run-unit-coverage.sh [policy ...]   # e.g. basic-auth backend-jwt/v2
#   COVERAGE_JOBS=8 scripts/coverage/run-unit-coverage.sh
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${COVERAGE_OUT:-$root/coverage}"
jobs="${COVERAGE_JOBS:-4}"

rm -rf "$out"
mkdir -p "$out/profiles" "$out/failed"

if [ "$#" -gt 0 ]; then
  modules=$(for p in "$@"; do echo "policies/$p"; done)
else
  modules=$(cd "$root" && find policies -name go.mod -not -path '*/it/*' -exec dirname {} \; | sort)
fi

run_module() {
  local dir="$1" name slug
  name="${dir#policies/}"
  slug="${name//\//-}"
  if [ ! -f "$root/$dir/go.mod" ]; then
    echo "::error::$dir is not a Go module" >&2
    : >"$out/failed/$slug"
    return
  fi
  if (cd "$root/$dir" && go test ./... -count=1 -coverpkg=./... -coverprofile="$out/profiles/$slug.txt" >"$out/profiles/$slug.log" 2>&1); then
    echo "ok    $name  $(grep -o 'coverage: [0-9.]*%' "$out/profiles/$slug.log" | tail -1)"
  else
    echo "FAIL  $name"
    sed 's/^/    /' "$out/profiles/$slug.log"
    : >"$out/failed/$slug"
  fi
}
export -f run_module
export root out
export GOWORK=off

echo "$modules" | xargs -P "$jobs" -I{} bash -c 'run_module "$1"' _ {}

# Every module writes the same "mode: set" header and a disjoint set of files, so the merged
# profile is the header followed by every module's blocks.
{
  echo "mode: set"
  for f in "$out"/profiles/*.txt; do
    [ -s "$f" ] && tail -n +2 "$f"
  done
} >"$out/coverage.txt"

failed=$(ls "$out/failed" 2>/dev/null)
if [ -n "$failed" ]; then
  echo
  echo "Unit tests failed in:" >&2
  echo "$failed" | sed 's/^/  - /' >&2
  exit 1
fi
