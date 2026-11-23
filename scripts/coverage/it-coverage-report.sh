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
# Turns the coverage counters the integration suites collected into one Go coverage profile in
# which every policy is covered by its own integration suite only.
#
# A run with `make it IT_COVERAGE_DIR=<raw>` leaves, for every gateway runtime a suite started, its
# counters (covmeta.* and covcounters.* files) under <raw>/<policy>/<n>/, <policy> being the policy
# whose suite started the runtime (a slash in its name is written "__"). Every suite runs on a
# gateway that carries all the policies, so a policy's code also runs in other suites, as a
# companion policy or at start-up. Crediting that would report coverage that no test of the policy
# earns, so the profile takes each policy's counters from its own suite's runs alone
# (own-suite-profile.py). A policy with no suite, or whose suite left no counters, is reported at 0%.
#
# Output, under <out>:
#   coverage.txt   the profile of the policies' code, the report Codecov uploads
#
# Usage:
#   scripts/coverage/it-coverage-report.sh <raw-dir> <out-dir>
set -euo pipefail

raw="${1:?usage: it-coverage-report.sh <raw-dir> <out-dir>}"
out="${2:?usage: it-coverage-report.sh <raw-dir> <out-dir>}"
here="$(cd "$(dirname "$0")" && pwd)"
policies='github.com/wso2/gateway-controllers/policies/...'

[ -d "$raw" ] || { echo "it-coverage-report: no coverage output at $raw; run the suites with IT_COVERAGE_DIR set" >&2; exit 1; }
case "$raw" in
  *,*) echo "it-coverage-report: $raw must not contain a comma: go tool covdata reads -i as a comma-separated list" >&2; exit 1 ;;
esac
raw="$(cd "$raw" && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/suite" "$out"

# A counter directory is found by the files it holds, not by its depth. Its first component beneath
# <raw> names the policy whose suite started it. The lists are kept in files, one per policy.
mkdir -p "$work/inputs"
all=""
while IFS= read -r meta; do
  dir="$(dirname "$meta")"
  ls "$dir"/covcounters.* >/dev/null 2>&1 || continue
  rel="${dir#"$raw"/}"
  policy="${rel%%/*}"
  if [ "$policy" = "$rel" ]; then
    echo "it-coverage-report: $dir is not under a policy folder; the counters must be collected by run-suites -coverage-out" >&2
    exit 1
  fi
  echo "$dir" >>"$work/inputs/$policy"
  all="${all:+$all,}$dir"
done < <(find "$raw" -type f -name 'covmeta.*' | sort -u)

[ -n "$all" ] || { echo "it-coverage-report: no coverage counters under $raw. A block writes them when its gateway stops, so a run that ended early leaves none." >&2; exit 1; }
echo "merging coverage of $(echo "$all" | tr ',' '\n' | wc -l | tr -d ' ') gateway runs of $(ls "$work/inputs" | wc -l | tr -d ' ') suites"

# The profile of every run, which lists every block of every policy, then the profile of each suite.
profile() { # <comma-separated counter dirs> <output profile>
  local merged="$work/merged.$$"
  rm -rf "$merged" && mkdir -p "$merged"
  go tool covdata merge -i="$1" -o="$merged"
  go tool covdata textfmt -i="$merged" -pkg="$policies" -o="$2"
  rm -rf "$merged"
}
profile "$all" "$work/all.txt"
for list in "$work"/inputs/*; do
  profile "$(paste -sd, "$list")" "$work/suite/$(basename "$list").txt"
done

python3 "$here/own-suite-profile.py" "$work" "$out/coverage.txt"
echo "wrote $out/coverage.txt ($(($(wc -l <"$out/coverage.txt") - 1)) blocks)"
