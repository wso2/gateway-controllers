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
# Turns the coverage counters the integration suites collected into one Go coverage profile.
#
# A run with `make it IT_COVERAGE_DIR=<raw>` leaves, for every block that ran, the counters of the
# instrumented policy engine under <raw>/.run-*/raw/<block>/<service>/ (covmeta.* and covcounters.*
# files). Every block boots a gateway built from the same binary, so the counters of all blocks of
# all suites are merged: a policy line counts as covered when any scenario of any suite ran it.
#
# Output, under <out>:
#   coverage.txt   the merged profile of the policies' code, the report Codecov uploads
#
# Usage:
#   scripts/coverage/it-coverage-report.sh <raw-dir> <out-dir>
set -euo pipefail

raw="${1:?usage: it-coverage-report.sh <raw-dir> <out-dir>}"
out="${2:?usage: it-coverage-report.sh <raw-dir> <out-dir>}"
policies='github.com/wso2/gateway-controllers/policies/...'

[ -d "$raw" ] || { echo "it-coverage-report: no coverage output at $raw; run the suites with IT_COVERAGE_DIR set" >&2; exit 1; }
case "$raw" in
  *,*) echo "it-coverage-report: $raw must not contain a comma: go tool covdata reads -i as a comma-separated list" >&2; exit 1 ;;
esac

# A counter directory is found by the files it holds, not by its depth.
inputs=""
while IFS= read -r meta; do
  dir="$(dirname "$meta")"
  if ls "$dir"/covcounters.* >/dev/null 2>&1; then
    inputs="${inputs:+$inputs,}$dir"
  fi
done < <(find "$raw" -type f -name 'covmeta.*' | sort -u)

[ -n "$inputs" ] || { echo "it-coverage-report: no coverage counters under $raw. A block writes them when its gateway stops, so a run that ended early leaves none." >&2; exit 1; }
echo "merging coverage of $(echo "$inputs" | tr ',' '\n' | wc -l | tr -d ' ') gateway runs"

mkdir -p "$out"
merged="$(mktemp -d)"
trap 'rm -rf "$merged"' EXIT
go tool covdata merge -i="$inputs" -o="$merged"
go tool covdata textfmt -i="$merged" -pkg="$policies" -o="$out/coverage.txt"

echo "wrote $out/coverage.txt ($(($(wc -l <"$out/coverage.txt") - 1)) blocks)"
