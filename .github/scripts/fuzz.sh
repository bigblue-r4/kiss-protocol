#!/usr/bin/env bash
# Run one Go fuzz target for CI.
#
#   .github/scripts/fuzz.sh PKG TARGET FUZZTIME     e.g. ./internal/soul/ FuzzHash 5m
#
# Go's fuzzer can fail right at the -fuzztime boundary with "context deadline
# exceeded" and no failing input (seen on the soul FuzzHash nightly). Only that
# case is retried, once: the output must contain "context deadline exceeded" AND
# no new file may have appeared under PKG/testdata/fuzz (a new file there is a
# real failing input). Any other failure, or a second failure, fails the job with
# go's own exit status.
set -uo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 PKG TARGET FUZZTIME" >&2
  exit 2
fi
pkg=$1 target=$2 fuzztime=$3
GO=${GO:-go}
corpus="${pkg%/}/testdata/fuzz"

snapshot() { find "$corpus" -type f 2>/dev/null | LC_ALL=C sort; }

run() {
  "$GO" test -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" "$pkg" 2>&1 | tee "$1"
  return "${PIPESTATUS[0]}"
}

logdir=$(mktemp -d)
before=$(snapshot)
run "$logdir/1.log"
rc=$?
[ "$rc" -eq 0 ] && exit 0

if grep -qF "context deadline exceeded" "$logdir/1.log" && [ "$(snapshot)" = "$before" ]; then
  echo "::warning::${target}: 'context deadline exceeded' at the fuzz time limit and no new failing input; retrying once"
  run "$logdir/2.log"
  exit $?
fi
exit "$rc"
