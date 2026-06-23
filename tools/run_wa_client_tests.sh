#!/usr/bin/env bash
# Run the partitioned wa-client test suite, one memory-bounded chunk at a time.
#
# WHY: the in-crate `#[cfg(test)] mod tests` is ~95K lines. Built as a single
# rustc unit it OOM-SIGKILLs on this VM (3.8GB RAM, no swap; peak ~3.9GB).
# The module is split into 8 feature-gated chunks (`wat1`..`wat8`), each a
# `mod chunk_K` compiled only when its feature is on, keeping each test build
# well under the RAM budget. Shared helpers (mock_connection, IncomingDecryptor,
# RelayEncryptor, ...) stay ungated in the parent `mod tests` so every chunk can
# use them via `use super::*`.
#
# Always build with debuginfo=0 and -j1 (single codegen unit job) to cap memory.
# Each chunk compile takes roughly 3-7 minutes; the whole run is ~30-50 minutes.
#
# Usage:
#   tools/run_wa_client_tests.sh            # run all chunks
#   tools/run_wa_client_tests.sh 3 5        # run only chunks 3 and 5
set -u

CHUNKS=("$@")
if [ ${#CHUNKS[@]} -eq 0 ]; then
  CHUNKS=(1 2 3 4 5 6 7 8)
fi

BASE_FEATURES="memory-store,http-media,link-preview,image"
LOGDIR="${TMPDIR:-/tmp}/wa_client_test_logs"
mkdir -p "$LOGDIR"

export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=1

fail=0
declare -a results
for k in "${CHUNKS[@]}"; do
  log="$LOGDIR/wat${k}.log"
  echo ">>> wat${k}: building + running (log: $log)"
  cargo test -p wa-client --features "${BASE_FEATURES},wat${k}" -j1 -- --test-threads=2 \
    > "$log" 2>&1
  code=$?
  # Judge by the rust harness lines AND the exit code, never by `| tail`.
  if [ $code -ne 0 ] || grep -qE "test result: FAILED" "$log"; then
    echo "!!! wat${k}: FAILED (exit=$code)"
    grep -E "test result:" "$log" | sed 's/^/    /'
    results+=("wat${k}: FAILED (exit=$code)")
    fail=1
  else
    echo "    wat${k}: OK"
    grep -E "test result: ok" "$log" | sed 's/^/    /'
    results+=("wat${k}: ok")
  fi
done

echo
echo "==== SUMMARY ===="
for r in "${results[@]}"; do echo "  $r"; done
exit $fail
