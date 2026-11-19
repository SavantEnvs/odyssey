#!/usr/bin/env bash
#
# mayhem/test.sh — run Odyssey's own unit suite (sources/tests, built by build.sh as
# build/mayhem-test/sources/odyssey_test with normal flags). Each kiwi/odyssey test
# asserts known values (parsed SQL/console ASTs, SCRAM proofs, address lists, hba
# masks, ...) and aborts on a mismatch; a test passes only if the runner prints
# "<name>: ok". Machinarium tests (sockets, TLS, timing) are left out: they need
# networking and are timing-sensitive, so they are not a reliable oracle here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/build/mayhem-test/sources/odyssey_test"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — run mayhem/build.sh first" >&2
  emit_ctrf "odyssey_test" 0 1 0
  exit 1
fi

TESTS="kiwi_test_enquote kiwi_test_vars_cas kiwi_test_pgoptions kiwi_test_be_read_startup_options
kiwi_test_fe_read_auth kiwi_test_be_read_query kiwi_test_backend_key_data kiwi_test_cancel_request
kiwi_test_cancel_write kiwi_test_msg_size_limits odyssey_test_tdigest odyssey_test_attribute
odyssey_test_util odyssey_test_hba odyssey_test_address_parse odyssey_test_address_cmp
odyssey_test_pstmt odyssey_test_clients_map odyssey_test_router_free_before_startup
odyssey_test_duration_parse odyssey_test_misc odyssey_test_linear_alloc odyssey_test_scram
odyssey_test_sql_minimal_parser odyssey_test_sql_full_parser odyssey_test_console_parser
odyssey_test_config_field odyssey_test_autoconf"

passed=0; failed=0
cd "$(dirname "$RUNNER")"
for t in $TESTS; do
  out=$(timeout 300 "$RUNNER" "$t" 2>&1)
  rc=$?
  if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q "^$t: ok"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $t (rc=$rc)"; printf '%s\n' "$out" | tail -5
  fi
done
cd "$SRC"
emit_ctrf "odyssey_test" "$passed" "$failed" 0
