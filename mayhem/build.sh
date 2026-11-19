#!/usr/bin/env bash
#
# mayhem/build.sh — build Odyssey's fuzz harnesses and its unit-test runner.
# Runs as `mayhem` in /mayhem. Build trees live under build/ (gitignored upstream).
#  1) build/mayhem-fuzz: upstream CMake build of the `odyssey` binary with
#     $SANITIZER_FLAGS + SanCov + $DEBUG_FLAGS; its object files (minus main.c)
#     are linked into every harness.
#  2) build/mayhem-test: upstream CMake Release build of `odyssey_test` with the
#     project's normal flags, run by mayhem/test.sh.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export CC CXX
cd "$SRC"

FUZZ_DIR="$SRC/build/mayhem-fuzz"
TEST_DIR="$SRC/build/mayhem-test"
OUT="$SRC/build/mayhem-out"
mkdir -p "$OUT"

# --- 1) sanitized + instrumented project build ------------------------------
# CC_FLAGS is upstream's hook, appended after COMMON_CFLAGS (so -gdwarf-3 wins
# over its -g). -Wno-error: upstream's -Werror trips on sanitizer builds.
cmake -S "$SRC" -B "$FUZZ_DIR" -DCMAKE_BUILD_TYPE=Release \
  -DCC_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -Wno-error"
cmake --build "$FUZZ_DIR" --target odyssey -j"$MAYHEM_JOBS"

OBJDIR="$FUZZ_DIR/sources/CMakeFiles/odyssey.dir"
mapfile -t OBJS < <(find "$OBJDIR" -name '*.o' ! -name 'main.c.o' | LC_ALL=C sort)
FLAGS_MAKE="$OBJDIR/flags.make"
C_DEFINES=$(sed -n 's/^C_DEFINES = //p' "$FLAGS_MAKE")
C_INCLUDES=$(sed -n 's/^C_INCLUDES = //p' "$FLAGS_MAKE")
LIBS="-lssl -lcrypto -lrt -ldl -lpthread -lm"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/harnesses/lsan_off.c" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

HARNESSES="fuzz_config fuzz_sql_full fuzz_sql_minimal fuzz_console fuzz_kiwi_be fuzz_kiwi_startup fuzz_kiwi_fe fuzz_scram_server fuzz_address"
for h in $HARNESSES; do
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -pthread -mcx16 $C_DEFINES $C_INCLUDES \
    -c "$SRC/mayhem/harnesses/$h.c" -o "$OUT/$h.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -pthread "$OUT/$h.o" "${OBJS[@]}" \
    "$OUT/lsan_off.o" $LIBS -o "$SRC/$h"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -pthread "$OUT/standalone_main.o" "$OUT/$h.o" "${OBJS[@]}" \
    "$OUT/lsan_off.o" $LIBS -o "$SRC/$h-standalone"
done

# --- 2) unit-test runner, normal flags ---------------------------------------
env -u CFLAGS -u LDFLAGS cmake -S "$SRC" -B "$TEST_DIR" -DCMAKE_BUILD_TYPE=Release \
  -DCC_FLAGS="$COVERAGE_FLAGS"
cmake --build "$TEST_DIR" --target odyssey_test -j"$MAYHEM_JOBS"
echo "build.sh: done"
