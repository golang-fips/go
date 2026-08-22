#!/bin/bash

set -eE

quiet() {
  2>&1 >/dev/null $@
}

# Find the GOROOT.
# If using a release branch, expect the GOROOT
# in the go submodule directory.
GOROOT=$(readlink -f $(dirname $0)/..)
quiet pushd $GOROOT
if 2>/dev/null cat .gitmodules | grep -q "url = https://github.com/golang/go.git"; then
  GOROOT=${GOROOT}/go
fi
quiet popd

export GOCACHE=/tmp/go-cache
export GO=${GOROOT}/bin/go

# Test suites to run
SUITES="crypto,tls"
# Modes to run (native-fips-auto, native-fips-strict, non-fips, or all)
MODES="all"
# Verbosity flags to pass to Go
VERBOSE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
  --suites)
    SUITES=$2
    shift
    shift
    ;;
  --mode)
    MODES=$2
    shift
    shift
    ;;
  -v)
    VERBOSE="$VERBOSE -v"
    set -x
    shift
    ;;
  *)
    >&2 echo "unsupported option $1"
    exit 1
    ;;
  esac
done

notify_running() {
  local mode=$1
  local suite=$2
  echo -e "\n##### ${suite} (${mode})"
}

# Run in native FIPS auto mode.
# Does NOT set GODEBUG=fips140=auto explicitly — the binary's embedded default
# is what activates FIPS, which is the behaviour we want to verify.
# Uses GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 to simulate a FIPS-enabled host.
run_native_fips_test_suite() {
  local mode=$1
  for suite in ${SUITES//,/ }; do
    if [[ "$suite" == "crypto" ]]; then
      notify_running ${mode} "crypto-native-fips"
      quiet pushd ${GOROOT}/src/crypto

 echo "=== Go tool debug ==="
  echo "GOFIPS140 env: ${GOFIPS140:-<unset>}"
  $GO env GOFIPS140
  $GO env GOROOT
  strings $($GO env GOROOT)/bin/go | grep "fips140=" || echo "no fips140= string found in go binary"

      GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
        $GO test -count=1 $($GO list ./... | grep -v tls) $VERBOSE
      quiet popd
    elif [[ "$suite" == "tls" ]]; then
      notify_running ${mode} "tls-native-fips"
      quiet pushd ${GOROOT}/src
      GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
        $GO test -count=1 crypto/tls -run "^TestBoring" $VERBOSE
      quiet popd
    fi
  done

}

# Run strict FIPS runtime checks against the native module.
# Verifies GOEXPERIMENT=strictfipsruntime and -tags strictfipsruntime.
run_native_fips_strict_test_suite() {
  local mode=$1
  quiet pushd ${GOROOT}/src

  notify_running ${mode} "native-fips-strict-auto"
  local output
  output=$(GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GOEXPERIMENT=strictfipsruntime GODEBUG=fips140=auto $GO test crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "^ok"; then
    echo "PASS: Native FIPS works when in strict fips mode"
  else
    echo "FAIL: Expected native FIPS to work without OpenSSL backend"
    echo "Output: $output"
    exit 1
  fi

  notify_running ${mode} "native-fips-strict-off"
  output=$(GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GOEXPERIMENT=strictfipsruntime GODEBUG=fips140=off $GO test crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "Host FIPS mode is enabled, but the required GODEBUG=fips140 module is disabled"; then
    echo "PASS: Native FIPS correctly aborts in strict fips mode"
  else
    echo "FAIL: Expected strict fips mode to abort when GODEBUG=fips140 is disabled"
    echo "Output: $output"
    exit 1
  fi

  notify_running ${mode} "native-fips-strict-tags"
  output=$(GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GODEBUG=fips140=off $GO test -tags strictfipsruntime crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "Host FIPS mode is enabled, but the required GODEBUG=fips140 module is disabled"; then
    echo "PASS: -tags strictfipsruntime correctly aborts when GODEBUG=fips140 is disabled"
  else
    echo "FAIL: Expected -tags strictfipsruntime to abort when GODEBUG=fips140 is disabled"
    echo "Output: $output"
    exit 1
  fi

  notify_running ${mode} "strict-fips-hub-coverage"
  if $GO test go/build -run 'TestDependencies|TestStrictFIPSHubCoverage' -count=1 $VERBOSE; then
    echo "PASS: Strict FIPS init hubs cover FIPS module importers"
  else
    echo "FAIL: Strict FIPS init hub dependency checks failed"
    exit 1
  fi

  quiet popd
}

# Run tests with no FIPS mode active.
# Exercises code paths that are skipped in FIPS mode and verifies
# standard behavior is not regressed.
run_non_fips_test_suite() {
  local mode=$1
  notify_running ${mode} "crypto-tls-full"
  quiet pushd ${GOROOT}/src
  GOFIPS140=off $GO test -count=1 \
    $(GOFIPS140=off $GO list crypto/... | grep -v fips140test) \
    $VERBOSE
  quiet popd
}

# Run tests based on selected modes
if [[ "$MODES" == "all" || "$MODES" == *"native-fips-auto"* ]]; then
  run_native_fips_test_suite "native-fips-auto"
fi

if [[ "$MODES" == "all" || "$MODES" == *"native-fips-strict"* ]]; then
  run_native_fips_strict_test_suite "native-fips-strict"
fi

if [[ "$MODES" == "all" || "$MODES" == *"non-fips"* ]]; then
  run_non_fips_test_suite "non-fips"
fi

echo ALL TESTS PASSED
