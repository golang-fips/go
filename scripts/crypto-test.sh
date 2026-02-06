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
SUITES="crypto,tls,http"
# Modes to run (default, strictfips, native-fips-auto, or all)
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

run_crypto_test_suite() {
  local mode=$1
  local tags=$2
  local suite="crypto-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src/crypto
  # Exclude packages/tests that spawn subprocesses with GODEBUG=fips140=on, which
  # conflicts with OpenSSL backend due to mutual exclusivity check.
  # - fips140test: tests for native FIPS module
  # - crypto/fips140: TestWithoutEnforcement spawns GODEBUG=fips140=only subprocess
  # - TestGCMNoncesFIPS*: these tests spawn GODEBUG=fips140=on subprocesses
  # These are tested in native-fips-auto mode instead.
  local SKIP_PATTERN="TestGCMNoncesFIPS"
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    $GO test $tags -count=1 -skip="${SKIP_PATTERN}" \
    $($GO list ./... | grep -v tls | grep -v fips140test | grep -v 'crypto/fips140$') $VERBOSE

  local suite="crypto-fips-parity-nocgo"
  notify_running ${mode} ${suite}
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    CGO_ENABLED=0 $GO test $tags -count=1 -skip="${SKIP_PATTERN}" \
    $($GO list ./... | grep -v tls | grep -v fips140test | grep -v 'crypto/fips140$') $VERBOSE
  quiet popd
}

run_http_test_suite() {
  local mode=$1
  local tags=$2
  local suite="net-http-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src/net/http
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    $GO test $tags -count=1 $VERBOSE

  local suite="net-http-fips-parity-nocgo"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src/net/http
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    CGO_ENABLED=0 $GO test $tags -count=1 $VERBOSE

  quiet popd
}

run_tls_test_suite() {
  local mode=$1
  local tags=$2
  local suite="tls-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    $GO test $tags -count=1 crypto/tls -run "^TestBoring" $VERBOSE
  quiet popd
}

run_full_test_suite() {
  local mode=$1
  local tags=$2
  for suite in ${SUITES//,/ }; do
    if [[ "$suite" == "crypto" ]]; then
      run_crypto_test_suite ${mode} ${tags}
    elif [[ "$suite" == "tls" ]]; then
      run_tls_test_suite ${mode} ${tags}
    elif [[ "$suite" == "http" ]]; then
      run_http_test_suite ${mode} ${tags}
    fi
  done
}

# Run in native FIPS auto mode (GODEBUG=fips140=auto)
# This mode uses Go's native FIPS 140-3 module instead of OpenSSL
# Requires -tags=no_openssl to disable the OpenSSL backend
# Uses GOFLAGS to propagate build tags to subprocess Go commands
run_native_fips_test_suite() {
  local mode=$1
  local suite="crypto-native-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src/crypto
  # Use GODEBUG=fips140=auto with GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 to test native FIPS module
  # The override simulates a FIPS-enabled host for testing purposes
  # Must use GOFLAGS=-tags=no_openssl to disable OpenSSL backend in all subprocess calls
  GODEBUG=fips140=auto GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GOFLAGS="-tags=no_openssl" \
    $GO test -tags=no_openssl -count=1 $($GO list -tags=no_openssl ./... | grep -v tls) $VERBOSE

  local suite="tls-native-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src
  GODEBUG=fips140=auto GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GOFLAGS="-tags=no_openssl" \
    $GO test -tags=no_openssl -count=1 crypto/tls -run "^TestBoring" $VERBOSE
  quiet popd

  quiet popd
}

# Test mutual exclusivity enforcement - verify correct behavior in various configurations
run_mutual_exclusivity_tests() {
  local mode="mutual-exclusivity"

  quiet pushd ${GOROOT}/src

  # Test 1: GODEBUG=fips140=on without GOLANG_FIPS should work (native FIPS, OpenSSL not enabled)
  notify_running ${mode} "native-fips-only"
  local output=$(GODEBUG=fips140=on $GO test crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "^ok"; then
    echo "PASS: Native FIPS works when OpenSSL backend not enabled"
  else
    echo "FAIL: Expected native FIPS to work without OpenSSL backend"
    echo "Output: $output"
    exit 1
  fi

  # Test 2: GOLANG_FIPS=1 with GODEBUG=fips140=on should panic (both backends conflict)
  notify_running ${mode} "openssl-fips-with-godebug-on"
  output=$(GOLANG_FIPS=1 GODEBUG=fips140=on $GO test crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "GOLANG_FIPS and GODEBUG=fips140 are mutually exclusive"; then
    echo "PASS: Correctly panicked - GOLANG_FIPS=1 + fips140=on conflict"
  else
    echo "FAIL: Expected panic about FIPS mutual exclusivity"
    echo "Output: $output"
    exit 1
  fi

  # Test 3: GOLANG_FIPS=1 with GODEBUG=fips140=only should also panic
  notify_running ${mode} "openssl-fips-with-godebug-only"
  output=$(GOLANG_FIPS=1 GODEBUG=fips140=only $GO test crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "GOLANG_FIPS and GODEBUG=fips140 are mutually exclusive"; then
    echo "PASS: Correctly panicked - GOLANG_FIPS=1 + fips140=only conflict"
  else
    echo "FAIL: Expected panic about FIPS mutual exclusivity"
    echo "Output: $output"
    exit 1
  fi

  # Test 4: GOLANG_FIPS=0 with GODEBUG=fips140=on should work (explicit OpenSSL opt-out)
  notify_running ${mode} "openssl-optout-with-native-fips"
  output=$(GOLANG_FIPS=0 GODEBUG=fips140=on $GO test crypto/sha256 -count=1 2>&1 || true)
  if echo "$output" | grep -q "^ok"; then
    echo "PASS: GOLANG_FIPS=0 allows native FIPS to work"
  else
    echo "FAIL: Expected GOLANG_FIPS=0 + fips140=on to work"
    echo "Output: $output"
    exit 1
  fi

  quiet popd
}

# Run tests based on selected modes
if [[ "$MODES" == "all" || "$MODES" == *"default"* ]]; then
  # Run in default mode (OpenSSL backend with GOLANG_FIPS=1)
  run_full_test_suite default ""

  # Run TLS Handshake tests to test ExpandHKDF (OpenSSL backend)
  notify_running "TLS Handshake" "(default)"
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    $GO test -count=1 crypto/tls -run "TestTrafficKey" $VERBOSE
fi

if [[ "$MODES" == "all" || "$MODES" == *"strictfips"* ]]; then
  # Run in strict fips mode (OpenSSL backend with strict mode)
  export GOEXPERIMENT=strictfipsruntime
  run_full_test_suite strictfips "-tags=strictfipsruntime"
  unset GOEXPERIMENT
fi

if [[ "$MODES" == "all" || "$MODES" == *"native-fips-auto"* ]]; then
  run_native_fips_test_suite "native-fips-auto"
fi

if [[ "$MODES" == "all" || "$MODES" == *"mutual-exclusivity"* ]]; then
  run_mutual_exclusivity_tests
fi

echo ALL TESTS PASSED
