#!/bin/bash

set -eE

quiet () {
  2>&1>/dev/null $@
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
      shift;shift
      ;;
    --mode)
      MODES=$2
      shift;shift
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

run_crypto_test_suite () {
  local mode=$1
  local tags=$2
  local suite="crypto-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src/crypto
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    $GO test $tags -count=1 $($GO list ./... | grep -v tls) $VERBOSE

  local suite="crypto-fips-parity-nocgo"
  notify_running ${mode} ${suite}
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    CGO_ENABLED=0 $GO test $tags -count=1 $($GO list ./... | grep -v tls) $VERBOSE
  quiet popd
}

run_http_test_suite () {
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

run_tls_test_suite () {
  local mode=$1
  local tags=$2
  local suite="tls-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src
  GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 \
    $GO test $tags -count=1 crypto/tls -run "^TestBoring" $VERBOSE
  quiet popd
}


run_full_test_suite () {
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
run_native_fips_test_suite () {
  local mode=$1
  local suite="crypto-native-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src/crypto
  # Use GODEBUG=fips140=auto with GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 to test native FIPS module
  # The override simulates a FIPS-enabled host for testing purposes
  GODEBUG=fips140=auto GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
    $GO test -count=1 $($GO list ./... | grep -v tls) $VERBOSE

  local suite="tls-native-fips"
  notify_running ${mode} ${suite}
  quiet pushd ${GOROOT}/src
  GODEBUG=fips140=auto GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
    $GO test -count=1 crypto/tls -run "^TestBoring" $VERBOSE
  quiet popd

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

echo ALL TESTS PASSED
