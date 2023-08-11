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
SUITES="crypto,tls"
# Verbosity flags to pass to Go
VERBOSE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --suites)
      SUITES=$2
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
    fi
  done
}

# Run in default mode
run_full_test_suite default ""

# Run in strict fips mode
export GOEXPERIMENT=strictfipsruntime
run_full_test_suite strictfips "-tags=strictfipsruntime"

echo ALL TESTS PASSED

