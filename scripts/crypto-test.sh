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
# Modes to run (native-fips-auto, native-fips-latest, native-fips-strict,
# non-fips, or all)
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
      # Relative wildcards conflict with the FIPS snapshot overlay.
      local crypto_packages
      crypto_packages=$($GO list crypto/...)
      crypto_packages=$(printf '%s\n' "$crypto_packages" | grep -v '^crypto/tls$')
      if [[ -z "$crypto_packages" ]]; then
        echo "FAIL: No crypto packages found"
        exit 1
      fi
      GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
        $GO test -count=1 $crypto_packages $VERBOSE
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

# Run the crypto test suite against the latest in-tree FIPS module with FIPS
# mode active.
# This gives the fork's FIPS test script explicit runtime coverage and verifies
# that GOFIPS140=latest did not silently degrade to off or select the certified
# v1.0 snapshot.
run_native_fips_latest_test_suite() {
  local mode=$1
  for suite in ${SUITES//,/ }; do
    if [[ "$suite" == "crypto" ]]; then
      notify_running ${mode} "crypto-native-fips-latest"
      quiet pushd ${GOROOT}/src

      local latest_check_dir
      latest_check_dir=$(mktemp -d)
      local latest_check="${latest_check_dir}/latest.go"
      cat >"$latest_check" <<'EOF'
package main

import (
	"crypto/fips140"
	"crypto/mldsa"
	"fmt"
	"strings"
)

func main() {
	if !fips140.Enabled() {
		panic("GOFIPS140=latest did not enable FIPS 140 mode")
	}
	if version := fips140.Version(); strings.HasPrefix(version, "v1.0.") {
		panic(fmt.Sprintf("GOFIPS140=latest selected certified snapshot %s", version))
	}
	if _, err := mldsa.GenerateKey(mldsa.MLDSA44()); err != nil {
		panic(fmt.Sprintf("ML-DSA is unavailable with GOFIPS140=latest: %v", err))
	}
	fmt.Printf("PASS: ML-DSA works with FIPS 140 module %s\n", fips140.Version())
}
EOF

      if ! GOFIPS140=latest GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
        $GO run "$latest_check"; then
        rm -rf "$latest_check_dir"
        exit 1
      fi
      rm -rf "$latest_check_dir"

      local crypto_packages
      crypto_packages=$(GOFIPS140=latest $GO list crypto/...)
      crypto_packages=$(printf '%s\n' "$crypto_packages" | grep -v '^crypto/tls$')
      if [[ -z "$crypto_packages" ]]; then
        echo "FAIL: No crypto packages found for GOFIPS140=latest"
        exit 1
      fi
      GOFIPS140=latest GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 \
        $GO test -count=1 $crypto_packages $VERBOSE
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

run_purego_test() {
  quiet pushd ${GOROOT}/src
  notify_running "native-fips" "purego-exclusivity"
  trap "rm -f sha256.test" EXIT
  if ! ../bin/go test -c -tags purego crypto/sha256 2>&1 |  grep -q "go: use of purego build tag requires GOFIPS140=off"; then
    echo "FAIL: purego tag should be rejected by default"
    exit 1
  fi
  output=$(GOFIPS140=off ../bin/go test -tags purego crypto/sha256 -count 1)
  if ! echo "$output" | grep -q "^ok"; then
    echo $output
    echo "FAIL: purego tag should work with GOFIPS140=off"
    exit 1
  fi
  echo "PASS: GOFIPS140 is exclusive with purego tag"
  quiet popd
}

run_cmd_go_version_m() {
  notify_running "go version -m" "cmd/go"
  if ! $GO version -m $GOROOT/bin/go | grep "fips140=auto"; then
      echo "FAIL: Expected DefaultGODEBUG=fips140=auto"
      exit 1
  fi
  if ! $GO version -m $GOROOT/bin/go | grep "GOFIPS140=v1.0.0"; then
    echo "FAIL: Expected fips140v1.0 module"
    exit 1
  fi
  if [ -d "$GOROOT/pkg/obj" ]; then
    echo "FAIL: Expected modcache to be erased"
    exit 1
  fi
}

# Run tests based on selected modes
if [[ "$MODES" == "all" || "$MODES" == *"native-fips-auto"* ]]; then
  run_native_fips_test_suite "native-fips-auto"
fi

if [[ "$MODES" == "all" || "$MODES" == *"native-fips-latest"* ]]; then
  run_native_fips_latest_test_suite "native-fips-latest"
fi

if [[ "$MODES" == "all" || "$MODES" == *"native-fips-strict"* ]]; then
  run_native_fips_strict_test_suite "native-fips-strict"
fi

if [[ "$MODES" == "all" || "$MODES" == *"non-fips"* ]]; then
  run_non_fips_test_suite "non-fips"
fi

if [[ "$MODES" == "all" || "$MODES" == *"purego"* ]]; then
  run_purego_test
fi

if [[ "$MODES" == "all" || "$MODES" == *"cmd/go"* ]]; then
  run_cmd_go_version_m
fi

echo ALL TESTS PASSED
