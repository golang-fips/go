#!/bin/bash

set -euo pipefail

SUITES=crypto,tls
MODES=all
VERBOSE=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --suites|--mode)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "Missing value for $1" >&2
        exit 1
      fi
      if [[ "$1" == --suites ]]; then SUITES=$2; else MODES=$2; fi
      shift 2
      ;;
    -v) VERBOSE=-v; shift ;;
    *) echo "Unsupported option: $1" >&2; exit 1 ;;
  esac
done

for selection in "$SUITES" "$MODES"; do
  if [[ -z "$selection" || "$selection" == ,* || "$selection" == *, ||
        "$selection" == *,,* || "$selection" =~ [[:space:]] ]]; then
    echo "Expected a nonempty comma-separated selection: $selection" >&2
    exit 1
  fi
done
for suite in ${SUITES//,/ }; do
  case "$suite" in
    crypto|tls) ;;
    *) echo "Unsupported suite: $suite" >&2; exit 1 ;;
  esac
done
if [[ "$MODES" == all ]]; then
  MODES=native-fips-auto,native-fips-inprocess,native-fips-latest,non-fips,purego,native-fips-strict,cmd/go
fi
for mode in ${MODES//,/ }; do
  case "$mode" in
    native-fips-auto|native-fips-inprocess|native-fips-latest|native-fips-strict|non-fips|purego|cmd/go) ;;
    *) echo "Unsupported mode: $mode" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
GOROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
if [[ ! -d "$GOROOT/src" ]]; then GOROOT=$GOROOT/go; fi
export GOROOT
GO=$GOROOT/bin/go
export GOCACHE=/tmp/go-cache

# The matrix owns these settings. In particular, inherited -run, -skip, -short,
# or build tags in GOFLAGS must not silently remove tests from an "all" run.
export GOFLAGS= GOEXPERIMENT= GODEBUG= GOFIPS140=certified
export GOLANG_NATIVE_HOSTFIPS_OVERRIDE=0 GOTOOLCHAIN=local
unset ACVP_WRAPPER GOENTROPYSOURCEACVP GONOPAAPAI

cd "$GOROOT/src"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED_CONFIGS=
HOST_FIPS=0
if [[ -e /proc/sys/crypto/fips_enabled ]]; then
  HOST_FIPS=$(cat /proc/sys/crypto/fips_enabled)
fi

# A successful go test invocation alone does not prove which module or runtime
# mode it exercised. Check both, including ML-DSA snapshot availability.
cat > "$WORK/state.go" <<'EOF'
package main

import (
	"crypto/fips140"
	"crypto/mldsa"
	"fmt"
	"os"
	"strings"
)

func main() {
	version, enabled, enforced := os.Args[1], os.Args[2] == "1", os.Args[3] == "1"
	if fips140.Version() != version || fips140.Enabled() != enabled || fips140.Enforced() != enforced {
		panic(fmt.Sprintf("unexpected FIPS state: version=%s enabled=%v enforced=%v; want %s %v %v",
			fips140.Version(), fips140.Enabled(), fips140.Enforced(), version, enabled, enforced))
	}
	_, err := mldsa.GenerateKey(mldsa.MLDSA44())
	rejected := strings.HasPrefix(version, "v1.0.")
	if (err != nil) != rejected {
		panic(fmt.Sprintf("unexpected ML-DSA availability: version=%s enabled=%v error=%v", version, enabled, err))
	}
	fmt.Printf("PASS: module=%s enabled=%v enforced=%v\n", version, enabled, enforced)
}
EOF

# Run every selected configuration even if an earlier one fails.
record() {
  local name=$1
  shift
  printf '\n##### %s\n' "$name"
  if "$@"; then
    echo "PASS: $name"
  else
    echo "FAIL: $name" >&2
    FAILED_CONFIGS+=$'\n'"  $name"
  fi
}

module_version() {
  local version
  case "$GOFIPS140" in
    off|latest) echo latest ;;
    *)
      version=$(cat "$GOROOT/lib/fips140/$GOFIPS140.txt") || return 1
      echo "${version%%-*}"
      ;;
  esac
}

# Flags and package lists below are script-owned argument lists, intentionally
# word-split. No user-supplied Go flags are accepted.
run_configuration() (
  export GOFIPS140=$1 GODEBUG=$2 GOLANG_NATIVE_HOSTFIPS_OVERRIDE=$3
  local enabled=$4 build_flags=${5:-} skip_flags=${6:-}
  local version packages suite failed=0
  version=$(module_version) || return 1
  if ! "$GO" run $build_flags "$WORK/state.go" "$version" "$enabled" 0; then
    failed=1
  fi
  for suite in ${SUITES//,/ }; do
    echo "Running $suite: GOFIPS140=$GOFIPS140 GODEBUG=${GODEBUG:-<compiled default>} host-override=$GOLANG_NATIVE_HOSTFIPS_OVERRIDE $build_flags"
    case "$suite" in
      crypto)
        # Relative wildcards conflict with frozen-module overlays.
        if ! packages=$("$GO" list $build_flags crypto/... | grep -v '^crypto/tls$'); then
          echo "FAIL: crypto package discovery failed" >&2
          failed=1
          continue
        fi
        if [[ -z "$packages" ]]; then
          echo "FAIL: no crypto packages found" >&2
          failed=1
          continue
        fi
        ;;
      tls)
        packages=crypto/tls
        ;;
      *)
        echo "FAIL: unsupported suite: $suite" >&2
        failed=1
        continue
        ;;
    esac
    if ! "$GO" test -count=1 $VERBOSE $build_flags $skip_flags $packages; then
      failed=1
    fi
  done
  return "$failed"
)

run_only() (
  export GOFIPS140=$1 GODEBUG=fips140=only GOLANG_NATIVE_HOSTFIPS_OVERRIDE=0
  local version failed=0
  version=$(module_version) || return 1
  if ! "$GO" run "$WORK/state.go" "$version" 1 1; then failed=1; fi
  # General crypto tests intentionally use non-approved algorithms. The
  # enforcement suite is the appropriate test of fips140=only, not crypto/....
  if [[ ",$SUITES," == *,crypto,* ]]; then
    if ! "$GO" test -count=1 $VERBOSE crypto/internal/fips140only; then failed=1; fi
  fi
  return "$failed"
)

run_module() {
  local module=$1
  # An empty GODEBUG tests the compiled auto default, not an explicit override.
  record "$module/auto-host" run_configuration "$module" "" 0 "$HOST_FIPS"
  record "$module/auto-fips-host" run_configuration "$module" "" 1 1
  record "$module/off" run_configuration "$module" fips140=off 1 0
  record "$module/on" run_configuration "$module" fips140=on 0 1
  record "$module/only" run_only "$module"
}

reject_purego() (
  export GOFIPS140=$1
  local output
  if output=$("$GO" test -c -o "$WORK/rejected.test" -tags=purego crypto/sha256 2>&1); then
    echo "FAIL: purego unexpectedly compiled with GOFIPS140=$GOFIPS140" >&2
    return 1
  fi
  printf '%s\n' "$output"
  [[ "$output" == *"go: use of purego build tag requires GOFIPS140=off"* ]]
)

run_strict_case() (
  export GOFIPS140=$1 GODEBUG=$3 GOLANG_NATIVE_HOSTFIPS_OVERRIDE=$4
  local mechanism=$2 enabled=$5 build_flags= version output
  if [[ "$mechanism" == experiment ]]; then
    export GOEXPERIMENT=strictfipsruntime
  else
    build_flags=-tags=strictfipsruntime
  fi
  version=$(module_version) || return 1
  if [[ "$enabled" == 0 && ( "$GOLANG_NATIVE_HOSTFIPS_OVERRIDE" == 1 || "$HOST_FIPS" == 1 ) ]]; then
    if output=$("$GO" run $build_flags "$WORK/state.go" "$version" 0 0 2>&1); then
      echo "FAIL: strict startup unexpectedly allowed disabled FIPS on a FIPS host" >&2
      return 1
    fi
    printf '%s\n' "$output"
    [[ "$output" == *"Host FIPS mode is enabled, but the required GODEBUG=fips140 module is disabled"* ]]
  else
    "$GO" run $build_flags "$WORK/state.go" "$version" "$enabled" 0 || return 1
    "$GO" test -count=1 $VERBOSE $build_flags crypto/sha256
  fi
)

run_strict() {
  local module mechanism
  for module in certified inprocess latest off; do
    for mechanism in experiment tag; do
      record "$module/strict-$mechanism/auto" run_strict_case "$module" "$mechanism" fips140=auto 1 1
      record "$module/strict-$mechanism/on" run_strict_case "$module" "$mechanism" fips140=on 0 1
      record "$module/strict-$mechanism/off-fips-host" run_strict_case "$module" "$mechanism" fips140=off 1 0
      record "$module/strict-$mechanism/off-host" run_strict_case "$module" "$mechanism" fips140=off 0 0
    done
  done
  record strict-import-coverage "$GO" test -count=1 $VERBOSE go/build -run '^(TestDependencies|TestStrictFIPSHubCoverage)$'
}

run_build_defaults() (
  # Exercise the toolchain's defaults, not the matrix's explicit selection
  # or a GOFIPS140 override saved with go env -w.
  unset GOFIPS140
  export GOENV=off
  local info snapshot
  snapshot=$(cat "$GOROOT/lib/fips140/certified.txt") || return 1
  "$GO" test -c -o "$WORK/sha256.test" crypto/sha256 || return 1
  info=$("$GO" version -m "$WORK/sha256.test") || return 1
  printf '%s\n' "$info"
  if ! printf '%s\n' "$info" | grep -Eq '^[[:space:]]*build[[:space:]]+DefaultGODEBUG=([^,[:space:]]+,)*fips140=auto(,|$)'; then
    echo "FAIL: default build must embed DefaultGODEBUG with fips140=auto" >&2
    return 1
  fi
  if ! printf '%s\n' "$info" | grep -Eq "^[[:space:]]*build[[:space:]]+GOFIPS140=${snapshot//./\\.}$"; then
    echo "FAIL: default build must embed GOFIPS140=$snapshot" >&2
    return 1
  fi
)

run_cmd_go() {
  local info snapshot
  info=$("$GO" version -m "$GO") || return 1
  snapshot=$(cat "$GOROOT/lib/fips140/certified.txt") || return 1
  if [[ "$info" != *"DefaultGODEBUG=fips140=auto"* || "$info" != *"GOFIPS140=$snapshot"* ]]; then
    echo "FAIL: toolchain must embed auto FIPS and the certified snapshot" >&2
    printf '%s\n' "$info"
    return 1
  fi
  if [[ -d "$GOROOT/pkg/obj" ]]; then
    echo "FAIL: expected the build's module cache to be erased" >&2
    return 1
  fi
  "$GO" test -count=1 $VERBOSE cmd/go -run '^TestScript/(fips|fipssnap|fipssnap_modcache)$'
}

for mode in ${MODES//,/ }; do
  case "$mode" in
    native-fips-auto) run_module certified ;;
    native-fips-inprocess) run_module inprocess ;;
    native-fips-latest) run_module latest ;;
    non-fips) record non-fips run_configuration off fips140=off 0 0 ;;
    purego)
      for module in certified inprocess latest; do
        record "$module/reject-purego" reject_purego "$module"
      done
      # ACVP launches a FIPS-enabled child, which cannot run with purego.
      # Keep the rest of fips140test instead of excluding the whole package.
      echo "Purego exception: TestACVP requires FIPS mode; it runs in the ordinary matrix."
      record purego run_configuration off fips140=off 0 0 -tags=purego '-skip=^TestACVP$'
      ;;
    native-fips-strict) run_strict ;;
    cmd/go)
      record cmd/go-defaults run_build_defaults
      record cmd/go run_cmd_go
      ;;
  esac
done

if [[ -n "$FAILED_CONFIGS" ]]; then
  printf '\nFAILED CONFIGURATIONS:%s\n' "$FAILED_CONFIGS" >&2
  exit 1
fi
echo ALL TESTS PASSED
