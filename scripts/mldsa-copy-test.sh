#!/bin/bash

# Verify that the nofips ML-DSA package is reproducible from the in-tree copy.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
if [[ -d "$REPO_DIR/src" ]]; then
  GOROOT=$REPO_DIR
else
  GOROOT=$REPO_DIR/go
fi
SOURCE=$GOROOT/src/crypto/internal/fips140/mldsa
ACTUAL=$GOROOT/src/crypto/internal/nofips/mldsa
if [[ ! -f "$SOURCE/mldsa.go" || ! -f "$ACTUAL/mldsa.go" ]]; then
  echo "FAIL: ML-DSA packages not found; initialize the Go tree first" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R "$SOURCE" "$WORK/expected"
cp -R "$ACTUAL" "$WORK/actual"

# Require and remove exactly one downstream startup-check import for comparison.
if ! awk '
  $0 == "\t_ \"crypto/internal/strictfips\"" { count++; next }
  { print }
  END { if (count != 1) exit 1 }
' "$WORK/actual/mldsa.go" > "$WORK/normalized"; then
  echo "FAIL: nofips ML-DSA must contain exactly one strict-FIPS startup-check import" >&2
  exit 1
fi
mv "$WORK/normalized" "$WORK/actual/mldsa.go"

# Git is already required to materialize the Go tree; do not require diffutils.
if git --no-pager diff --no-index --exit-code --no-ext-diff --no-textconv -- "$WORK/expected" "$WORK/actual"; then
  echo "PASS: nofips ML-DSA matches the in-tree package"
else
  status=$?
  if [[ "$status" -eq 1 ]]; then
    echo "FAIL: nofips ML-DSA differs from the in-tree package; run scripts/copy-mldsa.sh to refresh it" >&2
  else
    echo "FAIL: could not compare ML-DSA packages (git diff exited $status)" >&2
  fi
  exit "$status"
fi
