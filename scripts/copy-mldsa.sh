#!/bin/bash

# Copy the in-tree ML-DSA implementation, including tests and support files.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
if [[ -d "$REPO_DIR/src" ]]; then
  GOROOT=$REPO_DIR
else
  GOROOT=$REPO_DIR/go
fi
SOURCE=$GOROOT/src/crypto/internal/fips140/mldsa
DESTINATION=$GOROOT/src/crypto/internal/nofips/mldsa

if [[ ! -f "$SOURCE/mldsa.go" ]]; then
  echo "FAIL: in-tree ML-DSA package not found; initialize the Go tree first" >&2
  exit 1
fi

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
cp -R "$SOURCE/." "$STAGING/"

# Preserve the existing downstream blank import in the nofips copy. In strict
# builds it aborts startup on a FIPS host if the FIPS module is disabled.
# Do not add that import to the upstream crypto/internal/fips140/mldsa source.
awk '
  { print }
  $0 == "\t\"crypto/internal/fips140deps/byteorder\"" {
    print "\t_ \"crypto/internal/strictfips\""
    count++
  }
  END { if (count != 1) exit 1 }
' "$STAGING/mldsa.go" > "$STAGING/mldsa.go.new"
mv "$STAGING/mldsa.go.new" "$STAGING/mldsa.go"

# Do not delete destination-only files: the consistency test reports them so
# maintainers can review and remove obsolete files explicitly.
mkdir -p "$DESTINATION"
cp -R "$STAGING/." "$DESTINATION/"
