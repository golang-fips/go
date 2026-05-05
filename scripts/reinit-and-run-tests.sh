#!/bin/bash

# Removes any existing go subtree, reinitializes it by applying all patches,
# builds the toolchain, and runs the crypto test suite.

set -eE

SCRIPT_DIR=$(readlink -f $(dirname $0))
GO_DIR=${SCRIPT_DIR}/../go

# Remove the existing go subtree so full-initialize-repo.sh can start fresh.
# The FIPS module cache extracts read-only files; chmod before rm to avoid errors.
if [[ -d "${GO_DIR}" ]]; then
  echo "Removing existing go tree..."
  chmod -R u+w "${GO_DIR}"
  rm -rf "${GO_DIR}"
fi

# Reinitialize and apply patches.
${SCRIPT_DIR}/full-initialize-repo.sh

# Build the toolchain.
echo "Building toolchain..."
pushd "${GO_DIR}/src"
./make.bash
popd

# Run the crypto test suite, forwarding any extra arguments.
${SCRIPT_DIR}/crypto-test.sh $@
