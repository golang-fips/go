#!/bin/bash

set -ex

ROOT=$(pwd)

# Function to clean things up if any portion of the script fails.
function cleanup() {
    # shellcheck disable=SC2181
    if [ "0" != "${?}" ]; then
        cd "${ROOT}"
        rm -rf go
    fi
}
trap cleanup EXIT

./scripts/setup-go-submodule.sh "${1}"

# Enter the submodule directory.
cd ./go
ORIGINAL_GIT_SHA=$(git rev-parse HEAD)

"${ROOT}"/scripts/apply-initial-patch.sh
"${ROOT}"/scripts/create-secondary-patch.sh

# Clean things up again after we've generated the patch.
git reset --hard ${ORIGINAL_GIT_SHA}