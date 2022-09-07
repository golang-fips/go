#!/bin/bash

set -ex

ROOT=$(pwd)
BRANCH="${1}"
shift
ARGS="$@"

# Function to clean things up if any portion of the script fails.
function cleanup() {
    # shellcheck disable=SC2181
    if [ "0" != "${?}" ]; then
        cd "${ROOT}"
        rm -rf go
    fi
}
trap cleanup EXIT

"${ROOT}"/scripts/setup-go-submodule.sh ${BRANCH}

# Enter the submodule directory.
cd ./go
ORIGINAL_GIT_SHA=$(git rev-parse HEAD)

"${ROOT}"/scripts/apply-initial-patch.sh
"${ROOT}"/scripts/create-secondary-patch.sh ${ARGS}

# Clean things up again after we've generated the patch.
git reset --hard ${ORIGINAL_GIT_SHA}
