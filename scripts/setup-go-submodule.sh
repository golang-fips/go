#!/bin/bash

set -ex

GIT_REF=${1}
SCRIPT_DIR=$(readlink -f $(dirname $0))
CONFIG_DIR=$(readlink -f $(dirname $0)/../config)

if [ -z "${GIT_REF}" ]; then
    GIT_REF=$(go run ${SCRIPT_DIR}/versions.go ${CONFIG_DIR}/versions.json github.com/golang/go)
    if [ -z "${GIT_REF}" ]; then
      echo "You must supply a branch, tag, or commit for the Go submodule (for example release-branch.go1.19)"
      exit 1
    fi
fi

git submodule add --force https://github.com/golang/go.git
git submodule update

pushd go
git fetch
git checkout ${GIT_REF}

# If we're on a branch, the cached tree might be out of sync,
# so we should hard reset against origin.
if [[ "$(git branch --show-current | wc -l)" == "1" ]]; then
  git fetch
  git reset origin/${GIT_REF} --hard
fi

popd

