#!/bin/bash

set -ex

GIT_REF=${1}

if [ -z "${GIT_REF}" ]; then
    echo "You must supply a branch, tag, or commit for the Go submodule (for example release-branch.go1.19)"
    exit 1
fi

git submodule add --force https://github.com/golang/go.git
git submodule update

pushd go
git checkout ${GIT_REF}
popd

