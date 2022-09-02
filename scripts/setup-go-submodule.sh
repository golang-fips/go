#!/bin/bash

set -ex

BRANCH=${1}

if [ -z "${BRANCH}" ]; then
    echo "You must supply a branch for the Go submodule (for example dev.boringcrypto.go1.18)"
    exit 1
fi

git submodule add --force -b "${BRANCH}" https://github.com/golang/go.git
git submodule update

