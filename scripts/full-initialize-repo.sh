#!/bin/bash

# This script generates and applies FIPS
# patches to a Go tree.

echo "Host Go Version:"
go version

echo "Host Go Env:"
go env

SCRIPT_DIR=$(readlink -f $(dirname $0))
GO_DIR=${SCRIPT_DIR}/../go

if [[ -d "${GO_DIR}" ]]; then
  1>&2 echo "Existing go tree detected.  Aborting..."
  exit 1
fi

${SCRIPT_DIR}/setup-initial-patch.sh $@

set -ex
pushd ${GO_DIR}
for patch in $(ls ../patches); do
  git apply -v ../patches/${patch}
  git add -A
  git commit -am ${patch}
done
popd
