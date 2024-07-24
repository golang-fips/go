#!/usr/bin/env bash
# this script builds a go binary after applying openssl fips patches.

set -x
export GOLANG_VER=1.22.2
[[ -d go ]] || ./scripts/full-initialize-repo.sh go$GOLANG_VER
cd go/src
export GO_BUILDTAGS+="goexperiment.strictfipsruntime"
export CGO_ENABLED=1
./make.bash --no-clean
{ set +x ; } 2>/dev/null
