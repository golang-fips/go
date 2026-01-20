#! /usr/bin/env bash
# this script builds a go binary after applying openssl fips patches one by one.
#
export GOLANG_VER=1.22.2
export GOLANG_REL=1

# variables to store tar file names
GO_TAR_NAME=go$GOLANG_VER
PATCH_TAR_NAME=go$GOLANG_VER-$GOLANG_REL-openssl-fips
GO_SRC_TAR=$GO_TAR_NAME.tar.gz
PATCH_TAR=$PATCH_TAR_NAME.tar.gz

# after untar, the dir names are stored in PATCH_DIR and SRC_DIR
SRC_DIR=go-$GO_TAR_NAME
PATCH_DIR=go-$PATCH_TAR_NAME
TOP_DIR=/tmp/golang-fips/build2
# If the go src dir ends up in a weird state where in patches are failing to apply, you might want to remove the $TOP_DIR (rm -rf /tmp/golang-fips/build2) to start with a clean slate.
PATCH_PATH=$TOP_DIR/$PATCH_DIR/patches

# this file stores state of last applied patch, that way patches are not reapplied
PATCH_STATE=$TOP_DIR/state
set -x
[[ -d $TOP_DIR ]] || mkdir -p $TOP_DIR
cd $TOP_DIR

[[ -f $GO_SRC_TAR ]] || wget -q --show-progress https://github.com/golang/go/archive/refs/tags/$GO_SRC_TAR
[[ -f $PATCH_TAR ]] || wget -q --show-progress https://github.com/golang-fips/go/archive/refs/tags/$PATCH_TAR
[[ -d $SRC_DIR ]] || tar -xf $GO_SRC_TAR
[[ -d $PATCH_DIR ]] || tar -xf $PATCH_TAR

cd $SRC_DIR
{ set +x; } 2>/dev/null
if [[ -f $PATCH_STATE && "$(cat $PATCH_STATE)" == "complete" ]]; then
    echo "patches already applied. skipping"
else
    for patch in $PATCH_PATH/*.patch; do
        patch -p1 < "${patch}"
        [[ $? -eq 0 ]] || { echo "incomplete" > $PATCH_STATE; break; exit 1; }
    done
fi

echo "complete" > $PATCH_STATE
# patches have been supplied successfully, simply build like above.
set -x
cd src
export GO_BUILDTAGS+="goexperiment.strictfipsruntime,!no_openssl"
export CGO_ENABLED=1
./make.bash --no-clean
{ set +x; } 2>/dev/null
