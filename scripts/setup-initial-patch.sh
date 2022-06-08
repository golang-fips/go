#!/bin/bash

set -ex

ROOT=$(pwd)

# Function to clean things up if any portion of the script fails.
function cleanup() {
    if [ "0" != "${?}" ]; then
        cd ${ROOT}
        rm -rf go
    fi
}
trap cleanup EXIT

BRANCH=${1}

if [ -z "${BRANCH}" ]; then
    echo "You must supply a branch for the Go submodule (for example dev.boringcrypto.go1.18)"
    exit 1
fi

git submodule add --force -b ${BRANCH} https://github.com/golang/go.git
git submodule update

# Enter the submodule directory.
cd ./go

ORIGINAL_GIT_SHA=$(git rev-parse HEAD)

# Apply the initial patch. This patch is basic and shouldn't accrue many
# conflicts over time so it should be safe to apply.
git apply ../patches/000-initial-setup.patch
# Add the initial changes to the index so the later diff ignores them.
git add .
git commit -m phase1

# Apply some manual substitutions with sed. These changes will likely introduce
# merge conflicts if this was a patch, so we do them here instead and generate a patch
# after.
GO_SOURCES=src/crypto/**/*.go
sed -i -e "s/boringCert(t, \"R2\", boringRSAKey(t, 4096), nil, boringCertCA)/boringCert(t, \"R2\", boringRSAKey(t, 4096), nil, boringCertCA|boringCertFIPSOK)/g" src/crypto/tls/boring_test.go
sed -i -e "s/boring.SignRSAPKCS1v15(bkey, hash, hashed)/boring.SignRSAPKCS1v15(bkey, hash, hashed, true)/g" src/crypto/rsa/pkcs1v15.go
sed -i -e "s/boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig)/boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig, hash != crypto.Hash(0))/g" src/crypto/rsa/pkcs1v15.go
sed -i -e "s/boring.SignMarshalECDSA(b, digest)/boring.SignMarshalECDSA(b, digest, crypto.Hash(0))/g" src/crypto/ecdsa/ecdsa.go
sed -i -e "s/boring.SignECDSA(b, hash)/boring.SignECDSA(b, hash, crypto.Hash(0))/g" src/crypto/ecdsa/ecdsa.go
sed -i -e "s/boring.VerifyECDSA(b, hash, r, s)/boring.VerifyECDSA(b, hash, r, s, crypto.Hash(0))/g" src/crypto/ecdsa/ecdsa.go
sed -i -e "s/boring\.Enabled/boring\.Enabled()/g" ${GO_SOURCES}
sed -i -e "s/\"crypto\/internal\/boring\"/boring \"crypto\/internal\/backend\"/g" ${GO_SOURCES}
sed -i -e "s/const boringEnabled/var boringEnabled/g" ${GO_SOURCES}

# Remove the crypto/internal/boring code as we're replacing it with the openssl backend code.
rm src/crypto/internal/boring/*.*
rm src/crypto/boring/boring_test.go

# Add new openssl backend to module and vendor it.
echo "require github.com/golang-fips/openssl-fips v0.0.0-20220505153334-362f46022010" >> src/go.mod
cd src
go mod tidy
go mod vendor

# Generate the final patch.
git add .
git diff --cached --binary > ../../patches/001-initial-openssl-for-fips.patch

# Clean things up again after we've generated the patch.
git reset --hard ${ORIGINAL_GIT_SHA}