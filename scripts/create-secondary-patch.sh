#!/bin/bash

set -ex

# Apply some manual substitutions with sed. These changes will likely introduce
# merge conflicts if this was a patch, so we do them here instead and generate a patch
# after.
GO_SOURCES=src/crypto/**/*.go
sed -i -e "s/boring.SignRSAPKCS1v15(bkey, hash, hashed)/boring.SignRSAPKCS1v15(bkey, hash, hashed, true)/g" src/crypto/rsa/pkcs1v15.go
sed -i -e "s/boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig)/boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig, hash != crypto.Hash(0))/g" src/crypto/rsa/pkcs1v15.go
sed -i -e "s/boring\.Enabled/boring\.Enabled()/g" ${GO_SOURCES}
sed -i -e "s/\"crypto\/internal\/boring\"/boring \"crypto\/internal\/backend\"/g" ${GO_SOURCES}
sed -i -e "s/\"crypto\/internal\/boring\/bbig\"/\"crypto\/internal\/backend\/bbig\"/g" ${GO_SOURCES}
sed -i -e "s/const boringEnabled/var boringEnabled/g" ${GO_SOURCES}
sed -i -e "s/\!boringcrypto/no_openssl/g" ${GO_SOURCES}
sed -i -e "s/boringcrypto/!no_openssl/g" ${GO_SOURCES}
sed -i -e "s/boringcrypto/!no_openssl/g" src/crypto/internal/boring/fipstls/*.*
sed -i -e "s/boringcrypto/!no_openssl/g" src/cmd/api/*.*
# revert this back to fix the api test
sed -i -e "s/\!no_openssl/boringcrypto/g" src/crypto/boring/boring.go

# Remove the crypto/internal/boring code as we're replacing it with the openssl backend code.
rm -rf src/crypto/internal/boring/*.go
rm -rf src/crypto/internal/boring/bbig
rm src/crypto/boring/notboring_test.go
rm src/crypto/boring/boring_test.go

# Add new openssl backend to module and vendor it.
cd src
SCRIPT_DIR=$(readlink -f $(dirname $0))
CONFIG_DIR=$(readlink -f $(dirname $0)/../config)
OPENSSL_FIPS_REF=$(go run ${SCRIPT_DIR}/versions.go ${CONFIG_DIR}/versions.json \
			github.com/golang-fips/openssl-fips)
go get github.com/golang-fips/openssl-fips@${OPENSSL_FIPS_REF}

replace="${1}"
if [ -n "${replace}" ]; then
    echo "replace github.com/golang-fips/openssl-fips => ${replace}" >> go.mod
fi
go mod tidy -go=1.19
go mod vendor

# Generate the final patch.
git add .
git diff --cached --binary > ../../patches/001-initial-openssl-for-fips.patch
