#!/bin/bash

set -ex

# Apply some manual substitutions with sed. These changes will likely introduce
# merge conflicts if this was a patch, so we do them here instead and generate a patch
# after.
GO_SOURCES=src/crypto/**/*.go
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
#rm -rf src/crypto/internal/boring/bbig
rm src/crypto/boring/notboring_test.go
rm src/crypto/boring/boring_test.go
echo """// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package boring provides access to BoringCrypto implementation functions.
// Check the constant Enabled to find out whether BoringCrypto is available.
// If BoringCrypto is not available, the functions in this package all panic.
package boring

import \"github.com/golang-fips/openssl/v2\"

// A BigInt is the raw words from a BigInt.
// This definition allows us to avoid importing math/big.
// Conversion between BigInt and *big.Int is in crypto/internal/boring/bbig.
type BigInt = openssl.BigInt
""" >src/crypto/internal/boring/doc.go

# Add new openssl backend to module and vendor it.
export GOROOT=$(pwd)
cd src
SCRIPT_DIR=$(readlink -f $(dirname $0))
CONFIG_DIR=$(readlink -f $(dirname $0)/../config)
OPENSSL_FIPS_REF=$(../bin/go run ${SCRIPT_DIR}/versions.go ${CONFIG_DIR}/versions.json \
	github.com/golang-fips/openssl)
../bin/go get github.com/golang-fips/openssl/v2@${OPENSSL_FIPS_REF}

replace="${1}"
if [ -n "${replace}" ]; then
	go mod edit -replace github.com/golang-fips/openssl/v2="${replace}"
fi
../bin/go mod tidy
../bin/go mod vendor

# Generate the final patch.
git add .
git diff --cached --binary >../../patches/001-initial-openssl-for-fips.patch
