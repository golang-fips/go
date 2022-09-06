#!/bin/bash

set -ex

# Apply some manual substitutions with sed. These changes will likely introduce
# merge conflicts if this was a patch, so we do them here instead and generate a patch
# after.
GO_SOURCES=src/crypto/**/*.go
sed -i -e "s/boringCert(t, \"R2\", boringRSAKey(t, 4096), nil, boringCertCA)/boringCert(t, \"R2\", boringRSAKey(t, 4096), nil, boringCertCA|boringCertFIPSOK)/g" src/crypto/tls/boring_test.go
sed -i -e "s/boring.SignRSAPKCS1v15(bkey, hash, hashed)/boring.SignRSAPKCS1v15(bkey, hash, hashed, true)/g" src/crypto/rsa/pkcs1v15.go
sed -i -e "s/boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig)/boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig, hash != crypto.Hash(0))/g" src/crypto/rsa/pkcs1v15.go
sed -i -e "s/boring\.Enabled/boring\.Enabled()/g" ${GO_SOURCES}
sed -i -e "s/\"crypto\/internal\/boring\"/boring \"crypto\/internal\/backend\"/g" ${GO_SOURCES}
sed -i -e "s/\"crypto\/internal\/boring\/bbig\"/\"crypto\/internal\/backend\/bbig\"/g" ${GO_SOURCES}
sed -i -e "s/const boringEnabled/var boringEnabled/g" ${GO_SOURCES}
sed -i -e "s/testConfig\.Clone()/testConfigTemplate()/g" src/crypto/tls/boring_test.go
cat << EOF >> src/crypto/tls/boring_test.go
func testConfigTemplate() *Config {
	config := testConfig.Clone()
	if boring.Enabled() {
		config.Certificates[0].Certificate = [][]byte{testRSA2048Certificate}
		config.Certificates[0].PrivateKey = testRSA2048PrivateKey
	}
	return config
}
EOF

# Remove the crypto/internal/boring code as we're replacing it with the openssl backend code.
rm -rf src/crypto/internal/boring/syso
rm src/crypto/boring/boring_test.go

# Add new openssl backend to module and vendor it.
echo "require github.com/golang-fips/openssl-fips/v2 v2.0.0" >> src/go.mod
replace="${1}"
if [ -n "${replace}" ]; then
    echo "replace github.com/golang-fips/openssl-fips/v2 => ${replace}" >> src/go.mod
fi
cd src
go mod tidy
go mod vendor

# Generate the final patch.
git add .
git diff --cached --binary > ../../patches/001-initial-openssl-for-fips.patch
