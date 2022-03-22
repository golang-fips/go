# Go FIPS with OpenSSL

Repository for FIPS enabled Go using OpenSSL.

## Motivation

The cryptographic routines in the Go standard library cannot be FIPS certified and must instead rely on an external
cryptographic implementation which can be FIPS certified. This repository and the upstream sources it is based on
contain the necessary modifications for the Go crypto library to use an external cryptographic library in a FIPS
compliant way.

## Background

This repository contains a fork of the [Go](https://github.com/golang/go) toolchain [dev.boringcrypto](https://github.com/golang/go/tree/dev.boringcrypto) branch.

The `dev.boringcrypto` branch itself is a fork maintained separately from the main Go repository branches. This upstream
branch modifies the `crypto/*` packages to use [BoringCrypto](https://boringssl.googlesource.com/boringssl/) for cryptographic operations.
This branch uses a pre-compiled shared object which the Go toolchain can statically link against.

## OpenSSL support

The modifications contained in this repository add support for using OpenSSL as the crypto backend when the host system is in FIPS mode.

Main differences from the upstream BoringCrypto fork are:

* Uses OpenSSL as cryptographic library instead of BoringSSL.
* Not statically linked, we instead use `dlopen` to call into OpenSSL.
* FIPS mode (or `boring` mode as the package is named) is enabled either via an environment variable `GOLANG_FIPS=1` or by virtue of the host being in FIPS mode.
* A few more downstream modifications to ensure complete test coverage, and some downstream code changes to support various versions of OpenSSL

## Branches

The `main` branch contains only a license file and this README. The FIPS patches are stored on versioned branches
which follow the naming convention: `go1.x-openssl-fips`.