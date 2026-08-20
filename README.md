# Go Toolchain

This repository holds the source code for the fork of the Go toolchain used in the Go Toolset CentOS / RHEL packages. This fork builds on Go's native FIPS 140-3 module (`crypto/fips140`) with a small set of patches for host-auto FIPS activation and related feature parity.

**Disclaimer:** This repository itself is not an official Red Hat product.

## Background

### What is FIPS 140-3?

FIPS 140-3 is a standard for cryptographic modules used by federal agencies to protect sensitive information. It covers design, implementation, operation, and security requirements for different levels of protection.

https://csrc.nist.gov/pubs/fips/140-3/final

### Migration to upstream FIPS certified cryptography

Earlier releases of this fork routed cryptography through OpenSSL for FIPS compliance. That approach is **deprecated and removed**. Historical OpenSSL-based sources live on the corresponding `go1.*-fips-release` branches.

The upstream Go toolchain has achieved [CMVP certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247). The `main` branch no longer carries the OpenSSL backend; it applies a small set of patches on top of the certified native `crypto/fips140` module (host-auto FIPS detection, strict runtime checks, and related parity).

A notable user-facing difference from the old OpenSSL backend is how non-approved cryptography is handled. With the native module, operations that cannot be rejected gracefully are recorded via the FIPS service indicator rather than producing runtime errors or panics. Upstream guidance is to **test** with `GODEBUG=fips140=only` to surface non-approved use, and **run** in production with `on` (or `auto`, which resolves to `on` on a FIPS host) so critical applications do not crash unexpectedly.

## Go and FIPS

Before Go 1.24 there had never been an attempt to have the Go cryptographic libraries FIPS 140-3 certified. There was still a need for Go programs to run in FIPS environments, so the Go maintainers maintained a BoringCrypto-backed approach that later informed the native `crypto/internal/fips140` module and direct certification of Go cryptography.

## Downstream Modifications

This fork uses Go's certified native FIPS module and adds a few operator-facing defaults and checks:

- **Host-auto FIPS** — starting in Go 1.27, compiled-in default of `GODEBUG=fips140=auto`, so FIPS activates only when the host is booted in FIPS mode.
- **Certified module by default** — builds embed the certified FIPS 140-3 snapshot (`GOFIPS140=certified`) unless overridden.
- **Strict FIPS mode** — optional startup abort if the host is in FIPS mode but `GODEBUG=fips140` is disabled. See below.

## Building the Toolchain

### Clone the repository

```
$ git clone https://github.com/golang-fips/go.git && cd ./go
```

### Build the toolchain

```
$ ./scripts/full-initialize-repo.sh && cd ./go/src && ./make.bash
```

### Run tests

```
$ ./scripts/crypto-test.sh && cd ./go/src && ./all.bash
```

## Compiler Usage

### FIPS module embedding (`GOFIPS140`)

`GOFIPS140` selects which FIPS 140-3 module snapshot is embedded at build time. This fork defaults to the certified snapshot. Set `GOFIPS140=off` to build without embedding a FIPS module.

### Enabling strict FIPS mode

Strict FIPS mode aborts at startup if the host is in FIPS mode but the native `GODEBUG=fips140` module is disabled (for example, if someone overrides `GODEBUG=fips140=off` at runtime).

Enable it at compile time with either the experiment or the build tag:

```
GOEXPERIMENT=strictfipsruntime go build
```

```
go build -tags strictfipsruntime
```

## Runtime Usage

### `GODEBUG=fips140`

Starting in Go 1.27, this fork's compiled-in default is `fips140=auto`. Supported values:

| Value  | Behavior |
|--------|----------|
| `auto` | Activate FIPS only when the host is in FIPS mode (resolves to `on`); otherwise run without FIPS. |
| `on`   | Always activate FIPS, regardless of host configuration. Prefer for production. |
| `only` | Activate FIPS and reject non-approved algorithms where possible. Prefer for testing. |
| `off`  | Disable FIPS mode. |

With `auto`, host FIPS mode is detected once at startup (on Linux, via `/proc/sys/crypto/fips_enabled`) and the result is cached for the process lifetime.

As with all `GODEBUG` settings, a runtime `GODEBUG` environment variable overrides the compiled-in default.

### Strict FIPS runtime protection

If you compiled with `GOEXPERIMENT=strictfipsruntime` or `-tags strictfipsruntime`, then at startup the process checks whether the host is in FIPS mode. If it is, but `GODEBUG=fips140` resolved to off/disabled, the process exits with:

```
Host FIPS mode is enabled, but the required GODEBUG=fips140 module is disabled
```

This gives operators increased confidence that binaries running in FIPS environments are not silently falling back to non-validated cryptography.

### Testing host-auto mode without a FIPS-enabled host

For testing `fips140=auto` on a host that is not booted in FIPS mode, set `GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1`. This makes `auto` resolve as if the host were in FIPS mode.

## Further Reading

- https://access.redhat.com/compliance/fips
- https://github.com/golang-fips/go
- https://developers.redhat.com/articles/2025/03/10/benefits-native-fips-support-go-124
- https://developers.redhat.com/articles/2025/01/23/fips-mode-red-hat-go-toolset
- https://developers.redhat.com/articles/2024/02/27/handling-fips-mode-upstream-projects-rhel
- https://developers.redhat.com/articles/2023/12/14/how-improve-go-fips-test-coverage-packit
- https://developers.redhat.com/articles/2022/05/31/your-go-application-fips-compliant
- https://developers.redhat.com/blog/2019/06/24/go-and-fips-140-2-on-red-hat-enterprise-linux
