# Go Toolchain

This repository holds the source code for the fork of the Go toolchain used in the Go Toolset CentOS / RHEL packages. This fork contains modifications enabling Go to call into OpenSSL for FIPS compliance.

**Disclaimer:** This repository itself is not an official Red Hat product.

## Background

### What is FIPS 140-3?

FIPS 140-3 is a standard for cryptographic modules used by federal agencies to protect sensitive information. It covers design, implementation, operation, and security requirements for different levels of protection.

https://csrc.nist.gov/pubs/fips/140-3/final

## Go and FIPS

Before Go 1.24 there had never been an attempt to have the Go cryptographic libraries FIPS 140-3 certified. However, there was still a need for Go programs to run in environments where FIPS certification is necessary. To that end, the Go maintainers implemented a fork (maintained as a separate branch) which would link Go against the C library Boring Crypto. This branch would eventually be merged into the main branch, paving the way for their own eventual removal and the creation of the `crypto/internal/fips` module and the attempt to directly certify the Go source itself.

## Downstream Modifications

This Go toolchain is based on a fork of the upstream work enabling Go to link against Boring Crypto. This fork uses OpenSSL instead of BoringSSL and adds enhancements to give operators more confidence when deploying their Go binaries in environments requiring strict compliance.

### OpenSSL

The main difference between this fork and the upstream work is the FIPS validated library which is used to execute the cryptographic operations when FIPS mode is enabled. Our fork uses OpenSSL which is already FIPS validated on RHEL.

### Dynamic linkage

Our OpenSSL based toolchain produces binaries that are dynamically linked by default. When a Go binary built with this toolchain including FIPS enhancements is executed it will search for a supported version of libcrypto.so (starting with OpenSSL 3, falling back to older versions) and then dlopen it if found. This means that disabling of CGO via CGO_ENABLED=0 is unsupported in FIPS mode.

### Strict FIPS mode

Our downstream modifications also include a strict FIPS mode where a Go binary built with this enabled will crash when it detects it is running in a FIPS environment without being properly compiled or having loaded the appropriate OpenSSL version to call into. More details are available in later sections of this document.

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

This section details the different flags and options you have available when compiling your source code using the Go toolchain.

### Opting out of FIPS changes at compile time

A user can always opt out of the downstream changes and FIPS enhancements when compiling their source code. To opt out of the downstream changes in the Go Toolset related to using OpenSSL for cryptography, you can use the following compiler tag: `-tags no_openssl`.

Building your programs with this tag will completely bypass and compile out all of these changes. This means that instead of potentially calling into OpenSSL via dynamic linkage and CGO, your application will use the pure upstream standard library cryptography.

For example, you would use the command like this: `go build -tags no_openssl`.

### Enabling strict FIPS mode

This Go toolchain includes a strict FIPS mode. This is a startup check whose purpose is to detect build or runtime configuration issues that might prevent the application from properly using the OpenSSL backend in a FIPS environment, and it will cause the application to crash via a panic if such issues are detected.

To enable this strict FIPS mode during compilation, you need to use a specific GOEXPERIMENT setting.

You can enable this option by building your application using the following setting:

```
GOEXPERIMENT=strictfipsruntime
```

So, you would typically run your build command like this: `GOEXPERIMENT=strictfipsruntime go build`.

## Runtime Usage

### Forcing a specific OpenSSL version

When starting your application you can choose to force a specific OpenSSL version as opposed to letting the process search for an available version at startup. By default the process will try to load the latest version of OpenSSL available on the system, starting with OpenSSL 3. In order to instead explicitly select the version you must set the environment variable `GO_OPENSSL_VERSION_OVERRIDE`. For example, to ensure that OpenSSL 3 is used you would need to start the Go binary like so: `GO_OPENSSL_VERSION_OVERRIDE=libcrypto.so.3`.

**NOTE**: This option is for testing / development only and is not explicitly supported.

### Forcing FIPS mode at runtime

Typically the binary will only execute in FIPS mode and call into OpenSSL if the RHEL host is in FIPS mode. If you would like to force the process to execute in FIPS mode you can set the environment variable `GOLANG_FIPS=1`. Note also that if you are using OpenSSL 3 then you will also have to set `OPENSSL_FORCE_FIPS_MODE=1` as well.

### Strict FIPS runtime protection

If you have chosen to compile your binary with the additional strict FIPS runtime checks, then at startup the process will look for conditions that are incompatible with correct operation in a FIPS environment. Specifically, during initialization, the process will check if the host is in FIPS mode or FIPS mode has been specifically requested at runtime. If either of those are true, but the process was unable to successfully find a compatible OpenSSL library with the proper FIPS module (or `-tags no_openssl` was used during compilation), the process will crash via panic. This gives operators increased confidence that the binaries they are running in their FIPS environments are built correctly and are not falling back to non-FIPS validated cryptography.

## Validating a Compiled Binary

Aside from the strict FIPS runtime checks, another check to ensure that your binaries are compiled correctly is via static analysis of the binary itself. The OpenShift organization has an open source payload checker to ensure OpenShift binaries are compiled correctly. This code is rather specific to OpenShift and scans container images, however the code and Go specific analysis can be beneficial.

## CentOS / OpenSSL Version Considerations

Different versions of CentOS will have different versions of OpenSSL. Different versions of OpenSSL may differ with regards to accepted algorithms, etc… Please consider this during any testing or deployment.

## Native FIPS Mode (Host-Auto)

Starting with Go 1.24, the upstream Go standard library includes its own FIPS 140-3 module (`crypto/internal/fips140`) that can be certified independently of OpenSSL. This fork supports using that native FIPS module as an alternative to the OpenSSL backend, with a host-auto detection mode that activates FIPS at runtime only when the host operating system is booted in FIPS mode.

### Overview

When building with native FIPS support, the resulting binary embeds a certified snapshot of Go's FIPS 140-3 module and sets `GODEBUG=fips140=auto` as its compiled-in default, deferring the FIPS activation decision to runtime. At startup the binary checks whether the host is in FIPS mode by reading `/proc/sys/crypto/fips_enabled`. If the host is in FIPS mode, the native FIPS module activates and enforces FIPS-approved algorithms. If the host is not in FIPS mode, the binary runs with standard cryptography. As with all `GODEBUG` settings, the compiled-in default can be overridden at runtime by setting the `GODEBUG` environment variable explicitly — runtime settings always take precedence.

### Building with Native FIPS Auto Mode

To build a binary that uses Go's native FIPS module with host-auto detection, you need two things:

1. **Disable the OpenSSL backend** with `-tags=no_openssl`
2. **Set the FIPS GODEBUG to auto** via a `//go:debug` directive or `go.mod`

#### Using a `//go:debug` directive

Add the following directive to your `main` package source file:

```go
//go:debug fips140=auto

package main
```

Then build with:

```
go build -tags=no_openssl
```

#### Using `go.mod`

Add the `godebug` directive to your `go.mod`:

```
module example.com/myapp

go 1.24

godebug fips140=auto
```

Then build with:

```
go build -tags=no_openssl
```

### GODEBUG fips140 Values

The `GODEBUG=fips140` setting controls native FIPS mode. The following values are supported:

| Value   | Behavior |
|---------|----------|
| `auto`  | Check host FIPS mode at startup; activate FIPS if the host is in FIPS mode, otherwise run without FIPS. |
| `on`    | Always activate FIPS mode regardless of host configuration. |
| `only`  | Activate FIPS mode and restrict all cryptographic operations to FIPS-approved algorithms only. Non-approved algorithms will return errors. |
| `off`   | Disable FIPS mode (default when `GOFIPS140` is not set). |

The `auto` value is resolved at process startup: if `/proc/sys/crypto/fips_enabled` contains `1`, it resolves to `on`; otherwise it resolves to `off`. This resolution happens once and the result is cached for the lifetime of the process.

> **Note:** The `//go:debug` directive and `go.mod` `godebug` setting establish the *default* value of `GODEBUG=fips140` compiled into the binary. These defaults can always be overridden at runtime by setting the `GODEBUG` environment variable directly — for example, `GODEBUG=fips140=off` or `GODEBUG=fips140=` (empty) will disable FIPS mode regardless of what was compiled in. Runtime settings always take precedence over compiled-in defaults.

### GOFIPS140 Build Variable

The `GOFIPS140` environment variable controls which version of the FIPS 140-3 module snapshot is embedded into the binary at build time.

| Value     | Behavior |
|-----------|----------|
| `off`     | Do not embed a FIPS module snapshot. |
| `latest`  | Use the live source from `src/crypto/internal/fips140`. |
| `v1.0.0`  | Use the v1.0.0 certified snapshot (default when `GOFIPS140` is unset). |
| `inprocess` / `certified` | Version aliases resolved from files in `lib/fips140/`. |

When `GOFIPS140` is set to anything other than `off`, the build system defaults `GODEBUG=fips140=on` for the resulting binary. To use auto mode, you must override this default with `fips140=auto` via a `//go:debug` directive or `go.mod` `godebug` setting as described above.

### Mutual Exclusivity: OpenSSL and Native FIPS

The OpenSSL backend and the native FIPS module are **mutually exclusive**. A binary must use one or the other, never both simultaneously. The runtime enforces this: if the OpenSSL backend detects that `GODEBUG=fips140` is also set (to any non-empty value), it will panic at startup with the following message:

```
opensslcrypto: GOLANG_FIPS and GODEBUG=fips140 are mutually exclusive;
use GOLANG_FIPS=1 for OpenSSL FIPS or GODEBUG=fips140=auto with -tags=no_openssl for native FIPS
```

To choose between the two FIPS implementations:

| Implementation | Build Tags | Runtime Activation |
|----------------|------------|--------------------|
| **OpenSSL FIPS** | *(default, no special tags)* | `GOLANG_FIPS=1` or host FIPS mode detected automatically |
| **Native FIPS** | `-tags=no_openssl` | `GODEBUG=fips140=auto` (or `on` / `only`) |

In summary:

- **OpenSSL mode** (default): The binary links against the system's OpenSSL library at runtime. FIPS activation is controlled by `GOLANG_FIPS` or host FIPS detection. Do **not** set `GODEBUG=fips140`.
- **Native mode** (`-tags=no_openssl`): The binary uses Go's built-in FIPS 140-3 module. FIPS activation is controlled by `GODEBUG=fips140`. Do **not** set `GOLANG_FIPS`.

### Testing Native FIPS Without a FIPS-Enabled Host

For testing the native FIPS auto mode on a host that is not booted in FIPS mode, the environment variable `GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1` can be set. This causes `fips140=auto` to resolve as if the host were in FIPS mode. This override only affects the native FIPS module; it does not affect the OpenSSL backend's host FIPS detection.

### Example Configurations

#### Always use native FIPS (no host detection)

```
go build -tags=no_openssl
```

With `//go:debug fips140=on` or `GODEBUG=fips140=on` at runtime. The binary always runs in FIPS mode.

#### Native FIPS only when the host requires it

```
go build -tags=no_openssl
```

With `//go:debug fips140=auto` in the source or `godebug fips140=auto` in `go.mod`. FIPS activates only on hosts booted in FIPS mode.

#### OpenSSL FIPS (existing behavior)

```
go build
```

No special tags needed. The binary links against OpenSSL and activates FIPS when the host is in FIPS mode or `GOLANG_FIPS=1` is set.

#### No FIPS at all

```
GOFIPS140=off go build -tags=no_openssl
```

The binary uses upstream Go cryptography with no FIPS module embedded and no OpenSSL linkage.

## Migration to Upstream FIPS certified cryptography

We intend to sunset our downstream OpenSSL based solution in favor of pure upstream Go cryptography once the upstream sources are FIPS certified. The maintainers of this repository are directly involved in the upstream effort for FIPS certification of the cryptographic packages in the Go standard library, and are committed to continuing this work and ensuring we deliver on our upstream first approach.

## Further Reading

- https://access.redhat.com/compliance/fips
- https://github.com/openshift/check-payload
- https://github.com/golang-fips/go
- https://developers.redhat.com/articles/2025/03/10/benefits-native-fips-support-go-124
- https://developers.redhat.com/articles/2025/01/23/fips-mode-red-hat-go-toolset
- https://developers.redhat.com/articles/2024/02/27/handling-fips-mode-upstream-projects-rhel
- https://developers.redhat.com/articles/2023/12/14/how-improve-go-fips-test-coverage-packit
- https://developers.redhat.com/articles/2022/05/31/your-go-application-fips-compliant
- https://developers.redhat.com/blog/2019/06/24/go-and-fips-140-2-on-red-hat-enterprise-linux
