# Transitioning from OpenSSL to native Go FIPS

This guide is for applications built with the golang-fips Go toolchain, including
OpenShift components and applications deployed on RHEL. It compares the OpenSSL
backend on **`go1.25-fips-release`** with the **native-only Go 1.27 toolchain on
`main`**. Here, “native” means the Go Cryptographic Module implemented by
`crypto/internal/fips140`, not BoringCrypto or a Go wrapper around OpenSSL.

Go 1.26 was an intermediate release with both backends; its backend-selection
instructions are not the instructions for current `main`. In particular,
`-tags=no_openssl` is no longer needed to select native cryptography. These
instructions describe this modified toolchain, **not an unmodified upstream Go
installation**. Toolchain behavior was checked against `main` at `c427fcd6aa`
(Go 1.27.3). Certification information below was checked on October 28, 2026.

## Quick migration checklist

1. Rebuild with the native-only toolchain.
2. Remove OpenSSL-specific FIPS environment settings from the application's
   launch configuration. Replace any deliberate `GOLANG_FIPS=1` override with
   `GODEBUG=fips140=on`; otherwise let host-auto detection do its job.
3. Keep the default certified module unless your requirements explicitly permit
   an in-process or development module. Record the exact `GOFIPS140` value shown
   by `go version -m ./myapp` alongside the Go version in your build records.
4. You **can now use `CGO_ENABLED=0`** if your application does not otherwise need
   cgo. Native FIPS works with cgo enabled or disabled; it does not require a C
   compiler, `libcrypto.so`, or an OpenSSL provider.
5. Test on FIPS-enabled and non-FIPS hosts, check the application's actual FIPS
   state, and retest TLS interoperability and algorithm-dependent code paths.
   See [Verifying runtime FIPS state](#verifying-runtime-fips-state) for the
   runtime APIs.
6. Update [payload scanners](#payload-scanning-with-check-payload) and compliance
   evidence to recognize native FIPS.
   The absence of OpenSSL linkage is no longer evidence of a non-FIPS build.

A normal build is sufficient; no cgo setting is required for native FIPS:

```sh
go build -o myapp .
./myapp
```

With this toolchain's defaults, that executable contains the **v1.0.0 certified
module** and defaults to **`fips140=auto`**: FIPS mode on a FIPS host, normal mode
on a non-FIPS host. Building on a non-FIPS machine does not prevent the executable
from entering FIPS mode when deployed on a FIPS-enabled RHEL host.

## What changes, and what does not

| Area | Go 1.25 OpenSSL baseline | Current native-only toolchain |
| --- | --- | --- |
| Implementation of approved operations | System OpenSSL FIPS module through cgo | Go Cryptographic Module compiled into the executable |
| cgo required for FIPS | Yes | No; cgo remains available for unrelated application dependencies |
| Runtime crypto dependency | Compatible `libcrypto.so` and configured FIPS provider/module | No OpenSSL dependency for Go standard-library cryptography |
| Host FIPS detection | `/proc/sys/crypto/fips_enabled` | **Nothing has changed** in the host detection mechanism |
| Force FIPS on | `GOLANG_FIPS=1` (and, for the documented RHEL OpenSSL 3 setup, `OPENSSL_FORCE_FIPS_MODE=1`) | `GODEBUG=fips140=on` |
| Host-dependent activation | Automatic unless overridden | Compiled-in `GODEBUG=fips140=auto`, unless overridden |
| Choose module version | Determined by the OpenSSL installed at runtime | `GOFIPS140` at application build time |
| Pure-Go cross-compilation with FIPS | Not possible through the cgo/OpenSSL backend | Supported for supported target platforms; certification scope still matters |
| Crypto updates | OpenSSL updates can change the loaded module | Rebuild and redeploy to update the embedded module |

## Build-time module selection: the default is v1.0.0

There are two separate decisions:

- **`GOFIPS140` at build time** selects the module source linked into the binary.
- **`GODEBUG=fips140=...` at startup** controls whether that module operates in
  FIPS mode. It does not select or download a different module.

The downstream toolchain build defaults `GOFIPS140` to `certified`, unless the
toolchain builder overrides it. In the Go 1.27.3 sources used here,
`lib/fips140/certified.txt` resolves to **`v1.0.0-c2097c7c`**, the archive for the
certified **v1.0.0** module. `v1.0.0` is also an alias for that exact archive.
Thus ordinary application builds default to v1.0.0, **not** the newer crypto
implementation in the Go 1.27 source tree.

| `GOFIPS140` value | Source used | Default startup mode in this toolchain |
| --- | --- | --- |
| `certified` (toolchain default) | Bundled snapshot named by `certified.txt`; currently v1.0.0 | `auto` |
| `v1.0.0` | Certified v1.0.0 snapshot | `auto` |
| `inprocess` | Bundled snapshot named by `inprocess.txt`; currently v1.26.0 | `auto` |
| `v1.26.0` | Explicit v1.26.0 snapshot | `auto` |
| `latest` | Live `src/crypto/internal/fips140` in this toolchain | `auto` |
| `off` | Live source, without selecting a frozen snapshot | FIPS off unless separately enabled |

`off` does **not** remove all native crypto or make runtime FIPS activation
impossible. For example, `GOFIPS140=off` followed by `GODEBUG=fips140=on` runs the
live implementation in FIPS mode, not the certified snapshot.

Examples (run in the application's source directory):

```sh
# Explicitly retain the current certified default.
GOFIPS140=v1.0.0 go build -o myapp .

# Use the module undergoing CMVP validation.
GOFIPS140=inprocess go build -o myapp-inprocess .

# Pin that module instead of using an alias.
GOFIPS140=v1.26.0 go build -o myapp-v126 .

# Use the current toolchain's live module implementation.
GOFIPS140=latest go build -o myapp-latest .
```

The same selection applies to `go install` and `go test`. Selection uses snapshots
bundled under `$GOROOT/lib/fips140`; it is not a `go get` dependency to add to
`go.mod`. Snapshot extraction needs a writable module cache, which matters for
restricted or disconnected build environments. The bundled snapshot does not
need to be fetched from the network.

Inspect the installed defaults and aliases rather than assuming all toolchain
packages have identical settings:

```sh
go env GOFIPS140
cat "$(go env GOROOT)/lib/fips140/certified.txt"
cat "$(go env GOROOT)/lib/fips140/inprocess.txt"
go version -m ./myapp
```

Application environment settings, including `go env -w GOFIPS140=...`, can
override the toolchain default. Future toolchain updates can change alias targets.
Pin an exact bundled archive identifier when reproducibility requires it, and
retain the resolved `GOFIPS140` build setting in your build records.

**Upstream difference:** stock Go defaults to `GOFIPS140=off`; a non-`off` value
normally compiles in `fips140=on`. This fork instead defaults to `certified` and
compiles in `fips140=auto` for non-`off` selections. Do not assume that switching
to an upstream binary preserves these downstream defaults or host-auto behavior.

## Runtime activation and host-auto mode

### Host detection: nothing has changed

Comparing the Go 1.25 backend's `hostFIPSModeEnabled` with the current native
`hostfips.checkHostFIPS` confirms the same operating-system check:

- Read `/proc/sys/crypto/fips_enabled`.
- A nonempty value whose first byte is `1` means the host is in FIPS mode.
- A missing file means the host is not in FIPS mode.
- Other read failures print an error and terminate the process with exit status 1.

There is no new requirement to enable a separate host switch for native Go.
Normal RHEL host FIPS configuration remains necessary. The change is **which
module the process activates**, not how it recognizes the host configuration.
Explicit environment overrides are different, as described below.

With `auto`, this check happens during crypto initialization and is cached for
the process lifetime. A running process does not switch mode when an environment
variable or host setting changes; restart it after changing configuration.

In containers, the check reads the path visible **inside that container**. Verify
it in the actual deployment: a masked or absent path makes `auto` resolve to off;
a permission error terminates the process. Do not assume that an image's RHEL
label, its installed OpenSSL, or a FIPS-enabled build machine determines the
runtime result. On systems without this Linux interface, `auto` resolves to off.

### Supported operating modes

| Startup setting | Behavior |
| --- | --- |
| `GODEBUG=fips140=auto` | Enable FIPS if the host check is true; otherwise disable it. This is the downstream default for FIPS module builds. |
| `GODEBUG=fips140=on` | Enable FIPS regardless of host mode. This is the replacement for deliberately forcing the old backend on. |
| `GODEBUG=fips140=off` | Disable native FIPS, even on a FIPS host, unless strict runtime protection rejects this configuration. |
| `GODEBUG=fips140=only` | Enable FIPS and additionally reject non-approved operations with errors or panics where implemented. **Testing/assessment only, not recommended for production.** |

`on` (including `auto` resolving to on) enables the module integrity check,
algorithm self-tests, key-generation consistency tests, FIPS random generation,
and FIPS TLS policy. It does not promise that every cryptographic operation in
the process is approved or inside the validated module.

The `GODEBUG` **runtime environment takes precedence** over compiled defaults.
An unrelated setting such as `GODEBUG=gctrace=1` does not erase the default
`fips140=auto`; an explicit `fips140=off` or empty `fips140=` does override it.
Preserve other required `GODEBUG` entries when changing a launch configuration.

To establish an application-specific default instead of relying on the toolchain,
use a main-package directive before `package main`:

```go
//go:debug fips140=auto

package main
```

Or add this to the main module's `go.mod`:

```text
godebug fips140=auto
```

Use `fips140=on` instead if the application should always enable FIPS. Both forms
set defaults, not an immutable policy; runtime `GODEBUG` can still override them.
Setting `GODEBUG=fips140=on` only for the `go build` command does not, by itself,
set the resulting application's compiled-in default.

### Replacing legacy overrides

```sh
# Old OpenSSL application, shown only for comparison:
GOLANG_FIPS=1 OPENSSL_FORCE_FIPS_MODE=1 ./old-myapp

# Native application: force FIPS without changing host configuration.
GODEBUG=fips140=on ./myapp

# Native application: follow the host (already the normal compiled default).
GODEBUG=fips140=auto ./myapp
```

`GOLANG_FIPS`, `OPENSSL_FORCE_FIPS_MODE`, and `GO_OPENSSL_VERSION_OVERRIDE` no
longer control Go's native backend. In particular, **leaving `GOLANG_FIPS=1` in a
container spec does not force native FIPS on**, and `GOLANG_FIPS=0` no longer opts
it out. Remove or migrate these settings for the Go process. Other processes or
C libraries in the same container may still need their own OpenSSL configuration.

### Testing host-auto activation

`GODEBUG=fips140=on` is sufficient to test explicitly enabled FIPS. To test the
**host-auto activation path** on a non-FIPS host instead, use the test override:

```sh
GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GODEBUG=fips140=auto ./myapp
```

This makes the host check used by `auto` behave as if FIPS were enabled. It also
allows testing the strict guard's rejection path without a real FIPS host:

```sh
# For a binary built with strictfipsruntime, expect exit status 1.
GOLANG_NATIVE_HOSTFIPS_OVERRIDE=1 GODEBUG=fips140=off ./myapp
```

The override is for tests only. It does not put the host into FIPS mode and is
not evidence of a compliant operating environment. Use a real FIPS-enabled host
for deployment acceptance tests.

### Strict runtime protection

The native toolchain retains the optional `strictfipsruntime` experiment and also
supports the corresponding build tag:

```sh
GOEXPERIMENT=strictfipsruntime go build -o myapp .
# Alternative:
go build -tags=strictfipsruntime -o myapp .
```

The old guard checked that the OpenSSL backend was available on a FIPS host.
The new guard checks that native FIPS is enabled. If the host requires FIPS but
the effective setting disables it (for example, `GODEBUG=fips140=off`), startup
exits with status 1 and:

```text
Host FIPS mode is enabled, but the required GODEBUG=fips140 module is disabled
```

This guard is **not** `fips140=only`: it checks startup activation, not every
algorithm invocation. It also does not prove that a certified module was selected,
that the deployment matches the Security Policy, or that third-party crypto is
approved. Keep checking the module version and build records.

## Algorithm behavior: audit operations, not just the FIPS flag

Do not treat OpenSSL's provider restrictions and Go's native FIPS mode as
identical algorithm allowlists. Algorithms, key sizes, random generation,
protocol policies, and failure behavior must be tested against the selected
module and the application APIs that use it.

### MD5 and other non-approved operations

**Native `fips140=on` does not universally disable non-approved algorithms.**
For example, `crypto/md5.Sum` still computes MD5 with `on`, or with `auto` on a
FIPS host. MD5 is outside the validated module and is not thereby approved for
cryptographic protection. In `only` mode, MD5's `Write` returns an error, and
`Sum`/`md5.Sum` panic. This distinction matters for legacy checksums and code
that previously assumed “FIPS mode means MD5 must fail.”

There is an important baseline detail: on `go1.25-fips-release`, `crypto/md5`
itself is left as the upstream pure-Go implementation, rather than redirected
to OpenSSL. Thus it is **not accurate to claim that every MD5 call failed under
the old backend but succeeds under native FIPS**. An MD5-dependent operation
implemented through OpenSSL (for example, an HMAC or signature operation) may
instead fail according to its provider's policy. An OpenSSL failure is not a
portable specification of native Go behavior.

Similarly, do not infer that all uses of SHA-1, DSA, or a particular RSA operation
are permitted or forbidden merely from the algorithm name. API, operation,
parameters, and protocol context matter. Check every returned error; APIs without
an error result may panic when an operation is rejected. Third-party Go crypto
and crypto invoked through C libraries are not automatically brought inside the
Go module's validation boundary.

Use `GODEBUG=fips140=only` in an additional test run to find potentially
non-approved operations. Upstream documents this as a **best-effort debugging
mode**, with possible false positives and false negatives, not a production
compliance guarantee. Do not deploy it as a substitute for a crypto usage audit.

### Removed ECDSA `HashSign` and `HashVerify` APIs

The OpenSSL toolchain added four nonstandard APIs to `crypto/ecdsa`:
`HashSign`, `HashSignASN1`, `HashVerify`, and `HashVerifyASN1`. These combined
hashing and signing/verification so OpenSSL could perform the combined operation
within its FIPS module. **The native-only toolchain no longer implements these
APIs**, and applications using them must change their source code.

That OpenSSL-specific workaround is not needed for native FIPS. Hash the message
with an appropriate standard-library hash, then use the standard ECDSA APIs:

| Removed API | Replacement after hashing the message |
| --- | --- |
| `ecdsa.HashSign` | `ecdsa.Sign` for an existing `(r, s)` signature format |
| `ecdsa.HashVerify` | `ecdsa.Verify` for an existing `(r, s)` signature format |
| `ecdsa.HashSignASN1` | `ecdsa.SignASN1` |
| `ecdsa.HashVerifyASN1` | `ecdsa.VerifyASN1` |

The removed helpers accepted the **original message**. The standard APIs above
accept its **digest**: hash the message once and pass that digest, not the raw
message or a double-hashed value. For example, using SHA-256 and ASN.1 signatures:

```go
package example

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

func signAndVerify(priv *ecdsa.PrivateKey, message []byte) (bool, error) {
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signature), nil
}
```

Use an approved curve, hash, and parameters appropriate for your application and
the selected module's Security Policy. For new code, prefer the ASN.1 APIs;
retain `(r, s)` APIs where the existing signature format requires them.

### TLS and randomness

Native FIPS automatically restricts `crypto/tls` protocol versions, cipher
suites, signature algorithms, and key exchanges to its FIPS policy. No legacy
`crypto/tls/fipsonly` import is needed for this activation. Remove reliance on
OpenSSL/BoringCrypto-specific build tags and imports when migrating.

The native module supports algorithms that the old backend's TLS policy did
not allow, including Ed25519 and the ML-KEM hybrid key exchange. Conversely, it
still rejects non-approved TLS choices. Retest explicit `tls.Config` settings,
certificates, and older peers rather than expecting identical negotiation.
ML-KEM (key establishment) is different from ML-DSA (signatures): **v1.0.0
includes ML-KEM even though it does not include ML-DSA**.

`crypto/rand.Reader` uses the module's FIPS DRBG in FIPS mode, rather than
OpenSSL's random generator. Native FIPS also performs self-tests and key
consistency tests that can change startup and key-generation costs. Benchmark
the actual application if it is sensitive to these costs. Selecting v1.26.0
also changes the module's credited entropy source to its validated CPU-jitter
source; consult that module's documentation rather than applying v1.0.0 entropy
assumptions to it.

## ML-DSA and choosing a newer module

The **v1.0.0 certified module does not contain ML-DSA**. Updating the surrounding
toolchain alone does not add ML-DSA to that frozen module.

The current toolchain does **not** supply an out-of-module fallback. When built
against v1.0.0, ML-DSA is unavailable **regardless of the runtime FIPS setting**:

| Build selection | FIPS disabled | FIPS enabled (`on`, `only`, or `auto` on a FIPS host) |
| --- | --- | --- |
| v1.0.0 / current `certified` default | ML-DSA unavailable | ML-DSA unavailable |
| v1.26.0 / current `inprocess` | ML-DSA available | ML-DSA available through the selected module |
| `latest` | ML-DSA available | ML-DSA available through the live module implementation |

For v1.0.0, key generation, private/public key import, and verification return:

```text
mldsa: unavailable in FIPS 140-3 Go Cryptographic Module v1.0.0
```

No valid ML-DSA keys can be constructed in this configuration, so signing is
unavailable too; the stub key methods panic if called. Setting
`GODEBUG=fips140=off` does not enable ML-DSA in a v1.0.0 build.

To use ML-DSA with native FIPS enabled, rebuild using `GOFIPS140=inprocess`,
`GOFIPS140=v1.26.0`, or `GOFIPS140=latest`, as shown above. Changing only
`GODEBUG` cannot add algorithms to v1.0.0. **Availability is not certification:**
v1.26.0 is in process, and the live `latest` source is not the certified v1.0.0
snapshot. Do not claim certificate #5247 covers ML-DSA in either build. Where a
completed CMVP validation is mandatory, coordinate the algorithm/module choice
with your product's compliance owner instead of disabling FIPS to bypass errors.

For an application that does not need a frozen FIPS module, rebuilding with
`GOFIPS140=off` also makes ML-DSA available through the live implementation. That
is a build-time change, not a runtime workaround for the certified module.

## RHEL operating environments and certification scope

The public records distinguish a **completed module validation**, **algorithm
testing**, and **in-process module validation**. They are not interchangeable.
For RHEL, the named tested operating environments are:

| Module | Validation status | Named RHEL environments in public testing records |
| --- | --- | --- |
| v1.0.0 | FIPS 140-3 Level 1, active CMVP certificate **#5247**, initially validated April 27, 2026 | **RHEL 9** on Intel Xeon Silver 4410Y (`amd64`), Ampere Altra Q64-22 (`arm64`), IBM z16 (`s390x`, PR/SM), and IBM Power10 (`ppc64le`, PowerVM), with and without the listed processor acceleration |
| v1.26.0 | **In process**, not yet CMVP-certified; CAVP algorithm certificate **A8028** | **RHEL 9 and RHEL 10** on Intel Xeon Silver 4410Y and Ampere Altra Q64-22; **RHEL 9** on IBM z16 (PR/SM) and IBM Power10 (PowerVM), with and without the listed acceleration |

Sources: the [#5247 Security Policy, section 2.2][security-policy] (especially
Table 3) and [A8028 operating environments][a8028]. The live [CMVP in-process
list][mip] lists the Go Cryptographic Module under Geomys; on the verification
date its status was **Comment Resolution - Lab (October 22, 2026)**. The Go
documentation's older “Pending Review” date should not be read as a current
progress update.

These rows describe **named tested environments**, not an unconditional promise
for every RHEL installation or architecture. For example, do not extend the
v1.26.0 RHEL 10 x86/Arm testing to RHEL 10 on IBM platforms without evidence.
RHEL 8 is not a named RHEL tested environment in these records, and RHEL 10 is
not a named RHEL tested environment for v1.0.0. The #5247 Security Policy also
lists broader **vendor-affirmed Linux operating environments** (Table 4), which
may be relevant to other RHEL deployments. Assess the exact kernel, architecture,
hardware, hypervisor, entropy requirements, and permitted portability claims;
“not separately tested” is not the same as “cannot execute.”

For RHEL CoreOS/OpenShift, UBI containers, and other derived environments, map
the actual deployment to the applicable Security Policy and product compliance
requirements. Do not automatically equate those product names with a named RHEL
tested environment, or equate an upstream module certificate with Red Hat
product certification/support. The repository itself is not an official Red Hat
product. Check [Red Hat's certification information][redhat-fips] for the
supported product and release in question.

The certificate's current Security Policy also covers a v1.0.1 revision, but
that does not mean this toolchain bundles or defaults to it. Use the installed
alias files and exact archive identifier for build evidence, and recheck the
public validation records when making a release decision.

## Cross-compilation, static binaries, and containers

Native FIPS removes the backend's cgo/OpenSSL obstacle to normal Go
cross-compilation:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOFIPS140=v1.0.0 \
  go build -o myapp-linux-arm64 .
```

No target C compiler or target OpenSSL installation is required for this pure-Go
build. The resulting binary checks the **target host** at execution, not the
build host. Native FIPS also permits standalone pure-Go executables without
shipping OpenSSL into the runtime image. Applications that need cgo for database
drivers, system integration, or other C dependencies still have those build and
runtime dependencies; there is no need to disable cgo just to use native FIPS.

Technical cross-build support does not extend the module's validation scope.
Check the selected module's target support and Security Policy. In particular,
the upstream Go 1.27 native mode documents exclusions for OpenBSD, AIX, Wasm, and
32-bit Windows; “pure Go” is not a claim of FIPS support on every Go target.
Do not confuse **`CGO_ENABLED=0`** with **`-tags=purego`**: the latter changes
crypto implementations and is incompatible with the normal native FIPS build.
`GOEXPERIMENT=boringcrypto` is also incompatible with native FIPS selection.

Removing OpenSSL does not remove unrelated container requirements such as CA
trust roots, application data, host FIPS configuration visibility, or access to
the platform randomness facilities required by the selected module.

## Payload scanning with check-payload

Upstream `openshift/check-payload` **already recognizes native Go FIPS** through
its [native implementation][payload-native].

For crypto-using Go **1.27 and newer**, native inspection requires embedded
`DefaultGODEBUG` or `GODEBUG` containing a comma-separated entry
`fips140=auto`, `fips140=on`, or `fips140=only`, plus an accepted `GOFIPS140`
setting. Go 1.26 takes this path only with an accepted embedded mode; older Go
uses legacy checks. This toolchain's ordinary certified build records
`DefaultGODEBUG=fips140=auto` and `GOFIPS140=v1.0.0-c2097c7c`. These are build
settings, **not the launch environment**. Acceptance of `only` does not make it
recommended for production.

Inspect `go version -m ./myapp` and scan the final image contents. For a local
unpacked image filesystem root, using your audited scanner configuration:

```sh
./check-payload --config ./config.toml scan local \
  --path ./unpacked-root --fail-on-warnings --verbose
```

**A pass is not certification or proof of runtime activation.** The
[shipped Go policy][payload-config] sets a minimum `v1.0.0`, not an exact
certified-module allowlist. Walk scans use the first matching Go binary-source
minimum; the numeric comparison ignores archive suffixes. Resolved
`v1.0.0-c2097c7c` and in-process `v1.26.0` both pass. Literal `latest` fails with
that minimum, but any nonempty, non-`off` value passes when no minimum is set.
RPM scanning does not initialize the same minimum; do not assume equivalent
version enforcement across scan modes. Do not empty the config to bypass a
failure: that also removes OS/module policy.

At `check-payload` revision `75c94ce419deac761ac4feaf4c8d8a1a193fab80`,
**`certified_artifact_max_version` is not enforced for native Go**: a local scan
accepted in-process v1.26.0 even with maximum v1.0.0.
The [binary-source module phase][payload-module] skips separate artifact checks;
it does not verify an embedded module hash, exact archive suffix, or certificate.
Keep an independent exact-module/build-record policy and assess the module's
Security Policy and deployment scope. Extending upstream to enforce maximum
bounds or an exact archive allowlist is a recommendation, not a current feature.

Finally, verify runtime state in the actual deployment as described below.
Static scanning does not execute the program, observe runtime `GODEBUG`, evaluate
host FIPS visibility, or establish self-test success or exclusive approved-crypto
use. A known-built certified probe reported FIPS off and on under the respective
runtime overrides while retaining the same accepted embedded metadata.

## Verifying runtime FIPS state

Expose or log the public API's state during application startup; do not import
the internal implementation package:

```go
package main

import (
	"crypto/fips140"
	"fmt"
)

func main() {
	fmt.Printf("native FIPS enabled=%t module=%s\n",
		fips140.Enabled(), fips140.Version())
}
```

`Enabled()` reports the **effective process mode**, not just host configuration.
`Version()` reports the module's formal version, such as `v1.0.0`; use
`go version -m ./myapp` (or `runtime/debug.ReadBuildInfo`) for the exact archive
identifier, including suffixes. Neither an embedded snapshot nor `Enabled()`
alone proves the whole application complies with FIPS requirements.

## Sources and implementation references

The behavior above was checked against:

- [OpenSSL baseline patches on `go1.25-fips-release`][baseline], especially
  `000-fips.patch` and `002-fix-std-crypto.patch` (activation and host detection).
- [Native host-auto and default-module patch](../patches/001-host-fips-auto.patch).
- [Removal of the downstream ML-DSA fallback][mldsa-removal] and the
  [upstream v1.0.0 ML-DSA stubs][mldsa-stubs].
- [Native strict runtime guard](../patches/004-strictfipsruntime.patch).
- [Upstream FIPS documentation][go-fips], [Go 1.27 module-selection code][selection],
  [bundled aliases][aliases], [`crypto/md5` implementation][md5-source], and
  [standard ECDSA signing/verification][ecdsa-source].
- [CMVP certificate #5247][certificate], its [Security Policy][security-policy],
  the [CMVP in-process list][mip], and [CAVP certificate A8028][a8028].

[baseline]: https://github.com/golang-fips/go/tree/go1.25-fips-release/patches
[go-fips]: https://go.dev/doc/security/fips140
[selection]: https://github.com/golang/go/blob/go1.27.3/src/cmd/go/internal/fips140/fips140.go
[aliases]: https://github.com/golang/go/tree/go1.27.3/lib/fips140
[md5-source]: https://github.com/golang/go/blob/go1.27.3/src/crypto/md5/md5.go
[mldsa-removal]: https://github.com/golang-fips/go/commit/8197729646a25b727f5f554ed9386b3d5e7f1f26
[mldsa-stubs]: https://github.com/golang/go/blob/go1.27.3/src/crypto/mldsa/mldsa_fips140v1.0.go
[ecdsa-source]: https://github.com/golang/go/blob/go1.27.3/src/crypto/ecdsa/ecdsa.go
[certificate]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247
[security-policy]: https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf
[mip]: https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list
[a8028]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=40638
[redhat-fips]: https://access.redhat.com/compliance/fips
[payload-native]: https://github.com/openshift/check-payload/blob/75c94ce419deac761ac4feaf4c8d8a1a193fab80/internal/validations/validations.go#L143-L408
[payload-config]: https://github.com/openshift/check-payload/blob/75c94ce419deac761ac4feaf4c8d8a1a193fab80/config.toml#L60-L66
[payload-module]: https://github.com/openshift/check-payload/blob/75c94ce419deac761ac4feaf4c8d8a1a193fab80/internal/validations/validations_host_crypto.go#L105-L115
