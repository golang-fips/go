// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

package boring

// #include "goboringcrypto.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"crypto/internal/boring/fipstls"
	"crypto/internal/boring/sig"
	"math/big"
	"os"
	"runtime"
)

const (
	fipsOn  = C.int(1)
	fipsOff = C.int(0)
)

// Enabled controls whether FIPS crypto is enabled.
var enabled = false

func init() {
	// Check if we can `dlopen` OpenSSL
	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Check to see if the system is running in FIPS mode, if so
	// enable "boring" mode to call into OpenSSL for FIPS compliance.
	if fipsModeEnabled() {
		enableBoringFIPSMode()
	}
	sig.BoringCrypto()
}

func enableBoringFIPSMode() {
	enabled = true

	if C._goboringcrypto_OPENSSL_thread_setup() != 1 {
		panic("boringcrypto: OpenSSL thread setup failed")
	}
	fipstls.Force()
}

func fipsModeEnabled() bool {
	return os.Getenv("GOLANG_FIPS") == "1" ||
		C._goboringcrypto_FIPS_mode() == fipsOn
}

// Unreachable marks code that should be unreachable
// when BoringCrypto is in use. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if Enabled() {
		panic("boringcrypto: invalid code execution")
	}
}

// provided by runtime to avoid os import
func runtime_arg0() string

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

// UnreachableExceptTests marks code that should be unreachable
// when BoringCrypto is in use. It panics.
func UnreachableExceptTests() {
	name := runtime_arg0()
	// If BoringCrypto ran on Windows we'd need to allow _test.exe and .test.exe as well.
	if Enabled() && !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
		println("boringcrypto: unexpected code execution in", name)
		panic("boringcrypto: invalid code execution")
	}
}

type fail string

func (e fail) Error() string { return "boringcrypto: " + string(e) + " failed" }

func bigToBN(x *big.Int) *C.GO_BIGNUM {
	raw := x.Bytes()
	return C._goboringcrypto_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
}

func bnToBig(bn *C.GO_BIGNUM) *big.Int {
	raw := make([]byte, C._goboringcrypto_BN_num_bytes(bn))
	n := C._goboringcrypto_BN_bn2bin(bn, base(raw))
	return new(big.Int).SetBytes(raw[:n])
}

func bigToBn(bnp **C.GO_BIGNUM, b *big.Int) bool {
	if *bnp != nil {
		C._goboringcrypto_BN_free(*bnp)
		*bnp = nil
	}
	if b == nil {
		return true
	}
	raw := b.Bytes()
	bn := C._goboringcrypto_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
	if bn == nil {
		return false
	}
	*bnp = bn
	return true
}
