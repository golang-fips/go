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
// #cgo LDFLAGS: -lcrypto
import "C"
import (
	"crypto/internal/boring/sig"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
)

var available = false

const (
	fipsOn  = C.int(1)
	fipsOff = C.int(0)
)

func init() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Check to see if the system is running in FIPS mode, if so
	// enable "boring" mode to call into OpenSSL for FIPS compliance.
	if systemFIPSEnabled() {
		available = true

		if C._goboringcrypto_OPENSSL_thread_setup() != 1 {
			panic("boringcrypto: OpenSSL thread setup failed")
		}
		// By setting FIPS mode on, the power on self test will run.
		if C._goboringcrypto_FIPS_mode_set(fipsOn) != fipsOn {
			panic("boringcrypto: not in FIPS mode")
		}
		if C._goboringcrypto_FIPS_mode() != fipsOn {
			panic("boringcrypto: not in FIPS mode")
		}
	}
	sig.BoringCrypto()
}

func systemFIPSEnabled() bool {
	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	_, err := os.Stat("/etc/system-fips")
	if err != nil {
		return false
	}
	f, err = os.Open("/proc/sys/crypto/fips_enabled")
	if err != nil {
		return false
	}
	var b []byte
	b, err = ioutil.ReadAll(f)
	if err != nil {
		return false
	}
	return string(b) == "1"
}

// Unreachable marks code that should be unreachable
// when BoringCrypto is in use. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if available {
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
	if !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
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
