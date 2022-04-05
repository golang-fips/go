// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package boring

/*
#cgo LDFLAGS: -ldl

#include "goboringcrypto.h"
*/
import "C"
import (
	"crypto/internal/boring/fipstls"
	"crypto/internal/boring/sig"
	"errors"
	"math/big"
	"os"
	"runtime"
	"unsafe"
	"fmt"
)

const (
	fipsOn  = C.int(1)
	fipsOff = C.int(0)
)

const (
	OPENSSL_VERSION_1_1_0 = uint64(C.ulong(0x10100000))
	OPENSSL_VERSION_3_0_0 = uint64(C.ulong(0x30000000))
)

// Enabled controls whether FIPS crypto is enabled.
var enabled = false

// When this variable is true, the go crypto API will panic when a caller
// tries to use the API in a non-compliant manner.  When this is false, the
// go crytpo API will allow existing go crypto APIs to be used even
// if they aren't FIPS compliant.  However, all the unerlying crypto operations
// will still be done by OpenSSL.
var strictFIPS = false

func init() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Check if we can `dlopen` OpenSSL
	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		return
	}

	// Initialize the OpenSSL library.
	C._goboringcrypto_OPENSSL_setup()

	// Check to see if the system is running in FIPS mode, if so
	// enable "boring" mode to call into OpenSSL for FIPS compliance.
	if fipsModeEnabled() {
		enableBoringFIPSMode()
	}
	sig.BoringCrypto()
}

func openSSLVersion() uint64 {
	return uint64(C._goboringcrypto_internal_OPENSSL_VERSION_NUMBER())
}

func enableBoringFIPSMode() {
	enabled = true

	if C._goboringcrypto_OPENSSL_thread_setup() != 1 {
		panic("boringcrypto: OpenSSL thread setup failed")
	}
	fipstls.Force()
}

func fipsModeEnabled() bool {
	// Due to the way providers work in openssl 3, the FIPS methods are not
	// necessarily going to be available for us to load based on the GOLANG_FIPS
	// environment variable alone. For now, we must rely on the config to tell
	// us if the provider is configured and active.
	fipsConfigured := C._goboringcrypto_FIPS_mode() == fipsOn
	openSSLVersion := openSSLVersion()
	if openSSLVersion >= OPENSSL_VERSION_3_0_0 {
		if !fipsConfigured && os.Getenv("GOLANG_FIPS") == "1" {
			panic("GOLANG_FIPS=1 specified but OpenSSL FIPS provider is not configured")
		}
		return fipsConfigured

	} else {
		return os.Getenv("GOLANG_FIPS") == "1" || fipsConfigured
	}
}

var randstub bool

func RandStubbed() bool {
	return randstub
}

func StubOpenSSLRand() {
	if !randstub {
		randstub = true
		C._goboringcrypto_stub_openssl_rand()
	}
}

func RestoreOpenSSLRand() {
	if randstub {
		randstub = false
		C._goboringcrypto_restore_openssl_rand()
	}
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

func PanicIfStrictFIPS(msg string) {
	if os.Getenv("GOLANG_STRICT_FIPS") == "1" || strictFIPS {
		panic(msg)
	}
}

func NewOpenSSLError(msg string) error {
	var e C.ulong
	message := fmt.Sprintf("\n%v\nopenssl error(s):", msg)
	if openSSLVersion() >= OPENSSL_VERSION_3_0_0 {
		for {
			var buf [256]C.char
			var file, fnc, data *C.char
			var line, flags C.int
			e = C._goboringcrypto_internal_ERR_get_error_all(&file, &line, &fnc, &data, &flags)
			if e == 0 {
				break
			}

			C._goboringcrypto_internal_ERR_error_string_n(e,(*C.uchar)(unsafe.Pointer (&buf[0])), 256)
			message = fmt.Sprintf(
				"%v\nfile: %v\nline: %v\nfunction: %v\nflags: %v\nerror string: %s\n",
				message,C.GoString(file), line, C.GoString(fnc), flags, C.GoString(&(buf[0])))
		}
	} else {
		for {
			var buf [256]C.char
			e = C._goboringcrypto_internal_ERR_get_error()
			C._goboringcrypto_internal_ERR_error_string_n(e,(*C.uchar)(unsafe.Pointer (&buf[0])), 256)
			if e == 0 {
				break
			}
			message = fmt.Sprintf("%v: %v\n", message, buf)
		}
	}
	return errors.New(message)
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
