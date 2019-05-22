// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

package boring

// #include "goboringcrypto.h"
import "C"
import "unsafe"

func TLSPRF(mode []byte, needsSHA384 bool, result, secret, crandom, srandom, seed []byte) {
	var sha384 C.int
	if needsSHA384 {
		sha384 = 1
	}
	C._goboringcrypto_tls1_PRF(
		(*C.uchar)(unsafe.Pointer(&mode[0])), sha384,
		base(result),
		base(secret), C.size_t(len(secret)),
		base(srandom), C.size_t(len(srandom)),
		base(crandom), C.size_t(len(crandom)),
		base(seed), C.size_t(len(seed)),
	)
}
