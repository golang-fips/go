// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && amd64 && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,amd64,!android,!cmd_go_bootstrap,!msan,!no_openssl

package boring

// #include "goboringcrypto.h"
import "C"
import (
	"crypto"
	"encoding/asn1"
	"errors"
	"math/big"
	"runtime"
	"unsafe"
)

type ecdsaSignature struct {
	R, S *big.Int
}

type PrivateKeyECDSA struct {
	key *C.GO_EC_KEY
}

func (k *PrivateKeyECDSA) finalize() {
	C._goboringcrypto_EC_KEY_free(k.key)
}

type PublicKeyECDSA struct {
	key *C.GO_EC_KEY
}

func (k *PublicKeyECDSA) finalize() {
	C._goboringcrypto_EC_KEY_free(k.key)
}

var errUnknownCurve = errors.New("boringcrypto: unknown elliptic curve")
var errUnsupportedCurve = errors.New("boringcrypto: unsupported elliptic curve")

func curveNID(curve string) (C.int, error) {
	switch curve {
	case "P-224":
		return 0, errUnsupportedCurve
	case "P-256":
		return C.GO_NID_X9_62_prime256v1, nil
	case "P-384":
		return C.GO_NID_secp384r1, nil
	case "P-521":
		return C.GO_NID_secp521r1, nil
	}
	return 0, errUnknownCurve
}

func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*PublicKeyECDSA, error) {
	key, err := newECKey(curve, X, Y)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDSA{key}
	// Note: Because of the finalizer, any time k.key is passed to cgo,
	// that call must be followed by a call to runtime.KeepAlive(k),
	// to make sure k is not collected (and finalized) before the cgo
	// call returns.
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func newECKey(curve string, X, Y *big.Int) (*C.GO_EC_KEY, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	key := C._goboringcrypto_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, NewOpenSSLError("EC_KEY_new_by_curve_name failed")
	}
	group := C._goboringcrypto_EC_KEY_get0_group(key)
	pt := C._goboringcrypto_EC_POINT_new(group)
	if pt == nil {
		C._goboringcrypto_EC_KEY_free(key)
		return nil, NewOpenSSLError("EC_POINT_new failed")
	}
	bx := bigToBN(X)
	by := bigToBN(Y)
	ok := bx != nil && by != nil && C._goboringcrypto_EC_POINT_set_affine_coordinates_GFp(group, pt, bx, by, nil) != 0 &&
		C._goboringcrypto_EC_KEY_set_public_key(key, pt) != 0
	if bx != nil {
		C._goboringcrypto_BN_free(bx)
	}
	if by != nil {
		C._goboringcrypto_BN_free(by)
	}
	C._goboringcrypto_EC_POINT_free(pt)
	if !ok {
		C._goboringcrypto_EC_KEY_free(key)
		return nil, NewOpenSSLError("EC_POINT_free failed")
	}
	return key, nil
}

func NewPrivateKeyECDSA(curve string, X, Y *big.Int, D *big.Int) (*PrivateKeyECDSA, error) {
	key, err := newECKey(curve, X, Y)
	if err != nil {
		return nil, err
	}
	bd := bigToBN(D)
	ok := bd != nil && C._goboringcrypto_EC_KEY_set_private_key(key, bd) != 0
	if bd != nil {
		C._goboringcrypto_BN_free(bd)
	}
	if !ok {
		C._goboringcrypto_EC_KEY_free(key)
		return nil, NewOpenSSLError("EC_KEY_set_private_key failed")
	}
	k := &PrivateKeyECDSA{key}
	// Note: Because of the finalizer, any time k.key is passed to cgo,
	// that call must be followed by a call to runtime.KeepAlive(k),
	// to make sure k is not collected (and finalized) before the cgo
	// call returns.
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func SignECDSA(priv *PrivateKeyECDSA, hash []byte, h crypto.Hash) (r, s *big.Int, err error) {
	// We could use ECDSA_do_sign instead but would need to convert
	// the resulting BIGNUMs to *big.Int form. If we're going to do a
	// conversion, converting the ASN.1 form is more convenient and
	// likely not much more expensive.
	sig, err := SignMarshalECDSA(priv, hash, h)
	if err != nil {
		return nil, nil, err
	}
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return nil, nil, err
	}
	return esig.R, esig.S, nil
}

func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte, h crypto.Hash) ([]byte, error) {
	size := C._goboringcrypto_ECDSA_size(priv.key)
	sig := make([]byte, size)
	var sigLen C.uint
	if h == crypto.Hash(0) {
		ok := C._goboringcrypto_internal_ECDSA_sign(0, base(hash), C.size_t(len(hash)), (*C.uint8_t)(unsafe.Pointer(&sig[0])), &sigLen, priv.key) > 0
		if !ok {
			return nil, NewOpenSSLError(("ECDSA_sign failed"))
		}
	} else {
		md := cryptoHashToMD(h)
		if md == nil {
			panic("boring: invalid hash")
		}
		if C._goboringcrypto_ECDSA_sign(md, base(hash), C.size_t(len(hash)), (*C.uint8_t)(unsafe.Pointer(&sig[0])), &sigLen, priv.key) == 0 {
			return nil, NewOpenSSLError("ECDSA_sign failed")
		}
	}
	runtime.KeepAlive(priv)
	return sig[:sigLen], nil
}

func VerifyECDSA(pub *PublicKeyECDSA, msg []byte, r, s *big.Int, h crypto.Hash) bool {
	// We could use ECDSA_do_verify instead but would need to convert
	// r and s to BIGNUM form. If we're going to do a conversion, marshaling
	// to ASN.1 is more convenient and likely not much more expensive.
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return false
	}
	if h == crypto.Hash(0) {
		ok := C._goboringcrypto_internal_ECDSA_verify(0, base(msg), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&sig[0])), C.uint(len(sig)), pub.key) > 0
		runtime.KeepAlive(pub)
		return ok
	}
	md := cryptoHashToMD(h)
	if md == nil {
		panic("boring: invalid hash")
	}
	ok := C._goboringcrypto_ECDSA_verify(md, base(msg), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&sig[0])), C.uint(len(sig)), pub.key) > 0
	runtime.KeepAlive(pub)
	return ok
}

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, nil, nil, err
	}
	key := C._goboringcrypto_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, nil, nil, NewOpenSSLError("EC_KEY_new_by_curve_name failed")
	}
	defer C._goboringcrypto_EC_KEY_free(key)
	if C._goboringcrypto_EC_KEY_generate_key(key) == 0 {
		return nil, nil, nil, NewOpenSSLError("EC_KEY_generate_key failed")
	}
	group := C._goboringcrypto_EC_KEY_get0_group(key)
	pt := C._goboringcrypto_EC_KEY_get0_public_key(key)
	bd := C._goboringcrypto_EC_KEY_get0_private_key(key)
	if pt == nil || bd == nil {
		return nil, nil, nil, NewOpenSSLError("EC_KEY_get0_private_key failed")
	}
	bx := C._goboringcrypto_BN_new()
	if bx == nil {
		return nil, nil, nil, NewOpenSSLError("BN_new failed")
	}
	defer C._goboringcrypto_BN_free(bx)
	by := C._goboringcrypto_BN_new()
	if by == nil {
		return nil, nil, nil, NewOpenSSLError("BN_new failed")
	}
	defer C._goboringcrypto_BN_free(by)
	if C._goboringcrypto_EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil) == 0 {
		return nil, nil, nil, NewOpenSSLError("EC_POINT_get_affine_coordinates_GFp failed")
	}
	return bnToBig(bx), bnToBig(by), bnToBig(bd), nil
}
