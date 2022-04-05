// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package boring

// #include "goboringcrypto.h"
import "C"
import (
	"errors"
	"hash"
	"unsafe"
)

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	h := new(sha1Hash)
	h.Reset()
	return h
}

type sha1Hash struct {
	ctx C.GO_SHA_CTX
	out [20]byte
}

type sha1Ctx struct {
	h      [5]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (h *sha1Hash) Reset()               { C._goboringcrypto_SHA1_Init(&h.ctx) }
func (h *sha1Hash) Size() int            { return 20 }
func (h *sha1Hash) BlockSize() int       { return 64 }
func (h *sha1Hash) Sum(in []byte) []byte { return append(in, h.sum()...) }

func (h *sha1Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA1_Update(&h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA1_Update failed")
	}
	return len(p), nil
}

func (h0 *sha1Hash) sum() []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA1_Final((*C.uint8_t)(unsafe.Pointer(&h.out[0])), &h.ctx) == 0 {
		panic("boringcrypto: SHA1_Final failed")
	}
	return h.out[:]
}

const (
	sha1Magic         = "sha\x01"
	sha1MarshaledSize = len(sha1Magic) + 5*4 + 64 + 8
)

func (h *sha1Hash) MarshalBinary() ([]byte, error) {
	d := (*sha1Ctx)(unsafe.Pointer(&h.ctx))
	b := make([]byte, 0, sha1MarshaledSize)
	b = append(b, sha1Magic...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha1Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(sha1Magic) || string(b[:len(sha1Magic)]) != sha1Magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != sha1MarshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	d := (*sha1Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(sha1Magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	h := new(sha224Hash)
	h.Reset()
	return h
}

type sha224Hash struct {
	ctx C.GO_SHA256_CTX
	out [224 / 8]byte
}

func (h *sha224Hash) Reset()               { C._goboringcrypto_SHA224_Init(&h.ctx) }
func (h *sha224Hash) Size() int            { return 224 / 8 }
func (h *sha224Hash) BlockSize() int       { return 64 }
func (h *sha224Hash) Sum(in []byte) []byte { return append(in, h.sum()...) }

func (h *sha224Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA224_Update(&h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA224_Update failed")
	}
	return len(p), nil
}

func (h0 *sha224Hash) sum() []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA224_Final((*C.uint8_t)(unsafe.Pointer(&h.out[0])), &h.ctx) == 0 {
		panic("boringcrypto: SHA224_Final failed")
	}
	return h.out[:]
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	h := new(sha256Hash)
	h.Reset()
	return h
}

type sha256Hash struct {
	ctx C.GO_SHA256_CTX
	out [256 / 8]byte
}

func (h *sha256Hash) Reset()               { C._goboringcrypto_SHA256_Init(&h.ctx) }
func (h *sha256Hash) Size() int            { return 256 / 8 }
func (h *sha256Hash) BlockSize() int       { return 64 }
func (h *sha256Hash) Sum(in []byte) []byte { return append(in, h.sum()...) }

func (h *sha256Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA256_Update(&h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA256_Update failed")
	}
	return len(p), nil
}

func (h0 *sha256Hash) sum() []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA256_Final((*C.uint8_t)(unsafe.Pointer(&h.out[0])), &h.ctx) == 0 {
		panic("boringcrypto: SHA256_Final failed")
	}
	return h.out[:]
}

const (
	magic224         = "sha\x02"
	magic256         = "sha\x03"
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8
)

type sha256Ctx struct {
	h      [8]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (h *sha224Hash) MarshalBinary() ([]byte, error) {
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b := make([]byte, 0, marshaledSize256)
	b = append(b, magic224...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha256Hash) MarshalBinary() ([]byte, error) {
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b := make([]byte, 0, marshaledSize256)
	b = append(b, magic256...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha224Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic224) || string(b[:len(magic224)]) != magic224 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic224):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (h *sha256Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic256) || string(b[:len(magic256)]) != magic256 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic256):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	h := new(sha384Hash)
	h.Reset()
	return h
}

type sha384Hash struct {
	ctx C.GO_SHA512_CTX
	out [384 / 8]byte
}

func (h *sha384Hash) Reset()               { C._goboringcrypto_SHA384_Init(&h.ctx) }
func (h *sha384Hash) Size() int            { return 384 / 8 }
func (h *sha384Hash) BlockSize() int       { return 128 }
func (h *sha384Hash) Sum(in []byte) []byte { return append(in, h.sum()...) }

func (h *sha384Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA384_Update(&h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA384_Update failed")
	}
	return len(p), nil
}

func (h0 *sha384Hash) sum() []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA384_Final((*C.uint8_t)(unsafe.Pointer(&h.out[0])), &h.ctx) == 0 {
		panic("boringcrypto: SHA384_Final failed")
	}
	return h.out[:]
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	h := new(sha512Hash)
	h.Reset()
	return h
}

type sha512Hash struct {
	ctx C.GO_SHA512_CTX
	out [512 / 8]byte
}

func (h *sha512Hash) Reset()               { C._goboringcrypto_SHA512_Init(&h.ctx) }
func (h *sha512Hash) Size() int            { return 512 / 8 }
func (h *sha512Hash) BlockSize() int       { return 128 }
func (h *sha512Hash) Sum(in []byte) []byte { return append(in, h.sum()...) }

func (h *sha512Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA512_Update(&h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA512_Update failed")
	}
	return len(p), nil
}

func (h0 *sha512Hash) sum() []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA512_Final((*C.uint8_t)(unsafe.Pointer(&h.out[0])), &h.ctx) == 0 {
		panic("boringcrypto: SHA512_Final failed")
	}
	return h.out[:]
}

type sha512Ctx struct {
	h      [8]uint64
	nl, nh uint64
	x      [128]byte
	nx     uint32
}

const (
	magic384         = "sha\x04"
	magic512_224     = "sha\x05"
	magic512_256     = "sha\x06"
	magic512         = "sha\x07"
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8
)

var zero [128]byte

func (h *sha384Hash) MarshalBinary() ([]byte, error) {
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b := make([]byte, 0, marshaledSize512)
	b = append(b, magic384...)
	b = appendUint64(b, d.h[0])
	b = appendUint64(b, d.h[1])
	b = appendUint64(b, d.h[2])
	b = appendUint64(b, d.h[3])
	b = appendUint64(b, d.h[4])
	b = appendUint64(b, d.h[5])
	b = appendUint64(b, d.h[6])
	b = appendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha512Hash) MarshalBinary() ([]byte, error) {
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b := make([]byte, 0, marshaledSize512)
	b = append(b, magic512...)
	b = appendUint64(b, d.h[0])
	b = appendUint64(b, d.h[1])
	b = appendUint64(b, d.h[2])
	b = appendUint64(b, d.h[3])
	b = appendUint64(b, d.h[4])
	b = appendUint64(b, d.h[5])
	b = appendUint64(b, d.h[6])
	b = appendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha384Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic384)]) != magic384 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func (h *sha512Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic512)]) != magic512 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	putUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	putUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

func putUint64(x []byte, s uint64) {
	_ = x[7]
	x[0] = byte(s >> 56)
	x[1] = byte(s >> 48)
	x[2] = byte(s >> 40)
	x[3] = byte(s >> 32)
	x[4] = byte(s >> 24)
	x[5] = byte(s >> 16)
	x[6] = byte(s >> 8)
	x[7] = byte(s)
}

func putUint32(x []byte, s uint32) {
	_ = x[3]
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}
