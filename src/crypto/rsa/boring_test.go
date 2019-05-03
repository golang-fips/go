// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Note: Can run these tests against the non-BoringCrypto
// version of the code by using "CGO_ENABLED=0 go test".

package rsa

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"reflect"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestBoringASN1Marshal(t *testing.T) {
	k, err := GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatal(err)
	}
	// This used to fail, because of the unexported 'boring' field.
	// Now the compiler hides it [sic].
	_, err = asn1.Marshal(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBoringDeepEqual(t *testing.T) {
	k, err := GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatal(err)
	}
	k.boring = nil // probably nil already but just in case
	k2 := *k
	k2.boring = unsafe.Pointer(k) // anything not nil, for this test
	if !reflect.DeepEqual(k, &k2) {
		// compiler should be hiding the boring field from reflection
		t.Fatalf("DeepEqual compared boring fields")
	}
}

func TestBoringGenerateKey(t *testing.T) {
	k, err := GenerateKey(rand.Reader, 2048) // 2048 is smallest size BoringCrypto might kick in for
	if err != nil {
		t.Fatal(err)
	}

	// Non-Boring GenerateKey always sets CRTValues to a non-nil (possibly empty) slice.
	if k.Precomputed.CRTValues == nil {
		t.Fatalf("GenerateKey: Precomputed.CRTValues = nil")
	}
}

func TestBoringFinalizers(t *testing.T) {
	if runtime.GOOS == "nacl" || runtime.GOOS == "js" {
		// Times out on nacl and js/wasm (without BoringCrypto)
		// but not clear why - probably consuming rand.Reader too quickly
		// and being throttled. Also doesn't really matter.
		t.Skipf("skipping on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	k, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Run test with GOGC=10, to make bug more likely.
	// Without the KeepAlives, the loop usually dies after
	// about 30 iterations.
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	for n := 0; n < 200; n++ {
		// Clear the underlying BoringCrypto object.
		atomic.StorePointer(&k.boring, nil)

		// Race to create the underlying BoringCrypto object.
		// The ones that lose the race are prime candidates for
		// being GC'ed too early if the finalizers are not being
		// used correctly.
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sum := make([]byte, 32)
				_, err := SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum)
				if err != nil {
					panic(err) // usually caused by memory corruption, so hard stop
				}
			}()
		}
		wg.Wait()
	}
}
