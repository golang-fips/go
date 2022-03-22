// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto"
	"crypto/internal/boring"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	"testing/quick"
)

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

type DecryptPKCS1v15Test struct {
	in, out string
}

// Test vectors for testRSA2048PrivateKey
var decryptPKCS1v15Tests = []DecryptPKCS1v15Test{
	{
		"Ppg5lRhQZ8zLMgU8jFWURwm+Oj3t1+9x8qIDZwWMlP6O1QVO4xXxHdheVnLRa0Iq+L5HTgjk/PNNkSLIMD11ERxbMD5NtXoj64qaQDkyIBXaN0FNc5Nga/Lbb+vXVYSJ5F4KIOUYaOwzgNSCMensYNz5/7TloMy2Zoqa6vsWzcU+ujfyFaNjJXC26ZM0zv/4v9Aqqb/WIsLjEgdVvplqL1jwbI8Vv/MLEpQRay3S2RHoS9PIcvGKe3Ze0nOE8rAPiRQKfAsX+zlMkw1+LDttb5Dg/vM4lGF6jTg/nmfgCb6gjWE+QpapLKuZIN3WOwG/zslKeROErPn71xAlVeHI1Q==",
		"x",
	},
	{
		"kjtn1z9R67b0t7RydEoXeK9GC9wWt1J47i+14alOLCuWr9aqnJxYJS+jr2Z3/TWf4qqTiEujIP5bzvM8vnU2cnJqOGUqoH5xH1+8gq9aD0RbVY0auvUxPUKI3foLoMlp6M1fTSJGiuD9DASp7BZfiMvsU1kKPrLlHpu4azOKbAfIojyyt64Dl3cIpha8FBakym1SRM2iJKKBVae3Reu58uGX9lHroJAWiIdDT4VDIGXQv9dvsViPn4hvWKls5xYtf3V5GPHyvrptsLYcqBOUXM1Wnu2SpZxKRuyz9tWA3w377XNByDMchLJeC4qxdA6ayo53ckXr0no0fU0JrRHkdg==",
		"testing.",
	},
	{
		"gljV2jJNON8RwzgVezwG/ddFWPSpGHgnUgEot42vU7Kow5TMvd43f9QAJsPQd0ocT9YIp/3km+2CSWWr+5E3fWW0p2cQBxUfnsJFsNKPvQt6Ct7Bn8HzkhxLJuvIShFzQlBuph4hBuN33dWhAFFDESsZnPvU6EFJlmTHrmqY+H9cdECU4hXQ1R7Z+lHlvT8RxDNBu1fdAarRXcKrw9EeN2ZwSvVx62aXnAcAQQkijmOn9dkObgqeii/wHPI28SR/Aa/hTw1XE5DoZmDBCx6EFJ4hcY7MKAX0iSQiaxinM+IxkqiCftOnvYv737cD/vKG6llhGCCDx0Et5xYu2JWakw==",
		"testing.\n",
	},
	{
		"iJiYwVBtLhZBmYngT5u+YR5+raI33OvpShPR9arl4zSss+eK5krMANZUTrRCsw8Tho6kpyDgVohfH5V/8zX4Rtslak1peZdvnmcEkJCFk0FpnlcALRBGTCXUJEwxlSgaTz00awCjkfLzMYNCwTAlEP9QxUX2kSIABKSUw4ARwZ5jQTGCdJNl696Q/cF1JjEqsjpPbjn4UYkV3gNl0xXPiTVgfNJKZir1caEGOKfOsfbTFixvA5oANgRySxwZfoj/6dW9xIVgcq/ssmkTl8TnTKQTY0dRTNWs8+HuQxp2I4MSmAun6LYdr8pom1IazJtp1BEaSDZ+thRIQ/oMsYDJXQ==",
		"01234567890123456789012345678901234567890123456789012",
	},
}

func TestDecryptPKCS1v15(t *testing.T) {
	decryptionFuncs := []func([]byte) ([]byte, error){
		func(ciphertext []byte) (plaintext []byte, err error) {
			return DecryptPKCS1v15(nil, testRSA2048PrivateKey, ciphertext)
		},
		func(ciphertext []byte) (plaintext []byte, err error) {
			return testRSA2048PrivateKey.Decrypt(nil, ciphertext, nil)
		},
	}

	for _, decryptFunc := range decryptionFuncs {
		for i, test := range decryptPKCS1v15Tests {
			out, err := decryptFunc(decodeBase64(test.in))
			if err != nil {
				t.Errorf("#%d error decrypting: %v", i, err)
			}
			want := []byte(test.out)
			if !bytes.Equal(out, want) {
				t.Errorf("#%d got:%#v want:%#v", i, out, want)
			}
		}
	}
}

func TestEncryptPKCS1v15(t *testing.T) {
	random := rand.Reader
	k := (testRSA2048PrivateKey.N.BitLen() + 7) / 8

	tryEncryptDecrypt := func(in []byte, blind bool) bool {
		if len(in) > k-11 {
			in = in[0 : k-11]
		}

		ciphertext, err := EncryptPKCS1v15(random, &testRSA2048PrivateKey.PublicKey, in)
		if err != nil {
			t.Errorf("error encrypting: %s", err)
			return false
		}

		var rand io.Reader
		if !blind {
			rand = nil
		} else {
			rand = random
		}
		plaintext, err := DecryptPKCS1v15(rand, testRSA2048PrivateKey, ciphertext)
		if err != nil {
			t.Errorf("error decrypting: %s", err)
			return false
		}

		if !bytes.Equal(plaintext, in) {
			t.Errorf("output mismatch: %#v %#v", plaintext, in)
			return false
		}
		return true
	}

	config := new(quick.Config)
	if testing.Short() {
		config.MaxCount = 10
	}
	quick.Check(tryEncryptDecrypt, config)
}

// Test vectors for testRSA2048PrivateKey
var decryptPKCS1v15SessionKeyTests = []DecryptPKCS1v15Test{
	{
		"cSBy/rsocfCY2L/WDP7+oyI/uk0qf3BuJvWo1VwV/DG9XLuu7J1Gb2e7hYl3kmdf6rSnoqDuVE3viOsGeq1OsW9w0uw08syTwdOp34z90qxlrrKsGjjz9XIgErqwlWvfQ5KQQb8KA29Ub7q0sqQMMQD75bUxN3P4GhtOG6kNVY33QoCIVR65vHLcqe3SlrxAfYzlOjMNwdPsNP1GGVyAZpccxOiBJSUrssAFvRJ3g62wj2xrrtneRztmOGOy8ZSiEjGNjJ4/lmJXt2GyPXapTTKeHFbyqh5Xu8PNgMxaCgtWgMqnK6CPbJOGgski9axyaxPzjKEjUcs99dJ1mTT+qw==",
		"1234",
	},
	{
		"lcsS8tzZSJSiaaOSQSO4pT3Je5vvrNfAVUy3Axojr4uRreMuLRTIOOmEYRM/JcWakpJelPd+EHG/aXxId8aCoBg1MkH5q8AHW3zUARhlOd91rpASVs03v5wuk0jtiQiqr0HLNyxifSEzj04VPklc6n00yuHbI+DNTATTVkxj3a5hgOECqKi2matXGcJ5FtMEPAi2V+36y2dQ+DA/tgQrhlZ4ycA2FJnjvOHRJbC6QwNzPkzbjTlCqNzq92nwWKDypVJ29CrIQ2HYXG63DOuT96gIa08hyeZEeIrAUjtb9DK1TSEF/9BDASffHevW3/CqfpRYnFSNOj2xli3wBn1Dvg==",
		"FAIL",
	},
	{
		"Bsrz5yYuevhqx1Pxx4zEsegU2aVBZ2h9ebtAgQkq3N/og0t+8O92XpPBoNH/HT2jHclh01aij1niCqdBn2/6GBN4irnVjrWQkoAV2Q5Q+gVS0ZYeTzeX/15M/iq9xeLjBPXqj5PmNYh+vbL05FyPB+CcY8MPyv7HmtDsAWRVDxQVWy6y4lmC1/VwnG5jtmAbapE+Vyty0iVb9/Q6UaaV7DVKVssEDmwnychibJ4ACcTQ18kLkB1AE73dXp1B/XHh6ExbHXoaPeaRYr2gEI0No6VBTrMrG5eVz3dub/a5MVeat9n/oU2QQ3s/Pm0FlF9n2mwgvKm/4nLjwjiTFt3ToQ==",
		"abcd",
	},
	{
		"FKynVeuuoYxonMoXWwIw3mY7KTV3yS3fe2D+h5v6FXs/0xb5PeINCEq0+Ub5LFAZcx/lIbnt4bkLZcaKDxLpBCxpvpZNdgGxP970BvE5xmOuagF47VaqCciiERTTztRjwKTu0PZ5VtcpsxiSN4axlC1NOpJnIpDsNOWUaf5G6fCCEdfZWwgxaHLbxSAy+IdUHBH+honCPPZAyGyhERdcDRGJ8a6R20MFXC18e8asHtF5VWaicaYe0fy1Mrii46WqFY8hwoSrbHOGEQkjRymM/IQvXFdxQ1vtzAFavUsr5taiVe84DvcFJ5eRZ2jpVQTdO4gBy6RyD64iNSrv8a5dqA==",
		"FAIL",
	},
}

func TestEncryptPKCS1v15SessionKey(t *testing.T) {
	for i, test := range decryptPKCS1v15SessionKeyTests {
		key := []byte("FAIL")
		err := DecryptPKCS1v15SessionKey(nil, testRSA2048PrivateKey, decodeBase64(test.in), key)
		if err != nil {
			t.Errorf("#%d error decrypting", i)
		}
		want := []byte(test.out)
		if !bytes.Equal(key, want) {
			t.Errorf("#%d got:%#v want:%#v", i, key, want)
		}
	}
}

func TestEncryptPKCS1v15DecrypterSessionKey(t *testing.T) {
	for i, test := range decryptPKCS1v15SessionKeyTests {
		plaintext, err := testRSA2048PrivateKey.Decrypt(rand.Reader, decodeBase64(test.in), &PKCS1v15DecryptOptions{SessionKeyLen: 4})
		if err != nil {
			t.Fatalf("#%d: error decrypting: %s", i, err)
		}
		if len(plaintext) != 4 {
			t.Fatalf("#%d: incorrect length plaintext: got %d, want 4", i, len(plaintext))
		}

		if test.out != "FAIL" && !bytes.Equal(plaintext, []byte(test.out)) {
			t.Errorf("#%d: incorrect plaintext: got %x, want %x", i, plaintext, test.out)
		}
	}
}

func TestNonZeroRandomBytes(t *testing.T) {
	random := rand.Reader

	b := make([]byte, 512)
	err := nonZeroRandomBytes(b, random)
	if err != nil {
		t.Errorf("returned error: %s", err)
	}
	for _, b := range b {
		if b == 0 {
			t.Errorf("Zero octet found")
			return
		}
	}
}

type signPKCS1v15Test struct {
	in, out string
}

// Test vector for testRSA2048PrivateKey
// generated with `openssl pkeyutl -rawin -digest sha256 -sign -inkey <key>`
 var signPKCS1v15Tests = []signPKCS1v15Test{
	{"Test.\n", "467c3c8f16223ba09aecfe44488d6b34b3f91f11379949b1d8af31636ee8b3aa51eebb96ee11678323cb1f909af17c9d0fe4b6012078af8120474474efd1bb51765e1647369ddba6525c6608113857bb0e2aaed9ad01fe041b476b162f7d4db55bb31fa957046616ce463cecb2a66f38fa62c594d07afcc870582d545853b31fa705ab8565e4085804c32e73459720bf4e08f097843b0845116d4376231fa2472abc89b1e42462002bf70f9a1df31db6d2ab6dc52c8223798a4f57c40d6a9123b80739846d779044eac28d8c783e8ce73919f1d4a6efe8fb601b8d36c5c9b61654d6f8717d1fb9fcafa19669200900899dd08ce921a1745312eb06040a405903"},
}

func TestSignPKCS1v15(t *testing.T) {
	for i, test := range signPKCS1v15Tests {
		h := sha256.New()
		h.Write([]byte(test.in))
		digest := h.Sum(nil)

		s, err := SignPKCS1v15(nil, testRSA2048PrivateKey, crypto.SHA256, digest)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}

		expected, _ := hex.DecodeString(test.out)
		if !bytes.Equal(s, expected) {
			t.Errorf("#%d got: %x want: %x", i, s, expected)
		}
	}
}

func TestVerifyPKCS1v15(t *testing.T) {
	for i, test := range signPKCS1v15Tests {
		h := sha256.New()
		h.Write([]byte(test.in))
		digest := h.Sum(nil)

		sig, _ := hex.DecodeString(test.out)

		err := VerifyPKCS1v15(&testRSA2048PrivateKey.PublicKey, crypto.SHA256, digest, sig)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}
	}
}

func TestHashVerifyPKCS1v15(t *testing.T) {
	for i, test := range signPKCS1v15Tests {
		sig, _ := hex.DecodeString(test.out)

		err := HashVerifyPKCS1v15(&testRSA2048PrivateKey.PublicKey, crypto.SHA256, []byte(test.in), sig)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}
	}
}

func TestOverlongMessagePKCS1v15(t *testing.T) {
	ciphertext := decodeBase64("fjOVdirUzFoLlukv80dBllMLjXythIf22feqPrNo0YoIjzyzyoMFiLjAc/Y4krkeZ11XFThIrEvw\nkRiZcCq5ng==")
	_, err := DecryptPKCS1v15(nil, rsaPrivateKey, ciphertext)
	if err == nil {
		t.Error("RSA decrypted a message that was too long.")
	}
}

func TestUnpaddedSignature(t *testing.T) {
	if boring.Enabled() {
		t.Skip("skipping in boring mode")
	}
	msg := []byte("Thu Dec 19 18:06:16 EST 2013\n")
	// This base64 value was generated with:
	// % echo Thu Dec 19 18:06:16 EST 2013 > /tmp/msg
	// % openssl rsautl -sign -inkey key -out /tmp/sig -in /tmp/msg
	//
	// Where "key" contains the RSA private key given at the bottom of this
	// file.
	expectedSig := decodeBase64("pX4DR8azytjdQ1rtUiC040FjkepuQut5q2ZFX1pTjBrOVKNjgsCDyiJDGZTCNoh9qpXYbhl7iEym30BWWwuiZg==")

	sig, err := SignPKCS1v15(nil, rsaPrivateKey, crypto.Hash(0), msg)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %s", err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("signature is not expected value: got %x, want %x", sig, expectedSig)
	}
	if err := VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.Hash(0), msg, sig); err != nil {
		t.Fatalf("signature failed to verify: %s", err)
	}
}

func TestShortSessionKey(t *testing.T) {
	// This tests that attempting to decrypt a session key where the
	// ciphertext is too small doesn't run outside the array bounds.
	ciphertext, err := EncryptPKCS1v15(rand.Reader, &testRSA2048PrivateKey.PublicKey, []byte{1})
	if err != nil {
		t.Fatalf("Failed to encrypt short message: %s", err)
	}

	var key [32]byte
	if err := DecryptPKCS1v15SessionKey(nil, testRSA2048PrivateKey, ciphertext, key[:]); err != nil {
		t.Fatalf("Failed to decrypt short message: %s", err)
	}

	for _, v := range key {
		if v != 0 {
			t.Fatal("key was modified when ciphertext was invalid")
		}
	}
}

// In order to generate new test vectors you'll need the PEM form of this key (and s/TESTING/PRIVATE/):
// -----BEGIN RSA TESTING KEY-----
// MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
// fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
// /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
// RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
// EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
// IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
// tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
// -----END RSA TESTING KEY-----

var rsaPrivateKey = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase10("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077"),
		E: 65537,
	},
	D: fromBase10("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861"),
	Primes: []*big.Int{
		fromBase10("98920366548084643601728869055592650835572950932266967461790948584315647051443"),
		fromBase10("94560208308847015747498523884063394671606671904944666360068158221458669711639"),
	},
}

func TestShortPKCS1v15Signature(t *testing.T) {
	pub := &PublicKey{
		E: 65537,
		N: fromBase10("8272693557323587081220342447407965471608219912416565371060697606400726784709760494166080686904546560026343451112103559482851304715739629410219358933351333"),
	}
	sig, err := hex.DecodeString("193a310d0dcf64094c6e3a00c8219b80ded70535473acff72c08e1222974bb24a93a535b1dc4c59fc0e65775df7ba2007dd20e9193f4c4025a18a7070aee93")
	if err != nil {
		t.Fatalf("failed to decode signature: %s", err)
	}

	h := sha256.Sum256([]byte("hello"))
	err = VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	if err == nil {
		t.Fatal("VerifyPKCS1v15 accepted a truncated signature")
	}
}
