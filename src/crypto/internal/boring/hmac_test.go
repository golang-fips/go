package boring

import (
	"crypto/sha256"
	"testing"
)

// Just tests that we can create an HMAC instance.
// Previously would cause panic because of incorrect
// stack allocation of opaque OpenSSL type.
func TestNewHMAC(t *testing.T) {
	mac := NewHMAC(sha256.New, nil)
	mac.Write([]byte("foo"))
	t.Logf("%x\n", mac.Sum(nil))
}
