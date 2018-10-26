// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Most functionality in this package is tested by replacing existing code
// and inheriting that code's tests.

package boring

import "testing"

// Test that func init does not panic.
func TestInit(t *testing.T) {}

// Test that Unreachable panics.
func TestUnreachable(t *testing.T) {
	defer func() {
		if Enabled {
			if err := recover(); err == nil {
				t.Fatal("expected Unreachable to panic")
			}
		} else {
			if err := recover(); err != nil {
				t.Fatalf("expected Unreachable to be a no-op")
			}
		}
	}()
	Unreachable()
}

// Test that UnreachableExceptTests does not panic (this is a test).
func TestUnreachableExceptTests(t *testing.T) {
	UnreachableExceptTests()
}

// Test that the library FIPS mode is enabled when the host system
// is booted in FIPS mode.
func TestBoringEnabledWhenSystemInFIPSMode(t *testing.T) {
	systemFIPSOn := systemFIPSEnabled()
	if Enabled != systemFIPSOn {
		t.Fatal("Boring mode should be enabled when system in FIPS mode")
	}
	if fipsModeEnabled() != systemFIPSOn {
		t.Fatal("library FIPS mode should be enabled when system in FIPS mode")
	}
}
