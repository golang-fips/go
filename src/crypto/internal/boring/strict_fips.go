//go:build goexperiment.strictfipsruntime
// +build goexperiment.strictfipsruntime

package boring

import (
	"fmt"
	"os"
)

var isStrictFIPS bool = true

func strictFIPSOpenSSLRuntimeCheck() {
	if hostFIPSModeEnabled() && !Enabled() {
		fmt.Fprintln(os.Stderr, "FIPS mode is enabled, but the required OpenSSL backend is unavailable")
		os.Exit(1)
	}
}

func strictFIPSNonCompliantBinaryCheck() {
	if hostFIPSModeEnabled() {
		fmt.Fprintln(os.Stderr, "FIPS mode is enabled, but this binary is not compiled with FIPS compliant mode enabled")
		os.Exit(1)
	}
}
