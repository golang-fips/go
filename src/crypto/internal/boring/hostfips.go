package boring

import (
	"fmt"
	"os"
)

func hostFIPSModeEnabled() bool {
	// Look at /proc/sys/crypto/fips_enabled to see if FIPS mode is enabled.
	// If it is, log an error and exit.
	// If we run into an error reading that file because it doesn't exist, assume FIPS mode is not enabled.
	data := make([]byte, 16)
	f, err := os.Open("/proc/sys/crypto/fips_enabled")
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	_, err = f.Read(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading /proc/sys/crypto/fips_enabled: %v\n", err)
		os.Exit(1)
	}
	return len(data) > 0 && data[0] == '1'
}
