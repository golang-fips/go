//go:build !goexperiment.strictfipsruntime
// +build !goexperiment.strictfipsruntime

package boring

var isStrictFIPS bool = false

func strictFIPSOpenSSLRuntimeCheck() {
}

func strictFIPSNonCompliantBinaryCheck() {
}
