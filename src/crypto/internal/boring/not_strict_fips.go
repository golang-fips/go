//go:build !strictfipsruntime
// +build !strictfipsruntime

package boring

var isStrictFIPS bool = false

func strictFIPSOpenSSLRuntimeCheck() {
}

func strictFIPSNonCompliantBinaryCheck() {
}
