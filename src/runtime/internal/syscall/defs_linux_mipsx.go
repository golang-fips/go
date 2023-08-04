// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && (mips || mipsle)
// +build linux
// +build mips mipsle

package syscall

const (
	SYS_FCNTL = 4055
)
