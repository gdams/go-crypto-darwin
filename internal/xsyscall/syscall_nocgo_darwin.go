// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo && (amd64 || arm64)

package xsyscall

import (
	"syscall"
	"unsafe"
)

//go:linkname syscall_syscall6 syscall.syscall6

//go:noescape
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname noescape
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

const maxSyscallArgs = 32

type libcCallInfo struct {
	fn   uintptr
	n    uintptr // number of parameters
	args uintptr // parameters
}

var syscallNSystemStack_trampoline byte
var syscallNSystemStackABIInternal = uintptr(unsafe.Pointer(&syscallNSystemStack_trampoline))

// SyscallN calls fn using the host ABI. fn must not call back into Go.
//
// All its parameters and return values must be uintptr in order
// for the Go compiler to automatically set the //go:uintptrkeepalive
// directive (which we can't set manually here).
// See https://github.com/golang/go/blob/9a5a1202f4c4d5a7048b149b65c3e5b82a2de9aa/src/cmd/compile/internal/escape/call.go#L275.
//
//go:nosplit
func SyscallN(_ uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	if len(args) > maxSyscallArgs {
		panic("xsyscall: too many arguments")
	}
	libcArgs := libcCallInfo{
		fn: fn,
		n:  uintptr(len(args)),
	}
	if libcArgs.n != 0 {
		libcArgs.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	r1, r2, _ = syscall_syscall6(syscallNSystemStackABIInternal, uintptr(unsafe.Pointer(&libcArgs)), 0, 0, 0, 0, 0)
	return r1, r2
}

// Shim syscallN calls SyscallN.
//
//go:nosplit
func syscallN(errType uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	return SyscallN(errType, fn, args...)
}
