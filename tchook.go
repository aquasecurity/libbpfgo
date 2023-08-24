package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"
)

//
// TcHook
//

type TcHook struct {
	hook *C.struct_bpf_tc_hook
}

func (hook *TcHook) SetInterfaceByIndex(ifaceIdx int) {
	hook.hook.ifindex = C.int(ifaceIdx)
}

func (hook *TcHook) SetInterfaceByName(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	hook.hook.ifindex = C.int(iface.Index)

	return nil
}

func (hook *TcHook) GetInterfaceIndex() int {
	return int(hook.hook.ifindex)
}

func (hook *TcHook) SetAttachPoint(attachPoint TcAttachPoint) {
	hook.hook.attach_point = uint32(attachPoint)
}

func (hook *TcHook) SetParent(a int, b int) {
	parent := (((a) << 16) & 0xFFFF0000) | ((b) & 0x0000FFFF)
	hook.hook.parent = C.uint(parent)
}

func (hook *TcHook) Create() error {
	errC := C.bpf_tc_hook_create(hook.hook)
	if errC < 0 {
		return fmt.Errorf("failed to create tc hook: %w", syscall.Errno(-errC))
	}

	return nil
}

func (hook *TcHook) Destroy() error {
	errC := C.bpf_tc_hook_destroy(hook.hook)
	if errC < 0 {
		return fmt.Errorf("failed to destroy tc hook: %w", syscall.Errno(-errC))
	}

	return nil
}

type TcOpts struct {
	ProgFd   int
	Flags    TcFlags
	ProgId   uint
	Handle   uint
	Priority uint
}

func tcOptsToC(tcOpts *TcOpts) *C.struct_bpf_tc_opts {
	if tcOpts == nil {
		return nil
	}
	opts := C.struct_bpf_tc_opts{}
	opts.sz = C.sizeof_struct_bpf_tc_opts
	opts.prog_fd = C.int(tcOpts.ProgFd)
	opts.flags = C.uint(tcOpts.Flags)
	opts.prog_id = C.uint(tcOpts.ProgId)
	opts.handle = C.uint(tcOpts.Handle)
	opts.priority = C.uint(tcOpts.Priority)

	return &opts
}

func tcOptsFromC(tcOpts *TcOpts, opts *C.struct_bpf_tc_opts) {
	if opts == nil {
		return
	}
	tcOpts.ProgFd = int(opts.prog_fd)
	tcOpts.Flags = TcFlags(opts.flags)
	tcOpts.ProgId = uint(opts.prog_id)
	tcOpts.Handle = uint(opts.handle)
	tcOpts.Priority = uint(opts.priority)
}

func (hook *TcHook) Attach(tcOpts *TcOpts) error {
	opts := tcOptsToC(tcOpts)
	errC := C.bpf_tc_attach(hook.hook, opts)
	if errC < 0 {
		return fmt.Errorf("failed to attach tc hook: %w", syscall.Errno(-errC))
	}
	tcOptsFromC(tcOpts, opts)

	return nil
}

func (hook *TcHook) Detach(tcOpts *TcOpts) error {
	opts := tcOptsToC(tcOpts)
	errC := C.bpf_tc_detach(hook.hook, opts)
	if errC < 0 {
		return fmt.Errorf("failed to detach tc hook: %w", syscall.Errno(-errC))
	}
	tcOptsFromC(tcOpts, opts)

	return nil
}

func (hook *TcHook) Query(tcOpts *TcOpts) error {
	opts := tcOptsToC(tcOpts)
	errC := C.bpf_tc_query(hook.hook, opts)
	if errC < 0 {
		return fmt.Errorf("failed to query tc hook: %w", syscall.Errno(-errC))
	}
	tcOptsFromC(tcOpts, opts)

	return nil
}
