package main

import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	serverFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_IP)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer unix.Close(serverFD)
	serverAddr := &unix.SockaddrInet4{
		Port: 22345,
		Addr: [4]byte{127, 0, 0, 1},
	}
	if err := unix.Bind(serverFD, serverAddr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if err := unix.Listen(serverFD, 100); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	sockMapRx, err := bpfModule.GetMap("sock_map_rx")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	prog1, err := bpfModule.GetProgram("bpf_prog_parser")
	prog1.AttachGenericFD(sockMapRx.FileDescriptor(),
		bpf.BPFAttachTypeSKSKBStreamParser, bpf.BPFFNone)
	defer func() {
		if err := prog1.DetachGenericFD(sockMapRx.FileDescriptor(), bpf.BPFAttachTypeSKSKBStreamParser); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()
	prog2, err := bpfModule.GetProgram("bpf_prog_verdict")
	prog2.AttachGenericFD(sockMapRx.FileDescriptor(),
		bpf.BPFAttachTypeSKSKBStreamVerdict, bpf.BPFFNone)
	defer func() {
		if err := prog2.DetachGenericFD(sockMapRx.FileDescriptor(), bpf.BPFAttachTypeSKSKBStreamVerdict); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()

	go func() {
		acceptedFD, _, err := unix.Accept(serverFD)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
		key := int(0)
		val := int(acceptedFD)
		if err = sockMapRx.UpdateValueFlags(unsafe.Pointer(&key), unsafe.Pointer(&val), bpf.MapFlagUpdateAny); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()

	c, err := net.Dial("tcp", "127.0.0.1:22345")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer c.Close()
	if _, err = c.Write([]byte("foobar")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	data := make([]byte, 10)
	if _, err = c.Read(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
