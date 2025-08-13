package main

import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	serverFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_IP)
	if err != nil {
		common.Error(err)
	}
	defer unix.Close(serverFD)

	serverAddr := &unix.SockaddrInet4{
		Port: 22345,
		Addr: [4]byte{127, 0, 0, 1},
	}
	if err := unix.Bind(serverFD, serverAddr); err != nil {
		common.Error(err)
	}

	if err := unix.Listen(serverFD, 100); err != nil {
		common.Error(err)
	}

	sockMapRx, err := bpfModule.GetMap("sock_map_rx")
	if err != nil {
		common.Error(err)
	}

	prog1, err := bpfModule.GetProgram("bpf_prog_parser")
	prog1.AttachGenericFD(sockMapRx.FileDescriptor(),
		bpf.BPFAttachTypeSKSKBStreamParser, bpf.BPFFNone)
	defer func() {
		if err := prog1.DetachGenericFD(sockMapRx.FileDescriptor(), bpf.BPFAttachTypeSKSKBStreamParser); err != nil {
			common.Error(err)
		}
	}()

	prog2, err := bpfModule.GetProgram("bpf_prog_verdict")
	prog2.AttachGenericFD(sockMapRx.FileDescriptor(),
		bpf.BPFAttachTypeSKSKBStreamVerdict, bpf.BPFFNone)
	defer func() {
		if err := prog2.DetachGenericFD(sockMapRx.FileDescriptor(), bpf.BPFAttachTypeSKSKBStreamVerdict); err != nil {
			common.Error(err)
		}
	}()

	mapUpdateChan := make(chan struct{}, 1)

	go func() {
		acceptedFD, _, err := unix.Accept(serverFD)
		if err != nil {
			common.Error(err)
		}
		key := int(0)
		val := int(acceptedFD)
		if err = sockMapRx.UpdateValueFlags(unsafe.Pointer(&key), unsafe.Pointer(&val), bpf.MapFlagUpdateAny); err != nil {
			common.Error(err)
		}

		mapUpdateChan <- struct{}{}
	}()

	c, err := net.Dial("tcp", "127.0.0.1:22345")
	if err != nil {
		common.Error(err)
	}
	defer c.Close()

	// wait for the bpf map to be updated
	select {
	case <-mapUpdateChan:
	// continue with write/read
	case <-time.After(15 * time.Second): // Same of the selftest
		common.Error(errors.New("bpf map timeout"))
	}

	input := []byte("foobar")
	if _, err = c.Write(input); err != nil {
		common.Error(err)
	}

	output := make([]byte, 6)
	if _, err = c.Read(output); err != nil {
		common.Error(err)
	}

	if !bytes.Equal(output, input) {
		common.Error(fmt.Errorf("data mismatch: expected %q, got %q", input, output))
	}
}
