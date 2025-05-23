package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

type test_arg struct {
	id uint64
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	ch := make(chan []byte, 3) // We will send 3 messages
	urb, err := bpfModule.InitUserRingBuf("dispatched", ch)
	if err != nil {
		os.Exit(-1)
	}
	urb.Start()

	evtChan := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("errEvt", evtChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	rb.Poll(300)

	// Send 3 messages to the ring buffer
	var b bytes.Buffer // Stand-in for a network connection
	binary.Write(&b, binary.LittleEndian, test_arg{id: 0x1122334455667788})
	ch <- b.Bytes()
	ch <- b.Bytes()
	ch <- b.Bytes()

	time.Sleep(1 * time.Second)

	prog, err := bpfModule.GetProgram("test_user_ring_buff")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	arg := &test_arg{
		id: 0,
	}

	var data bytes.Buffer
	binary.Write(&data, binary.LittleEndian, arg)
	opt := bpf.RunOpts{
		CtxIn:     data.Bytes(),
		CtxSizeIn: uint32(data.Len()),
	}

	// Run the program and check if 3 messages were drained by the program
	prog.Run(&opt)
	if opt.RetVal != 3 {
		fmt.Fprintln(os.Stderr, "error: expected 3, got", opt.RetVal)
		os.Exit(-1)
	}
}
