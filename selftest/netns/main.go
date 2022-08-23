package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
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

	prog, err := bpfModule.GetProgram("sk_lookup__lookup")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	link, err := prog.AttachNetns("/proc/self/ns/net")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link.GetFd() == 0 {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Start()
	numberOfEventsReceived := 0
	go func() {
		l, err := net.Listen("tcp", "127.0.0.1:")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
		go func() {
			for {
				l.Accept()
			}
		}()
		for i := 0; i < 10; i++ {
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(-1)
			}
			c.Write([]byte{0})
			c.Close()
		}
	}()

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()
}
