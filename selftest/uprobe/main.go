package main

import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	if len(os.Args) < 3 {
		common.Error(errors.New("wrong syntax"))
	}

	binaryPath := os.Args[1]
	symbolName := os.Args[2]

	_, err := os.Stat(binaryPath)
	if err != nil {
		common.Error(err)
	}

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	if err = common.ResizeMap(bpfModule, "events", 8192); err != nil {
		common.Error(err)
	}

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("uprobe__test_function")
	if err != nil {
		common.Error(err)
	}

	offset, err := common.SymbolToOffset(binaryPath, symbolName)
	if err != nil {
		common.Error(err)
	}

	_, err = prog.AttachUprobe(-1, binaryPath, offset)
	if err != nil {
		common.Error(err)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		common.Error(err)
	}

	rb.Poll(300)

	numberOfEventsReceived := 0

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			common.Error(fmt.Errorf("invalid data retrieved: %v", b))
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	rb.Stop()
	rb.Stop()
	rb.Close()
	rb.Close()
	rb.Stop()
}
