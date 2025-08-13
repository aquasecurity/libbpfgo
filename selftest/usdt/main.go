package main

import (
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	binaryPath := "./ctest"
	providerName := "test"
	markerName := "test_marker"

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
	prog, err := bpfModule.GetProgram("usdt__test_marker")
	if err != nil {
		common.Error(err)
	}

	_, err = prog.AttachUSDT(-1, binaryPath, providerName, markerName)
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
		if binary.LittleEndian.Uint32(b) != 1234 {
			common.Error(fmt.Errorf("invalid data retrieved: %v", b))
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()
}
