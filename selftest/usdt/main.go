package main

import (
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	binaryPath := "./ctest"
	providerName := "test"
	markerName := "test_marker"

	_, err := os.Stat(binaryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("usdt__test_marker")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachUSDT(-1, binaryPath, providerName, markerName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Poll(300)

	numberOfEventsReceived := 0

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 1234 {
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

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap("events")
	if err != nil {
		return err
	}

	if err = m.SetMaxEntries(size); err != nil {
		return err
	}

	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}
