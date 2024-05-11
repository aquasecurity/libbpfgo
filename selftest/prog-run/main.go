package main

import "C"

import (
	"encoding/binary"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF module: %v", err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatalf("Failed to load object: %v", err)
	}

	tcProg, err := bpfModule.GetProgram("test_tc")
	if err != nil || tcProg == nil {
		log.Fatalf("Failed to get prog: %v", err)
	}

	dataIn := make([]byte, 16)
	binary.LittleEndian.PutUint32(dataIn, 0xdeadbeef)
	opts := bpf.RunOpts{
		DataIn:      dataIn,
		DataSizeIn:  16,
		DataOut:     make([]byte, 32),
		DataSizeOut: 32,
		Repeat:      1,
	}
	err = tcProg.Run(&opts)
	if err != nil {
		log.Fatalf("Failed to run prog: %v", err)
	}
	if opts.RetVal != 1 {
		log.Fatalf("retVal %d should be 1", opts.RetVal)
	}
	if len(opts.DataOut) != 14 {
		log.Fatalf("dataOut len %v should be 14", opts.DataOut)
	}
	if binary.LittleEndian.Uint32(opts.DataOut) != 0x04030201 {
		log.Fatalf("dataOut 0x%x should be 0x04030201", binary.LittleEndian.Uint32(opts.DataOut))
	}
}
