package main

import "C"

import (
	"encoding/binary"
	"fmt"

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

	tcProg, err := bpfModule.GetProgram("test_tc")
	if err != nil || tcProg == nil {
		common.Error(fmt.Errorf("failed to get prog test_tc: %v", err))
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
		common.Error(err)
	}
	if opts.RetVal != 1 {
		common.Error(fmt.Errorf("retVal %d should be 1", opts.RetVal))
	}
	if len(opts.DataOut) != 14 {
		common.Error(fmt.Errorf("dataOut len %v should be 14", opts.DataOut))
	}
	if binary.LittleEndian.Uint32(opts.DataOut) != 0x04030201 {
		common.Error(fmt.Errorf("dataOut 0x%x should be 0x04030201", binary.LittleEndian.Uint32(opts.DataOut)))
	}
}
