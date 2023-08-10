package main

import "C"

import (
	"encoding/binary"
	"log"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		log.Fatal(err)
	}

	// Get info about the "tester" map
	infoTester, err := bpf.GetMapInfoByFD(testerMap.FileDescriptor())
	if err != nil {
		log.Fatal(err)
	}

	// Get a new BPFMapLow object pointing to the "tester" map
	testerMapLow, err := bpf.GetMapByID(infoTester.ID)
	if err != nil {
		log.Fatal(err)
	}

	if testerMapLow.Name() != testerMap.Name() {
		log.Fatal("Names do not match")
	}
	if testerMapLow.Type() != testerMap.Type() {
		log.Fatal("Types do not match")
	}
	if testerMapLow.MaxEntries() != testerMap.MaxEntries() {
		log.Fatal("Max entries do not match")
	}
	if testerMapLow.KeySize() != testerMap.KeySize() {
		log.Fatal("Key sizes do not match")
	}
	if testerMapLow.ValueSize() != testerMap.ValueSize() {
		log.Fatal("Value sizes do not match")
	}

	// Save a value in the "tester" map using the original BPFMap object
	key1 := uint32(11)
	value1 := uint32(1917)
	key1Unsafe := unsafe.Pointer(&key1)
	value1Unsafe := unsafe.Pointer(&value1)
	err = testerMap.Update(key1Unsafe, value1Unsafe)
	if err != nil {
		log.Fatal(err)
	}

	// Get the value from the "tester" map using the new BPFMapLow object
	v, err := testerMapLow.GetValue(key1Unsafe)
	if err != nil {
		log.Fatal(err)
	}
	if endian().Uint32(v) != value1 {
		log.Fatal("Value mismatch")
	}
}

func endian() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
