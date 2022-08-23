package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	iteratorMax uint32 = 5
	added       uint32 = 1
	checked     uint32 = 2
)

var one = 1

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()
	bpfModule.BPFLoadObject()

	numbers, err := bpfModule.GetMap("numbers")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	testMap := map[uint32]uint32{}
	var i uint32
	for i = 0; i < iteratorMax; i++ {
		testMap[i] = added
		index := unsafe.Pointer(&i)
		value := unsafe.Pointer(&one)
		err = numbers.Update(index, value)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}

	iterator := numbers.Iterator()
	for iterator.Next() {
		keyBytes := iterator.Key()
		key := determineHostByteOrder().Uint32(keyBytes)

		val, ok := testMap[key]
		if !ok {
			fmt.Fprintln(os.Stderr, "Unknown key was found: %d", val)
			os.Exit(-1)
		}
		if val != 1 {
			fmt.Fprintln(os.Stderr, "Corrupted value: %d", val)
			os.Exit(-1)
		}
		testMap[key] = checked
	}
	if iterator.Err() != nil {
		fmt.Fprintf(os.Stderr, "iterator error: %v\n", iterator.Err())
		os.Exit(-1)
	}

	// make sure it got everything
	for k, v := range testMap {
		if v != 2 {
			fmt.Fprintln(os.Stderr, "Key was not found: ", k)
			os.Exit(-1)
		}
	}
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
