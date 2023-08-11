package main

import "C"

import (
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	outerHash, err := bpfModule.GetMap("outer_hash")
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve an inner map prototype information from the outer map.
	innerInfo, err := outerHash.InnerMapInfo()
	if err != nil {
		log.Fatal(err)
	}

	if innerInfo.Name != "outer_hash.inner" {
		log.Fatal("inner prototype name should be 'outer_hash.inner'")
	}
	if innerInfo.Type != bpf.MapTypeArray {
		log.Fatal("inner prototype type should be MapTypeArray")
	}
	if innerInfo.MaxEntries != 1 {
		log.Fatal("inner prototype max entries should be 1")
	}
	if innerInfo.KeySize != 4 {
		log.Fatal("inner prototype key size should be 4")
	}
	if innerInfo.ValueSize != 4 {
		log.Fatal("inner prototype value size should be 4")
	}
	if innerInfo.MapFlags != 0 {
		log.Fatal("inner prototype map flags should be 0")
	}
	if innerInfo.IfIndex != 0 {
		log.Fatal("inner prototype ifindex should be 0")
	}
	if innerInfo.MapExtra != 0 {
		log.Fatal("inner prototype map extra should be 0")
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	// Attempting to get inner map prototype information after the
	// object is loaded will fail.
	_, err = outerHash.InnerMapInfo()
	if err == nil {
		log.Fatal("should fail after object is loaded")
	}
}
