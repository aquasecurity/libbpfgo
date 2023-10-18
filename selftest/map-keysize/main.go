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

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		log.Fatal(err)
	}

	keySize := testerMap.KeySize()
	if keySize != 4 {
		log.Fatal("keySize do not match")
	}

	err = testerMap.SetKeySize(8)
	if err != nil {
		log.Fatal(err)
	}

	keySize = testerMap.KeySize()
	if keySize != 8 {
		log.Fatal("keySize do not match")
	}

	bpfModule.BPFLoadObject()
}
