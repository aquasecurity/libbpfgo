package main

import "C"

import (
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModuleWithAutocreate, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModuleWithAutocreate.Close()

	testerMapWithAutocreate, err := bpfModuleWithAutocreate.GetMap("tester")
	if err != nil {
		log.Fatal(err)
	}

	isAutocreate := testerMapWithAutocreate.Autocreate()
	if !isAutocreate {
		log.Fatal("Autocreate is false")
	}

	err = bpfModuleWithAutocreate.BPFLoadObject()
	if err == nil {
		log.Fatal("Was able to load with a bad type of map")
	}

	bpfModuleWithoutAutocreate, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModuleWithoutAutocreate.Close()

	testerMapWithoutAutocreate, err := bpfModuleWithoutAutocreate.GetMap("tester")
	if err != nil {
		log.Fatal(err)
	}

	err = testerMapWithoutAutocreate.SetAutocreate(false)
	if err != nil {
		log.Fatal(err)
	}

	isAutocreate = testerMapWithoutAutocreate.Autocreate()
	if isAutocreate {
		log.Fatal("Autocreate is true")
	}

	err = bpfModuleWithoutAutocreate.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}
}
