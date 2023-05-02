package main

import "C"

import (
	"encoding/binary"
	"log"
	"os"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	mapModule, err := bpf.NewModuleFromFile("map.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer mapModule.Close()

	firstModule, err := bpf.NewModuleFromFile("first.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer firstModule.Close()

	secondModule, err := bpf.NewModuleFromFile("second.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer secondModule.Close()

	err = mapModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}
	err = firstModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}
	err = secondModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	firstProgram, err := firstModule.GetProgram("openat_fentry")
	if err != nil {
		log.Fatalf("couldn't get program1 %s\n", err)
	}

	link1, err := firstProgram.AttachGeneric()
	if err != nil {
		fmt.Println("couldn't attach prog")
		os.Exit(-1)
	}
	if link1.GetFd() == 0 {
		os.Exit(-1)
	}

	secondProgram, err := secondModule.GetProgram("mmap_fentry")
	if err != nil {
		log.Fatalf("couldn't get program2 %s\n", err)
	}

	link2, err := secondProgram.AttachGeneric()
	if err != nil {
		fmt.Println("couldn't attach prog")
		os.Exit(-1)
	}
	if link2.GetFd() == 0 {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	ringBuf, err := mapModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Println("couldn't init ringbuffer")
		os.Exit(-1)
	}
	ringBuf.Poll(300)
	gotOne, gotTwo := false, false

thisloop:
	for {
		b := <-eventsChannel
		switch binary.LittleEndian.Uint32(b) {
		case 1:
			gotOne = true
			if gotTwo {
				break thisloop
			}
		case 2:
			gotTwo = true
			if gotOne {
				break thisloop
			}
		default:
			log.Fatal("got invalid response from bpf")
		}
	}
}
