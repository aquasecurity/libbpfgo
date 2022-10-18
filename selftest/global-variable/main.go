package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

func exitWithErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}

type Event struct {
	Sum uint64
	A   [6]byte
}

type Config struct {
	A uint64
	B [6]byte
}

func initGlobalVariables(bpfModule *bpf.Module, variables map[string]interface{}) {
	for name, value := range variables {
		if err := bpfModule.InitGlobalVariable(name, value); err != nil {
			exitWithErr(err)
		}
	}
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		exitWithErr(err)
	}
	defer bpfModule.Close()

	initGlobalVariables(bpfModule, map[string]interface{}{
		"abc":    uint32(9),
		"efg":    uint32(80),
		"foobar": Config{A: uint64(700), B: [6]byte{'a', 'b'}},
		"foo":    uint64(6000),
		"bar":    uint32(50000),
		"baz":    uint32(400000),
		"qux":    uint32(3000000),
	})

	if err := bpfModule.BPFLoadObject(); err != nil {
		exitWithErr(err)
	}

	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		exitWithErr(err)
	}
	if _, err := prog.AttachKprobe("__x64_sys_mmap"); err != nil {
		exitWithErr(err)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		exitWithErr(err)
	}

	rb.Start()
	go func() {
		time.Sleep(time.Second)
		syscall.Mmap(999, 999, 999, 1, 1)
	}()

	b := <-eventsChannel

	var event Event
	err = binary.Read(bytes.NewReader(b), binary.LittleEndian, &event)
	if err != nil {
		exitWithErr(err)
	}

	expect := Event{
		Sum: 9 + 80 + 700 + 6000 + 50000 + 400000 + 3000000,
		A:   [6]byte{'a', 'b'},
	}
	if !reflect.DeepEqual(event, expect) {
		fmt.Fprintf(os.Stderr, "want %v but got %v\n", expect, event)
		os.Exit(1)
	}

	rb.Stop()
	rb.Close()
}
