package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"strings"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

type Event struct {
	Cookie uint64
}

type FunctionInfo struct {
	Name   string
	Offset uint64
}

const (
	bpfProgramName   = "uprobe__test_functions"
	bpfProgramObject = "main.bpf.o"
)

func main() {
	if len(os.Args) < 3 {
		common.Error(errors.New("wrong syntax"))
	}

	// Executable and expected symbols to be traced as positional arguments.
	binaryPath := os.Args[1]
	expectedSymbolNames := strings.Split(os.Args[2], ",")

	// Build cookie-to-function mapping for expected symbols.
	cookieToFunctionInfo := make(map[uint64]FunctionInfo)
	type probeTarget struct {
		offset uint64
		cookie uint64
	}
	var targets []probeTarget

	for _, name := range expectedSymbolNames {
		offset, err := common.SymbolToOffset(binaryPath, name)
		if err != nil {
			common.Error(fmt.Errorf("failed to resolve symbol %s: %v", name, err))
		}
		cookie := hash(name)
		targets = append(targets, probeTarget{offset: offset, cookie: cookie})
		cookieToFunctionInfo[cookie] = FunctionInfo{
			Name:   name,
			Offset: offset,
		}
	}

	bpfModule, err := bpf.NewModuleFromFile(bpfProgramObject)
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	if err = common.ResizeMap(bpfModule, "events", 8192); err != nil {
		common.Error(err)
	}

	log.Println("getting program")
	prog, err := bpfModule.GetProgram(bpfProgramName)
	if err != nil {
		common.Error(err)
	}

	log.Println("loading object")
	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	// Attach individual uprobes with per-attachment cookies.
	log.Println("attaching uprobes with cookies")
	for _, t := range targets {
		_, err = prog.AttachUprobeWithOpts(-1, binaryPath, t.offset, t.cookie)
		if err != nil {
			common.Error(fmt.Errorf("failed to attach uprobe at offset %d with cookie %d: %v", t.offset, t.cookie, err))
		}
	}

	log.Println("initializing events ring buffer")
	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		common.Error(err)
	}

	rb.Poll(300)

	// We get back from BPF and keep track of the function having traced via cookies.
	log.Println("consuming events")
	got := make(map[string]struct{})
	go func() {
		for {
			b := <-eventsChannel
			var event Event
			buf := bytes.NewBuffer(b)
			if err = binary.Read(buf, binary.LittleEndian, &event); err != nil {
				continue
			}
			cookie := event.Cookie
			info, ok := cookieToFunctionInfo[cookie]
			if !ok {
				continue
			}
			got[info.Name] = struct{}{}
		}
	}()
	// Just wait for a minimum amount of time for the tested tracee to call
	// the expected functions.
	time.Sleep(2 * time.Second)

	// Verify that all uprobes have been executed.
	for _, symbolName := range expectedSymbolNames {
		if _, ok := got[symbolName]; !ok {
			common.Error(fmt.Errorf("function %s has not been traced", symbolName))
		}
	}
	log.Println("all functions have been traced with correct cookies")

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	rb.Stop()
	rb.Stop()
	rb.Close()
	rb.Close()
	rb.Stop()
}

func hash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))

	return h.Sum64()
}
