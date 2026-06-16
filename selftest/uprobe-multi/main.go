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
	attachBatchSize  = 256
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

	// Hashmap to correlate a cookie got from BPF to a function.
	cookieToFunctionInfo := make(map[uint64]FunctionInfo)

	// cookies and offsets bpf_program__attach_uprobe_multi_opts options.
	cookies := make([]uint64, 0, len(expectedSymbolNames))
	offsets := make([]uint64, 0, len(expectedSymbolNames))

	for _, symbolName := range expectedSymbolNames {
		offset, err := common.SymbolToOffset(binaryPath, symbolName)
		if err != nil {
			common.Error(fmt.Errorf("failed to resolve symbol %s in %s: %v", symbolName, binaryPath, err))
		}
		cookie := hash(symbolName)
		cookies = append(cookies, cookie)
		offsets = append(offsets, offset)
		cookieToFunctionInfo[cookie] = FunctionInfo{Name: symbolName, Offset: offset}
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

	log.Println("setting expected attach type uprobe multi before loading")
	if err = prog.SetExpectedAttachType(bpf.BPFAttachTypeTraceUprobeMulti); err != nil {
		common.Error(err)
	}

	log.Println("loading object")
	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	log.Println("attaching multi uprobes")
	for i := 0; i < len(offsets); i += attachBatchSize {
		end := i + attachBatchSize
		if end > len(offsets) {
			end = len(offsets)
		}

		_, err = prog.AttachUprobeMulti(-1, binaryPath, offsets[i:end], cookies[i:end])
		if err != nil {
			common.Error(err)
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
				// Error handling is out of scope for this test.
				continue
			}
			cookie := event.Cookie
			info, ok := cookieToFunctionInfo[cookie]
			if !ok {
				// Error handling is out of scope for this test.
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
	log.Println("all functions have been traced")

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
