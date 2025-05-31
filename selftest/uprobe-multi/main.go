package main

import "C"
import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"strings"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
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

var (
	excludePatterns = []string{"runtime.", "go:", "internal"}
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "wrong syntax")
		os.Exit(-1)
	}

	// Executable and expected symbols to be traced as positional arguments.
	binaryPath := os.Args[1]
	expectedSymbolNames := strings.Split(os.Args[2], ",")

	// We try to attach uprobes to the maximum amount of functions supported
	// as possible.
	symbols, err := getFunSyms(binaryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get function symbols: %v\n", err)
		os.Exit(1)
	}

	// Hashmap to correlate a cookie got from BPF to a function.
	cookieToFunctionInfo := make(map[uint64]FunctionInfo)

	// cookies and offsets bpf_program__attach_uprobe_multi_opts options.
	cookies := make([]uint64, 0)
	offsets := make([]uint64, 0)
	for _, symbol := range symbols {
		// Skip go runtime functions.
		if shouldExclude(symbol.Name, excludePatterns) {
			continue
		}

		offset, err := helpers.SymbolToOffset(binaryPath, symbol.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get offset for symbol %s: %v\n", symbol.Name, err)
			continue
		}
		cookie := hash(symbol.Name)
		cookies = append(cookies, cookie)
		offsets = append(offsets, uint64(offset))
		cookieToFunctionInfo[cookie] = FunctionInfo{
			Name:   symbol.Name,
			Offset: uint64(offset),
		}
	}

	bpfModule, err := bpf.NewModuleFromFile(bpfProgramObject)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	log.Println("getting program")
	prog, err := bpfModule.GetProgram(bpfProgramName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	log.Println("setting expected attach type uprobe multi before loading")
	if err = prog.SetExpectedAttachType(bpf.BPFAttachTypeTraceUprobeMulti); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	log.Println("loading object")
	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	log.Println("attaching multi uprobes")
	for i := 0; i < len(offsets); i += attachBatchSize {
		end := i + attachBatchSize
		if end > len(offsets) {
			end = len(offsets)
		}

		_, err = prog.AttachUprobeMulti(-1, binaryPath, offsets[i:end], cookies[i:end])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}

	log.Println("initializing events ring buffer")
	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
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
			fmt.Fprintf(os.Stderr, "function %s has not been traced\n", symbolName)
			os.Exit(1)
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

// getFunSyms returns the list of elf.Symbol of type function.
func getFunSyms(name string) ([]elf.Symbol, error) {
	var symbols []elf.Symbol

	b, err := elf.Open(name)
	defer b.Close()
	if err != nil {
		return nil, err
	}
	syms, err := b.Symbols()
	if err != nil {
		return nil, err
	}
	log.Printf("found %d symbols in %s\n", len(syms), name)
	log.Printf("showing first %d symbols\n", min(10, len(syms)))
	for i := 0; i < min(10, len(syms)); i++ {
		log.Printf("symbol %d: %v\n", i, syms[i])
	}
	for _, sym := range syms {
		// Exclude non-function symbols.
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		symbols = append(symbols, sym)
	}

	return symbols, nil
}

// shouldExclude returns whether a symbol should be excluded based
// on a list of string patterns.
func shouldExclude(symbol string, excludeList []string) bool {
	for _, v := range excludeList {
		if strings.Contains(symbol, v) {
			return true
		}
	}
	return false
}

func hash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))

	return h.Sum64()
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.SetMaxEntries(size); err != nil {
		return err
	}

	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func min[T interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64 | ~string
}](a, b T) T {
	if a < b {
		return a
	}
	return b
}
