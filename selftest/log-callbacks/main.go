package main

import "C"

import (
	"os"
	"strings"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

var logOutput []string

// log is a handler to save the log output
func log(level int, msg string) {
	logOutput = append(logOutput, msg)
}

func main() {
	//
	// Filter example 1: filter out all outputs but containing "found program 'kprobe__sys_mmap'"
	//
	filterMatch := "found program 'kprobe__sys_mmap'"
	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: log,
		LogFilters: []func(libLevel int, msg string) bool{
			func(libLevel int, msg string) bool {
				return !strings.Contains(msg, filterMatch)
			},
		},
	})

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	bpfModule.Close()

	if len(logOutput) != 1 {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Log output should contain only one output matching the string: %s", filterMatch))
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Log output: %v", logOutput))
		os.Exit(-1)
	}

	// clean logOutput
	logOutput = []string{}

	//
	// Filter example 2: filter out all outputs which level is LibbpfDebugLevel
	//
	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: log,
		LogFilters: []func(libLevel int, msg string) bool{
			func(libLevel int, msg string) bool {
				return libLevel == bpf.LibbpfDebugLevel
			},
		},
	})

	bpfModule, err = bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	bpfModule.Close()

	if len(logOutput) != 0 {
		fmt.Fprintln(os.Stderr, "Log output should be empty")
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Log output: %v", logOutput))
		os.Exit(-1)
	}
}
