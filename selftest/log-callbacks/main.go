package main

import "C"

import (
	"strings"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
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
		common.Error(err)
	}
	bpfModule.Close()

	if len(logOutput) != 1 {
		common.Error(fmt.Errorf("log output should contain only one output matching the string %s: %v", filterMatch, logOutput))
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
		common.Error(err)
	}
	bpfModule.Close()

	if len(logOutput) != 0 {
		common.Error(fmt.Errorf("log output should be empty: %v", logOutput))
	}
}
