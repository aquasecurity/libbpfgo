package main

import "C"

import (
	"os"
	"strings"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

var logOutput []string

func log(level int, msg string, keyValues ...interface{}) {
	logOutput = append(logOutput, msg)
}

func main() {
	filterMatch := "found program 'kprobe__sys_mmap'"
	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: log, // use log() as a handler for libbpf outputs that are not excluded by LogFilters
		LogFilters: []func(libLevel int, msg string) bool{
			func(libLevel int, msg string) bool {
				// filter all output but containing "found program 'kprobe__sys_mmap'"
				return !strings.Contains(msg, filterMatch)
			},
		},
	})

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if len(logOutput) != 1 {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Log output should contain only one output matching the string: %s", filterMatch))
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Log output: %v", logOutput))
		os.Exit(-1)
	}
}
