package main

import (
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	// Should not be supported before 5.8
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)
	if err == nil || isSupported {
		fmt.Fprintln(os.Stderr, "Ringbuf is supported unexpectedly or no error")
		os.Exit(-1)
	}

	fmt.Fprintln(os.Stdout, "Ringbuf is not supported as expected")
}
