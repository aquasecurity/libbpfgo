package main

import (
	"errors"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	// Should not be supported before 5.8
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)
	if err == nil || isSupported {
		common.Error(errors.New("ringbuf is supported unexpectedly or no error"))
	}

	log.Println("Ringbuf is not supported as expected")
}
