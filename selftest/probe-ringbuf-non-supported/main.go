package main

import (
	"errors"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	kernelVersion := common.GetKernelVersion()
	kernelRelease := common.GetKernelRelease()
	log.Printf("Running on kernel: %s", kernelVersion)
	log.Printf("Kernel release: %s", kernelRelease)

	// Should not be supported before 5.8
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)

	log.Printf("BPFMapTypeIsSupported(MapTypeRingbuf) returned: isSupported=%v, err=%v", isSupported, err)

	// Handle any error from the BPF probing function itself
	if err != nil {
		log.Printf("Ringbuf probing returned an error as expected: %v", err)
		return // This is expected behavior for unsupported features
	}

	// We expect isSupported = false with no error
	if isSupported {
		log.Printf("WARNING: ringbuf is unexpectedly supported on this kernel")
		log.Printf("This may indicate a libbpf probing issue or kernel backport")
		common.Error(errors.New("ringbuf is unexpectedly supported on this kernel (expected not supported before 5.8)"))
	}

	log.Println("Ringbuf is not supported as expected")
}
