package main

import "C"

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		Error(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		Error(err)
	}

	prog, err := bpfModule.GetProgram("cgroup__skb_ingress")
	if err != nil {
		Error(err)
	}

	cgroupRootDir := getCgroupV2RootDir()

	link, err := prog.AttachCgroupLegacy(cgroupRootDir, bpf.BPFAttachTypeCgroupInetIngress)
	if err != nil {
		Error(err)
	}

	eventsChannel := make(chan []byte, 100)
	lostChannel := make(chan uint64, 10)

	// initialize an eBPF perf buffer to receive events
	bpfPerfBuffer, err := bpfModule.InitPerfBuf(
		"perfbuffer", eventsChannel, lostChannel, 1,
	)
	if err != nil {
		Error(err)
	}

	// signal handling
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	// start eBPF perf buffer event polling
	bpfPerfBuffer.Start()

	go func() {
		_, err := exec.Command("ping", "127.0.0.1", "-c 5", "-w 10").Output()
		if err != nil {
			Error(err)
		}
		time.Sleep(time.Second)
		stop()
	}()

	testPassed := false
	numberOfEventsReceived := 0
LOOP:
	for {
		select {
		case raw := <-eventsChannel:
			value := int(binary.LittleEndian.Uint32(raw))
			if value == 20220823 {
				fmt.Println("Received correct event.")
				numberOfEventsReceived++
				if numberOfEventsReceived >= 5 {
					testPassed = true
					break LOOP
				}
			}
		case <-ctx.Done():
			break LOOP
		}
	}

	err = link.Destroy()
	if err != nil {
		Error(err)
	}

	if !testPassed {
		Error(fmt.Errorf("unable to get all packets"))
	}

	os.Exit(0)
}

func getCgroupV2RootDir() string {
	data, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read /proc/mounts failed: %+v\n", err)
		os.Exit(-1)
	}
	items := reCgroup2Mount.FindStringSubmatch(string(data))
	if len(items) < 2 {
		fmt.Fprintln(os.Stderr, "cgroupv2 is not mounted")
		os.Exit(-1)
	}
	return items[1]
}

func Error(err error) {
	_, fn, line, _ := runtime.Caller(1)
	log.Printf("ERROR: %s:%d %v\n", fn, line, err)
	os.Exit(1)
}
