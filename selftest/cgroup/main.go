package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"

	bpf "github.com/aquasecurity/libbpfgo"
)

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	prog, err := bpfModule.GetProgram("cgroup__sock")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	cgroupRootDir := getCgroupV2RootDir()
	link, err := prog.AttachCgroup(cgroupRootDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link.GetFd() == 0 {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Start()
	numberOfEventsReceived := 0
	go func() {
		for i := 0; i < 10; i++ {
			_, err := exec.Command("ping", "localhost", "-c 1", "-w 1").Output()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(-1)
			}
		}
	}()

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()
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
