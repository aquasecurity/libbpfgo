package main

import "C"

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	prog, err := bpfModule.GetProgram("iter__task")
	if err != nil {
		common.Error(err)
	}

	link, err := prog.AttachIter(bpf.IterOpts{})
	if err != nil {
		common.Error(err)
	}

	reader, err := link.Reader()
	if err != nil {
		common.Error(err)
	}
	defer reader.Close()

	totalExecs := 10
	thisPid := syscall.Getpid()
	pids := make(map[int]*os.Process, 0)
	for i := 0; i < totalExecs; i++ {
		cmd := exec.Command("ping", "-c1", "-w1", "0.0.0.0")
		err := cmd.Start()
		if err != nil {
			common.Error(err)
		}
		pids[cmd.Process.Pid] = cmd.Process
	}

	time.Sleep(5 * time.Second)

	numberOfMatches := 0
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			common.Error(fmt.Errorf("invalid data retrieved: %s", scanner.Text()))
		}
		if fields[2] == "ping" {
			ppid, err := strconv.Atoi(fields[0])
			if err != nil {
				common.Error(err)
			}
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				common.Error(err)
			}
			if proc, found := pids[pid]; found {
				if ppid == thisPid {
					numberOfMatches++
					proc.Kill()
				}
			}
		}
		if numberOfMatches == totalExecs {
			break
		}
	}
	if numberOfMatches != totalExecs {
		err := fmt.Errorf("expect numberOfMatches == %d but got %d", totalExecs, numberOfMatches)
		common.Error(err)
	}
}
