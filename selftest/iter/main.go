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

	totalExecs := 10
	thisPid := syscall.Getpid()
	pids := make(map[int]*os.Process, 0)

	// Start processes with predictable running time to ensure they're captured
	for i := 0; i < totalExecs; i++ {
		cmd := exec.Command("sleep", "10")
		err := cmd.Start()
		if err != nil {
			common.Error(err)
		}
		pids[cmd.Process.Pid] = cmd.Process
	}
	defer func() {
		// Clean up any remaining processes
		for _, proc := range pids {
			_ = proc.Kill()
		}
	}()

	// Give processes time to start and be registered
	time.Sleep(2 * time.Second)

	reader, err := link.Reader()
	if err != nil {
		common.Error(err)
	}
	defer reader.Close()

	numberOfMatches := 0
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			common.Error(fmt.Errorf("invalid data retrieved: %s", scanner.Text()))
		}
		if fields[2] == "sleep" {
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
					_ = proc.Kill() // Kill the sleep process
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
