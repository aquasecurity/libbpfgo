package main

import "C"

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

	// Give the iterator a moment to be fully set up before starting processes
	log.Printf("Sleeping 1 second to ensure iterator is ready...")
	time.Sleep(1 * time.Second)

	totalExecs := 10
	pids := make(map[int]*os.Process, 0)

	// Start processes with predictable running time to ensure they're captured
	log.Printf("Starting %d sleep processes...", totalExecs)
	for i := 0; i < totalExecs; i++ {
		cmd := exec.Command("sleep", "10")
		err := cmd.Start()
		if err != nil {
			common.Error(err)
		}
		pids[cmd.Process.Pid] = cmd.Process
		log.Printf("Started sleep process with PID %d", cmd.Process.Pid)
	}
	defer func() {
		// Clean up any remaining processes
		for _, proc := range pids {
			_ = proc.Kill()
		}
	}()

	// Give processes time to start and be registered
	log.Printf("Sleeping for 5 seconds to allow processes to register...")
	time.Sleep(5 * time.Second)

	reader, err := link.Reader()
	if err != nil {
		common.Error(err)
	}
	defer reader.Close()

	numberOfMatches := 0
	scanner := bufio.NewScanner(reader)
	log.Println("Reading iterator output:")
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			common.Error(fmt.Errorf("invalid data retrieved: %s", line))
		}

		log.Printf("[iter] %s", line)
		if fields[1] == "sleep" {
			pid, err := strconv.Atoi(fields[0])
			if err != nil {
				common.Error(err)
			}
			if proc, found := pids[pid]; found {
				numberOfMatches++
				log.Printf("Matched sleep process: pid=%d", pid)
				_ = proc.Kill() // Kill the sleep process
			}
		}
		if numberOfMatches == totalExecs {
			break
		}
	}

	if numberOfMatches != totalExecs {
		err := fmt.Errorf("expect numberOfMatches == %d but got %d", totalExecs, numberOfMatches)
		common.Error(err)
	} else {
		log.Printf("All %d sleep processes matched successfully", totalExecs)
	}
}
