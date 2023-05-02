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

	bpf "github.com/aquasecurity/libbpfgo"
)

func exitWithErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		exitWithErr(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		exitWithErr(err)
	}

	prog, err := bpfModule.GetProgram("iter__task")
	if err != nil {
		exitWithErr(err)
	}

	link, err := prog.AttachIter(bpf.IterOpts{})
	if err != nil {
		exitWithErr(err)
	}

	reader, err := link.Reader()
	if err != nil {
		exitWithErr(err)
	}
	defer reader.Close()

	totalExecs := 10
	thisPid := syscall.Getpid()
	pids := make(map[int]*os.Process, 0)
	for i := 0; i < totalExecs; i++ {
		cmd := exec.Command("ping", "-w", "15", "8.8.8.8")
		err := cmd.Start()
		if err != nil {
			exitWithErr(err)
		}
		pids[cmd.Process.Pid] = cmd.Process
	}

	numberOfMatches := 0
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
		}
		if fields[2] == "ping" {
			ppid, err := strconv.Atoi(fields[0])
			if err != nil {
				exitWithErr(err)
			}
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				exitWithErr(err)
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
		exitWithErr(err)
	}
}
