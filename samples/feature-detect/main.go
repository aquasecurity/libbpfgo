package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/libbpfgo"
)

func main() {

	// Open module
	bpfModule, err := libbpfgo.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	// Collect all BPF programs (iterate)
	iterator := bpfModule.Iterator()

	programs := []*libbpfgo.BPFProg{}
	referenceProg := iterator.NextProgram()
	for referenceProg != nil {
		programs = append(programs, referenceProg)
		referenceProg = iterator.NextProgram()
	}

	// Define a map for the various events and their programs (based on section format)
	eventsToPrograms := map[string][]*libbpfgo.BPFProg{}

	var (
		progName, eventName string
		progNameSplit       []string
	)
	for _, prog := range programs {
		progName = prog.GetName()
		progNameSplit = strings.Split(progName, "_")
		eventName = progNameSplit[0]
		eventsToPrograms[eventName] = append(eventsToPrograms[eventName], prog)
	}

	// For each specified event (os.Args),
	//    - Check what programs are available for that event
	//    - If there are multiple, see if the program type is supported
	//      (should be ordered by newest to oldest)
	var (
		chosenPrograms []*libbpfgo.BPFProg
	)

	// For each event that the user specified, check what programs are available that create that event
	for _, arg := range os.Args[1:] {
		programs := eventsToPrograms[arg]
		// For each program for this event, check the section, to see if the program type is supported
		for i := range programs {

			programType := programs[i].GetProgramType()
			programTypeIsSupported, err := libbpfgo.BPFProgramTypeIsSupported(programType)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(programType, programTypeIsSupported)
		}
	}

	for _, prog := range chosenPrograms {
		prog.SetAutoload(true)
		fmt.Printf("Will load %s %s\n", prog.GetName(), prog.GetSectionName())
	}
}

func ParseProgTypeString(str string) (libbpfgo.BPFProgType, error) {
	x := map[string]libbpfgo.BPFProgType{
		"fentry": libbpfgo.BPFProgTypeTracing,
		"fexit":  libbpfgo.BPFProgTypeTracing,
		"kprobe": libbpfgo.BPFProgTypeKprobe,
		// ...
	}
	progType := x[str]
	if progType == libbpfgo.BPFProgTypeUnspec {
		return progType, fmt.Errorf("unsupported bpf prog type: %s", str)
	}
	return progType, nil
}
