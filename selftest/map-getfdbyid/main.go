package main

import "C"

import (
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		log.Fatal(err)
	}

	// Get info about the "tester" map
	infoTester, err := bpf.GetMapInfoByFD(testerMap.FileDescriptor())
	if err != nil {
		log.Fatal(err)
	}

	// Get a new FD pointing to the "tester" map
	newFD, err := bpf.GetMapFDByID(infoTester.ID)
	if err != nil {
		log.Fatal(err)
	}

	// Get info about the "tester" map again, this time using the new FD
	infoNewFD, err := bpf.GetMapInfoByFD(newFD)
	if err != nil {
		log.Fatal(err)
	}

	if infoTester.Type != infoNewFD.Type {
		log.Fatal("Types do not match")
	}
	if infoTester.ID != infoNewFD.ID {
		log.Fatal("IDs do not match")
	}
	if infoTester.KeySize != infoNewFD.KeySize {
		log.Fatal("Key sizes do not match")
	}
	if infoTester.ValueSize != infoNewFD.ValueSize {
		log.Fatal("Value sizes do not match")
	}
	if infoTester.MaxEntries != infoNewFD.MaxEntries {
		log.Fatal("Max entries do not match")
	}
	if infoTester.MapFlags != infoNewFD.MapFlags {
		log.Fatal("Map flags do not match")
	}
	if infoTester.Name != infoNewFD.Name {
		log.Fatal("Names do not match")
	}
	if infoTester.IfIndex != infoNewFD.IfIndex {
		log.Fatal("Ifindexes do not match")
	}
	if infoTester.NetnsDev != infoNewFD.NetnsDev {
		log.Fatal("Netns do not match")
	}
	if infoTester.NetnsIno != infoNewFD.NetnsIno {
		log.Fatal("Netns inodes do not match")
	}
	if infoTester.BTFID != infoNewFD.BTFID {
		log.Fatal("BTF IDs do not match")
	}
	if infoTester.BTFKeyTypeID != infoNewFD.BTFKeyTypeID {
		log.Fatal("BTF key type IDs do not match")
	}
	if infoTester.BTFValueTypeID != infoNewFD.BTFValueTypeID {
		log.Fatal("BTF value type IDs do not match")
	}
	if infoTester.MapExtra != infoNewFD.MapExtra {
		log.Fatal("Map extras do not match")
	}
}
