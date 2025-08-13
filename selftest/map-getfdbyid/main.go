package main

import "C"

import (
	"errors"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		common.Error(err)
	}

	// Get info about the "tester" map
	infoTester, err := bpf.GetMapInfoByFD(testerMap.FileDescriptor())
	if err != nil {
		common.Error(err)
	}

	// Get a new FD pointing to the "tester" map
	newFD, err := bpf.GetMapFDByID(infoTester.ID)
	if err != nil {
		common.Error(err)
	}
	if newFD == testerMap.FileDescriptor() {
		common.Error(errors.New("new FD should be different from the old one"))
	}

	// Get info about the "tester" map again, this time using the new FD
	infoNewFD, err := bpf.GetMapInfoByFD(newFD)
	if err != nil {
		common.Error(err)
	}

	if infoTester.Type != infoNewFD.Type {
		common.Error(fmt.Errorf("types do not match: %s != %s", infoTester.Type, infoNewFD.Type))
	}
	if infoTester.ID != infoNewFD.ID {
		common.Error(fmt.Errorf("IDs do not match: %d != %d", infoTester.ID, infoNewFD.ID))
	}
	if infoTester.KeySize != infoNewFD.KeySize {
		common.Error(fmt.Errorf("key sizes do not match: %d != %d", infoTester.KeySize, infoNewFD.KeySize))
	}
	if infoTester.ValueSize != infoNewFD.ValueSize {
		common.Error(fmt.Errorf("value sizes do not match: %d != %d", infoTester.ValueSize, infoNewFD.ValueSize))
	}
	if infoTester.MaxEntries != infoNewFD.MaxEntries {
		common.Error(fmt.Errorf("max entries do not match: %d != %d", infoTester.MaxEntries, infoNewFD.MaxEntries))
	}
	if infoTester.MapFlags != infoNewFD.MapFlags {
		common.Error(fmt.Errorf("map flags do not match: %d != %d", infoTester.MapFlags, infoNewFD.MapFlags))
	}
	if infoTester.Name != infoNewFD.Name {
		common.Error(fmt.Errorf("names do not match: %s != %s", infoTester.Name, infoNewFD.Name))
	}
	if infoTester.IfIndex != infoNewFD.IfIndex {
		common.Error(fmt.Errorf("ifindexes do not match: %d != %d", infoTester.IfIndex, infoNewFD.IfIndex))
	}
	if infoTester.NetnsDev != infoNewFD.NetnsDev {
		common.Error(fmt.Errorf("netns dev do not match: %d != %d", infoTester.NetnsDev, infoNewFD.NetnsDev))
	}
	if infoTester.NetnsIno != infoNewFD.NetnsIno {
		common.Error(fmt.Errorf("netns inodes do not match: %d != %d", infoTester.NetnsIno, infoNewFD.NetnsIno))
	}
	if infoTester.BTFID != infoNewFD.BTFID {
		common.Error(fmt.Errorf("BTF IDs do not match: %d != %d", infoTester.BTFID, infoNewFD.BTFID))
	}
	if infoTester.BTFKeyTypeID != infoNewFD.BTFKeyTypeID {
		common.Error(fmt.Errorf("BTF key type IDs do not match: %d != %d", infoTester.BTFKeyTypeID, infoNewFD.BTFKeyTypeID))
	}
	if infoTester.BTFValueTypeID != infoNewFD.BTFValueTypeID {
		common.Error(fmt.Errorf("BTF value type IDs do not match: %d != %d", infoTester.BTFValueTypeID, infoNewFD.BTFValueTypeID))
	}
	if infoTester.MapExtra != infoNewFD.MapExtra {
		common.Error(fmt.Errorf("map extras do not match: %v != %v", infoTester.MapExtra, infoNewFD.MapExtra))
	}
}
