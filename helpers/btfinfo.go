package helpers

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
)

func fileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

// fileGrepUnique: returns first 'needle' string found in a file 'path'.
func fileGrepUnique(path string, needle string) string {
	file, _ := os.Open(path)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		if strings.Contains(scanner.Text(), needle) {
			return scanner.Text()
		}
	}
	return ""
}

func BTFEnabled() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// NewBTFInfo creates a BTFInfo object and runs DiscoverDistro()
// on its creation. It returns nil if no discovery data was
// avalable. To get specific error from DiscoverDistro method,
// user should create a BTFInfo struct and call DiscoverDistro
// by itself.
func NewBTFInfo() *BTFInfo {
	btfi := new(BTFInfo)
	if err := btfi.DiscoverDistro(); err != nil {
		return nil
	}
	return btfi
}

// BTFInfo object contains all BTF relevant information so user
// is able to not only discover underlaying Linux distribution
// but also, in future, manage acquisition & cache of external
// BTF files to be used by the BPF CO-RE objects.
type BTFInfo struct {
	distroId      string
	distroVersion string
	distroKernel  string
}

func (btfi *BTFInfo) GetDistroId() string {
	return btfi.distroId
}

func (btfi *BTFInfo) GetDistroVer() string {
	return btfi.distroVersion
}

func (btfi *BTFInfo) GetDistroKernel() string {
	return btfi.distroKernel
}

// DiscoverDistro tries to discover running Linux distribution either by reading
// /etc/os-releases (https://man7.org/linux/man-pages/man5/os-release.5.html) or
// by interpreting the version out of uname(2) system call.
func (btfi *BTFInfo) DiscoverDistro() error {

	x := unix.Utsname{}
	if err := unix.Uname(&x); err != nil {
		return fmt.Errorf("could not determine uname release: %v", err)
	}
	ker := string(x.Release[:])

	osrelease := "/etc/os-release"
	if fileExists(osrelease) {
		id := fileGrepUnique(osrelease, "ID=")
		id = id[strings.Index(id, "=")+1:]
		id = strings.ReplaceAll(id, "\"", "")
		ver := fileGrepUnique(osrelease, "VERSION_ID=")
		ver = ver[strings.Index(ver, "=")+1:]
		ver = strings.ReplaceAll(ver, "\"", "")
		btfi.distroId = id
		btfi.distroVersion = ver
		btfi.distroKernel = ker
		return nil
	}

	// real examples:
	// fedora:      4.18.16-300.fc29
	// centos:      3.10.0-1160.31.1.el7.centos.x86_64
	if strings.Contains(ker, "fc") {
		btfi.distroId = "fedora"
		btfi.distroVersion = ker[strings.Index(ker, "fc")+2:]
		btfi.distroKernel = ker[:strings.Index(ker, ".fc")]
		return nil
	} else if strings.Contains(ker, "centos") {
		btfi.distroId = "centos"
		t := ker
		t = t[strings.Index(t, "el")+2:]
		t = t[:strings.Index(t, ".")]
		btfi.distroVersion = t
		btfi.distroKernel = ker[:strings.Index(ker, ".el")]
		return nil
	} // else if may continue...

	return errors.New("distribution could not be discovered")
}
