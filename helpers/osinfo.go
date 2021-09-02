package helpers

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type OSReleaseID uint32

func (o OSReleaseID) String() string {
	return osReleaseIDToString[o]
}

const (
	UBUNTU OSReleaseID = iota + 1
	FEDORA
	ARCH
	DEBIAN
	CENTOS
	STREAM
	ALMA
)

// stringToOSReleaseID is a map of supported distributions
var stringToOSReleaseID = map[string]OSReleaseID{
	"ubuntu": UBUNTU,
	"fedora": FEDORA,
	"arch":   ARCH,
	"debian": DEBIAN,
	"centos": CENTOS,
	"stream": STREAM,
	"alma":   ALMA,
}

// osReleaseIDToString is a map of supported distributions
var osReleaseIDToString = map[OSReleaseID]string{
	UBUNTU: "ubuntu",
	FEDORA: "fedora",
	ARCH:   "arch",
	DEBIAN: "debian",
	CENTOS: "centos",
	STREAM: "stream",
	ALMA:   "alma",
}

const (
	OS_NAME osReleaseField = iota + 0
	OS_ID
	OS_ID_LIKE
	OS_PRETTY_NAME
	OS_VARIANT
	OS_VARIANT_ID
	OS_VERSION
	OS_VERSION_ID
	OS_VERSION_CODENAME
	OS_BUILD_ID
	OS_IMAGE_ID
	OS_IMAGE_VERSION
	OS_KERNEL_RELEASE // not part of default os-release, but we can use it here to facilitate things
)

type osReleaseField uint32

func (o osReleaseField) String() string {
	return osReleaseFieldToString[o]
}

// StringToOSReleaseField is a map of os-release file fields
var stringToOSReleaseField = map[string]osReleaseField{
	"NAME":             OS_NAME,
	"ID":               OS_ID,
	"ID_LIKE":          OS_ID_LIKE,
	"PRETTY_NAME":      OS_PRETTY_NAME,
	"VARIANT":          OS_VARIANT,
	"VARIANT_ID":       OS_VARIANT_ID,
	"VERSION":          OS_VERSION,
	"VERSION_ID":       OS_VERSION_ID,
	"VERSION_CODENAME": OS_VERSION_CODENAME,
	"BUILD_ID":         OS_BUILD_ID,
	"IMAGE_ID":         OS_IMAGE_ID,
	"IMAGE_VERSION":    OS_IMAGE_VERSION,
	"KERNEL_RELEASE":   OS_KERNEL_RELEASE,
}

// OSReleaseFieldToString is a map of os-release file fields
var osReleaseFieldToString = map[osReleaseField]string{
	OS_NAME:             "NAME",
	OS_ID:               "ID",
	OS_ID_LIKE:          "ID_LIKE",
	OS_PRETTY_NAME:      "PRETTY_NAME",
	OS_VARIANT:          "VARIANT",
	OS_VARIANT_ID:       "VARIANT_ID",
	OS_VERSION:          "VERSION",
	OS_VERSION_ID:       "VERSION_ID",
	OS_VERSION_CODENAME: "VERSION_CODENAME",
	OS_BUILD_ID:         "BUILD_ID",
	OS_IMAGE_ID:         "IMAGE_ID",
	OS_IMAGE_VERSION:    "IMAGE_VERSION",
	OS_KERNEL_RELEASE:   "KERNEL_RELEASE",
}

// CompareOSBaseKernelRelease will compare two given kernel version/release
// strings and return -1, 0 or 1 if given version is less, equal or bigger,
// respectively, than the given one
//
// Examples of $(uname -r):
//
// 5.11.0-31-generic (ubuntu)
// 4.18.0-305.12.1.el8_4.x86_64 (alma)
// 4.18.0-338.el8.x86_64 (stream8)
// 4.18.0-305.7.1.el8_4.centos.x86_64 (centos)
// 4.18.0-305.7.1.el8_4.centos.plus.x86_64 (centos + plus repo)
// 5.13.13-arch1-1 (archlinux)
//
func CompareOSBaseKernelRelease(base, given string) int {
	b := strings.Split(base, "-") // [base]-xxx
	b = strings.Split(b[0], ".")  // [major][minor][patch]

	g := strings.Split(given, "-")
	g = strings.Split(g[0], ".")

	for n := 0; n <= 2; n++ {
		i, _ := strconv.Atoi(g[n])
		j, _ := strconv.Atoi(b[n])

		if i > j {
			return 1 // given is bigger
		} else if i < j {
			return -1 // given is less
		} else {
			continue // equal
		}
	}

	return 0 // equal
}

// OSBTFEnabled checks if kernel has embedded BTF vmlinux file
func OSBTFEnabled() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux") // TODO: accept a KernelConfig param and check for CONFIG_DEBUG_INFO_BTF=y, or similar

	return err == nil
}

// GetOSInfo creates a OSInfo object and runs discoverOSDistro() on its creation
func GetOSInfo() (*OSInfo, error) {
	info := OSInfo{}
	var err error

	if info.OSReleaseInfo == nil {
		info.OSReleaseInfo = make(map[osReleaseField]string)
	}

	info.OSReleaseInfo[OS_KERNEL_RELEASE], err = UnameRelease()
	if err != nil {
		return &info, fmt.Errorf("could not determine uname release: %w", err)
	}

	info.OSReleaseFilePath, err = checkEnvPath("LIBBPFGO_OSRELEASE_FILE") // useful if users wants to mount host os-release in a container
	if err != nil {
		return &info, err
	} else if info.OSReleaseFilePath == "" {
		info.OSReleaseFilePath = "/etc/os-release"
	}

	if err = info.discoverOSDistro(); err != nil {
		return &info, err
	}

	return &info, nil
}

// OSInfo object contains all OS relevant information
//
// OSRelease is relevant to examples such as:
// 1) OSInfo.OSReleaseInfo[helpers.OS_KERNEL_RELEASE]) => will provide $(uname -r) string
// 2) if OSInfo.OSRelease == helpers.UBUNTU => {} will allow to run code in specific distros
//
type OSInfo struct {
	OSReleaseInfo     map[osReleaseField]string
	OSRelease         OSReleaseID
	OSReleaseFilePath string
}

// CompareOSBaseKernelRelease will compare a given kernel version/release string
// to the current running version and return -1, 0 or 1 if given version is less,
// equal or bigger, respectively, than running one. Example:
//
// OSInfo.CompareOSBaseKernelRelease("5.11.0"))
//
func (btfi *OSInfo) CompareOSBaseKernelRelease(version string) int {
	return CompareOSBaseKernelRelease(btfi.OSReleaseInfo[OS_KERNEL_RELEASE], version)
}

// discoverOSDistro discover running Linux distribution information by reading UTS and
// the /etc/os-releases file (https://man7.org/linux/man-pages/man5/os-release.5.html)
func (btfi *OSInfo) discoverOSDistro() error {
	var err error

	if btfi.OSReleaseFilePath == "" {
		return fmt.Errorf("should specify os-release filepath")
	}

	file, err := os.Open(btfi.OSReleaseFilePath)
	if err != nil {
		return err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		val := strings.Split(scanner.Text(), "=")
		if len(val) != 2 {
			continue
		}
		keyID := stringToOSReleaseField[val[0]]
		if keyID == 0 { // could not find KEY= from os-release in consts
			continue
		}
		btfi.OSReleaseInfo[keyID] = val[1]
		if keyID == OS_ID {
			btfi.OSRelease = stringToOSReleaseID[strings.ToLower(val[1])]
		}
	}

	return nil
}
