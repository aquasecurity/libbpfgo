package helpers

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type OSReleaseID uint32

func (o OSReleaseID) String() string {
	return OSReleaseIDToString[o]
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

// StringToOSReleaseID is a map of supported distributions
var StringToOSReleaseID = map[string]OSReleaseID{
	"ubuntu": UBUNTU,
	"fedora": FEDORA,
	"arch":   ARCH,
	"debian": DEBIAN,
	"centos": CENTOS,
	"stream": STREAM,
	"alma":   ALMA,
}

// OSReleaseIDToString is a map of supported distributions
var OSReleaseIDToString = map[OSReleaseID]string{
	UBUNTU: "ubuntu",
	FEDORA: "fedora",
	ARCH:   "arch",
	DEBIAN: "debian",
	CENTOS: "centos",
	STREAM: "stream",
	ALMA:   "alma",
}

const (
	OS_NAME OSReleaseField = iota + 0
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

type OSReleaseField uint32

func (o OSReleaseField) String() string {
	return OSReleaseFieldToString[o]
}

// StringToOSReleaseField is a map of os-release file fields
var StringToOSReleaseField = map[string]OSReleaseField{
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
var OSReleaseFieldToString = map[OSReleaseField]string{
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

// UnameRelease gets the version string of the current running kernel
func UnameRelease() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", fmt.Errorf("could not get utsname")
	}

	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}

	ver := string(buf[:])
	ver = strings.Trim(ver, "\x00")

	return ver, nil
}

// OSBTFEnabled checks if kernel has embedded BTF vmlinux file
func OSBTFEnabled() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")

	return err == nil
}

// NewOSInfo creates a OSInfo object and runs DiscoverDistro() on its creation
// This is a more complete approach than NewOSInfoRelease only
func NewOSInfo(releaseFilePath string) (*OSInfo, error) {
	info := OSInfo{}

	if err := info.DiscoverDistro(releaseFilePath); err != nil {
		return nil, err
	}

	return &info, nil
}

// NewOSInfoRelease creates a OSInfo object and runs DiscoverRelease() on its creation
// This is a less complete approach than NewOSInfo call, recommended
func NewOSInfoRelease() (*OSInfo, error) {
	info := OSInfo{}

	if err := info.DiscoverRelease(); err != nil {
		return nil, err
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
	OSReleaseInfo map[OSReleaseField]string
	OSRelease     OSReleaseID
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

func (btfi *OSInfo) DiscoverRelease() error {
	var err error

	if btfi.OSReleaseInfo == nil {
		btfi.OSReleaseInfo = make(map[OSReleaseField]string)
	}

	if btfi.OSReleaseInfo[OS_KERNEL_RELEASE], err = UnameRelease(); err != nil {
		return fmt.Errorf("could not determine uname release: %w", err)
	}

	return nil
}

// DiscoverDistro discover running Linux distribution information by
// reading /etc/os-releases and UTS name.
// (https://man7.org/linux/man-pages/man5/os-release.5.html)
func (btfi *OSInfo) DiscoverDistro(releaseFilePath string) error {
	if releaseFilePath == "" {
		releaseFilePath = "/etc/os-release"
	}

	if _, err := os.Stat(releaseFilePath); err != nil {
		return err
	}

	if btfi.OSReleaseInfo == nil {
		btfi.OSReleaseInfo = make(map[OSReleaseField]string)
	}

	if err := btfi.DiscoverRelease(); err != nil {
		return err
	}

	file, _ := os.Open(releaseFilePath)
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for i := 1; scanner.Scan(); i++ {
		val := strings.Split(scanner.Text(), "=")
		if len(val) != 2 {
			continue
		}

		keyID := StringToOSReleaseField[val[0]]
		if keyID == 0 { // could not find KEY= from os-release in consts
			continue
		}

		btfi.OSReleaseInfo[keyID] = val[1]

		if keyID == OS_ID {
			btfi.OSRelease = StringToOSReleaseID[strings.ToLower(val[1])]
		}
	}

	return nil
}
