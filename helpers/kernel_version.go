package helpers

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// UnameRelease gets the version string of the current running kernel
func UnameRelease() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return ""
	}
	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}
	ver := string(buf[:])
	ver = strings.Trim(ver, "\x00")
	return ver
}

func kernelIsAtLeast(verMajor, verMinor int) (bool, error) {
	ver := UnameRelease()
	if ver == "" {
		return false, fmt.Errorf("could not determine current release")
	}
	verSplit := strings.Split(ver, ".")
	if len(verSplit) < 2 {
		return false, fmt.Errorf("invalid version returned by uname")
	}
	major, err := strconv.Atoi(verSplit[0])
	if err != nil {
		return false, fmt.Errorf("invalid major number: %s", verSplit[0])
	}
	minor, err := strconv.Atoi(verSplit[1])
	if err != nil {
		return false, fmt.Errorf("invalid minor number: %s", verSplit[1])
	}
	if ((major == verMajor) && (minor >= verMinor)) || (major > verMajor) {
		return true, nil
	}
	return false, nil
}
