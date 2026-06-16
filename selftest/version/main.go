package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	cmd := exec.Command("git", "describe", "--tags")
	cmd.Dir = "../../libbpf"

	b, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to reading libbpf_version.h if git fails (e.g. shallow clone)
		major, minor := getLibbpfVersionFromHeader()
		if major == -1 {
			common.Error(fmt.Errorf("failed to determine libbpf version from git and header: %v", err))
		}
		version := fmt.Sprintf("v%d.%d", major, minor)
		if version != libbpfgo.LibbpfVersionString() {
			common.Error(fmt.Errorf("libbpf version %s does not match expected version %s (from header)", libbpfgo.LibbpfVersionString(), version))
		}
		return
	}

	version := strings.TrimSpace(string(b))
	// libbpf doesn't put the patch version in exported version
	// symbols, so use just prefix to exclude it
	if !strings.HasPrefix(version, libbpfgo.LibbpfVersionString()) {
		common.Error(fmt.Errorf("libbpf version %s does not match expected version %s", libbpfgo.LibbpfVersionString(), version))
	}
}

func getLibbpfVersionFromHeader() (int, int) {
	data, err := os.ReadFile("../../libbpf/src/libbpf_version.h")
	if err != nil {
		return -1, -1
	}
	major := -1
	minor := -1
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LIBBPF_MAJOR_VERSION") {
			fmt.Sscanf(line, "#define LIBBPF_MAJOR_VERSION %d", &major)
		}
		if strings.Contains(line, "LIBBPF_MINOR_VERSION") {
			fmt.Sscanf(line, "#define LIBBPF_MINOR_VERSION %d", &minor)
		}
	}
	return major, minor
}
