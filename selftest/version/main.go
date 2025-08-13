package main

import (
	"fmt"
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
		common.Error(err)
	}

	// libbpf doesn't put the patch version in exported version
	// symbols, so use just prefix to exclude it
	if strings.HasPrefix(libbpfgo.LibbpfVersionString(), string(b)) {
		common.Error(fmt.Errorf("libbpf version %s does not match expected version %s", libbpfgo.LibbpfVersionString(), b))
	}
}
