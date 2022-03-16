package main

import (
	"log"
	"os/exec"
	"strings"

	"github.com/aquasecurity/libbpfgo"
)

func main() {

	cmd := exec.Command("git", "describe", "--tags")
	cmd.Dir = "../../libbpf"

	b, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(string(b), err)
	}

	// libbpf doesn't put the patch version in exported version
	// symbols, so use just prefix to exclude it
	if strings.HasPrefix(libbpfgo.LibbpfVersionString(), string(b)) {
		log.Fatalf("Error reading exported symbols for libbpf major and minor version: %s is not %s", libbpfgo.LibbpfVersionString(), b)
	}
}
