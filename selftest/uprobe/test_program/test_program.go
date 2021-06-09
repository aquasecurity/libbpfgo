package main

import (
	"os"
)

//go:noinline
func testFunction() int {
	if os.Getenv("SELFTEST_UPROBE_DO_BRANCH") == "y" {
		return 1
	}
	return 0
}

func main() {
	for {
		testFunction()
	}
}
