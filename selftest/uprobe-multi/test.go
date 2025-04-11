package main

import (
	"os"
	"time"
)

//go:noinline
func fooFunction() int {
	if os.Getenv("SELFTEST_UPROBE_DO_BRANCH") == "y" {
		return 1
	}
	return 0
}

//go:noinline
func barFunction() int {
	if os.Getenv("SELFTEST_UPROBE_DO_BRANCH") == "y" {
		return 1
	}
	return 0
}

//go:noinline
func bazFunction() int {
	if os.Getenv("SELFTEST_UPROBE_DO_BRANCH") == "y" {
		return 1
	}
	return 0
}

func main() {
	for {
		time.Sleep(100 * time.Millisecond)
		fooFunction()
		time.Sleep(100 * time.Millisecond)
		barFunction()
		time.Sleep(100 * time.Millisecond)
		bazFunction()
	}
}
