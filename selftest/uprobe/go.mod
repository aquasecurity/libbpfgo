module github.com/aquasecurity/libbpfgo/selftest/uprobe

go 1.22.0

toolchain go1.22.3

require (
	github.com/aquasecurity/libbpfgo v0.0.0
	github.com/aquasecurity/libbpfgo/helpers v0.0.0
)

require golang.org/x/sys v0.20.0 // indirect

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/helpers => ../../helpers
