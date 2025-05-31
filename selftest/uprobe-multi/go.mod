module github.com/aquasecurity/libbpfgo/selftest/uprobe

go 1.21

require (
	github.com/aquasecurity/libbpfgo v0.0.0
	github.com/aquasecurity/libbpfgo/helpers v0.0.0-00010101000000-000000000000
)

require golang.org/x/sys v0.25.0 // indirect

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/helpers => ../../helpers
