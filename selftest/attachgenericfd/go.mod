module github.com/aquasecurity/libbpfgo/selftest/attachgenericfd

go 1.21

require github.com/aquasecurity/libbpfgo v0.0.0

require (
	github.com/aquasecurity/libbpfgo/selftest/common v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.25.0
)

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/selftest/common => ../../selftest/common
