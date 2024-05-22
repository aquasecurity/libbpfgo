module github.com/aquasecurity/libbpfgo/selftest/global-variable

go 1.22.0

toolchain go1.22.3

require github.com/aquasecurity/libbpfgo v0.0.0

replace (
	github.com/aquasecurity/libbpfgo => ../../
	github.com/aquasecurity/libbpfgo/helpers => ../../helpers
)
