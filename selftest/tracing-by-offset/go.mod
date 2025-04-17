module github.com/aquasecurity/libbpfgo/selftest/tracing-by-offset

go 1.22.0

toolchain go1.22.4

require (
	github.com/aquasecurity/libbpfgo v0.7.0-libbpf-1.4.0.20240729111821-61d531acf4ca
	github.com/aquasecurity/tracee v0.22.5
)

replace github.com/aquasecurity/libbpfgo => ../../
