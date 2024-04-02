module github.com/aquasecurity/libbpfgo/selftest/tracing-by-offset

go 1.21

require (
	github.com/aquasecurity/libbpfgo v0.0.0
	github.com/aquasecurity/libbpfgo/helpers v0.4.5
)

require golang.org/x/sys v0.7.0 // indirect

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/helpers => ../../helpers
