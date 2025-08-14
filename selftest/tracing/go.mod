module github.com/aquasecurity/libbpfgo/selftest/tracing

go 1.24

toolchain go1.24.2

require (
	github.com/aquasecurity/libbpfgo v0.9.0-libbpf-1.5.1.0.20250716183222-3474da5de8f6
	github.com/aquasecurity/libbpfgo/selftest/common v0.0.0-00010101000000-000000000000
	github.com/aquasecurity/tracee v0.23.1-0.20250812173613-0a9ab353c692
)

require (
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/selftest/common => ../../selftest/common
