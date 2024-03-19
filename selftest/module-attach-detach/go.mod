module github.com/aquasecurity/libbpfgo/selftest/module-attach-detach

go 1.18

require (
	github.com/aquasecurity/libbpfgo v0.4.7-libbpf-1.2.0-b2e29a1
	github.com/aquasecurity/libbpfgo/helpers v0.4.5
)

require golang.org/x/sys v0.7.0 // indirect

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/helpers => ../../helpers
