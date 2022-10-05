module github.com/aquasecurity/libbpfgo/selftest/uprobe

go 1.18

require (
	github.com/aquasecurity/libbpfgo v0.4.0-libbpf-1.0.0.0.20221004153638-7139cb41036f
	github.com/aquasecurity/libbpfgo/helpers v0.0.0-20221004153638-7139cb41036f
)

require golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/helpers => ../../helpers
