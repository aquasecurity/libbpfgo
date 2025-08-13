module github.com/aquasecurity/libbpfgo/selftest/map-getfdbyid

go 1.21

require (
	github.com/aquasecurity/libbpfgo v0.0.0
	github.com/aquasecurity/libbpfgo/selftest/common v0.0.0-00010101000000-000000000000
)

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/selftest/common => ../../selftest/common
