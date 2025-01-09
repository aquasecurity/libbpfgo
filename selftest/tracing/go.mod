module github.com/aquasecurity/libbpfgo/selftest/tracing

go 1.21

require (
	github.com/aquasecurity/libbpfgo v0.9.2-libbpf-1.5.1.0.20250826130354-1b9ce23ef29b
	github.com/aquasecurity/libbpfgo/selftest/common v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
)

replace github.com/aquasecurity/libbpfgo => ../../

replace github.com/aquasecurity/libbpfgo/selftest/common => ../../selftest/common
