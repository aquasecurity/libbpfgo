BASEDIR = $(abspath ../../)

OUTPUT = ../../output

LIBBPF_SRC = $(abspath ../../libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = gcc
CLANG = clang
GO = go

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"

CGO_CFLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

.PHONY: $(TEST)
.PHONY: $(TEST).go
.PHONY: $(TEST).bpf.c

TEST = main

all: $(TEST)-static

.PHONY: libbpfgo
.PHONY: libbpfgo-static
.PHONY: libbpfgo-dynamic

## libbpfgo

libbpfgo-static:
	$(MAKE) -C $(BASEDIR) libbpfgo-static

libbpfgo-dynamic:
	$(MAKE) -C $(BASEDIR) libbpfgo-dynamic

vmlinuxh:
	$(MAKE) -C $(BASEDIR) vmlinuxh

## test (bpf)

.PHONY: $(TEST)-bpf

$(TEST)-bpf: vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) -c $(TEST).bpf.c -o $(TEST).bpf.o

## test deps

DEPS = ctest gotest

.PHONY: ctest
ctest:
	@if [ ! -x ctest ]; then \
		$(CLANG) -o ctest test.c; \
	fi

.PHONY: gotest
gotest:
	@if [ ! -x gotest ]; then \
		$(GO) build -o gotest test.go; \
	 fi

## test

.PHONY: $(TEST)-static
.PHONY: $(TEST)-dynamic

$(TEST)-static: $(TEST)-bpf libbpfgo-static $(DEPS)
	CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_STATIC) CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	   $(GO) build -o $(TEST)-static ./$(TEST).go

$(TEST)-dynamic: $(TEST)-bpf libbpfgo-dynamic $(DEPS)
	CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_DYN) CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
	   $(GO) build -o ./$(TEST)-dynamic ./$(TEST).go

## run

.PHONY: run
.PHONY: run-static
.PHONY: run-dynamic

run: run-static

run-static: $(TEST)-static
	sudo ./run.sh $(TEST)-static

run-dynamic: $(TEST)-dynamic
	sudo ./run.sh $(TEST)-dynamic

clean:
	rm -f *.o $(TEST)-static $(TEST)-dynamic $(DEPS)
