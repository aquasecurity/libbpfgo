BASEDIR = $(abspath ../../)

OUTPUT = ../../output

LIBBPF_SRC = $(abspath ../../libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = gcc
CLANG = clang
GO = go

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

GOARCH = amd64

BPFTOOL = $(shell which bpftool || /bin/false)

CFLAGS = -g -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFGLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

.PHONY: $(TEST)
.PHONY: $(TEST).go
.PHONY: $(TEST).bpf.c
.PHONY: tcpclient tcpserver

TEST = main

all:
	$(MAKE) -C . $(TEST)-dynamic
	$(MAKE) -C . $(TEST)-static
	$(MAKE) -C . $(TEST)-c-dynamic
	$(MAKE) -C . $(TEST)-c-static

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

outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

## test bpf dependency

$(TEST).bpf.o: $(TEST).bpf.c
	$(MAKE) -C $(BASEDIR) vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) -c $< -o $@

## test

.PHONY: $(TEST)-static
.PHONY: $(TEST)-dynamic

$(TEST)-static: libbpfgo-static | $(TEST).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOARCH=$(GOARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(TEST)-static ./$(TEST).go

$(TEST)-dynamic: libbpfgo-dynamic | $(TEST).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		$(GO) build -o ./$(TEST)-dynamic ./$(TEST).go

## clean

clean:
	rm -f *.o *-static *-dynamic *.skel.h

## c example (extra, no need for libbpfgo only project)

.PHONY: $(TEST).c

$(TEST).skel.h: $(TEST).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

.PHONY: $(TEST)-c-static
.PHONY: $(TEST)-c-dynamic

libbpf-static:
	$(MAKE) -C $(BASEDIR) libbpf-static

# static here means libbpf statically compiled only
# go example is generating full static binaries

$(TEST)-c-static: libbpf-static | $(TEST).skel.h
	$(CLANG) $(CGO_CFLAGS_STATIC) -lelf -lz -I$(OUTPUT) $(TEST).c -o $@ $(LIBBPF_OBJ)

$(TEST)-c-dynamic: $(TEST).skel.h
	$(CLANG) $(CGO_CFLAGS_STATIC) -lelf -lz -lbpf -I$(OUTPUT) $(TEST).c -o $@

## run

.PHONY: run
.PHONY: run-static
.PHONY: run-dynamic

run: run-static

run-static: $(TEST)-static | $(TEST)-c-static
	sudo ./run.sh $(TEST)-static
	sudo ./run.sh $(TEST)-c-static

run-dynamic: $(TEST)-dynamic | $(TEST)-c-dynamic
	sudo ./run.sh $(TEST)-dynamic
	sudo ./run.sh $(TEST)-c-dynamic
