BASEDIR = $(abspath ../../)

OUTPUT = ../../output

LIBBPF_SRC = $(abspath ../../libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CLANG = clang
CC = $(CLANG)
GO = go

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

CFLAGS = -g -O2 -Wall -fpie -I$(abspath ../common)
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT)) -I$(abspath ../common)"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

MAIN = main

.PHONY: $(MAIN)
.PHONY: $(MAIN).go
.PHONY: $(MAIN).bpf.c

all: $(MAIN)-static

.PHONY: libbpfgo
.PHONY: libbpfgo-static
.PHONY: libbpfgo-dynamic

## libbpfgo

libbpfgo-static:
	$(MAKE) -C $(BASEDIR) libbpfgo-static

libbpfgo-dynamic:
	$(MAKE) -C $(BASEDIR) libbpfgo-dynamic

outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

## test bpf dependency

$(MAIN).bpf.o: $(MAIN).bpf.c
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) -I$(abspath ../common) -c $< -o $@

## test

.PHONY: $(MAIN)-static
.PHONY: $(MAIN)-dynamic

$(MAIN)-static: libbpfgo-static | $(MAIN).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(MAIN)-static ./$(MAIN).go

$(MAIN)-dynamic: libbpfgo-dynamic | $(MAIN).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		$(GO) build -o ./$(MAIN)-dynamic ./$(MAIN).go

## run

.PHONY: run
.PHONY: run-static
.PHONY: run-dynamic

run: run-static

run-static: $(MAIN)-static
	sudo ./run.sh $(MAIN)-static

run-dynamic: $(MAIN)-dynamic
	sudo ./run.sh $(MAIN)-dynamic

clean:
	rm -f *.o *-static *-dynamic
