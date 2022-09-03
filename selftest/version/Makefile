BASEDIR = $(abspath ../../)

OUTPUT = ../../output

LIBBPF_SRC = $(abspath ../../libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = gcc
CLANG = clang

ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

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

outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

## test bpf dependency

$(TEST).bpf.o: $(TEST).bpf.c
	$(MAKE) -C $(BASEDIR) vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -I$(OUTPUT) -c $< -o $@

## test

.PHONY: $(TEST)-static
.PHONY: $(TEST)-dynamic

$(TEST)-static: libbpfgo-static | $(TEST).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		go build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(TEST)-static ./$(TEST).go

$(TEST)-dynamic: libbpfgo-dynamic | $(TEST).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		go build -o ./$(TEST)-dynamic ./$(TEST).go

## run

.PHONY: run
.PHONY: run-static
.PHONY: run-dynamic

run: run-static

run-static: $(TEST)-static
	./run.sh $(TEST)-static

run-dynamic: $(TEST)-dynamic
	./run.sh $(TEST)-dynamic

clean:
	rm -f *.o *-static *-dynamic
