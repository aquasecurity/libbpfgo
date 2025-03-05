BASEDIR = $(abspath ../../)

OUTPUT = ../../output

LIBBPF_SRC = $(abspath ../../libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = gcc
CLANG = clang
GO = go
PKGCONFIG = pkg-config

GOARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
BPFARCH := $(shell uname -m | sed 's/x86_64/x86/g; s/aarch64/arm64/g')

# libbpf

LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT)) -I$(abspath ../common)"
CGO_LDFLAGS_STATIC = "$(shell PKG_CONFIG_PATH=$(LIBBPF_OBJDIR) $(PKGCONFIG) --static --libs libbpf)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "$(shell $(PKGCONFIG) --shared --libs libbpf)"

TEST = main

.PHONY: $(TEST)
.PHONY: $(TEST).go
.PHONY: $(TEST).bpf.c

all: $(TEST)-static

.PHONY: libbpfgo
.PHONY: libbpfgo-static
.PHONY: libbpfgo-dynamic

## libbpfgo

libbpfgo-static:
	$(MAKE) -C $(BASEDIR) libbpfgo-static

libbpfgo-dynamic:
	$(MAKE) -C $(BASEDIR) libbpfgo-dynamic

## test (bpf)

$(TEST).bpf.o: $(TEST).bpf.c
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(BPFARCH) -I$(OUTPUT) -I$(abspath ../common) -c $< -o $@

## test deps

DEPS = ctest

.PHONY: ctest
ctest:
	@if [ ! -x ctest ]; then \
		$(CLANG) -o ctest test.c; \
	fi

## test

.PHONY: $(TEST)-static
.PHONY: $(TEST)-dynamic

$(TEST)-static: libbpfgo-static | $(TEST).bpf.o $(DEPS)
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(GOARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(TEST)-static ./$(TEST).go

$(TEST)-dynamic: libbpfgo-dynamic | $(TEST).bpf.o $(DEPS)
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
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
