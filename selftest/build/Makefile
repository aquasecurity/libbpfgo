BASEDIR = $(abspath ../../)

OUTPUT = ../../output

CC = gcc
CLANG = clang

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

TEST = libbpfgo_test

all: $(TEST).bpf.o

## main tree dependency

outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

vmlinuxh: outputdir
	$(MAKE) -C $(BASEDIR) vmlinuxh

## test bpf dependency

$(TEST).bpf.o: $(TEST).bpf.c
	$(MAKE) -C $(BASEDIR) vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) -c $< -o $@

## clean

clean:
	rm -f *.o
