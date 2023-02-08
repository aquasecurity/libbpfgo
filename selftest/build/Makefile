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

## test bpf dependency

$(TEST).bpf.o: $(TEST).bpf.c
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) -I$(abspath ../common) -c $< -o $@

## clean

clean:
	rm -f *.o
