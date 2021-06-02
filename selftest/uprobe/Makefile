TARGET := self
TARGET_BPF := $(TARGET).bpf.o

TEST_GO_SRC := test_program/test_program.go
TEST_C_SRC := test_program/test_program.c
TEST_C_OBJ := test_program/dist/test_c_object
TEST_GO_OBJ := test_program/dist/test_go_object

GO_SRC := $(shell find . -type f -name '*.go')
LIBBPFGO_SRC := $(shell find ../.. -type f -name '*.go')
BPF_SRC := $(shell find . -type f -name '*.bpf.c')
PWD := $(shell pwd)

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := $(abspath ../dist/libbpf.a)

.PHONY: all
all: vmlinux.h $(TARGET) $(TARGET_BPF) $(TEST_GO_OBJ) $(TEST_C_OBJ)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(TEST_C_OBJ): $(TEST_C_SRC)
	clang $(TEST_C_SRC) -o $(TEST_C_OBJ)

$(TEST_GO_OBJ): $(TEST_GO_SRC)
	go build -o $(TEST_GO_OBJ) $(TEST_GO_SRC)

go_env := CC=gcc CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC) $(LIBBPFGO_SRC)
	$(go_env) go build -ldflags '-extldflags "-static"' -o $(TARGET) 

$(TARGET_BPF): $(BPF_SRC)
	clang \
		-g -O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean: 
	rm $(TARGET) $(TARGET_BPF) $(TEST_GO_OBJ) $(TEST_C_OBJ) vmlinux.h
