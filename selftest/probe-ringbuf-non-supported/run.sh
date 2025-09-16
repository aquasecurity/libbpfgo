#!/bin/bash

TEST=$(dirname $0)/$1  # execute
TIMEOUT=10             # seconds
KERNEL_VERSION=v5.7    # kernel version

# SETTINGS
COMMON="$(dirname $0)/../common/common.sh"

vng -v -r $KERNEL_VERSION --rodir="$(realpath ..)" --  "export TEST=$TEST COMMON=$COMMON TIMEOUT=$TIMEOUT; ./run-vm.sh"

# Don't override the exit code from the VM
exit $?
