#!/bin/bash

TEST=$(dirname $0)/$1  # execute
TIMEOUT=10             # seconds
KERNEL_VERSION=v5.8    # kernel version

# SETTINGS
COMMON="$(dirname $0)/../common/common.sh"

vng -v -r $KERNEL_VERSION --rodir="$(realpath ..)" --  "export TEST=$TEST COMMON=$COMMON TIMEOUT=$TIMEOUT; ./run-vm.sh"

exit 0
