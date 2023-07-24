#!/bin/bash

# SETTINGS

TEST=$(dirname $0)/$1  # execute
TIMEOUT=10             # seconds

# COMMON

COMMON="$(dirname $0)/../common/common.sh"
[[ -f $COMMON ]] && { . $COMMON; } || { error "no common"; exit 1; }

# MAIN

kern_version gt 4.18

check_build
check_ppid
test_exec
test_finish

exit 0
