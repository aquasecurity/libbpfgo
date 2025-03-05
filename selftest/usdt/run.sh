#!/bin/bash

# SETTINGS

TEST=$(dirname $0)/$1  # execute
TIMEOUT=10             # seconds

CTEST=$(dirname $0)/ctest

# COMMON

COMMON="$(dirname $0)/../common/common.sh"
[[ -f $COMMON ]] && { . $COMMON; } || { error "no common"; exit 1; }

# MAIN

check_build
check_ppid

execbg 10 $CTEST

execfg 5 $TEST
test_finish

waitbg

exit 0
