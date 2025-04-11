#!/bin/bash

# SETTINGS

TEST=$(dirname $0)/$1  # execute
TIMEOUT=10             # seconds

CTEST=$(dirname $0)/ctest
GOTEST=$(dirname $0)/gotest
CFUNCS="fooFunction,barFunction,bazFunction"
GOFUNCS="main.fooFunction,main.barFunction,main.bazFunction"

# COMMON

COMMON="$(dirname $0)/../common/common.sh"
[[ -f $COMMON ]] && { . $COMMON; } || { error "no common"; exit 1; }

# MAIN

kern_version gt 4.3
check_build
check_ppid

execbg 10 $CTEST
execbg 10 $GOTEST

execfg 5 $TEST $CTEST $CFUNCS
test_step

execfg 5 $TEST $GOTEST $GOFUNCS
test_finish

waitbg

exit 0
