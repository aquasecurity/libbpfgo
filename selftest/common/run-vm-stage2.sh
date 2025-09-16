#!/bin/bash

# COMMON

[[ -f $COMMON ]] && { . $COMMON; } || { error "no common"; exit 1; }

# MAIN

check_build
# check_ppid # not needed for VM
test_exec
test_finish

# Don't override the exit code from test_finish
exit $?
