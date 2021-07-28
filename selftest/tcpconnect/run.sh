#!/bin/bash

# SETTINGS

TEST=$(dirname $0)/$1	# execute

SERVER=$(dirname $0)/tcpserver
CLIENT=$(dirname $0)/tcpclient

# COMMON

COMMON="$(dirname $0)/../common/common.sh"
[[ -f $COMMON ]] && { . $COMMON; } || { error "no common"; exit 1; }

# MAIN

kern_version gt 5.2
check_build
check_ppid
execbg 20 $SERVER
execbg 20 $CLIENT
execfg 10 $TEST
test_finish

waitbg

exit 0
