#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' 

OUT_DIR=`realpath ./dist`

cat .libbpf-versions.txt | while read line 
do
    VERSION=$(echo $line | awk -F" " '{print $1}')
    SHA=$(echo $line | awk -F" " '{print $2}')
    echo -e "${YELLOW}Attempting to run selftests with libbpf $VERSION ${NC}"

    # build libbpf version
    rm -rf dist/*
    pushd libbpf-module/src &> /dev/null
    git checkout $SHA &> /dev/null
    make OBJDIR=$OUT_DIR BUILD_STATIC_ONLY=1
    popd &> /dev/null

    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    for d in ${DIR}/*/
    do
        if [[ $(basename $d) == "libbpf-module" ]] || [[ $(basename $d) == "dist" ]]; then
            continue
        else
            echo -e "${GREEN}[*] RUNNING $d ${NC}"
            ( cd $d && bash "run.sh" )
            echo
        fi
    done
done
