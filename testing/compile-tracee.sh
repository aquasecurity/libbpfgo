#!/bin/bash -e

#
# This script downloads and updates the aquasecurity/tracee repository
# 

die() {
    echo ${@}
    exit 1
}

BASEDIR=$(dirname "${0}") ; cd ${BASEDIR}/../ ; BASEDIR=$(pwd) ; cd ${BASEDIR}
TRACEE_REPO="https://github.com/aquasecurity/tracee.git"
TRACEE_DIR="${BASEDIR}/testing/tracee"
RETURN_CODE=0

CMDS="rsync git cp rm mv"
for cmd in ${CMDS}; do
    command -v $cmd 2>&1 >/dev/null || die "cmd ${cmd} not found"
done

branch_clean() {
    cd ${1} || die "could not change dirs"

    # small sanity check
    [ ! -f ./Readme.md ] && die "$(basename $(pwd)) not a repo dir"

    git fetch -a || die "could not fetch ${1}"  # make sure its updated
    git clean -fdX                              # clean leftovers
    git reset --hard                            # reset letfovers
    git checkout origin/main -b main-$$
    git branch -D main
    git branch -m main-$$ main                  # origin/main == main

    cd ${BASEDIR}
}

[ ! -d ${TRACEE_DIR} ] && git clone "${TRACEE_REPO}" ${TRACEE_DIR}
if [ -z ${SKIP_FETCH} ]; then
    branch_clean ${TRACEE_DIR}
fi

echo "replace github.com/aquasecurity/libbpfgo => ../../" >> ${TRACEE_DIR}/go.mod
cd ${TRACEE_DIR}

make -f Makefile.one
if [ $? -ne 0 ]; then
	echo "failed to build tracee with location version of libbpfgo"
    RETURN_CODE=-1
fi

rm -rf ${TRACEE_DIR}
exit $RETURN_CODE