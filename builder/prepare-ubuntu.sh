#!/bin/bash

#
# This shell script is meant to prepare a building/exec environment for libbpfgo.
#


# variables

[ -z "${GO_VERSION}" ] && GO_VERSION="1.17"
[ -z "${CLANG_VERSION}" ] && CLANG_VERSION="12"
[ -z "${ARCH}" ] && ARCH="amd64"


# functions

die() {
    echo "ERROR: ${*}"
    exit 1
}

info() {
    echo "INFO: ${*}"
}

check_tooling() {
    local tools="sudo apt-get"
    for tool in ${tools}
    do
        command -v "${tool}" >/dev/null 2>&1 || die "missing required tool ${tool}"
    done
}

install_pkgs() {
    # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
    export DEBIAN_FRONTEND=noninteractive

    sudo -E apt-get update || die "coud not update package list"
    for pkg in "${@}"
    do
        info "Installing ${pkg}"
        sudo -E apt-get install -y "${pkg}" || die "could not install ${pkg}"
        info "${pkg} installed"
    done
}

setup_go() {
    info "Setting Go ${GO_VERSION} as default"
    
    local tools="go gofmt"
    for tool in ${tools}
    do
        sudo -E update-alternatives --install "/usr/bin/${tool}" "${tool}" "/usr/lib/go-${GO_VERSION}/bin/${tool}" 100
    done

    info "Go ${GO_VERSION} set as default"
}

setup_clang() {
    info "Setting Clang ${CLANG_VERSION} as default"

    local tools="clang llc llvm-strip clang-format"
    for tool in ${tools}
    do
        sudo -E update-alternatives --install "/usr/bin/${tool}" "${tool}" "/usr/bin/${tool}-${CLANG_VERSION}" 100
    done

    info "Clang ${CLANG_VERSION} set as default"
}


# startup

info "Starting preparation"

check_tooling

install_pkgs \
    coreutils bsdutils findutils \
    build-essential pkgconf \
    golang-"${GO_VERSION}"-go \
    llvm-"${CLANG_VERSION}" clang-"${CLANG_VERSION}" clang-format-"${CLANG_VERSION}" \
    linux-headers-generic \
    linux-tools-generic linux-tools-"$(uname -r)" \
    zlib1g-dev libelf-dev libbpf-dev

setup_go
setup_clang

info "Preparation finished"
