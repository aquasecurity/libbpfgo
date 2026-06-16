#!/bin/bash

TEST=$(dirname $0)/$1  # execute
TIMEOUT=10             # seconds
MAINLINE_URL="https://kernel.ubuntu.com/mainline/"

# SETTINGS
COMMON="$(dirname $0)/../common/common.sh"

# Discover available v6.12 kernels from Ubuntu mainline index.
# Keep a static fallback list in case directory listing is unavailable.
DISCOVERED_VERSIONS=$(
    curl -fsSL "${MAINLINE_URL}" 2>/dev/null |
        sed -n 's/.*href="\(v6\.12\.[0-9]\+\)\/".*/\1/p' |
        sort -V |
        uniq
)

if [ -n "${DISCOVERED_VERSIONS}" ]; then
    mapfile -t KERNEL_VERSIONS < <(printf '%s\n' "${DISCOVERED_VERSIONS}" | sort -Vr)
else
    # Known versions that existed historically; newest first.
    KERNEL_VERSIONS=(v6.12.25 v6.12.21 v6.12)
fi

echo "INFO: kernel candidates: ${KERNEL_VERSIONS[*]}"

ATTEMPTED=()
for KERNEL_VERSION in "${KERNEL_VERSIONS[@]}"; do
    ATTEMPTED+=("${KERNEL_VERSION}")
    echo "INFO: trying kernel ${KERNEL_VERSION}"
    OUTPUT=$(
        vng -v -r "${KERNEL_VERSION}"
            --rodir="$(realpath ..)"
            --append "psi=0"
            -- "export TEST=${TEST} COMMON=${COMMON} TIMEOUT=${TIMEOUT}; ./run-vm.sh"
            2>&1
    )
    STATUS=$?
    echo "${OUTPUT}"

    if [ "${STATUS}" -eq 0 ]; then
        exit 0
    fi

    if echo "${OUTPUT}" | grep -q "failed to retrieve content, error: 404"; then
        echo "WARN: kernel ${KERNEL_VERSION} not available, trying next candidate"
        continue
    fi

    # Any non-404 failure means kernel was testable but test failed: fail fast.
    exit "${STATUS}"
done

echo "ERROR: struct-ops selftest is not testable: no candidate kernel available"
echo "ERROR: attempted kernels: ${ATTEMPTED[*]}"
exit 1
