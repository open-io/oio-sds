#!/usr/bin/env bash

set -e

ENV_PATH=${1:-$VIRTUAL_ENV}
if [ -z "${ENV_PATH}" ]; then
    echo >&2 "This script expects python environment"
    exit 1
fi

PATCHES_DIR="$(realpath "$(dirname "$0")/../python-patches")"
for VENV in "${ENV_PATH}/lib/python"*"/site-packages/"; do
    VENV=$(realpath "${VENV}")
    cd "${VENV}"
    for PATCH in "${PATCHES_DIR}/"*".patch"; do
        if ! patch -f -p1 -R --dry-run -s < "${PATCH}" > /dev/null; then
            patch -f -p1 < "${PATCH}"
        else
            echo "${PATCH} already patched"
        fi
    done
done
