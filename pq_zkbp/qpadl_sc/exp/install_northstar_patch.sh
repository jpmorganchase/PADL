#!/usr/bin/env bash
set -euo pipefail

# MIT Licensed Plonky3
readonly UPSTREAM_URL="https://github.com/Plonky3/Plonky3.git"
readonly UPSTREAM_COMMIT="4aed8fe4195d40305175d55e58690f46171258d9"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PATCH_FILE="${SCRIPT_DIR}/northstar-source.patch"
readonly TARGET_DIR="${1:-${SCRIPT_DIR}/../Plonky3-northstar}"

if [[ ! -f "${PATCH_FILE}" ]]; then
    printf 'Patch file not found: %s\n' "${PATCH_FILE}" >&2
    exit 1
fi

if [[ -e "${TARGET_DIR}" ]]; then
    printf 'Target path already exists: %s\n' "${TARGET_DIR}" >&2
    exit 1
fi

cleanup_on_error() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        rm -rf -- "${TARGET_DIR}"
    fi
}
trap cleanup_on_error EXIT

git init --quiet "${TARGET_DIR}"
git -C "${TARGET_DIR}" remote add origin "${UPSTREAM_URL}"
git -C "${TARGET_DIR}" fetch --quiet --depth 1 origin "${UPSTREAM_COMMIT}"
git -C "${TARGET_DIR}" checkout --quiet --detach FETCH_HEAD

actual_commit="$(git -C "${TARGET_DIR}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${UPSTREAM_COMMIT}" ]]; then
    printf 'Expected commit %s, downloaded %s\n' "${UPSTREAM_COMMIT}" "${actual_commit}" >&2
    exit 1
fi

git -C "${TARGET_DIR}" apply --check "${PATCH_FILE}"
git -C "${TARGET_DIR}" apply "${PATCH_FILE}"

printf 'Installed Plonky3 %s with the Northstar source patch at:\n%s\n' \
    "${UPSTREAM_COMMIT}" "${TARGET_DIR}"