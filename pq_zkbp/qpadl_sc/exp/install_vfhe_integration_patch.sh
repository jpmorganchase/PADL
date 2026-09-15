#!/usr/bin/env bash
# Clone from https://zenodo.org/records/20275781

set -euo pipefail

readonly UPSTREAM_URL="https://github.com/f7ed/HasteBoots.git"
readonly UPSTREAM_COMMIT="3a371359327831535964931cb91fc8b5aac3ec8e"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PATCH_FILE="${SCRIPT_DIR}/vfhe-integration-source.patch"
readonly TARGET_DIR="${1:-${SCRIPT_DIR}/../HasteBoots-vfhe}"

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

printf 'Installed HasteBoots %s with the VFHE integration patch at:\n%s\n' \
    "${UPSTREAM_COMMIT}" "${TARGET_DIR}"
