#!/bin/bash
#
# Writes the file the cache key of uv's Python downloads is computed from,
# for the tool install commands. The file names:
#
#   - the CPU, from uname -m, and the C library (glibc or musl), which decide
#     the Python build uv downloads;
#   - HOME, since a cache is restored to the absolute path it was saved from;
#   - the uv version and the python parameter, with environment variables
#     expanded: the uv release decides which patch release "3.14" means.
#
# The cache holds only the archives uv downloaded, which uv checks against
# the SHA-256 it carries every time it unpacks one, so a cached archive is
# never trusted on its own.
#
# Parameters arrive as PARAM_PYTHON, PARAM_UV_VERSION and ORB_CACHE_KEY_FILE.

set -euo pipefail

subst() {
    # The value is piped in on stdin: passed as an argument, a value starting
    # with "-" would be parsed as a flag.
    if command -v circleci > /dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}
libc=gnu
if compgen -G '/lib/ld-musl-*' > /dev/null; then
    libc=musl
fi
uv_version=$(subst "${PARAM_UV_VERSION}")
# The file is written under a new name and renamed into place, so a file or
# symlink someone else left at its name in a shared /tmp is never written
# through.
tmp=$(mktemp "${ORB_CACHE_KEY_FILE}.XXXXXX")
trap 'rm -f "${tmp}"' EXIT
printf '%s\n%s\n%s\n%s\n%s\n' "$(uname -m)" "${libc}" "${HOME:-}" "${uv_version#v}" "$(subst "${PARAM_PYTHON}")" > "${tmp}"
if [[ -d "${ORB_CACHE_KEY_FILE}" ]] || ! mv -f "${tmp}" "${ORB_CACHE_KEY_FILE}"; then
    echo "ERROR: Could not write ${ORB_CACHE_KEY_FILE}." >&2
    exit 1
fi
