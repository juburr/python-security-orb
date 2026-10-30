#!/usr/bin/env bash
#
# Runs the install contract every juburr orb's install command meets
# (tests/install_contract.sh, a copy of the tests/install_test.sh the
# single-tool orbs share, never edited here) for uv, the one tool this orb
# downloads with the shared install logic, and checks that every tool the
# orb installs with uv has its lock and its command. tests/install_tool_test.sh
# covers those installs.
#
# The contract expects one tool per orb: src/scripts/install.sh and
# src/commands/install.yml. So uv gets a temporary tree laid out that way,
# holding its install.sh, install_uv.yml with the include pointed at
# scripts/install.sh, the orb's cache_key.sh, and a copy of the contract
# whose tool fixture section comes from tests/install_fixtures/release.sh
# (the download_base_url mirror).
#
# Run from a checkout:
#   bash tests/install_test.sh

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTRACT="${ROOT}/tests/install_contract.sh"
FIXTURES="${ROOT}/tests/install_fixtures"
# The tools installed with uv, each from src/install/<tool>/locks.txt.
LOCKED="pip-audit bandit pip-licenses"

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
FAILURES=0
fail() {
    printf 'FAIL: %s\n' "$*"
    FAILURES=$((FAILURES + 1))
}

echo "=== per-tool files"
for file in src/install/uv/install.sh src/install/uv/install_hash.sh src/commands/install_uv.yml src/commands/install_python.yml; do
    if [[ ! -f "${ROOT}/${file}" ]]; then
        fail "${file} is missing"
    fi
done
for tool in ${LOCKED}; do
    if [[ ! -f "${ROOT}/src/install/${tool}/locks.txt" ]]; then
        fail "src/install/${tool}/locks.txt is missing"
    fi
    if [[ ! -f "${ROOT}/src/commands/install_${tool//-/_}.yml" ]]; then
        fail "src/commands/install_${tool//-/_}.yml is missing"
    fi
done
for dir in "${ROOT}"/src/install/*/; do
    tool=${dir%/}
    tool=${tool##*/}
    if [[ "${tool}" != uv && " ${LOCKED} " != *" ${tool} "* ]]; then
        fail "src/install/${tool} holds a tool this test doesn't know"
    fi
done
for tool_yml in "${ROOT}"/src/commands/install_*.yml; do
    tool=${tool_yml##*/install_}
    tool=${tool%.yml}
    if [[ " uv python ${LOCKED} " != *" ${tool//_/-} "* ]]; then
        fail "${tool_yml##*/} installs a tool this test doesn't know"
    fi
done
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "ok: uv and every locked tool have their files and commands"
fi

echo "=== the install contract for uv"
tree="${WORK}/uv"
mkdir -p "${tree}/src/scripts" "${tree}/src/commands" "${tree}/tests"
cp "${ROOT}/src/@orb.yml" "${tree}/src/"
cp "${ROOT}/src/install/uv/install.sh" "${tree}/src/scripts/install.sh"
cp "${ROOT}/src/scripts/cache_key.sh" "${tree}/src/scripts/"
sed "s|<< include(install/uv/install.sh) >>|<< include(scripts/install.sh) >>|" \
    "${ROOT}/src/commands/install_uv.yml" > "${tree}/src/commands/install.yml"
{
    sed -n '1,/^# >>> tool fixture >>>$/p' "${CONTRACT}"
    cat "${FIXTURES}/release.sh"
    sed -n '/^# <<< tool fixture <<<$/,$p' "${CONTRACT}"
} > "${tree}/tests/install_test.sh"
if ! bash "${tree}/tests/install_test.sh"; then
    fail "the install contract for uv"
fi

if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${FAILURES} failure(s)"
    exit 1
fi
echo "uv meets the install contract."
