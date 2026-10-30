#!/usr/bin/env bash
#
# Tests src/scripts/install_tool.sh, which installs pip-audit, bandit and
# pip-licenses (and, for install_python, the Python alone) with uv. It runs
# through tests/run_command.sh, so with each command's YAML defaults, its
# locks and the shared helpers, against a stand-in uv that records every call
# and the UV_* variables it sees, and stand-in interpreters that answer what
# the install asks them. It checks:
#
#   - a listed release installs from its lock with --require-hashes, wheels
#     only, ignoring uv configuration, into a new environment that replaces
#     the old one only after the tool runs in it
#   - strict refuses an unlisted release before running uv; known_versions
#     and false install unverified, with a warning
#   - the job's UV_* variables are cleared but the network ones
#   - python: a uv-managed CPython (default 3.14), system, or a path, which
#     must be CPython 3.10 to 3.14
#   - index_url and python_install_mirror are checked and passed on
#   - the script that runs the tool, the install record, and the exports
#
# Run from a checkout:
#   bash tests/install_tool_test.sh

# The checks run small scripts in single quotes, which expand their own
# arguments.
# shellcheck disable=SC2016

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STUB="${WORK}/stub"
HOME_DIR="${WORK}/home"
BIN="${HOME_DIR}/.python-security-orb/bin"
mkdir -p "${STUB}" "${WORK}/path"

# A stand-in interpreter: the platform question install_tool.sh asks, and a
# tool's --version, from the "installed" file the stand-in uv writes in the
# environment it belongs to.
cat > "${STUB}/python" << 'EOF'
#!/usr/bin/env bash
if [[ "$1" == -I && "$2" == -c ]]; then
    echo "${STUB_PYTHON_IMPL:-CPython} ${STUB_PYTHON_VERSION:-3.14.10}"
    exit 0
fi
if [[ "$1" == -I && "$2" == -m ]]; then
    dir=$(cd "$(dirname "$0")/.." && pwd)
    read -r name version < "${dir}/installed" || exit 1
    printf '%s %s\n' "${name}" "${STUB_REPORT_VERSION:-${version}}"
    exit "${STUB_RUN_EXIT:-0}"
fi
echo "python stub: unexpected: $*" >&2
exit 1
EOF
# The stand-in uv.
cat > "${STUB}/uv" << 'EOF'
#!/usr/bin/env bash
set +o errexit +o nounset +o pipefail +o xtrace
{
    printf 'call:'
    printf ' %s' "$@"
    printf '\n'
    env | grep '^UV_' | sort | sed 's/^/  env /'
    printf '  cwd %s\n' "${PWD}"
} >> "${STUB_DIR}/uv.log"
args=("$@")
# opt FLAG: the value after FLAG.
opt() {
    local i
    for ((i = 0; i < ${#args[@]}; i++)); do
        if [[ "${args[i]}" == "$1" ]]; then
            printf '%s\n' "${args[i + 1]}"
            return 0
        fi
    done
    return 1
}
python_dir="${UV_PYTHON_INSTALL_DIR}/cpython-3.14.10-linux-x86_64-gnu/bin"
case "$1 $2" in
    "--version "*)
        echo "uv 0.13.6"
        exit 0
        ;;
    "python install")
        [[ -n "${STUB_PYTHON_INSTALL_EXIT:-}" ]] && { echo "error: no download for that request" >&2; exit "${STUB_PYTHON_INSTALL_EXIT}"; }
        mkdir -p "${python_dir}"
        cp "${STUB_DIR}/python" "${python_dir}/python3.14"
        exit 0
        ;;
    "python find")
        echo "${python_dir}/python3.14"
        exit 0
        ;;
    "venv "*)
        dest=${args[${#args[@]} - 1]}
        mkdir -p "${dest}/bin"
        cp "${STUB_DIR}/python" "${dest}/bin/python"
        printf 'home = %s\n' "$(dirname "$(opt --python)")" > "${dest}/pyvenv.cfg"
        exit 0
        ;;
    "pip install")
        venv=$(dirname "$(dirname "$(opt --python)")")
        if lock=$(opt -r); then
            cp "${lock}" "${STUB_DIR}/lock.txt"
            spec=$(grep -E "^${STUB_TOOL}==" "${lock}" | head -n 1)
        else
            spec=${args[${#args[@]} - 1]}
        fi
        [[ -n "${STUB_INSTALL_EXIT:-}" ]] && { echo "error: hash mismatch for some-package" >&2; exit "${STUB_INSTALL_EXIT}"; }
        spec=${spec%% *}
        name=${spec%%==*}
        printf '%s %s\n' "${name%%[*}" "${spec#*==}" > "${venv}/installed"
        exit 0
        ;;
    "pip list")
        echo '[{"name":"stub-package","version":"1.0"}]'
        exit 0
        ;;
esac
echo "uv stub: unexpected: $*" >&2
exit 1
EOF
chmod +x "${STUB}/python" "${STUB}/uv"
# A python3 for python: system.
cp "${STUB}/python" "${WORK}/path/python3"

FAILURES=0
RC=0
OUTPUT=""

# run COMMAND [NAME=VALUE ...] [-- VAR=value ...]: runs COMMAND's script
# through tests/run_command.sh with HOME in the work directory, the stand-in
# uv in install_path, and the environment settings after --.
run() {
    local command=$1 params=() envs=()
    shift
    while [[ $# -gt 0 && "$1" != -- ]]; do
        params+=("$1")
        shift
    done
    if [[ $# -gt 0 ]]; then
        shift
        envs=("$@")
    fi
    rm -f "${STUB}/uv.log" "${STUB}/lock.txt"
    : > "${STUB}/uv.log"
    : > "${WORK}/bash_env"
    mkdir -p "${BIN}"
    cp "${STUB}/uv" "${BIN}/uv"
    OUTPUT=$(env HOME="${HOME_DIR}" PATH="${WORK}/path:${PATH}" BASH_ENV="${WORK}/bash_env" STUB_DIR="${STUB}" \
        ${envs[@]+"${envs[@]}"} bash "${ROOT}/tests/run_command.sh" "${command}" ${params[@]+"${params[@]}"} 2>&1)
    RC=$?
}

check() {
    local description=$1
    shift
    if "$@"; then
        printf 'ok: %s\n' "${description}"
    else
        printf 'FAIL: %s\n' "${description}"
        while IFS= read -r line; do
            printf '    | %s\n' "${line}"
        done <<< "${OUTPUT}"
        sed 's/^/    uv: /' "${STUB}/uv.log"
        FAILURES=$((FAILURES + 1))
    fi
}
rc_is() { [[ "${RC}" -eq "$1" ]]; }
said() { grep -qF -- "$1" <<< "${OUTPUT}"; }
not_said() { ! said "$1"; }
# script_lacks TEXT: the script's output lacks TEXT; run_command.sh's own
# first line, which echoes the parameters, is left out.
script_lacks() { ! grep -v '^Running scripts/' <<< "${OUTPUT}" | grep -qF -- "$1"; }
called() { grep -q -- "^call: $1" "${STUB}/uv.log"; }
not_called() { ! called "$1"; }
call_has() { grep "^call: $1" "${STUB}/uv.log" | grep -qF -- "$2"; }
call_lacks() { ! call_has "$1" "$2"; }
uv_env() { grep -qx -- "  env $1" "${STUB}/uv.log"; }
no_uv_env() { ! grep -q -- "^  env $1=" "${STUB}/uv.log"; }
exported() {
    # shellcheck disable=SC2016 # expanded by the clean shell, not here
    [[ "$(env -i bash -c 'source "$1"; printf "%s" "${!2}"' _ "${WORK}/bash_env" "$1")" == "$2" ]]
}
record() { jq -r "$1" "${BIN}/.$2.install.json" 2> /dev/null; }
# block TOOL VERSION: the lock for TOOL VERSION in its locks.txt.
block() {
    awk -v start="# >>> $1 $2 >>>" -v end="# <<< $1 $2 <<<" '$0 == start { on = 1; next } $0 == end { on = 0 } on' \
        "${ROOT}/src/install/$1/locks.txt"
}

echo "=== a listed release, from its lock"
run install_pip_audit -- STUB_TOOL=pip-audit
check "pip-audit's default release installs" rc_is 0
check "uv installs CPython 3.14 first" call_has "python install" "--no-bin --managed-python 3.14"
check "into the orb's own directory" uv_env "UV_PYTHON_INSTALL_DIR=${HOME_DIR}/.python-security-orb/python"
check "keeping the archive in the cached directory" uv_env "UV_PYTHON_CACHE_DIR=${HOME_DIR}/.cache/python-security-orb/python"
check "creates the environment with that Python" call_has "venv" "--no-python-downloads --relocatable --quiet --python ${HOME_DIR}/.python-security-orb/python/cpython-3.14.10-linux-x86_64-gnu/bin/python3.14"
check "installs with --require-hashes from a lock" call_has "pip install" "--require-hashes -r "
check "wheels only, every installed file checked" call_has "pip install" "--only-binary :all: --strict --link-mode copy"
check "from PyPI, with no keyring" call_has "pip install" "--default-index https://pypi.org/simple --keyring-provider disabled"
check "ignoring uv configuration" call_has "pip install" "--no-config"
check "and UV_NO_CONFIG is set besides" uv_env "UV_NO_CONFIG=1"
check "with a cache of its own" grep -q '^  env UV_CACHE_DIR=/tmp' "${STUB}/uv.log"
check "the lock is the 2.10.1 block of src/install/pip-audit/locks.txt" diff -q <(block pip-audit 2.10.1) "${STUB}/lock.txt"
check "uv runs in a directory with no project files" bash -c '! grep "^  cwd " "$1" | grep -qv "^  cwd /tmp"' _ "${STUB}/uv.log"
check "says how many packages it pins" said "Installing pip-audit 2.10.1 from its lock (29 packages"
check "the script that runs it is in install_path" test -x "${BIN}/pip-audit"
check "and runs the tool with python -I" grep -q "^exec '${HOME_DIR}/.python-security-orb/venvs/pip-audit/bin/python' -I -m pip_audit \"\$@\"$" "${BIN}/pip-audit"
check "which works" bash -c '[[ "$("$1" --version)" == "pip-audit 2.10.1" ]]' _ "${BIN}/pip-audit"
check "the environment is in venvs/pip-audit" test -f "${HOME_DIR}/.python-security-orb/venvs/pip-audit/pyvenv.cfg"
check "no staging directory is left" bash -c '[[ -z "$(find "$1" -maxdepth 1 -name ".pip-audit.*")" ]]' _ "${HOME_DIR}/.python-security-orb/venvs"
check "the install record says it was verified" test "$(record .verified pip-audit)" = true
check "with the lock's SHA-256" test "$(record .lock_sha256 pip-audit)" = "$(block pip-audit 2.10.1 | sha256sum | awk '{ print $1 }')"
check "the Python" test "$(record '.python.version + " " + .python.source' pip-audit)" = "3.14.10 uv"
check "uv's version" test "$(record .uv pip-audit)" = "0.13.6"
check "what is installed" test "$(record '.packages[0].name' pip-audit)" = "stub-package"
check "and the SHA-512 of the script" test "$(record .binary_sha512 pip-audit)" = "$(sha512sum "${BIN}/pip-audit" | awk '{ print $1 }')"
check "install_path goes on the PATH of later steps" grep -q "^export PATH=${BIN}:" "${WORK}/bash_env"
check "and the Python in PYTHON_SECURITY_ORB_PYTHON" \
    exported PYTHON_SECURITY_ORB_PYTHON "${HOME_DIR}/.python-security-orb/python/cpython-3.14.10-linux-x86_64-gnu/bin/python3.14"

printf 'old\n' > "${HOME_DIR}/.python-security-orb/venvs/pip-audit/old-marker"
run install_pip_audit version=2.10.0 -- STUB_TOOL=pip-audit
check "another release replaces the environment" rc_is 0
check "with the 2.10.0 lock" diff -q <(block pip-audit 2.10.0) "${STUB}/lock.txt"
check "and nothing of the old one stays" test ! -e "${HOME_DIR}/.python-security-orb/venvs/pip-audit/old-marker"
check "the script runs the new one" bash -c '[[ "$("$1" --version)" == "pip-audit 2.10.0" ]]' _ "${BIN}/pip-audit"

run install_pip_audit -- STUB_TOOL=pip-audit STUB_REPORT_VERSION=9.9.9
check "a tool that reports another version fails" rc_is 1
check "saying so" said "pip-audit reports 'pip-audit 9.9.9', not version 2.10.1"
check "and leaves the environment there was" bash -c '[[ "$("$1" --version)" == "pip-audit 2.10.0" ]]' _ "${BIN}/pip-audit"
run install_pip_audit -- STUB_TOOL=pip-audit STUB_RUN_EXIT=1
check "a tool that doesn't run fails the install" rc_is 1
check "saying so" said "pip-audit 2.10.1 was installed, but doesn't run"
run install_pip_audit -- STUB_TOOL=pip-audit STUB_INSTALL_EXIT=1
check "a failed uv pip install fails the install" rc_is 1
check "with uv's error" said "hash mismatch for some-package"
check "and leaves the environment there was" bash -c '[[ "$("$1" --version)" == "pip-audit 2.10.0" ]]' _ "${BIN}/pip-audit"

run install_bandit -- STUB_TOOL=bandit
check "bandit installs" rc_is 0
check "from its lock" diff -q <(block bandit 1.9.4) "${STUB}/lock.txt"
check "run with python -m bandit" grep -q -- "-I -m bandit \"\$@\"$" "${BIN}/bandit"
run install_pip_licenses -- STUB_TOOL=pip-licenses
check "pip-licenses installs" rc_is 0
check "from its lock" diff -q <(block pip-licenses 5.5.5) "${STUB}/lock.txt"
check "run with python -m piplicenses" grep -q -- "-I -m piplicenses \"\$@\"$" "${BIN}/pip-licenses"

echo "=== verify_checksums"
run install_pip_audit version=9.9.9 -- STUB_TOOL=pip-audit
check "strict refuses a release without a lock" rc_is 1
check "naming the ones it has" said "It has locks for: 2.10.1 2.10.0."
check "before running uv" not_called "python"
run install_pip_audit version=v2.10.1 -- STUB_TOOL=pip-audit
check "a leading v is ignored" rc_is 0
run install_pip_audit version=9.9.9 verify_checksums=known_versions -- STUB_TOOL=pip-audit
check "known_versions installs a release without a lock" rc_is 0
check "warning that it isn't verified" said "WARN: This orb has no lock for pip-audit 9.9.9"
check "without --require-hashes" call_lacks "pip install" "--require-hashes"
check "but still wheels only" call_has "pip install" "--only-binary :all:"
check "the requirement is the release" call_has "pip install" " pip-audit==9.9.9"
check "and the record says it wasn't verified" test "$(record .verified pip-audit)" = false
run install_bandit version=1.9.4 verify_checksums=false -- STUB_TOOL=bandit
check "false installs a listed release unverified too" rc_is 0
check "with a warning" said "WARN: verify_checksums is false"
check "bandit with its toml extra" call_has "pip install" " bandit[toml]==1.9.4"
run install_pip_audit version='$ORB_TEST_VERSION' -- STUB_TOOL=pip-audit ORB_TEST_VERSION=2.10.0 PATH="${WORK}/cli:${WORK}/path:${PATH}"
check "a version from an environment variable without the CircleCI CLI is taken as is" rc_is 1

echo "=== the job's uv settings"
run install_pip_audit -- STUB_TOOL=pip-audit UV_CONFIG_FILE=/tmp/evil.toml UV_PYTHON_DOWNLOADS_JSON_URL=https://evil.example/d.json \
    UV_INDEX_URL=https://evil.example/simple UV_VENV_SEED=1 UV_HTTP_TIMEOUT=90 UV_NATIVE_TLS=1 VIRTUAL_ENV=/somewhere
check "installs" rc_is 0
check "UV_CONFIG_FILE, which beats --no-config, never reaches uv" no_uv_env UV_CONFIG_FILE
check "nor UV_PYTHON_DOWNLOADS_JSON_URL, which replaces the Python hashes" no_uv_env UV_PYTHON_DOWNLOADS_JSON_URL
check "nor UV_INDEX_URL" no_uv_env UV_INDEX_URL
check "nor UV_VENV_SEED" no_uv_env UV_VENV_SEED
check "but the network settings do" uv_env "UV_HTTP_TIMEOUT=90"
check "all of them" uv_env "UV_NATIVE_TLS=1"

echo "=== python"
run install_pip_audit python=3.12 -- STUB_TOOL=pip-audit STUB_PYTHON_VERSION=3.12.9
check "another CPython minor version" rc_is 0
check "is asked of uv" call_has "python install" "--managed-python 3.12"
run install_pip_audit python=system -- STUB_TOOL=pip-audit STUB_PYTHON_VERSION=3.11.4
check "system uses the python3 on the PATH" rc_is 0
check "without asking uv for one" not_called "python install"
check "creating the environment with it" call_has "venv" "--python ${WORK}/path/python3"
check "and the record says so" test "$(record '.python.source + " " + .python.version' pip-audit)" = "system 3.11.4"
run install_pip_audit python="${WORK}/path/python3" -- STUB_TOOL=pip-audit
check "an interpreter's path works too" rc_is 0
check "recorded as a path" test "$(record .python.source pip-audit)" = path
run install_pip_audit python=system -- STUB_TOOL=pip-audit STUB_PYTHON_IMPL=PyPy
check "an interpreter that isn't CPython is refused" rc_is 1
check "saying so" said "but the tools need CPython 3.10 to 3.14"
run install_pip_audit python=system -- STUB_TOOL=pip-audit STUB_PYTHON_VERSION=3.9.18
check "CPython 3.9 is refused" rc_is 1
check "before installing anything" not_called "venv"
run install_pip_audit python=system -- STUB_TOOL=pip-audit STUB_PYTHON_VERSION=3.15.0
check "CPython 3.15, which the locks don't cover, is refused" rc_is 1
for value in 3.9 3.15 3 latest python3.14; do
    run install_pip_audit python="${value}" -- STUB_TOOL=pip-audit
    check "python: ${value} is refused" rc_is 1
    check "saying what it can be" said "ERROR: python must be 3.10 to 3.14"
    check "before running uv" not_called "python"
done
run install_pip_audit python="${WORK}/missing/python3" -- STUB_TOOL=pip-audit
check "a path that doesn't run is refused" rc_is 1
check "saying so" said "does not run as a Python interpreter"
run install_pip_audit -- STUB_TOOL=pip-audit STUB_PYTHON_INSTALL_EXIT=2
check "a Python uv can't install fails the step" rc_is 1
check "with uv's error" said "no download for that request"

echo "=== mirrors"
run install_pip_audit index_url=https://artifactory.example/api/pypi/pypi/simple -- STUB_TOOL=pip-audit
check "index_url is the index uv downloads from" call_has "pip install" "--default-index https://artifactory.example/api/pypi/pypi/simple"
check "and the record names it" test "$(record .index pip-audit)" = "https://artifactory.example/api/pypi/pypi/simple"
for value in http://pypi.example/simple pypi.example/simple; do
    run install_pip_audit index_url="${value}" -- STUB_TOOL=pip-audit
    check "index_url ${value} is refused" rc_is 1
    check "saying it must be https" said "index_url must be a https:// URL"
done
run install_pip_audit index_url=https://user:s3cret@pypi.example/simple -- STUB_TOOL=pip-audit
check "credentials in index_url are refused" rc_is 1
check "without printing them" script_lacks "s3cret"
run install_pip_audit python_install_mirror=file:///srv/python-build-standalone -- STUB_TOOL=pip-audit
check "a file:// Python mirror" rc_is 0
check "reaches uv as UV_PYTHON_INSTALL_MIRROR" uv_env "UV_PYTHON_INSTALL_MIRROR=file:///srv/python-build-standalone"
run install_pip_audit python_install_mirror=http://mirror.example/python -- STUB_TOOL=pip-audit
check "an http:// Python mirror is refused" rc_is 1
check "saying what it can be" said "python_install_mirror must be a https:// or file:// URL"
run install_pip_audit caching=false -- STUB_TOOL=pip-audit
check "caching false keeps the Python archive in a temporary directory" grep -q '^  env UV_PYTHON_CACHE_DIR=/tmp' "${STUB}/uv.log"

echo "=== install_path and uv"
run install_pip_audit install_path=relative -- STUB_TOOL=pip-audit
check "a relative install_path is refused" rc_is 1
check "saying so" said "install_path must be an absolute path"
run install_pip_audit install_path="${WORK}/elsewhere" -- STUB_TOOL=pip-audit
check "an install_path without uv is refused" rc_is 1
check "saying to run install_uv there first" said "There is no uv in ${WORK}/elsewhere"
mkdir -p "${WORK}/elsewhere"
cp "${STUB}/uv" "${WORK}/elsewhere/uv"
run install_pip_audit install_path="${WORK}/elsewhere" -- STUB_TOOL=pip-audit
check "another install_path with uv in it" rc_is 0
check "gets the script" test -x "${WORK}/elsewhere/pip-audit"
check "and goes on the PATH" grep -q "^export PATH=${WORK}/elsewhere:" "${WORK}/bash_env"
mkdir -p "${HOME_DIR}/tools"
cp "${STUB}/uv" "${HOME_DIR}/tools/uv"
run install_pip_audit "install_path=~/tools" -- STUB_TOOL=pip-audit
check "a leading ~ in install_path is the home directory, as install_uv reads it" test -x "${HOME_DIR}/tools/pip-audit"
run install_pip_audit -- STUB_TOOL=pip-audit PATH="${BIN}:${WORK}/path:${PATH}"
check "an install_path already on the PATH isn't added again" bash -c '! grep -q "^export PATH=" "$1"' _ "${WORK}/bash_env"

echo "=== install_python"
run install_python -- STUB_TOOL=python
check "installs the Python alone" rc_is 0
check "with uv" call_has "python install" "--managed-python 3.14"
check "and no environment" not_called "venv"
check "exporting it" exported PYTHON_SECURITY_ORB_PYTHON "${HOME_DIR}/.python-security-orb/python/cpython-3.14.10-linux-x86_64-gnu/bin/python3.14"

if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${FAILURES} install check(s) failed."
    exit 1
fi
echo "All install checks passed."
