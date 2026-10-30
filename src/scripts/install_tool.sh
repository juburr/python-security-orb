#!/bin/bash
#
# Installs one Python tool for install_pip_audit, install_bandit and
# install_pip_licenses (or, for install_python, only the Python they run on)
# with the uv that install_uv put in install_path:
#
#   1. Python: a CPython that uv downloads and checks against the SHA-256 it
#      carries for each build (python: 3.10 to 3.14), or the executor's own
#      (system, or a path).
#   2. A new virtual environment on it, into which uv installs the tool's lock
#      from PS_LOCKS (src/install/<tool>/locks.txt) with --require-hashes:
#      every file is checked against the SHA-256 the lock pins, and a package
#      the lock doesn't pin fails the install. Wheels only, so no build code
#      runs.
#   3. A smoke test, then the environment replaces any earlier one, and a
#      small script in install_path runs the tool in it with python -I, so a
#      job's PYTHONPATH or a project's own packages can't reach it.
#
# Nothing a job or a project configures for uv (UV_* variables, uv.toml,
# [tool.uv]) changes what is installed, and the install leaves a record
# beside the script, which the commands' run records include.

set -euo pipefail

if [[ -z "${SCRIPT_PYTHON_SECURITY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_PYTHON_SECURITY_LIB is not set; run this script through the orb's install commands." >&2
    exit 1
fi
eval "${SCRIPT_PYTHON_SECURITY_LIB}"

TOOL=${PARAM_TOOL}
VERSION=$(ps_subst "${PARAM_VERSION}")
VERSION=${VERSION#v}
VERIFY=$(ps_subst "${PARAM_VERIFY_CHECKSUMS}")
PYTHON_REQUEST=$(ps_subst "${PARAM_PYTHON}")
INDEX_URL=$(ps_subst "${PARAM_INDEX_URL}")
MIRROR=$(ps_subst "${PARAM_PYTHON_INSTALL_MIRROR}")
INSTALL_DIR=$(ps_subst "${PARAM_INSTALL_PATH}")
CACHING=$(ps_bool caching "${PARAM_CACHING}")
ORB_HOME="${HOME}/.python-security-orb"

# Each tool's module, run with python -m.
case "${TOOL}" in
    pip-audit) MODULE=pip_audit ;;
    bandit) MODULE=bandit ;;
    pip-licenses) MODULE=piplicenses ;;
    python) MODULE="" ;;
    *)
        echo "ERROR: install_tool.sh doesn't install '${TOOL}'." >&2
        exit 1
        ;;
esac

# --- Parameters ---
if [[ -n "${MODULE}" ]] && ! ps_match "${VERSION}" '^[0-9]+(\.[0-9]+)*$'; then
    echo "ERROR: version must be a ${TOOL} release, such as 1.2.3, not '${VERSION}'." >&2
    exit 1
fi
case "${VERIFY}" in
    strict | known_versions | false) ;;
    *)
        echo "ERROR: verify_checksums must be strict, known_versions or false, not '${VERIFY}'." >&2
        exit 1
        ;;
esac
PYTHON_REQUEST=${PYTHON_REQUEST:-3.14}
if [[ "${PYTHON_REQUEST}" != system && "${PYTHON_REQUEST}" != /* ]] \
    && ! ps_match "${PYTHON_REQUEST}" '^3\.1[0-4]$'; then
    echo "ERROR: python must be 3.10 to 3.14 (a CPython that uv downloads), system, or an interpreter's absolute" >&2
    echo "  path, not '${PYTHON_REQUEST}'. The locks cover CPython 3.10 to 3.14." >&2
    exit 1
fi
# ps_mirror PARAMETER VALUE SCHEMES: stops the step unless VALUE is a URL
# with one of SCHEMES and without credentials, a query or a fragment, which
# would show in the log.
ps_mirror() {
    local authority=${2#*://}
    if [[ "${authority%%/*}" == *@* || "$2" == *[?#]* ]]; then
        echo "ERROR: $1 must not hold credentials, a query or a fragment, which would show in the log." >&2
        exit 1
    fi
    if ! ps_match "$2" "^($3)://[^[:space:]\"'<>\\\\]+\$"; then
        echo "ERROR: $1 must be a ${3//|/:// or }:// URL, not '$2'." >&2
        exit 1
    fi
}
INDEX_URL=${INDEX_URL:-https://pypi.org/simple}
ps_mirror index_url "${INDEX_URL}" https
if [[ -n "${MIRROR}" ]]; then
    ps_mirror python_install_mirror "${MIRROR}" 'https|file'
fi
INSTALL_DIR=${INSTALL_DIR:-${ORB_HOME}/bin}
INSTALL_DIR=${INSTALL_DIR%/}
if [[ "${INSTALL_DIR}" != /* || "${INSTALL_DIR}" == *$'\n'* ]]; then
    echo "ERROR: install_path must be an absolute path, not '${INSTALL_DIR}'." >&2
    exit 1
fi
UV="${INSTALL_DIR}/uv"
if [[ ! -x "${UV}" ]]; then
    echo "ERROR: There is no uv in ${INSTALL_DIR}. Install it there first with install_uv, with the same install_path." >&2
    exit 1
fi

# --- What to install ---
REQUIREMENTS=""
VERIFIED=false
if [[ -n "${MODULE}" ]]; then
    LOCK=$(awk -v start="# >>> ${TOOL} ${VERSION} >>>" -v end="# <<< ${TOOL} ${VERSION} <<<" '
        $0 == start { on = 1; next } $0 == end { on = 0 } on' <<< "${PS_LOCKS:-}")
    LISTED=$(sed -n "s/^# >>> ${TOOL} \\([^ ]*\\) >>>\$/\\1/p" <<< "${PS_LOCKS:-}" | tr '\n' ' ')
    if [[ -n "${LOCK}" && "${VERIFY}" != false ]]; then
        VERIFIED=true
    elif [[ "${VERIFY}" == strict ]]; then
        echo "ERROR: This orb has no lock for ${TOOL} ${VERSION}, so it can't verify what it would install." >&2
        echo "  It has locks for: ${LISTED% }. Pick one of those, or set verify_checksums to known_versions to" >&2
        echo "  install an unlisted version without verifying it." >&2
        exit 1
    elif [[ "${VERIFY}" == known_versions ]]; then
        echo "WARN: This orb has no lock for ${TOOL} ${VERSION}, so it is installed WITHOUT verification (known_versions)." >&2
    else
        echo "WARN: verify_checksums is false, so ${TOOL} ${VERSION} is installed WITHOUT verification." >&2
    fi
fi

WORK=$(mktemp -d)
STAGE=""
trap 'rm -rf "${WORK}" ${STAGE:+"${STAGE}"}' EXIT

# Nothing a job sets for uv may change what is installed: UV_CONFIG_FILE
# beats --no-config, UV_PYTHON_DOWNLOADS_JSON_URL replaces the hashes of the
# Python builds, UV_VENV_SEED adds unhashed packages, and others change the
# index, the cache or the Python. Only the network settings stay; the hashes
# cover whatever comes through them.
while IFS= read -r name; do
    case "${name}" in
        UV_HTTP_TIMEOUT | UV_HTTP_RETRIES | UV_NATIVE_TLS | UV_SYSTEM_CERTS | UV_INSECURE_HOST) ;;
        UV_*) unset "${name}" ;;
    esac
done < <(compgen -e)
unset VIRTUAL_ENV CONDA_PREFIX PYTHONPATH PYTHONHOME
export UV_NO_CONFIG=1 UV_CACHE_DIR="${WORK}/uv-cache" UV_PYTHON_INSTALL_DIR="${ORB_HOME}/python"
if [[ "${CACHING}" == true ]]; then
    export UV_PYTHON_CACHE_DIR="${HOME}/.cache/python-security-orb/python"
else
    export UV_PYTHON_CACHE_DIR="${WORK}/python-cache"
fi
if [[ -n "${MIRROR}" ]]; then
    export UV_PYTHON_INSTALL_MIRROR="${MIRROR}"
fi
# uv reads no project files outside the work directory.
cd "${WORK}"
UV_VERSION=$("${UV}" --version | awk '{ print $2 }')

# --- Python ---
case "${PYTHON_REQUEST}" in
    system)
        if ! PYTHON=$(command -v python3); then
            echo "ERROR: python is system, but there is no python3 on the PATH." >&2
            exit 1
        fi
        PYTHON_SOURCE=system
        ;;
    /*)
        PYTHON=${PYTHON_REQUEST}
        PYTHON_SOURCE=path
        ;;
    *)
        echo "Installing CPython ${PYTHON_REQUEST} with uv ${UV_VERSION}, checked against the SHA-256 uv carries for it."
        if ! "${UV}" python install --no-config --no-bin --managed-python "${PYTHON_REQUEST}" 2> "${WORK}/python.log"; then
            ps_tail "${WORK}/python.log" 20
            echo "ERROR: uv could not install CPython ${PYTHON_REQUEST}." >&2
            exit 1
        fi
        PYTHON=$("${UV}" python find --no-config --managed-python --no-python-downloads "${PYTHON_REQUEST}")
        PYTHON_SOURCE=uv
        ;;
esac
if ! PYTHON_INFO=$("${PYTHON}" -I -c 'import platform, sys; print(platform.python_implementation(), "%d.%d.%d" % sys.version_info[:3])' 2> /dev/null); then
    echo "ERROR: ${PYTHON} does not run as a Python interpreter." >&2
    exit 1
fi
PYTHON_VERSION=${PYTHON_INFO#* }
if [[ "${PYTHON_INFO%% *}" != CPython ]] || ! ps_match "${PYTHON_VERSION}" '^3\.1[0-4]\.'; then
    echo "ERROR: ${PYTHON} is ${PYTHON_INFO}, but the tools need CPython 3.10 to 3.14, which the locks cover." >&2
    exit 1
fi
echo "Python: ${PYTHON} (CPython ${PYTHON_VERSION}, ${PYTHON_SOURCE})"
ps_export PYTHON_SECURITY_ORB_PYTHON "${PYTHON}"
if [[ -z "${MODULE}" ]]; then
    exit 0
fi

# --- The tool's environment ---
VENVS="${ORB_HOME}/venvs"
mkdir -p "${VENVS}" "${INSTALL_DIR}"
STAGE=$(mktemp -d "${VENVS}/.${TOOL}.XXXXXX")
if ! "${UV}" venv --no-config --no-python-downloads --relocatable --quiet --python "${PYTHON}" "${STAGE}/venv" 2> "${WORK}/venv.log"; then
    ps_tail "${WORK}/venv.log" 20
    echo "ERROR: uv could not create a virtual environment with ${PYTHON}." >&2
    exit 1
fi
INSTALL=("${UV}" pip install --no-config --python "${STAGE}/venv/bin/python" --only-binary :all: --strict
    --link-mode copy --compile-bytecode --default-index "${INDEX_URL}" --keyring-provider disabled)
if [[ "${VERIFIED}" == true ]]; then
    printf '%s\n' "${LOCK}" > "${WORK}/lock.txt"
    INSTALL+=(--require-hashes -r "${WORK}/lock.txt")
    echo "Installing ${TOOL} ${VERSION} from its lock ($(grep -c '^[A-Za-z0-9]' "${WORK}/lock.txt") packages, every file checked against its SHA-256)."
else
    case "${TOOL}" in
        bandit) REQUIREMENTS="bandit[toml]==${VERSION}" ;;
        *) REQUIREMENTS="${TOOL}==${VERSION}" ;;
    esac
    INSTALL+=("${REQUIREMENTS}")
    echo "Installing ${REQUIREMENTS} and the dependencies the index offers today, unverified."
fi
if ! "${INSTALL[@]}" 2> "${WORK}/install.log"; then
    ps_tail "${WORK}/install.log" 30
    echo "ERROR: uv could not install ${TOOL} ${VERSION} from ${INDEX_URL}." >&2
    exit 1
fi

# The new environment must run the tool before it replaces the old one.
if ! REPORTED=$("${STAGE}/venv/bin/python" -I -m "${MODULE}" --version 2>&1); then
    printf '%s\n' "${REPORTED}" | sed 's/^/  /' >&2
    echo "ERROR: ${TOOL} ${VERSION} was installed, but doesn't run." >&2
    exit 1
fi
if [[ "$(head -n 1 <<< "${REPORTED}")" != *" ${VERSION}"* ]]; then
    echo "ERROR: ${TOOL} reports '$(head -n 1 <<< "${REPORTED}")', not version ${VERSION}." >&2
    exit 1
fi
VENV="${VENVS}/${TOOL}"
if [[ -e "${VENV}" ]]; then
    mv "${VENV}" "${STAGE}/old"
fi
mv "${STAGE}/venv" "${VENV}"

# The script that runs it: python -I keeps PYTHONPATH, PYTHONHOME and the
# user's site-packages out of the tool's imports.
SHIM="${INSTALL_DIR}/${TOOL}"
QUOTED="'${VENV//\'/\'\\\'\'}/bin/python'"
printf '#!/bin/sh\n# %s %s, installed by python-security-orb in %s.\nexec %s -I -m %s "$@"\n' \
    "${TOOL}" "${VERSION}" "${VENV}" "${QUOTED}" "${MODULE}" > "${WORK}/shim"
chmod 755 "${WORK}/shim"
mv "${WORK}/shim" "${SHIM}"
LOCK_SHA=""
if [[ "${VERIFIED}" == true ]]; then
    LOCK_SHA=$(ps_sha256 "${WORK}/lock.txt")
fi
jq -n --arg tool "${TOOL}" --arg version "${VERSION}" --argjson verified "${VERIFIED}" --arg mode "${VERIFY}" \
    --arg lock "${LOCK_SHA}" --arg python "${PYTHON}" --arg python_version "${PYTHON_VERSION}" \
    --arg python_source "${PYTHON_SOURCE}" --arg uv "${UV_VERSION}" --arg index "$(ps_url_public "${INDEX_URL}")" \
    --arg venv "${VENV}" --arg sha "$(sha512sum -- "${SHIM}" | awk '{ print $1 }')" \
    --argjson packages "$("${UV}" pip list --no-config --python "${VENV}/bin/python" --format json 2> /dev/null || echo null)" '{
        tool: $tool, version: $version, verified: $verified, verify_checksums: $mode,
        lock_sha256: (if $lock == "" then null else $lock end),
        python: {path: $python, version: $python_version, source: $python_source},
        uv: $uv, index: $index, venv: $venv, packages: $packages, binary_sha512: $sha}' \
    > "${INSTALL_DIR}/.${TOOL}.install.json"

if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
    if [[ -n "${BASH_ENV:-}" ]]; then
        ps_export PATH "${INSTALL_DIR}:${PATH}"
        echo "Added ${INSTALL_DIR} to the PATH for later steps."
    else
        echo "WARN: ${INSTALL_DIR} is not on the PATH. Add it to run ${TOOL} by name." >&2
    fi
fi
echo "Installed ${TOOL} ${VERSION} in ${VENV}, run by ${SHIM}."
