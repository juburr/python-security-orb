#!/usr/bin/env bash
#
# Tests the command scripts offline, each run by tests/run_command.sh with its
# parameters' defaults from the command's YAML, against stand-ins for
# pip-audit, bandit, pip-licenses and the package managers that record their
# arguments and answer from fixtures, and the real Python helper:
#
#   audit         every lockfile format, pinned requirements and environments
#                 into one pylock.toml; findings, ignores, skips, and every
#                 way an audit has no verdict; the reports
#   bandit        the arguments, the gate, files Bandit couldn't parse, a scan
#                 of nothing, suppressions without reasons; the reports
#   licenses      the inventory and the policy: SPDX expressions, classifiers,
#                 clarify and ignore; the checks that it inventoried something
#   lock_verify   hashes, pins, sources, indexes, release age, freshness with
#                 the package manager, and installed files against RECORD
#
# The scripts run with the bash first on the PATH, so putting an older bash
# there checks it. A stand-in circleci CLI expands $ORB_TEST_VAR. The Python
# helper runs on the python3 on the PATH, which must be 3.11 or newer.
#
# Run from a checkout:
#   bash tests/commands_test.sh

# The checks run small scripts in single quotes, which expand their own
# arguments.
# shellcheck disable=SC2016

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURES="${ROOT}/tests/fixtures"
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STUB="${WORK}/stub"
HOME_DIR="${WORK}/home"
JOB="${WORK}/job"
OUT="${WORK}/reports"
mkdir -p "${WORK}/bin" "${STUB}" "${HOME_DIR}" "${JOB}"

# Like `circleci env subst`, expands $NAME and ${NAME} references, from stdin.
cat > "${WORK}/bin/circleci" << 'EOF'
#!/usr/bin/env bash
if [[ "$*" != "env subst" ]]; then
    echo "circleci stub: expected 'env subst' with the value on stdin, got: $*" >&2
    exit 1
fi
input=$(cat)
output=""
re='^([^$]*)\$(\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))(.*)$'
while [[ "${input}" =~ ${re} ]]; do
    name=${BASH_REMATCH[3]:-${BASH_REMATCH[4]}}
    output+="${BASH_REMATCH[1]}${!name-}"
    input=${BASH_REMATCH[5]}
done
printf '%s' "${output}${input}"
EOF

# The stand-in pip-audit: audits the pylock.toml in the --locked directory
# against a few real advisories. Settings:
#   STUB_AUDIT_EXIT   exit with this code after a traceback, writing no report
#   STUB_SKIP         a package to report as not found on PyPI
#   STUB_EXIT         exit with this code whatever the report says
#   STUB_DRY_RUN      write a report that lists no package, as --dry-run does
cat > "${WORK}/bin/pip-audit" << 'EOF'
#!/usr/bin/env bash
set +o errexit +o nounset +o pipefail +o xtrace
if [[ "$1" == --version ]]; then
    echo "pip-audit 2.10.1"
    exit 0
fi
printf '%s\n' "$@" > "${STUB_DIR}/pip-audit.args"
env | grep -E '^(PIP_AUDIT|PIPAPI)' > "${STUB_DIR}/pip-audit.env"
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[i]}" in
        --locked) lockdir=${args[i + 1]} ;;
        --output) out=${args[i + 1]} ;;
    esac
done
cp "${lockdir}/pylock.toml" "${STUB_DIR}/pylock.toml"
if [[ -n "${STUB_AUDIT_EXIT:-}" ]]; then
    echo "Traceback (most recent call last):"
    echo "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='pypi.org', port=443)"
    exit "${STUB_AUDIT_EXIT}"
fi
if [[ -n "${STUB_DRY_RUN:-}" ]]; then
    echo '{"dependencies": [], "fixes": []}' > "${out}"
    exit 0
fi
python3 -I - "${lockdir}/pylock.toml" "${out}" "${STUB_SKIP:-}" << 'PY'
import json, sys, tomllib
ADVISORIES = {
    ("requests", "2.19.1"): [
        {"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"], "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
         "description": "The Requests package sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect."},
        {"id": "GHSA-j8r2-6x86-q33q", "fix_versions": ["2.31.0"], "aliases": ["CVE-2023-32681", "PYSEC-2023-74"],
         "description": "Unintended leak of Proxy-Authorization header in requests"},
    ],
    ("urllib3", "1.23"): [
        {"id": "PYSEC-2019-133", "fix_versions": ["1.24.2"], "aliases": ["CVE-2019-11324"],
         "description": "The urllib3 library mishandles certain cases where the desired set of CA certificates is different from the OS store."},
    ],
}
lock, out, skip = sys.argv[1], sys.argv[2], sys.argv[3]
deps = []
for p in tomllib.load(open(lock, "rb"))["packages"]:
    # pip-audit reports versions normalized (a leading v dropped, numbers
    # without leading zeros).
    version = p["version"].strip().lower()
    version = version[1:] if version.startswith("v") else version
    p["version"] = ".".join(str(int(part)) if part.isdigit() else part for part in version.split("."))
    if p["name"] == skip:
        deps.append({"name": p["name"], "skip_reason": "Dependency not found on PyPI and could not be audited: %s (%s)" % (p["name"], p["version"])})
    else:
        deps.append({"name": p["name"], "version": p["version"], "vulns": ADVISORIES.get((p["name"], p["version"]), [])})
json.dump({"dependencies": deps, "fixes": []}, open(out, "w"))
n = sum(len(d.get("vulns", [])) for d in deps)
print("Found %d known vulnerabilities in %d packages" % (n, sum(1 for d in deps if d.get("vulns"))) if n else "No known vulnerabilities found", file=sys.stderr)
sys.exit(1 if n else 0)
PY
status=$?
exit "${STUB_EXIT:-${status}}"
EOF
# The stand-in bandit: writes a fixture report from tests/fixtures/bandit to
# --output, the --ignore-nosec run's from STUB_BANDIT_ALL, and exits 1 when
# it has results. Settings:
#   STUB_BANDIT_REPORT  the report (default clean.json), or an absolute path
#   STUB_BANDIT_ALL     the --ignore-nosec run's report (default all.json)
#   STUB_BANDIT_EXIT    exit with this code after a traceback, the report empty
#   STUB_BANDIT_LOG     a line to log on stderr
cat > "${WORK}/bin/bandit" << 'EOF'
#!/usr/bin/env bash
set +o errexit +o nounset +o pipefail +o xtrace
if [[ "$1" == --version ]]; then
    printf 'bandit 1.9.4\n  python version = 3.14.10 (main, Oct 9 2026, 00:00:00) [Clang 20.1.4 ]\n'
    exit 0
fi
args=("$@")
report="${STUB_FIXTURES}/bandit/${STUB_BANDIT_REPORT:-clean.json}"
[[ "${STUB_BANDIT_REPORT:-}" == /* ]] && report=${STUB_BANDIT_REPORT}
pass=""
for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[i]}" in
        --output) out=${args[i + 1]} ;;
        --ignore-nosec)
            report="${STUB_FIXTURES}/bandit/${STUB_BANDIT_ALL:-all.json}"
            pass=-all
            ;;
        --ini) cp "${args[i + 1]}" "${STUB_DIR}/bandit.ini" ;;
    esac
done
printf '%s\n' "$@" > "${STUB_DIR}/bandit${pass}.args"
: > "${out}"
[[ -n "${STUB_BANDIT_LOG:-}" ]] && echo "${STUB_BANDIT_LOG}" >&2
if [[ -n "${STUB_BANDIT_EXIT:-}" ]]; then
    echo "Traceback (most recent call last):" >&2
    echo "TypeError: argument of type 'NoneType' is not iterable" >&2
    exit "${STUB_BANDIT_EXIT}"
fi
cp "${report}" "${out}"
[[ "$(jq '.results | length' "${out}")" -gt 0 ]] && exit 1
exit 0
EOF
# The stand-in pip-licenses: lists the distributions the --python
# interpreter sees, with the fields pip-licenses --from=all writes, read from
# their metadata. Settings:
#   STUB_LICENSES_EXIT  exit with this code after a traceback, listing nothing
#   STUB_LICENSES_DROP  a package to leave out
cat > "${WORK}/bin/pip-licenses" << 'EOF'
#!/usr/bin/env bash
set +o errexit +o nounset +o pipefail +o xtrace
if [[ "$1" == --version ]]; then
    echo "pip-licenses 5.5.5"
    exit 0
fi
printf '%s\n' "$@" > "${STUB_DIR}/pip-licenses.args"
{
    echo "files in the working directory: $(find . -mindepth 1 | wc -l)"
    echo "PYTHONPATH: ${PYTHONPATH-unset}"
} > "${STUB_DIR}/pip-licenses.env"
for arg in "$@"; do
    case "${arg}" in
        --python=*) python=${arg#--python=} ;;
    esac
done
if [[ -n "${STUB_LICENSES_EXIT:-}" ]]; then
    echo "Traceback (most recent call last):" >&2
    echo "FileNotFoundError: [Errno 2] No such file or directory" >&2
    exit "${STUB_LICENSES_EXIT}"
fi
"${python}" - "${STUB_LICENSES_DROP:-}" << 'PY'
import json, sys
from importlib import metadata
rows = []
for dist in metadata.distributions():
    meta = dist.metadata
    if meta["Name"] == sys.argv[1]:
        continue
    classifiers = [c.split(" :: ")[-1] for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    rows.append({"Name": meta["Name"], "Version": dist.version, "License-Metadata": meta.get("License") or "UNKNOWN",
                 "License-Classifier": "; ".join(classifiers) or "UNKNOWN",
                 "License-Expression": meta.get("License-Expression") or "UNKNOWN", "URL": meta.get("Home-page") or "UNKNOWN"})
print(json.dumps(rows))
PY
EOF
chmod +x "${WORK}/bin/"*

# The stand-in package managers, uv, poetry, pdm and pipenv (one script,
# by the name it runs as): each records its arguments, working directory and
# the variables that would change its check, and answers with the real
# managers' messages. Settings:
#   STUB_FRESH      fresh (default), stale, stale1 (Poetry 1.x's message) or error
#   STUB_FRESH_FOR  the one manager STUB_FRESH applies to; the others answer fresh
mkdir -p "${WORK}/managers"
cat > "${WORK}/managers/uv" << 'EOF'
#!/usr/bin/env bash
set +o errexit +o nounset +o pipefail +o xtrace
tool=${0##*/}
if [[ "$1" == --version ]]; then
    echo "${tool} 9.9.9"
    exit 0
fi
printf '%s\n' "$@" > "${STUB_DIR}/${tool}.args"
{
    pwd
    env | grep -E '^(UV_FROZEN|UV_LOCKED|UV_PROJECT|UV_WORKING_DIR|UV_WORKING_DIRECTORY|PDM_PROJECT|PIPENV_PIPFILE)=' || true
} > "${STUB_DIR}/${tool}.env"
state=${STUB_FRESH:-fresh}
if [[ -n "${STUB_FRESH_FOR:-}" && "${STUB_FRESH_FOR}" != "${tool}" ]]; then
    state=fresh
fi
case "${state}:${tool}" in
    stale:uv)
        echo 'error: The lockfile at `uv.lock` needs to be updated, but `--check` was provided. To update the lockfile, run `uv lock`.' >&2
        exit 1
        ;;
    stale:poetry)
        echo 'Error: pyproject.toml changed significantly since poetry.lock was last generated. Run `poetry lock` to fix the lock file.' >&2
        exit 1
        ;;
    stale1:poetry)
        echo 'Error: poetry.lock is not consistent with pyproject.toml. Run `poetry lock [--no-update]` to fix it.' >&2
        exit 1
        ;;
    stale:pdm)
        echo '❌ Lockfile is out of date.' >&2
        exit 1
        ;;
    stale:pipenv)
        echo 'Pipfile.lock is out-of-date. Run $ pipenv lock to update.' >&2
        exit 1
        ;;
    error:*)
        echo 'error: No `pyproject.toml` found in current directory or any parent directory' >&2
        exit 2
        ;;
    fresh:pdm)
        echo '✅ Lockfile is up to date.' >&2
        ;;
    fresh:pipenv)
        echo 'Pipfile.lock is up-to-date.'
        ;;
    *)
        echo 'Resolved 6 packages in 1ms'
        ;;
esac
exit 0
EOF
for manager in poetry pdm pipenv; do
    ln -s uv "${WORK}/managers/${manager}"
done
chmod +x "${WORK}/managers/uv"

# The PATH without the machine's own package managers: each directory that
# holds one is replaced by links to everything else in it.
CLEAN_PATH=""
IFS=: read -ra PATH_DIRS <<< "${PATH}"
for dir in "${PATH_DIRS[@]}"; do
    [[ -d "${dir}" ]] || continue
    if [[ -e "${dir}/uv" || -e "${dir}/poetry" || -e "${dir}/pdm" || -e "${dir}/pipenv" ]]; then
        shadow=$(mktemp -d "${WORK}/path.XXXXXX")
        for file in "${dir}"/*; do
            case "${file##*/}" in
                uv | uvx | poetry | pdm | pipenv) ;;
                *) ln -s "${file}" "${shadow}/" ;;
            esac
        done
        dir=${shadow}
    fi
    CLEAN_PATH+="${CLEAN_PATH:+:}${dir}"
done

FAILURES=0
RC=0
OUTPUT=""

# run COMMAND [NAME=VALUE ...] [-- VAR=value ...]: runs COMMAND's script in
# the job directory through tests/run_command.sh, with the parameters given
# and the environment settings after --.
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
    rm -f "${STUB}"/*.args "${STUB}"/*.env "${STUB}/pylock.toml"
    : > "${WORK}/bash_env"
    OUTPUT=$(cd "${JOB}" && env HOME="${HOME_DIR}" PATH="${WORK}/bin:${WORK}/managers:${CLEAN_PATH}" BASH_ENV="${WORK}/bash_env" \
        STUB_DIR="${STUB}" STUB_FIXTURES="${FIXTURES}" ${envs[@]+"${envs[@]}"} \
        bash "${ROOT}/tests/run_command.sh" "${command}" "output_dir=${OUT}" ${params[@]+"${params[@]}"} 2>&1)
    RC=$?
    for record in "${OUT}"/*.run-record.json; do
        [[ -f "${record}" ]] || continue
        RECORDS=$((RECORDS + 1))
        cp "${record}" "${WORK}/records/${RECORDS}.json"
    done
}
RECORDS=0
mkdir -p "${WORK}/records"

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
        FAILURES=$((FAILURES + 1))
    fi
}
rc_is() { [[ "${RC}" -eq "$1" ]]; }
said() { grep -qF -- "$1" <<< "${OUTPUT}"; }
not_said() { ! said "$1"; }
# script_lacks TEXT: the script's output lacks TEXT; run_command.sh's own
# first line, which echoes the parameters, is left out.
script_lacks() { ! grep -v '^Running scripts/' <<< "${OUTPUT}" | grep -qF -- "$1"; }
args_have() { grep -qzF -- "$(printf '%s\n' "${@:2}")" "${STUB}/$1.args"; }
args_lack() { ! grep -qxF -- "$2" "${STUB}/$1.args"; }
not_run() { [[ ! -e "${STUB}/$1.args" ]]; }
report() { [[ -s "${OUT}/$1" ]]; }
no_report() { [[ ! -e "${OUT}/$1" ]]; }
json_is() { [[ "$(jq -c "$2" "${OUT}/$1" 2> /dev/null)" == "$3" ]]; }
# fixture NAME: copies tests/fixtures/NAME to the job directory, alone.
fixture() {
    rm -rf "${JOB}"
    mkdir -p "${JOB}"
    if [[ -n "${1:-}" ]]; then
        cp -R "${FIXTURES}/$1/." "${JOB}/"
    fi
}

echo "=== audit: inputs"
fixture vulnerable
run audit
check "the vulnerable fixture fails the audit" rc_is 1
check "auditing every lockfile in working_dir" said "Auditing the lockfiles in ${JOB}: uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml"
check "pip-audit audits a pylock.toml" args_have pip-audit --locked
check "with a JSON report pip-audit writes only when it completes" args_have pip-audit --format json --output
check "with descriptions and aliases" args_have pip-audit --desc on --aliases on --progress-spinner off
check "from PyPI by default" args_have pip-audit --vulnerability-service pypi --timeout 15
check "every package once, though five lockfiles list them" \
    test "$(grep -c '^\[\[packages\]\]' "${STUB}/pylock.toml")" -eq 5
check "but not the project itself" bash -c '! grep -q fixture-vulnerable "$1"' _ "${STUB}/pylock.toml"
check "saying how many it audits" said "Auditing 5 packages with the pypi service."
check "and what it found" said "pip-audit: 5 packages audited, 3 vulnerabilities in 2 packages."
check "naming each" said "  requests 2.19.1: PYSEC-2018-28 (CVE-2018-18074, GHSA-x84v-xcm2-53pg), fixed in 2.20.0"
check "and the local package it didn't audit" said "Not audited, as local packages: fixture-vulnerable (uv.lock)"
check "the summary report" report pip-audit.json
check "lists the five inputs" json_is pip-audit.json '[.inputs[].kind]' '["uv.lock","poetry.lock","pdm.lock","Pipfile.lock","pylock"]'
check "and the findings, with the inputs each package came from" \
    json_is pip-audit.json '[.findings[] | select(.id == "PYSEC-2019-133") | .inputs | length]' '[5]'
check "pip-audit's own report is kept" report pip-audit.pip-audit.json
check "SARIF has a rule per vulnerability" json_is pip-audit.sarif '[.runs[0].tool.driver.rules[].id] | sort' \
    '["GHSA-j8r2-6x86-q33q","PYSEC-2018-28","PYSEC-2019-133"]'
check "and a result per vulnerability and input" json_is pip-audit.sarif '.runs[0].results | length' 15
check "at the package's line in each lockfile" json_is pip-audit.sarif \
    '[.runs[0].results[] | select(.ruleId == "PYSEC-2019-133" and .locations[0].physicalLocation.artifactLocation.uri == "uv.lock") | .locations[0].physicalLocation.region.startLine]' \
    "[$(grep -n '^name = "urllib3"$' "${FIXTURES}/vulnerable/uv.lock" | cut -d: -f1)]"
check "JUnit has a failed case per vulnerable package" \
    test "$(grep -c '<failure ' "${OUT}/junit/pip-audit.xml")" -eq 2
check "and passed ones for the rest" grep -q 'name="certifi 2026.7.22"></testcase>' "${OUT}/junit/pip-audit.xml"
run audit -- PIP_AUDIT_FORMAT=columns PIP_AUDIT_OUTPUT=/tmp/x PIPAPI_PYTHON_LOCATION=/usr/bin/python3
check "the job's PIP_AUDIT_* and PIPAPI_* variables never reach pip-audit" test ! -s "${STUB}/pip-audit.env"
check "so the audit still works" said "pip-audit: 5 packages audited"

for file in uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml requirements.txt; do
    if [[ "${file}" == requirements.txt ]]; then
        run audit requirements="${file}"
    else
        run audit lockfiles="${file}"
    fi
    check "${file} alone: every package audited" said "Auditing 5 packages with the pypi service."
    check "${file} alone: and the findings" said "3 vulnerabilities in 2 packages"
done
run audit 'lockfiles=*.lock'
check "a glob names several lockfiles" json_is pip-audit.json '[.inputs[].path]' '["Pipfile.lock","pdm.lock","poetry.lock","uv.lock"]'
run audit lockfiles=missing.lock
check "a lockfile that isn't there fails the step" rc_is 1
check "saying so" said "lockfiles names 'missing.lock', but there is no such file"
check "before pip-audit runs" not_run pip-audit
run audit 'lockfiles=*.missing'
check "and so does a glob that matches nothing" said "lockfiles names '*.missing'"

fixture ""
run audit
check "a directory without a lockfile fails the step" rc_is 1
check "saying what to name" said "There is no lockfile in ${JOB}"
fixture clean
run audit
check "the clean fixture passes" rc_is 0
check "auditing its one package" said "pip-audit: 1 package audited, 0 vulnerabilities in 0 packages."

echo "=== audit: the gate"
fixture vulnerable
run audit lockfiles=uv.lock report_only=true
check "report_only reports the vulnerabilities" rc_is 0
check "with a warning" said "WARN: pip-audit found 3 vulnerabilities in 2 packages."
run audit lockfiles=uv.lock ignore=PYSEC-2018-28,CVE-2019-11324
check "ignore takes an ID or an alias" said "pip-audit: 5 packages audited, 1 vulnerability in 1 package."
check "listing what it ignored" said "Ignored: PYSEC-2018-28 in requests 2.19.1, PYSEC-2019-133 in urllib3 1.23."
check "in the report too" json_is pip-audit.json '[.ignored[].ignore_entry]' '["PYSEC-2018-28","CVE-2019-11324"]'
run audit lockfiles=uv.lock "ignore=PYSEC-2018-28 PYSEC-2023-74 PYSEC-2019-133"
check "ignoring all three passes" rc_is 0
run audit lockfiles=uv.lock "ignore=PYSEC-2018-28 PYSEC-2023-74 PYSEC-2019-133 GHSA-0000-0000-0000"
check "an unused ignore is a warning" said "WARN: ignore lists 1 ID that matched no vulnerability: GHSA-0000-0000-0000."
check "and doesn't fail the step" rc_is 0
run audit lockfiles=uv.lock "ignore=PYSEC-2018-28 PYSEC-2023-74 PYSEC-2019-133 GHSA-0000-0000-0000" unused_ignores=deny
check "unused_ignores deny fails the step" rc_is 1
check "saying why" said "ignore lists 1 ID that matched none (unused_ignores: deny)"
run audit lockfiles=uv.lock "ignore=PYSEC-2018-28 PYSEC-2023-74 PYSEC-2019-133 GHSA-0000-0000-0000" unused_ignores=allow
check "unused_ignores allow says nothing" not_said "matched no vulnerability"
run audit lockfiles=uv.lock "ignore=not an id"
check "an ignore entry that isn't an ID is refused" rc_is 1
check "saying what it takes" said "ignore takes vulnerability IDs"

echo "=== audit: no verdict"
run audit lockfiles=uv.lock report_only=true -- STUB_AUDIT_EXIT=1
check "pip-audit failing fails the step, report_only or not" rc_is 1
check "saying there is no verdict" said "pip-audit could not complete the audit (exit code 1), so there is no verdict."
run audit lockfiles=uv.lock -- STUB_EXIT=0
check "an exit code that disagrees with the report fails the step" rc_is 1
check "saying so" said "pip-audit exited with 0, but its report lists 3 vulnerabilities"
run audit lockfiles=uv.lock report_only=true -- STUB_SKIP=idna
check "a package pip-audit couldn't audit fails the step" rc_is 1
check "naming it" said "  idna : Dependency not found on PyPI and could not be audited"
check "and how to allow it" said "can be listed in allow_skipped"
run audit lockfiles=uv.lock report_only=true allow_skipped=IDNA -- STUB_SKIP=idna
check "unless allow_skipped lists it" rc_is 0
cat > "${JOB}/requirements-loose.txt" << 'EOF'
requests==2.19.1 --hash=sha256:63b52e3c866428a224f97cab011de738c36aec0185aa91cfacd418b5d58911d1
urllib3>=1.23
-e ./libs/private
-e git+https://github.com/example/shared.git@main#egg=shared
EOF
run audit requirements=requirements-loose.txt report_only=true
check "an unpinned requirement can't be audited" rc_is 1
check "saying why" said "  urllib3 : not pinned to one version (>=1.23)"
check "a local editable package can't either, but needs no entry" said "Not audited, as local packages: ./libs/private (requirements-loose.txt)"
check "an editable git package is a git source, not a local one" said "  shared : a git source (git+https://github.com/example/shared.git@main)"
run audit requirements=requirements-loose.txt report_only=true allow_skipped=urllib3,shared
check "allow_skipped lets the rest through" rc_is 0
cat > "${JOB}/pyproject.toml" << 'EOF'
[project]
name = "only-me"
version = "1.0"
EOF
mkdir -p "${JOB}/only"
cat > "${JOB}/only/uv.lock" << 'EOF'
version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "only-me"
version = "1.0"
source = { virtual = "." }
EOF
run audit lockfiles=only/uv.lock
check "a lock with nothing to audit fails the step" rc_is 1
check "saying it checked nothing" said "There were no packages to audit, so the audit checked nothing."
check "without running pip-audit, which refuses an empty lock" not_run pip-audit
run audit lockfiles=only/uv.lock allow_empty=true
check "unless allow_empty is true" rc_is 0
printf 'version = 2\n' > "${JOB}/only/uv.lock"
run audit lockfiles=only/uv.lock
check "a uv.lock version this orb doesn't read fails the step" rc_is 1
check "saying so" said "has lock version 2; this orb reads uv.lock version 1"
printf 'requests==2.19.1\n' > "${JOB}/deps.lock"
run audit lockfiles=deps.lock
check "a lockfile whose name says nothing of its kind is refused" rc_is 1
check "saying to name requirements files in requirements" said "name requirements files in requirements"

echo "=== audit: an installed environment"
VENV="${WORK}/venv"
python3 -m venv --without-pip "${VENV}"
SITE=$("${VENV}/bin/python" -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
for dist in requests:2.19.1 six:1.17.0; do
    mkdir -p "${SITE}/${dist%%:*}-${dist#*:}.dist-info"
    printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "${dist%%:*}" "${dist#*:}" > "${SITE}/${dist%%:*}-${dist#*:}.dist-info/METADATA"
done
fixture ""
run audit environment="${VENV}/bin/python" run_record=true
check "an environment's packages are audited" said "pip-audit: 2 packages audited, 2 vulnerabilities in 1 package."
check "listed by its own interpreter, needing no pip" grep -q 'name = "six"' "${STUB}/pylock.toml"
check "and named in the run record" json_is pip-audit.run-record.json '.target.packages' 2
check "with the interpreter as the input" json_is pip-audit.run-record.json '[.inputs[].role]' '["environment"]'
run audit environment="${WORK}/nope/python"
check "an environment that isn't an interpreter is refused" said "is not an executable file"

echo "=== audit: parameters"
fixture vulnerable
run audit lockfiles=uv.lock service=osv osv_url=https://osv.internal.example/v1/query
check "service osv with a self-hosted API" args_have pip-audit --vulnerability-service osv --timeout 15 --osv-url https://osv.internal.example/v1/query
run audit lockfiles=uv.lock osv_url=https://osv.internal.example/v1/query
check "osv_url needs service osv" said "osv_url names an OSV API, so it needs service: osv."
run audit lockfiles=uv.lock service=osv osv_url=http://osv.internal.example/v1/query
check "osv_url must be https" said "osv_url must be an https:// URL"
run audit lockfiles=uv.lock service=osv osv_url=https://user:s3cret@osv.internal.example/v1/query
check "without credentials" rc_is 1
check "which stay out of the log" script_lacks "s3cret"
run audit lockfiles=uv.lock timeout=45 "extra_args=--cache-dir /tmp/pip-audit-cache"
check "timeout and extra_args reach pip-audit" args_have pip-audit --timeout 45 --cache-dir /tmp/pip-audit-cache
for refused in --format=columns "-r requirements.txt" --fix --strict --dry-run "--ignore-vuln X" project; do
    run audit lockfiles=uv.lock "extra_args=${refused}"
    check "extra_args can't hold ${refused}" rc_is 1
    check "before pip-audit runs" not_run pip-audit
done
run audit lockfiles=uv.lock service=snyk
check "an unknown service is refused" said "service must be pypi or osv"
run audit lockfiles=uv.lock timeout=0
check "a timeout of 0 is refused" said "timeout must be a whole number of at least 1"
run audit lockfiles=uv.lock run_record=true report_name=deps
check "report_name names every report" report deps.json
check "the run record" report deps.run-record.json
check "names the inputs with their SHA-256" json_is deps.run-record.json '.inputs[0].sha256' "\"$(sha256sum "${JOB}/uv.lock" | cut -d' ' -f1)\""
check "and the counts" json_is deps.run-record.json '.counts | [.audited, .findings, .vulnerable_packages]' '[5,3,2]'

echo "=== audit: review fixes"
fixture vulnerable
for refused in -d --dry --ignore=PYSEC-2018-28 "--ignore PYSEC-2018-28" -vd -S --form=json --out=x; do
    run audit "extra_args=${refused}"
    check "extra_args can't hold ${refused}" said "ERROR: extra_args can't hold"
    check "before pip-audit runs" not_run pip-audit
done
run audit "extra_args=-vv --cache-d /tmp/pip-audit-cache" report_only=true
check "-v and an abbreviated --cache-dir with its value pass" args_have pip-audit -vv --cache-d /tmp/pip-audit-cache
run audit report_only=true -- STUB_DRY_RUN=1
check "a report that leaves out the packages given fails the step, report_only or not" rc_is 1
check "naming them" said "pip-audit's report leaves out packages it was given, so there is no verdict: certifi, chardet, idna, requests, urllib3."
run audit "ignore=PYSEC-2018-28 CVE-2018-18074 GHSA-j8r2-6x86-q33q PYSEC-2019-133" unused_ignores=deny
check "an ID and its alias for one vulnerability both count as used" rc_is 0
printf 'requests==v2.19.1\n' > "${JOB}/requirements-v.txt"
run audit requirements=requirements-v.txt report_only=true
check "a version spelled as PEP 440 allows keeps its finding's input" \
    json_is pip-audit.sarif '[.runs[0].results[].locations[0].physicalLocation.artifactLocation.uri] | unique' '["requirements-v.txt"]'
printf 'requests==2.19.01\n' > "${JOB}/requirements-zeros.txt"
run audit requirements=requirements-zeros.txt report_only=true
check "a version written with leading zeros keeps its finding's input" \
    json_is pip-audit.sarif '[.runs[0].results[].locations[0].physicalLocation.artifactLocation.uri] | unique' '["requirements-zeros.txt"]'
VENV_PROJECT="${WORK}/project-venv"
python3 -m venv --without-pip "${VENV_PROJECT}"
SITE=$("${VENV_PROJECT}/bin/python" -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
for dist in requests:2.19.1 fixture-vulnerable:0.1.0; do
    mkdir -p "${SITE}/${dist%%:*}-${dist#*:}.dist-info"
    printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "${dist%%:*}" "${dist#*:}" > "${SITE}/${dist%%:*}-${dist#*:}.dist-info/METADATA"
done
mv "${SITE}/fixture-vulnerable-0.1.0.dist-info" "${SITE}/fixture_vulnerable-0.1.0.dist-info"
printf '{"url": "file://%s", "dir_info": {"editable": true}}' "${JOB}" > "${SITE}/fixture_vulnerable-0.1.0.dist-info/direct_url.json"
run audit environment="${VENV_PROJECT}" report_only=true
check "the project's editable install in an environment is local, needing no entry" said "Not audited, as local packages: fixture-vulnerable"
check "and isn't sent to pip-audit" bash -c '! grep -q "fixture-vulnerable" "$1"' _ "${STUB}/pylock.toml"
check "an environment's findings aren't put in SARIF, which is for the checkout" json_is pip-audit.sarif '.runs[0].results' '[]'

echo "=== bandit"
fixture vulnerable
run bandit -- STUB_BANDIT_REPORT=findings.json
check "findings fail the step" rc_is 1
check "bandit scans the targets recursively, with its default exclusions" \
    args_have bandit -r --exclude ".svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg"
check "at every severity and confidence" args_have bandit --severity-level all --confidence-level all
check "with a JSON report, quietly" args_have bandit --format json --output
check "reading an empty .bandit file of its own" grep -qx '\[bandit\]' "${STUB}/bandit.ini"
check "the targets after --" args_have bandit -- .
check "logging the command, quoted only where needed" \
    said "Running: bandit -r --exclude '.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg' --severity-level all"
check "saying what Python parses the code" said "Bandit 1.9.4 parses code with Python 3.14.10."
check "listing the findings" said "  ./app.py:9: B602 subprocess_popen_with_shell_equals_true [HIGH/HIGH]"
check "and the count" said "Bandit scanned 1 file (15 lines): 2 findings."
check "failing with the summary" said "ERROR: Bandit found 2 problems."
check "Bandit's report is kept" report bandit.json
check "SARIF has a rule per test" json_is bandit.sarif '[.runs[0].tool.driver.rules[].id]' '["B324","B602"]'
check "with a security severity and the CWE" json_is bandit.sarif \
    '.runs[0].tool.driver.rules[] | select(.id == "B602") | .properties' '{"tags":["security","external/cwe/cwe-78"],"security-severity":"8.0"}'
check "and results at the file and line, without ./" json_is bandit.sarif \
    '.runs[0].results[0].locations[0].physicalLocation | [.artifactLocation.uri, .region.startLine, .region.startColumn]' '["app.py",9,12]'
check "JUnit has a failed case per finding" test "$(grep -o '<failure ' "${OUT}/junit/bandit.xml" | wc -l)" -eq 2
run bandit report_only=true -- STUB_BANDIT_REPORT=findings.json
check "report_only reports them" rc_is 0
check "with a warning" said "WARN: Bandit found 2 problems."
fixture clean
run bandit -- STUB_BANDIT_REPORT=clean.json
check "a clean scan passes" rc_is 0
check "saying what it scanned" said "Bandit scanned 1 file (15 lines): 0 findings."

echo "=== bandit: no verdict"
fixture vulnerable
cp "${FIXTURES}/bandit/new.py" "${JOB}/"
run bandit report_only=true -- STUB_BANDIT_REPORT=errors.json
check "a file Bandit couldn't parse fails the step, report_only or not" rc_is 1
check "naming it" said "  ./new.py: syntax error while parsing AST from file"
check "with the parser's message, which Bandit drops" said "    line 1: "
check "and what to do" said "Fix the syntax, install Bandit with a newer python"
run bandit report_only=true -- STUB_BANDIT_REPORT=findings.json STUB_BANDIT_EXIT=1
check "a crash, which exits 1 like findings, fails the step" rc_is 1
check "saying there is no verdict" said "Bandit could not complete the scan (exit code 1), so there is no verdict."
run bandit -- STUB_BANDIT_REPORT=clean.json STUB_BANDIT_EXIT=2
check "so does a usage error" said "Bandit could not complete the scan (exit code 2)"
run bandit report_only=true -- STUB_BANDIT_REPORT=findings.json \
    "STUB_BANDIT_LOG=[tester] ERROR Bandit internal error running: hashlib on file ./app.py at line 13: boom"
check "an internal error in a check fails the step" rc_is 1
check "saying that code wasn't fully checked" said "A Bandit check failed on some code"
run bandit -- STUB_BANDIT_REPORT=empty.json
check "a scan of no files fails the step" rc_is 1
check "saying it checked nothing" said "Bandit found no Python files to scan in ., so the scan checked nothing."
run bandit allow_empty=true -- STUB_BANDIT_REPORT=empty.json
check "unless allow_empty is true" rc_is 0

echo "=== bandit: suppressions"
fixture vulnerable
run bandit require_suppression_reasons=true -- STUB_BANDIT_REPORT=findings.json
check "require_suppression_reasons runs Bandit again with --ignore-nosec" args_have bandit-all --ignore-nosec
check "lists the suppressed findings" json_is bandit.suppressed.json '[.[].test_id]' '["B301","B108"]'
check "with each one's reason" json_is bandit.suppressed.json '[.[].reason]' '["","a fixed path in a test fixture"]'
check "and the comment" json_is bandit.suppressed.json '.[0].nosec_comment' '"# nosec B301"'
check "names the suppression without a reason" said "  ./app.py:17: B301 blacklist: # nosec B301"
check "which fails the step" said "ERROR: Bandit found 2 problems, and 1 suppression without a reason."
check "SARIF marks the suppressed findings" json_is bandit.sarif \
    '[.runs[0].results[] | select(.suppressions) | .suppressions[0].justification]' '["","a fixed path in a test fixture"]'
check "JUnit fails the one without a reason" \
    grep -q 'B301 suppressed without a reason, line 17' "${OUT}/junit/bandit.xml"
fixture clean
run bandit require_suppression_reasons=true -- STUB_BANDIT_REPORT=clean.json STUB_BANDIT_ALL=clean.json
check "nothing suppressed passes" rc_is 0

echo "=== bandit: parameters"
fixture vulnerable
mkdir -p "${JOB}/.venv/lib" "${JOB}/src" "${JOB}/tests"
run bandit "targets=src app.py" "exclude=./tests,legacy" severity_level=medium confidence_level=high \
    tests=B602,B324 skip=B101 "extra_args=--number 5" -- STUB_BANDIT_REPORT=findings.json
check "targets, filters, tests and skips reach Bandit" \
    args_have bandit --severity-level medium --confidence-level high --tests B602,B324 --skip B101 --number 5
check "with the targets" args_have bandit -- src app.py
check "the exclusions follow Bandit's own and an existing ./.venv" \
    args_have bandit -r --exclude ".svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,./.venv,./tests,legacy"
printf '[tool.bandit]\nskips = ["B101"]\n' > "${JOB}/pyproject.toml"
run bandit run_record=true -- STUB_BANDIT_REPORT=findings.json
check "pyproject.toml with [tool.bandit] is the config" args_have bandit --configfile pyproject.toml
check "saying so" said "Using the [tool.bandit] settings in pyproject.toml."
check "and the run record names it" json_is bandit.run-record.json '[.inputs[].role]' '["config"]'
check "with the counts" json_is bandit.run-record.json '.counts | [.files, .findings, .high]' '[1,2,2]'
printf '[bandit]\nformat = screen\n' > "${JOB}/.bandit"
run bandit -- STUB_BANDIT_REPORT=findings.json
check "a .bandit file is never read" said "WARN: ./.bandit is not read"
for value in tests=B60 tests=hashlib skip=b101; do
    run bandit "${value}"
    check "${value} is refused" said "tests and skip take Bandit test IDs"
    check "before Bandit runs" not_run bandit
done
for refused in -tB101 -bbase.json -x./src --base=base.json --exit "-qr ."; do
    run bandit "extra_args=${refused}"
    check "extra_args can't hold ${refused}" said "ERROR: extra_args can't hold"
    check "before Bandit runs" not_run bandit
done
run bandit "extra_args=-n5 -qa vuln --num 3" -- STUB_BANDIT_REPORT=findings.json
check "-n with its value attached, -a after -q, and an abbreviated --number pass" args_have bandit -n5 -qa vuln --num 3
jq '.results = [range(3000) as $i | .results[0] + {line_number: ($i + 1)}]' "${FIXTURES}/bandit/findings.json" > "${WORK}/many.json"
run bandit report_only=true run_record=true -- STUB_BANDIT_REPORT="${WORK}/many.json"
check "thousands of findings are listed in part, without a broken pipe ending the step" rc_is 0
check "saying how many more the reports hold" said "  ... and 2950 more, in the reports."
check "and the run record is written" report bandit.run-record.json
run bandit targets=missing
check "a target that doesn't exist is refused" said "targets names 'missing', which doesn't exist"
run bandit config=missing.yaml
check "a config that doesn't exist is refused" said "config names 'missing.yaml', which is not a file"
for refused in --format=txt "-o out.json" --exit-zero --ignore-nosec "-b base.json" "--ini x" other.py; do
    run bandit "extra_args=${refused}"
    check "extra_args can't hold ${refused}" rc_is 1
    check "before Bandit runs" not_run bandit
done

# dist SITE NAME VERSION [HEADER...]: writes a distribution's METADATA with
# the headers given, such as "License: MIT".
dist() {
    local dir="$1/$2-$3.dist-info"
    mkdir -p "${dir}"
    {
        printf 'Metadata-Version: 2.4\nName: %s\nVersion: %s\n' "$2" "$3"
        if [[ $# -gt 3 ]]; then
            printf '%s\n' "${@:4}"
        fi
    } > "${dir}/METADATA"
}
# licensed_venv DIR: a virtual environment holding the vulnerable fixture's
# dependencies and the project itself, with their real license metadata.
licensed_venv() {
    local site
    python3 -m venv --without-pip "$1"
    site=$("$1/bin/python" -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
    dist "${site}" requests 2.19.1 "License: Apache 2.0" "Classifier: License :: OSI Approved :: Apache Software License"
    dist "${site}" certifi 2018.4.16 "License: MPL-2.0" "Classifier: License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"
    dist "${site}" idna 2.7 "License: BSD-like" "Classifier: License :: OSI Approved :: BSD License"
    dist "${site}" urllib3 1.23 "License: MIT" "Classifier: License :: OSI Approved :: MIT License"
    dist "${site}" packaging 25.0 "License-Expression: Apache-2.0 OR BSD-2-Clause"
    dist "${site}" fixture-vulnerable 0.1.0
}

echo "=== licenses"
fixture vulnerable
licensed_venv "${JOB}/.venv"
run licenses -- PYTHONPATH=/nowhere
check "packages that aren't allowed fail the step" rc_is 1
check "pip-licenses lists the .venv in working_dir" args_have pip-licenses "--python=${JOB}/.venv/bin/python"
check "every field, the installers and the URLs, as JSON" \
    args_have pip-licenses --format=json --from=all --with-system --with-urls
check "from an empty directory" grep -qx 'files in the working directory: 0' "${STUB}/pip-licenses.env"
check "without PYTHONPATH" grep -qx 'PYTHONPATH: unset' "${STUB}/pip-licenses.env"
check "a License field that names a license is taken" said "  urllib3 1.23: MIT  [License]"
check "a License field in other words maps to SPDX" said "  requests 2.19.1: Apache-2.0  [License (Apache 2.0)]"
check "License-Expression comes first" said "  packaging 25.0: Apache-2.0 OR BSD-2-Clause  [License-Expression]"
check "a license that isn't allowed is named" said "  certifi 2018.4.16: MPL-2.0  [License]  NOT ALLOWED"
check "so is one the metadata doesn't name exactly" said "  idna 2.7: BSD-like  [License]  NOT ALLOWED"
check "the project isn't checked by default" said "  fixture-vulnerable 0.1.0: UNKNOWN  [none]  the project, not checked"
check "failing with the packages" said "ERROR: 2 packages have a license that isn't allowed: certifi (MPL-2.0), idna (BSD-like)."
check "the inventory names the findings" json_is licenses.json '[.findings[].name]' '["certifi","idna"]'
check "and the policy" json_is licenses.json '.allowed_licenses' '["Apache-2.0","BSD-2-Clause","BSD-3-Clause","ISC","MIT","PSF-2.0"]'
check "pip-licenses' own inventory is kept" json_is licenses.pip-licenses.json 'length' 6
check "the CSV has a row per package" test "$(wc -l < "${OUT}/licenses.csv")" -eq 7
check "with a header" grep -qx '"name","version","license","origin","allowed","ignored"' "${OUT}/licenses.csv"
check "JUnit fails the packages that aren't allowed" test "$(grep -o '<failure ' "${OUT}/junit/licenses.xml" | wc -l)" -eq 2
run licenses report_only=true
check "report_only reports them" rc_is 0
check "with a warning" said "WARN: 2 packages have a license that isn't allowed"
run licenses "allowed_licenses=MIT Apache-2.0 BSD-2-Clause BSD-3-Clause MPL-2.0" "clarify=# idna's own LICENSE.rst
idna==2.7=BSD-3-Clause"
check "allowed_licenses and clarify settle them" rc_is 0
check "clarify comes first" said "  idna 2.7: BSD-3-Clause  [clarify:idna==2.7]"
check "passing" said "Passed: every package checked has an allowed license."
run licenses "ignore=certifi idna==2.7"
check "ignore leaves packages unchecked" rc_is 0
check "listing them" said "  certifi 2018.4.16: MPL-2.0  [License]  ignored"
check "JUnit skips them" grep -q 'Ignored (idna==2.7): BSD-like' "${OUT}/junit/licenses.xml"
run licenses ignore=certifi,idna==2.6
check "ignore matches the version given" said "idna (BSD-like)"
check "warning about an entry that matched nothing" said "WARN: ignore lists packages that aren't installed: idna==2.6."
run licenses "ignore=certifi idna" check_project=true
check "check_project checks the project too" said "ERROR: 1 package has a license that isn't allowed: fixture-vulnerable (UNKNOWN)."
check "suggesting clarify for a license the metadata doesn't name" said "can be given in clarify"
run licenses environment=.venv/bin/python
check "environment takes the interpreter" args_have pip-licenses "--python=${JOB}/.venv/bin/python"

echo "=== licenses: no verdict"
fixture vulnerable
licensed_venv "${JOB}/.venv"
run licenses report_only=true -- STUB_LICENSES_EXIT=1
check "pip-licenses failing fails the step, report_only or not" rc_is 1
check "saying there is no verdict" said "pip-licenses could not list the licenses (exit code 1), so there is no verdict."
run licenses report_only=true -- STUB_LICENSES_DROP=urllib3
check "an inventory that leaves out a package fails the step" rc_is 1
check "naming it" said "pip-licenses left out packages ${JOB}/.venv/bin/python sees, so their licenses weren't checked: urllib3 1.23."
python3 -m venv --without-pip "${WORK}/empty-venv"
run licenses environment="${WORK}/empty-venv" run_record=true
check "an environment with nothing to check fails the step" said "has no packages to check, so the check checked nothing."
check "with an error run record" json_is licenses.run-record.json '.outcome' '"error"'
run licenses environment="${WORK}/empty-venv" allow_empty=true
check "unless allow_empty is true" rc_is 0
fixture vulnerable
run licenses
check "no .venv and no environment is refused" said "There is no .venv in ${JOB}."
check "before pip-licenses runs" not_run pip-licenses

echo "=== licenses: parameters"
fixture vulnerable
licensed_venv "${WORK}/licensed"
run licenses environment="${WORK}/licensed" run_record=true "allowed_licenses=\${ORB_TEST_VAR}" -- ORB_TEST_VAR=MIT
check "environment takes the environment's directory" args_have pip-licenses "--python=${WORK}/licensed/bin/python"
check "allowed_licenses expands variables" json_is licenses.json '.allowed_licenses' '["MIT"]'
check "the run record names the environment" json_is licenses.run-record.json '[.inputs[].role]' '["environment"]'
check "and counts the packages" json_is licenses.run-record.json '.counts | [.packages, .checked, .findings]' '[6,5,4]'
for value in "allowed_licenses=MIT,(GPL)" "allowed_licenses=" "ignore=requests>=2"; do
    run licenses environment="${WORK}/licensed" "${value}"
    check "${value} is refused" rc_is 1
    check "before pip-licenses runs" not_run pip-licenses
done
run licenses environment="${WORK}/licensed" "clarify=idna BSD"
check "a clarify line that isn't name=EXPRESSION is refused" said "clarify entries are name[==version]=EXPRESSION"
check "before pip-licenses runs" not_run pip-licenses
run licenses environment="${WORK}/licensed" "clarify=idna=BSD 3 Clause"
check "and so is one that isn't an SPDX expression" said "clarify entries are name[==version]=EXPRESSION"
run licenses environment="${WORK}/nope"
check "an environment that doesn't exist is refused" said "'${WORK}/nope' is not an executable file."

echo "=== lock_verify"
fixture vulnerable
# pipenv checks Pipfile.lock against the Pipfile next to it.
printf '[packages]\nrequests = "==2.19.1"\n' > "${JOB}/Pipfile"
run lock_verify -- UV_FROZEN=1 UV_LOCKED=1 UV_PROJECT=/elsewhere UV_WORKING_DIR=/elsewhere \
    UV_WORKING_DIRECTORY=/elsewhere PDM_PROJECT=/elsewhere PIPENV_PIPFILE=/elsewhere/Pipfile
check "pinned, hashed, up-to-date lockfiles pass" rc_is 0
check "checking every lockfile in working_dir" said "Checking the lockfiles in ${JOB}: uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml"
check "each with its kind and version" said "uv.lock (uv.lock 1): 6 packages, 0 findings, up to date (uv 9.9.9)"
check "a pylock.toml has no package manager to ask" said "pylock.toml (pylock 1.0): 5 packages, 0 findings"
check "uv checks uv.lock" args_have uv lock --check
check "without the job's UV_FROZEN, UV_LOCKED, UV_PROJECT or UV_WORKING_DIR" bash -c '! grep -q "^UV_" "$1"' _ "${STUB}/uv.env"
check "in the lockfile's directory" grep -qx "${JOB}" "${STUB}/uv.env"
check "poetry checks poetry.lock" args_have poetry check --lock --no-interaction
check "pdm checks pdm.lock, verbosely to say so" args_have pdm lock --check -v
check "without the job's PDM_PROJECT" bash -c '! grep -q "^PDM_PROJECT" "$1"' _ "${STUB}/pdm.env"
check "pipenv checks Pipfile.lock" args_have pipenv verify
check "next to its own Pipfile" bash -c '! grep -q "^PIPENV_PIPFILE" "$1"' _ "${STUB}/pipenv.env"
check "passing" said "Passed: every package is pinned and hashed, and the lockfiles checked are up to date."
check "the report lists every input" json_is lock-verify.json '[.inputs[] | [.kind, .freshness.status]]' \
    '[["uv.lock","fresh"],["poetry.lock","fresh"],["pdm.lock","fresh"],["Pipfile.lock","fresh"],["pylock","none"]]'
for manager in uv:uv.lock poetry:poetry.lock pdm:pdm.lock pipenv:Pipfile.lock; do
    run lock_verify -- STUB_FRESH=stale STUB_FRESH_FOR="${manager%%:*}"
    check "a stale ${manager#*:} fails the step" rc_is 1
    check "named as out of date" said "${manager#*:} ("
    check "with ${manager%%:*}'s message" said "  ${manager#*:}:1: stale: ${manager#*:} is out of date with its pyproject.toml: "
    check "in the summary" said "ERROR: lock_verify found 1 problem: 1 stale."
done
run lock_verify -- STUB_FRESH=stale STUB_FRESH_FOR=uv
check "uv's message, without its prefix" \
    said 'stale: uv.lock is out of date with its pyproject.toml: The lockfile at `uv.lock` needs to be updated'
run lock_verify report_only=true -- STUB_FRESH=error STUB_FRESH_FOR=pdm
check "a manager that can't complete its check fails the step, report_only or not" rc_is 1
check "saying there is no verdict" said "Whether 1 lockfile is up to date is unknown, so there is no verdict:"
check "naming it" said "pdm.lock: pdm could not check it (exit code 2); its output is above."
check "with its output" said 'No `pyproject.toml` found'
rm "${JOB}/pyproject.toml" "${JOB}/Pipfile"
run lock_verify lockfiles=uv.lock
check "a lockfile without its pyproject.toml can't be checked" said "freshness not checked: there is no pyproject.toml next to it"
check "so uv doesn't run" not_run uv
run lock_verify lockfiles=Pipfile.lock
check "a Pipfile.lock without its Pipfile can't either" said "Pipfile.lock (Pipfile.lock 6): 5 packages, 0 findings, freshness not checked: there is no Pipfile next to it"
run lock_verify freshness=require
check "which fails the step with freshness: require" said "uv.lock: there is no pyproject.toml next to it, and freshness is require."
fixture vulnerable
run lock_verify freshness=skip
check "freshness: skip runs no package manager" not_run uv
check "and says so" said "uv.lock (uv.lock 1): 6 packages, 0 findings, freshness not checked (freshness: skip)"
run lock_verify -- PATH="${WORK}/bin:${CLEAN_PATH}"
check "a manager that isn't on the PATH is skipped" rc_is 0
check "with a note" said "freshness not checked: uv is not on the PATH"
run lock_verify freshness=require -- PATH="${WORK}/bin:${CLEAN_PATH}"
check "unless freshness is require" rc_is 1
check "which names each" said "uv.lock: uv is not on the PATH, and freshness is require."

echo "=== lock_verify: findings"
fixture loose
run lock_verify requirements=requirements.txt
check "a loose requirements file fails the step" rc_is 1
check "a requirement without a pin" said "  requirements.txt:5: unpinned: requests is not pinned to one version (>=2.19)"
check "a pin without a hash" said "  requirements.txt:6: unhashed: six 1.17.0 has no hash"
check "a weak hash" said "  requirements.txt:7: weak-hash: attrs 25.3.0 lists md5 hashes, so a file that matches one would be installed"
check "git without a commit" said "  requirements.txt:8: unpinned-vcs: private-lib comes from git+https://github.com/example/private-lib@main"
check "a path outside the checkout" \
    said "  requirements.txt:9: local-source: the path ../shared/vendored-lib is outside the lockfile's directory"
check "a plain http index, at its line" said "  requirements.txt:3: insecure-index: the index http://pypi.internal.example/simple is plain http"
check "--trusted-host" said "  requirements.txt:4: trusted-host: --trusted-host pypi.internal.example turns off TLS verification"
check "summed up by kind" said \
    "ERROR: lock_verify found 7 problems: 1 insecure-index, 1 local-source, 1 trusted-host, 1 unhashed, 1 unpinned, 1 unpinned-vcs, 1 weak-hash."
check "SARIF has a rule per kind" json_is lock-verify.sarif '.runs[0].tool.driver.rules | length' 7
check "and each result at its line" json_is lock-verify.sarif \
    '[.runs[0].results[] | .locations[0].physicalLocation | "\(.artifactLocation.uri):\(.region.startLine)"] | sort' \
    '["requirements.txt:3","requirements.txt:4","requirements.txt:5","requirements.txt:6","requirements.txt:7","requirements.txt:8","requirements.txt:9"]'
check "JUnit fails the file" grep -q '<failure message="7 findings in 5 packages"' "${OUT}/junit/lock-verify.xml"
run lock_verify requirements=requirements.txt report_only=true
check "report_only reports them" rc_is 0
run lock_verify requirements=requirements.txt require_hashes=false
check "require_hashes: false leaves hashes alone" said "lock_verify found 5 problems"
check "and nothing else" not_said "weak-hash"
fixture vulnerable
run lock_verify lockfiles=uv.lock freshness=skip min_release_age_days=100000
check "min_release_age_days reports releases newer than that" said "ERROR: lock_verify found 5 problems: 5 too-new."
check "with their upload time" said "too-new: requests 2.19.1 was uploaded 2018-06-14T13:40:41.014Z"
check "at their entry in uv.lock" said "  uv.lock:$(grep -n '^name = "requests"$' "${JOB}/uv.lock" | cut -d: -f1): too-new: requests"
run lock_verify lockfiles=uv.lock freshness=skip allowed_indexes=https://pypi.example.com/simple
check "an index outside allowed_indexes is a finding" said "index-not-allowed: the index https://pypi.org/simple is not in allowed_indexes"
run lock_verify lockfiles=uv.lock freshness=skip allowed_indexes=https://pypi.org/simple/
check "matched whatever its trailing slash" rc_is 0
mkdir -p "${JOB}/workspace"
cat > "${JOB}/workspace/uv.lock" << 'EOF'
version = 1
requires-python = ">=3.10"

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "member"
version = "0.1.0"
source = { editable = "packages/member" }

[[package]]
name = "shared"
version = "0.1.0"
source = { directory = "../shared" }
EOF
run lock_verify lockfiles=workspace/uv.lock freshness=skip
check "the project and its members are local by design" said "1 problem: 1 local-source."
check "a directory outside isn't" said "local-source: shared 0.1.0 comes from ../shared, outside the lockfile's directory"
run lock_verify lockfiles=workspace/uv.lock freshness=skip allow_local=shared
check "unless allow_local names it" rc_is 0

echo "=== lock_verify: review fixes"
fixture ""
printf '# a comment that ends in a backslash \\\nevil-package\n--extra-index-url http://127.attacker.example/simple\n--extra-index-url http://127.0.0.1:8080/simple\n--index-url https://user:hunter2@corp.example.com/simple\ngit+https://github.com/psf/requests.git@main#egg=requests\nhttps://example.com/pkg-1.0.whl\n' > "${JOB}/requirements.txt"
run lock_verify requirements=requirements.txt report_only=true
check "a comment line ending in a backslash doesn't swallow the next requirement" said "requirements.txt:2: unpinned: evil-package"
check "a host that starts with 127. isn't loopback" said "insecure-index: the index http://127.attacker.example/simple is plain http"
check "127.0.0.1 is" not_said "the index http://127.0.0.1:8080/simple is plain http"
check "an index's credentials are never shown" not_said "hunter2"
check "and kept out of the reports" bash -c '! grep -rq hunter2 "$1"' _ "${OUT}"
check "a VCS URL without a name is named by its #egg=" said "unpinned-vcs: requests comes from git+https://github.com/psf/requests.git@main without"
check "an archive URL without a name is checked too" said "unhashed: https://example.com/pkg-1.0.whl has no hash"
cat > "${JOB}/Pipfile.lock" << 'EOF'
{"_meta": {"pipfile-spec": 6, "hash": {"sha256": "x"},
  "sources": [{"name": "corp", "url": "https://corp.example.com/simple", "verify_ssl": false}]},
 "default": {"requests": {"file": "https://github.com/psf/requests/archive/refs/heads/main.zip", "version": "==2.32.3"}},
 "develop": {}}
EOF
cat > "${JOB}/pylock.toml" << 'EOF'
lock-version = "1.0"
created-by = "test"

[[packages]]
name = "six"
version = "1.17.0"
index = "https://pypi.org/simple"
wheels = [
  { name = "six-1.17.0-py2.py3-none-any.whl", hashes = { sha256 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274" } },
  { name = "six-1.17.0-py3-none-any.whl", hashes = { md5 = "0123456789abcdef0123456789abcdef" } },
]
EOF
run lock_verify lockfiles=pylock.toml freshness=skip
check "a file hashed only with MD5 beside one with SHA-256 is a weak hash" said "weak-hash: six 1.17.0 lists md5 hashes"
printf 'six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\n-rdeps.txt\n' > "${JOB}/requirements-top.txt"
printf 'requests>=2\n' > "${JOB}/deps.txt"
run lock_verify requirements=requirements-top.txt
check "an include with its file attached to -r is followed" said "deps.txt:1: unpinned: requests is not pinned to one version (>=2)"
run lock_verify lockfiles=Pipfile.lock freshness=skip report_only=true
check "a Pipfile source without TLS verification is a finding" said "trusted-host: the source https://corp.example.com/simple has verify_ssl = false"
check "a Pipfile file URL isn't a local path" said "unhashed: requests 2.32.3 has no hash"
mkdir -p "${JOB}/flat"
cat > "${JOB}/flat/uv.lock" << 'EOF'
version = 1
requires-python = ">=3.10"

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "../wheels" }
wheels = [{ path = "requests-2.19.1-py2.py3-none-any.whl", hash = "sha256:63b52e3c866428a224f97cab011de738c36aec0185aa91cfacd418b5d58911d1" }]
EOF
run lock_verify lockfiles=flat/uv.lock freshness=skip
check "a hashed package from a uv flat index passes" rc_is 0
run audit lockfiles=flat/uv.lock report_only=true
check "and is audited by name and version" said "requests 2.19.1: PYSEC-2018-28"
cat > "${JOB}/poetry.lock" << 'EOF'
[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
category = "main"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"

[metadata]
lock-version = "1.1"
python-versions = "^3.10"
content-hash = "0000000000000000000000000000000000000000000000000000000000000000"

[metadata.files]
six = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]
EOF
run lock_verify lockfiles=poetry.lock freshness=skip min_release_age_days=7
check "poetry.lock 1.1's hashes in [metadata.files] count" rc_is 0
check "min_release_age_days warns about a lockfile that records no upload times" \
    said "WARN: poetry.lock records no upload time for 1 of its packages (six 1.16.0), so min_release_age_days can't check them"
fixture vulnerable
run lock_verify lockfiles=pdm.lock freshness=skip allowed_indexes=https://pypi.org/simple
check "allowed_indexes warns that pdm.lock records no indexes" said "WARN: pdm.lock doesn't record the indexes its packages came from"
printf '[packages]\nrequests = "==2.19.1"\n' > "${JOB}/Pipfile"
run lock_verify -- STUB_FRESH=stale1 STUB_FRESH_FOR=poetry
check "Poetry 1.x's message for a stale lockfile is a finding too" said "stale: poetry.lock is out of date with its pyproject.toml: poetry.lock is not consistent with pyproject.toml"
fixture ""
PTH_VENV="${WORK}/pth-venv"
python3 -m venv --without-pip "${PTH_VENV}"
SITE=$("${PTH_VENV}/bin/python" -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
printf 'import os; open(%s, "w")\n' "'${WORK}/pth-ran'" > "${SITE}/evil.pth"
printf 'import _virtualenv\n' > "${SITE}/_virtualenv.pth"
run lock_verify environment="${PTH_VENV}"
check "a .pth file no RECORD lists is a finding" said "record-unlisted: ${SITE}/evil.pth is in no package's RECORD"
check "but not the one virtual environments come with" not_said "_virtualenv.pth is in no"
check "and the check runs nothing in the environment" test ! -e "${WORK}/pth-ran"

echo "=== lock_verify: requirements options, credentials and links"
fixture ""
printf 'requests>=2\n' > "${JOB}/deps.txt"
printf 'six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\n--no-index -rdeps.txt --extra-index=https://mirror.example.com/simple\n' > "${JOB}/requirements-top.txt"
run lock_verify requirements=requirements-top.txt allowed_indexes=https://pypi.org/simple
check "every option on an option line counts, an include after another option too" said "deps.txt:1: unpinned: requests is not pinned to one version (>=2)"
check "and an abbreviated long option" said "index-not-allowed: the index https://mirror.example.com/simple is not in allowed_indexes"
HEX=4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274
printf 'demo @ https://example.com/demo-1.0.tar.gz#sha256=%s\nhttps://example.com/pkg-1.0.whl#egg=pkg&sha256=%s\nold @ https://example.com/old-1.0.tar.gz#md5=0123456789abcdef0123456789abcdef\n' "${HEX}" "${HEX}" > "${JOB}/requirements-url-hash.txt"
run lock_verify requirements=requirements-url-hash.txt report_only=true
check "a direct URL's #sha256= fragment is its hash, as pip reads it" not_said "unhashed"
check "and a weak one there is a weak hash" said "weak-hash: old lists md5 hashes"
printf 'six (==1.17.0) --hash=sha256:%s\nsix[extra] ( >=1 ) --hash=sha256:%s\n' "${HEX}" "${HEX}" > "${JOB}/requirements-parens.txt"
run lock_verify requirements=requirements-parens.txt report_only=true
check "a pin in parentheses is a pin, as PEP 508 allows" not_said "==1.17.0)"
check "and a range in them is still unpinned" said "unpinned: six is not pinned to one version (>=1)"
# A constraints file's options apply, as pip applies them; its packages
# aren't installed.
printf 'six==1.17.0 --hash=sha256:%s\n-c constraints.txt\n' "${HEX}" > "${JOB}/requirements-c.txt"
printf -- '--index-url http://packages.example/simple\n--trusted-host packages.example\nrequests==2.19.1\n-r more-constraints.txt\n' > "${JOB}/constraints.txt"
printf 'idna>=2\n--extra-index-url http://more.example/simple\n' > "${JOB}/more-constraints.txt"
run lock_verify requirements=requirements-c.txt report_only=true
check "a constraints file's index is checked" said "insecure-index: the index http://packages.example/simple is plain http"
check "and its --trusted-host" said "trusted-host: --trusted-host packages.example turns off TLS verification"
check "and those of the files it includes" said "insecure-index: the index http://more.example/simple is plain http"
check "but its packages aren't taken for installed ones" not_said "requests"
check "nor those of the files it includes" not_said "idna"
# A byte order mark is the file's encoding, not part of its first line.
printf '\xef\xbb\xbfrequests>=2\nsix==1.17.0 --hash=sha256:%s\n' "${HEX}" > "${JOB}/requirements-bom.txt"
run lock_verify requirements=requirements-bom.txt report_only=true
check "a first requirement after a UTF-8 byte order mark is read" said "requirements-bom.txt:1: unpinned: requests is not pinned to one version (>=2)"
python3 -c 'import sys; open(sys.argv[1], "wb").write("requests>=2\n".encode("utf-16"))' "${JOB}/requirements-bom.txt"
run lock_verify requirements=requirements-bom.txt report_only=true
check "and so is a UTF-16 file" said "requirements-bom.txt:1: unpinned: requests is not pinned to one version (>=2)"
cat > "${JOB}/Pipfile.lock" << EOF
{"_meta": {"hash": {"sha256": "0"}, "pipfile-spec": 6, "requires": {},
           "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]},
 "default": {"six": {"hashes": ["sha256:${HEX}"], "index": "pypi", "version": "==1.17.0"}},
 "develop": {},
 "production": {"requests": {"index": "pypi", "version": "==2.19.1"}}}
EOF
run lock_verify lockfiles=Pipfile.lock freshness=skip report_only=true
check "a custom Pipfile category's packages are checked" said "unhashed: requests 2.19.1 has no hash"
run audit lockfiles=Pipfile.lock report_only=true
check "and audited" said "requests 2.19.1: PYSEC-2018-28"
# ${NAME} in a requirements file is the variable's value, as pip expands it.
printf 'six==1.17.0 --hash=sha256:%s\n${DEPENDENCY}\n-r ${MORE_DIR}/deps.txt\n--extra-index-url https://${IDX_USER}:${IDX_TOKEN}@corp.example.com/simple\n' "${HEX}" > "${JOB}/requirements-env.txt"
mkdir -p "${JOB}/more"
printf 'idna>=2\n' > "${JOB}/more/deps.txt"
run lock_verify requirements=requirements-env.txt report_only=true -- DEPENDENCY='requests>=2' MORE_DIR=more IDX_USER=me IDX_TOKEN=env-secret
check "a requirement in an environment variable is read as pip expands it" said "requirements-env.txt:2: unpinned: requests is not pinned to one version (>=2)"
check "and so is an include's path" said "deps.txt:1: unpinned: idna is not pinned to one version (>=2)"
check "and a token in an index URL stays out of the output" script_lacks "env-secret"
check "and out of the reports" bash -c '! grep -rq env-secret "$1"' _ "${OUT}"
run lock_verify requirements=requirements-env.txt -- MORE_DIR=more
check "a requirement in a variable that isn't set is refused, not taken for a path" rc_is 1
check "naming the variable, and the line as written" \
    said "requirements-env.txt:2: the environment variable DEPENDENCY is not set (or empty), so '\${DEPENDENCY}' can't be read as pip would read it"
printf 'six==1.17.0 --hash=sha256:%s\n--extra-index-url https://${IDX_USER}:${IDX_TOKEN}@corp.example.com/simple\n' "${HEX}" > "${JOB}/requirements-env.txt"
run lock_verify requirements=requirements-env.txt
check "an index URL's unset credentials don't stop the check" rc_is 0
printf -- '--no-such-option\n' > "${JOB}/requirements-top.txt"
run lock_verify requirements=requirements-top.txt
check "an option pip doesn't know is refused, as pip refuses it" said "requirements-top.txt:1: no such option --no-such-option"
printf -- '--no-index -r\n' > "${JOB}/requirements-top.txt"
run lock_verify requirements=requirements-top.txt
check "and so is an option without its value" said "requirements-top.txt:1: -r needs a value"
printf 'demo @ git+https://user:review-secret@example.com/demo.git@main\n-e git+https://token-secret@example.com/tool.git@main#egg=tool\n--index-url https://user:index-secret@corp.example.com/simple?key=query-secret\nhttps://url-secret@example.com/pkg-1.0.whl\n' > "${JOB}/requirements-creds.txt"
run lock_verify requirements=requirements-creds.txt report_only=true run_record=true
check "a VCS URL's credentials are left out of the findings" said "unpinned-vcs: demo comes from git+https://example.com/demo.git@main without a full commit hash"
check "and out of the output" script_lacks "secret"
check "and out of every report" bash -c '! grep -rq secret "$1"' _ "${OUT}"
fixture vulnerable
printf 'requests==2.19.1\n-e git+https://token-secret@example.com/tool.git@main#egg=tool\n' > "${JOB}/requirements-creds.txt"
run audit requirements=requirements-creds.txt report_only=true run_record=true
check "audit's skip reasons leave the credentials out" said "a git source (git+https://example.com/tool.git@main)"
check "and so do its output and reports" bash -c '! grep -q secret <<< "$1" && ! grep -rq secret "$2"' _ "${OUTPUT}" "${OUT}"
fixture ""
mkdir -p "${WORK}/external" "${JOB}/inside"
ln -s ../external "${JOB}/dep"
ln -s inside "${JOB}/alias"
printf -- '-e ./dep\n-e ./alias\n' > "${JOB}/requirements.txt"
run lock_verify requirements=requirements.txt
check "a local path through a link out of the lockfile's directory is a local source" said "local-source: the path ./dep is outside the lockfile's directory"
check "and one through a link that stays inside isn't" not_said "the path ./alias"

echo "=== lock_verify: system site-packages"
# site-dirs: the base interpreter's site-packages (and the user's) count when
# a virtual environment includes them, after its own.
HELPER="${ROOT}/src/scripts/lib/python_security.py"
BASE_SITES=$(python3 -I -c 'import json, os, site; print(json.dumps([d for d in site.getsitepackages() + [site.getusersitepackages()] if os.path.isdir(d)]))')
SYSTEM_VENV="${WORK}/system-venv"
python3 -m venv --without-pip --system-site-packages "${SYSTEM_VENV}"
"${SYSTEM_VENV}/bin/python" -I -S "${HELPER}" site-dirs > "${WORK}/system-site.json"
check "a virtual environment with include-system-site-packages says so" jq -e '.system_site_packages' "${WORK}/system-site.json"
check "and has the base interpreter's site-packages, after its own" jq -e --arg venv "${SYSTEM_VENV}" --argjson base "${BASE_SITES}" \
    '(.site[0] | startswith($venv)) and ($base - .site) == []' "${WORK}/system-site.json"
PLAIN_VENV="${WORK}/plain-venv"
python3 -m venv --without-pip "${PLAIN_VENV}"
"${PLAIN_VENV}/bin/python" -I -S "${HELPER}" site-dirs > "${WORK}/plain-site.json"
check "one without them has only its own" jq -e --arg venv "${PLAIN_VENV}" \
    '(.system_site_packages | not) and (.site | length) > 0 and all(.site[]; startswith($venv))' "${WORK}/plain-site.json"

echo "=== lock_verify: installed files"
VENV="${WORK}/record-venv"
python3 -m venv --without-pip "${VENV}"
SITE=$("${VENV}/bin/python" -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
mkdir -p "${SITE}/tidy" "${SITE}/tidy-1.0.dist-info"
printf 'VALUE = 1\n' > "${SITE}/tidy/__init__.py"
printf 'Metadata-Version: 2.4\nName: tidy\nVersion: 1.0\n' > "${SITE}/tidy-1.0.dist-info/METADATA"
python3 -I - "${SITE}" << 'EOF'
import base64, hashlib, os, sys
site = sys.argv[1]
lines = []
for path in ("tidy/__init__.py", "tidy-1.0.dist-info/METADATA"):
    data = open(os.path.join(site, path), "rb").read()
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    lines.append("%s,sha256=%s,%d" % (path, digest, len(data)))
lines += ["tidy/__pycache__/__init__.cpython-314.pyc,,", "tidy-1.0.dist-info/RECORD,,"]
open(os.path.join(site, "tidy-1.0.dist-info/RECORD"), "w").write("\n".join(lines) + "\n")
EOF
fixture ""
run lock_verify environment="${VENV}" run_record=true
check "installed files that match their RECORD pass" rc_is 0
check "saying what was checked" said "${VENV}/bin/python: 2 installed files of 1 package checked against their RECORD, 0 not matching"
check "the run record names the environment" json_is lock-verify.run-record.json '[.inputs[].role]' '["environment"]'
check "with no tool of its own" json_is lock-verify.run-record.json '.tool' 'null'
# A second copy of the package, in another site-packages, with a changed file.
SECOND_SITE="${WORK}/second-site"
mkdir -p "${SECOND_SITE}"
cp -R "${SITE}/tidy" "${SITE}/tidy-1.0.dist-info" "${SECOND_SITE}/"
printf 'VALUE = 3\n' > "${SECOND_SITE}/tidy/__init__.py"
python3 -I "${ROOT}/src/scripts/lib/python_security.py" installed --record --path "${SITE}" --path "${SECOND_SITE}" > "${WORK}/two-sites.json"
check "every copy of a package is checked against its RECORD" jq -e --arg dir "${SECOND_SITE}" \
    '.findings == [{package: "tidy", version: "1.0", file: "tidy/__init__.py", kind: "modified",
      message: "tidy 1.0: tidy/__init__.py doesn\u0027t match its RECORD hash (another copy, in \($dir))"}]' "${WORK}/two-sites.json"
check "and the inventory lists it once, with both copies' files" jq -e \
    '[.packages[] | select(.name == "tidy") | .files] == [4]' "${WORK}/two-sites.json"
rm -rf "${SECOND_SITE}"
printf 'VALUE = 2\n' > "${SITE}/tidy/__init__.py"
run lock_verify environment="${VENV}"
check "a changed file fails the step" rc_is 1
check "naming it" said "record-modified: tidy 1.0: tidy/__init__.py doesn't match its RECORD hash"
rm "${SITE}/tidy/__init__.py"
run lock_verify environment="${VENV}"
check "so does a missing one" said "record-missing: tidy 1.0: tidy/__init__.py is missing"

echo "=== lock_verify: no verdict and parameters"
fixture vulnerable
run lock_verify lockfiles=pyproject.toml report_only=true
check "a file that isn't a lockfile fails the step, report_only or not" rc_is 1
check "saying so" said "Could not read pyproject.toml."
printf '# nothing\n' > "${JOB}/empty.txt"
run lock_verify requirements=empty.txt
check "a check of no packages fails the step" said "There were no packages to check, so the check checked nothing."
run lock_verify requirements=empty.txt allow_empty=true
check "unless allow_empty is true" rc_is 0
run lock_verify lockfiles=uv.lock freshness=skip run_record=true
check "the run record lists each lockfile's result" json_is lock-verify.run-record.json \
    '.results | map([.kind, .packages, .findings, .freshness.status])' '[["uv.lock",6,0,"skipped"]]'
for value in freshness=sometimes min_release_age_days=-1 allowed_indexes=ftp://example.com/simple \
    allowed_indexes=https://user:secret@example.com/simple "allow_local=a/b"; do
    run lock_verify "${value}"
    check "${value} is refused" rc_is 1
    check "before anything runs" not_run uv
done
check "an index's credentials aren't shown" script_lacks secret
fixture ""
run lock_verify
check "nothing to check and no lockfile is refused" said "There is no lockfile in ${JOB}"

echo "=== run records"
if [[ "${RECORDS}" -eq 0 ]]; then
    echo "FAIL: no run record was written"
    FAILURES=$((FAILURES + 1))
elif python3 -c 'import jsonschema' 2> /dev/null; then
    if python3 - "${ROOT}/schemas/run-record.v1.json" "${WORK}"/records/*.json << 'PY'; then
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
bad = 0
for path in sys.argv[2:]:
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(json.load(open(path))))
    for error in errors:
        print("FAIL: %s: %s at %s" % (path, error.message, list(error.absolute_path)))
    bad += bool(errors)
sys.exit(1 if bad else 0)
PY
        echo "ok: all ${RECORDS} run records match schemas/run-record.v1.json"
    else
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "NOTE: python3 has no jsonschema, so the run records were not checked against the schema."
fi

if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${FAILURES} command check(s) failed."
    exit 1
fi
echo "All command checks passed."
