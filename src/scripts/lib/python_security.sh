#!/bin/bash

# Shared helpers for the python-security-orb commands. Each command passes this
# file to its step as SCRIPT_PYTHON_SECURITY_LIB, and its script evals it after
# set -euo pipefail, so it only defines functions.

# ps_subst VALUE: prints VALUE with environment variables expanded. The value
# is piped in on stdin: passed as an argument, a value starting with "-" would
# be parsed as a flag. Without the CircleCI CLI (GitHub Actions and local
# runs), the value is used as is.
ps_subst() {
    if command -v circleci > /dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}

# ps_bool NAME VALUE: prints true or false. CircleCI passes boolean parameters
# as 1 or 0; GitHub Actions and local callers use true or false.
ps_bool() {
    case "$2" in
        1 | true) echo true ;;
        0 | false) echo false ;;
        *)
            echo "ERROR: ${1} must be true or false, not '${2}'." >&2
            exit 1
            ;;
    esac
}

# split_shell_words STRING: splits STRING into the SHELL_WORDS array the way
# the shell splits a command line into words, but expands and executes
# nothing. Single quotes keep everything literal. Inside double quotes a
# backslash escapes only ", \, $, ` and newline, as in bash. Outside quotes a
# backslash escapes the next character, and a backslash-newline joins lines.
# A # that starts a word starts a comment, which runs to the end of the line.
# Spaces, tabs and newlines separate words, and '' is an empty word. Returns 1
# if a quote is never closed, 2 if the input ends in a backslash outside
# quotes (which escapes nothing), 3 for bash's $'...' or $"..." quoting, which
# it does not implement, 4 for a $(...) or backtick outside quotes, which it
# would not run, and 5 for a shell operator (| & ; < > ( )) outside quotes,
# such as a redirection or a <(...) process substitution.
split_shell_words() {
    local input=$1 word="" in_word=false quote="" char next i
    SHELL_WORDS=()
    for ((i = 0; i < ${#input}; i++)); do
        char=${input:i:1}
        if [[ "${quote}" == "'" ]]; then
            if [[ "${char}" == "'" ]]; then quote=""; else word+=${char}; fi
        elif [[ "${quote}" == '"' ]]; then
            if [[ "${char}" == '"' ]]; then
                quote=""
            elif [[ "${char}" == "\\" ]] && ((i + 1 < ${#input})); then
                next=${input:i+1:1}
                case "${next}" in
                    '"' | "\\" | '$' | '`') word+=${next}; i=$((i + 1)) ;;
                    $'\n') i=$((i + 1)) ;;
                    *) word+=${char} ;;
                esac
            else
                word+=${char}
            fi
        else
            case "${char}" in
                ' ' | $'\t' | $'\n')
                    if [[ "${in_word}" == true ]]; then
                        SHELL_WORDS+=("${word}")
                        word=""
                        in_word=false
                    fi
                    ;;
                "'" | '"') quote=${char}; in_word=true ;;
                "#")
                    if [[ "${in_word}" == true ]]; then
                        word+=${char}
                    else
                        while ((i + 1 < ${#input})) && [[ "${input:i+1:1}" != $'\n' ]]; do
                            i=$((i + 1))
                        done
                    fi
                    ;;
                "\\")
                    ((i + 1 < ${#input})) || return 2
                    i=$((i + 1))
                    if [[ "${input:i:1}" != $'\n' ]]; then
                        word+=${input:i:1}
                        in_word=true
                    fi
                    ;;
                '$')
                    case "${input:i+1:1}" in
                        "'" | '"') return 3 ;;
                        "(") return 4 ;;
                    esac
                    word+=${char}
                    in_word=true
                    ;;
                '`') return 4 ;;
                '|' | '&' | ';' | '<' | '>' | '(' | ')') return 5 ;;
                *) word+=${char}; in_word=true ;;
            esac
        fi
    done
    [[ -z "${quote}" ]] || return 1
    if [[ "${in_word}" == true ]]; then
        SHELL_WORDS+=("${word}")
    fi
}

# ps_words PARAMETER VALUE: sets PS_WORDS to VALUE split like shell words
# (see split_shell_words), naming PARAMETER in any error. Nothing in it is
# expanded or executed: a $(...) or backtick that reached a parameter through
# an environment variable (a branch name, a commit message) reaches the tool as
# text inside quotes, and fails the step outside them.
ps_words() {
    local status=0
    split_shell_words "$2" || status=$?
    case "${status}" in
        0) ;;
        1)
            echo "ERROR: ${1} could not be split into arguments: it has a quote that is never closed." >&2
            echo "  A literal ' or \" needs a backslash before it, or quotes of the other kind around it." >&2
            exit 1
            ;;
        2)
            echo "ERROR: ${1} could not be split into arguments: it ends in a backslash." >&2
            echo "  A literal \\ at the end needs another \\ before it." >&2
            exit 1
            ;;
        3)
            echo "ERROR: ${1} could not be split into arguments: \$'...' and \$\"...\" quoting is not supported." >&2
            echo "  Use '...' or \"...\" instead." >&2
            exit 1
            ;;
        4)
            echo "ERROR: ${1} could not be split into arguments: it has a \$(...) or backtick outside quotes." >&2
            echo "  ${1} is not run as shell code, so the command would not run. Quote it to pass it to the tool as text." >&2
            exit 1
            ;;
        *)
            echo "ERROR: ${1} could not be split into arguments: it has one of | & ; < > ( ) outside quotes." >&2
            echo "  ${1} is not run as shell code, so pipes, redirections and <(...) would not work. Quote it to pass it to the tool as text." >&2
            exit 1
            ;;
    esac
    # shellcheck disable=SC2034 # read by the script that evals this file
    PS_WORDS=(${SHELL_WORDS[@]+"${SHELL_WORDS[@]}"})
}

# ps_match VALUE REGEX: [[ VALUE =~ REGEX ]] in the C locale, setting
# BASH_REMATCH. In other locales a range such as [a-z] can match letters such
# as é (cimg images set LC_ALL=en_US.UTF-8), so checks with ranges use this.
ps_match() {
    local LC_ALL=C
    [[ "$1" =~ $2 ]]
}

# ps_list PARAMETER VALUE: sets PS_LIST to VALUE, with environment variables
# expanded, split on commas and spaces.
ps_list() {
    local value
    PS_LIST=()
    value=$(ps_subst "$2")
    if [[ "${value}" == *$'\n'* ]]; then
        echo "ERROR: ${1} must be separated by commas or spaces, not newlines." >&2
        exit 1
    fi
    # shellcheck disable=SC2034 # read by the script that evals this file
    read -r -a PS_LIST <<< "${value//,/ }"
}

# ps_require_jq: stops the step unless jq, which the reports are built with,
# is on the PATH.
ps_require_jq() {
    if ! command -v jq > /dev/null 2>&1; then
        echo "ERROR: jq is not on the PATH, and this command needs it to write its reports." >&2
        echo "  CircleCI's cimg images and GitHub's hosted runners have it; elsewhere, install jq in an earlier step." >&2
        exit 1
    fi
}

# ps_output DIR NAME: checks output_dir and report_name, creates DIR, and sets
# PS_OUT to DIR and PS_BASE to the path every report of this run starts with.
ps_output() {
    if [[ "$1" != /* || "$1" == *$'\n'* ]]; then
        echo "ERROR: output_dir must be an absolute path, not '$1'." >&2
        exit 1
    fi
    if ! ps_match "$2" '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
        echo "ERROR: report_name must be letters, digits, '.', '_' and '-', not '$2'." >&2
        exit 1
    fi
    if ! mkdir -p "$1"; then
        echo "ERROR: Could not create output_dir $1." >&2
        exit 1
    fi
    PS_OUT=${1%/}
    PS_OUT=${PS_OUT:-/}
    # shellcheck disable=SC2034 # read by the script that evals this file
    PS_BASE="${PS_OUT%/}/$2"
}

# ps_uint PARAMETER VALUE [MIN]: stops the step unless VALUE is a whole number
# of at least MIN (default 0).
ps_uint() {
    if ! ps_match "$2" '^[0-9]{1,9}$' || ((10#$2 < ${3:-0})); then
        echo "ERROR: ${1} must be a whole number of at least ${3:-0}, not '$2'." >&2
        exit 1
    fi
}

# ps_junit FILE SUITE CASES: writes JUnit XML to FILE, for CircleCI's Tests
# tab or any other JUnit reader, from CASES, a JSON array of test cases:
#   {"classname": ..., "name": ..., "status": "failed" | "skipped" | "passed",
#    "message": ..., "detail": ...}
# A run with no cases gets one passing case, so the tab shows it ran.
ps_junit() {
    local dir=${1%/*}
    mkdir -p "${dir}"
    # shellcheck disable=SC2016 # jq program, not shell
    jq -r --arg suite "$2" '
        (if length == 0 then [{classname: $suite, name: "no findings", status: "passed"}] else . end) as $cases
        | "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
          "<testsuites>",
          "  <testsuite name=\"\($suite | @html)\" tests=\"\($cases | length)\" failures=\"\([$cases[] | select(.status == "failed")] | length)\" skipped=\"\([$cases[] | select(.status == "skipped")] | length)\">",
          ($cases[] |
            "    <testcase classname=\"\(.classname | @html)\" name=\"\(.name | @html)\">"
            + (if .status == "failed" then "<failure message=\"\((.message // "") | @html)\">\((.detail // "") | @html)</failure>"
               elif .status == "skipped" then "<skipped message=\"\((.message // "") | @html)\"/>"
               else "" end)
            + "</testcase>"),
          "  </testsuite>",
          "</testsuites>"
    ' <<< "$3" > "$1"
}

# ps_gate FINDINGS REPORT_ONLY SUMMARY: ends a check. Without findings it
# succeeds. With findings it fails with SUMMARY, unless REPORT_ONLY is true,
# when it only warns: the reports are written either way.
ps_gate() {
    if [[ "$1" == false ]]; then
        echo "Passed: $3"
        exit 0
    fi
    if [[ "$2" == true ]]; then
        echo "WARN: $3" >&2
        echo "WARN: report_only is true, so this step passes. The reports are in ${PS_OUT}." >&2
        exit 0
    fi
    echo "ERROR: $3" >&2
    echo "  The reports are in ${PS_OUT}. Set report_only to true to report findings without failing." >&2
    exit 1
}

# ps_plural COUNT SINGULAR PLURAL: prints COUNT and the word that goes with
# it, such as "1 file" or "2 files".
ps_plural() {
    if [[ "$1" -eq 1 ]]; then
        printf '%s %s\n' "$1" "$2"
    else
        printf '%s %s\n' "$1" "$3"
    fi
}

# ps_tail FILE [LINES]: prints the last LINES (default 40) lines of FILE to
# stderr, indented, to show why a tool failed. A Python traceback ends with
# the exception, so the tail holds it.
ps_tail() {
    tail -n "${2:-40}" "$1" | sed 's/^/  /' >&2
}

# ps_export NAME VALUE: exports NAME=VALUE, shell-quoted, to later steps
# through BASH_ENV (on GitHub Actions, the action passes it on through
# GITHUB_ENV).
ps_export() {
    if [[ -z "${BASH_ENV:-}" ]]; then
        echo "WARN: BASH_ENV is not set, so ${1} is not exported to later steps." >&2
        return 0
    fi
    printf 'export %s=%q\n' "$1" "$2" >> "${BASH_ENV}"
}

# ps_env_var_name PARAMETER VALUE: stops the step unless VALUE can name an
# environment variable.
ps_env_var_name() {
    if ! ps_match "$2" '^[A-Za-z_][A-Za-z0-9_]*$'; then
        echo "ERROR: ${1} must name an environment variable, not '${2}'." >&2
        exit 1
    fi
}

# ps_json_is FILE FILTER [JQ_OPTION...]: whether FILE holds one JSON value for
# which FILTER is true. It compares jq's output instead of using -e, since jq
# 1.6 (as on Ubuntu 22.04 and some cimg images) exits 0 with -e when the file
# is empty, as a tool that failed before writing its report leaves it.
ps_json_is() {
    local file=$1 filter=$2 options=()
    if [[ $# -gt 2 ]]; then
        options=("${@:3}")
    fi
    [[ "$(jq -c ${options[@]+"${options[@]}"} "(${filter}) | if . then true else false end" "${file}" 2> /dev/null)" == true ]]
}

# ps_sha256 FILE: prints FILE's SHA-256.
ps_sha256() {
    sha256sum -- "$1" | awk '{ print $1 }'
}

# ps_url_public URL: prints URL without the userinfo, query and fragment,
# which can hold credentials, so it can go in a log or an artifact.
ps_url_public() {
    local url=$1
    if [[ "${url}" =~ ^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*@)?([^?#]*) ]]; then
        printf '%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
    else
        printf '%s\n' "${url%%[?#]*}"
    fi
}

# ps_ci_json: describes the CI job this runs in, for run records: a CircleCI
# job or a GitHub Actions run, or null elsewhere.
ps_ci_json() {
    if [[ -n "${CIRCLE_BUILD_URL:-}" ]]; then
        jq -cn --arg url "${CIRCLE_BUILD_URL}" --arg sha "${CIRCLE_SHA1:-}" --arg job "${CIRCLE_JOB:-}" \
            --arg repo "${CIRCLE_PROJECT_USERNAME:-}${CIRCLE_PROJECT_REPONAME:+/${CIRCLE_PROJECT_REPONAME}}" \
            '{provider: "circleci", build_url: $url, sha1: $sha, job: $job, repository: $repo}'
    elif [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        jq -cn --arg url "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}/attempts/${GITHUB_RUN_ATTEMPT:-1}" \
            --arg sha "${GITHUB_SHA:-}" --arg job "${GITHUB_JOB:-}" --arg repo "${GITHUB_REPOSITORY:-}" \
            '{provider: "github-actions", build_url: $url, sha1: $sha, job: $job, repository: $repo}'
    else
        echo null
    fi
}

# ps_tool NAME: sets PS_TOOL to NAME's path on the PATH, or stops the step
# saying how to install it, and PS_TOOL_PYTHON to the interpreter of the
# virtual environment this orb's install put it in, as the install record
# beside it says. Warns when NAME is not one this orb's install verified,
# such as a copy that came with the image or a project's own environment:
# PS_TOOL_PYTHON is then empty.
ps_tool() {
    local record sha
    PS_TOOL_PYTHON=""
    if ! PS_TOOL=$(command -v "$1"); then
        echo "ERROR: $1 is not on the PATH. Install it in an earlier step with this orb's install (tools: $1)," >&2
        echo "  or with install_${1//-/_}." >&2
        exit 1
    fi
    record="$(dirname "${PS_TOOL}")/.$1.install.json"
    sha=$(sha512sum -- "${PS_TOOL}" 2> /dev/null | awk '{ print $1 }') || sha=""
    # shellcheck disable=SC2016 # jq program, not shell
    if [[ -n "${sha}" && -f "${record}" ]] && ps_json_is "${record}" '.binary_sha512 == $sha' --arg sha "${sha}"; then
        # shellcheck disable=SC2034 # read by the script that evals this file
        PS_TOOL_PYTHON=$(jq -r '.venv + "/bin/python"' "${record}")
        if [[ "$(jq -r '.verified' "${record}")" != true ]]; then
            echo "WARN: ${PS_TOOL} was installed without verifying it against this orb's locks (verify_checksums)." >&2
        fi
        return 0
    fi
    echo "WARN: ${PS_TOOL} is not the $1 this orb's install verified against its locks." >&2
    echo "WARN: Install $1 with this orb's install, and put its install_path first on the PATH, to run a verified one." >&2
}

# ps_tool_json PATH VERSION: describes a tool that ran for the run record:
# its SHA-512, and how the orb installed it, from the install record beside
# it when that record describes this very file.
ps_tool_json() {
    local sha="" install="null" entry
    if [[ -n "$1" && -f "$1" ]]; then
        # Without sha512sum the record says so with a null SHA-512, as ps_tool
        # only warns.
        sha=$(sha512sum -- "$1" 2> /dev/null | awk '{ print $1 }') || sha=""
        entry="$(dirname "$1")/.${1##*/}.install.json"
        # shellcheck disable=SC2016 # jq program, not shell
        if [[ -f "${entry}" ]] && ps_json_is "${entry}" '.binary_sha512 == $sha' --arg sha "${sha}"; then
            install=$(jq -c 'del(.binary_sha512)' "${entry}")
        fi
    fi
    jq -cn --arg name "${1##*/}" --arg path "$1" --arg version "$2" --arg sha "${sha}" --argjson install "${install}" \
        '{name: $name, path: $path, version: $version, sha512: (if $sha == "" then null else $sha end), install: $install}'
}

# ps_args_json ARG...: the arguments as a JSON array. They pass through jq
# NUL-separated, so arguments that start with "-" never reach jq's own option
# parsing, and a URL among them loses its userinfo, query and fragment.
ps_args_json() {
    if [[ $# -eq 0 ]]; then
        echo '[]'
        return 0
    fi
    # Ended by a word rather than a NUL, which jq 1.6 drops from the end of
    # raw input.
    { printf '%s\0' "$@"; printf 'end'; } | jq -Rsc 'split("\u0000") | .[:-1]
        | map(gsub("(?<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/?#\\s]*@"; "\(.scheme)")
            | gsub("(?<url>[A-Za-z][A-Za-z0-9+.-]*://[^?#\\s]*)[?#]\\S*"; "\(.url)"))'
}

# ps_show_command ARG...: the arguments as one line to log, each quoted for
# the shell only when it needs it, and URLs stripped as ps_args_json strips
# them.
ps_show_command() {
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    ps_args_json "$@" | jq -r 'map(if test("^[A-Za-z0-9_./:=@%+,-]+$") then . else @sh end) | join(" ")'
}

# ps_py PYTHON COMMAND ARG...: runs the orb's Python helper (SCRIPT_PYTHON_SECURITY_PY,
# src/scripts/lib/python_security.py) with PYTHON in isolated mode, so the
# job's PYTHONPATH and the working directory's modules stay out of it.
ps_py() {
    local python=$1
    shift
    "${python}" -I -c "${SCRIPT_PYTHON_SECURITY_PY}" "$@"
}

# ps_helper_python: sets PS_PYTHON to the Python the helper runs on: the one
# the orb's install exported in PYTHON_SECURITY_ORB_PYTHON, or else python3
# on the PATH. Stops the step if neither runs.
ps_helper_python() {
    PS_PYTHON=${PYTHON_SECURITY_ORB_PYTHON:-}
    if [[ -z "${PS_PYTHON}" || ! -x "${PS_PYTHON}" ]]; then
        PS_PYTHON=$(command -v python3 || true)
    fi
    if [[ -z "${PS_PYTHON}" ]] || ! "${PS_PYTHON}" -I -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2> /dev/null; then
        echo "ERROR: This command needs Python 3.8 or newer: install it in an earlier step with this orb's install" >&2
        echo "  (tools: python, or any tool), or use an image with python3." >&2
        exit 1
    fi
}

# ps_abbreviates WORD OPTION...: whether WORD, a long option as given (with
# or without =VALUE), is one of OPTIONS or a prefix of one, which argparse
# reads as that option.
ps_abbreviates() {
    local name=${1%%=*} option
    shift
    for option in "$@"; do
        if [[ "${option}" == "${name}"* ]]; then
            return 0
        fi
    done
    return 1
}

# ps_lock_line FILE NAME: the line of package NAME's entry in a lockfile or
# requirements file, or 1, for SARIF.
ps_lock_line() {
    awk -v name="$2" '
        BEGIN { want1 = "name = \"" name "\""; want2 = "\"" name "\": {" }
        { line = $0; sub(/^[ \t]+/, "", line) }
        line == want1 || line == want2 || tolower(line) ~ "^" name "(\\[[^]]*\\])?[ ]*==" { print NR; found = 1; exit }
        END { if (!found) print 1 }' "$1" 2> /dev/null || echo 1
}

# ps_environment VALUE: sets PS_ENVIRONMENT to the interpreter of an
# installed environment: VALUE itself, or VALUE/bin/python for the
# environment's directory, made absolute without following links, since a
# virtual environment's python is a link to the interpreter it was made with.
ps_environment() {
    local python=$1
    if [[ -d "${python}" && -x "${python}/bin/python" ]]; then
        python=${python%/}/bin/python
    fi
    if [[ -d "${python}" || ! -x "${python}" ]]; then
        echo "ERROR: environment must be the Python interpreter of an installed environment, such as .venv/bin/python," >&2
        echo "  or its directory, such as .venv; '$1' is not an executable file." >&2
        exit 1
    fi
    if [[ "${python}" != /* ]]; then
        python="$(cd "$(dirname "${python}")" && pwd)/${python##*/}"
    fi
    # shellcheck disable=SC2034 # read by the script that evals this file
    PS_ENVIRONMENT=${python}
}

# ps_files PARAMETER: sets PS_FILES to the files PS_LIST names, each a path
# or a glob relative to the working directory. A pattern that matches no
# file fails the step: a typo would otherwise check nothing.
ps_files() {
    local pattern match matches
    PS_FILES=()
    for pattern in ${PS_LIST[@]+"${PS_LIST[@]}"}; do
        matches=0
        while IFS= read -r match; do
            [[ -n "${match}" ]] || continue
            PS_FILES+=("${match}")
            matches=$((matches + 1))
        done < <(compgen -G "${pattern}" | LC_ALL=C sort || true)
        if [[ "${matches}" -eq 0 || ( "${pattern}" != *[*?[]* && ! -f "${pattern}" ) ]]; then
            echo "ERROR: $1 names '${pattern}', but there is no such file in $(pwd)." >&2
            exit 1
        fi
    done
}

# ps_run_record FILE COMMAND OUTCOME EXIT_CODE STARTED: writes a run record,
# the JSON document schemas/run-record.v1.json describes, saying what exactly
# this command checked, so a reviewer can tell without running it again. It
# reads what the command set:
#   PS_TOOL          the tool that ran, if any (the script install put on the PATH)
#   PS_TOOL_VERSION  what it reports as its version
#   PS_ARGS          the arguments it ran with, as an array
#   PS_INPUTS        "role:path" entries, such as "lockfile:uv.lock"
#   PS_REPORTS       the report files written
#   PS_COUNTS        a JSON object of the command's counts
#   PS_RESULTS       a JSON array of per-item results, such as one per input
#   PS_TARGET_JSON   the environment checked, as JSON, if any
# OUTCOME is passed, findings, findings-reported (findings with report_only)
# or error.
ps_run_record() {
    local file=$1 entry path role sha inputs="[]" reports="[]" args
    for entry in ${PS_INPUTS[@]+"${PS_INPUTS[@]}"}; do
        role=${entry%%:*}
        path=${entry#*:}
        sha=""
        if [[ -f "${path}" ]]; then
            sha=$(ps_sha256 "${path}")
        fi
        if [[ -d "$(dirname "${path}")" ]]; then
            path=$(cd "$(dirname "${path}")" && pwd)/${path##*/}
        fi
        inputs=$(jq -c --arg role "${role}" --arg path "${path}" --arg sha "${sha}" \
            '. + [{role: $role, path: $path, sha256: (if $sha == "" then null else $sha end)}]' <<< "${inputs}")
    done
    for path in ${PS_REPORTS[@]+"${PS_REPORTS[@]}"}; do
        if [[ -f "${path}" ]]; then
            reports=$(jq -c --arg path "${path}" --arg sha "$(ps_sha256 "${path}")" '. + [{path: $path, sha256: $sha}]' <<< "${reports}")
        fi
    done
    args=$(ps_args_json ${PS_ARGS[@]+"${PS_ARGS[@]}"})
    if ! jq -n --arg command "$2" --arg outcome "$3" --argjson code "$4" --arg started "$5" \
        --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg cwd "$(pwd)" --argjson ci "$(ps_ci_json)" \
        --argjson tool "$(if [[ -n "${PS_TOOL:-}" ]]; then ps_tool_json "${PS_TOOL}" "${PS_TOOL_VERSION:-}"; else echo null; fi)" \
        --argjson target "${PS_TARGET_JSON:-null}" \
        --argjson inputs "${inputs}" --argjson reports "${reports}" --argjson counts "${PS_COUNTS:-null}" \
        --argjson results "${PS_RESULTS:-null}" --argjson args "${args}" '{
            schema: "https://github.com/juburr/python-security-orb/blob/main/schemas/run-record.v1.json",
            command: $command, outcome: $outcome, exit_code: $code,
            started_at: $started, finished_at: $finished, ci: $ci, working_directory: $cwd,
            tool: $tool, arguments: $args, target: $target,
            inputs: $inputs, counts: $counts, results: $results, reports: $reports
        }' > "${file}"; then
        echo "WARN: Could not write the run record ${file}." >&2
        return 0
    fi
    echo "Run record: ${file}"
}
