#!/bin/bash
#
# Scans Python code for security problems with Bandit, for the bandit
# command. Bandit runs once with a JSON report, from which the orb writes
# SARIF and JUnit, since Bandit writes one format per run and its own SARIF
# is unreliable.
#
# Bandit's exit code says only whether it reported results: a crash exits 1
# too, and a file it can't parse (newer syntax than its Python knows, an
# encoding error) is skipped with exit 0. So the JSON report decides: results
# are findings, which fail the step unless report_only is true, and these
# fail it either way: a report that is missing or isn't Bandit's, a file in
# its errors, an internal error in a check, and a scan of no files. With
# require_suppression_reasons, Bandit runs again with --ignore-nosec, and
# every finding a # nosec suppressed must give a reason after a second #.

set -euo pipefail

if [[ -z "${SCRIPT_PYTHON_SECURITY_LIB:-}" || -z "${SCRIPT_PYTHON_SECURITY_PY:-}" ]]; then
    echo "ERROR: SCRIPT_PYTHON_SECURITY_LIB and SCRIPT_PYTHON_SECURITY_PY must be set; run this script through the orb's bandit command." >&2
    exit 1
fi
eval "${SCRIPT_PYTHON_SECURITY_LIB}"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ps_list targets "${PARAM_TARGETS}"
TARGETS=(${PS_LIST[@]+"${PS_LIST[@]}"})
ps_list exclude "${PARAM_EXCLUDE}"
EXCLUDE=(${PS_LIST[@]+"${PS_LIST[@]}"})
SEVERITY=$(ps_subst "${PARAM_SEVERITY_LEVEL}")
CONFIDENCE=$(ps_subst "${PARAM_CONFIDENCE_LEVEL}")
ps_list tests "${PARAM_TESTS}"
TESTS=(${PS_LIST[@]+"${PS_LIST[@]}"})
ps_list skip "${PARAM_SKIP}"
SKIP=(${PS_LIST[@]+"${PS_LIST[@]}"})
CONFIG=$(ps_subst "${PARAM_CONFIG}")
REASONS=$(ps_bool require_suppression_reasons "${PARAM_REQUIRE_SUPPRESSION_REASONS}")
ALLOW_EMPTY=$(ps_bool allow_empty "${PARAM_ALLOW_EMPTY}")
REPORT_NAME=$(ps_subst "${PARAM_REPORT_NAME}")
JUNIT=$(ps_bool junit "${PARAM_JUNIT}")
RUN_RECORD=$(ps_bool run_record "${PARAM_RUN_RECORD}")
REPORT_ONLY=$(ps_bool report_only "${PARAM_REPORT_ONLY}")
ps_words extra_args "$(ps_subst "${PARAM_EXTRA_ARGS}")"
EXTRA_ARGS=(${PS_WORDS[@]+"${PS_WORDS[@]}"})

# --- Parameters ---
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(.)
fi
for target in "${TARGETS[@]}"; do
    if [[ "${target}" == -* ]]; then
        echo "ERROR: targets can't start with '-': '${target}'." >&2
        exit 1
    fi
    if [[ ! -e "${target}" ]]; then
        echo "ERROR: targets names '${target}', which doesn't exist in $(pwd)." >&2
        exit 1
    fi
done
for level in severity_level:"${SEVERITY}" confidence_level:"${CONFIDENCE}"; do
    case "${level#*:}" in
        low | medium | high) ;;
        *)
            echo "ERROR: ${level%%:*} must be low, medium or high, not '${level#*:}'." >&2
            exit 1
            ;;
    esac
done
for id in ${TESTS[@]+"${TESTS[@]}"} ${SKIP[@]+"${SKIP[@]}"}; do
    # Bandit only warns about an unknown ID, and a test in a # nosec it
    # doesn't know becomes a blanket suppression.
    if ! ps_match "${id}" '^B[0-9]{3}$'; then
        echo "ERROR: tests and skip take Bandit test IDs, such as B602 or B101, not '${id}'." >&2
        exit 1
    fi
done
for path in ${EXCLUDE[@]+"${EXCLUDE[@]}"}; do
    if [[ "${path}" == *,* ]]; then
        echo "ERROR: exclude entries can't hold a comma: '${path}'." >&2
        exit 1
    fi
done
if [[ -n "${CONFIG}" && ! -f "${CONFIG}" ]]; then
    echo "ERROR: config names '${CONFIG}', which is not a file in $(pwd)." >&2
    exit 1
fi
if [[ -z "${CONFIG}" && -f pyproject.toml ]] && grep -q '^\[tool\.bandit[].]' pyproject.toml; then
    # Bandit never reads pyproject.toml by itself.
    CONFIG=pyproject.toml
    echo "Using the [tool.bandit] settings in pyproject.toml."
fi
# Options the command sets itself, or that would change what the report says,
# also as argparse abbreviations (--base for --baseline). Of the short
# options, -v, -d and -q can be given, and -n and -a with their value
# (attached, as in -n5, or next); the others are the command's. A word after
# an option that takes a value is its value.
REFUSED=(--format --output --recursive --exclude --severity-level --confidence-level --tests --skip --configfile --ini
    --exit-zero --ignore-nosec --baseline --profile --version --help)
value_next=false
for word in ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}; do
    if [[ "${value_next}" == true ]]; then
        value_next=false
        continue
    fi
    case "${word}" in
        --)
            echo "ERROR: extra_args can't hold --: what follows would be scanned. Name what to scan in targets." >&2
            exit 1
            ;;
        --*)
            if ps_abbreviates "${word}" "${REFUSED[@]}"; then
                echo "ERROR: extra_args can't hold ${word%%=*}: the bandit command sets it, or it would change what the report says." >&2
                exit 1
            fi
            if [[ "${word}" != *=* ]] && ps_abbreviates "${word}" --number --aggregate --msg-template; then
                value_next=true
            fi
            ;;
        -*)
            if ! ps_match "${word}" '^-[vdq]*([an].*)?$' || [[ "${word}" == - ]]; then
                echo "ERROR: extra_args can't hold ${word}: of Bandit's short options only -v, -d, -q, -n and -a can be given." >&2
                exit 1
            fi
            if ps_match "${word}" '^-[vdq]*[an]$'; then
                value_next=true
            fi
            ;;
        *)
            echo "ERROR: extra_args can't hold '${word}': Bandit would scan it. Name what to scan in targets." >&2
            exit 1
            ;;
    esac
done
ps_require_jq
ps_output "${PARAM_OUTPUT_DIR}" "${REPORT_NAME}"
ps_tool bandit
ps_helper_python
HELPER=${PS_TOOL_PYTHON:-${PS_PYTHON}}
if [[ ! -x "${HELPER}" ]]; then
    HELPER=${PS_PYTHON}
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
rm -f "${PS_BASE}.json" "${PS_BASE}.sarif" "${PS_BASE}.suppressed.json" "${PS_BASE}.run-record.json" \
    "${PS_OUT}/junit/${REPORT_NAME}.xml"
PS_REPORTS=()
PS_INPUTS=()
PS_COUNTS=null
VERSION_TEXT=$("${PS_TOOL}" --version 2> /dev/null || true)
PS_TOOL_VERSION=$(awk 'NR == 1 { print $NF }' <<< "${VERSION_TEXT}")
TOOL_PYTHON=$(sed -n 's/^ *python version = \([^ ]*\).*/\1/p' <<< "${VERSION_TEXT}")
if [[ -n "${CONFIG}" ]]; then
    PS_INPUTS+=("config:${CONFIG}")
fi

# error MESSAGE...: the scan has no verdict. Writes the run record, then
# fails the step.
error() {
    printf 'ERROR: %s\n' "$1" >&2
    if [[ $# -gt 1 ]]; then
        printf '  %s\n' "${@:2}" >&2
    fi
    if [[ "${RUN_RECORD}" == true ]]; then
        PS_REPORTS+=("${PS_BASE}.run-record.json")
        ps_run_record "${PS_BASE}.run-record.json" bandit error 1 "${STARTED}"
    fi
    exit 1
}

# A .bandit file below a target can set Bandit's options, the format and the
# output included, so it is never read: an empty one is named instead.
printf '[bandit]\n' > "${WORK}/bandit.ini"
while IFS= read -r ini; do
    echo "WARN: ${ini} is not read: Bandit's settings come from this command's parameters and config." >&2
done < <(find "${TARGETS[@]}" -name .bandit -type f 2> /dev/null | awk 'NR <= 5')

# Bandit's default exclusions are replaced by -x, so they go first. Bandit
# leaves out a path that contains an entry, so .git also leaves out .github.
# Virtual environments in the working directory hold other people's code; an
# entry for a directory that exists becomes dir/*, which leaves out only it.
EXCLUDES=".svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg"
for path in ./.venv ./venv ./.nox; do
    if [[ -d "${path}" && ! -L "${path}" ]]; then
        EXCLUDES+=",${path}"
    fi
done
for path in ${EXCLUDE[@]+"${EXCLUDE[@]}"}; do
    EXCLUDES+=",${path}"
done
# low is every result, those of plugins that set no severity included.
level() {
    if [[ "$1" == low ]]; then echo all; else echo "$1"; fi
}
PS_ARGS=(-r --exclude "${EXCLUDES}" --severity-level "$(level "${SEVERITY}")" --confidence-level "$(level "${CONFIDENCE}")")
if [[ ${#TESTS[@]} -gt 0 ]]; then
    PS_ARGS+=(--tests "$(IFS=,; echo "${TESTS[*]}")")
fi
if [[ ${#SKIP[@]} -gt 0 ]]; then
    PS_ARGS+=(--skip "$(IFS=,; echo "${SKIP[*]}")")
fi
if [[ -n "${CONFIG}" ]]; then
    PS_ARGS+=(--configfile "${CONFIG}")
fi
PS_ARGS+=(${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})

# scan REPORT LOG [OPTION...]: runs Bandit on the targets.
scan() {
    local report=$1 log=$2 status=0 options=()
    shift 2
    # bash 4.0 takes an empty "$@" for an unbound variable.
    if [[ $# -gt 0 ]]; then
        options=("$@")
    fi
    "${PS_TOOL}" "${PS_ARGS[@]}" --ini "${WORK}/bandit.ini" --format json --output "${report}" --quiet \
        ${options[@]+"${options[@]}"} -- "${TARGETS[@]}" > "${log}" 2>&1 || status=$?
    return "${status}"
}
# completed STATUS REPORT LOG: stops the step unless Bandit completed.
completed() {
    if [[ "$1" -ne 0 && "$1" -ne 1 ]] || ! ps_json_is "$2" \
        '(.results | type) == "array" and (.errors | type) == "array" and (.metrics._totals | type) == "object"'; then
        ps_tail "$3" 30
        error "Bandit could not complete the scan (exit code $1), so there is no verdict." \
            "Bandit exits 1 for results and for a crash alike; only its JSON report tells them apart."
    fi
    if [[ "$1" -eq 1 && "$(jq '.results | length' "$2")" -eq 0 ]]; then
        ps_tail "$3" 30
        error "Bandit exited with 1 but reported nothing, so there is no verdict."
    fi
    # A check that raised an exception on some code is only logged.
    if grep -qE 'Bandit internal error running:|Exception occurred when executing tests against' "$3"; then
        # awk reads every line, where head would end the pipeline early and
        # fail the step with SIGPIPE under pipefail.
        grep -E 'Bandit internal error running:|Exception occurred when executing tests against' "$3" | awk 'NR <= 5 { print "  " $0 }' >&2
        error "A Bandit check failed on some code, so that code wasn't fully checked."
    fi
    if grep -q 'Unknown test found in profile:' "$3"; then
        grep 'Unknown test found in profile:' "$3" | sed 's/^/  /' >&2
        error "The tests or skips name a test Bandit doesn't have."
    fi
}

REPORT="${WORK}/bandit.json"
echo "Running: bandit $(ps_show_command "${PS_ARGS[@]}" -- "${TARGETS[@]}")"
echo "Bandit ${PS_TOOL_VERSION:-?} parses code with Python ${TOOL_PYTHON:-?}."
STATUS=0
scan "${REPORT}" "${WORK}/bandit.log" || STATUS=$?
grep -v -e '^\[main\]' -e '^Run started' "${WORK}/bandit.log" | sed 's/^/  /' || true
completed "${STATUS}" "${REPORT}" "${WORK}/bandit.log"
cp "${REPORT}" "${PS_BASE}.json"
PS_REPORTS+=("${PS_BASE}.json")

# --- Files Bandit couldn't scan ---
ERRORS=$(jq '.errors | length' "${REPORT}")
if [[ "${ERRORS}" -gt 0 ]]; then
    echo "ERROR: Bandit couldn't scan $(ps_plural "${ERRORS}" file files), so the scan is incomplete:" >&2
    while IFS=$'\t' read -r file reason; do
        echo "  ${file}: ${reason}" >&2
        if [[ "${reason}" == *"syntax error"* && -f "${file}" ]]; then
            # Bandit drops the parser's message; the same Python gives it.
            "${HELPER}" -I -c 'import ast, sys
try:
    ast.parse(open(sys.argv[1], "rb").read(), sys.argv[1])
except SyntaxError as error:
    print("    line %s: %s" % (error.lineno, error.msg))' "${file}" >&2 || true
        fi
    done < <(jq -r '.errors[:20][] | [.filename, .reason] | @tsv' "${REPORT}")
    error "Bandit parses code with the Python it runs on (${TOOL_PYTHON:-unknown}), and skips what that Python can't parse." \
        "Fix the syntax, install Bandit with a newer python (install's python parameter) for code that needs one," \
        "or exclude the files."
fi
SCANNED=$(jq '[.metrics | keys[] | select(. != "_totals")] - [.errors[].filename] | length' "${REPORT}")
if [[ "${SCANNED}" -eq 0 && "${ALLOW_EMPTY}" != true ]]; then
    error "Bandit found no Python files to scan in ${TARGETS[*]}, so the scan checked nothing." \
        "Check targets and exclude (an entry leaves out every path that contains it), or set allow_empty to true."
fi

# --- Suppressions ---
SUPPRESSED="[]"
if [[ "${REASONS}" == true ]]; then
    STATUS=0
    scan "${WORK}/all.json" "${WORK}/all.log" --ignore-nosec || STATUS=$?
    completed "${STATUS}" "${WORK}/all.json" "${WORK}/all.log"
    if [[ "$(jq -c '[.errors[].filename] | sort' "${WORK}/all.json")" != "$(jq -c '[.errors[].filename] | sort' "${REPORT}")" ]]; then
        error "Bandit scanned different files with --ignore-nosec, so the suppressions can't be told apart."
    fi
    # The results only the second run has are the suppressed ones.
    jq -n --slurpfile kept "${REPORT}" --slurpfile all "${WORK}/all.json" '
        def key: [.filename, .test_id, .line_number, .col_offset];
        ($kept[0].results | map(key)) as $keys
        | reduce $all[0].results[] as $r ({keys: $keys, out: []};
            ($r | key) as $k | (.keys | index([$k])) as $i
            | if $i == null then .out += [$r] else .keys |= (.[:$i] + .[$i + 1:]) end)
        | .out' > "${WORK}/suppressed.json"
    ps_py "${HELPER}" nosec "${WORK}/suppressed.json" > "${WORK}/suppressed-reasons.json"
    SUPPRESSED=$(jq -c . "${WORK}/suppressed-reasons.json")
    cp "${WORK}/suppressed-reasons.json" "${PS_BASE}.suppressed.json"
    PS_REPORTS+=("${PS_BASE}.suppressed.json")
fi
UNREASONED=$(jq '[.[] | select(.reason == "")] | length' <<< "${SUPPRESSED}")

# --- Reports ---
FINDINGS=$(jq '.results | length' "${REPORT}")
# shellcheck disable=SC2016 # jq program, not shell
jq --argjson suppressed "${SUPPRESSED}" --arg version "${PS_TOOL_VERSION}" '
    def uri: sub("^\\./"; "");
    def level: {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}[.issue_severity] // "warning";
    def score: {"HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}[.issue_severity] // "5.5";
    def result($suppression):
        {ruleId: .test_id, level: level,
         message: {text: "\(.issue_text) (severity \(.issue_severity), confidence \(.issue_confidence))"},
         locations: [{physicalLocation: {artifactLocation: {uri: (.filename | uri)},
            region: ({startLine: .line_number, endLine: ([.line_range[]?, .line_number] | max), startColumn: (.col_offset + 1)})}}]}
        + (if $suppression then {suppressions: [{kind: "inSource", justification: (.reason // "")}]} else {} end);
    {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
     runs: [{
        tool: {driver: {name: "Bandit", version: $version, informationUri: "https://bandit.readthedocs.io/",
            rules: [(.results + $suppressed) | unique_by(.test_id)[] | {id: .test_id, name: .test_name,
                shortDescription: {text: "\(.test_id): \(.test_name)"},
                helpUri: .more_info,
                properties: {tags: (["security"] + (if .issue_cwe.id then ["external/cwe/cwe-\(.issue_cwe.id)"] else [] end)),
                    "security-severity": score}}]}},
        results: ([.results[] | result(false)] + [$suppressed[] | result(true)])}]}' "${REPORT}" > "${PS_BASE}.sarif"
PS_REPORTS+=("${PS_BASE}.sarif")
if [[ "${JUNIT}" == true ]]; then
    # shellcheck disable=SC2016 # jq program, not shell
    ps_junit "${PS_OUT}/junit/${REPORT_NAME}.xml" "bandit" "$(jq -c --argjson suppressed "${SUPPRESSED}" '
        [(.results[] | {classname: .filename, name: "\(.test_id) \(.test_name) line \(.line_number)", status: "failed",
            message: "\(.issue_text) (\(.issue_severity))", detail: .code}),
         ($suppressed[] | select(.reason == "") | {classname: .filename,
            name: "\(.test_id) suppressed without a reason, line \(.nosec_line // .line_number)", status: "failed",
            message: "A # nosec suppresses \(.test_id) without a reason after a second #", detail: (.nosec_comment // "")}),
         ($suppressed[] | select(.reason != "") | {classname: .filename, name: "\(.test_id) line \(.line_number)",
            status: "skipped", message: "Suppressed: \(.reason)"})]' "${REPORT}")"
    PS_REPORTS+=("${PS_OUT}/junit/${REPORT_NAME}.xml")
fi

# --- Summary and gate ---
# shellcheck disable=SC2034 # read by ps_run_record
PS_COUNTS=$(jq -c --argjson scanned "${SCANNED}" --argjson suppressed "${SUPPRESSED}" '{files: $scanned,
    lines: (.metrics._totals.loc // 0), findings: (.results | length),
    high: [.results[] | select(.issue_severity == "HIGH")] | length,
    medium: [.results[] | select(.issue_severity == "MEDIUM")] | length,
    low: [.results[] | select(.issue_severity == "LOW")] | length,
    nosec: ((.metrics._totals.nosec // 0) + (.metrics._totals.skipped_tests // 0)),
    suppressed_without_reason: [$suppressed[] | select(.reason == "")] | length}' "${REPORT}")
echo "Bandit scanned $(ps_plural "${SCANNED}" file files) ($(jq '.metrics._totals.loc // 0' "${REPORT}") lines): $(ps_plural "${FINDINGS}" finding findings)."
if [[ "${FINDINGS}" -gt 0 ]]; then
    jq -r '(.results[:50][] | "  \(.filename):\(.line_number): \(.test_id) \(.test_name) [\(.issue_severity)/\(.issue_confidence)]\n    \(.issue_text)"),
        (.results | length | select(. > 50) | "  ... and \(. - 50) more, in the reports.")' "${REPORT}"
fi
if [[ "${UNREASONED}" -gt 0 ]]; then
    echo "Suppressed without a reason (write it after a second #, as in '# nosec B602 # why it is safe'):"
    jq -r '.[] | select(.reason == "") | "  \(.filename):\(.nosec_line // .line_number): \(.test_id) \(.test_name): \(.nosec_comment // "")"' <<< "${SUPPRESSED}"
fi
GATE=false
OUTCOME=passed
if [[ "${FINDINGS}" -gt 0 || "${UNREASONED}" -gt 0 ]]; then
    GATE=true
    OUTCOME=findings
    if [[ "${REPORT_ONLY}" == true ]]; then
        OUTCOME=findings-reported
    fi
fi
if [[ "${RUN_RECORD}" == true ]]; then
    PS_REPORTS+=("${PS_BASE}.run-record.json")
    ps_run_record "${PS_BASE}.run-record.json" bandit "${OUTCOME}" 0 "${STARTED}"
fi
ps_gate "${GATE}" "${REPORT_ONLY}" \
    "Bandit found $(ps_plural "${FINDINGS}" problem problems)$(if [[ "${UNREASONED}" -gt 0 ]]; then echo ", and $(ps_plural "${UNREASONED}" suppression suppressions) without a reason"; fi)."
