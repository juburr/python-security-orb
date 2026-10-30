#!/bin/bash
#
# Inventories the licenses of an installed environment's packages with
# pip-licenses, and checks them against allowed_licenses, for the licenses
# command. pip-licenses reads each package's metadata (License-Expression,
# the License field and the license classifiers) and runs from an empty
# directory, so no [tool.pip-licenses] settings filter what it lists. The
# policy is applied here, not with pip-licenses' --allow-only, which compares
# whole strings: each license is read as an SPDX expression (an OR needs one
# allowed side, an AND every part), from clarify first, then
# License-Expression, a License field that reads as an identifier, then the
# classifiers, each of which must be allowed.
#
# Packages that aren't allowed or ignored fail the step unless report_only is
# true. These always fail it: pip-licenses failing, an inventory that leaves
# out a package the interpreter sees, and an environment with no package to
# check (unless allow_empty).

set -euo pipefail

if [[ -z "${SCRIPT_PYTHON_SECURITY_LIB:-}" || -z "${SCRIPT_PYTHON_SECURITY_PY:-}" ]]; then
    echo "ERROR: SCRIPT_PYTHON_SECURITY_LIB and SCRIPT_PYTHON_SECURITY_PY must be set; run this script through the orb's licenses command." >&2
    exit 1
fi
eval "${SCRIPT_PYTHON_SECURITY_LIB}"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ENVIRONMENT=$(ps_subst "${PARAM_ENVIRONMENT}")
ps_list allowed_licenses "${PARAM_ALLOWED_LICENSES}"
ALLOWED=(${PS_LIST[@]+"${PS_LIST[@]}"})
ps_list ignore "${PARAM_IGNORE}"
IGNORE=(${PS_LIST[@]+"${PS_LIST[@]}"})
CLARIFY=$(ps_subst "${PARAM_CLARIFY}")
CHECK_PROJECT=$(ps_bool check_project "${PARAM_CHECK_PROJECT}")
ALLOW_EMPTY=$(ps_bool allow_empty "${PARAM_ALLOW_EMPTY}")
REPORT_NAME=$(ps_subst "${PARAM_REPORT_NAME}")
JUNIT=$(ps_bool junit "${PARAM_JUNIT}")
RUN_RECORD=$(ps_bool run_record "${PARAM_RUN_RECORD}")
REPORT_ONLY=$(ps_bool report_only "${PARAM_REPORT_ONLY}")

# --- Parameters ---
if [[ ${#ALLOWED[@]} -eq 0 ]]; then
    echo "ERROR: allowed_licenses is empty, so no package could pass." >&2
    exit 1
fi
for license in "${ALLOWED[@]}"; do
    if ! ps_match "${license}" '^[A-Za-z0-9][A-Za-z0-9.+:-]*$'; then
        echo "ERROR: allowed_licenses takes license identifiers, such as MIT or Apache-2.0, not '${license}'." >&2
        exit 1
    fi
done
for entry in ${IGNORE[@]+"${IGNORE[@]}"}; do
    if ! ps_match "${entry}" '^[A-Za-z0-9][A-Za-z0-9._-]*(==[^=[:space:]]+)?$'; then
        echo "ERROR: ignore takes package names, or name==version, not '${entry}'." >&2
        exit 1
    fi
done
if [[ -z "${ENVIRONMENT}" ]]; then
    if [[ ! -x .venv/bin/python ]]; then
        echo "ERROR: There is no .venv in $(pwd). Name the environment whose packages to check with environment," >&2
        echo "  such as .venv/bin/python." >&2
        exit 1
    fi
    ENVIRONMENT=.venv
fi
ps_environment "${ENVIRONMENT}"
ENVIRONMENT=${PS_ENVIRONMENT}
ps_require_jq
ps_output "${PARAM_OUTPUT_DIR}" "${REPORT_NAME}"
ps_tool pip-licenses
ps_helper_python
HELPER=${PS_TOOL_PYTHON:-${PS_PYTHON}}
if [[ ! -x "${HELPER}" ]]; then
    HELPER=${PS_PYTHON}
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
# An earlier run's reports, which would otherwise be stored with this one's.
rm -f "${PS_BASE}.json" "${PS_BASE}.pip-licenses.json" "${PS_BASE}.csv" "${PS_BASE}.run-record.json" \
    "${PS_OUT}/junit/${REPORT_NAME}.xml"
# clarify is read before pip-licenses runs; the helper names a line it can't
# read.
echo '[]' > "${WORK}/none.json"
if ! ps_py "${HELPER}" licenses "${WORK}/none.json" "" "" "${CLARIFY}" "" > /dev/null; then
    exit 1
fi
PS_REPORTS=()
# shellcheck disable=SC2034 # read by ps_run_record
PS_INPUTS=("environment:${ENVIRONMENT}")
PS_COUNTS=null
# shellcheck disable=SC2034 # read by ps_run_record
PS_TOOL_VERSION=$("${PS_TOOL}" --version 2> /dev/null | awk '{ print $NF; exit }' || true)

# error MESSAGE...: the check has no verdict. Writes the run record, then
# fails the step.
error() {
    printf 'ERROR: %s\n' "$1" >&2
    if [[ $# -gt 1 ]]; then
        printf '  %s\n' "${@:2}" >&2
    fi
    if [[ "${RUN_RECORD}" == true ]]; then
        PS_REPORTS+=("${PS_BASE}.run-record.json")
        ps_run_record "${PS_BASE}.run-record.json" licenses error 1 "${STARTED}"
    fi
    exit 1
}

# What the interpreter sees, listed by itself, to check pip-licenses missed
# nothing.
if ! ps_py "${ENVIRONMENT}" installed > "${WORK}/env.json" 2> "${WORK}/env.log"; then
    ps_tail "${WORK}/env.log" 5
    error "Could not list the packages installed for ${ENVIRONMENT}, which needs Python 3.8 or newer."
fi
# shellcheck disable=SC2034 # read by ps_run_record
PS_TARGET_JSON=$(jq -c '{python: .python, version: .version, packages: (.packages | length)}' "${WORK}/env.json")
PROJECT=""
if [[ -f pyproject.toml ]]; then
    if ! PROJECT=$(ps_py "${HELPER}" project-name . 2> "${WORK}/project.log" | jq -r .name); then
        ps_tail "${WORK}/project.log" 5
        error "Could not read the project's name from pyproject.toml."
    fi
fi

# pip-licenses lists the packages on the interpreter's sys.path, which it asks
# the interpreter for. From an empty directory, without PYTHONPATH or the
# user's site-packages, that is the environment the helper listed.
mkdir -p "${WORK}/empty"
PS_ARGS=("--python=${ENVIRONMENT}" --format=json --from=all --with-system --with-urls)
echo "Running: pip-licenses $(ps_show_command "${PS_ARGS[@]}")"
STATUS=0
(cd "${WORK}/empty" && env -u PYTHONPATH -u PYTHONHOME -u PYTHONSTARTUP PYTHONNOUSERSITE=1 \
    "${PS_TOOL}" "${PS_ARGS[@]}" > "${WORK}/inventory.json" 2> "${WORK}/pip-licenses.log") || STATUS=$?
if [[ "${STATUS}" -ne 0 ]] || ! ps_json_is "${WORK}/inventory.json" 'type == "array" and all(.[]; type == "object" and has("Name") and has("Version"))'; then
    ps_tail "${WORK}/pip-licenses.log" 30
    error "pip-licenses could not list the licenses (exit code ${STATUS}), so there is no verdict."
fi
cp "${WORK}/inventory.json" "${PS_BASE}.pip-licenses.json"
PS_REPORTS+=("${PS_BASE}.pip-licenses.json")
# shellcheck disable=SC2016 # jq program, not shell
MISSING=$(jq -rn --slurpfile env "${WORK}/env.json" --slurpfile inventory "${WORK}/inventory.json" '
    def canon: ascii_downcase | gsub("[-_.]+"; "-");
    ([$inventory[0][] | "\(.Name | canon) \(.Version)"]) as $listed
    | [$env[0].packages[] | "\(.name) \(.version)" | select(IN($listed[]) | not)] | join(", ")')
if [[ -n "${MISSING}" ]]; then
    error "pip-licenses left out packages ${ENVIRONMENT} sees, so their licenses weren't checked: ${MISSING}."
fi

ALLOWED_TEXT=$(IFS=,; echo "${ALLOWED[*]}")
IGNORE_TEXT=$(IFS=,; echo "${IGNORE[*]-}")
if ! ps_py "${HELPER}" licenses "${WORK}/inventory.json" "${ALLOWED_TEXT}" "${IGNORE_TEXT}" "${CLARIFY}" "${PROJECT}" \
    > "${WORK}/licenses.json" 2> "${WORK}/licenses.log"; then
    ps_tail "${WORK}/licenses.log" 5
    error "Could not apply the license policy."
fi

# --- The verdict ---
# A finding is a package whose license isn't allowed, unless ignore lists it
# or it is the project itself and check_project is false.
# shellcheck disable=SC2016 # jq program, not shell
jq --argjson check_project "${CHECK_PROJECT}" --arg python "${ENVIRONMENT}" --arg allowed "${ALLOWED_TEXT}" '
    .packages |= map(. + {checked: ((.project | not) or $check_project)}
        | . + {finding: (.checked and (.allowed | not) and .ignored == null)})
    | {python: $python, allowed_licenses: ($allowed | split(",")), packages, unused_ignores, unused_clarify,
       findings: [.packages[] | select(.finding) | {name, version, license, origin, known}]}' \
    "${WORK}/licenses.json" > "${PS_BASE}.json"
PS_REPORTS+=("${PS_BASE}.json")
count() {
    jq -r "$1" "${PS_BASE}.json"
}
FINDINGS=$(count '.findings | length')
CHECKED=$(count '[.packages[] | select(.checked)] | length')
# shellcheck disable=SC2034 # read by ps_run_record
PS_COUNTS=$(jq -c '{packages: (.packages | length), checked: ([.packages[] | select(.checked)] | length),
    allowed: ([.packages[] | select(.checked and .allowed)] | length), findings: (.findings | length),
    unknown: ([.packages[] | select(.known | not)] | length), ignored: ([.packages[] | select(.ignored != null)] | length),
    unused_ignores: (.unused_ignores | length), unused_clarify: (.unused_clarify | length)}' "${PS_BASE}.json")
jq -r '["name", "version", "license", "origin", "allowed", "ignored"],
    (.packages[] | [.name, .version, .license, .origin, (if .allowed then "yes" else "no" end), (.ignored // "")]) | @csv' \
    "${PS_BASE}.json" > "${PS_BASE}.csv"
PS_REPORTS+=("${PS_BASE}.csv")
if [[ "${JUNIT}" == true ]]; then
    # shellcheck disable=SC2016 # jq program, not shell
    ps_junit "${PS_OUT}/junit/${REPORT_NAME}.xml" "pip-licenses" "$(jq -c '
        [.packages[] | {classname: "pip-licenses", name: "\(.name) \(.version)",
            status: (if .finding then "failed" elif .ignored != null or (.checked | not) then "skipped" else "passed" end),
            message: (if .finding then "\(.license) is not allowed (from \(.origin))"
                elif .ignored != null then "Ignored (\(.ignored)): \(.license)"
                elif (.checked | not) then "The project itself: \(.license)" else .license end)}]' "${PS_BASE}.json")"
    PS_REPORTS+=("${PS_OUT}/junit/${REPORT_NAME}.xml")
fi

# --- Summary and gate ---
echo "pip-licenses: $(ps_plural "$(count '.packages | length')" package packages) in ${ENVIRONMENT}, $(ps_plural "${CHECKED}" package packages) checked."
count '.packages[] | "  \(.name) \(.version): \(.license)  [\(.origin)]\(if .finding then "  NOT ALLOWED"
    elif .ignored != null then "  ignored" elif (.checked | not) then "  the project, not checked" else "" end)"'
if [[ "$(count '.unused_ignores | length')" -gt 0 ]]; then
    echo "WARN: ignore lists packages that aren't installed: $(count '.unused_ignores | join(", ")')." >&2
fi
if [[ "$(count '.unused_clarify | length')" -gt 0 ]]; then
    echo "WARN: clarify names packages that aren't installed: $(count '.unused_clarify | join(", ")')." >&2
fi
if [[ "$(count '[.findings[] | select(.known | not)] | length')" -gt 0 ]]; then
    echo "A license the metadata doesn't name exactly ($(count '[.findings[] | select(.known | not) | .name] | join(", ")'))"
    echo "can be given in clarify, one name[==version]=EXPRESSION per line, such as idna==2.7=BSD-3-Clause."
fi
if [[ "${CHECKED}" -eq 0 && "${ALLOW_EMPTY}" != true ]]; then
    error "${ENVIRONMENT} has no packages to check, so the check checked nothing." \
        "Install the project's dependencies first, name another environment, or set allow_empty to true."
fi
OUTCOME=passed
GATE=false
if [[ "${FINDINGS}" -gt 0 ]]; then
    GATE=true
    OUTCOME=findings
    if [[ "${REPORT_ONLY}" == true ]]; then
        OUTCOME=findings-reported
    fi
fi
if [[ "${RUN_RECORD}" == true ]]; then
    PS_REPORTS+=("${PS_BASE}.run-record.json")
    ps_run_record "${PS_BASE}.run-record.json" licenses "${OUTCOME}" 0 "${STARTED}"
fi
if [[ "${FINDINGS}" -gt 0 ]]; then
    SUMMARY="$(ps_plural "${FINDINGS}" "package has a license" "packages have a license") that isn't allowed: $(count '[.findings[] | "\(.name) (\(.license))"] | join(", ")')."
else
    SUMMARY="every package checked has an allowed license."
fi
ps_gate "${GATE}" "${REPORT_ONLY}" "${SUMMARY}"
