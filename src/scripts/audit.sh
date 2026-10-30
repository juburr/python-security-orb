#!/bin/bash
#
# Audits a project's locked dependencies for known vulnerabilities with
# pip-audit, for the audit command. Each lockfile (uv.lock, poetry.lock,
# pdm.lock, Pipfile.lock, pylock.toml), pinned requirements file, or
# installed environment is read with the orb's Python helper, and every
# package pinned to a version goes into one minimal pylock.toml, which
# pip-audit audits with --locked: no resolution, no index and no build code,
# and every locked version whatever its markers, not only the ones this
# Python would install.
#
# pip-audit exits 1 for vulnerabilities and for every failure alike, so the
# verdict comes from its JSON report, which it writes only when the audit
# completed. Findings (vulnerabilities not in ignore) fail the step unless
# report_only is true. These always fail it: an audit that didn't complete,
# a package that couldn't be audited and isn't in allow_skipped, and an
# audit of nothing (unless allow_empty).

set -euo pipefail

if [[ -z "${SCRIPT_PYTHON_SECURITY_LIB:-}" || -z "${SCRIPT_PYTHON_SECURITY_PY:-}" ]]; then
    echo "ERROR: SCRIPT_PYTHON_SECURITY_LIB and SCRIPT_PYTHON_SECURITY_PY must be set; run this script through the orb's audit command." >&2
    exit 1
fi
eval "${SCRIPT_PYTHON_SECURITY_LIB}"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ps_list lockfiles "${PARAM_LOCKFILES}"
LOCKFILE_PATTERNS=(${PS_LIST[@]+"${PS_LIST[@]}"})
ps_list requirements "${PARAM_REQUIREMENTS}"
REQUIREMENT_PATTERNS=(${PS_LIST[@]+"${PS_LIST[@]}"})
ENVIRONMENT=$(ps_subst "${PARAM_ENVIRONMENT}")
SERVICE=$(ps_subst "${PARAM_SERVICE}")
OSV_URL=$(ps_subst "${PARAM_OSV_URL}")
TIMEOUT=$(ps_subst "${PARAM_TIMEOUT}")
ps_list ignore "${PARAM_IGNORE}"
IGNORE=(${PS_LIST[@]+"${PS_LIST[@]}"})
UNUSED_IGNORES=$(ps_subst "${PARAM_UNUSED_IGNORES}")
ps_list allow_skipped "${PARAM_ALLOW_SKIPPED}"
ALLOW_SKIPPED=(${PS_LIST[@]+"${PS_LIST[@]}"})
ALLOW_EMPTY=$(ps_bool allow_empty "${PARAM_ALLOW_EMPTY}")
REPORT_NAME=$(ps_subst "${PARAM_REPORT_NAME}")
JUNIT=$(ps_bool junit "${PARAM_JUNIT}")
RUN_RECORD=$(ps_bool run_record "${PARAM_RUN_RECORD}")
REPORT_ONLY=$(ps_bool report_only "${PARAM_REPORT_ONLY}")
ps_words extra_args "$(ps_subst "${PARAM_EXTRA_ARGS}")"
EXTRA_ARGS=(${PS_WORDS[@]+"${PS_WORDS[@]}"})

# --- Parameters ---
case "${SERVICE}" in
    pypi | osv) ;;
    *)
        echo "ERROR: service must be pypi or osv, not '${SERVICE}'." >&2
        exit 1
        ;;
esac
if [[ -n "${OSV_URL}" ]]; then
    if [[ "${SERVICE}" != osv ]]; then
        echo "ERROR: osv_url names an OSV API, so it needs service: osv." >&2
        exit 1
    fi
    if [[ "${OSV_URL#*://}" == *@* || "${OSV_URL}" == *[?#]* ]] || ! ps_match "${OSV_URL}" '^https://[^[:space:]]+$'; then
        echo "ERROR: osv_url must be an https:// URL without credentials, a query or a fragment, not '$(ps_url_public "${OSV_URL}")'." >&2
        exit 1
    fi
fi
ps_uint timeout "${TIMEOUT}" 1
TIMEOUT=$((10#${TIMEOUT}))
case "${UNUSED_IGNORES}" in
    allow | warn | deny) ;;
    *)
        echo "ERROR: unused_ignores must be allow, warn or deny, not '${UNUSED_IGNORES}'." >&2
        exit 1
        ;;
esac
for id in ${IGNORE[@]+"${IGNORE[@]}"}; do
    if ! ps_match "${id}" '^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9:._-]+$'; then
        echo "ERROR: ignore takes vulnerability IDs, such as PYSEC-2018-28, GHSA-x84v-xcm2-53pg or CVE-2018-18074, not '${id}'." >&2
        exit 1
    fi
done
# Options the command sets itself, which would change what is audited or how
# the report is read. A word after an option that takes a value is its value.
value_next=false
for word in ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}; do
    if [[ "${value_next}" == true ]]; then
        value_next=false
        continue
    fi
    if [[ "${word}" == --cache-dir ]]; then
        value_next=true
        continue
    fi
    case "${word%%=*}" in
        -f | --format | -o | --output | -s | --vulnerability-service | --osv-url | --ignore-vuln | -r | --requirement \
            | --locked | --path | -l | --local | --fix | --dry-run | -S | --strict | --desc | --aliases \
            | --progress-spinner | --timeout | --disable-pip | --no-deps | --require-hashes | --index-url \
            | --extra-index-url | --skip-editable | --)
            echo "ERROR: extra_args can't hold ${word%%=*}: the audit command sets it, or it would change what is audited." >&2
            exit 1
            ;;
        -*) ;;
        *)
            echo "ERROR: extra_args can't hold '${word}': pip-audit would read it as a project to audit." >&2
            exit 1
            ;;
    esac
done
if [[ -n "${ENVIRONMENT}" ]]; then
    ps_environment "${ENVIRONMENT}"
    ENVIRONMENT=${PS_ENVIRONMENT}
fi

# --- Inputs ---
PS_LIST=(${LOCKFILE_PATTERNS[@]+"${LOCKFILE_PATTERNS[@]}"})
ps_files lockfiles
LOCKFILES=(${PS_FILES[@]+"${PS_FILES[@]}"})
PS_LIST=(${REQUIREMENT_PATTERNS[@]+"${REQUIREMENT_PATTERNS[@]}"})
ps_files requirements
REQUIREMENTS=(${PS_FILES[@]+"${PS_FILES[@]}"})
if [[ ${#LOCKFILES[@]} -eq 0 && ${#REQUIREMENTS[@]} -eq 0 && -z "${ENVIRONMENT}" ]]; then
    # Every lockfile in the working directory, when nothing is named.
    for file in uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml pylock.*.toml; do
        if [[ -f "${file}" ]]; then
            LOCKFILES+=("${file}")
        fi
    done
    if [[ ${#LOCKFILES[@]} -eq 0 ]]; then
        echo "ERROR: There is no lockfile in $(pwd) (uv.lock, poetry.lock, pdm.lock, Pipfile.lock or pylock.toml)." >&2
        echo "  Name what to audit with lockfiles, requirements (pinned requirements files) or environment." >&2
        exit 1
    fi
    echo "Auditing the lockfiles in $(pwd): ${LOCKFILES[*]}"
fi
ps_require_jq
ps_output "${PARAM_OUTPUT_DIR}" "${REPORT_NAME}"
ps_tool pip-audit
ps_helper_python
# The helper reads TOML with the tool's own Python when the orb installed it:
# its environment has tomli on Python 3.10.
HELPER=${PS_TOOL_PYTHON:-${PS_PYTHON}}
if [[ ! -x "${HELPER}" ]]; then
    HELPER=${PS_PYTHON}
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
# An earlier run's reports, which would otherwise be stored with this one's.
rm -f "${PS_BASE}.json" "${PS_BASE}.pip-audit.json" "${PS_BASE}.sarif" "${PS_BASE}.run-record.json" \
    "${PS_OUT}/junit/${REPORT_NAME}.xml"
PS_REPORTS=()
PS_INPUTS=()
PS_COUNTS=null
PS_TOOL_VERSION=$("${PS_TOOL}" --version 2> /dev/null | awk '{ print $NF; exit }' || true)

# error MESSAGE...: the audit has no verdict. Writes the run record, then
# fails the step.
error() {
    printf 'ERROR: %s\n' "$1" >&2
    if [[ $# -gt 1 ]]; then
        printf '  %s\n' "${@:2}" >&2
    fi
    if [[ "${RUN_RECORD}" == true ]]; then
        PS_REPORTS+=("${PS_BASE}.run-record.json")
        ps_run_record "${PS_BASE}.run-record.json" audit error 1 "${STARTED}"
    fi
    exit 1
}

# Each input, normalized: WORK/inputs/N.json.
mkdir -p "${WORK}/inputs"
n=0
for file in ${LOCKFILES[@]+"${LOCKFILES[@]}"} ${REQUIREMENTS[@]+"${REQUIREMENTS[@]}"}; do
    n=$((n + 1))
    kind=lock
    if [[ " ${REQUIREMENTS[*]-} " == *" ${file} "* && " ${LOCKFILES[*]-} " != *" ${file} "* ]]; then
        kind=requirements
    fi
    if ! ps_py "${HELPER}" read-lock "${file}" "${kind}" > "${WORK}/inputs/${n}.json" 2> "${WORK}/read.log"; then
        ps_tail "${WORK}/read.log" 5
        error "Could not read ${file}."
    fi
    PS_INPUTS+=("$(jq -r .kind "${WORK}/inputs/${n}.json"):${file}")
done
if [[ -n "${ENVIRONMENT}" ]]; then
    n=$((n + 1))
    # The interpreter lists its own distributions, so the environment needs
    # no pip, as uv's environments have none.
    if ! ps_py "${ENVIRONMENT}" installed > "${WORK}/env.json" 2> "${WORK}/read.log"; then
        ps_tail "${WORK}/read.log" 5
        error "Could not list the packages installed for ${ENVIRONMENT}."
    fi
    jq -c --arg path "${ENVIRONMENT}" '{path: $path, kind: "environment", lock_version: null, indexes: [], options: [],
        packages: [.packages[] | {name, version, source: "registry", line: null}]}' "${WORK}/env.json" > "${WORK}/inputs/${n}.json"
    PS_INPUTS+=("environment:${ENVIRONMENT}")
    # shellcheck disable=SC2034 # read by ps_run_record
    PS_TARGET_JSON=$(jq -c '{python: .python, version: .version, packages: (.packages | length)}' "${WORK}/env.json")
fi

# Every package with a version from a package index is audited, once. Local
# packages (the project itself, path dependencies) can't be; git, URL and
# unpinned ones aren't, since PyPI's advisories for a name and version may
# not describe them.
jq -s '[.[] as $input | $input.packages[] | . + {input: $input.path, kind: $input.kind}]' "${WORK}"/inputs/*.json > "${WORK}/entries.json"
jq '[.[] | select(.source == "registry" and .version != null)]' "${WORK}/entries.json" > "${WORK}/audited.json"
# shellcheck disable=SC2016 # jq program, not shell
jq '[.[] | select(.source != "registry" or .version == null)
    | {name, version, input, local: (.source | IN("editable", "virtual", "directory", "path")),
       reason: (if .source == "registry" then "not pinned to one version (\(.specifier // "no version"))"
                else "a \(.source) source (\(.location // "")), which advisories by name and version may not describe" end)}]
    | unique_by([.name, .version, .input])' "${WORK}/entries.json" > "${WORK}/not_audited.json"
AUDITED=$(jq '[.[] | [.name, .version]] | unique | length' "${WORK}/audited.json")

mkdir -p "${WORK}/lock"
REPORT="${WORK}/report.json"
STATUS=0
PS_ARGS=()
if [[ "${AUDITED}" -gt 0 ]]; then
    ps_py "${HELPER}" pylock "${WORK}/audited.json" "${WORK}/lock/pylock.toml" > /dev/null
    PS_ARGS=(--locked "${WORK}/lock" --format json --output "${REPORT}" --desc on --aliases on --progress-spinner off
        --vulnerability-service "${SERVICE}" --timeout "${TIMEOUT}")
    if [[ -n "${OSV_URL}" ]]; then
        PS_ARGS+=(--osv-url "${OSV_URL}")
    fi
    PS_ARGS+=(${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})
    echo "Running: pip-audit $(ps_show_command "${PS_ARGS[@]}")"
    echo "Auditing $(ps_plural "${AUDITED}" package packages) with the ${SERVICE} service."
    # pip-audit reads these, and pip-api reads PIPAPI_PYTHON_LOCATION.
    env -u PIP_AUDIT_FORMAT -u PIP_AUDIT_OUTPUT -u PIP_AUDIT_VULNERABILITY_SERVICE -u PIP_AUDIT_DESC \
        -u PIP_AUDIT_ALIASES -u PIP_AUDIT_PROGRESS_SPINNER -u PIP_AUDIT_OSV_URL -u PIPAPI_PYTHON_LOCATION \
        "${PS_TOOL}" "${PS_ARGS[@]}" > "${WORK}/pip-audit.log" 2>&1 || STATUS=$?
    sed 's/^/  /' "${WORK}/pip-audit.log"
    if [[ "${STATUS}" -ne 0 && "${STATUS}" -ne 1 ]] \
        || ! ps_json_is "${REPORT}" '(.dependencies | type) == "array" and (.fixes | type) == "array"'; then
        error "pip-audit could not complete the audit (exit code ${STATUS}), so there is no verdict. Its log is above." \
            "pip-audit exits 1 for vulnerabilities and for failures alike, and writes its report only when it completes."
    fi
    VULNS=$(jq '[.dependencies[].vulns[]?] | length' "${REPORT}")
    if [[ "${STATUS}" -eq 1 && "${VULNS}" -eq 0 ]] || [[ "${STATUS}" -eq 0 && "${VULNS}" -gt 0 ]]; then
        error "pip-audit exited with ${STATUS}, but its report lists $(ps_plural "${VULNS}" vulnerability vulnerabilities), so there is no verdict."
    fi
    cp "${REPORT}" "${PS_BASE}.pip-audit.json"
    PS_REPORTS+=("${PS_BASE}.pip-audit.json")
else
    echo '{"dependencies": [], "fixes": []}' > "${REPORT}"
fi

# --- The verdict ---
# Each audited package with its vulnerabilities, which an ignore entry
# matches by ID or alias, and the inputs it came from.
IGNORE_JSON=$(jq -cn '$ARGS.positional' --args ${IGNORE[@]+"${IGNORE[@]}"})
ALLOW_JSON=$(jq -cn '[$ARGS.positional[] | ascii_downcase | gsub("[-_.]+"; "-")]' --args ${ALLOW_SKIPPED[@]+"${ALLOW_SKIPPED[@]}"})
# shellcheck disable=SC2016 # jq program, not shell
jq -n --slurpfile report "${REPORT}" --slurpfile audited "${WORK}/audited.json" --slurpfile not_audited "${WORK}/not_audited.json" \
    --argjson ignore "${IGNORE_JSON}" --argjson allow "${ALLOW_JSON}" --arg service "${SERVICE}" '
    def canon: ascii_downcase | gsub("[-_.]+"; "-");
    ($report[0].dependencies) as $deps
    | ($audited[0] | group_by([.name, .version]) | map({key: "\(.[0].name)==\(.[0].version)", value: [.[].input] | unique}) | from_entries) as $inputs
    | [$deps[] | select(.vulns) | {name: (.name | canon), version, inputs: ($inputs["\(.name | canon)==\(.version)"] // []),
        vulns: [.vulns[] | . as $v | ([$ignore[] | . as $i | select(any(([$v.id] + ($v.aliases // []))[]; . == $i))] | first) as $hit
            | $v + {ignored: ($hit != null), ignore_entry: $hit}]}] as $packages
    | ([$deps[] | select(.skip_reason) | {name: (.name | canon), version: null, reason: .skip_reason, input: null, local: false}]
       + [$not_audited[0][] | select(.local | not)]) as $skips
    | {
        service: $service,
        packages: $packages,
        findings: [$packages[] as $p | $p.vulns[] | select(.ignored | not) | {package: $p.name, version: $p.version,
            id, aliases, fix_versions, description, inputs: $p.inputs}],
        ignored: [$packages[] as $p | $p.vulns[] | select(.ignored) | {package: $p.name, version: $p.version, id, ignore_entry}],
        unused_ignores: [$ignore[] as $i | select([$packages[].vulns[] | select(.ignore_entry == $i)] | length == 0) | $i],
        skipped: [$skips[] | . + {allowed: (.name | IN($allow[]))}],
        local: [$not_audited[0][] | select(.local)]
    }' > "${WORK}/summary.json"

count() {
    jq -r "$1" "${WORK}/summary.json"
}
FINDINGS=$(count '.findings | length')
VULNERABLE=$(count '[.findings[].package] | unique | length')
SKIPPED=$(count '[.skipped[] | select(.allowed | not)] | length')
UNUSED=$(count '.unused_ignores | length')
# shellcheck disable=SC2034 # read by ps_run_record
PS_COUNTS=$(jq -c --argjson audited "${AUDITED}" --argjson inputs "${n}" '{inputs: $inputs, audited: $audited,
    findings: (.findings | length), vulnerable_packages: ([.findings[].package] | unique | length),
    ignored: (.ignored | length), unused_ignores: (.unused_ignores | length),
    skipped: (.skipped | length), skipped_allowed: ([.skipped[] | select(.allowed)] | length), local: (.local | length)}' "${WORK}/summary.json")
jq --slurpfile inputs <(jq -s '[.[] | {path, kind, lock_version, packages: (.packages | length)}]' "${WORK}"/inputs/*.json) \
    '{inputs: $inputs[0]} + .' "${WORK}/summary.json" > "${PS_BASE}.json"
PS_REPORTS+=("${PS_BASE}.json")

# SARIF: one rule per vulnerability, one result per vulnerable package and
# input, at the package's entry in that input.
LOCATIONS="[]"
while IFS=$'\t' read -r package input; do
    [[ -n "${package}" ]] || continue
    line=1
    if [[ -f "${input}" ]]; then
        line=$(ps_lock_line "${input}" "${package}")
    fi
    LOCATIONS=$(jq -c --arg p "${package}" --arg i "${input}" --argjson l "${line}" '. + [{package: $p, input: $i, line: $l}]' <<< "${LOCATIONS}")
done < <(jq -r '.findings[] as $f | $f.inputs[] | [$f.package, .] | @tsv' "${WORK}/summary.json" | sort -u)
# shellcheck disable=SC2016 # jq program, not shell
jq --argjson locations "${LOCATIONS}" --arg version "${PS_TOOL_VERSION}" '{
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{
        tool: {driver: {name: "pip-audit", version: $version, informationUri: "https://github.com/pypa/pip-audit",
            rules: [.findings | unique_by(.id)[] | {id, name: .id,
                shortDescription: {text: ("\(.id): " + (.description // "" | .[0:200]))},
                fullDescription: {text: (.description // .id)},
                helpUri: "https://osv.dev/vulnerability/\(.id)",
                help: {text: "Upgrade to a fixed version: \(if (.fix_versions | length) > 0 then (.fix_versions | join(", ")) else "none is known yet" end)."},
                properties: {tags: (["security", "vulnerability"] + (.aliases // []))}}]}},
        results: [.findings[] as $f | $f.inputs[] as $input
            | ($locations | map(select(.package == $f.package and .input == $input)) | first // {line: 1}) as $loc
            | {ruleId: $f.id, level: "error",
               message: {text: "\($f.package) \($f.version) has \($f.id)\(if ($f.aliases | length) > 0 then " (" + ($f.aliases | join(", ")) + ")" else "" end). Fixed in: \(if ($f.fix_versions | length) > 0 then ($f.fix_versions | join(", ")) else "no release yet" end)."},
               locations: [{physicalLocation: {artifactLocation: {uri: $input}, region: {startLine: $loc.line}}}],
               partialFingerprints: {primaryLocationLineHash: "\($f.id):\($f.package):\($f.version)"}}]
    }]}' "${WORK}/summary.json" > "${PS_BASE}.sarif"
PS_REPORTS+=("${PS_BASE}.sarif")

if [[ "${JUNIT}" == true ]]; then
    # shellcheck disable=SC2016 # jq program, not shell
    ps_junit "${PS_OUT}/junit/${REPORT_NAME}.xml" "pip-audit" "$(jq -c '
        [(.packages[] | {classname: "pip-audit", name: "\(.name) \(.version)",
            status: (if any(.vulns[]; .ignored | not) then "failed" else "passed" end),
            message: ([.vulns[] | select(.ignored | not) | .id] | join(", ")),
            detail: ([.vulns[] | select(.ignored | not) | "\(.id): \(.description // "")"] | join("\n"))}),
         (.skipped[] | {classname: "pip-audit", name: "\(.name) \(.version // "")", status: "skipped", message: .reason})]' "${WORK}/summary.json")"
    PS_REPORTS+=("${PS_OUT}/junit/${REPORT_NAME}.xml")
fi

# --- Summary and gate ---
echo "pip-audit: $(ps_plural "${AUDITED}" package packages) audited, $(ps_plural "${FINDINGS}" vulnerability vulnerabilities) in $(ps_plural "${VULNERABLE}" package packages)."
if [[ "$(count '.ignored | length')" -gt 0 ]]; then
    echo "Ignored: $(count '[.ignored[] | "\(.id) in \(.package) \(.version)"] | join(", ")')."
fi
if [[ "$(count '.local | length')" -gt 0 ]]; then
    echo "Not audited, as local packages: $(count '[.local[] | "\(.name) (\(.input))"] | unique | join(", ")')."
fi
if [[ "${FINDINGS}" -gt 0 ]]; then
    echo "Vulnerabilities:"
    count '.findings[] | "  \(.package) \(.version): \(.id)\(if (.aliases | length) > 0 then " (" + (.aliases | join(", ")) + ")" else "" end), fixed in \(if (.fix_versions | length) > 0 then (.fix_versions | join(", ")) else "no release yet" end)\n    \(.description // "" | .[0:300])"'
fi
if [[ "${UNUSED}" -gt 0 ]]; then
    message="ignore lists $(ps_plural "${UNUSED}" ID IDs) that matched no vulnerability: $(count '.unused_ignores | join(", ")')."
    if [[ "${UNUSED_IGNORES}" == warn ]]; then
        echo "WARN: ${message} Remove them, or set unused_ignores to allow." >&2
    elif [[ "${UNUSED_IGNORES}" == deny ]]; then
        echo "${message}"
    fi
fi
OUTCOME=passed
GATE=false
if [[ "${FINDINGS}" -gt 0 ]] || [[ "${UNUSED}" -gt 0 && "${UNUSED_IGNORES}" == deny ]]; then
    GATE=true
    OUTCOME=findings
    if [[ "${REPORT_ONLY}" == true ]]; then
        OUTCOME=findings-reported
    fi
fi
if [[ "${SKIPPED}" -gt 0 ]]; then
    echo "ERROR: $(ps_plural "${SKIPPED}" package packages) could not be audited, so the audit is incomplete:" >&2
    count '.skipped[] | select(.allowed | not) | "  \(.name) \(.version // ""): \(.reason)"' >&2
    echo "  A private package that no public advisory database knows can be listed in allow_skipped." >&2
    error "The audit has no verdict while a package goes unaudited."
fi
if [[ "${AUDITED}" -eq 0 && "${ALLOW_EMPTY}" != true ]]; then
    error "There were no packages to audit, so the audit checked nothing." \
        "Check lockfiles, requirements and environment, or set allow_empty to true."
fi
if [[ "${RUN_RECORD}" == true ]]; then
    PS_REPORTS+=("${PS_BASE}.run-record.json")
    ps_run_record "${PS_BASE}.run-record.json" audit "${OUTCOME}" 0 "${STARTED}"
fi
ps_gate "${GATE}" "${REPORT_ONLY}" \
    "pip-audit found $(ps_plural "${FINDINGS}" vulnerability vulnerabilities) in $(ps_plural "${VULNERABLE}" package packages)$(if [[ "${UNUSED}" -gt 0 && "${UNUSED_IGNORES}" == deny ]]; then echo ", and ignore lists $(ps_plural "${UNUSED}" ID IDs) that matched none (unused_ignores: deny)"; fi)."
