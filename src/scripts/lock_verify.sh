#!/bin/bash
#
# Checks that a project's lockfiles pin what gets installed, for the
# lock_verify command. Each lockfile (uv.lock, poetry.lock, pdm.lock,
# Pipfile.lock, pylock.toml) or requirements file is read with the orb's
# Python helper, which reports every package that isn't pinned to one version
# and hashed (with SHA-256 or stronger), every git source without a full
# commit hash, every local path outside the lockfile's directory, plain http
# indexes, --trusted-host, indexes outside allowed_indexes, and, with
# min_release_age_days, releases uploaded too recently.
#
# Then each lockfile is checked against its pyproject.toml with its package
# manager, when that is on the PATH: uv lock --check, poetry check --lock,
# pdm lock --check and pipenv verify. A stale lockfile installs something
# other than what pyproject.toml asks for. The managers' exit codes don't
# tell a stale lockfile from a failure, so their messages decide. And with
# environment, every installed file is checked against the hash its RECORD
# lists.
#
# Findings fail the step unless report_only is true. These always fail it: a
# lockfile that can't be read, a package manager that can't complete its
# check (or is missing with freshness: require), and a check of nothing
# (unless allow_empty).

set -euo pipefail

if [[ -z "${SCRIPT_PYTHON_SECURITY_LIB:-}" || -z "${SCRIPT_PYTHON_SECURITY_PY:-}" ]]; then
    echo "ERROR: SCRIPT_PYTHON_SECURITY_LIB and SCRIPT_PYTHON_SECURITY_PY must be set; run this script through the orb's lock_verify command." >&2
    exit 1
fi
eval "${SCRIPT_PYTHON_SECURITY_LIB}"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ps_list lockfiles "${PARAM_LOCKFILES}"
LOCKFILE_PATTERNS=(${PS_LIST[@]+"${PS_LIST[@]}"})
ps_list requirements "${PARAM_REQUIREMENTS}"
REQUIREMENT_PATTERNS=(${PS_LIST[@]+"${PS_LIST[@]}"})
ENVIRONMENT=$(ps_subst "${PARAM_ENVIRONMENT}")
REQUIRE_HASHES=$(ps_bool require_hashes "${PARAM_REQUIRE_HASHES}")
MIN_AGE=$(ps_subst "${PARAM_MIN_RELEASE_AGE_DAYS}")
ps_list allowed_indexes "${PARAM_ALLOWED_INDEXES}"
ALLOWED_INDEXES=(${PS_LIST[@]+"${PS_LIST[@]}"})
ps_list allow_local "${PARAM_ALLOW_LOCAL}"
ALLOW_LOCAL=(${PS_LIST[@]+"${PS_LIST[@]}"})
FRESHNESS=$(ps_subst "${PARAM_FRESHNESS}")
ALLOW_EMPTY=$(ps_bool allow_empty "${PARAM_ALLOW_EMPTY}")
REPORT_NAME=$(ps_subst "${PARAM_REPORT_NAME}")
JUNIT=$(ps_bool junit "${PARAM_JUNIT}")
RUN_RECORD=$(ps_bool run_record "${PARAM_RUN_RECORD}")
REPORT_ONLY=$(ps_bool report_only "${PARAM_REPORT_ONLY}")

# --- Parameters ---
ps_uint min_release_age_days "${MIN_AGE}" 0
MIN_AGE=$((10#${MIN_AGE}))
case "${FRESHNESS}" in
    auto | require | skip) ;;
    *)
        echo "ERROR: freshness must be auto, require or skip, not '${FRESHNESS}'." >&2
        exit 1
        ;;
esac
for index in ${ALLOWED_INDEXES[@]+"${ALLOWED_INDEXES[@]}"}; do
    if ! ps_match "${index}" '^https?://[^[:space:]]+$' || [[ "${index#*://}" == *@* ]]; then
        echo "ERROR: allowed_indexes takes index URLs without credentials, such as https://pypi.org/simple, not '$(ps_url_public "${index}")'." >&2
        exit 1
    fi
done
for name in ${ALLOW_LOCAL[@]+"${ALLOW_LOCAL[@]}"}; do
    if ! ps_match "${name}" '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
        echo "ERROR: allow_local takes package names, not '${name}'." >&2
        exit 1
    fi
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
        echo "  Name what to check with lockfiles, requirements or environment." >&2
        exit 1
    fi
    echo "Checking the lockfiles in $(pwd): ${LOCKFILES[*]}"
fi
ps_require_jq
ps_output "${PARAM_OUTPUT_DIR}" "${REPORT_NAME}"
ps_helper_python

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
# An earlier run's reports, which would otherwise be stored with this one's.
rm -f "${PS_BASE}.json" "${PS_BASE}.sarif" "${PS_BASE}.run-record.json" "${PS_OUT}/junit/${REPORT_NAME}.xml"
PS_REPORTS=()
PS_INPUTS=()
PS_COUNTS=null
# shellcheck disable=SC2034 # read by ps_run_record: lock_verify runs no tool of its own
PS_TOOL=""

# error MESSAGE...: the check has no verdict. Writes the run record, then
# fails the step.
error() {
    printf 'ERROR: %s\n' "$1" >&2
    if [[ $# -gt 1 ]]; then
        printf '  %s\n' "${@:2}" >&2
    fi
    if [[ "${RUN_RECORD}" == true ]]; then
        PS_REPORTS+=("${PS_BASE}.run-record.json")
        ps_run_record "${PS_BASE}.run-record.json" lock_verify error 1 "${STARTED}"
    fi
    exit 1
}

# --- Static checks ---
# shellcheck disable=SC2016 # jq program, not shell
OPTIONS=$(jq -cn --argjson age "${MIN_AGE}" --argjson hashes "${REQUIRE_HASHES}" \
    --argjson indexes "$(jq -cn '$ARGS.positional' --args ${ALLOWED_INDEXES[@]+"${ALLOWED_INDEXES[@]}"})" \
    --argjson local "$(jq -cn '$ARGS.positional' --args ${ALLOW_LOCAL[@]+"${ALLOW_LOCAL[@]}"})" \
    '{min_release_age_days: $age, require_hashes: $hashes, allowed_indexes: $indexes, allow_local: $local}')
mkdir -p "${WORK}/inputs"
n=0
for file in ${LOCKFILES[@]+"${LOCKFILES[@]}"} ${REQUIREMENTS[@]+"${REQUIREMENTS[@]}"}; do
    n=$((n + 1))
    kind=lock
    if [[ " ${REQUIREMENTS[*]-} " == *" ${file} "* && " ${LOCKFILES[*]-} " != *" ${file} "* ]]; then
        kind=requirements
    fi
    if ! ps_py "${PS_PYTHON}" read-lock "${file}" "${kind}" > "${WORK}/inputs/${n}.lock.json" 2> "${WORK}/read.log"; then
        ps_tail "${WORK}/read.log" 5
        error "Could not read ${file}."
    fi
    PS_INPUTS+=("$(jq -r .kind "${WORK}/inputs/${n}.lock.json"):${file}")
    if ! ps_py "${PS_PYTHON}" lock-findings "${WORK}/inputs/${n}.lock.json" "${OPTIONS}" > "${WORK}/inputs/${n}.findings.json" 2> "${WORK}/read.log"; then
        ps_tail "${WORK}/read.log" 5
        error "Could not check ${file}."
    fi
    # Each finding with its line, for SARIF: the package's entry, or the
    # index's first mention.
    while IFS= read -r finding; do
        line=$(jq -r '.line // empty' <<< "${finding}")
        if [[ -z "${line}" ]]; then
            target=$(jq -r '.lockfile' <<< "${finding}")
            package=$(jq -r '.package // empty' <<< "${finding}")
            if [[ -n "${package}" ]]; then
                line=$(ps_lock_line "${target}" "${package}")
            else
                index=$(jq -r '.index // empty' <<< "${finding}")
                if [[ -n "${index}" ]]; then
                    line=$(grep -nF -- "${index}" "${target}" 2> /dev/null | head -n 1 | cut -d: -f1 || true)
                fi
            fi
        fi
        jq -c --argjson line "${line:-1}" '. + {line: $line}' <<< "${finding}"
    done < <(jq -c '.findings[]' "${WORK}/inputs/${n}.findings.json") | jq -s . > "${WORK}/inputs/${n}.located.json"
done

# --- Freshness ---
# manager KIND: the package manager that wrote a lockfile of KIND.
manager() {
    case "$1" in
        uv.lock) echo uv ;;
        poetry.lock) echo poetry ;;
        pdm.lock) echo pdm ;;
        Pipfile.lock) echo pipenv ;;
    esac
}
FRESH_ERRORS=()
for ((i = 1; i <= n; i++)); do
    file=$(jq -r .path "${WORK}/inputs/${i}.lock.json")
    tool=$(manager "$(jq -r .kind "${WORK}/inputs/${i}.lock.json")")
    status=none
    message=""
    version=""
    manifest=pyproject.toml
    if [[ "${tool}" == pipenv ]]; then
        manifest=Pipfile
    fi
    if [[ -n "${tool}" && "${FRESHNESS}" == skip ]]; then
        status=skipped
    elif [[ -n "${tool}" ]] && { ! command -v "${tool}" > /dev/null 2>&1 || [[ ! -f "$(dirname "${file}")/${manifest}" ]]; }; then
        status=not-checked
        message="${tool} is not on the PATH"
        if [[ ! -f "$(dirname "${file}")/${manifest}" ]]; then
            message="there is no ${manifest} next to it"
        fi
        if [[ "${FRESHNESS}" == require ]]; then
            FRESH_ERRORS+=("${file}: ${message}, and freshness is require.")
        fi
    elif [[ -n "${tool}" ]]; then
        version=$("${tool}" --version 2> /dev/null | head -n 1 || true)
        dir=$(dirname "${file}")
        code=0
        case "${tool}" in
            uv) (cd "${dir}" && env -u UV_FROZEN -u UV_LOCKED uv lock --check) > "${WORK}/fresh.log" 2>&1 || code=$? ;;
            poetry) (cd "${dir}" && poetry check --lock --no-interaction) > "${WORK}/fresh.log" 2>&1 || code=$? ;;
            # pdm says whether the lockfile is up to date only with -v.
            pdm) (cd "${dir}" && pdm lock --check -v) > "${WORK}/fresh.log" 2>&1 || code=$? ;;
            pipenv) (cd "${dir}" && env -u PIPENV_PIPFILE pipenv verify) > "${WORK}/fresh.log" 2>&1 || code=$? ;;
        esac
        # Poetry 1.6 to 1.8 say "not consistent", 1.x before and 2.x
        # "changed significantly".
        stale_re='needs to be updated|changed significantly since poetry.lock|poetry.lock is not consistent with pyproject.toml|Lockfile is out of date|Pipfile.lock is out-of-date'
        if grep -qE "${stale_re}" "${WORK}/fresh.log"; then
            status=stale
            message=$(grep -m 1 -E "${stale_re}" "${WORK}/fresh.log" | sed -e 's/^[^A-Za-z]*//' -e 's/^error: //' -e 's/^Error: //')
        elif [[ "${code}" -eq 0 ]]; then
            status=fresh
        else
            status=error
            message="${tool} could not check it (exit code ${code})"
            ps_tail "${WORK}/fresh.log" 15
            FRESH_ERRORS+=("${file}: ${message}; its output is above.")
        fi
    fi
    jq -n --arg tool "${tool}" --arg version "${version}" --arg status "${status}" --arg message "${message}" \
        '{manager: (if $tool == "" then null else $tool end), manager_version: (if $version == "" then null else $version end),
          status: $status, message: (if $message == "" then null else $message end)}' > "${WORK}/inputs/${i}.fresh.json"
done

# --- Installed files ---
ENV_JSON=null
if [[ -n "${ENVIRONMENT}" ]]; then
    PS_INPUTS+=("environment:${ENVIRONMENT}")
    # The environment's interpreter only names its site-packages, with -S so
    # that no .pth file in them runs: the files are hashed by the helper's
    # Python, so code in the environment can't change what the check sees.
    if ! "${ENVIRONMENT}" -I -S -c "${SCRIPT_PYTHON_SECURITY_PY}" site-dirs > "${WORK}/site.json" 2> "${WORK}/env.log"; then
        ps_tail "${WORK}/env.log" 5
        error "Could not find the site-packages of ${ENVIRONMENT}, which needs Python 3.8 or newer."
    fi
    SITE_ARGS=()
    while IFS= read -r directory; do
        SITE_ARGS+=(--path "${directory}")
    done < <(jq -r '.site[]' "${WORK}/site.json")
    if [[ ${#SITE_ARGS[@]} -eq 0 ]]; then
        error "${ENVIRONMENT} has no site-packages directory to check."
    fi
    if ! ps_py "${PS_PYTHON}" installed --record "${SITE_ARGS[@]}" > "${WORK}/env.json" 2> "${WORK}/env.log"; then
        ps_tail "${WORK}/env.log" 5
        error "Could not check the files installed for ${ENVIRONMENT}."
    fi
    # shellcheck disable=SC2016 # jq program, not shell
    ENV_JSON=$(jq -c --slurpfile site "${WORK}/site.json" --arg python "${ENVIRONMENT}" '{python: $python,
        version: $site[0].version, site: $site[0].site, packages: (.packages | length),
        files: ([.packages[].files // 0] | add // 0),
        findings: [.findings[] | . + {lockfile: null, kind: "record-\(.kind)"}], warnings}' "${WORK}/env.json")
    # shellcheck disable=SC2034 # read by ps_run_record
    PS_TARGET_JSON=$(jq -c '{python, version, packages}' <<< "${ENV_JSON}")
fi

# --- The verdict ---
# shellcheck disable=SC2016 # jq program, not shell
jq -n --argjson environment "${ENV_JSON}" --slurpfile locks <(for ((i = 1; i <= n; i++)); do
        jq -c --slurpfile f "${WORK}/inputs/${i}.findings.json" --slurpfile l "${WORK}/inputs/${i}.located.json" \
            --slurpfile fresh "${WORK}/inputs/${i}.fresh.json" \
            '{path, kind, lock_version, packages: (.packages | length), findings: $l[0], warnings: $f[0].warnings, freshness: $fresh[0]}' \
            "${WORK}/inputs/${i}.lock.json"
    done) '
    ($locks | map(. + {findings: (.findings + (if .freshness.status == "stale" then [{kind: "stale", lockfile: .path, line: 1,
        message: "\(.path) is out of date with its pyproject.toml: \(.freshness.message)"}] else [] end))})) as $locks
    | {inputs: $locks, environment: $environment,
       findings: ([$locks[].findings[]] + ($environment.findings // [])),
       warnings: ([$locks[].warnings[]] + ($environment.warnings // []))}' > "${PS_BASE}.json"
PS_REPORTS+=("${PS_BASE}.json")
count() {
    jq -r "$1" "${PS_BASE}.json"
}
FINDINGS=$(count '.findings | length')
PACKAGES=$(count '([.inputs[].packages] | add // 0) + (.environment.packages // 0)')
# shellcheck disable=SC2034 # read by ps_run_record
PS_COUNTS=$(jq -c '{inputs: (.inputs | length), packages: ([.inputs[].packages] | add // 0), findings: (.findings | length),
    by_kind: (.findings | group_by(.kind) | map({key: .[0].kind, value: length}) | from_entries),
    stale: ([.inputs[] | select(.freshness.status == "stale")] | length),
    fresh: ([.inputs[] | select(.freshness.status == "fresh")] | length),
    not_checked: ([.inputs[] | select(.freshness.status == "not-checked")] | length),
    installed_packages: (.environment.packages // null), installed_files: (.environment.files // null)}' "${PS_BASE}.json")
# shellcheck disable=SC2034 # read by ps_run_record
PS_RESULTS=$(jq -c '[.inputs[] | {path, kind, packages, findings: (.findings | length), freshness}]' "${PS_BASE}.json")

# SARIF: one rule per kind of finding, each result at its lockfile's line.
# Installed files are outside the checkout, so they are only in the JSON and
# JUnit reports.
# shellcheck disable=SC2016 # jq program, not shell
jq '{
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{
        tool: {driver: {name: "python-security-orb lock_verify", informationUri: "https://github.com/juburr/python-security-orb",
            rules: [.findings[] | select(.lockfile) | .kind] | unique | map({id: ., name: .,
                shortDescription: {text: ({
                    "unpinned": "A requirement not pinned to one version",
                    "unhashed": "A package installed without a hash to check it against",
                    "weak-hash": "A package hashed only with a weak algorithm",
                    "unpinned-vcs": "A version control source without a full commit hash",
                    "local-source": "A local path outside the lockfile'"'"'s directory",
                    "unknown-source": "A source this check can'"'"'t verify",
                    "too-new": "A release uploaded more recently than min_release_age_days",
                    "insecure-index": "A plain http package index",
                    "index-not-allowed": "A package index outside allowed_indexes",
                    "trusted-host": "--trusted-host, which turns off TLS verification",
                    "stale": "A lockfile out of date with its pyproject.toml"}[.] // .)},
                properties: {tags: ["security", "supply-chain"]}})}},
        results: [.findings[] | select(.lockfile) | {ruleId: .kind, level: "error", message: {text: .message},
            locations: [{physicalLocation: {artifactLocation: {uri: (.lockfile | sub("^\\./"; ""))}, region: {startLine: (.line // 1)}}}],
            partialFingerprints: {primaryLocationLineHash: "\(.kind):\(.package // .message)"}}]
    }]}' "${PS_BASE}.json" > "${PS_BASE}.sarif"
PS_REPORTS+=("${PS_BASE}.sarif")
if [[ "${JUNIT}" == true ]]; then
    # shellcheck disable=SC2016 # jq program, not shell
    ps_junit "${PS_OUT}/junit/${REPORT_NAME}.xml" "lock_verify" "$(jq -c '
        [(.inputs[] | {classname: "lock_verify", name: .path, status: (if (.findings | length) > 0 then "failed" else "passed" end),
            message: "\(.findings | length) findings in \(.packages) packages", detail: ([.findings[].message] | join("\n"))}),
         (.inputs[] | select(.freshness.status == "not-checked" or .freshness.status == "skipped")
            | {classname: "lock_verify", name: "\(.path) freshness", status: "skipped", message: (.freshness.message // "freshness: skip")}),
         (.environment // empty | {classname: "lock_verify", name: "installed files (\(.python))",
            status: (if (.findings | length) > 0 then "failed" else "passed" end),
            message: "\(.findings | length) of \(.files) files don'"'"'t match their RECORD", detail: ([.findings[].message] | join("\n"))})]' "${PS_BASE}.json")"
    PS_REPORTS+=("${PS_OUT}/junit/${REPORT_NAME}.xml")
fi

# --- Summary and gate ---
# shellcheck disable=SC2016 # jq program, not shell
count 'def n($count; $word): "\($count) \($word)\(if $count == 1 then "" else "s" end)";
    .inputs[] | "\(.path) (\(.kind)\(if .lock_version then " " + .lock_version else "" end)): \(n(.packages; "package")), \(n(.findings | length; "finding"))\(
    {"fresh": ", up to date (\(.freshness.manager_version // .freshness.manager))", "stale": ", OUT OF DATE",
     "not-checked": ", freshness not checked: \(.freshness.message)", "skipped": ", freshness not checked (freshness: skip)",
     "error": ", freshness unknown"}[.freshness.status] // "")"'
if [[ "${ENV_JSON}" != null ]]; then
    count '.environment | "\(.python): \(.files) installed files of \(.packages) package\(if .packages == 1 then "" else "s" end) checked against their RECORD, \(.findings | length) not matching"'
fi
if [[ "${FINDINGS}" -gt 0 ]]; then
    echo "Findings:"
    count '.findings[] | "  \(if .lockfile then "\(.lockfile):\(.line // 1): " else "" end)\(.kind): \(.message)"'
fi
count '.warnings[] | "WARN: \(.)"' >&2
if [[ ${#FRESH_ERRORS[@]} -gt 0 ]]; then
    error "Whether $(ps_plural "${#FRESH_ERRORS[@]}" "lockfile is" "lockfiles are") up to date is unknown, so there is no verdict:" \
        "${FRESH_ERRORS[@]}" "Set freshness to skip to check the lockfiles without their package managers."
fi
if [[ "${PACKAGES}" -eq 0 && "${ALLOW_EMPTY}" != true ]]; then
    error "There were no packages to check, so the check checked nothing." \
        "Check lockfiles, requirements and environment, or set allow_empty to true."
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
    ps_run_record "${PS_BASE}.run-record.json" lock_verify "${OUTCOME}" 0 "${STARTED}"
fi
if [[ "${FINDINGS}" -gt 0 ]]; then
    SUMMARY="lock_verify found $(ps_plural "${FINDINGS}" problem problems): $(count '.findings | group_by(.kind) | map("\(length) \(.[0].kind)") | join(", ")')."
else
    SUMMARY="every package is pinned and hashed$(if [[ "$(count '[.inputs[] | select(.freshness.status == "fresh")] | length')" -gt 0 ]]; then echo ", and the lockfiles checked are up to date"; fi)."
fi
ps_gate "${GATE}" "${REPORT_ONLY}" "${SUMMARY}"
