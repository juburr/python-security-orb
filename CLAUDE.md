# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an unofficial CircleCI orb, and set of GitHub Actions, that checks Python projects for security. It installs uv (checksum-verified), a CPython uv verifies, and pip-audit, Bandit and pip-licenses, each into its own environment from a lock that pins every wheel by SHA-256, and wraps the checks around them: `audit` (pip-audit on lockfiles), `bandit`, `licenses` (pip-licenses with an SPDX policy) and `lock_verify` (lockfile hygiene, freshness and installed files against RECORD). Out of scope: OSV-Scanner (an orb of its own), Safety (needs an account), GuardDog, PEP 740 attestations of dependencies, `uv audit` (preview); the README's "Not Yet Included" says why.

## Development Commands

```bash
# Pack the orb from source into a single file, and validate it
circleci orb pack src/ > orb.yml
circleci orb validate orb.yml

# Lint
yamllint .
shellcheck src/scripts/*.sh src/scripts/lib/*.sh src/install/*.sh src/install/*/*.sh actions/*.sh tests/*.sh

# Tests (offline; commands_test.sh needs jq, python3 3.11+, and jsonschema to check run records)
for t in tests/*_test.sh; do bash "$t" || break; done

# Run one command's script with its YAML defaults (what test-deploy.yml uses for steps that must fail)
bash tests/run_command.sh lock_verify working_dir=tests/fixtures/loose requirements=requirements.txt

# SHA-512 table entries for a new uv release, and a lock for a new tool release
./src/install/uv/install_hash.sh -v <version>
./src/install/lock.sh -t <pip-audit|bandit|pip-licenses> -v <version>
```

## Architecture

### Orb Structure (`src/`)

- `@orb.yml` - Orb metadata (version 2.1)
- `commands/`
  - `install.yml` - Checks `tools` (`scripts/install_tools.sh`), runs `install_uv`, then `install_python`, `install_pip_audit`, `install_bandit` and `install_pip_licenses` with `install_uv: false`, each picked by a `when: condition: matches:` on `tools` (`^(.*[ ,])?<tool>([ ,].*)?$`).
  - `install_uv.yml` - The family's standard install command shape: cache key from `scripts/cache_key.sh`, `restore_cache`, `install/uv/install.sh`, `save_cache`.
  - `install_python.yml`, `install_pip_audit.yml`, `install_bandit.yml`, `install_pip_licenses.yml` - Optionally `install_uv`, then the Python cache key (`scripts/python_cache_key.sh`) and restore, `scripts/install_tool.sh` with `PARAM_TOOL` fixed and `SCRIPT_TOOL_LOCKS: << include(install/<tool>/locks.txt) >>`, and save. They were generated from one template (identical but for the tool); keep them in step.
  - `audit`, `bandit`, `licenses`, `lock_verify` - One script each in `scripts/`.
- `install/uv/install.sh` and `install_hash.sh`, `install/lock.sh`, `install/<tool>/locks.txt` - Kept outside `scripts/`, since `tests/shell_conventions_test.sh` exempts only `src/scripts/install.sh`, `install_hash.sh` and `cache_key.sh` by exact path. orb pack ignores the directory; commands include its files.
- `scripts/lib/python_security.sh` - Shell helpers (`ps_*`), passed to each step as `SCRIPT_PYTHON_SECURITY_LIB` and `eval`ed after a check that it is set. Only defines functions; no `set` line.
- `scripts/lib/python_security.py` - The Python helper, standard library only and Python 3.8 syntax (`tests/wiring_test.sh` checks), passed as `SCRIPT_PYTHON_SECURITY_PY` and run as `python -I -c "${SCRIPT_PYTHON_SECURITY_PY}" COMMAND ...` through `ps_py`, never written to a file.
- `examples/` - Usage examples, pinned to the orb's current version
- `../schemas/run-record.v1.json` - The run record's JSON Schema. Its URL is in every run record, so fields are only ever added within v1.
- `../actions/<command>/action.yml` - The GitHub Action for each command (see below).

### Install

- **uv** (`install/uv/install.sh`): the layout every juburr orb's install.sh shares: a tool definition, the shared install logic (byte-identical across the orbs; never edit it here alone), and the `sha512sums` table keyed `"<version>/<arch>"`, holding the SHA-512 of the `uv` binary in the static musl archive (`uv-<x86_64|aarch64>-unknown-linux-musl.tar.gz`). URLs: GitHub, then `releases.astral.sh`, or `download_base_url` alone. `tests/install_test.sh` runs the shared install contract (`tests/install_contract.sh`, with `tests/install_fixtures/release.sh`). `install_hash.sh` checks the GitHub `.sha256`, and `gh attestation verify --repo astral-sh/uv --signer-workflow astral-sh/uv/.github/workflows/release.yml` when `gh` is installed. The table covers 0.13.0 to 0.13.6.
- **The tools** (`scripts/install_tool.sh`):
  1. **Python**: `uv python install --managed-python` (`python` 3.10 to 3.14) into `~/.python-security-orb/python`, which uv checks against the SHA-256 it carries for each build; or `system`, or an absolute path. It must be CPython 3.10 to 3.14, the range the locks cover. Exports `PYTHON_SECURITY_ORB_PYTHON`.
  2. **The environment**: `uv venv` in a staging directory, then `uv pip install --require-hashes --only-binary :all: --strict` from the tool's lock (the lines between `# >>> TOOL VERSION >>>` and `# <<< TOOL VERSION <<<` in `locks.txt`), smoke-tested (`-m MODULE --version` must report the version), then swapped into `~/.python-security-orb/venvs/<tool>`. `strict` refuses a version without a lock before uv runs; `known_versions` and `false` install `TOOL==VERSION` unverified (`bandit[toml]` for Bandit).
  3. **The shim**: a script in `install_path` (`exec '<venv>/bin/python' -I -m <module> "$@"`), and the install record `.<tool>.install.json` beside it (version, `verified`, the lock's SHA-256, the Python, uv, the index, the packages, the shim's SHA-512), which `ps_tool` checks and the run records include.

  The job's `UV_*` variables are dropped but for an allowlist, uv runs with `UV_NO_CONFIG=1` from a temporary directory, so no `uv.toml`, `[tool.uv]` or job setting changes what is installed. `install_path` takes a leading `~`, as the shared logic does.
- **Locks** (`install/lock.sh -t TOOL -v VERSION [-d DATE]`): `uv pip compile --universal --python-version 3.10 --only-binary :all: --generate-hashes --exclude-newer DATE` (default 7 days ago), then an embedded filter keeps the wheels CPython 3.10 to 3.14 can install on x86_64 and aarch64, glibc and musl, and checks every combination is covered. It checks the tool's own wheel with `pypi-attestations verify pypi` when that is installed. When a tool's default version changes, change it in `install_<tool>.yml` and `install.yml`'s `<tool>_version`; `tests/wiring_test.sh` requires both to be the newest lock, and uv's defaults the newest table entry.

### Command scripts (`src/scripts/`)

Every check takes `working_dir`, `output_dir`, `report_name`, `junit`, `run_record`, `report_only`, `allow_empty` and `store_artifacts`, and first removes the reports an earlier run with the same `report_name` left. The rule every gate follows: findings fail the step unless `report_only` is true; a tool that didn't complete, or a check of nothing (unless `allow_empty`), always fails it. Each script tells them apart from the tool's report, not its exit code.

- **`extra_args`**: `audit` and `bandit` refuse their options also as argparse abbreviations (`ps_abbreviates`), and allow only short options that change neither what is checked nor the report (`-v` for pip-audit; `-v`, `-d`, `-q`, `-n`, `-a` for Bandit).
- **`audit.sh`**: reads each lockfile (`read-lock`, auto-detecting `uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml pylock.*.toml` when nothing is named), requirements file or environment (`installed`, run on the environment's own interpreter), merges every versioned registry package into one minimal pylock.toml (`pylock`), and runs `pip-audit --locked DIR --format json --output R --desc on --aliases on --progress-spinner off --vulnerability-service S --timeout T`, without the job's `PIP_AUDIT_*` and `PIPAPI_PYTHON_LOCATION`. pip-audit exits 1 for vulnerabilities and failures alike and writes its report only when it completes; the report must hold `dependencies` and `fixes`, its vulnerability count must agree with the exit code, and it must name every package pip-audit was given (an option such as `--dry-run` reports none). Versions are matched as pip-audit reports them, by the helper's `version_key` (`pep440()`, packaging's `str(Version(v))`: `v2.19.1` is `2.19.1`, `2018.04.16` is `2018.4.16`), which the pylock.toml uses too, and an ignore entry is used when it names any matching vulnerability's ID or alias. `ignore` matches an ID or any alias. A `skip_reason` (a package PyPI doesn't know) not in `allow_skipped` is no verdict; local packages are listed, not audited. SARIF puts each finding at the package's entry in each lockfile (`ps_lock_line`).
- **`bandit.sh`**: one run with `--ini` naming a file that holds only `[bandit]` (a `.bandit` can set the format; one under the targets is warned about), `--format json --quiet`, `-r --exclude` with Bandit's defaults first (`-x` replaces them; an entry matches as a substring, so `.git` also leaves out `.github`) plus existing `./.venv`, `./venv`, `./.nox`. `low` is passed as `all`. `config`, or `pyproject.toml` with `[tool.bandit]`, goes to `--configfile` (Bandit never reads pyproject.toml by itself). Bandit exits 1 for results and for a crash; `errors[]` (code it couldn't parse, which it skips with exit 0) fails the step with the parser's message from `ast.parse` on the tool's Python; "Bandit internal error running:" in its log too; scanned files are the metrics' keys minus `_totals` and the errors. With `require_suppression_reasons`, a second run with `--ignore-nosec`; the multiset difference by `[filename, test_id, line_number, col_offset]` is what `# nosec` suppressed, and `nosec` (the helper) finds each comment with Bandit's own regex: the reason is the text after a second `#`. SARIF is built with jq (Bandit's own is unreliable): `security-severity` as strings (HIGH 8.0, MEDIUM 5.5, LOW 3.0), CWE tags, suppressions `inSource`.
- **`licenses.sh`**: `pip-licenses --python=<abs> --format=json --from=all --with-system --with-urls` from an empty directory, without `PYTHONPATH` and the user site, so no `[tool.pip-licenses]` applies and it sees what `installed` lists; a package `installed` lists that pip-licenses left out is no verdict. The policy is the helper's `licenses` (never `--allow-only`, which matches strings): clarify, then License-Expression, a License field that reads as an identifier (or `LICENSE_ALIASES`), then classifiers (`CLASSIFIERS`; several must all be allowed; an unmapped one is unknown); SPDX `OR` needs one allowed side, `AND` every part, `WITH` its license. The project `pyproject.toml` names (`project-name`) isn't checked unless `check_project`. `clarify` is checked before pip-licenses runs.
- **`lock_verify.sh`**: `read-lock` and `lock-findings` per input: `unpinned`, `unhashed`, `weak-hash` (with `require_hashes`), `unpinned-vcs` (no full commit), `local-source` (a path outside the lockfile's directory, `inside()`, which resolves symbolic links, unless `allow_local`), `unknown-source`, `too-new` (`min_release_age_days`, from upload times), `insecure-index` (http but loopback, and `--find-links`), `index-not-allowed`, `trusted-host`. Then freshness by the lockfile's manager when it is on the `PATH` and the manifest is beside the lockfile (`freshness`: `auto`, `require`, `skip`): `uv lock --check` (without `UV_FROZEN`/`UV_LOCKED`, and `UV_PROJECT`/`UV_WORKING_DIR`, which would point it at another project), `poetry check --lock --no-interaction`, `pdm lock --check -v` (pdm says nothing without `-v`; without `PDM_PROJECT`), `pipenv verify` (without `PIPENV_PIPFILE`), each in the lockfile's directory. Their exit codes don't tell a stale lockfile from an error, so the message decides: "needs to be updated", "changed significantly since poetry.lock", "poetry.lock is not consistent with pyproject.toml" (Poetry 1.6 to 1.8), "Lockfile is out of date", "Pipfile.lock is out-of-date" are `stale` findings; exit 0 is fresh; anything else is no verdict. With `environment`, the environment's interpreter runs only `site-dirs`, with `-I -S` so no `.pth` file runs (under `-S` a venv's `sys.prefix` is the base interpreter's, so its site-packages come from beside `pyvenv.cfg`; with `include-system-site-packages = true` in it, and for a system interpreter, the base interpreter's and the user's follow, as the site module adds them), and the helper's own Python runs `installed --record --path DIR...`: every RECORD hash (RECORD is parsed directly: `Distribution.files` drops missing files from Python 3.12 on; `.pyc` files are skipped), and every `.pth` file no RECORD lists (`unlisted`; virtualenv's and uv's `_virtualenv.pth` excepted). `min_release_age_days` reads upload times from uv.lock and pylock.toml only, and warns once per lockfile with packages it can't date. SARIF leaves out installed files, which aren't in the checkout. The run record's `tool` is null; `results` has one entry per input.

### Shared helpers

- `python_security.sh`: `ps_subst` (stdin `circleci env subst`, the value as is without the CLI), `ps_list`, `ps_words` (`split_shell_words`, the parser the juburr orbs share), `ps_bool`, `ps_match` (C locale), `ps_uint`, `ps_output` (`PS_OUT`, `PS_BASE`), `ps_files` (globs; no match is an error), `ps_environment` (an interpreter or a venv directory, made absolute without following links), `ps_lock_line`, `ps_tool` (and its install record), `ps_helper_python` (`PYTHON_SECURITY_ORB_PYTHON` or `python3`, 3.8+), `ps_py`, `ps_junit`, `ps_gate`, `ps_export`, `ps_json_is` (never `jq -e` on a tool's output: jq 1.6 exits 0 on an empty file), `ps_args_json`, `ps_show_command` (the logged command line, quoted only where needed), `ps_run_record`.
- `python_security.py`: `read-lock PATH [KIND]` (uv.lock 1, poetry.lock 1.x/2.x, pdm.lock 4.x, Pipfile.lock spec 6, pylock 1.x, requirements with `-r`, options and hashes, and the options of `-c` constraints files, which pip applies, but not their packages, which it doesn't install; every Pipfile.lock category, custom ones too; normalized to `{name, version, version_key, source, location, commit, hashes, artifacts, unhashed_artifacts, upload_times, index, marker, line}`; `KIND` `lock` refuses a name that isn't a lockfile's), `pylock`, `lock-findings`, `installed [--record] [--path DIR]...` (with each distribution's source from `direct_url.json`, so `audit` treats an editable or VCS install as one; it lists a package once, the copy Python imports, but checks every copy's RECORD), `site-dirs`, `licenses`, `project-name`, `nosec`. URLs in messages and comparisons go through `public()` (no userinfo, query or fragment), and `read-lock` and `installed` redact every URL they return (`redact_lock`), so no token reaches a message or report; an option line is read as pip's optparse reads it (`option_tokens`: every option on the line, shell-split, long options by unique prefix, short options' values attached or not; an option pip doesn't take is refused); `loopback()` uses `ipaddress`; requirements files are decoded as pip decodes them (a byte order mark names the encoding), their lines joined as pip joins them (a comment line never continues), then `${NAME}` is expanded as pip expands it (`expand_env`: set and not empty, upper case; a requirement or include whose variable isn't set is refused, never taken for a path; messages show the line as written); a URL or VCS requirement without `name @` is named by its `#egg=`; a specifier may stand in parentheses (`requests (==2.32.3)`), as PEP 508 allows; a direct URL's `#sha256=` (or other) fragment counts as its hash, as pip checks it (`url_hashes`, read before the URL is redacted). Exit 1 with `ERROR:` for input it refuses, 2 for usage. TOML through `tomllib`, or `tomli`, imported only where needed: the tools' environments have tomli on 3.10, so `audit` and `licenses` run the helper on the tool's Python.

### GitHub Actions (`actions/`)

Every command has a composite action of the same name in `actions/<command>/action.yml`, with inputs identical to the command's parameters (names and defaults). Each step passes inputs to the orb's script as `PARAM_*` environment variables, as the command does, and runs it with `bash "${GITHUB_ACTION_PATH}/../run_script.sh" SCRIPT SCRIPT_PYTHON_SECURITY_LIB=<lib> [SCRIPT_PYTHON_SECURITY_PY=<py>|SCRIPT_TOOL_LOCKS=<locks>]`, with `working-directory: ${{ inputs.working_dir }}`. Inputs never appear inside a `run:` script. The install actions cache uv and the Python archive with `actions/cache`, keyed as the commands are; `install` runs the steps of each tool's install under `contains(steps.tools.outputs.list, ' <tool> ')`. The checks name their artifact `python-security-reports-<report_name>-<random>` and upload `output_dir` with `if: always()` and `store_artifacts`. Every `uses:` is pinned to a commit SHA with its version in a comment.

`actions/run_script.sh` and `tests/actions_test.sh` are identical in every juburr orb that ships actions; never edit them here alone. The actions were generated from the command YAML; keep them in sync by hand or with an equivalent generator, and quote any default a YAML 1.1 reader would take for a boolean or number. The action descriptions leave out "Environment variables are expanded". `tests/actions_test.sh` checks all of this.

### Tests

- `tests/install_test.sh`: the shared install contract against uv's install, with stand-in releases.
- `tests/install_tool_test.sh`: `install_tool.sh` against a stand-in uv and Python: Python requests, locks and checksum modes, the environment swap, the shim, the record, mirrors, `install_path`.
- `tests/commands_test.sh`: every check through `tests/run_command.sh` (with its YAML defaults), against stand-ins for pip-audit (answering from a few real advisories), Bandit (reports from `tests/fixtures/bandit`), pip-licenses (reading the target environment's metadata), uv, Poetry, PDM and Pipenv (one script answering with each one's real messages), and the CircleCI CLI, with the real Python helper; machine-installed managers are hidden by `CLEAN_PATH`. Every run record is checked against the schema when jsonschema is installed. It passes with bash 4.0, 4.3 and 5 first on the `PATH`.
- `tests/wiring_test.sh`: every `PARAM_` a script reads is set, every parameter used, reports stored, run steps named, the README documents every command and action, defaults are the newest releases, the helper is Python 3.8 syntax, the schema names every command with a run record.
- `tests/validate_reports.sh` (and `.py`): the CI jobs' reports: SARIF against the OASIS schema pinned by SHA-256, JUnit counts, run records.
- Fixtures: `tests/fixtures/vulnerable` (requests 2.19.1 and its dependencies in every lockfile format, and `app.py` with Bandit findings, a `# nosec` without a reason and one with), `clean` (six 1.17.0, safe code) and `loose` (a requirements file where every line is a `lock_verify` finding). Their `pyproject.toml` sets `[tool.uv] exclude-newer` to the date uv.lock records, so `uv lock --check` finds it fresh. The poetry.lock, pdm.lock and Pipfile.lock content hashes are placeholders, so CI checks freshness on uv.lock only.

### CI Pipeline

- `.circleci/config.yml` - Setup workflow: `test-install`, `test-env-subst` (env subst and shell conventions), `test-commands` (`cimg/python`, with jsonschema; then the wiring test), `test-actions`, orb-tools lint, pack and review (`orb_name: python-security`), shellcheck.
- `.circleci/test-deploy.yml` - With the real tools: `install-test` (every tool on `cimg/base`, with Python 3.10 and 3.14), `checksum-test` (unlisted uv and pip-audit fail closed; `known_versions` installs unverified), `arm64-test`, `audit-test` (both fixtures, OSV, ignores, an environment), `bandit-test` (suppressions, a file Bandit can't parse), `licenses-test` (an environment of the vulnerable fixture's packages, real metadata, and `lock_verify` against its RECORDs, then a changed file), `lock-verify-test` (uv's freshness, the loose fixture, a stale uv.lock). Steps that must fail run through `tests/run_command.sh`; each job ends with `tests/validate_reports.sh`. Publishing runs on `v*` tags.
- `.github/workflows/actions.yml` - The same with the actions on GitHub's runners: `offline-tests`, `install` (amd64 and arm64, Python 3.10, an unlisted version failing), `install-from-cache` (uv's and Python's hosts blocked), `audit`, `bandit`, `licenses`, `lock-verify`, with steps that must fail under `continue-on-error` and their outcomes checked.

## Linting

YAML linting uses `.yamllint` config (extends "relaxed", 200-char line limit). Shell scripts are linted with shellcheck via the CI pipeline.

Scripts pass parameter values to `circleci env subst` on stdin, as `ps_subst` does. Passed as an argument, a value starting with `-` is parsed as a CLI flag. `tests/env_subst_test.sh` enforces this.

## Shell conventions

Every script in `src/scripts/` except the shared install code follows the conventions all juburr orbs share. `tests/shell_conventions_test.sh` checks the mechanical ones; it is identical in every orb, so never edit it.

- Line 1 is `#!/bin/bash` and the first command is `set -euo pipefail` (the library in `lib/` has no `set` line). No `set +o history`, never xtrace.
- Under `-u`, use `${VAR:-}` for variables that may be unset. `PARAM_*` values the command YAML always sets are read directly, so tests that run a script directly must set every one of them (`tests/run_command.sh` sets them from the YAML).
- Expand an array that can be empty as `${arr[@]+"${arr[@]}"}`, not `"${arr[@]}"`: under `-u`, bash before 4.4 treats an empty array as unset and aborts with "unbound variable", and the orb supports bash 4.0+. Bash 4.0 also treats an empty `"$@"` as unbound, so copy `"$@"` into an array only when `$#` is non-zero: an unbound variable there ended bandit.sh with exit 0.
- `ERROR: ` and `WARN: ` messages go to stderr (`>&2` on every line of the message); everything else goes to stdout. Every non-zero exit prints an `ERROR:` line first, unless the failing tool already explained itself.
- `$BASH_ENV` exports use `printf 'export %s=%q\n'` (`ps_export`); `eval` only runs orb code (`"${SCRIPT_PYTHON_SECURITY_LIB}"`). Secrets never go on a command line, and curl that sends credentials or fetches trusted content uses `--fail` and `--proto '=https'`.
- Temporary files and directories come from `mktemp` and are removed by one EXIT trap per script.
- Variables a script sets for the lib to read carry `# shellcheck disable=SC2034 # read by ...`, since shellcheck can't see into the eval'd lib.

## Naming

Command names say what they check: the tool's job (`audit` for pip-audit, `licenses` for pip-licenses), the tool (`bandit`), or the subject (`lock_verify`). Parameters that map onto one flag take its name in snake_case (`service` for `--vulnerability-service`, `osv_url`, `timeout`, `severity_level`, `confidence_level`, `tests`, `skip`, `targets`); `lockfiles`, `requirements`, `environment`, `ignore` and `extra_args` mean the same in every command that has them. Plumbing matches the other juburr orbs: `working_dir`, `output_dir`, `report_name`, `junit`, `run_record`, `report_only`, `allow_empty`, `store_artifacts`; `allowed_licenses` and `check_project` follow go-security-orb's `licenses`; lists take commas or spaces.

## Verification

Before committing changes, verify work locally if tools are available on the system:
- Run `shellcheck` over every script and `yamllint .`
- Run every `tests/*_test.sh`, also with bash 4.0 and 4.3 first on the `PATH`
- Run `circleci orb pack src/ > orb.yml && circleci orb validate orb.yml`, and validate `.circleci/test-deploy.yml` with the packed orb spliced in under `orbs.python-security-orb`
- Run `actionlint .github/workflows/actions.yml`
- Never run the real tools or uv's downloads on a workstation you don't control; CI runs them
