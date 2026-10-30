#!/bin/bash
#
# Prints a lock for one release of a tool the orb installs with uv (pip-audit,
# bandit or pip-licenses), ready to paste into src/install/<tool>/locks.txt.
# A development helper: the orb never runs it.
#
#   src/install/lock.sh -t <tool> -v <version> [-d <date>]
#
#   -t  pip-audit, bandit or pip-licenses
#   -v  the tool's version
#   -d  only releases uploaded before this time (RFC 3339, default seven days
#       ago), so a compromised release has time to come to light before it
#       reaches a lock, and the lock can be made again
#
# The lock pins the tool and every dependency to one version, with the
# SHA-256 of every wheel the orb can install: CPython 3.10 to 3.14 on Linux
# x86_64 and aarch64, glibc (manylinux) or musl (musllinux). The step fails
# when a package has no wheel for one of those, since the orb never builds
# from source. When pypi-attestations is on the PATH, the tool's own wheel
# must carry PyPI provenance from the tool's release workflow.
#
# Needs uv (the orb's pinned release, so the lock is the one the orb would
# make) and python3. The lock goes to stdout and everything else to stderr.

set -euo pipefail

TOOL=""
VERSION=""
BEFORE=""
while getopts "t:v:d:" opt; do
    case "${opt}" in
        t) TOOL=${OPTARG} ;;
        v) VERSION=${OPTARG#v} ;;
        d) BEFORE=${OPTARG} ;;
        *) exit 2 ;;
    esac
done
# The requirement each tool installs (bandit reads [tool.bandit] from
# pyproject.toml with tomli on Python 3.10), and the release workflow whose
# PyPI provenance its wheel carries.
case "${TOOL}" in
    pip-audit)
        REQUIREMENT="pip-audit==${VERSION}"
        IDENTITY="https://github.com/pypa/pip-audit/.github/workflows/release.yml@refs/tags/v${VERSION}"
        ;;
    bandit)
        REQUIREMENT="bandit[toml]==${VERSION}"
        IDENTITY="https://github.com/PyCQA/bandit/.github/workflows/publish-to-pypi.yml@refs/tags/${VERSION}"
        ;;
    pip-licenses)
        REQUIREMENT="pip-licenses==${VERSION}"
        IDENTITY="https://github.com/raimon49/pip-licenses/.github/workflows/CD-PyPi.yml@refs/tags/v-${VERSION}"
        ;;
    *)
        echo "Usage: $0 -t pip-audit|bandit|pip-licenses -v <version> [-d <date>]" >&2
        exit 2
        ;;
esac
if [[ ! "${VERSION}" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
    echo "ERROR: -v must be a release version, such as 2.10.1." >&2
    exit 2
fi
if [[ -z "${BEFORE}" ]]; then
    BEFORE=$(date -u -d '7 days ago' +%Y-%m-%dT00:00:00Z)
fi
for tool in uv python3; do
    if ! command -v "${tool}" > /dev/null; then
        echo "ERROR: ${tool} is not on the PATH." >&2
        exit 1
    fi
done

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
cd "${WORK}"
printf '%s\n' "${REQUIREMENT}" > requirements.in

# One version per package for every Python the orb supports (fewest), wheels
# only, from PyPI, ignoring any uv configuration around.
env -u UV_CONFIG_FILE -u UV_INDEX_URL -u UV_DEFAULT_INDEX -u UV_INDEX -u UV_EXTRA_INDEX_URL -u UV_FIND_LINKS \
    -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
    uv pip compile --quiet --no-config --universal --fork-strategy fewest --python-version 3.10 \
    --only-binary :all: --generate-hashes --no-header --no-annotate \
    --default-index https://pypi.org/simple --exclude-newer "${BEFORE}" \
    -o universal.txt requirements.in >&2

python3 -I - universal.txt "${TOOL}" "${VERSION}" "${IDENTITY}" > filtered.txt << 'PY'
"""Keeps the hashes of the wheels the orb can install, and checks coverage."""
import json
import re
import shutil
import subprocess
import sys
import urllib.request

LOCK, TOOL, VERSION, IDENTITY = sys.argv[1:5]
MINORS = (10, 11, 12, 13, 14)
ARCHES = ("x86_64", "aarch64")
LIBCS = ("gnu", "musl")


def simple(name):
    req = urllib.request.Request(
        "https://pypi.org/simple/%s/" % name,
        headers={"Accept": "application/vnd.pypi.simple.v1+json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def parse(path):
    entries, cur = [], None
    for raw in open(path, encoding="utf-8"):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            m = re.match(r"^([A-Za-z0-9._-]+)==([^ ;\\]+)\s*(?:;\s*(.*?))?\s*\\?$", line)
            if not m:
                sys.exit("ERROR: can't read the lock line: %s" % line)
            cur = {"name": m.group(1), "version": m.group(2), "marker": (m.group(3) or "").strip(), "hashes": []}
            entries.append(cur)
        else:
            cur["hashes"] += re.findall(r"--hash=sha256:([0-9a-f]{64})", line)
    return entries


def compatible(filename, minor, arch, libc):
    py, abi, plat = (part.split(".") for part in filename[:-4].split("-")[-3:])
    if not any(
        p == "any"
        or (p.endswith("_" + arch) and (p.startswith("musllinux") if libc == "musl" else p.startswith(("manylinux", "linux_"))))
        for p in plat
    ):
        return False
    for tag in py:
        for a in abi:
            if a == "none" and tag in ("py3", "py3%d" % minor, "py2.py3"):
                return True
            if tag == "cp3%d" % minor and a in ("cp3%d" % minor, "none"):
                return True
            m = re.fullmatch(r"cp3(\d+)", tag)
            if m and a == "abi3" and int(m.group(1)) <= minor:
                return True
    return False


def marker_true(marker, minor):
    """Evaluates the markers uv writes for Linux CPython, or None if unsure."""
    if not marker:
        return True
    env = {"python_version": "3.%d" % minor, "python_full_version": "3.%d" % minor, "sys_platform": "linux", "platform_system": "Linux",
           "os_name": "posix", "implementation_name": "cpython", "platform_python_implementation": "CPython"}

    def clause(text):
        m = re.fullmatch(r"\s*(\w+)\s*(==|!=|<=|>=|<|>)\s*'([^']*)'\s*", text)
        if not m or m.group(1) not in env:
            raise ValueError(text)
        left, op, right = env[m.group(1)], m.group(2), m.group(3)
        if m.group(1) in ("python_version", "python_full_version"):
            # Every 3.X.Y release of a minor version must agree.
            right = tuple(map(int, right.split(".")))
            if len(right) > 2 and right[:2] == (3, minor):
                raise ValueError(text)
            left, right = (3, minor), right[:2]
        return {"==": left == right, "!=": left != right, "<=": left <= right,
                ">=": left >= right, "<": left < right, ">": left > right}[op]

    try:
        return any(all(clause(c) for c in part.split(" and ")) for part in marker.split(" or "))
    except ValueError:
        return None


entries = parse(LOCK)
names = [e["name"] for e in entries]
if len(names) != len(set(names)):
    sys.exit("ERROR: the lock has more than one version of a package: %s" % ", ".join(sorted(names)))
out, problems, provenance = [], [], 0
for e in entries:
    files = {f["hashes"].get("sha256"): f for f in simple(e["name"])["files"]}
    missing = [h for h in e["hashes"] if h not in files]
    if missing:
        problems.append("%s %s: PyPI lists no file with hash %s" % (e["name"], e["version"], missing[0]))
    wheels = [files[h] for h in e["hashes"] if h in files and files[h]["filename"].endswith(".whl")]
    keep = [f for f in wheels if any(compatible(f["filename"], m, a, l) for m in MINORS for a in ARCHES for l in LIBCS)]
    for m in MINORS:
        if marker_true(e["marker"], m) is False:
            continue
        for a in ARCHES:
            for l in LIBCS:
                if not any(compatible(f["filename"], m, a, l) for f in keep):
                    problems.append("%s %s has no wheel for CPython 3.%d on %s %s" % (e["name"], e["version"], m, a, l))
    provenance += any(f.get("provenance") for f in keep)
    if e["name"] == TOOL:
        tool_wheels = keep
    spec = "%s==%s" % (e["name"], e["version"]) + (" ; %s" % e["marker"] if e["marker"] else "")
    out.append(spec + " \\")
    hashes = sorted(f["hashes"]["sha256"] for f in keep)
    for i, h in enumerate(hashes):
        out.append("    --hash=sha256:%s%s" % (h, " \\" if i < len(hashes) - 1 else ""))
if problems:
    sys.exit("ERROR: the lock can't be used:\n  " + "\n  ".join(problems))
if not any(e["name"] == TOOL and e["version"] == VERSION for e in entries):
    sys.exit("ERROR: the lock doesn't hold %s %s." % (TOOL, VERSION))
print("%d packages, %d of them with PyPI provenance." % (len(entries), provenance), file=sys.stderr)
if shutil.which("pypi-attestations"):
    for f in tool_wheels:
        ok = subprocess.run(["pypi-attestations", "verify", "pypi", "--repository",
                             IDENTITY.split("/.github/")[0], "pypi:" + f["filename"]],
                            stdout=sys.stderr, stderr=sys.stderr).returncode == 0
        if not ok:
            sys.exit("ERROR: %s has no PyPI provenance from %s." % (f["filename"], IDENTITY))
        print("ok: %s carries PyPI provenance from %s." % (f["filename"], IDENTITY.split("/.github/")[0]), file=sys.stderr)
else:
    print("NOTE: pypi-attestations is not installed, so the PyPI provenance of the %s wheel was not checked." % TOOL,
          file=sys.stderr)
print("\n".join(out))
PY

printf '# >>> %s %s >>>\n' "${TOOL}" "${VERSION}"
printf '# %s, resolved by %s from releases uploaded before %s.\n' "${REQUIREMENT}" "$(uv --version)" "${BEFORE}"
cat filtered.txt
printf '# <<< %s %s <<<\n' "${TOOL}" "${VERSION}"
