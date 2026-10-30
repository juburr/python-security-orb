"""Helpers the python-security-orb commands run with python -I -c.

Standard library only. The commands pass this file to their steps as
SCRIPT_PYTHON_SECURITY_PY and run it as

    python -I -c "${SCRIPT_PYTHON_SECURITY_PY}" COMMAND ARG...

Most commands run on the Python the orb installed, but "installed" runs on
the interpreter of the environment it inventories, which can be older, so
the file keeps to Python 3.8 syntax, and TOML is read with tomllib (3.11+)
or tomli, imported only where a lockfile needs it.

Commands (each prints JSON on stdout; exit 1 with ERROR: on stderr when its
input can't be read, 2 for a usage error):

    read-lock PATH [KIND]       a lockfile or requirements file, normalized
                                (KIND "lock": a lockfile by its name)
    pylock IN.json OUT.toml     a minimal pylock.toml of the versioned packages
    lock-findings IN.json ...   lock_verify's static checks
    installed [--record] [--path DIR]...
                                the distributions this interpreter sees, or
                                those in each DIR; with --record their files
                                against RECORD
    licenses INVENTORY.json ... each package's license, and the policy
    project-name DIR            the project's name in DIR/pyproject.toml
    site-dirs                   this interpreter's site-packages, run with -S
    nosec SUPPRESSED.json       the reason on the # nosec of each finding
"""

import base64
import csv
import datetime
import hashlib
import json
import os
import re
import sys

KINDS = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock", "requirements")


class Refused(Exception):
    """An input this helper can't read, said in one line."""


def fail(message, code=1):
    sys.stderr.write("ERROR: %s\n" % message)
    sys.exit(code)


def canonical(name):
    """PEP 503 normalized name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def toml_load(path):
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            raise Refused("reading %s needs Python 3.11 or newer (tomllib), or tomli" % path)
    with open(path, "rb") as handle:
        try:
            return tomllib.load(handle)
        except tomllib.TOMLDecodeError as error:
            raise Refused("%s is not valid TOML: %s" % (path, error))


def kind_of(path):
    name = os.path.basename(path)
    if name == "pylock.toml" or re.fullmatch(r"pylock\.[^.]+\.toml", name):
        return "pylock"
    if name in KINDS:
        return name
    return "requirements"


def public(url):
    """URL without userinfo, query and fragment, for messages and comparisons."""
    url = re.sub(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@", r"\1", url or "")
    return re.sub(r"[?#].*$", "", url)


def classify_url(entry, url):
    """Sets a package's source from a URL: a VCS URL, a file: URL or an archive."""
    entry["location"] = url
    if re.match(r"^(git|hg|svn|bzr)\+", url):
        entry["source"] = "git" if url.startswith("git+") else url.split("+", 1)[0]
        commit = re.search(r"@([0-9a-f]{40,64})(?:#|$)", url)
        entry["commit"] = commit.group(1) if commit else None
    elif url.startswith("file:"):
        entry["source"] = "path"
    else:
        entry["source"] = "url"


URL_START = re.compile(r"^((git|hg|svn|bzr)\+|[A-Za-z][A-Za-z0-9+.-]*://|file:)")


def package(name, version=None, source="registry", **extra):
    entry = {
        "name": canonical(name),
        "version": version,
        "source": source,
        "location": None,
        "commit": None,
        "hashes": [],
        "artifacts": 0,
        "unhashed_artifacts": 0,
        "upload_times": [],
        "index": None,
        "marker": None,
        "line": None,
    }
    entry.update(extra)
    return entry


def add_artifact(entry, hashes, upload_time=None):
    """Counts one file of a package, with its hashes ("alg:hex")."""
    entry["artifacts"] += 1
    hashes = [h for h in hashes if h]
    if not hashes:
        entry["unhashed_artifacts"] += 1
    entry["hashes"].extend(hashes)
    if upload_time:
        entry["upload_times"].append(str(upload_time))


# --- Lockfile readers ---

def read_uv(path):
    data = toml_load(path)
    version = data.get("version")
    if version != 1:
        raise Refused("%s has lock version %r; this orb reads uv.lock version 1" % (path, version))
    packages, indexes = [], set()
    for raw in data.get("package", []):
        source = raw.get("source", {})
        entry = package(raw["name"], raw.get("version"))
        if "registry" in source:
            entry["index"] = source["registry"]
            if "://" in source["registry"]:
                indexes.add(source["registry"])
            else:
                # A flat index of local files (find-links): the packages are
                # still released versions, audited by name and version.
                entry["local_index"] = True
                entry["location"] = source["registry"]
        elif "git" in source:
            entry["source"] = "git"
            entry["location"] = source["git"]
            match = re.search(r"#([0-9a-f]{40,64})$", source["git"])
            entry["commit"] = match.group(1) if match else None
        elif "url" in source:
            entry["source"] = "url"
            entry["location"] = source["url"]
        elif "editable" in source or "virtual" in source:
            entry["source"] = "editable" if "editable" in source else "virtual"
            entry["location"] = source.get("editable", source.get("virtual"))
        elif "path" in source or "directory" in source:
            entry["source"] = "path" if "path" in source else "directory"
            entry["location"] = source.get("path", source.get("directory"))
        artifacts = []
        if "sdist" in raw:
            artifacts.append(raw["sdist"])
        artifacts.extend(raw.get("wheels", []))
        for artifact in artifacts:
            add_artifact(entry, [artifact.get("hash")], artifact.get("upload-time"))
        packages.append(entry)
    return {"lock_version": str(version), "indexes": sorted(indexes), "packages": packages}


def read_poetry(path):
    data = toml_load(path)
    lock_version = str(data.get("metadata", {}).get("lock-version", ""))
    if not lock_version.startswith(("1.", "2.")):
        raise Refused("%s has lock-version %r; this orb reads poetry.lock 1.x and 2.x" % (path, lock_version))
    packages, indexes = [], set()
    # Lock-version 1.0 and 1.1 (Poetry 1.0 to 1.2) list each package's files
    # in [metadata.files], by name, rather than with the package.
    metadata_files = {canonical(k): v for k, v in (data.get("metadata", {}).get("files") or {}).items()}
    for raw in data.get("package", []):
        entry = package(raw["name"], raw.get("version"))
        if "files" not in raw:
            raw = dict(raw, files=metadata_files.get(canonical(raw["name"]), []))
        source = raw.get("source") or {}
        kind = source.get("type")
        if kind == "git":
            entry["source"] = "git"
            entry["location"] = source.get("url")
            commit = source.get("resolved_reference") or ""
            entry["commit"] = commit if re.fullmatch(r"[0-9a-f]{40,64}", commit) else None
        elif kind == "url":
            entry["source"] = "url"
            entry["location"] = source.get("url")
        elif kind in ("file", "directory"):
            entry["source"] = "path" if kind == "file" else "directory"
            entry["location"] = source.get("url")
            if raw.get("develop"):
                entry["source"] = "editable"
        elif kind == "legacy":
            entry["index"] = source.get("url")
            if source.get("url"):
                indexes.add(source["url"])
        else:
            entry["index"] = "https://pypi.org/simple"
            indexes.add("https://pypi.org/simple")
        for artifact in raw.get("files", []):
            add_artifact(entry, [artifact.get("hash")], artifact.get("upload-time"))
        packages.append(entry)
    return {"lock_version": lock_version, "indexes": sorted(indexes), "packages": packages}


def read_pdm(path):
    data = toml_load(path)
    lock_version = str(data.get("metadata", {}).get("lock_version", ""))
    if not lock_version.startswith("4."):
        raise Refused("%s has lock_version %r; this orb reads pdm.lock 4.x" % (path, lock_version))
    packages = []
    for raw in data.get("package", []):
        entry = package(raw["name"], raw.get("version"))
        if raw.get("git"):
            entry["source"] = "git"
            entry["location"] = raw["git"]
            commit = raw.get("revision") or ""
            entry["commit"] = commit if re.fullmatch(r"[0-9a-f]{40,64}", commit) else None
        elif raw.get("path"):
            entry["source"] = "editable" if raw.get("editable") else "directory"
            entry["location"] = raw["path"]
        elif raw.get("url"):
            entry["source"] = "url"
            entry["location"] = raw["url"]
        for artifact in raw.get("files", []):
            add_artifact(entry, [artifact.get("hash")], artifact.get("upload_time"))
        packages.append(entry)
    # pdm.lock doesn't name the index a package came from; the project's
    # sources live in pyproject.toml.
    return {"lock_version": lock_version, "indexes": [], "packages": packages}


def read_pipfile(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except ValueError as error:
        raise Refused("%s is not valid JSON: %s" % (path, error))
    meta = data.get("_meta", {})
    spec = meta.get("pipfile-spec")
    if spec not in (6,):
        raise Refused("%s has pipfile-spec %r; this orb reads Pipfile.lock spec 6" % (path, spec))
    sources = {s.get("name"): s for s in meta.get("sources", [])}
    indexes = sorted({s.get("url") for s in sources.values() if s.get("url")})
    packages = []
    # pipenv installs from a source with verify_ssl false without checking
    # its certificate, as --trusted-host does.
    options = [{"option": "verify_ssl", "value": s.get("url"), "line": None, "file": path}
               for s in sources.values() if s.get("url") and s.get("verify_ssl") is False]
    for group in ("default", "develop"):
        for name, raw in sorted(data.get(group, {}).items()):
            version = raw.get("version")
            if version and version.startswith("=="):
                version = version[2:]
            elif version:
                version = None
            entry = package(name, version, group=group)
            if raw.get("git"):
                entry["source"] = "git"
                entry["location"] = raw["git"]
                commit = raw.get("ref") or ""
                entry["commit"] = commit if re.fullmatch(r"[0-9a-f]{40,64}", commit) else None
            elif raw.get("file") and URL_START.match(raw["file"]):
                classify_url(entry, raw["file"])
            elif raw.get("path") or raw.get("file"):
                entry["source"] = "editable" if raw.get("editable") else "path"
                entry["location"] = raw.get("path") or raw.get("file")
            else:
                index = sources.get(raw.get("index"), {}).get("url") if raw.get("index") else None
                entry["index"] = index or (indexes[0] if len(indexes) == 1 else None)
            entry["marker"] = raw.get("markers")
            hashes = raw.get("hashes", [])
            entry["artifacts"] = len(hashes) or 1
            entry["unhashed_artifacts"] = 0 if hashes else 1
            entry["hashes"] = list(hashes)
            packages.append(entry)
    return {"lock_version": str(spec), "indexes": indexes, "packages": packages, "options": options}


def read_pylock(path):
    data = toml_load(path)
    version = str(data.get("lock-version", ""))
    if not version.startswith("1."):
        raise Refused("%s has lock-version %r; this orb reads pylock.toml 1.x" % (path, version))
    packages, indexes = [], set()
    for raw in data.get("packages", []):
        entry = package(raw["name"], raw.get("version"), marker=raw.get("marker"))
        if raw.get("index"):
            entry["index"] = raw["index"]
            indexes.add(raw["index"])
        if "vcs" in raw:
            vcs = raw["vcs"]
            entry["source"] = "git" if vcs.get("type") == "git" else vcs.get("type", "vcs")
            entry["location"] = vcs.get("url") or vcs.get("path")
            commit = vcs.get("commit-id") or ""
            entry["commit"] = commit if re.fullmatch(r"[0-9a-f]{40,64}", commit) else None
        elif "directory" in raw:
            directory = raw["directory"]
            entry["source"] = "editable" if directory.get("editable") else "directory"
            entry["location"] = directory.get("path")
        elif "archive" in raw:
            archive = raw["archive"]
            entry["source"] = "url" if archive.get("url") else "path"
            entry["location"] = archive.get("url") or archive.get("path")
            add_artifact(entry, ["%s:%s" % kv for kv in archive.get("hashes", {}).items()], archive.get("upload-time"))
        artifacts = ([raw["sdist"]] if "sdist" in raw else []) + list(raw.get("wheels", []))
        for artifact in artifacts:
            add_artifact(entry, ["%s:%s" % kv for kv in artifact.get("hashes", {}).items()], artifact.get("upload-time"))
        packages.append(entry)
    return {"lock_version": version, "indexes": sorted(indexes), "packages": packages}


REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
    r"(?:(?P<at>@)\s*(?P<url>\S+)|(?P<spec>[^;]*?))\s*(?:;\s*(?P<marker>.*))?$"
)


def read_requirements(path, seen=None):
    """A pip requirements file: options, pins, hashes, -r includes."""
    seen = set() if seen is None else seen
    real = os.path.realpath(path)
    if real in seen:
        return {"lock_version": None, "indexes": [], "packages": [], "options": []}
    seen.add(real)
    try:
        with open(path, encoding="utf-8") as handle:
            raw_lines = handle.read().split("\n")
    except OSError as error:
        raise Refused("can't read %s: %s" % (path, error.strerror))
    # Joined continuation lines, each with the number of its first line, as
    # pip's join_lines does: a comment line never continues, and ends a
    # continuation.
    lines, buffer, start = [], "", None
    for number, line in enumerate(raw_lines, 1):
        comment = re.match(r"(^|\s+)#", line)
        if line.endswith("\\") and not comment:
            if start is None:
                start = number
            buffer += line[:-1] + " "
            continue
        if start is None:
            start = number
        lines.append((start, buffer + (" " + line if comment else line)))
        buffer, start = "", None
    if buffer:
        lines.append((start, buffer))
    result = {"lock_version": None, "indexes": [], "packages": [], "options": []}
    base = os.path.dirname(path)
    for number, line in lines:
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        if line.startswith("-"):
            match = re.match(r"^(--?[A-Za-z-]+)(?:[=\s]+(\S+))?", line)
            option, value = match.group(1), match.group(2)
            if option in ("-r", "--requirement") and value:
                nested = read_requirements(os.path.join(base, value), seen)
                for key in ("indexes", "packages", "options"):
                    result[key].extend(nested[key])
            elif option in ("-i", "--index-url", "--extra-index-url") and value:
                result["indexes"].append(value)
                result["options"].append({"option": option, "value": value, "line": number, "file": path})
            elif option in ("-e", "--editable") and value:
                name = re.search(r"#egg=([A-Za-z0-9._-]+)", value)
                entry = package(name.group(1) if name else value, None, "editable", location=value, line=number)
                if not name:
                    entry["name"] = value
                if URL_START.match(value):
                    classify_url(entry, value)
                entry["file"] = path
                result["packages"].append(entry)
            else:
                result["options"].append({"option": option, "value": value, "line": number, "file": path})
            continue
        hashes = re.findall(r"--hash[=\s]+([A-Za-z0-9]+:[0-9A-Fa-f]+)", line)
        spec_text = re.sub(r"\s--hash[=\s]+\S+", "", " " + line).strip()
        if URL_START.match(spec_text):
            # A URL without "name @", named by its #egg= when it has one.
            url = spec_text.split()[0]
            name = re.search(r"#egg=([A-Za-z0-9._-]+)", url)
            entry = package(name.group(1) if name else url, None, line=number)
            if not name:
                entry["name"] = url
            classify_url(entry, url)
            entry["file"] = path
            add_artifact(entry, hashes)
            result["packages"].append(entry)
            continue
        match = REQUIREMENT.match(spec_text)
        if not match:
            # A path or URL without a name.
            entry = package(spec_text, None, "path" if not re.match(r"^[a-z+]+://", spec_text) else "url",
                            location=spec_text, line=number)
            # It has no name but its path or URL, which isn't normalized.
            entry["name"] = spec_text
            entry["file"] = path
            result["packages"].append(entry)
            continue
        entry = package(match.group("name"), None, line=number, marker=match.group("marker"))
        entry["file"] = path
        if match.group("at"):
            classify_url(entry, match.group("url"))
        else:
            spec = (match.group("spec") or "").strip()
            pinned = re.fullmatch(r"===?\s*([A-Za-z0-9.+!_-]+)", spec)
            if pinned and "*" not in spec:
                entry["version"] = pinned.group(1)
            else:
                entry["specifier"] = spec
        add_artifact(entry, hashes)
        result["packages"].append(entry)
    return result


READERS = {
    "uv.lock": read_uv,
    "poetry.lock": read_poetry,
    "pdm.lock": read_pdm,
    "Pipfile.lock": read_pipfile,
    "pylock": read_pylock,
    "requirements": read_requirements,
}


def read_lock(path, kind=None):
    if kind == "lock":
        kind = kind_of(path)
        if kind == "requirements":
            raise Refused("%s is not a lockfile this orb reads by its name (uv.lock, poetry.lock, pdm.lock, Pipfile.lock, "
                          "pylock.toml or pylock.<name>.toml); name requirements files in requirements" % path)
    kind = kind or kind_of(path)
    if kind not in READERS:
        raise Refused("%s is not a lockfile this orb reads" % path)
    if not os.path.isfile(path):
        raise Refused("%s is not a file" % path)
    result = READERS[kind](path)
    result.setdefault("options", [])
    result["path"] = path
    result["kind"] = kind
    return result


# --- pylock.toml for pip-audit ---

def toml_string(value):
    return json.dumps(value)


def write_pylock(entries, out):
    """A minimal PEP 751 lock: every versioned registry package once."""
    seen = set()
    lines = ['lock-version = "1.0"', 'created-by = "python-security-orb"', ""]
    for entry in sorted(entries, key=lambda e: (e["name"], e["version"] or "")):
        key = (entry["name"], entry["version"])
        if not entry["version"] or key in seen:
            continue
        seen.add(key)
        lines += ["[[packages]]", "name = %s" % toml_string(entry["name"]),
                  "version = %s" % toml_string(entry["version"]), ""]
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    return len(seen)


# --- lock_verify's static checks ---

def loopback(url):
    import ipaddress
    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^@/]*@)?(\[[^]]*\]|[^/:?#]*)", url)
    host = match.group(1).strip("[]") if match else ""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def inside(location):
    """Whether a local source's path stays in the lockfile's directory, so the
    commit that holds the lockfile holds it too."""
    path = (location or "").replace("\\", "/")
    if not path or path.startswith(("/", "file:", "~")) or re.match(r"^[A-Za-z]:", path):
        return False
    return ".." not in path.split("/")


def lock_findings(lock, options):
    """lock_verify's static checks of one normalized lock."""
    now = options["now"]
    min_age = options["min_release_age_days"]
    allow_local = {canonical(n) for n in options["allow_local"]}
    allowed_indexes = [public(i).rstrip("/") for i in options["allowed_indexes"]]
    require_hashes = options.get("require_hashes", True)
    findings, warnings, no_age = [], [], []

    def finding(kind, message, entry=None, **where):
        item = {"kind": kind, "message": message, "lockfile": lock["path"]}
        item.update(where)
        if entry is not None:
            item.update({"package": entry["name"], "version": entry["version"], "line": entry.get("line")})
            if entry.get("file"):
                item["lockfile"] = entry["file"]
        findings.append(item)

    for entry in lock["packages"]:
        label = "%s %s" % (entry["name"], entry["version"] or "")
        source = entry["source"]
        if source in ("editable", "virtual", "directory", "path"):
            # The project, its workspace members and other paths in the
            # checkout come with the commit; a path outside it doesn't.
            if inside(entry["location"]) or entry["name"] in allow_local:
                continue
            if entry["name"] == entry["location"]:
                message = "the path %s is outside the lockfile's directory" % entry["location"]
            else:
                message = "%s comes from %s, outside the lockfile's directory" % (label.strip(), entry["location"])
            finding("local-source", message + ", so neither the commit nor a hash covers it", entry)
            continue
        if source not in ("registry", "url", "git"):
            finding("unknown-source", "%s comes from a %s source this check can't verify" % (label.strip(), source), entry)
            continue
        if source == "git":
            if not entry["commit"]:
                finding("unpinned-vcs", "%s comes from %s without a full commit hash, so it can change" % (label.strip(), entry["location"]), entry)
            continue
        if source == "registry" and not entry["version"]:
            finding("unpinned", "%s is not pinned to one version (%s)" % (entry["name"], entry.get("specifier") or "no version"), entry)
            continue
        strong = [h for h in entry["hashes"] if h.split(":", 1)[0].lower() in ("sha256", "sha384", "sha512")]
        if not require_hashes:
            pass
        elif not entry["hashes"]:
            finding("unhashed", "%s has no hash, so whatever the index serves would be installed" % label.strip(), entry)
        elif entry["unhashed_artifacts"]:
            finding("unhashed", "%s has %d of its %d files without a hash, so those would be installed unchecked"
                    % (label.strip(), entry["unhashed_artifacts"], entry["artifacts"]), entry)
        elif not strong:
            finding("weak-hash", "%s is hashed only with %s" % (label.strip(), ", ".join(sorted({h.split(":")[0] for h in entry["hashes"]}))), entry)
        if min_age > 0:
            if not entry["upload_times"]:
                no_age.append(label.strip())
            for stamp in entry["upload_times"]:
                try:
                    uploaded = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                except ValueError:
                    warnings.append("%s %s: can't read the upload time %r, so its age is unknown" % (lock["path"], label.strip(), stamp))
                    continue
                if uploaded.tzinfo is None:
                    uploaded = uploaded.replace(tzinfo=datetime.timezone.utc)
                age = (now - uploaded).total_seconds() / 86400
                if age < min_age:
                    finding("too-new", "%s was uploaded %s, %.1f days ago, less than min_release_age_days (%d)"
                            % (label.strip(), stamp, age, min_age), entry)
                    break
    if no_age:
        # poetry.lock, pdm.lock, Pipfile.lock and requirements files record no
        # upload times.
        warnings.append("%s records no upload time for %d of its packages (%s), so min_release_age_days can't check them"
                        % (lock["path"], len(no_age), ", ".join(no_age[:5]) + (", ..." if len(no_age) > 5 else "")))
    if lock["kind"] == "pdm.lock" and allowed_indexes:
        warnings.append("%s doesn't record the indexes its packages came from, so allowed_indexes can't check it" % lock["path"])
    indexes = sorted({public(i) for i in lock["indexes"]})
    for index in indexes:
        if index.startswith("http://") and not loopback(index):
            finding("insecure-index", "the index %s is plain http, so anyone on the path can change what it serves" % index,
                    index=index)
        if allowed_indexes and index.rstrip("/") not in allowed_indexes:
            finding("index-not-allowed", "the index %s is not in allowed_indexes" % index, index=index)
    if not allowed_indexes and len(indexes) > 1:
        warnings.append("%s uses %d indexes (%s): a package name on more than one of them can be taken from the wrong one; "
                        "list the expected ones in allowed_indexes" % (lock["path"], len(indexes), ", ".join(indexes)))
    for option in lock["options"]:
        where = {"lockfile": option["file"], "line": option["line"]}
        if option["option"] == "--trusted-host":
            finding("trusted-host", "--trusted-host %s turns off TLS verification for that host" % option["value"], **where)
        elif option["option"] in ("-f", "--find-links") and (option["value"] or "").startswith("http://") \
                and not loopback(option["value"]):
            finding("insecure-index", "--find-links %s finds packages over plain http" % public(option["value"]), **where)
        elif option["option"] == "verify_ssl":
            finding("trusted-host", "the source %s has verify_ssl = false, which turns off TLS verification for it"
                    % public(option["value"]), lockfile=option["file"], index=public(option["value"]))
    return {"findings": findings, "warnings": warnings}


# --- Installed distributions ---

def record_hash(path, algorithm):
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")


def direct_source(dist):
    """A distribution's source from its direct_url.json (PEP 610), or registry."""
    try:
        direct = json.loads(dist.read_text("direct_url.json") or "null")
    except ValueError:
        direct = None
    if not isinstance(direct, dict) or not direct.get("url"):
        return {"source": "registry"}
    url = direct["url"]
    if "dir_info" in direct:
        return {"source": "editable" if (direct.get("dir_info") or {}).get("editable") else "directory", "location": url}
    if "vcs_info" in direct:
        vcs = direct["vcs_info"] or {}
        return {"source": "git" if vcs.get("vcs") == "git" else vcs.get("vcs", "vcs"), "location": url,
                "commit": vcs.get("commit_id")}
    return {"source": "path" if url.startswith("file:") else "url", "location": url}


def site_dirs():
    """This interpreter's site-packages, found without running the site module
    (python -S), which would run the .pth files in them: a virtual
    environment's from beside its pyvenv.cfg, since under -S its sys.prefix
    is the base interpreter's."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    venv = os.path.isfile(os.path.join(root, "pyvenv.cfg"))
    if venv:
        dirs = [os.path.join(root, lib, "python%d.%d" % sys.version_info[:2], "site-packages") for lib in ("lib", "lib64")]
    else:
        import site
        dirs = site.getsitepackages()
    seen, found = set(), []
    for directory in dirs:
        real = os.path.realpath(directory)
        if os.path.isdir(directory) and real not in seen:
            seen.add(real)
            found.append(directory)
    return {"python": sys.executable, "version": "%d.%d.%d" % sys.version_info[:3], "venv": venv, "site": found}


def installed(check_record, paths=None):
    """The distributions on this interpreter's sys.path, or in paths, once each."""
    from importlib import metadata
    found, findings, warnings, recorded = {}, [], [], set()
    for dist in (metadata.distributions(path=paths) if paths else metadata.distributions()):
        name = dist.metadata.get("Name")
        if not name:
            continue
        key = (canonical(name), dist.version)
        if key in found:
            continue
        entry = {"name": key[0], "version": dist.version, "path": str(getattr(dist, "_path", "") or "")}
        entry.update(direct_source(dist))
        found[key] = entry
        if not check_record:
            continue
        # RECORD itself, since Distribution.files leaves out missing files
        # from Python 3.12 on.
        record = dist.read_text("RECORD")
        if record is None:
            warnings.append("%s %s has no RECORD, so its files can't be checked" % key)
            entry["files"] = None
            continue
        checked = 0
        for row in csv.reader(record.splitlines()):
            if len(row) < 2 or not row[1] or row[0].endswith((".pyc", "/RECORD")):
                continue
            file, (algorithm, _, expected) = row[0], row[1].partition("=")
            target = dist.locate_file(file)
            recorded.add(os.path.normpath(str(target)))
            try:
                actual = record_hash(str(target), algorithm)
            except FileNotFoundError:
                findings.append({"package": key[0], "version": key[1], "file": str(file), "kind": "missing",
                                 "message": "%s %s: %s is missing" % (key[0], key[1], file)})
                continue
            except (OSError, ValueError) as error:
                findings.append({"package": key[0], "version": key[1], "file": str(file), "kind": "unreadable",
                                 "message": "%s %s: %s can't be read: %s" % (key[0], key[1], file, error)})
                continue
            checked += 1
            if actual != expected:
                findings.append({"package": key[0], "version": key[1], "file": str(file), "kind": "modified",
                                 "message": "%s %s: %s doesn't match its RECORD hash" % (key[0], key[1], file)})
        entry["files"] = checked
    # A .pth file runs at every start of the interpreter: one that no RECORD
    # lists was put there by something other than an installer. Virtual
    # environments made by virtualenv and uv have one of their own.
    for directory in (paths or []) if check_record else []:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            target = os.path.normpath(os.path.join(directory, name))
            if not name.endswith(".pth") or target in recorded:
                continue
            if name == "_virtualenv.pth":
                with open(target, encoding="utf-8", errors="replace") as handle:
                    if handle.read().strip() == "import _virtualenv":
                        continue
            findings.append({"package": None, "version": None, "file": target, "kind": "unlisted",
                             "message": "%s is in no package's RECORD, and Python runs it whenever it starts" % target})
    packages = sorted(found.values(), key=lambda e: (e["name"], e["version"]))
    return {"python": sys.executable, "version": "%d.%d.%d" % sys.version_info[:3], "sys_path": sys.path,
            "packages": packages, "findings": findings, "warnings": warnings}


# --- Licenses ---

LICENSE_ALIASES = {
    "mit license": "MIT", "the mit license": "MIT", "mit-license": "MIT",
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0", "apache software license 2.0": "Apache-2.0",
    "bsd 3-clause": "BSD-3-Clause", "3-clause bsd license": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "bsd 2-clause": "BSD-2-Clause", "2-clause bsd license": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause", "isc license": "ISC", "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl 2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0", "psf": "PSF-2.0", "psfl": "PSF-2.0",
    "the unlicense": "Unlicense", "unlicense": "Unlicense",
}
CLASSIFIERS = {
    "MIT License": "MIT", "MIT No Attribution License (MIT-0)": "MIT-0", "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0", "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense", "Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "Zero-Clause BSD (0BSD)": "0BSD", "Apache License 2.0": "Apache-2.0",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only", "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0", "European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
}
SPDX_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")


def spdx_parse(text):
    """Parses an SPDX expression into nested tuples, or returns None."""
    tokens, position = [], 0
    text = text.strip()
    while position < len(text):
        match = SPDX_TOKEN.match(text, position)
        if not match:
            return None
        tokens.append(match.group(1))
        position = match.end()
        while position < len(text) and text[position].isspace():
            position += 1
    if not tokens:
        return None
    index = [0]

    def peek():
        return tokens[index[0]] if index[0] < len(tokens) else None

    def take():
        index[0] += 1
        return tokens[index[0] - 1]

    def primary():
        token = peek()
        if token == "(":
            take()
            node = expression()
            if take() != ")":
                raise ValueError
            return node
        if token is None or token.upper() in ("AND", "OR", "WITH", ")"):
            raise ValueError
        identifier = take()
        if not re.fullmatch(r"(LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.-]*\+?)", identifier):
            raise ValueError
        if peek() and peek().upper() == "WITH":
            take()
            exception = take()
            return ("with", identifier, exception)
        return ("id", identifier)

    def conjunction():
        node = primary()
        while peek() and peek().upper() == "AND":
            take()
            node = ("and", node, primary())
        return node

    def expression():
        node = conjunction()
        while peek() and peek().upper() == "OR":
            take()
            node = ("or", node, conjunction())
        return node

    try:
        node = expression()
    except (ValueError, IndexError):
        return None
    return node if index[0] == len(tokens) else None


def spdx_allowed(node, allowed):
    kind = node[0]
    if kind == "id":
        return node[1].lower() in allowed
    if kind == "with":
        # An exception only adds permissions to the license it modifies.
        return node[1].lower() in allowed or ("%s with %s" % (node[1], node[2])).lower() in allowed
    if kind == "and":
        return spdx_allowed(node[1], allowed) and spdx_allowed(node[2], allowed)
    return spdx_allowed(node[1], allowed) or spdx_allowed(node[2], allowed)


def all_of(identifiers):
    node = ("id", identifiers[0])
    for identifier in identifiers[1:]:
        node = ("and", node, ("id", identifier))
    return node


def resolve_license(row, clarify):
    """The license of one pip-licenses row: (text, origin, node), node being
    the parsed SPDX expression, or None when there is none to check."""
    name, version = canonical(row.get("Name", "")), row.get("Version", "")
    for key in ("%s==%s" % (name, version), name):
        if key in clarify:
            return clarify[key], "clarify:" + key, spdx_parse(clarify[key])
    expression = (row.get("License-Expression") or "").strip()
    if expression and expression != "UNKNOWN":
        return expression, "License-Expression", spdx_parse(expression)
    field = (row.get("License-Metadata") or row.get("License") or "").strip()
    if field and field != "UNKNOWN" and "\n" not in field and len(field) < 120:
        alias = LICENSE_ALIASES.get(field.lower())
        if alias:
            return alias, "License (%s)" % field, ("id", alias)
        # A short field that reads as an identifier or expression, such as
        # MIT, BSD-3-Clause or "Apache-2.0 OR MIT", is taken as written; the
        # license's full text, or prose, is not.
        node = spdx_parse(field)
        if node and re.fullmatch(r"[A-Za-z0-9.+()\s:-]+", field) and re.search(r"\d|^[A-Z0-9]+$|-", field):
            return field, "License", node
    classifiers = sorted({c.strip() for c in (row.get("License-Classifier") or "").split(";")} - {"", "UNKNOWN"})
    if classifiers:
        mapped = [CLASSIFIERS.get(c) for c in classifiers]
        if all(mapped):
            # Several classifiers may mean a choice or every one of them, so
            # each must be allowed.
            return " AND ".join(mapped), "classifiers", all_of(mapped)
        # Classifiers such as "BSD License" don't say which license.
        return "; ".join(classifiers), "classifiers", None
    return "UNKNOWN", "none", None


def licenses(inventory, allowed_text, ignore_text, clarify_text, project):
    allowed = {a.lower() for a in re.split(r"[,\s]+", allowed_text) if a}
    ignores = [i for i in re.split(r"[,\s]+", ignore_text) if i]
    clarify = {}
    for line in clarify_text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9._-]+(?:==[^=\s]+)?)\s*=\s*(.+)$", line)
        if not match or not spdx_parse(match.group(2)):
            raise Refused("clarify entries are name[==version]=EXPRESSION, one per line, such as"
                          " 'idna=BSD-3-Clause', not '%s'" % line)
        name, _, version = match.group(1).partition("==")
        clarify[canonical(name) + ("==" + version if version else "")] = match.group(2).strip()
    used_ignores, used_clarify, packages = set(), set(), []
    for row in inventory:
        name, version = canonical(row.get("Name", "")), row.get("Version", "")
        ignored = None
        for entry in ignores:
            key_name, _, key_version = entry.partition("==")
            if canonical(key_name) == name and (not key_version or key_version == version):
                ignored = entry
                used_ignores.add(entry)
        text, origin, node = resolve_license(row, clarify)
        if origin.startswith("clarify:"):
            used_clarify.add(origin[len("clarify:"):])
        packages.append({
            "name": name, "version": version, "license": text, "origin": origin, "known": node is not None,
            "allowed": node is not None and spdx_allowed(node, allowed), "ignored": ignored,
            "project": bool(project) and name == canonical(project),
            "license_expression": row.get("License-Expression"),
            "license_field": row.get("License-Metadata", row.get("License")),
            "classifiers": row.get("License-Classifier"), "url": row.get("URL"),
        })
    packages.sort(key=lambda p: (p["name"], p["version"]))
    return {
        "packages": packages,
        "unused_ignores": [i for i in ignores if i not in used_ignores],
        "unused_clarify": sorted(k for k in clarify if k not in used_clarify),
    }


def project_name(directory):
    """The name pyproject.toml gives the project, or ""."""
    path = os.path.join(directory, "pyproject.toml")
    if not os.path.isfile(path):
        return ""
    data = toml_load(path)
    name = (data.get("project") or {}).get("name") or ((data.get("tool") or {}).get("poetry") or {}).get("name") or ""
    return canonical(name) if isinstance(name, str) else ""


# --- Bandit suppressions ---

# Bandit's own pattern for a nosec comment (bandit/core/manager.py); the
# reason is the text after a second #, which Bandit never parses.
NOSEC = re.compile(r"#\s*nosec:?\s*(?P<tests>[^#]+)?#?(?P<reason>.*)$")


def comments(path):
    import io
    import tokenize
    found = {}
    with open(path, "rb") as handle:
        source = handle.read()
    try:
        for token in tokenize.tokenize(io.BytesIO(source).readline):
            if token.type == tokenize.COMMENT:
                found.setdefault(token.start[0], []).append(token.string)
    except (tokenize.TokenError, SyntaxError):
        pass
    return found


def nosec(suppressed):
    cache, out = {}, []
    for item in suppressed:
        path = item["filename"]
        if path not in cache:
            try:
                cache[path] = comments(path)
            except OSError:
                cache[path] = {}
        lines = [item["line_number"]] + list(item.get("line_range") or [])
        reason, comment, line_found = "", None, None
        for line in lines:
            for text in cache[path].get(line, []):
                match = NOSEC.search(text)
                if match:
                    comment, line_found = text, line
                    reason = match.group("reason").strip()
                    break
            if comment:
                break
        out.append(dict(item, nosec_comment=comment, nosec_line=line_found, reason=reason))
    return out


# --- Command line ---

def main(argv):
    if not argv:
        fail("usage: python_security.py COMMAND ARG...", 2)
    command, args = argv[0], argv[1:]
    try:
        if command == "read-lock":
            result = read_lock(args[0], args[1] if len(args) > 1 else None)
        elif command == "pylock":
            with open(args[0], encoding="utf-8") as handle:
                entries = json.load(handle)
            result = {"packages": write_pylock(entries, args[1])}
        elif command == "lock-findings":
            with open(args[0], encoding="utf-8") as handle:
                lock = json.load(handle)
            options = json.loads(args[1])
            options["now"] = datetime.datetime.now(datetime.timezone.utc)
            result = lock_findings(lock, options)
        elif command == "installed":
            paths = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "--path"]
            result = installed("--record" in args, paths)
        elif command == "licenses":
            with open(args[0], encoding="utf-8") as handle:
                inventory = json.load(handle)
            if not isinstance(inventory, list):
                raise Refused("the pip-licenses inventory is not a list")
            result = licenses(inventory, args[1], args[2], args[3], args[4])
        elif command == "site-dirs":
            result = site_dirs()
        elif command == "project-name":
            result = {"name": project_name(args[0])}
        elif command == "nosec":
            with open(args[0], encoding="utf-8") as handle:
                result = nosec(json.load(handle))
        else:
            fail("unknown command %s" % command, 2)
    except Refused as error:
        fail(str(error))
    except (IndexError, KeyError) as error:
        fail("%s: unexpected input (%s: %s)" % (command, type(error).__name__, error))
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


main(sys.argv[1:])
