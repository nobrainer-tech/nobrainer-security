#!/usr/bin/env python3
"""Memory-only package inspector for NoBrainer Security (quarantine step 1: remote static read).

    python3 tools/inspect_package.py esbuild@0.24.0                  # npm, exact version
    python3 tools/inspect_package.py six==1.16.0 [--wheel]           # PyPI sdist (or wheel)
    python3 tools/inspect_package.py OWNER/REPO@<40-hex commit SHA>  # GitHub
    python3 tools/inspect_package.py TARGET --show PATH              # print one text file

The artifact is downloaded into memory, checked against the digest its registry
publishes, and listed without being written to disk, extracted, imported,
installed or executed. Stdout is one JSON document (fixed key order; only the
fetch time and the age derived from it vary); with --show it is plain text.
Flags, URLs and IPs are leads, not proof, and never a malware verdict. Only HTTPS
to official hosts is contacted. Exit codes: 0 OK, 1 PARTIAL, 2 REFUSED,
3 FETCH_ERROR, 4 VERIFICATION_FAILED.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import binascii
import bz2
import collections
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import itertools
import json
import lzma
import re
import ssl
import stat
import struct
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MIB = 1 << 20
POLICY_DAYS = 14
EXIT = {"OK": 0, "PARTIAL": 1, "REFUSED": 2, "FETCH_ERROR": 3, "VERIFICATION_FAILED": 4}
DEFAULT_CAPS = {"download": 50 * MIB, "entries": 20000, "entry": 64 * MIB, "total": 512 * MIB}
KEEP = MIB  # bytes of a text file kept for evidence and --show; also the URL/IP scan window
SHOW_MAX = 256 * 1024
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepack", "postpack", "preprepare", "postprepare", "prepublish")
LIMITS = [
    "Static inventory only: nothing was executed, installed, imported, extracted or written to disk. Not a malware verdict; a clean result does not show the package is safe.",
    "Flags, URLs and IPs are leads for a reviewer, not proof. Only IPv4 literals are searched, in the first 1 MiB of each text file.",
    "Dependencies are listed from manifests, not fetched. Binaries and nested archives are hashed and flagged, not analysed.",
    "Release age is recency evidence only (14-day rule): an older release is not thereby safe, and a cooldown can delay an urgent security fix.",
]
ECO_LIMITS = {
    "npm": "The digest comes from the same registry response as the metadata: it catches corruption and a metadata/tarball mismatch, not a malicious publisher or a compromised registry.",
    "pypi": "The sha256 comes from the same PyPI response as the file URL: it catches corruption, not a malicious publisher or a compromised index.",
    "github": "GitHub publishes no digest for archives; the recorded sha256 is for reference and archives may not be byte-stable. Identity relies on the commit id in the archive header, and GitHub resolves SHAs across a repository's fork network, so the commit may not be on a branch of this repository. Git dates are author-controlled.",
}


class Stop(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status, self.msg, self.log = status, msg, []


def refuse(msg):
    raise Stop("REFUSED", msg)


def clip(value, n=300):
    text = str(value)
    return text if len(text) <= n else text[:n] + "..."


def digest(data, alg):
    return hashlib.new(alg, data).hexdigest()


def when(value):
    try:
        text = str(value).strip()
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00" if text[-1:] in "Zz" else text)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)


def esc(text):
    """Untrusted text made safe to display: controls and bidirectional characters become visible escapes."""
    return "".join(c if c in "\n\t" or c.isprintable() else ("\\x%02x" % ord(c) if ord(c) < 256 else "[U+%04X]" % ord(c)) for c in text)


SECRET = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_|github_pat_|npm_|xox[baprs]-|sk-|AKIA|AIza)[A-Za-z0-9_-]{16,}|://[^/\s:@]+:[^/\s@]+@")
PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.S,
)


def redact(text):
    text = PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    return SECRET.sub(lambda m: "://REDACTED@" if m.group(0).startswith("://") else "[REDACTED]", text)


# ---- targets: exact pins only

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$")
NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
PY_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
PEP440 = re.compile(r"^(\d+!)?\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?(\+[a-z0-9]+([._-][a-z0-9]+)*)?$", re.I)


def parse_target(raw):
    """Return (ecosystem, name, exact_version). Ranges, tags, branches and URLs are refused."""
    if not raw or len(raw) > 300 or re.search(r"[\s\x00-\x1f\x7f]", raw) or "://" in raw:
        refuse("target must be one token: NAME@X.Y.Z, NAME==X.Y.Z or OWNER/REPO@<40-hex commit SHA> (no URLs)")
    if "==" in raw:
        name, version = raw.split("==", 1)
        if not PY_NAME.match(name) or not PEP440.match(version):
            refuse("PyPI target must be an exact NAME==VERSION (no ranges, wildcards, extras or markers)")
        return "pypi", name, version
    if "@" not in raw[1:]:
        refuse("target needs an exact version pin (NAME@X.Y.Z, NAME==X.Y.Z or OWNER/REPO@<sha>)")
    name, version = raw.rsplit("@", 1)
    if raw.startswith("@") or "/" not in name:
        if not NPM_NAME.match(name) or len(name) > 214 or not SEMVER.match(version):
            refuse("npm target must be NAME@X.Y.Z with an exact semver version (ranges and tags such as 'latest' are refused)")
        return "npm", name, version
    owner, _, repo = name.partition("/")
    if not (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", owner) and re.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo)
            and repo not in (".", "..") and re.fullmatch(r"[0-9a-fA-F]{40}", version)):
        refuse("GitHub target must be OWNER/REPO@<full 40-hex commit SHA>; resolve branches and tags first (git ls-remote)")
    return "github", name, version.lower()


# ---- network: HTTPS to allow-listed hosts, everything kept in memory
def check_url(url, hosts):
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        refuse("not a valid URL: %s" % clip(url, 100))
    if p.scheme != "https" or p.username or p.password or port not in (None, 443) or (p.hostname or "").lower() not in hosts or re.search(r"[\s\x00-\x1f]", url):
        refuse("refusing %s: only HTTPS to %s is allowed" % (clip(url, 120), ", ".join(sorted(hosts))))


class _Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url, cap, hosts, accept="*/*"):
    opener = urllib.request.build_opener(_Redirect(hosts), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, headers={"User-Agent": "nobrainer-security-inspect/1.0", "Accept": accept, "Accept-Encoding": "identity"})
    host = urllib.parse.urlsplit(url).hostname
    too_big = Stop("FETCH_ERROR", "download from %s exceeds the %d-byte cap" % (host, cap))
    try:
        with opener.open(req, timeout=30) as resp:
            if int(resp.headers.get("Content-Length") or 0) > cap:
                raise too_big
            body = resp.read(cap + 1)
    except urllib.error.HTTPError as exc:
        raise Stop("FETCH_ERROR", "HTTP %d from %s" % (exc.code, host))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Stop("FETCH_ERROR", "request to %s failed: %s" % (host, clip(exc, 120)))
    if len(body) > cap:
        raise too_big
    return body


class Net:
    """Validates every URL, applies the cap and records each request (fetch is injectable for tests)."""

    def __init__(self, fetch, now):
        self.fetch, self.now, self.log = fetch, now, []

    def get(self, url, why, cap, hosts, accept="*/*"):
        check_url(url, hosts)
        rec = {"purpose": why, "url": url, "bytes": None}
        self.log.append(rec)
        body = self.fetch(url, cap, hosts, accept)
        if len(body) > cap:
            raise Stop("FETCH_ERROR", "%s exceeds the %d-byte cap" % (why, cap))
        rec["bytes"] = len(body)
        return body

    def json(self, url, why, hosts, cap=32 * MIB):
        try:
            return json.loads(self.get(url, why, cap, hosts, "application/json").decode("utf-8"))
        except (ValueError, RecursionError):
            raise Stop("FETCH_ERROR", "%s: response is not valid JSON" % why)


# ---- registries: metadata, artifact URL, expected digests, publish time
def resolve_npm(net, name, version, registry):
    base = (registry or "https://registry.npmjs.org").rstrip("/")
    hosts = {urllib.parse.urlsplit(base).hostname.lower()}
    q = urllib.parse.quote(name, safe="@")
    vurl = "%s/%s/%s" % (base, q, urllib.parse.quote(version, safe=""))
    doc = net.json(vurl, "npm version metadata", hosts)
    if not isinstance(doc, dict) or doc.get("name") != name or doc.get("version") != version:
        raise Stop("VERIFICATION_FAILED", "registry answered for a different name or version than requested")
    dist = doc.get("dist") if isinstance(doc.get("dist"), dict) else {}
    tarball = dist.get("tarball")
    if not isinstance(tarball, str):
        raise Stop("FETCH_ERROR", "registry metadata has no dist.tarball")
    check_url(tarball, hosts)
    expected = []
    for token in str(dist.get("integrity", "")).split():
        if token.startswith("sha512-"):
            try:
                want = binascii.hexlify(base64.b64decode(token[7:], validate=True)).decode()
            except (binascii.Error, ValueError):
                want = "invalid-base64"
            expected.append(("dist.integrity", "sha512", want))
    if dist.get("shasum"):
        expected.append(("dist.shasum", "sha1", str(dist["shasum"]).strip().lower()))
    published = None
    try:
        times = net.json("%s/%s" % (base, q), "npm packument (publish times)", hosts).get("time")
        published = times.get(version) if isinstance(times, dict) else None
    except (Stop, AttributeError):
        pass
    return {"url": tarball, "hosts": hosts, "file": tarball.rsplit("/", 1)[-1], "expected": expected, "published": published,
            "published_from": "registry packument time[%s]" % version, "weak": False, "sources": [vurl, "%s/%s" % (base, q)]}


def resolve_pypi(net, name, version, wheel):
    canon = re.sub(r"[-_.]+", "-", name).lower()
    url = "https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(canon), urllib.parse.quote(version))
    doc = net.json(url, "PyPI release metadata", {"pypi.org"})
    info = doc.get("info") if isinstance(doc, dict) and isinstance(doc.get("info"), dict) else {}
    trim = lambda v: re.sub(r"(\.0+)+$", "", str(v).lower())
    if re.sub(r"[-_.]+", "-", str(info.get("name", ""))).lower() != canon or trim(info.get("version")) != trim(version):
        raise Stop("VERIFICATION_FAILED", "PyPI answered for a different project or version than requested")
    files = [f for f in doc.get("urls") or [] if isinstance(f, dict)]
    kind = "bdist_wheel" if wheel else "sdist"
    cands = [f for f in files if f.get("packagetype") == kind]
    if wheel and len(cands) > 1:
        cands = [f for f in cands if str(f.get("filename", "")).endswith("-none-any.whl")]
    if len(cands) != 1:
        refuse("expected exactly one %s file, found %d; release files: %s" % (kind, len(cands), ", ".join(sorted(str(f.get("filename")) for f in files)[:10])))
    f = cands[0]
    check_url(str(f.get("url")), {"files.pythonhosted.org"})
    sha = (f.get("digests") or {}).get("sha256") if isinstance(f.get("digests"), dict) else None
    return {"url": f["url"], "hosts": {"files.pythonhosted.org"}, "file": str(f.get("filename")), "sources": [url],
            "expected": [("urls[].digests.sha256", "sha256", str(sha).lower())] if sha else [],
            "published": f.get("upload_time_iso_8601"), "published_from": "PyPI upload_time_iso_8601 of %s" % f.get("filename"), "weak": False}


def resolve_github(net, name, sha):
    owner, repo = (urllib.parse.quote(p) for p in name.split("/"))
    api = "https://api.github.com/repos/%s/%s/commits/%s" % (owner, repo, sha)
    published = None
    try:
        d = net.json(api, "GitHub commit metadata (unauthenticated)", {"api.github.com"}, 5 * MIB)
        if str(d.get("sha", "")).lower() == sha:
            published = d["commit"]["committer"]["date"]
    except (Stop, KeyError, TypeError, AttributeError):
        pass
    return {"url": "https://codeload.github.com/%s/%s/tar.gz/%s" % (owner, repo, sha), "hosts": {"codeload.github.com"},
            "file": "%s-%s.tar.gz" % (name.split("/")[1], sha), "expected": [], "published": published,
            "published_from": "commit.committer.date from api.github.com", "weak": True, "sources": [api]}


def verify(data, expected):
    checks = []
    for source, alg, want in expected:
        got = digest(data, alg)
        checks.append({"source": source, "algorithm": alg, "expected": want, "actual": got, "match": got == want})
    status = "NOT_AVAILABLE" if not checks else "VERIFIED" if all(c["match"] for c in checks) else "MISMATCH"
    return {"status": status, "checks": checks}


def release_age(raw, now, source, weak):
    t = when(raw) if raw else None
    if t is None:
        return {"status": "NOT_ESTABLISHED", "policy_days": POLICY_DAYS, "reason": "no publish time available from %s" % source}
    days = (now - t).total_seconds() / 86400
    return {"status": "ESTABLISHED", "policy_days": POLICY_DAYS, "published_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": source,
            "age_days": round(days, 2), "younger_than_policy": days < POLICY_DAYS,
            "reliability": "weak: a git commit date is author-controlled, not a publication time" if weak else "registry metadata"}


# ---- archives: read from memory, flag unsafe entries, never extract

Entry = collections.namedtuple("Entry", "name kind size target opener csize")
EXEC_MAGIC = {b"\x7fELF": "elf", b"\xfe\xed\xfa\xce": "mach-o", b"\xfe\xed\xfa\xcf": "mach-o", b"\xce\xfa\xed\xfe": "mach-o",
              b"\xcf\xfa\xed\xfe": "mach-o", b"\xca\xfe\xba\xbe": "mach-o/java-class", b"\x00asm": "wasm", b"MZ": "pe"}
MEDIA = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"wOFF", b"wOF2", b"%PDF", b"RIFF")
CONFIG = re.compile(r"(?:^|/)(?:package\.json|setup\.py|pyproject\.toml|\.github/workflows/[^/]+\.ya?ml|\.mcp\.json|mcp\.json|[^/]*\.mcp\.json|"
                    r"hooks/hooks\.json|\.vscode/(?:mcp|tasks)\.json|\.codex/[^/]+|\.claude/[^/]+|\.claude-plugin/[^/]+\.json|\.cursor/[^/]+|\.husky/[^/]+|"
                    r"AGENTS\.md|CLAUDE\.md|SKILL\.md|\.cursorrules|\.github/copilot-instructions\.md)$")
URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s'\"<>\\^{}|\x60]+")
IPV4 = re.compile(r"(?<![\w.\-/])(?:\d{1,3}\.){3}\d{1,3}(?![\w\-]|\.\d)")


class Cap(Exception):
    """A reading cap was reached; what was read so far is kept."""


class Limited:
    """File-like wrapper that counts decompressed bytes and stops at the total cap."""

    def __init__(self, raw, limit):
        self.raw, self.limit, self.count = raw, limit, 0

    def read(self, n=-1):
        chunk = self.raw.read(MIB if n is None or n < 0 or n > MIB else n)
        self.count += len(chunk)
        if self.count > self.limit:
            raise Cap("total_size_limit")
        return chunk


class Archive:
    def __init__(self):
        self.fmt, self.entries, self.flags, self.keep = None, [], [], {}
        self.urls, self.ips, self.truncated, self.errors, self.pax = {}, {}, [], [], {}
        self.read, self.kept, self.counter, self.total = 0, 0, None, 0

    def flag(self, code, path, detail, line=None):
        if len(self.flags) < 2000:
            self.flags.append({"code": code, "path": path, "line": line, "detail": clip(detail)})


def tar_entries(data, arc, caps):
    bio = io.BytesIO(data)
    kinds = ((b"\x1f\x8b", "tar.gz", lambda: gzip.GzipFile(fileobj=bio)), (b"BZh", "tar.bz2", lambda: bz2.BZ2File(bio)), (b"\xfd7zXZ\x00", "tar.xz", lambda: lzma.LZMAFile(bio)))
    arc.fmt, stream = next(((name, make()) for magic, name, make in kinds if data.startswith(magic)), ("tar", bio))
    if stream is bio and data[257:262] != b"ustar":
        raise ValueError("unrecognised archive format (expected tar, tar.gz, tar.bz2, tar.xz or zip)")
    arc.counter = Limited(stream, caps["total"])
    tf = tarfile.open(fileobj=arc.counter, mode="r|", errors="replace")
    arc.pax = tf.pax_headers
    for m in tf:
        kind = ("file" if m.isreg() else "dir" if m.isdir() else "symlink" if m.issym() else "hardlink" if m.islnk()
                else "device" if (m.ischr() or m.isblk() or m.isfifo()) else "other")
        yield Entry(m.name, kind, m.size if kind == "file" else 0, m.linkname, (lambda m=m: tf.extractfile(m)) if kind == "file" else None, None)


def zip_entries(data, caps):
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end >= 0 and len(data) >= end + 22:
        total, size_cd = struct.unpack_from("<10xHI", data, end)
        if total >= 0xFFFF or total > caps["entries"] or size_cd > caps["entries"] * 1024:
            raise Cap("entry_limit")
    zf = zipfile.ZipFile(io.BytesIO(data))
    for i in zf.infolist():
        mode = (i.external_attr >> 16) & 0xFFFF if i.create_system == 3 else 0
        kind = ("symlink" if stat.S_ISLNK(mode) else "dir" if i.is_dir() else
                "device" if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode)) else "file")
        target = (lambda i=i: zf.open(i).read(4096).decode("utf-8", "replace")) if kind == "symlink" else None
        yield Entry(i.filename, kind, i.file_size if kind == "file" else 0, target, (lambda i=i: zf.open(i)) if kind == "file" else None,
                    i.compress_size)


def consume(stream, arc, caps):
    h, n, head, buf, over = hashlib.sha256(), 0, b"", bytearray(), False
    try:
        while True:
            chunk = stream.read(min(65536, caps["entry"] + 1 - n))
            if not chunk:
                break
            n += len(chunk)
            arc.read += len(chunk)
            if arc.read > caps["total"]:
                raise Cap("total_size_limit")
            if len(head) < 8192:
                head += chunk[: 8192 - len(head)]
            if n > caps["entry"]:
                over = True
                break
            h.update(chunk)
            if len(buf) < KEEP:
                buf += chunk[: KEEP - len(buf)]
    finally:
        stream.close()
    return (None if over else h.hexdigest()), n, head, bytes(buf), over


def kind_of(head):
    for magic, kind in EXEC_MAGIC.items():
        if head.startswith(magic) and (magic != b"MZ" or b"\0" in head[:64]):
            return kind
    if head.startswith(MEDIA):
        return "media"
    return "binary" if b"\0" in head else "text"


def note(table, key, path, text, pos, cap):
    item = table.get(key) or (table.setdefault(key, {"count": 0, "first_seen": []}) if len(table) < cap else None)
    if item is None:
        return
    item["count"] += 1
    if len(item["first_seen"]) < 3:
        item["first_seen"].append("%s:%d" % (path, text.count("\n", 0, pos) + 1))


def scan_text(arc, path, text):
    for m in itertools.islice(URL.finditer(text), 200):
        note(arc.urls, redact(m.group(0).rstrip(".,;:!?)]}>'\""))[:300], path, text, m.start(), 500)
    for m in itertools.islice(IPV4.finditer(text), 200):
        try:
            ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        note(arc.ips, m.group(0), path, text, m.start(), 200)


def add_entry(arc, e, caps, want):
    p = clip(e.name, 500)
    row = {"path": p, "type": e.kind, "size": e.size, "kind": None, "sha256": None}
    arc.entries.append(row)
    if e.name.startswith(("/", "\\")) or re.match(r"[A-Za-z]:[\\/]", e.name):
        arc.flag("absolute_path", p, "entry path is absolute")
    if ".." in re.split(r"[\\/]", e.name):
        arc.flag("path_traversal", p, "entry path contains a '..' component")
    if e.kind in ("symlink", "hardlink", "device", "other"):
        target = e.target() if callable(e.target) else e.target
        arc.flag(e.kind, p, "-> %s (recorded, never followed)" % clip(target, 200) if target else "entry recorded, never created or followed")
        return
    if e.kind != "file":
        return
    if e.csize and e.size >= MIB and e.size / max(e.csize, 1) >= 100:
        arc.flag("high_compression_ratio", p, "%d bytes expand to %d (%d:1)" % (e.csize, e.size, e.size / max(e.csize, 1)))
    if e.size > caps["entry"]:
        arc.flag("oversize_entry", p, "declared size %d exceeds the %d-byte per-entry cap; not read" % (e.size, caps["entry"]))
        return
    try:
        row["sha256"], n, head, buf, over = consume(e.opener(), arc, caps)
    except Cap:
        raise
    except Exception as exc:  # damaged member: record it and go on
        arc.flag("unreadable_entry", p, "%s: %s" % (type(exc).__name__, clip(exc, 100)))
        return
    if over:
        arc.flag("oversize_entry", p, "content exceeds the %d-byte per-entry cap; hashing stopped" % caps["entry"])
    row["kind"] = kind = kind_of(head)
    if kind not in ("text", "media"):
        arc.flag("binary_file", p, "%s content; not analysed" % kind)
    norm = re.sub(r"^(\./)+", "", e.name)
    if kind == "text" and buf:
        scan_text(arc, p, buf.decode("utf-8", "replace"))
    if buf and arc.kept + len(buf) <= 32 * MIB and (CONFIG.search(e.name) or norm in want or norm.split("/", 1)[-1] in want):
        arc.keep[p] = buf
        arc.kept += len(buf)


def read_archive(data, caps, want=()):
    arc = Archive()
    is_zip = data[:2] == b"PK"
    arc.fmt = "zip" if is_zip else None
    try:
        for e in zip_entries(data, caps) if is_zip else tar_entries(data, arc, caps):
            if len(arc.entries) >= caps["entries"]:
                arc.truncated.append("entry_limit")
                break
            add_entry(arc, e, caps, want)
    except Cap as exc:
        arc.truncated.append(str(exc))
    except Exception as exc:  # hostile or damaged archive: keep what was read
        arc.errors.append("%s: %s" % (type(exc).__name__, clip(exc, 150)))
    for reason in arc.truncated:
        arc.flag("limit_reached", "", "reading stopped: %s" % reason)
    total = max(arc.read, arc.counter.count if arc.counter else 0)
    if not is_zip and total >= MIB and total / max(len(data), 1) >= 100:
        arc.flag("high_compression_ratio", "", "archive of %d bytes expands to at least %d bytes" % (len(data), total))
    arc.total = total
    return arc


# ---- install-time and agent-time evidence
def root_of(entries):
    names = [(re.sub(r"^(\./)+", "", e["path"]), e["type"]) for e in entries]
    tops = {n.split("/", 1)[0] for n, _ in names if n}
    return tops.pop() + "/" if len(tops) == 1 and all("/" in n or t == "dir" for n, t in names if n) else ""


def ref(row):
    return {"path": row["path"], "size": row["size"], "sha256": row["sha256"]}


def npm_manifest(arc, row):
    try:
        pkg = json.loads(arc.keep[row["path"]].decode("utf-8", "replace"))
    except (KeyError, ValueError, RecursionError):
        pkg = None
    if not isinstance(pkg, dict):
        arc.flag("manifest_unreadable", row["path"], "package.json is not a readable JSON object")
        return dict(ref(row), parsed=False)
    scripts = {clip(k, 60): clip(redact(v), 500) for k, v in (pkg.get("scripts") or {}).items() if isinstance(v, str)} if isinstance(pkg.get("scripts"), dict) else {}
    for k in LIFECYCLE:
        if k in scripts:
            arc.flag("lifecycle_script", row["path"], "%s: %s" % (k, scripts[k]))
    bins = pkg.get("bin")
    bins = {str(pkg.get("name", "")).split("/")[-1]: bins} if isinstance(bins, str) else bins if isinstance(bins, dict) else {}
    deps = {g: {clip(k, 100): clip(redact(str(v)), 150) for k, v in sorted(pkg[g].items())[:200]}
            for g in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies") if isinstance(pkg.get(g), dict)}
    for g, d in deps.items():
        for k, v in d.items():
            if re.match(r"^(git\+|git:|github:|gitlab:|file:|link:|https?:|[\w.-]+/[\w.-]+(#.*)?$)", v):
                arc.flag("non_registry_dependency", row["path"], "%s %s: %s" % (g, k, v))
    return dict(ref(row), parsed=True, name=clip(pkg.get("name")), version=clip(pkg.get("version")), scripts=scripts,
                lifecycle_scripts=[k for k in LIFECYCLE if k in scripts], bin={clip(k, 60): clip(v, 150) for k, v in list(bins.items())[:50]},
                dependencies=deps)


def python_build(arc, files):
    out = {name: ref(files[name]) for name in ("setup.py", "pyproject.toml") if name in files}
    if "setup.py" in out:
        arc.flag("build_hook", out["setup.py"]["path"], "setup.py runs on the installing machine when this source distribution is built")
    if "pyproject.toml" in out:
        text = arc.keep.get(out["pyproject.toml"]["path"], b"").decode("utf-8", "replace")
        backend = re.search(r"(?m)^\s*build-backend\s*=\s*[\"']([^\"']+)", text)
        out["pyproject.toml"]["build_backend"] = backend.group(1) if backend else None
        if re.search(r"(?m)^\s*backend-path\s*=", text):
            arc.flag("build_hook", out["pyproject.toml"]["path"], "backend-path makes the build run code shipped inside this artifact")
    return out or None


def config_summary(arc, row):
    text = arc.keep.get(row["path"])
    if text is None or not row["path"].endswith(".json"):
        return None
    try:
        doc = json.loads(text.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        doc = None
    if not isinstance(doc, dict):
        return {"parsed": False}
    servers = next((doc[k] for k in ("mcpServers", "mcp_servers", "servers") if isinstance(doc.get(k), dict)), {})
    out = {"keys": sorted(map(str, doc))[:30], "mcp_servers": [
        {"name": clip(n, 80), "command": clip(redact(str(c.get("command") or "")), 200), "args": [clip(redact(str(a)), 150) for a in (c.get("args") or [])[:8]],
         "url": clip(redact(str(c.get("url") or "")), 200)} for n, c in sorted(servers.items())[:30] if isinstance(c, dict)]}
    hooks = re.findall(r'"command"\s*:\s*"([^"]{1,200})"', json.dumps(doc.get("hooks"))) if doc.get("hooks") else []
    if hooks:
        out["hook_commands"] = [redact(h) for h in hooks[:20]]
    return out


def workflow(arc, row, text):
    uses = re.findall(r"(?m)^\s*-?\s*uses\s*:\s*['\"]?([^\s'\"#]+)", text)
    out = {"unpinned_actions": sorted({u for u in uses if not u.startswith(("./", "docker://")) and not re.search(r"@[0-9a-f]{40}$", u)})[:20],
           "pull_request_target": bool(re.search(r"(?m)^\s*-?\s*pull_request_target\b|\[[^\]]*pull_request_target", text)),
           "pipes_to_shell": bool(re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b", text))}
    if out["pull_request_target"]:
        arc.flag("workflow_pull_request_target", row["path"], "runs with base-repository secrets and a write token; unsafe if it runs pull-request code")
    if out["pipes_to_shell"]:
        arc.flag("workflow_pipes_to_shell", row["path"], "downloaded content is piped into a shell")
    return out


def evidence(arc, root):
    files = {}
    for row in arc.entries:
        if row["type"] == "file":
            p = re.sub(r"^(\./)+", "", row["path"])
            files.setdefault(p[len(root):] if root and p.startswith(root) else p, row)
    out = {"npm_manifest": npm_manifest(arc, files["package.json"]) if "package.json" in files else None,
           "python_build": python_build(arc, files), "ci_workflows": [], "agent_and_hook_files": []}
    for rel, row in sorted(files.items()):
        if re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", rel):
            if row["path"] in arc.keep and len(out["ci_workflows"]) < 100:
                out["ci_workflows"].append(dict(ref(row), **workflow(arc, row, arc.keep[row["path"]].decode("utf-8", "replace"))))
        elif CONFIG.search(rel) and not re.search(r"(?:^|/)(package\.json|setup\.py|pyproject\.toml)$", rel) and len(out["agent_and_hook_files"]) < 200:
            out["agent_and_hook_files"].append(dict(ref(row), summary=config_summary(arc, row)))
            arc.flag("agent_or_hook_file", row["path"], "agent, MCP, hook or instruction file; its text is untrusted (read it with --show)")
    return out


# ---- report
def inspect_target(raw, fetch, now, caps=None, wheel=False, registry=None, want=()):
    """Return (report, archive). Raises Stop for refusals and fetch failures."""
    caps = caps or DEFAULT_CAPS
    eco, name, version = parse_target(raw)
    if (wheel and eco != "pypi") or (registry and eco != "npm"):
        refuse("--wheel applies to PyPI targets and --registry to npm targets only")
    if registry:
        p = urllib.parse.urlsplit(registry)
        if p.scheme != "https" or not p.hostname or p.username or p.query or p.fragment or ".." in p.path.split("/"):
            refuse("--registry must be an HTTPS URL without credentials, query or fragment")
    net = Net(fetch, now)
    try:
        r = resolve_npm(net, name, version, registry) if eco == "npm" else resolve_pypi(net, name, version, wheel) if eco == "pypi" else resolve_github(net, name, version)
        data = net.get(r["url"], "artifact download (memory only)", caps["download"], r["hosts"])
        arc = read_archive(data, caps, {re.sub(r"^(\./)+", "", want).lstrip("/")} if want else ())
        return build_report(eco, name, version, raw, r, data, arc, net, caps), arc
    except Stop as stop:
        stop.log = net.log
        raise


def build_report(eco, name, version, raw, r, data, arc, net, caps):
    root = root_of(arc.entries)
    ev = evidence(arc, root)
    sha256 = digest(data, "sha256")
    identity = []
    if eco == "github":
        got = str(arc.pax.get("comment", "")).strip().lower() or None
        identity.append({"source": "tar pax header (commit id)", "expected": version, "actual": got, "match": None if got is None else got == version})
        integrity = {"status": "NOT_PUBLISHED_UPSTREAM", "checks": [], "archive_sha256": sha256,
                     "note": "GitHub publishes no digest for archives; identity comes from the commit id in the archive header."}
    else:
        integrity = verify(data, r["expected"])
    manifest = ev["npm_manifest"]
    if eco == "npm" and manifest and manifest.get("parsed") and (manifest["name"], manifest["version"]) != (name, version):
        arc.flag("identity_mismatch_in_artifact", manifest["path"], "tarball package.json says %s@%s" % (manifest["name"], manifest["version"]))
    status, why = "OK", []
    if integrity["status"] == "MISMATCH" or any(c["match"] is False for c in identity):
        status = "VERIFICATION_FAILED"
        why.append("downloaded bytes or commit id do not match what the source publishes")
    else:
        if integrity["status"] == "NOT_AVAILABLE":
            why.append("the registry published no digest to verify against")
        if any(c["match"] is None for c in identity):
            why.append("the archive carries no commit id to verify against")
        if arc.truncated or arc.errors:
            why.append("archive not fully read: %s" % ", ".join(arc.truncated + arc.errors[:2]))
    age = release_age(r["published"], net.now, r["published_from"], r["weak"])
    if status == "OK" and age["status"] != "ESTABLISHED":
        why.append("release age not established")
    status = "PARTIAL" if status == "OK" and why else status
    by_type, kinds = collections.Counter(e["type"] for e in arc.entries), collections.Counter(e["kind"] for e in arc.entries if e["kind"])
    urls = [{"url": u, "host": (re.match(r"[a-z][a-z0-9+.-]*://(?:REDACTED@)?([^/:?#]+)", u, re.I) or [None, None])[1], **v} for u, v in sorted(arc.urls.items())]
    ips = [{"ip": ip, **v} for ip, v in sorted(arc.ips.items())]
    flags = sorted(arc.flags, key=lambda f: (f["path"], f["code"], f["line"] or 0, f["detail"]))
    return {
        "tool": {"name": "nobrainer-security inspect_package", "schema": "nobrainer-security.inspect-package/2"},
        "result": {"status": status, "reasons": why, "exit_code": EXIT[status]},
        "target": {"ecosystem": eco, "input": clip(raw), "name": name, "version": version, "exact_pin": True},
        "source": {"metadata_urls": r["sources"], "artifact_url": r["url"]},
        "fetch": {"fetched_at": net.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "memory_only": True, "requests": net.log, "download_cap_bytes": caps["download"]},
        "artifact": {"filename": clip(r["file"], 200), "size_bytes": len(data), "sha256": sha256},
        "integrity": integrity,
        "identity": identity,
        "release_age": age,
        "inventory": {"format": arc.fmt, "root_prefix": root, "complete": not arc.truncated and not arc.errors, "truncated": arc.truncated,
                      "errors": arc.errors, "entry_count": len(arc.entries), "types": dict(sorted(by_type.items())), "kinds": dict(sorted(kinds.items())),
                      "uncompressed_bytes_read": arc.total, "entries": sorted(arc.entries, key=lambda e: e["path"])},
        "flags": flags,
        "flag_summary": dict(sorted(collections.Counter(f["code"] for f in flags).items())),
        "install_evidence": ev,
        "network_literals": {"urls": urls, "ips": ips},
        "limits": LIMITS + [ECO_LIMITS[eco]],
    }


def render_show(report, arc, path):
    want = re.sub(r"^(\./)+", "", path).lstrip("/")
    norm = lambda p: re.sub(r"^(\./)+", "", p)
    hit = next((p for match in (lambda n: n == want, lambda n: n.split("/", 1)[-1] == want) for p in arc.keep if match(norm(p))), None)
    if hit is None:
        return "no readable file %r in the archive (see inventory.entries)\n" % clip(path, 200), 2
    row = next(e for e in arc.entries if e["path"] == hit)
    if row["kind"] != "text":
        return "%r is %s content, not text; refusing to print it\n" % (clip(hit, 200), row["kind"]), 2
    body = esc(redact(arc.keep[hit][:SHOW_MAX].decode("utf-8", "replace")))
    shown = "whole file" if row["size"] <= SHOW_MAX else "first %d bytes" % SHOW_MAX
    failed = report["result"]["status"] == "VERIFICATION_FAILED"
    head = ["# inspect_package --show: static text view; nothing executed, extracted or written to disk (control and bidirectional characters escaped, secret-shaped strings redacted)",
            "# target: %s %s | integrity: %s | result: %s" % (report["target"]["ecosystem"], report["target"]["input"], report["integrity"]["status"], report["result"]["status"]),
            "# file: %s | size: %d bytes | sha256: %s | shown: %s" % (esc(hit), row["size"], row["sha256"], shown)]
    if failed:
        head.append("# WARNING: verification failed; this content is NOT what the source vouches for")
    code = EXIT["VERIFICATION_FAILED"] if failed else 0
    return "\n".join(head + ["# ----- begin file content -----", body.rstrip("\n"), "# ----- end file content -----", ""]), code


def main(argv=None, *, fetch=http_get, out=None, err=None, now=None):
    out, err = out or sys.stdout, err or sys.stderr
    ap = argparse.ArgumentParser(prog="inspect_package.py", description="Read-only, memory-only inspection of an exact npm, PyPI or GitHub artifact.")
    ap.add_argument("target", help="NAME@X.Y.Z (npm), NAME==X.Y.Z (PyPI) or OWNER/REPO@<40-hex commit SHA>")
    ap.add_argument("--wheel", action="store_true", help="PyPI: inspect the wheel instead of the sdist")
    ap.add_argument("--registry", help="npm only: HTTPS registry URL replacing registry.npmjs.org")
    ap.add_argument("--show", metavar="PATH", help="print one text file from the archive as plain text")
    args = ap.parse_args(argv)
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        report, arc = inspect_target(args.target, fetch, now, DEFAULT_CAPS, args.wheel, args.registry, args.show or "")
    except Stop as stop:
        err.write("inspect_package: %s: %s\n" % (stop.status, stop.msg))
        if args.show is None:
            out.write(json.dumps({"tool": {"name": "nobrainer-security inspect_package"}, "result": {"status": stop.status, "reasons": [stop.msg], "exit_code": EXIT[stop.status]},
                                  "target": {"input": clip(args.target)}, "fetch": {"requests": stop.log}, "limits": LIMITS[:1]}, indent=2, ensure_ascii=True) + "\n")
        return EXIT[stop.status]
    if args.show is not None:
        text, code = render_show(report, arc, args.show)
        (out if code != 2 else err).write(text)
        return code
    out.write(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
    return report["result"]["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
