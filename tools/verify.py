#!/usr/bin/env python3
"""
tools/verify.py — the checks CI runs on every push and tag; run it locally
before tagging (`python3 tools/verify.py`). Pure stdlib plus jinja2.

Each check exists because it has bitten this plugin before or bit Jen's
own tree in a way that silently reaches a plugin:

  * plugin.zip matches the working tree — v1.4.1 was a version-bump-only
    release because v1.4.0's zip was never rebuilt, so Jen's Update button
    kept installing the previous code.
  * no inline event handlers / every <script> nonce'd — Jen v5.22.0's CSP
    stopped executing `onclick=` attributes and un-nonce'd scripts; nothing
    errors, buttons just stop working.
  * manifest version == top CHANGELOG entry — the version Jen's registry
    pins to is the manifest's; a changelog that says otherwise is the kind
    of drift that makes a release unreviewable after the fact.
  * every POST <form> carries csrf_token — Jen's own tests/test_template_csrf.py
    exists because a form without one 403's on every save with no hint why;
    this plugin's own CI catches that before it ever reaches Jen's bundled-
    copy scan of the same thing.

Exit status is non-zero on the first failure, with every failing check
listed. Nothing here needs a database or the `jen` package.
"""

import io
import json
import os
import py_compile
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The zip's exact member list: the flat files below (any that exist) plus
# every file under templates/. Anything else in the tree is deliberately
# NOT shipped — a stray .pyc, a scratch file, this tools/ dir.
ZIP_FLAT_FILES = ["manifest.json", "plugin.py", "README.md", "CHANGELOG.md", "LICENSE", ".enabled"]

_INLINE_HANDLER_RE = re.compile(r"""\son[a-z]+\s*=\s*["']""", re.I)
_SCRIPT_OPEN_RE = re.compile(r"<script\b[^>]*>", re.I)
_CHANGELOG_HEAD_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)
# Same pattern as Jen's own tests/test_plugin_template_csrf.py, copied here
# so a missing csrf_token fails THIS repo's CI, not just Jen's bundled scan.
_POST_FORM_RE = re.compile(r'<form\b[^>]*\bmethod\s*=\s*["\']POST["\'][^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)

failures = []


def fail(msg):
    failures.append(msg)
    print(f"FAIL  {msg}")


def ok(msg):
    print(f"ok    {msg}")


def expected_zip_members():
    members = [f for f in ZIP_FLAT_FILES if os.path.isfile(os.path.join(ROOT, f))]
    tdir = os.path.join(ROOT, "templates")
    for dirpath, _dirs, files in os.walk(tdir):
        for fn in files:
            rel = os.path.relpath(os.path.join(dirpath, fn), ROOT).replace(os.sep, "/")
            members.append(rel)
    return sorted(members)


def build_zip_bytes(members):
    """Deterministic build — fixed timestamps, sorted members — so the same
    tree always produces the same bytes, whether this is the `--build`
    that writes plugin.zip or the rebuild check_zip() compares against."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in members:
            info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(ROOT, rel), "rb") as f:
                z.writestr(info, f.read())
    return buf.getvalue()


def check_compile():
    try:
        py_compile.compile(os.path.join(ROOT, "plugin.py"), doraise=True)
        ok("plugin.py compiles")
    except py_compile.PyCompileError as e:
        fail(f"plugin.py does not compile: {e}")


def check_manifest():
    path = os.path.join(ROOT, "manifest.json")
    try:
        with open(path, encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as e:
        fail(f"manifest.json unreadable or not valid JSON: {e}")
        return None
    for key in ("id", "name", "version", "requires_jen"):
        if not manifest.get(key):
            fail(f"manifest.json is missing '{key}'")
    version = str(manifest.get("version", ""))
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fail(f"manifest.json version {version!r} is not X.Y.Z")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", str(manifest.get("id", ""))):
        fail(f"manifest.json id {manifest.get('id')!r} would be rejected by Jen's valid_plugin_id()")
    for m in manifest.get("db_migrations", []):
        if not (isinstance(m, str) or (isinstance(m, dict) and "version" in m and "sql" in m)):
            fail(f"manifest.json db_migrations entry is neither a SQL string nor a {{version, sql}} object: {m!r}")
    if not failures:
        ok(f"manifest.json valid (id={manifest['id']}, version={version})")
    return manifest


def check_changelog(manifest):
    if not manifest:
        return
    path = os.path.join(ROOT, "CHANGELOG.md")
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        fail(f"CHANGELOG.md unreadable: {e}")
        return
    m = _CHANGELOG_HEAD_RE.search(text)
    if not m:
        fail("CHANGELOG.md has no '## [X.Y.Z]' heading")
        return
    if m.group(1) != manifest["version"]:
        fail(f"CHANGELOG.md top entry is [{m.group(1)}] but manifest.json version is {manifest['version']}")
    else:
        ok(f"CHANGELOG.md top entry matches manifest ({m.group(1)})")


def check_templates():
    try:
        from jinja2 import Environment
    except ImportError:
        fail("jinja2 is not installed (pip install jinja2)")
        return
    env = Environment()
    tdir = os.path.join(ROOT, "templates")
    count = 0
    for dirpath, _dirs, files in os.walk(tdir):
        for fn in files:
            if not fn.endswith(".html"):
                continue
            count += 1
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            with open(path, encoding="utf-8") as f:
                src = f.read()
            try:
                env.parse(src)
            except Exception as e:
                fail(f"{rel}: Jinja parse error: {e}")
            for lineno, line in enumerate(src.splitlines(), 1):
                if _INLINE_HANDLER_RE.search(line):
                    fail(f"{rel}:{lineno}: inline event handler (blocked by Jen's CSP): {line.strip()[:80]}")
            for sm in _SCRIPT_OPEN_RE.finditer(src):
                tag = sm.group(0)
                if "nonce=" not in tag:
                    lineno = src.count("\n", 0, sm.start()) + 1
                    fail(f'{rel}:{lineno}: <script> without nonce="{{{{ csp_nonce }}}}" (blocked by Jen\'s CSP)')
            for i, form_html in enumerate(_POST_FORM_RE.findall(src)):
                if "csrf_token" not in form_html:
                    fail(f"{rel}: POST form #{i + 1} has no csrf_token field — every submission 403s")
    if count == 0:
        fail("no templates found under templates/")
    elif not any(f.startswith("templates/") for f in failures):
        ok(f"{count} template(s) parse; no inline handlers; every <script> nonce'd; every POST form has csrf_token")


def check_line_endings():
    """The tree is declared LF (.gitattributes) and plugin.zip is built from
    the tree: a CRLF file here — an editor on Windows, a Python text-mode
    write — would ship CRLF inside the zip and fail CI's rebuild
    comparison against an LF checkout. Catch it before the build does."""
    bad = []
    for rel in expected_zip_members():
        with open(os.path.join(ROOT, rel), "rb") as f:
            if b"\r\n" in f.read():
                bad.append(rel)
    for rel in bad:
        fail(f"{rel} has CRLF line endings — the tree must be LF (see .gitattributes)")
    if not bad:
        ok("every zip member is LF")


def check_zip():
    members = expected_zip_members()
    path = os.path.join(ROOT, "plugin.zip")
    if not os.path.isfile(path):
        fail("plugin.zip is missing")
        return
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        fail(f"plugin.zip is not a valid zip: {e}")
        return
    names = sorted(n for n in z.namelist() if not n.endswith("/"))
    missing = sorted(set(members) - set(names))
    extra = sorted(set(names) - set(members))
    for n in missing:
        fail(f"plugin.zip is missing {n}")
    for n in extra:
        fail(f"plugin.zip contains {n}, which is not part of the plugin")
    stale = []
    for rel in members:
        if rel in names:
            with open(os.path.join(ROOT, rel), "rb") as f:
                if z.read(rel) != f.read():
                    stale.append(rel)
    for rel in stale:
        fail(f"plugin.zip's {rel} differs from the working tree — rebuild the zip")
    if not (missing or extra or stale):
        ok(f"plugin.zip matches the working tree ({len(members)} members)")


def build_zip():
    """`--build`: (re)write plugin.zip deterministically from the working
    tree — fixed member timestamps, sorted members — so the same tree
    produces the same bytes (and the same sha256 for registry.json) on
    any machine. Always run the checks afterwards."""
    members = expected_zip_members()
    data = build_zip_bytes(members)
    with open(os.path.join(ROOT, "plugin.zip"), "wb") as f:
        f.write(data)
    import hashlib

    print(f"built plugin.zip ({len(members)} members) sha256 {hashlib.sha256(data).hexdigest()}")


def main():
    if "--build" in sys.argv[1:]:
        build_zip()
    check_compile()
    manifest = check_manifest()
    check_changelog(manifest)
    check_templates()
    check_line_endings()
    check_zip()
    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
