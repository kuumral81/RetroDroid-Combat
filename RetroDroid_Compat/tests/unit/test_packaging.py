"""Milestone M4 unit tests for Dockerfile hardening, .dockerignore, README.txt, and release packaging."""

from __future__ import annotations

import fnmatch
import hashlib
import http.server
import importlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
WORKSPACE_ROOT = REPO_ROOT.parent
RELEASE_ZIP_PATH = WORKSPACE_ROOT / "RetroDroid_Compat_v5.4.0.zip"
SOURCE_V531_ZIP_PATH = WORKSPACE_ROOT / "RetroDroid_Compat_v5.3.1_temiz.zip"
EXPECTED_V531_SHA256 = "d0e91199c51e882d02d03f8eae7a9d8c8b6c4c5c0ad22662e81cc3dfb133ad8f"


def _load_retrodroid_config() -> Any:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("retrodroid.config")


def _load_build_release_zip_module() -> Any:
    script_path = REPO_ROOT / "scripts" / "build_release_zip.py"
    spec = importlib.util.spec_from_file_location("build_release_zip", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_release_zip"] = module
    spec.loader.exec_module(module)
    return module


def _parse_dockerfile_instructions(dockerfile_text: str) -> list[tuple[str, str]]:
    """Join backslash continuations (skipping comment lines) into `(INSTRUCTION, args)` tuples."""
    logical_lines: list[str] = []
    buf = ""
    for raw_line in dockerfile_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1].rstrip() + " "
        else:
            buf += stripped
            logical_lines.append(buf.strip())
            buf = ""
    if buf.strip():
        logical_lines.append(buf.strip())

    instructions: list[tuple[str, str]] = []
    for line in logical_lines:
        parts = line.split(None, 1)
        instr = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        instructions.append((instr, rest))
    return instructions


def _parse_dockerignore_patterns(text: str) -> list[str]:
    patterns: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line.strip("/"))
    return patterns


def _match_segments(pat_parts: list[str], path_parts: list[str]) -> bool:
    if not pat_parts:
        return not path_parts
    head = pat_parts[0]
    if head == "**":
        return _match_segments(pat_parts[1:], path_parts) or (
            bool(path_parts) and _match_segments(pat_parts, path_parts[1:])
        )
    if not path_parts:
        return False
    if not fnmatch.fnmatchcase(path_parts[0], head):
        return False
    return _match_segments(pat_parts[1:], path_parts[1:])


def _dockerignore_matches(rel_posix: str, patterns: list[str]) -> bool:
    """Evaluate Docker-style `.dockerignore` patterns including directory prefixes and `**`."""
    parts = [p for p in rel_posix.strip("/").split("/") if p]
    matched = False
    for raw_pat in patterns:
        negated = raw_pat.startswith("!")
        pat = raw_pat[1:].strip("/") if negated else raw_pat
        if not pat:
            continue
        pat_parts = [p for p in pat.split("/") if p]
        hit = False
        for prefix_len in range(1, len(parts) + 1):
            if _match_segments(pat_parts, parts[:prefix_len]):
                hit = True
                break
        if hit:
            matched = not negated
    return matched


# ---------------------------------------------------------------------------
# 1. Dockerfile Hardening & Live HEALTHCHECK / Uvicorn CLI Flag Verification
# ---------------------------------------------------------------------------


def test_dockerfile_base_image_and_hardened_packages() -> None:
    raw = (REPO_ROOT / "Dockerfile").read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    text = raw.decode("utf-8")
    instructions = _parse_dockerfile_instructions(text)

    from_instrs = [args for instr, args in instructions if instr == "FROM"]
    assert from_instrs == ["python:3.11-slim-bookworm"]

    run_joined = "\n".join(args for instr, args in instructions if instr == "RUN")
    assert "apt-get update" in run_joined
    assert "--no-install-recommends" in run_joined
    assert "rm -rf /var/lib/apt/lists/*" in run_joined
    for pkg in (
        "default-jre-headless",
        "apktool",
        "aapt",
        "zipalign",
        "apksigner",
        "android-framework-res",
        "ca-certificates",
    ):
        assert re.search(rf"\b{re.escape(pkg)}\b", run_joined), f"Missing package {pkg} in Dockerfile"


def test_dockerfile_build_time_tool_verification() -> None:
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    run_joined = "\n".join(args for instr, args in instructions if instr == "RUN")

    for tool in ("java", "keytool", "aapt", "apktool", "zipalign", "apksigner"):
        assert f"command -v {tool}" in run_joined, f"Missing build-time presence check for {tool}"
    assert "java -version" in run_joined
    assert "aapt version" in run_joined
    assert "apktool --version" in run_joined
    assert "apksigner --version" in run_joined
    # OpenJDK keytool rejects `-version` with exit code 1; verify `-help` is used instead
    assert "keytool -version" not in run_joined
    assert "keytool -help" in run_joined


def test_dockerfile_env_vars_and_no_java_tool_options_trap() -> None:
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    env_joined = " ".join(args for instr, args in instructions if instr == "ENV")

    assert "JAVA_TOOL_OPTIONS" not in env_joined
    assert "PYTHONDONTWRITEBYTECODE=1" in env_joined
    assert "PYTHONUNBUFFERED=1" in env_joined
    assert "PORT=10000" in env_joined
    assert "/tmp/retrodroid_jobs" in env_joined
    assert "/var/data/retrodroid.jks" in env_joined
    assert 'JAVA_HEAP_MB="256"' in env_joined or "JAVA_HEAP_MB=256" in env_joined


def test_dockerfile_non_root_appuser_dirs_and_explicit_copies() -> None:
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    instr_names = [instr for instr, _ in instructions]

    run_joined = "\n".join(args for instr, args in instructions if instr == "RUN")
    assert "appuser" in run_joined
    for required_dir in ("/app", "/var/data", "/var/data/jobs", "/tmp/retrodroid_jobs"):
        assert required_dir in run_joined
    assert "chmod 0755" in run_joined
    assert "chmod 0644" in run_joined

    copy_args = [args for instr, args in instructions if instr == "COPY"]
    assert copy_args, "Expected explicit COPY instructions"
    for arg in copy_args:
        assert not re.search(r"(?:^|\s)\.\s+\.(?:$|\s)", arg), "Blind `COPY . .` is prohibited"
    copy_joined = "\n".join(copy_args)
    for prod_target in ("requirements.txt", "server.py", "index.html", "README.txt", "retrodroid/", "static/"):
        assert prod_target in copy_joined

    user_idx = next(i for i, (ins, arg) in enumerate(instructions) if ins == "USER" and arg == "appuser")
    hc_idx = next(i for i, (ins, _) in enumerate(instructions) if ins == "HEALTHCHECK")
    cmd_idx = next(i for i, (ins, _) in enumerate(instructions) if ins == "CMD")
    assert user_idx < hc_idx < cmd_idx
    assert ("EXPOSE", "10000") in instructions
    assert "WORKDIR" in instr_names


def test_dockerfile_healthcheck_snippet_executes_against_live_http_server() -> None:
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    hc_args = [args for instr, args in instructions if instr == "HEALTHCHECK"]
    assert len(hc_args) == 1
    hc = hc_args[0]

    for flag in ("--interval=30s", "--timeout=5s", "--start-period=15s", "--retries=3"):
        assert flag in hc

    cmd_pos = hc.index("CMD")
    cmd_list = json.loads(hc[cmd_pos + 3 :].strip())
    assert cmd_list[:2] == ["python", "-c"]
    snippet = cmd_list[2]
    assert "urllib.request.ProxyHandler({})" in snippet
    assert "build_opener" in snippet
    assert "os.environ.get('PORT') or '10000'" in snippet
    assert "/health" in snippet

    status_to_serve = {"code": 200}

    class _HealthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                body = b'{"status":"ok","healthy":true}'
                self.send_response(status_to_serve["code"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["HTTP_PROXY"] = "http://127.0.0.1:1"
        env["http_proxy"] = "http://127.0.0.1:1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        ok_res = subprocess.run(
            [sys.executable, "-c", snippet],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert ok_res.returncode == 0, ok_res.stderr

        status_to_serve["code"] = 503
        fail_res = subprocess.run(
            [sys.executable, "-c", snippet],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert fail_res.returncode != 0
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)

    # Closed port must also fail healthcheck cleanly
    closed_env = os.environ.copy()
    closed_env["PORT"] = str(port)
    closed_env["PYTHONDONTWRITEBYTECODE"] = "1"
    closed_res = subprocess.run(
        [sys.executable, "-c", snippet],
        env=closed_env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert closed_res.returncode != 0


def test_dockerfile_cmd_exec_signal_forwarding_and_valid_uvicorn_flags() -> None:
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    cmd_args = [args for instr, args in instructions if instr == "CMD"]
    assert len(cmd_args) == 1

    cmd_list = json.loads(cmd_args[0])
    assert cmd_list[:2] == ["sh", "-c"]
    shell_cmd = cmd_list[2]
    assert shell_cmd.startswith("exec uvicorn server:app ")
    assert "--host 0.0.0.0" in shell_cmd
    assert "--port ${PORT:-10000}" in shell_cmd
    assert "--proxy-headers" in shell_cmd
    assert "--forwarded-allow-ips=" in shell_cmd
    assert "--timeout-keep-alive 120" in shell_cmd
    assert "--workers" not in shell_cmd

    help_res = subprocess.run(
        [sys.executable, "-m", "uvicorn", "--help"],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    uvicorn_flags = re.findall(r"--[a-z0-9-]+", shell_cmd)
    assert uvicorn_flags
    for flag in uvicorn_flags:
        assert flag in help_res.stdout, f"Flag {flag} is not supported by installed uvicorn"


# ---------------------------------------------------------------------------
# 2. .dockerignore Pattern Coverage
# ---------------------------------------------------------------------------


def test_dockerignore_excludes_dev_test_cache_secret_and_artifact_paths() -> None:
    raw = (REPO_ROOT / ".dockerignore").read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    patterns = _parse_dockerignore_patterns(raw.decode("utf-8"))

    must_ignore = [
        ".git",
        ".git/config",
        ".gitignore",
        ".github/workflows/ci.yml",
        ".agents/teamwork/worker_m4_r12/handoff.md",
        ".venv/pyvenv.cfg",
        "venv/bin/python",
        "__pycache__/server.cpython-311.pyc",
        "retrodroid/__pycache__/config.cpython-311.pyc",
        "retrodroid/orphan.pyc",
        "retrodroid/orphan.pyo",
        "retrodroid/native.pyd",
        "Demo$py.class",
        ".pytest_cache/v/cache/nodeids",
        ".ruff_cache/CACHEDIR.TAG",
        ".mypy_cache/3.11/server.meta.json",
        "node_modules/jszip/index.js",
        "tests/unit/test_packaging.py",
        "tests/e2e/test_tier1_features.py",
        "scripts/build_release_zip.py",
        ".env",
        ".env.local",
        ".env.production",
        "retrodroid.jks",
        "nested/retrodroid.jks",
        "release.keystore",
        "retrodroid.jks.pass",
        "nested/secret.pass",
        "retrodroid.jks.bak.1700000000",
        "game.apk",
        "nested/game.xapk",
        "bundle.apks",
        "mirror.apkm",
        "main.1.com.example.obb",
        "RetroDroid_Compat_v5.4.0.zip",
        "uvicorn.log",
        ".DS_Store",
        "static/.DS_Store",
        "Thumbs.db",
    ]
    for rel in must_ignore:
        assert _dockerignore_matches(rel, patterns), f".dockerignore failed to exclude {rel!r}"


def test_dockerignore_preserves_all_production_deliverables() -> None:
    patterns = _parse_dockerignore_patterns((REPO_ROOT / ".dockerignore").read_text(encoding="utf-8"))
    must_keep = [
        "Dockerfile",
        ".dockerignore",
        "README.txt",
        "requirements.txt",
        "server.py",
        "index.html",
        "retrodroid/__init__.py",
        "retrodroid/config.py",
        "retrodroid/keystore.py",
        "retrodroid/axml.py",
        "retrodroid/inspector.py",
        "retrodroid/patcher.py",
        "retrodroid/containers.py",
        "retrodroid/jobs.py",
        "static/styles.css",
        "static/app.js",
        "static/vendor/jszip.js",
    ]
    for rel in must_keep:
        assert not _dockerignore_matches(rel, patterns), f".dockerignore erroneously excluded {rel!r}"


# ---------------------------------------------------------------------------
# 3. requirements.txt CVE-Free Dependency Floors
# ---------------------------------------------------------------------------


def _parse_version_tuple(ver_str: str) -> tuple[int, ...]:
    nums = [int(part) for part in re.findall(r"\d+", ver_str)]
    return tuple(nums)


def test_requirements_txt_cve_free_dependency_floors() -> None:
    raw = (REPO_ROOT / "requirements.txt").read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")

    parsed: dict[str, tuple[str, tuple[int, ...]]] = {}
    for line in raw.decode("utf-8").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*(==|>=)\s*([0-9][0-9A-Za-z_.-]*)$", cleaned)
        assert m is not None, f"Unpinned or malformed requirement line: {cleaned!r}"
        pkg_name = m.group(1).lower()
        op = m.group(2)
        ver = _parse_version_tuple(m.group(3))
        parsed[pkg_name] = (op, ver)

    assert parsed["fastapi"][1] >= (0, 115, 3)
    assert parsed["starlette"][1] >= (0, 47, 2)
    assert parsed["python-multipart"][1] >= (0, 0, 22)
    assert parsed["uvicorn"][1] >= (0, 30, 0)
    assert parsed["pyyaml"][1] >= (6, 0, 1)


# ---------------------------------------------------------------------------
# 4. Turkish README.txt v5.4.0 Accuracy & Completeness
# ---------------------------------------------------------------------------


def test_readme_utf8_lf_and_v540_modular_architecture() -> None:
    readme_path = REPO_ROOT / "README.txt"
    raw = readme_path.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    mode = stat.S_IMODE(readme_path.stat().st_mode)
    assert mode == 0o644

    cfg_mod = _load_retrodroid_config()
    text = raw.decode("utf-8")
    assert f"v{cfg_mod.APP_VERSION}" in text
    assert "v5.3.1)" not in text

    for module_ref in (
        "server.py",
        "retrodroid/config.py",
        "retrodroid/keystore.py",
        "retrodroid/axml.py",
        "retrodroid/inspector.py",
        "retrodroid/patcher.py",
        "retrodroid/containers.py",
        "retrodroid/jobs.py",
        "index.html",
        "static/styles.css",
        "static/app.js",
        "static/vendor/jszip.js",
    ):
        assert module_ref in text, f"README.txt missing architecture reference: {module_ref}"


def test_readme_documents_all_watched_env_vars_and_defaults() -> None:
    cfg_mod = _load_retrodroid_config()
    text = (REPO_ROOT / "README.txt").read_text(encoding="utf-8")
    defaults = cfg_mod.Settings()

    for env_name in ("PORT", *cfg_mod._WATCHED_ENV_VARS):
        assert env_name in text, f"README.txt missing env var documentation for {env_name}"

    expected_default_tokens = (
        "10000",
        str(defaults.WORK_DIR),
        "/var/data/retrodroid.jks",
        defaults.KEYSTORE_ALIAS,
        str(defaults.MAX_UPLOAD_MB),
        str(defaults.CHUNK_SIZE_MB),
        str(defaults.JOB_TTL_SECONDS),
        str(defaults.DISK_FREE_FLOOR_MB),
        str(defaults.MAX_ARCHIVE_ENTRIES),
        str(defaults.MAX_DECOMPRESSED_BYTES),
        str(defaults.RATE_LIMIT_PER_MIN),
        str(defaults.JAVA_HEAP_MB),
    )
    for token in expected_default_tokens:
        assert token in text, f"README.txt missing exact default value {token!r}"


def test_readme_keystore_fallback_persistent_disk_single_worker_and_honest_ux() -> None:
    text = (REPO_ROOT / "README.txt").read_text(encoding="utf-8")

    # MED-16: exact fallback path, zero stale /tmp/retrodroid_keystore, non-destructive .bak, /var/data WORK_DIR
    assert "/tmp/retrodroid_keystore" not in text
    assert "_keystore/retrodroid.jks" in text
    assert "/tmp/retrodroid_jobs/_keystore/retrodroid.jks" in text
    assert "KEYSTORE_AUTO_REGEN" in text
    assert ".bak." in text
    assert "WORK_DIR=/var/data/jobs" in text
    assert "/var/data" in text

    # LOW-09: single-worker uvicorn deployment requirement
    assert "--workers 1" in text or "tek worker" in text.lower()

    # Android 14 (API 23) & Android 15-17 (API 24) install floor + 16 KB ELF + honest preview wording
    assert "API 23" in text or "< 23" in text
    assert "API 24" in text or ">= 24" in text
    assert "16 KB" in text
    assert "PT_LOAD" in text
    assert "ARM32 -> ARM64" in text or "JIT" in text
    assert "Vulkan" in text


# ---------------------------------------------------------------------------
# 5. Deterministic Release Packaging & Standalone Extracted Smoke Tests
# ---------------------------------------------------------------------------


def test_build_release_zip_is_byte_for_byte_deterministic(tmp_path: Path) -> None:
    mod = _load_build_release_zip_module()
    zip_a = tmp_path / "release_first.zip"
    zip_b = tmp_path / "release_second.zip"

    res_a = mod.build_release_zip(REPO_ROOT, zip_a)
    res_b = mod.build_release_zip(REPO_ROOT, zip_b)

    bytes_a = zip_a.read_bytes()
    bytes_b = zip_b.read_bytes()
    assert bytes_a == bytes_b
    assert res_a["sha256"] == res_b["sha256"] == hashlib.sha256(bytes_a).hexdigest()
    assert res_a["entries"] == sorted(res_a["entries"])


def test_build_release_zip_excludes_adversarial_decoys_and_normalizes_crlf_and_modes(
    tmp_path: Path,
) -> None:
    mod = _load_build_release_zip_module()
    dirty_repo = tmp_path / "dirty_repo"
    dirty_repo.mkdir(parents=True)

    # Copy production tree into dirty_repo
    for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt", "server.py"):
        shutil.copy2(REPO_ROOT / rel, dirty_repo / rel)
    shutil.copytree(REPO_ROOT / "retrodroid", dirty_repo / "retrodroid")
    shutil.copytree(REPO_ROOT / "static", dirty_repo / "static")

    # Inject CRLF and strip trailing newline on two production text files
    readme_crlf = (dirty_repo / "README.txt").read_text(encoding="utf-8").rstrip("\n").replace("\n", "\r\n")
    (dirty_repo / "README.txt").write_bytes(readme_crlf.encode("utf-8"))
    server_crlf = (dirty_repo / "server.py").read_text(encoding="utf-8").rstrip("\n").replace("\n", "\r\n")
    (dirty_repo / "server.py").write_bytes(server_crlf.encode("utf-8"))

    # Plant dirty 0o660 / 0o2770 permissions (LOW-04 regression test)
    os.chmod(dirty_repo / "retrodroid", 0o2770)
    os.chmod(dirty_repo / "README.txt", 0o660)
    os.chmod(dirty_repo / "server.py", 0o660)

    # Plant adversarial decoy secrets, caches, tests, scripts, and binary artifacts
    decoys = [
        ".env",
        ".env.production",
        "key.jks",
        "signing.keystore",
        "key.pass",
        "retrodroid.jks.bak.1700000000",
        "bad.apk",
        "bad.xapk",
        "bad.apks",
        "bad.apkm",
        "main.1.pkg.obb",
        "bad.zip",
        "server.log",
        ".DS_Store",
        "Thumbs.db",
        ".gitignore",
        ".git/HEAD",
        ".agents/teamwork/handoff.md",
        ".ruff_cache/a",
        ".pytest_cache/v/cache/nodeids",
        "__pycache__/a.pyc",
        "retrodroid/__pycache__/config.cpython-312.pyc",
        "retrodroid/rogue.pyc",
        "retrodroid/.hidden.py",
        ".venv/pyvenv.cfg",
        "tests/x.py",
        "scripts/x.py",
        "static/.hidden.js",
        "static/vendor/evil.apk",
        "static/vendor/secret.pass",
    ]
    for decoy in decoys:
        target = dirty_repo / decoy
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"DECOY_PAYLOAD_DO_NOT_PACKAGE\r\n")

    out_zip = tmp_path / "cleaned_release.zip"
    summary = mod.build_release_zip(dirty_repo, out_zip)

    assert set(summary["normalized_files"]) == {"README.txt", "server.py"}
    assert stat.S_IMODE(out_zip.stat().st_mode) == 0o644

    with zipfile.ZipFile(out_zip, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        for decoy in decoys:
            assert f"RetroDroid_Compat_v5.4.0/{decoy}" not in names
            assert decoy not in names

        for info in zf.infolist():
            assert info.date_time == (2026, 1, 1, 0, 0, 0)
            unix_mode = (info.external_attr >> 16) & 0o7777
            if info.is_dir():
                assert unix_mode == 0o755, f"Bad dir mode {oct(unix_mode)} on {info.filename}"
            else:
                assert unix_mode == 0o644, f"Bad file mode {oct(unix_mode)} on {info.filename}"
                content = zf.read(info.filename)
                assert b"DECOY_PAYLOAD_DO_NOT_PACKAGE" not in content
                assert b"\r" not in content, f"CR byte remained in {info.filename}"
                assert content.endswith(b"\n"), f"Missing trailing LF in {info.filename}"


def test_build_release_zip_rejects_missing_deliverables_and_symlinks_cleanly(tmp_path: Path) -> None:
    mod = _load_build_release_zip_module()
    empty_dir = tmp_path / "empty_repo"
    empty_dir.mkdir()
    out_zip = tmp_path / "should_not_exist.zip"

    with pytest.raises(FileNotFoundError):
        mod.build_release_zip(empty_dir, out_zip)
    assert not out_zip.exists()
    assert list(tmp_path.glob("*.tmp")) == []

    with pytest.raises(ValueError):
        mod.build_release_zip(REPO_ROOT, out_zip, archive_prefix="../traversal")

    sym_repo = tmp_path / "sym_repo"
    sym_repo.mkdir()
    for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt"):
        shutil.copy2(REPO_ROOT / rel, sym_repo / rel)
    (sym_repo / "server.py").symlink_to(REPO_ROOT / "server.py")
    shutil.copytree(REPO_ROOT / "retrodroid", sym_repo / "retrodroid")
    shutil.copytree(REPO_ROOT / "static", sym_repo / "static")

    with pytest.raises(ValueError, match="symlink"):
        mod.build_release_zip(sym_repo, out_zip)
    assert not out_zip.exists()


def test_build_release_zip_cli_entrypoint(tmp_path: Path) -> None:
    mod = _load_build_release_zip_module()
    cli_zip = tmp_path / "cli_out.zip"
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    proc = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "build_release_zip.py"),
            "--root",
            str(REPO_ROOT),
            "--output",
            str(cli_zip),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert cli_zip.is_file()
    expected = mod.build_release_zip(REPO_ROOT, tmp_path / "api_out.zip")
    cli_sha = hashlib.sha256(cli_zip.read_bytes()).hexdigest()
    assert cli_sha == expected["sha256"]
    assert cli_sha in proc.stdout


def test_release_zip_artifact_structure_permissions_and_immutable_v531_source() -> None:
    assert SOURCE_V531_ZIP_PATH.is_file()
    v531_sha = hashlib.sha256(SOURCE_V531_ZIP_PATH.read_bytes()).hexdigest()
    assert v531_sha == EXPECTED_V531_SHA256

    assert RELEASE_ZIP_PATH.is_file(), f"Release zip missing at {RELEASE_ZIP_PATH}"
    assert stat.S_IMODE(RELEASE_ZIP_PATH.stat().st_mode) == 0o644

    with zipfile.ZipFile(RELEASE_ZIP_PATH, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        assert "RetroDroid_Compat_v5.4.0/" in names

        for req in (
            "RetroDroid_Compat_v5.4.0/.dockerignore",
            "RetroDroid_Compat_v5.4.0/Dockerfile",
            "RetroDroid_Compat_v5.4.0/README.txt",
            "RetroDroid_Compat_v5.4.0/index.html",
            "RetroDroid_Compat_v5.4.0/requirements.txt",
            "RetroDroid_Compat_v5.4.0/server.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/__init__.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/config.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/keystore.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/axml.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/inspector.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/patcher.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/containers.py",
            "RetroDroid_Compat_v5.4.0/retrodroid/jobs.py",
            "RetroDroid_Compat_v5.4.0/static/styles.css",
            "RetroDroid_Compat_v5.4.0/static/app.js",
            "RetroDroid_Compat_v5.4.0/static/vendor/jszip.js",
        ):
            assert req in names, f"Missing required entry in release zip: {req}"

        forbidden_substrings = (
            "/tests/",
            "/scripts/",
            "/.venv/",
            "/.git/",
            "/.agents/",
            "__pycache__",
            ".ruff_cache",
            ".pytest_cache",
            ".jks",
            ".pass",
            ".apk",
            ".xapk",
            ".obb",
            ".pyc",
        )
        for info in zf.infolist():
            assert info.filename.startswith("RetroDroid_Compat_v5.4.0/")
            for bad in forbidden_substrings:
                assert bad not in info.filename, f"Forbidden path {bad!r} leaked into {info.filename}"
            unix_mode = (info.external_attr >> 16) & 0o7777
            if info.is_dir():
                assert unix_mode == 0o755
            else:
                assert unix_mode == 0o644
                raw = zf.read(info.filename)
                text = raw.decode("utf-8")
                assert "\r" not in text
                assert text.endswith("\n")


def test_release_zip_extracted_standalone_smoke_boot_and_static_assets(tmp_path: Path) -> None:
    extract_dir = tmp_path / "extracted"
    with zipfile.ZipFile(RELEASE_ZIP_PATH, "r") as zf:
        zf.extractall(extract_dir)

    app_root = extract_dir / "RetroDroid_Compat_v5.4.0"
    assert app_root.is_dir()

    smoke_code = """
import json, os, sys
from pathlib import Path
from fastapi.testclient import TestClient
import server

assert Path(server.__file__).resolve() == (Path.cwd() / "server.py").resolve()
with TestClient(server.create_app()) as client:
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "RetroDroid" in r_root.text
    assert r_root.headers.get("x-content-type-options") == "nosniff"
    assert r_root.headers.get("x-frame-options") == "DENY"

    r_health = client.get("/health")
    assert r_health.status_code == 200
    h = r_health.json()
    assert h["version"] == "5.4.0"
    assert h["keystoreReady"] is True

    r_ks = client.get("/api/keystore-info")
    assert r_ks.status_code == 200
    assert r_ks.json()["ready"] is True

    for asset in ("/static/styles.css", "/static/app.js", "/static/vendor/jszip.js"):
        r_asset = client.get(asset)
        assert r_asset.status_code == 200, asset
        assert len(r_asset.content) > 100, asset
print("STANDALONE_SMOKE_OK")
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(app_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["WORK_DIR"] = str(tmp_path / "standalone_work")
    env["KEYSTORE_PATH"] = str(tmp_path / "standalone_ks" / "retrodroid.jks")

    proc = subprocess.run(
        [sys.executable, "-c", smoke_code],
        cwd=str(app_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert "STANDALONE_SMOKE_OK" in proc.stdout


def test_dockerfile_cmd_shell_expansion_respects_custom_port_and_avoids_globbing(
    tmp_path: Path,
) -> None:
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    cmd_list = json.loads(next(args for instr, args in instructions if instr == "CMD"))
    shell_cmd = cmd_list[2]

    # Create files in cwd to ensure `--forwarded-allow-ips='*'` never glob-expands `*`
    (tmp_path / "alpha.txt").write_text("x", encoding="utf-8")
    (tmp_path / "beta.txt").write_text("y", encoding="utf-8")

    probe_cmd = shell_cmd.replace(
        "exec uvicorn",
        f'exec "{sys.executable}" -c "import json, sys; print(json.dumps(sys.argv[1:]))"',
        1,
    )

    env_default = {k: v for k, v in os.environ.items() if k != "PORT"}
    res_default = subprocess.run(
        ["sh", "-c", probe_cmd],
        cwd=str(tmp_path),
        env=env_default,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    argv_default = json.loads(res_default.stdout.strip())
    assert argv_default[0] == "server:app"
    assert argv_default[argv_default.index("--port") + 1] == "10000"
    assert "--forwarded-allow-ips=*" in argv_default

    env_custom = dict(env_default, PORT="18080")
    res_custom = subprocess.run(
        ["sh", "-c", probe_cmd],
        cwd=str(tmp_path),
        env=env_custom,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    argv_custom = json.loads(res_custom.stdout.strip())
    assert argv_custom[argv_custom.index("--port") + 1] == "18080"
    assert "--forwarded-allow-ips=*" in argv_custom


def test_readme_documents_all_rest_api_endpoints() -> None:
    text = (REPO_ROOT / "README.txt").read_text(encoding="utf-8")
    expected_routes = (
        "/health",
        "/static/",
        "/api/keystore-info",
        "/api/upload/init",
        "/api/upload/status/",
        "/api/upload/chunk",
        "/api/upload/finish",
        "/api/analyze",
        "/api/patch-sign",
        "/api/patch-status/",
        "/api/patch-cancel/",
        "/api/jobs",
        "/api/attach-obb/",
        "/api/full-xapk/",
        "/api/full-xapk-status/",
        "/api/download-full-xapk/",
        "/api/download/",
        "/api/download-obb/",
    )
    for route in expected_routes:
        assert route in text, f"README.txt missing REST endpoint documentation for {route}"


def test_build_release_zip_rejects_null_bytes_and_invalid_utf8_in_text_deliverables(
    tmp_path: Path,
) -> None:
    mod = _load_build_release_zip_module()
    bad_repo = tmp_path / "bad_text_repo"
    bad_repo.mkdir()
    for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt", "server.py"):
        shutil.copy2(REPO_ROOT / rel, bad_repo / rel)
    shutil.copytree(REPO_ROOT / "retrodroid", bad_repo / "retrodroid")
    shutil.copytree(REPO_ROOT / "static", bad_repo / "static")

    out_zip = tmp_path / "corrupt.zip"
    (bad_repo / "README.txt").write_bytes(b"Valid text with\x00null byte\n")
    with pytest.raises(ValueError, match="Null byte"):
        mod.build_release_zip(bad_repo, out_zip)
    assert not out_zip.exists()

    (bad_repo / "README.txt").write_bytes(b"\xff\xfeInvalid UTF-8 bytes\n")
    with pytest.raises(ValueError, match="Non-UTF-8"):
        mod.build_release_zip(bad_repo, out_zip)
    assert not out_zip.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_build_release_zip_strict_archive_prefix_case_insensitive_exclusions_and_static_symlink(
    tmp_path: Path,
) -> None:
    mod = _load_build_release_zip_module()
    out_zip = tmp_path / "should_not_exist.zip"

    # Item #4: strict raw archive_prefix validation before any .strip()
    bad_prefixes = (
        "",
        " ",
        ".",
        "..",
        "..\x00safe",
        "/abs",
        "RetroDroid/",
        " evil",
        "evil ",
        "evil\nbar",
        "evil\n",
        "C:evil",
        "a\\b",
        "-leading-dash",
        ".leading-dot",
    )
    for bad in bad_prefixes:
        with pytest.raises(ValueError, match="Invalid archive_prefix"):
            mod.build_release_zip(REPO_ROOT, out_zip, archive_prefix=bad)
        assert not out_zip.exists()
        assert list(tmp_path.glob("*.tmp")) == []

    # CLI exits non-zero and leaves no output or .tmp files for malicious --prefix
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cli_res = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "build_release_zip.py"),
            "--root",
            str(REPO_ROOT),
            "--output",
            str(out_zip),
            "--prefix",
            "/abs",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert cli_res.returncode != 0
    assert not out_zip.exists()
    assert list(tmp_path.glob("*.tmp")) == []

    # Item #5: case-insensitive exclusion for *.BAK.* / *.JKS.* / *.PASS.*
    case_repo = tmp_path / "case_repo"
    case_repo.mkdir()
    for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt", "server.py"):
        shutil.copy2(REPO_ROOT / rel, case_repo / rel)
    shutil.copytree(REPO_ROOT / "retrodroid", case_repo / "retrodroid")
    shutil.copytree(REPO_ROOT / "static", case_repo / "static")

    uppercase_decoys = (
        "static/vendor/leaked.BAK.js",
        "static/vendor/leaked.JKS.txt",
        "static/vendor/leaked.PASS.txt",
        "static/vendor/leaked.KEYSTORE.json",
        "retrodroid/Backup.BAK.py",
    )
    for decoy in uppercase_decoys:
        (case_repo / decoy).write_text("SECRET_UPPERCASE_DECOY\n", encoding="utf-8")

    case_zip = tmp_path / "case_out.zip"
    mod.build_release_zip(case_repo, case_zip)
    with zipfile.ZipFile(case_zip, "r") as zf:
        names = set(zf.namelist())
        for decoy in uppercase_decoys:
            assert f"RetroDroid_Compat_v5.4.0/{decoy}" not in names

    # Item #5: explicit rejection of symlinked static/ directory (symmetry with retrodroid/ & static/vendor/)
    sym_static_repo = tmp_path / "sym_static_repo"
    sym_static_repo.mkdir()
    for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt", "server.py"):
        shutil.copy2(REPO_ROOT / rel, sym_static_repo / rel)
    shutil.copytree(REPO_ROOT / "retrodroid", sym_static_repo / "retrodroid")
    real_static = sym_static_repo / "_real_static"
    shutil.copytree(REPO_ROOT / "static", real_static)
    (sym_static_repo / "static").symlink_to(real_static)

    sym_out = tmp_path / "sym_static_out.zip"
    with pytest.raises(ValueError, match="symlink"):
        mod.build_release_zip(sym_static_repo, sym_out)
    assert not sym_out.exists()


def test_m5_dockerignore_tmp_readme_keystore_health_and_empty_port_healthcheck() -> None:
    # Item #8: .dockerignore excludes *.tmp and **/*.tmp
    patterns = _parse_dockerignore_patterns((REPO_ROOT / ".dockerignore").read_text(encoding="utf-8"))
    assert _dockerignore_matches("scratch.tmp", patterns)
    assert _dockerignore_matches("nested/deep/upload.tmp", patterns)

    # Item #7: README accurately attributes persistent: false to /api/keystore-info (not /health)
    readme_text = (REPO_ROOT / "README.txt").read_text(encoding="utf-8")
    assert "`/health` ve `/api/keystore-info`" not in readme_text
    assert "`/api/keystore-info`" in readme_text
    assert "`persistent: false`" in readme_text
    assert "/health?strict=true" in readme_text
    assert "HTTP 503" in readme_text

    # Item #6: Dockerfile HEALTHCHECK resolves empty PORT="" to 10000 cleanly (without ValueError)
    instructions = _parse_dockerfile_instructions((REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    hc = next(args for instr, args in instructions if instr == "HEALTHCHECK")
    snippet = json.loads(hc[hc.index("CMD") + 3 :].strip())[2]
    assert "os.environ.get('PORT') or '10000'" in snippet
    env_empty_port = os.environ.copy()
    env_empty_port["PORT"] = ""
    env_empty_port["HTTP_PROXY"] = "http://127.0.0.1:1"
    # Probe the port expression directly to prove empty PORT="" falls back to '10000'
    eval_res = subprocess.run(
        [sys.executable, "-c", "import os; print(os.environ.get('PORT') or '10000')"],
        env=env_empty_port,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert eval_res.stdout.strip() == "10000"


