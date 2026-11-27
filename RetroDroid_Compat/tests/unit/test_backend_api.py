"""Comprehensive real-toolchain backend API, job manager, async concurrency, and security tests (M2)."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import retrodroid.jobs as jobs_mod
import server as server_mod
from retrodroid.config import (
    APP_VERSION,
    CommandCanceledError,
    Settings,
    probe_android_tools,
    reset_settings_cache,
    run_cmd,
)
from retrodroid.keystore import ensure_signing_keystore, reset_keystore_state
from server import create_app

FRAMEWORK_RES = Path("/usr/share/android-framework-res/framework-res.apk")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

REQUIRED_SECURITY_HEADERS = (
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def assert_security_headers(resp: httpx.Response | Any) -> None:
    """Assert that all four mandatory M2 security headers are present with expected values."""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"
    assert "camera=()" in headers.get("permissions-policy", "")
    assert "microphone=()" in headers.get("permissions-policy", "")


# ---------------------------------------------------------------------------
# Real Android Artifact Builders (compiled on-the-fly with real `aapt`)
# ---------------------------------------------------------------------------


def make_minimal_png() -> bytes:
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\x10\xb9\x81\xff")
    return PNG_MAGIC + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def make_minimal_dex(version: str = "035", method_count: int = 24, class_count: int = 4) -> bytes:
    buf = bytearray(112)
    buf[0:8] = f"dex\n{version}\x00".encode("ascii")
    struct.pack_into("<I", buf, 32, 112)
    struct.pack_into("<I", buf, 36, 112)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<I", buf, 88, method_count)
    struct.pack_into("<I", buf, 96, class_count)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def build_real_apk(
    out_path: Path,
    *,
    package: str = "com.retro.legacy",
    label: str = "Retro's Quest",
    version_code: int = 10,
    version_name: str = "1.2.3",
    min_sdk: int = 14,
    target_sdk: int = 19,
    include_unexported: bool = True,
    split_name: str | None = None,
) -> Path:
    build_dir = out_path.parent / f"_build_{out_path.stem}_{os.getpid()}_{time.time_ns()}"
    res_dir = build_dir / "res" / "drawable"
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / "icon.png").write_bytes(make_minimal_png())

    split_attr = f' split="{split_name}"' if split_name else ""
    safe_label = (
        label.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    if include_unexported:
        comp_xml = """
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        """
    else:
        comp_xml = """
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        """

    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}"{split_attr}>
    <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="{target_sdk}" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <application android:label="{safe_label}" android:icon="@drawable/icon">
{comp_xml}
    </application>
</manifest>
"""
    manifest_file = build_dir / "AndroidManifest.xml"
    manifest_file.write_text(manifest_xml, encoding="utf-8")

    raw_apk = build_dir / "raw.apk"
    res = subprocess.run(
        [
            "aapt",
            "package",
            "-f",
            "-M",
            str(manifest_file),
            "-S",
            str(build_dir / "res"),
            "-I",
            str(FRAMEWORK_RES),
            "-F",
            str(raw_apk),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"aapt package failed: {res.stderr}\n{res.stdout}"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(raw_apk, "r") as zin, zipfile.ZipFile(out_path, "w") as zout:
        for item in zin.infolist():
            info = zipfile.ZipInfo(item.filename)
            info.date_time = item.date_time
            info.compress_type = zipfile.ZIP_STORED if item.filename == "resources.arsc" else item.compress_type
            zout.writestr(info, zin.read(item.filename))
        zout.writestr("classes.dex", make_minimal_dex())
    return out_path


@pytest.fixture(scope="session")
def sample_artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Build real synthetic APK, split APK, XAPK, and a valid JKS keystore once per session."""
    root = tmp_path_factory.mktemp("rd_m2_artifacts")
    apk_path = build_real_apk(root / "legacy_game.apk")
    split_path = build_real_apk(
        root / "config.arm64_v8a.apk",
        split_name="config.arm64_v8a",
        include_unexported=False,
    )
    obb_payload = b"RETRODROID_OBB_PAYLOAD_" * 512  # ~11.7 KiB
    xapk_path = root / "legacy_bundle.xapk"
    manifest = {
        "xapk_version": 2,
        "package_name": "com.retro.legacy",
        "name": "Retro's Quest",
        "version_code": "10",
        "version_name": "1.2.3",
        "split_apks": [
            {"file": "base.apk", "id": "base"},
            {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"},
        ],
        "expansions": [
            {
                "file": "Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb",
                "install_location": "EXTERNAL_STORAGE",
                "install_path": "Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb",
            }
        ],
    }
    with zipfile.ZipFile(xapk_path, "w") as zx:
        zx.writestr("manifest.json", json.dumps(manifest))
        zx.write(apk_path, arcname="base.apk")
        zx.write(split_path, arcname="config.arm64_v8a.apk")
        zx.writestr("Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb", obb_payload)

    # Pre-generate one valid RSA-2048 JKS keystore to speed up tests while still running real keytool -list
    ks_dir = root / "shared_ks"
    ks_dir.mkdir(parents=True, exist_ok=True)
    ks_path = ks_dir / "retrodroid.jks"
    ks_pass = "test-keystore-pass-540"

    ensure_signing_keystore(
        Settings(
            WORK_DIR=root / "ks_work",
            KEYSTORE_PATH=ks_path,
            KEYSTORE_PERSISTENT=True,
            KEYSTORE_PASS=ks_pass,
        )
    )
    reset_keystore_state()

    return {
        "apk_bytes": apk_path.read_bytes(),
        "xapk_bytes": xapk_path.read_bytes(),
        "obb_payload": obb_payload,
        "ks_path": ks_path,
        "ks_pass": ks_pass,
    }


@pytest.fixture()
def api_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sample_artifacts: dict[str, Any],
) -> dict[str, Any]:
    """Configure an isolated WORK_DIR and valid keystore per test."""
    work_dir = tmp_path / "jobs"
    work_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WORK_DIR", str(work_dir))
    monkeypatch.setenv("KEYSTORE_PATH", str(sample_artifacts["ks_path"]))
    monkeypatch.setenv("KEYSTORE_PASS", sample_artifacts["ks_pass"])
    monkeypatch.setenv("KEYSTORE_AUTO_REGEN", "false")
    monkeypatch.setenv("API_TOKEN", "")
    monkeypatch.setenv("API_ACCESS_TOKEN", "")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "0")
    monkeypatch.setenv("MAX_CONCURRENT_PATCHES", "1")
    monkeypatch.setenv("JOB_TTL_SECONDS", "3600")
    monkeypatch.setenv("MAX_UPLOAD_MB", "50")
    monkeypatch.setenv("CHUNK_SIZE_MB", "1")
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    reset_settings_cache()
    reset_keystore_state()
    yield {"work_dir": work_dir, "tmp_path": tmp_path}
    reset_settings_cache()
    reset_keystore_state()


def _analyze_apk(client: TestClient, apk_bytes: bytes, filename: str = "legacy_game.apk", headers: dict[str, str] | None = None) -> dict[str, Any]:
    resp = client.post(
        "/api/analyze",
        files={"file": (filename, apk_bytes, "application/vnd.android.package-archive")},
        headers=headers or {},
    )
    assert resp.status_code == 200, resp.text
    assert_security_headers(resp)
    return resp.json()


# ---------------------------------------------------------------------------
# F01: Architecture, UI, Static, Health, Keystore Info & Lifespan
# ---------------------------------------------------------------------------


def test_architecture_invariants_lifespan_and_framework_free_jobs() -> None:
    server_src = Path(server_mod.__file__).read_text(encoding="utf-8")
    assert "@app.on_event" not in server_src
    assert "@application.on_event" not in server_src
    assert isinstance(server_mod.app, FastAPI)

    jobs_src = inspect.getsource(jobs_mod)
    for forbidden in ("fastapi", "starlette", "uvicorn"):
        assert forbidden not in jobs_src.lower()


def test_root_ui_and_static_dynamic_serving_without_creating_static_dir(
    api_env: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_static = server_mod.BASE_DIR / "static"
    assert real_static.is_dir(), "M3 static/ directory must exist on disk"

    app = create_app()
    with TestClient(app) as client:
        r_root = client.get("/")
        assert r_root.status_code == 200
        assert "text/html" in r_root.headers["content-type"]
        assert_security_headers(r_root)

        for static_path in ("/static/app.js", "/static/styles.css", "/static/vendor/jszip.js"):
            r_static = client.get(static_path)
            assert r_static.status_code == 200
            assert_security_headers(r_static)

        r_trav = client.get("/static/../server.py")
        assert r_trav.status_code == 404
        assert_security_headers(r_trav)

        # Verify dynamic serving (404 when static/ is absent, 200 once created) + dotfile/traversal blocking
        fake_base = tmp_path / "fake_base"
        fake_base.mkdir(parents=True)
        monkeypatch.setattr(server_mod, "BASE_DIR", fake_base)

        r_missing = client.get("/static/app.js")
        assert r_missing.status_code == 404
        assert_security_headers(r_missing)

        (fake_base / "static").mkdir(parents=True)
        (fake_base / "static" / "app.js").write_text("export const ok = true;\n", encoding="utf-8")
        (fake_base / "static" / "styles.css").write_text("body { color: #fff; }", encoding="utf-8")
        (fake_base / "static" / ".hidden").write_text("secret", encoding="utf-8")
        (fake_base / "secret.txt").write_text("outside", encoding="utf-8")

        r_app_js = client.get("/static/app.js")
        assert r_app_js.status_code == 200
        assert "export const ok = true;" in r_app_js.text
        assert_security_headers(r_app_js)

        r_ok = client.get("/static/styles.css")
        assert r_ok.status_code == 200
        assert "color: #fff" in r_ok.text
        assert_security_headers(r_ok)

        assert client.get("/static/.hidden").status_code == 404
        assert client.get("/static/..%2fsecret.txt").status_code == 404


def test_health_ok_full_schema_and_keystore_info_never_leaks_password(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as client:
        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert_security_headers(r_health)
        data = r_health.json()
        assert data["status"] == "ok"
        assert data["healthy"] is True
        assert data["version"] == APP_VERSION == "5.4.0"
        assert isinstance(data["serverTime"], float)
        assert data["diskFreeMB"] > 0
        assert data["workDir"] == str(api_env["work_dir"])
        assert data["maxUploadMB"] == 50
        assert data["chunkSizeMB"] == 1
        assert data["jobTtlSeconds"] == 3600
        assert data["maxConcurrentPatches"] == 1
        assert data["activePatches"] == 0
        assert data["keystoreReady"] is True
        assert isinstance(data["keystoreFingerprintSha256"], str) and ":" in data["keystoreFingerprintSha256"]
        assert data["authRequired"] is False
        assert isinstance(data["zipalign16kSupported"], bool)
        for tool in ("aapt", "apktool", "zipalign", "apksigner", "java", "keytool"):
            assert data["tools"][tool] is True
            assert data["toolVersions"].get(tool)

        r_strict = client.get("/health?strict=true")
        assert r_strict.status_code == 200

        r_ks = client.get("/api/keystore-info")
        assert r_ks.status_code == 200
        assert_security_headers(r_ks)
        ks_json = r_ks.json()
        assert set(ks_json.keys()) == {
            "ready",
            "alias",
            "algorithm",
            "sha256",
            "subject",
            "validUntil",
            "persistent",
            "path",
        }
        assert ks_json["ready"] is True
        assert sample_artifacts["ks_pass"] not in r_ks.text
        assert "password" not in r_ks.text.lower()


def test_health_degraded_returns_200_and_strict_returns_503(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_dir = tmp_path / "degraded_jobs"
    corrupt_ks = tmp_path / "corrupt.jks"
    corrupt_ks.write_bytes(b"NOT_A_VALID_JKS_KEYSTORE")
    monkeypatch.setenv("WORK_DIR", str(work_dir))
    monkeypatch.setenv("KEYSTORE_PATH", str(corrupt_ks))
    monkeypatch.setenv("KEYSTORE_PASS", "wrong-password-123")
    monkeypatch.setenv("KEYSTORE_AUTO_REGEN", "false")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "0")
    reset_settings_cache()
    reset_keystore_state()

    app = create_app()
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert_security_headers(r)
        body = r.json()
        assert body["status"] == "degraded"
        assert body["healthy"] is False
        assert body["keystoreReady"] is False

        r_strict = client.get("/health?strict=true")
        assert r_strict.status_code == 503
        assert_security_headers(r_strict)
        assert r_strict.json()["status"] == "degraded"
        # Existing corrupt keystore must NOT have been deleted
        assert corrupt_ks.is_file()


# ---------------------------------------------------------------------------
# F03: Resumable Chunked Upload & Single-Shot Analysis
# ---------------------------------------------------------------------------


def test_chunked_upload_resume_duplicate_and_finish_real_apk(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    apk_bytes = sample_artifacts["apk_bytes"]
    total_size = len(apk_bytes)
    total_chunks = 3
    chunk_len = (total_size + total_chunks - 1) // total_chunks
    slices = [apk_bytes[i * chunk_len : (i + 1) * chunk_len] for i in range(total_chunks)]
    assert b"".join(slices) == apk_bytes

    app = create_app()
    with TestClient(app) as client:
        raw_name = "My Cool Game (v1.2) #special.apk"
        r_init = client.post(
            "/api/upload/init",
            data={"fileName": raw_name, "totalSize": str(total_size), "totalChunks": str(total_chunks)},
        )
        assert r_init.status_code == 200, r_init.text
        init_data = r_init.json()
        job_id = init_data["jobId"]
        assert init_data["fileName"] == raw_name
        assert init_data["sanitizedFileName"].endswith(".apk")
        assert len(init_data["sanitizedFileName"]) <= 120
        assert init_data["totalChunks"] == total_chunks

        # Upload chunk 0
        r_c0 = client.post(
            "/api/upload/chunk",
            data={"jobId": job_id, "chunkIndex": "0", "totalChunks": str(total_chunks)},
            files={"chunk": ("chunk0", slices[0], "application/octet-stream")},
        )
        assert r_c0.status_code == 200
        assert r_c0.json()["duplicate"] is False
        assert r_c0.json()["receivedCount"] == 1

        # Verify resumable status endpoint
        r_st = client.get(f"/api/upload/status/{job_id}")
        assert r_st.status_code == 200
        st = r_st.json()
        assert st["receivedChunks"] == [0]
        assert st["missingChunks"] == [1, 2]
        assert st["complete"] is False
        assert st["status"] == "uploading"

        # Early finish must reject with 400 WITHOUT wiping the resumable session
        r_early = client.post("/api/upload/finish", data={"jobId": job_id})
        assert r_early.status_code == 400
        assert client.get(f"/api/upload/status/{job_id}").status_code == 200

        # Duplicate chunk 0 is idempotent
        r_dup = client.post(
            "/api/upload/chunk",
            data={"jobId": job_id, "chunkIndex": "0"},
            files={"chunk": ("chunk0", slices[0], "application/octet-stream")},
        )
        assert r_dup.status_code == 200
        assert r_dup.json()["duplicate"] is True

        # Upload remaining chunks 2 then 1 (out-of-order)
        for idx in (2, 1):
            rc = client.post(
                "/api/upload/chunk",
                data={"jobId": job_id, "chunkIndex": str(idx)},
                files={"chunk": (f"chunk{idx}", slices[idx], "application/octet-stream")},
            )
            assert rc.status_code == 200, rc.text
            assert rc.json()["duplicate"] is False

        r_fin = client.post("/api/upload/finish", data={"jobId": job_id})
        assert r_fin.status_code == 200, r_fin.text
        fin = r_fin.json()
        assert fin["jobId"] == job_id
        assert fin["packageId"] == "com.retro.legacy"
        assert fin["appLabel"] == "Retro's Quest"
        assert fin["minSdk"] == 14
        assert fin["targetSdk"] == 19
        assert fin["containerType"] == "APK"
        assert fin["hasObb"] is False
        assert fin["sanitizedFileName"] == init_data["sanitizedFileName"]

        # Verify BOTH fileName and sanitizedFileName persisted in upload_meta.json and upload lock cleaned
        meta = json.loads((api_env["work_dir"] / job_id / "upload_meta.json").read_text(encoding="utf-8"))
        assert meta["fileName"] == raw_name
        assert meta["sanitizedFileName"] == init_data["sanitizedFileName"]
        assert meta["complete"] is True
        assert app.state.job_manager.lock_counts()["uploadLocks"] == 0


def test_upload_and_analyze_validation_boundaries(
    api_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAX_UPLOAD_MB", "1")
    reset_settings_cache()

    app = create_app()
    with TestClient(app) as client:
        # 0-byte rejection (400)
        assert client.post("/api/upload/init", data={"fileName": "a.apk", "totalSize": "0"}).status_code == 400
        assert (
            client.post("/api/analyze", files={"file": ("empty.apk", b"", "application/octet-stream")}).status_code
            == 400
        )

        # Oversize > MAX_UPLOAD_MB (413)
        r_big = client.post(
            "/api/upload/init",
            data={"fileName": "huge.apk", "totalSize": str(2 * 1024 * 1024)},
        )
        assert r_big.status_code == 413
        assert_security_headers(r_big)

        r_an_big = client.post(
            "/api/analyze",
            files={"file": ("huge.apk", b"A" * (1024 * 1024 + 10), "application/octet-stream")},
        )
        assert r_an_big.status_code == 413

        # Unsupported extension (400)
        assert client.post("/api/upload/init", data={"fileName": "malware.exe", "totalSize": "100"}).status_code == 400
        assert (
            client.post("/api/analyze", files={"file": ("bad.exe", b"PK\x03\x04test", "application/octet-stream")}).status_code
            == 400
        )

        # Long filename (>120 chars) sanitized to <=120 preserving .apk extension
        long_name = "a" * 170 + ".apk"
        r_long = client.post("/api/upload/init", data={"fileName": long_name, "totalSize": "512"})
        assert r_long.status_code == 200
        assert len(r_long.json()["sanitizedFileName"]) <= 120
        assert r_long.json()["sanitizedFileName"].endswith(".apk")


# ---------------------------------------------------------------------------
# F06 & F07: Real Patch & Sign Pipeline (Sync, Background, Flags, Splits, Concurrency)
# ---------------------------------------------------------------------------


def test_patch_sign_sync_all_manifest_flags_verified_with_real_tools(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    tmp_path: Path,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        an = _analyze_apk(client, sample_artifacts["apk_bytes"], "Retro Game v1.apk")
        job_id = an["jobId"]

        r_patch = client.post(
            "/api/patch-sign",
            data={
                "jobId": job_id,
                "targetSdk": "33",
                "mode": "patch_and_sign",
                "resign": "true",
                "background": "false",
                "patchTargetSdk": "true",
                "addLegacyStorage": "true",
                "enableCleartext": "true",
                "addNotchSupport": "true",
                "forceExtractNativeLibs": "true",
                "allowDowngrade": "false",
            },
        )
        assert r_patch.status_code == 200, r_patch.text
        assert_security_headers(r_patch)
        res = r_patch.json()
        assert res["ok"] is True
        assert res["verified"] is True
        assert res["targetSdk"] == 33
        assert res["repatchAvailable"] is True
        assert isinstance(res["serverTime"], float)
        assert res["patchSummary"]["manifestPatched"] is True
        assert res["patchSummary"]["method"] == "slim_apktool"
        assert res["downloadUrl"].startswith(f"/api/download/{job_id}/")
        assert " " not in res["downloadUrl"]

        # Download signed APK and independently verify with real apksigner & aapt xmltree
        r_dl = client.get(res["downloadUrl"])
        assert r_dl.status_code == 200
        assert_security_headers(r_dl)
        out_apk = tmp_path / "downloaded_patched.apk"
        out_apk.write_bytes(r_dl.content)

        verify_proc = subprocess.run(
            ["apksigner", "verify", "--verbose", str(out_apk)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert verify_proc.returncode == 0, verify_proc.stderr + verify_proc.stdout

        xml_proc = subprocess.run(
            ["aapt", "dump", "xmltree", str(out_apk), "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert xml_proc.returncode == 0, xml_proc.stderr
        tree_txt = xml_proc.stdout
        assert "targetSdkVersion" in tree_txt and "0x21" in tree_txt  # 33 == 0x21
        assert "requestLegacyExternalStorage" in tree_txt
        assert "usesCleartextTraffic" in tree_txt
        assert "android.max_aspect" in tree_txt
        assert "extractNativeLibs" in tree_txt
        assert "exported" in tree_txt


def test_patch_sign_background_and_xapk_split_bundle_download(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    tmp_path: Path,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        r_an = client.post(
            "/api/analyze",
            files={"file": ("legacy_bundle.xapk", sample_artifacts["xapk_bytes"], "application/octet-stream")},
        )
        assert r_an.status_code == 200, r_an.text
        an = r_an.json()
        job_id = an["jobId"]
        assert an["containerType"] == "XAPK"
        assert an["hasObb"] is True
        assert len(an["splitApks"]) == 1

        r_bg = client.post(
            "/api/patch-sign",
            data={"jobId": job_id, "targetSdk": "28", "background": "true"},
        )
        assert r_bg.status_code == 200, r_bg.text
        bg = r_bg.json()
        assert bg["jobId"] == job_id
        assert bg["status"] == "running"

        # Poll until done
        final_status: dict[str, Any] | None = None
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            rs = client.get(f"/api/patch-status/{job_id}")
            assert rs.status_code == 200
            st = rs.json()
            assert isinstance(st["serverTime"], float)
            assert isinstance(st["expiresInSeconds"], int)
            if st["status"] in {"done", "error", "canceled"}:
                final_status = st
                break
            time.sleep(0.15)
        assert final_status is not None
        assert final_status["status"] == "done", final_status
        result = final_status["result"]
        assert result["verified"] is True
        assert result["targetSdk"] == 28
        assert result["splitBundle"] is not None

        # Download split .apks bundle and verify contents
        r_bundle = client.get(result["splitBundle"]["downloadUrl"])
        assert r_bundle.status_code == 200
        bundle_path = tmp_path / "out.apks"
        bundle_path.write_bytes(r_bundle.content)
        with zipfile.ZipFile(bundle_path, "r") as zb:
            names = set(zb.namelist())
            assert "base.apk" in names
            assert "config.arm64_v8a.apk" in names


def test_patch_sign_concurrency_409_same_job_and_429_second_job(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    real_pipeline = server_mod.patch_and_sign_pipeline

    def _gated_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        entered.set()
        release.wait(timeout=15.0)
        return real_pipeline(*args, **kwargs)

    monkeypatch.setattr(server_mod, "patch_and_sign_pipeline", _gated_pipeline)

    app = create_app()
    with TestClient(app) as client:
        job_a = _analyze_apk(client, sample_artifacts["apk_bytes"], "a.apk")["jobId"]
        job_b = _analyze_apk(client, sample_artifacts["apk_bytes"], "b.apk")["jobId"]

        r_start = client.post("/api/patch-sign", data={"jobId": job_a, "background": "true"})
        assert r_start.status_code == 200
        assert entered.wait(timeout=5.0), "Background worker did not enter pipeline"

        # Same job while running -> 409
        r_dup = client.post("/api/patch-sign", data={"jobId": job_a, "background": "true"})
        assert r_dup.status_code == 409
        assert_security_headers(r_dup)

        # Different job while MAX_CONCURRENT_PATCHES=1 -> 429
        r_full = client.post("/api/patch-sign", data={"jobId": job_b, "background": "true"})
        assert r_full.status_code == 429
        assert_security_headers(r_full)

        # Also DELETE on active job must fail with 409
        assert client.delete(f"/api/jobs/{job_a}").status_code == 409

        release.set()
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            st = client.get(f"/api/patch-status/{job_a}").json()
            if st["status"] == "done":
                break
            time.sleep(0.1)
        assert client.get(f"/api/patch-status/{job_a}").json()["status"] == "done"
        assert client.get("/health").json()["activePatches"] == 0


# ---------------------------------------------------------------------------
# F09: Non-Blocking Event Loop, Restart Persistence, Cancel, Delete & Janitor
# ---------------------------------------------------------------------------


def test_health_stays_nonblocking_under_200ms_during_real_sync_patch(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()

    # Initialize keystore & tool probe once beforehand (as lifespan does in production)
    with TestClient(app) as setup_client:
        job_id = _analyze_apk(setup_client, sample_artifacts["apk_bytes"], "async_test.apk")["jobId"]

    async def _run_concurrent() -> tuple[httpx.Response, list[float]]:
        latencies_ms: list[float] = []
        patch_done = asyncio.Event()

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            async def _do_patch() -> httpx.Response:
                try:
                    return await ac.post(
                        "/api/patch-sign",
                        data={
                            "jobId": job_id,
                            "targetSdk": "33",
                            "addLegacyStorage": "true",
                            "background": "false",
                        },
                        timeout=60.0,
                    )
                finally:
                    patch_done.set()

            async def _probe_health() -> None:
                while not patch_done.is_set():
                    t0 = time.perf_counter()
                    r = await ac.get("/health")
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    assert r.status_code == 200
                    assert_security_headers(r)
                    latencies_ms.append(dt_ms)
                    await asyncio.sleep(0.03)

            patch_resp, _ = await asyncio.gather(_do_patch(), _probe_health())
            return patch_resp, latencies_ms

    patch_resp, latencies_ms = asyncio.run(_run_concurrent())
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["verified"] is True
    assert len(latencies_ms) >= 3, f"Expected multiple concurrent health probes, got {len(latencies_ms)}"
    assert max(latencies_ms) < 200.0, f"Event loop stalled! Health latencies (ms): {latencies_ms}"


def test_job_state_persists_across_restart_and_recovers_stale_running(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    work_dir = api_env["work_dir"]
    app1 = create_app()
    with TestClient(app1) as client1:
        job_done = _analyze_apk(client1, sample_artifacts["apk_bytes"], "done.apk")["jobId"]
        r_p = client1.post("/api/patch-sign", data={"jobId": job_done, "targetSdk": "28"})
        assert r_p.status_code == 200

        job_stale = _analyze_apk(client1, sample_artifacts["apk_bytes"], "stale.apk")["jobId"]
        # Simulate crash mid-run by persisting "running" in job_state.json
        stale_state = {
            "jobId": job_stale,
            "status": "running",
            "progress": 42,
            "stage": "Apktool çalışıyor",
            "logs": ["started"],
            "result": None,
            "error": None,
            "createdAt": time.time() - 10,
            "updatedAt": time.time() - 5,
            "finishedAt": None,
            "fullXapk": {
                "status": "running",
                "progress": 30,
                "stage": "XAPK yazılıyor",
                "logs": [],
                "result": None,
                "error": None,
                "startedAt": time.time() - 5,
                "finishedAt": None,
                "updatedAt": time.time() - 5,
            },
        }
        (work_dir / job_stale / "job_state.json").write_text(json.dumps(stale_state), encoding="utf-8")

    # Fresh app instance simulating full server restart on same WORK_DIR
    app2 = create_app()
    with TestClient(app2) as client2:
        r_done = client2.get(f"/api/patch-status/{job_done}")
        assert r_done.status_code == 200
        assert r_done.json()["status"] == "done"
        assert r_done.json()["result"]["verified"] is True
        assert r_done.json()["expiresInSeconds"] > 0

        r_stale = client2.get(f"/api/patch-status/{job_stale}")
        assert r_stale.status_code == 200
        assert r_stale.json()["status"] == "interrupted"

        r_stale_xapk = client2.get(f"/api/full-xapk-status/{job_stale}")
        assert r_stale_xapk.status_code == 200
        assert r_stale_xapk.json()["status"] == "interrupted"

        r_jobs = client2.get("/api/jobs")
        assert r_jobs.status_code == 200
        jobs_payload = r_jobs.json()
        assert jobs_payload["linkTtlSeconds"] == 3600
        assert isinstance(jobs_payload["serverTime"], float)
        ids = {j["jobId"]: j for j in jobs_payload["jobs"]}
        assert job_done in ids and job_stale in ids
        assert ids[job_done]["status"] == "done"
        assert ids[job_stale]["status"] == "interrupted"
        assert isinstance(ids[job_done]["expiresInSeconds"], int)


def test_patch_cancel_terminates_real_subprocess_and_409_when_not_cancelable(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc_started = threading.Event()

    def _long_subprocess_pipeline(
        *,
        cancel_event: threading.Event | None = None,
        on_proc: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        def _wrap_on_proc(proc: subprocess.Popen[str]) -> None:
            if on_proc is not None:
                on_proc(proc)
            proc_started.set()

        run_cmd(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=35,
            cancel_event=cancel_event,
            on_proc=_wrap_on_proc,
        )
        return {"ok": True}

    monkeypatch.setattr(server_mod, "patch_and_sign_pipeline", _long_subprocess_pipeline)

    app = create_app()
    with TestClient(app) as client:
        job_id = _analyze_apk(client, sample_artifacts["apk_bytes"], "cancel_me.apk")["jobId"]

        # Not running yet -> 409
        assert client.post(f"/api/patch-cancel/{job_id}").status_code == 409
        # Missing job -> 404
        assert client.post("/api/patch-cancel/000000000000").status_code == 404
        # Invalid job id -> 400
        assert client.post("/api/patch-cancel/not-hex-id").status_code == 400

        r_bg = client.post("/api/patch-sign", data={"jobId": job_id, "background": "true"})
        assert r_bg.status_code == 200
        assert proc_started.wait(timeout=5.0)

        t0 = time.monotonic()
        r_cancel = client.post(f"/api/patch-cancel/{job_id}")
        assert r_cancel.status_code == 200
        assert r_cancel.json() == {"ok": True, "jobId": job_id, "status": "canceled"}

        # Slot must release promptly once child subprocess terminates
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if app.state.job_manager.active_patch_count == 0:
                break
            time.sleep(0.05)
        assert app.state.job_manager.active_patch_count == 0
        assert (time.monotonic() - t0) < 5.0
        assert client.get(f"/api/patch-status/{job_id}").json()["status"] == "canceled"

        # Canceling an already-canceled job returns 409
        assert client.post(f"/api/patch-cancel/{job_id}").status_code == 409


def test_delete_job_and_activity_safe_ttl_janitor(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        job1 = _analyze_apk(client, sample_artifacts["apk_bytes"], "j1.apk")["jobId"]
        job2 = _analyze_apk(client, sample_artifacts["apk_bytes"], "j2.apk")["jobId"]
        jm = app.state.job_manager

        # Delete blocked with 409 while active ref held
        with jm.hold_active(job1):
            assert client.delete(f"/api/jobs/{job1}").status_code == 409

        # Idle delete succeeds and cleans locks
        r_del = client.delete(f"/api/jobs/{job1}")
        assert r_del.status_code == 200
        assert r_del.json() == {"ok": True, "jobId": job1, "deleted": True}
        assert not (api_env["work_dir"] / job1).exists()
        assert client.get(f"/api/patch-status/{job1}").status_code == 404
        assert client.delete(f"/api/jobs/{job1}").status_code == 404

        # Activity-safe TTL janitor test (real wall-clock TTL expiration)
        job_active = _analyze_apk(client, sample_artifacts["apk_bytes"], "active.apk")["jobId"]
        ks_placeholder = api_env["work_dir"] / "_keystore"
        ks_placeholder.mkdir(exist_ok=True)
        monkeypatch.setenv("JOB_TTL_SECONDS", "1")
        reset_settings_cache()

        with jm.hold_active(job_active):
            time.sleep(1.25)
            removed = jm.cleanup_old_jobs()
            assert removed == 1
            assert not (api_env["work_dir"] / job2).exists()
            assert (api_env["work_dir"] / job_active).is_dir()
            assert ks_placeholder.is_dir()


# ---------------------------------------------------------------------------
# F08: OBB Attach (Multipart + Chunked), Full XAPK v2 (Sync + Bg) & Download OBB
# ---------------------------------------------------------------------------


def test_attach_obb_multipart_and_full_xapk_sync_v2(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    tmp_path: Path,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        an = _analyze_apk(client, sample_artifacts["apk_bytes"], "game.apk")
        job_id = an["jobId"]

        # Full XAPK before patch -> 409
        assert client.post(f"/api/full-xapk/{job_id}").status_code == 409

        # Patch-sign first
        assert client.post("/api/patch-sign", data={"jobId": job_id, "targetSdk": "28"}).status_code == 200

        # Full XAPK with zero OBBs -> 400
        assert client.post(f"/api/full-xapk/{job_id}").status_code == 400

        # Reject 0-byte OBB and traversal OBB with 400
        assert (
            client.post(
                f"/api/attach-obb/{job_id}",
                files=[("files", ("main.10.com.retro.legacy.obb", b"", "application/octet-stream"))],
            ).status_code
            == 400
        )
        assert (
            client.post(
                f"/api/attach-obb/{job_id}",
                files=[("files", ("../evil.obb", b"abc", "application/octet-stream"))],
            ).status_code
            == 400
        )

        # Attach valid nested OBB (must strip Android/obb/<pkg>/ to prevent double nesting) + non-canonical OBB
        obb1 = b"MAIN_OBB_DATA_" * 200
        obb2 = b"CUSTOM_OBB_DATA_" * 100
        r_att = client.post(
            f"/api/attach-obb/{job_id}",
            files=[
                (
                    "files",
                    (
                        "Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb",
                        obb1,
                        "application/octet-stream",
                    ),
                ),
                ("files", ("custom_extra.obb", obb2, "application/octet-stream")),
            ],
        )
        assert r_att.status_code == 200, r_att.text
        att = r_att.json()
        assert att["ok"] is True
        assert att["count"] == 2
        assert att["totalSizeBytes"] == len(obb1) + len(obb2)
        by_name = {f["name"]: f for f in att["files"]}
        assert by_name["main.10.com.retro.legacy.obb"]["normalizedPath"] == "main.10.com.retro.legacy.obb"
        assert by_name["main.10.com.retro.legacy.obb"]["validObbName"] is True
        assert by_name["main.10.com.retro.legacy.obb"]["warning"] is None
        assert by_name["custom_extra.obb"]["validObbName"] is False
        assert by_name["custom_extra.obb"]["warning"]
        # Ensure internal disk filePath is NOT leaked in API response
        for f in att["files"]:
            assert "filePath" not in f

        # Build Full XAPK v2 synchronously
        r_fx = client.post(f"/api/full-xapk/{job_id}", data={"background": "false"})
        assert r_fx.status_code == 200, r_fx.text
        fx = r_fx.json()
        assert fx["ok"] is True
        assert fx["downloadUrl"] == f"/api/download-full-xapk/{job_id}"
        assert fx["manifest"]["xapk_version"] == 2
        assert fx["manifest"]["package_name"] == "com.retro.legacy"
        assert fx["manifest"]["target_sdk_version"] == "28"
        assert fx["manifest"]["total_size"] > 0
        assert "android.permission.INTERNET" in fx["manifest"]["permissions"]

        # Download and verify Full XAPK contents (icon.png, manifest.json, NO double-nested OBB path)
        r_dl = client.get(fx["downloadUrl"])
        assert r_dl.status_code == 200
        assert_security_headers(r_dl)
        xapk_out = tmp_path / "full.xapk"
        xapk_out.write_bytes(r_dl.content)
        with zipfile.ZipFile(xapk_out, "r") as zx:
            names = set(zx.namelist())
            assert "manifest.json" in names
            assert "icon.png" in names
            assert "RETRODROID-INSTALL.txt" in names
            assert "Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb" in names
            assert not any("com.retro.legacy/com.retro.legacy" in n for n in names)
            assert zx.read("Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb") == obb1
            manifest_in_zip = json.loads(zx.read("manifest.json").decode("utf-8"))
            assert manifest_in_zip["target_sdk_version"] == "28"
            install_txt = zx.read("RETRODROID-INSTALL.txt").decode("utf-8")
            assert "targetSdk: 28" in install_txt
            assert "targetSdk: 19" not in install_txt


def test_attach_obb_chunked_and_full_xapk_background(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as client:
        job_id = _analyze_apk(client, sample_artifacts["apk_bytes"], "chunked_obb_game.apk")["jobId"]
        assert client.post("/api/patch-sign", data={"jobId": job_id, "targetSdk": "28"}).status_code == 200

        obb_bytes = b"CHUNKED_OBB_PAYLOAD_1234567890" * 300
        mid = (len(obb_bytes) + 1) // 2
        c0, c1 = obb_bytes[:mid], obb_bytes[mid:]

        r_init = client.post(
            f"/api/attach-obb/{job_id}/init",
            data={
                "fileName": "com.retro.legacy/main.10.com.retro.legacy.obb",
                "totalSize": str(len(obb_bytes)),
                "totalChunks": "2",
            },
        )
        assert r_init.status_code == 200, r_init.text
        upload_id = r_init.json()["uploadId"]
        assert r_init.json()["normalizedPath"] == "main.10.com.retro.legacy.obb"

        for idx, part in enumerate((c0, c1)):
            rc = client.post(
                f"/api/attach-obb/{job_id}/chunk",
                data={"uploadId": upload_id, "chunkIndex": str(idx), "totalChunks": "2"},
                files={"chunk": (f"obb_{idx}", part, "application/octet-stream")},
            )
            assert rc.status_code == 200, rc.text

        # Duplicate chunk retry is idempotent
        r_dup = client.post(
            f"/api/attach-obb/{job_id}/chunk",
            data={"uploadId": upload_id, "chunkIndex": "0"},
            files={"chunk": ("obb_0", c0, "application/octet-stream")},
        )
        assert r_dup.status_code == 200
        assert r_dup.json()["duplicate"] is True

        r_fin = client.post(f"/api/attach-obb/{job_id}/finish", data={"uploadId": upload_id})
        assert r_fin.status_code == 200, r_fin.text
        assert r_fin.json()["count"] == 1
        assert r_fin.json()["totalSizeBytes"] == len(obb_bytes)

        # Download attached extra OBB via /api/download-obb/{job_id}/0
        r_dl_obb = client.get(f"/api/download-obb/{job_id}/0")
        assert r_dl_obb.status_code == 200
        assert r_dl_obb.content == obb_bytes

        # Background Full XAPK build + status polling
        r_bg = client.post(f"/api/full-xapk/{job_id}", data={"background": "true"})
        assert r_bg.status_code == 200
        assert r_bg.json()["status"] == "running"

        done_payload = None
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            rs = client.get(f"/api/full-xapk-status/{job_id}")
            assert rs.status_code == 200
            st = rs.json()
            if st["status"] in {"done", "error"}:
                done_payload = st
                break
            time.sleep(0.1)
        assert done_payload is not None and done_payload["status"] == "done", done_payload

        r_xapk = client.get(f"/api/download-full-xapk/{job_id}")
        assert r_xapk.status_code == 200
        assert r_xapk.content[:2] == b"PK"


def test_download_obb_concurrent_unique_temp_and_cleanup(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as setup_client:
        r_an = setup_client.post(
            "/api/analyze",
            files={"file": ("bundle.xapk", sample_artifacts["xapk_bytes"], "application/octet-stream")},
        )
        assert r_an.status_code == 200
        job_id = r_an.json()["jobId"]

    async def _download_many() -> list[httpx.Response]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            return await asyncio.gather(
                *[ac.get(f"/api/download-obb/{job_id}/0") for _ in range(5)]
            )

    responses = asyncio.run(_download_many())
    for resp in responses:
        assert resp.status_code == 200
        assert resp.content == sample_artifacts["obb_payload"]
        assert_security_headers(resp)

    # BackgroundTask cleanup must leave zero temp files and release all active refs
    extracted_obb_dir = api_env["work_dir"] / job_id / "_extracted_obb"
    leftovers = list(extracted_obb_dir.iterdir()) if extracted_obb_dir.exists() else []
    assert leftovers == [], f"Leftover temp OBB files found: {leftovers}"
    assert app.state.job_manager.active_refs(job_id) == 0

    with TestClient(app) as client:
        assert client.get(f"/api/download-obb/{job_id}/-1").status_code == 400
        assert client.get(f"/api/download-obb/{job_id}/99").status_code == 404


# ---------------------------------------------------------------------------
# F10: API Security — Token Auth, Download Allowlist, Job ID, CORS, Rate Limit, Headers
# ---------------------------------------------------------------------------


def test_api_token_auth_headers_download_query_and_exemptions(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "rd-super-secret-token-2026"
    monkeypatch.setenv("API_TOKEN", token)
    reset_settings_cache()

    app = create_app()
    with TestClient(app) as client:
        # Public endpoints remain exempt
        r_root = client.get("/")
        assert r_root.status_code == 200
        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["authRequired"] is True

        # Protected endpoints reject missing, wrong, and query-param tokens
        for bad_headers in ({}, {"Authorization": "Bearer wrong"}, {"X-API-Token": "wrong"}):
            r = client.get("/api/jobs", headers=bad_headers)
            assert r.status_code == 401
            assert r.headers.get("www-authenticate") == "Bearer"
            assert_security_headers(r)

        # ?token= MUST NOT work on non-download API endpoints!
        assert client.get(f"/api/jobs?token={token}").status_code == 401
        assert client.get(f"/api/keystore-info?token={token}").status_code == 401

        # Authorization: Bearer and X-API-Token both succeed
        assert client.get("/api/jobs", headers={"Authorization": f"Bearer {token}"}).status_code == 200
        assert client.get("/api/keystore-info", headers={"X-API-Token": token}).status_code == 200

        # Upload, patch, and verify ?token= works ONLY on GET /api/download*
        auth_hdr = {"Authorization": f"Bearer {token}"}
        job_id = _analyze_apk(client, sample_artifacts["apk_bytes"], "auth.apk", headers=auth_hdr)["jobId"]
        r_patch = client.post("/api/patch-sign", data={"jobId": job_id, "targetSdk": "28"}, headers=auth_hdr)
        assert r_patch.status_code == 200
        dl_url = r_patch.json()["downloadUrl"]

        assert client.get(dl_url).status_code == 401
        r_qdl = client.get(f"{dl_url}?token={urllib.parse.quote(token)}")
        assert r_qdl.status_code == 200
        assert r_qdl.content[:2] == b"PK"


def test_download_strict_allowlist_blocks_raw_uploads_metadata_and_secrets(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as client:
        an = _analyze_apk(client, sample_artifacts["apk_bytes"], "raw_original.apk")
        job_id = an["jobId"]
        jdir = api_env["work_dir"] / job_id

        # Plant sensitive-looking files in job_dir to prove strict allowlist enforcement
        (jdir / "leaked.jks").write_bytes(b"fake-keystore")
        (jdir / "leaked.jks.pass").write_text("supersecret", encoding="utf-8")
        (jdir / "_work").mkdir(exist_ok=True)
        (jdir / "_work" / "temp.apk").write_bytes(b"temp")

        r_patch = client.post("/api/patch-sign", data={"jobId": job_id, "targetSdk": "28"})
        assert r_patch.status_code == 200
        signed_url = r_patch.json()["downloadUrl"]

        # Recorded signed output succeeds
        assert client.get(signed_url).status_code == 200

        # Non-allowlisted files MUST be rejected with 403 (or 404 for nested _work/...)
        for forbidden_name in (
            "raw_original.apk",
            "upload_meta.json",
            "job_state.json",
            "patch_result.json",
            "leaked.jks",
            "leaked.jks.pass",
            "_work",
        ):
            r = client.get(f"/api/download/{job_id}/{forbidden_name}")
            assert r.status_code == 403, f"Expected 403 for {forbidden_name}, got {r.status_code}"
            assert_security_headers(r)

        assert client.get(f"/api/download/{job_id}/_work/temp.apk").status_code == 404


def test_invalid_job_id_rejected_with_400_on_every_job_route(api_env: dict[str, Any]) -> None:
    app = create_app()
    bad_ids = ("SHORT", "UPPERCASE123", "zzzzzzzzzzzz", "0123456789abc")
    with TestClient(app) as client:
        for bad in bad_ids:
            assert client.get(f"/api/upload/status/{bad}").status_code == 400
            assert client.post("/api/upload/finish", data={"jobId": bad}).status_code == 400
            assert client.post("/api/patch-sign", data={"jobId": bad}).status_code == 400
            assert client.get(f"/api/patch-status/{bad}").status_code == 400
            assert client.post(f"/api/patch-cancel/{bad}").status_code == 400
            assert client.delete(f"/api/jobs/{bad}").status_code == 400
            assert client.post(f"/api/full-xapk/{bad}").status_code == 400
            assert client.get(f"/api/full-xapk-status/{bad}").status_code == 400
            assert client.get(f"/api/download-full-xapk/{bad}").status_code == 400
            assert client.get(f"/api/download/{bad}/file.apk").status_code == 400
            assert client.get(f"/api/download-obb/{bad}/0").status_code == 400


def test_cors_origins_and_never_wildcard_with_credentials(
    api_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        # Default safe localhost origin allowed; untrusted origin rejected
        r_ok = client.get("/health", headers={"Origin": "http://localhost:8000"})
        assert r_ok.headers.get("access-control-allow-origin") == "http://localhost:8000"
        assert r_ok.headers.get("access-control-allow-credentials") is None

        r_bad = client.get("/health", headers={"Origin": "https://evil.example"})
        assert r_bad.headers.get("access-control-allow-origin") is None

        # Dynamic env change respected immediately
        monkeypatch.setenv("ALLOWED_ORIGINS", "https://trusted.example.com")
        reset_settings_cache()
        r_dyn = client.get("/health", headers={"Origin": "https://trusted.example.com"})
        assert r_dyn.headers.get("access-control-allow-origin") == "https://trusted.example.com"
        assert client.get("/health", headers={"Origin": "http://localhost:8000"}).headers.get(
            "access-control-allow-origin"
        ) is None

        # Even with wildcard origin, credentials must NEVER be enabled
        monkeypatch.setenv("ALLOWED_ORIGINS", "*")
        reset_settings_cache()
        r_star = client.get("/health", headers={"Origin": "https://any.example"})
        assert r_star.headers.get("access-control-allow-origin") == "*"
        assert r_star.headers.get("access-control-allow-credentials") is None


def test_rate_limit_enforced_and_zero_disables(
    api_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "3")
    reset_settings_cache()

    app = create_app()
    with TestClient(app) as client:
        for _ in range(3):
            r = client.get("/api/jobs")
            assert r.status_code == 200
            assert_security_headers(r)

        r_429 = client.get("/api/jobs")
        assert r_429.status_code == 429
        assert int(r_429.headers.get("retry-after", "0")) >= 1
        assert_security_headers(r_429)

        # Setting RATE_LIMIT_PER_MIN=0 disables rate limiting immediately
        monkeypatch.setenv("RATE_LIMIT_PER_MIN", "0")
        reset_settings_cache()
        for _ in range(5):
            assert client.get("/api/jobs").status_code == 200


def test_security_headers_on_validation_422_and_internal_500(
    api_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        # 422 validation error (missing required form fields)
        r_422 = client.post("/api/upload/init", data={})
        assert r_422.status_code == 422
        assert_security_headers(r_422)

        # 500 internal error (unexpected exception does not leak traceback & keeps security headers)
        def _boom() -> dict[str, Any]:
            raise RuntimeError("sensitive internal detail xyz")

        monkeypatch.setattr(server_mod, "get_keystore_info", _boom)
        r_500 = client.get("/api/keystore-info")
        assert r_500.status_code == 500
        assert_security_headers(r_500)
        assert "sensitive internal detail" not in r_500.text


def test_probe_android_tools_cached_fast() -> None:
    probe_android_tools()
    t0 = time.perf_counter()
    info = probe_android_tools()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert info["tools"]["aapt"] is True
    assert elapsed_ms < 50.0


# ---------------------------------------------------------------------------
# M2 Iteration 2 Regression Suite (rev F1-F8, chal C1-C5, chal L1-L4)
# ---------------------------------------------------------------------------


def test_download_range_416_and_400_zero_ref_and_temp_obb_leak(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as client:
        r_an = client.post(
            "/api/analyze",
            files={"file": ("bundle.xapk", sample_artifacts["xapk_bytes"], "application/octet-stream")},
        )
        assert r_an.status_code == 200, r_an.text
        job_id = r_an.json()["jobId"]

        r_patch = client.post("/api/patch-sign", data={"jobId": job_id, "targetSdk": "28"})
        assert r_patch.status_code == 200, r_patch.text
        signed_url = r_patch.json()["downloadUrl"]

        r_fx = client.post(f"/api/full-xapk/{job_id}", data={"background": "false"})
        assert r_fx.status_code == 200, r_fx.text
        fx_url = r_fx.json()["downloadUrl"]

        jm = app.state.job_manager

        # Range 416 on /api/download-obb must release active ref AND delete temp OBB file
        r_416_obb = client.get(f"/api/download-obb/{job_id}/0", headers={"Range": "bytes=999999999-"})
        assert r_416_obb.status_code == 416
        assert_security_headers(r_416_obb)
        assert jm.active_refs(job_id) == 0
        extracted_obb_dir = api_env["work_dir"] / job_id / "_extracted_obb"
        leftovers = list(extracted_obb_dir.iterdir()) if extracted_obb_dir.exists() else []
        assert leftovers == [], f"Temp OBB leaked after 416: {leftovers}"

        # Range 400 on /api/download must release active ref
        r_400_dl = client.get(signed_url, headers={"Range": "invalid"})
        assert r_400_dl.status_code == 400
        assert_security_headers(r_400_dl)
        assert jm.active_refs(job_id) == 0

        # Range 416 on /api/download-full-xapk must release active ref
        r_416_fx = client.get(fx_url, headers={"Range": "bytes=999999999-"})
        assert r_416_fx.status_code == 416
        assert_security_headers(r_416_fx)
        assert jm.active_refs(job_id) == 0

        # Valid 206 partial content also cleans up cleanly
        r_206 = client.get(f"/api/download-obb/{job_id}/0", headers={"Range": "bytes=0-15"})
        assert r_206.status_code == 206
        assert r_206.content == sample_artifacts["obb_payload"][:16]
        assert jm.active_refs(job_id) == 0
        leftovers_after_206 = list(extracted_obb_dir.iterdir()) if extracted_obb_dir.exists() else []
        assert leftovers_after_206 == []

        # Job must be immediately deletable (proving zero leaked active_refs)
        r_del = client.delete(f"/api/jobs/{job_id}")
        assert r_del.status_code == 200, r_del.text


def test_download_obb_high_concurrency_burst_zero_500_race(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as setup_client:
        r_an = setup_client.post(
            "/api/analyze",
            files={"file": ("burst.xapk", sample_artifacts["xapk_bytes"], "application/octet-stream")},
        )
        assert r_an.status_code == 200, r_an.text
        job_id = r_an.json()["jobId"]

    async def _run_burst() -> list[tuple[int, bytes]]:
        results: list[tuple[int, bytes]] = []
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            for _wave in range(6):
                resps = await asyncio.gather(
                    *[ac.get(f"/api/download-obb/{job_id}/0") for _ in range(12)]
                )
                for resp in resps:
                    results.append((resp.status_code, resp.content))
        return results

    burst_results = asyncio.run(_run_burst())
    assert len(burst_results) == 72
    expected = sample_artifacts["obb_payload"]
    failures = [status for status, body in burst_results if status != 200 or body != expected]
    assert failures == [], f"Concurrent download-obb failures: {failures}"

    extracted_obb_dir = api_env["work_dir"] / job_id / "_extracted_obb"
    leftovers = list(extracted_obb_dir.iterdir()) if extracted_obb_dir.exists() else []
    assert leftovers == [], f"Leftover temp OBBs after concurrent burst: {leftovers}"
    assert app.state.job_manager.active_refs(job_id) == 0


def test_duplicate_upload_finish_409_preserves_state_and_failed_finish_forgets(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk_bytes = sample_artifacts["apk_bytes"]
    app = create_app()
    with TestClient(app) as client:
        # Part A: Replay /api/upload/finish after completed patch must return 409 without wiping done state
        r_init = client.post(
            "/api/upload/init",
            data={"fileName": "replay.apk", "totalSize": str(len(apk_bytes)), "totalChunks": "1"},
        )
        assert r_init.status_code == 200
        job_done = r_init.json()["jobId"]
        assert (
            client.post(
                "/api/upload/chunk",
                data={"jobId": job_done, "chunkIndex": "0", "totalChunks": "1"},
                files={"chunk": ("c0", apk_bytes, "application/octet-stream")},
            ).status_code
            == 200
        )
        assert client.post("/api/upload/finish", data={"jobId": job_done}).status_code == 200
        assert client.post("/api/patch-sign", data={"jobId": job_done, "targetSdk": "28"}).status_code == 200

        r_replay = client.post("/api/upload/finish", data={"jobId": job_done})
        assert r_replay.status_code == 409
        assert_security_headers(r_replay)
        st_after = client.get(f"/api/patch-status/{job_done}").json()
        assert st_after["status"] == "done"
        assert st_after["result"] is not None and st_after["result"]["verified"] is True
        assert app.state.job_manager.lock_counts()["uploadLocks"] == 0

        # Part B: Replay /api/upload/finish during active background patch must return 409 & keep cancel working
        proc_started = threading.Event()

        def _slow_patch(*, cancel_event: threading.Event | None = None, on_proc: Any = None, **kwargs: Any) -> dict[str, Any]:
            def _wrap(proc: subprocess.Popen[str]) -> None:
                if on_proc is not None:
                    on_proc(proc)
                proc_started.set()

            run_cmd(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=35,
                cancel_event=cancel_event,
                on_proc=_wrap,
            )
            return {"ok": True}

        monkeypatch.setattr(server_mod, "patch_and_sign_pipeline", _slow_patch)
        r_init2 = client.post(
            "/api/upload/init",
            data={"fileName": "active_replay.apk", "totalSize": str(len(apk_bytes)), "totalChunks": "1"},
        )
        job_active = r_init2.json()["jobId"]
        assert (
            client.post(
                "/api/upload/chunk",
                data={"jobId": job_active, "chunkIndex": "0", "totalChunks": "1"},
                files={"chunk": ("c0", apk_bytes, "application/octet-stream")},
            ).status_code
            == 200
        )
        assert client.post("/api/upload/finish", data={"jobId": job_active}).status_code == 200
        assert client.post("/api/patch-sign", data={"jobId": job_active, "background": "true"}).status_code == 200
        assert proc_started.wait(timeout=5.0)

        r_replay_active = client.post("/api/upload/finish", data={"jobId": job_active})
        assert r_replay_active.status_code == 409
        assert client.get(f"/api/patch-status/{job_active}").json()["status"] == "running"

        r_cancel = client.post(f"/api/patch-cancel/{job_active}")
        assert r_cancel.status_code == 200
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and app.state.job_manager.active_patch_count > 0:
            time.sleep(0.05)
        assert app.state.job_manager.active_patch_count == 0
        assert client.get(f"/api/patch-status/{job_active}").json()["status"] == "canceled"

        # Part C (chal L4): Failed first-time finish on corrupt archive deletes jdir AND immediately forgets registries
        bad_bytes = b"THIS_IS_NOT_A_VALID_ZIP_OR_APK_FILE"
        r_init3 = client.post(
            "/api/upload/init",
            data={"fileName": "corrupt.apk", "totalSize": str(len(bad_bytes)), "totalChunks": "1"},
        )
        job_bad = r_init3.json()["jobId"]
        assert (
            client.post(
                "/api/upload/chunk",
                data={"jobId": job_bad, "chunkIndex": "0", "totalChunks": "1"},
                files={"chunk": ("c0", bad_bytes, "application/octet-stream")},
            ).status_code
            == 200
        )
        r_bad_fin = client.post("/api/upload/finish", data={"jobId": job_bad})
        assert r_bad_fin.status_code == 400
        assert not (api_env["work_dir"] / job_bad).exists()
        jm = app.state.job_manager
        assert job_bad not in jm._job_locks
        assert job_bad not in jm._upload_locks
        assert job_bad not in jm._persist_locks
        assert not any(k[1] == job_bad for k in jm._jobs)


def test_download_same_dir_symlink_and_extra_obb_symlink_blocked(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as client:
        an = _analyze_apk(client, sample_artifacts["apk_bytes"], "symlink_test.apk")
        job_id = an["jobId"]
        jdir = api_env["work_dir"] / job_id

        r_patch = client.post("/api/patch-sign", data={"jobId": job_id, "targetSdk": "28"})
        assert r_patch.status_code == 200, r_patch.text
        signed_name = r_patch.json()["fileName"]

        r_obb = client.post(
            f"/api/attach-obb/{job_id}",
            files=[("files", ("main.10.com.retro.legacy.obb", b"REAL_OBB_CONTENT", "application/octet-stream"))],
        )
        assert r_obb.status_code == 200, r_obb.text

        r_fx = client.post(f"/api/full-xapk/{job_id}", data={"background": "false"})
        assert r_fx.status_code == 200, r_fx.text
        fx_name = r_fx.json()["fileName"]

        # Plant forbidden sibling secret inside job_dir
        secret_file = jdir / "secret.pass"
        secret_file.write_bytes(b"SECRET_KEYSTORE_PASSWORD")

        # Replace allowlisted signed APK with a same-directory symlink to secret.pass
        signed_path = jdir / signed_name
        signed_path.unlink()
        signed_path.symlink_to(secret_file)
        r_dl_sym = client.get(f"/api/download/{job_id}/{signed_name}")
        assert r_dl_sym.status_code == 403
        assert b"SECRET_KEYSTORE_PASSWORD" not in r_dl_sym.content
        assert_security_headers(r_dl_sym)

        # Replace Full XAPK with a same-directory symlink to job_state.json
        fx_path = jdir / fx_name
        fx_path.unlink()
        fx_path.symlink_to(jdir / "job_state.json")
        r_fx_sym = client.get(f"/api/download-full-xapk/{job_id}")
        assert r_fx_sym.status_code == 403
        assert b"jobId" not in r_fx_sym.content
        assert_security_headers(r_fx_sym)

        # Replace extra OBB with a symlink to secret.pass
        obb_path = jdir / "extra_obb" / "main.10.com.retro.legacy.obb"
        obb_path.unlink()
        obb_path.symlink_to(secret_file)
        r_obb_sym = client.get(f"/api/download-obb/{job_id}/0")
        assert r_obb_sym.status_code == 403
        assert b"SECRET_KEYSTORE_PASSWORD" not in r_obb_sym.content
        assert_security_headers(r_obb_sym)


def test_static_symlink_to_dotfile_and_dir_symlink_blocked(
    api_env: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_base = tmp_path / "static_sym_base"
    static_root = fake_base / "static"
    (static_root / "sub").mkdir(parents=True)
    (static_root / ".secret_dir").mkdir(parents=True)
    (static_root / ".hidden_secret").write_text("DOTFILE_SECRET", encoding="utf-8")
    (static_root / ".secret_dir" / "token.txt").write_text("NESTED_DOT_SECRET", encoding="utf-8")
    (static_root / "sub" / "ok.txt").write_text("VISIBLE_OK", encoding="utf-8")
    (static_root / "link.txt").symlink_to(static_root / ".hidden_secret")
    (static_root / "dirlink").symlink_to(static_root / ".secret_dir")
    (static_root / "sublink").symlink_to(static_root / "sub")
    monkeypatch.setattr(server_mod, "BASE_DIR", fake_base)

    app = create_app()
    with TestClient(app) as client:
        r_ok = client.get("/static/sub/ok.txt")
        assert r_ok.status_code == 200
        assert r_ok.text == "VISIBLE_OK"

        for blocked_path in ("/static/link.txt", "/static/dirlink/token.txt", "/static/sublink/ok.txt"):
            resp = client.get(blocked_path)
            assert resp.status_code == 404, f"Expected 404 for {blocked_path}, got {resp.status_code}"
            assert "SECRET" not in resp.text
            assert_security_headers(resp)


def test_upload_init_rejects_purpose_obb_and_bare_traversal_filenames(
    api_env: dict[str, Any],
) -> None:
    app = create_app()
    with TestClient(app) as client:
        # purpose="obb" must be rejected cleanly with 400 pointing to /api/attach-obb/{job_id}/init
        r_obb = client.post(
            "/api/upload/init",
            data={
                "fileName": "main.10.com.retro.legacy.obb",
                "totalSize": "1024",
                "totalChunks": "1",
                "purpose": "obb",
            },
        )
        assert r_obb.status_code == 400
        assert "/api/attach-obb/" in r_obb.json()["detail"]
        assert_security_headers(r_obb)

        # Invalid purpose -> 400
        assert (
            client.post(
                "/api/upload/init",
                data={"fileName": "game.apk", "totalSize": "1024", "purpose": "invalid"},
            ).status_code
            == 400
        )

        # Bare traversal / empty basenames must be rejected with 400 (never fallback to paket.apk)
        for bad_name in ("../../..", "..", ".", "/", "\\", "...", "foo/..", "   ", "日本語"):
            r_bad = client.post(
                "/api/upload/init",
                data={"fileName": bad_name, "totalSize": "1024"},
            )
            assert r_bad.status_code == 400, f"Expected 400 for fileName={bad_name!r}, got {r_bad.status_code}"

        # Bare traversal on /api/analyze also rejected with 400
        r_an_bad = client.post(
            "/api/analyze",
            files={"file": ("../../..", b"PK\x03\x04dummy", "application/octet-stream")},
        )
        assert r_an_bad.status_code == 400

        # Valid Unicode filename with .apk extension still succeeds cleanly
        r_uni = client.post(
            "/api/upload/init",
            data={"fileName": "日本語.apk", "totalSize": "1024"},
        )
        assert r_uni.status_code == 200
        assert r_uni.json()["sanitizedFileName"] == "paket.apk"


def test_obb_file_vs_dir_collisions_incomplete_upload_and_replace_existing_413(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAX_UPLOAD_MB", "2")
    reset_settings_cache()

    app = create_app()
    with TestClient(app) as client:
        # Incomplete APK upload (complete=False) must reject both multipart & chunked OBB attach with 409
        r_inc = client.post("/api/upload/init", data={"fileName": "incomplete.apk", "totalSize": "1024"})
        assert r_inc.status_code == 200
        inc_id = r_inc.json()["jobId"]
        assert (
            client.post(
                f"/api/attach-obb/{inc_id}",
                files=[("files", ("main.10.com.retro.legacy.obb", b"abc", "application/octet-stream"))],
            ).status_code
            == 409
        )
        assert (
            client.post(
                f"/api/attach-obb/{inc_id}/init",
                data={"fileName": "main.10.com.retro.legacy.obb", "totalSize": "3", "totalChunks": "1"},
            ).status_code
            == 409
        )

        # Complete analyzed job for OBB collision & replaceExisting tests
        job_id = _analyze_apk(client, sample_artifacts["apk_bytes"], "obb_coll.apk")["jobId"]

        # Multipart file-vs-directory collision (both orders) must return 400 (never 500)
        for pair in (
            [("foo.obb", b"AAA"), ("foo.obb/bar.obb", b"BBB")],
            [("foo.obb/bar.obb", b"BBB"), ("foo.obb", b"AAA")],
        ):
            r_col = client.post(
                f"/api/attach-obb/{job_id}",
                files=[("files", (name, data, "application/octet-stream")) for name, data in pair],
            )
            assert r_col.status_code == 400, f"Expected 400 for {pair}, got {r_col.status_code}: {r_col.text}"
            assert_security_headers(r_col)

        # Chunked: attach foo.obb (200), then collide with foo.obb/bar.obb (/finish -> 400)
        def _chunked_obb(name: str, payload: bytes, replace: bool = False) -> httpx.Response:
            r_i = client.post(
                f"/api/attach-obb/{job_id}/init",
                data={
                    "fileName": name,
                    "totalSize": str(len(payload)),
                    "totalChunks": "1",
                    "replaceExisting": "true" if replace else "false",
                },
            )
            assert r_i.status_code == 200, r_i.text
            uid = r_i.json()["uploadId"]
            r_c = client.post(
                f"/api/attach-obb/{job_id}/chunk",
                data={"uploadId": uid, "chunkIndex": "0", "totalChunks": "1"},
                files={"chunk": ("part", payload, "application/octet-stream")},
            )
            assert r_c.status_code == 200, r_c.text
            return client.post(f"/api/attach-obb/{job_id}/finish", data={"uploadId": uid})

        r_ok1 = _chunked_obb("foo.obb", b"VALID_FOO_OBB")
        assert r_ok1.status_code == 200, r_ok1.text

        r_col_chunk = _chunked_obb("foo.obb/bar.obb", b"COLLIDING_CHILD_OBB", replace=False)
        assert r_col_chunk.status_code == 400, r_col_chunk.text
        assert (api_env["work_dir"] / job_id / "extra_obb" / "foo.obb").read_bytes() == b"VALID_FOO_OBB"

        # rev F6: replaceExisting=True failing with 413 at /finish MUST preserve existing valid OBBs
        big_obb = b"X" * (1_200_000)  # ~1.14 MB (<= 2 MB at init, > 1 MB after limit lowered)
        r_i_big = client.post(
            f"/api/attach-obb/{job_id}/init",
            data={
                "fileName": "replacement.obb",
                "totalSize": str(len(big_obb)),
                "totalChunks": "2",
                "replaceExisting": "true",
            },
        )
        assert r_i_big.status_code == 200, r_i_big.text
        big_uid = r_i_big.json()["uploadId"]
        csize = r_i_big.json()["chunkSizeBytes"]
        for idx in range(2):
            part = big_obb[idx * csize : (idx + 1) * csize]
            rc = client.post(
                f"/api/attach-obb/{job_id}/chunk",
                data={"uploadId": big_uid, "chunkIndex": str(idx), "totalChunks": "2"},
                files={"chunk": (f"p{idx}", part, "application/octet-stream")},
            )
            assert rc.status_code == 200, rc.text

        monkeypatch.setenv("MAX_UPLOAD_MB", "1")
        reset_settings_cache()
        r_fin_413 = client.post(f"/api/attach-obb/{job_id}/finish", data={"uploadId": big_uid})
        assert r_fin_413.status_code == 413
        # Original valid foo.obb and metadata must still be intact!
        assert (api_env["work_dir"] / job_id / "extra_obb" / "foo.obb").read_bytes() == b"VALID_FOO_OBB"
        meta_after = json.loads((api_env["work_dir"] / job_id / "extra_obb_meta.json").read_text(encoding="utf-8"))
        assert len(meta_after) == 1 and meta_after[0]["normalizedPath"] == "foo.obb"


def test_patch_resign_false_resign_only_and_background_full_xapk_cancel(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        job_id = _analyze_apk(client, sample_artifacts["apk_bytes"], "modes.apk")["jobId"]

        # resign=false produces unsigned/unverified patched APK and blocks Full XAPK with 400
        r_nosign = client.post(
            "/api/patch-sign",
            data={"jobId": job_id, "targetSdk": "28", "resign": "false"},
        )
        assert r_nosign.status_code == 200, r_nosign.text
        nosign = r_nosign.json()
        assert nosign["verified"] is False
        assert nosign["patchSummary"]["resigned"] is False
        assert nosign["patchSummary"]["manifestPatched"] is True
        assert client.post(f"/api/full-xapk/{job_id}").status_code == 400

        # mode="resign_only" signs without manifest patching
        r_ro = client.post(
            "/api/patch-sign",
            data={"jobId": job_id, "mode": "resign_only", "resign": "true"},
        )
        assert r_ro.status_code == 200, r_ro.text
        ro = r_ro.json()
        assert ro["verified"] is True
        assert ro["patchSummary"]["method"] == "resign_only"
        assert ro["patchSummary"]["manifestPatched"] is False

        # Attach OBB and test cancel on background Full XAPK
        assert (
            client.post(
                f"/api/attach-obb/{job_id}",
                files=[("files", ("main.10.com.retro.legacy.obb", b"OBB_CANCEL_DATA", "application/octet-stream"))],
            ).status_code
            == 200
        )

        entered = threading.Event()

        def _cancellable_build_full_xapk(
            *,
            cancel_event: threading.Event | None = None,
            **kwargs: Any,
        ) -> dict[str, Any]:
            entered.set()
            assert cancel_event is not None
            if cancel_event.wait(timeout=10.0):
                raise CommandCanceledError("build_full_xapk")
            return {"ok": True}

        monkeypatch.setattr(server_mod, "build_full_xapk", _cancellable_build_full_xapk)
        r_bg = client.post(f"/api/full-xapk/{job_id}", data={"background": "true"})
        assert r_bg.status_code == 200
        assert entered.wait(timeout=5.0)

        r_cancel = client.post(f"/api/patch-cancel/{job_id}")
        assert r_cancel.status_code == 200
        assert r_cancel.json()["status"] == "canceled"

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and app.state.job_manager.active_patch_count > 0:
            time.sleep(0.05)
        assert app.state.job_manager.active_patch_count == 0
        assert client.get(f"/api/full-xapk-status/{job_id}").json()["status"] == "canceled"

        # rev F7: execute_operation sync cancel must NOT double-format CommandCanceledError
        jm = app.state.job_manager
        jm.reserve_patch_slot(job_id)

        def _pre_canceled_runner(
            cancel_ev: threading.Event,
            _on_proc: Any,
            _log_cb: Any,
            _prog_cb: Any,
        ) -> dict[str, Any]:
            cancel_ev.set()
            return {"ok": True}

        with pytest.raises(CommandCanceledError) as exc_info:
            jm.execute_operation(job_id, "patch", _pre_canceled_runner, reraise=True)
        assert exc_info.value.detail == "İşlem iptal edildi."


def test_patch_slot_reserved_before_keystore_preflight(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def _gated_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        entered.set()
        release.wait(timeout=10.0)
        return {"ok": True, "verified": True}

    monkeypatch.setattr(server_mod, "patch_and_sign_pipeline", _gated_pipeline)

    app = create_app()
    with TestClient(app) as client:
        job_a = _analyze_apk(client, sample_artifacts["apk_bytes"], "slot_a.apk")["jobId"]
        job_b = _analyze_apk(client, sample_artifacts["apk_bytes"], "slot_b.apk")["jobId"]

        assert client.post("/api/patch-sign", data={"jobId": job_a, "background": "true"}).status_code == 200
        assert entered.wait(timeout=5.0)

        # Simulate degraded keystore while job_a holds the patch slot
        corrupt_ks = tmp_path / "broken_midrun.jks"
        corrupt_ks.write_bytes(b"CORRUPT")
        monkeypatch.setenv("KEYSTORE_PATH", str(corrupt_ks))
        reset_settings_cache()
        reset_keystore_state()

        # Slot conflicts (409 same job, 429 other job) must NOT be masked by 500 keystore error
        assert client.post("/api/patch-sign", data={"jobId": job_a}).status_code == 409
        assert client.post("/api/patch-sign", data={"jobId": job_b}).status_code == 429

        release.set()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and app.state.job_manager.active_patch_count > 0:
            time.sleep(0.05)
        assert app.state.job_manager.active_patch_count == 0


def test_health_runtime_keystore_unlink_and_low_disk_janitor_eviction(
    api_env: dict[str, Any],
    sample_artifacts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Copy keystore to per-test path so we can unlink it at runtime without affecting session fixture
    ks_copy = tmp_path / "runtime_unlink.jks"
    shutil.copy2(sample_artifacts["ks_path"], ks_copy)
    monkeypatch.setenv("KEYSTORE_PATH", str(ks_copy))
    monkeypatch.setenv("KEYSTORE_PASS", sample_artifacts["ks_pass"])
    reset_settings_cache()
    reset_keystore_state()

    app = create_app()
    with TestClient(app) as client:
        assert client.get("/health?strict=true").status_code == 200
        assert client.get("/api/keystore-info").json()["ready"] is True

        # Unlink active keystore at runtime (chal L1)
        ks_copy.unlink()
        r_h = client.get("/health")
        assert r_h.status_code == 200
        h_data = r_h.json()
        assert h_data["status"] == "degraded"
        assert h_data["healthy"] is False
        assert h_data["keystoreReady"] is False
        assert h_data["keystoreFingerprintSha256"] is None

        r_strict = client.get("/health?strict=true")
        assert r_strict.status_code == 503
        assert_security_headers(r_strict)
        assert client.get("/api/keystore-info").json()["ready"] is False

        # Low-disk janitor eviction + in-lock activity age re-check (rev F7, F8)
        job_old = _analyze_apk(client, sample_artifacts["apk_bytes"], "old_lowdisk.apk")["jobId"]
        job_fresh = _analyze_apk(client, sample_artifacts["apk_bytes"], "fresh_lowdisk.apk")["jobId"]
        jm = app.state.job_manager

        old_dir = api_env["work_dir"] / job_old
        backdated = time.time() - 300.0
        for item in [old_dir, *old_dir.rglob("*")]:
            os.utime(item, (backdated, backdated))

        # Force low free disk (100 MB < default 1500 MB floor) while TTL=3600s
        disk_usage_type = type(shutil.disk_usage(api_env["work_dir"]))
        monkeypatch.setattr(
            jobs_mod.shutil,
            "disk_usage",
            lambda _p: disk_usage_type(10 * 1024**3, 9 * 1024**3, 100 * 1024**2),
        )
        removed = jm.cleanup_old_jobs()
        assert removed == 1
        assert not old_dir.exists()
        assert (api_env["work_dir"] / job_fresh).is_dir()

        # Direct TOCTOU check: _remove_if_idle refuses eviction when job was recently touched
        fresh_dir = api_env["work_dir"] / job_fresh
        jm.touch_activity(job_fresh)
        assert jm._remove_if_idle(job_fresh, fresh_dir, min_age_seconds=120.0) is False
        assert fresh_dir.is_dir()

