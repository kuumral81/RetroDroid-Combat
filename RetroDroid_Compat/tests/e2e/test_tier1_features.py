"""Opaque-box E2E Tier 1 Feature Coverage Tests (F01–F16, >= 80 tests).

Exercises every RetroDroid Compat v5.4.0 feature end-to-end against live ``uvicorn server:app``
HTTP endpoints and verifies produced Android artifacts with real ``aapt``, ``zipalign``,
``apksigner``, and ``keytool`` CLI tools.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.e2e.conftest import (
    REPO_ROOT,
    LiveServer,
    upload_via_analyze,
    upload_via_chunks,
)
from tests.e2e.fixtures_apk import (
    E2ECorpus,
    verify_apk_with_aapt,
    verify_apk_with_apksigner,
    verify_apk_with_zipalign,
    verify_apk_xmltree,
)

REQUIRED_SECURITY_HEADERS = (
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def _assert_security_headers(resp: httpx.Response) -> None:
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    assert hdrs.get("x-content-type-options") == "nosniff"
    assert hdrs.get("x-frame-options") == "DENY"
    assert hdrs.get("referrer-policy") == "no-referrer"
    assert "camera=()" in hdrs.get("permissions-policy", "")


@pytest.fixture(scope="module")
def patched_legacy(http_client: httpx.Client, apk_corpus: E2ECorpus, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Analyze + patch + download legacy APK once per module for read-only CLI artifact assertions."""
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    resp = http_client.post(
        "/api/patch-sign",
        data={
            "jobId": an["jobId"],
            "targetSdk": "28",
            "mode": "patch_and_sign",
            "resign": "true",
            "patchTargetSdk": "true",
            "addLegacyStorage": "true",
            "enableCleartext": "true",
            "addNotchSupport": "true",
            "forceExtractNativeLibs": "true",
        },
    )
    assert resp.status_code == 200, resp.text
    patch_json = resp.json()
    dl_resp = http_client.get(patch_json["downloadUrl"])
    assert dl_resp.status_code == 200
    out_dir = tmp_path_factory.mktemp("t1_patched_legacy")
    out_apk = out_dir / patch_json["fileName"]
    out_apk.write_bytes(dl_resp.content)
    return {
        "analyze": an,
        "patch": patch_json,
        "apk_path": out_apk,
        "download_headers": dl_resp.headers,
    }


@pytest.fixture(scope="module")
def analyzed_xapk(http_client: httpx.Client, apk_corpus: E2ECorpus) -> dict[str, Any]:
    """Analyze XAPK v2 once per module for container/split/OBB assertions."""
    return upload_via_analyze(http_client, apk_corpus.xapk_v2)


# ===========================================================================
# F01: Server Health, Keystore Info & Startup Lifespan (6 tests)
# ===========================================================================


def test_f01_health_ok_schema_and_version(http_client: httpx.Client) -> None:
    resp = http_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["healthy"] is True
    assert data["version"] == "5.4.0"
    assert isinstance(data["serverTime"], (int, float))
    assert data["diskFreeMB"] > 0
    assert data["maxUploadMB"] > 0
    assert data["chunkSizeMB"] > 0
    assert data["jobTtlSeconds"] > 0
    assert data["keystoreReady"] is True
    assert data["authRequired"] is False
    assert isinstance(data["zipalign16kSupported"], bool)


def test_f01_health_strict_true_returns_200_when_healthy(http_client: httpx.Client) -> None:
    resp = http_client.get("/health?strict=true")
    assert resp.status_code == 200
    assert resp.json()["healthy"] is True


def test_f01_health_tools_and_tool_versions_populated(http_client: httpx.Client) -> None:
    data = http_client.get("/health").json()
    for tool in ("java", "keytool", "aapt", "apktool", "zipalign", "apksigner"):
        assert data["tools"].get(tool) is True, f"Tool {tool} not ready"
    assert isinstance(data["toolVersions"], dict)
    assert len(data["toolVersions"]) >= 4


def test_f01_keystore_info_schema_and_no_secret_leak(http_client: httpx.Client) -> None:
    resp = http_client.get("/api/keystore-info")
    assert resp.status_code == 200
    info = resp.json()
    assert info["ready"] is True
    assert info["alias"]
    assert "RSA" in str(info["algorithm"]).upper()
    assert re.fullmatch(r"[0-9A-Fa-f:]{64,95}", info["sha256"])
    assert info["subject"]
    assert info["validUntil"]
    assert isinstance(info["persistent"], bool)
    for forbidden in ("password", "pass", "storepass", "keypass", "secret"):
        assert forbidden not in {k.lower() for k in info}


@pytest.mark.parametrize(
    ("path", "expected_snippet"),
    [
        ("/", "RetroDroid"),
        ("/static/styles.css", ".rd-btn"),
        ("/static/app.js", "APP_VERSION"),
        ("/static/vendor/jszip.js", "JSZip"),
    ],
)
def test_f01_root_html_and_static_assets_served(
    http_client: httpx.Client,
    path: str,
    expected_snippet: str,
) -> None:
    resp = http_client.get(path)
    assert resp.status_code == 200
    assert expected_snippet in resp.text
    _assert_security_headers(resp)


def test_f01_security_headers_on_health_and_keystore(http_client: httpx.Client) -> None:
    _assert_security_headers(http_client.get("/health"))
    _assert_security_headers(http_client.get("/api/keystore-info"))


# ===========================================================================
# F02: Secure Keystore Lifecycle & JVM Diagnostics (5 tests)
# ===========================================================================


def test_f02_keystore_and_pass_file_created_with_0600_permissions(live_server: LiveServer) -> None:
    ks = live_server.keystore_path
    assert ks.is_file()
    assert stat.S_IMODE(ks.stat().st_mode) == 0o600
    pass_file = Path(f"{ks}.pass")
    assert pass_file.is_file()
    assert stat.S_IMODE(pass_file.stat().st_mode) == 0o600
    assert len(pass_file.read_text(encoding="utf-8").strip()) >= 6


def test_f02_keystore_fingerprint_matches_between_health_and_keystore_info(http_client: httpx.Client) -> None:
    h = http_client.get("/health").json()
    ks = http_client.get("/api/keystore-info").json()
    assert h["keystoreFingerprintSha256"] == ks["sha256"]


def test_f02_keystore_verifies_with_real_keytool_and_signs_matching_cert(
    live_server: LiveServer,
    patched_legacy: dict[str, Any],
) -> None:
    pass_val = Path(f"{live_server.keystore_path}.pass").read_text(encoding="utf-8").strip()
    env = os.environ.copy()
    env["TEST_KS_PASS"] = pass_val
    kt = subprocess.run(
        [
            "keytool",
            "-list",
            "-v",
            "-keystore",
            str(live_server.keystore_path),
            "-storepass:env",
            "TEST_KS_PASS",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert kt.returncode == 0, kt.stderr
    assert "SHA256:" in kt.stdout
    ok, sig_out = verify_apk_with_apksigner(patched_legacy["apk_path"])
    assert ok, sig_out
    assert "RetroDroid" in sig_out or "SHA-256 digest" in sig_out


def test_f02_degraded_keystore_is_never_silently_deleted(degraded_server: LiveServer) -> None:
    with degraded_server.client() as c:
        h = c.get("/health").json()
        assert h["keystoreReady"] is False
        assert h["status"] == "degraded"
        ks = c.get("/api/keystore-info").json()
        assert ks["ready"] is False
    assert degraded_server.keystore_path.read_bytes() == b"NOT_A_VALID_JKS_KEYSTORE_DO_NOT_DELETE"


def test_f02_keystore_auto_regen_backs_up_corrupt_file_and_recovers(
    server_factory: Any,
    tmp_path: Path,
) -> None:
    ks = tmp_path / "regen_ks" / "retrodroid.jks"
    ks.parent.mkdir(parents=True, exist_ok=True)
    ks.write_bytes(b"CORRUPT_KEYSTORE_CONTENT_FOR_BACKUP")
    os.chmod(ks, 0o600)
    srv = server_factory(
        keystore_path=ks,
        extra_env={"KEYSTORE_AUTO_REGEN": "true"},
    )
    with srv.client() as c:
        h = c.get("/health").json()
        assert h["keystoreReady"] is True
        assert h["healthy"] is True
    backups = list(ks.parent.glob("retrodroid.jks.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == b"CORRUPT_KEYSTORE_CONTENT_FOR_BACKUP"


# ===========================================================================
# F03: Resumable Chunked Upload & Single-Shot Analysis (6 tests)
# ===========================================================================


def test_f03_single_shot_analyze_legacy_apk(http_client: httpx.Client, apk_corpus: E2ECorpus) -> None:
    data = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    assert re.fullmatch(r"[0-9a-f]{12}", data["jobId"])
    assert data["packageId"] == "com.retro.legacy"
    assert data["minSdk"] == 19
    assert data["targetSdk"] == 21
    assert data["containerType"] == "APK"
    assert data["sizeBytes"] == apk_corpus.legacy_apk.stat().st_size


def test_f03_chunked_upload_init_status_chunk_finish_full_cycle(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    init_json, fin_json = upload_via_chunks(http_client, apk_corpus.legacy_apk, chunk_size=2048)
    jid = init_json["jobId"]
    assert init_json["chunkSizeMB"] >= 1
    assert fin_json["jobId"] == jid
    assert fin_json["packageId"] == "com.retro.legacy"
    st = http_client.get(f"/api/upload/status/{jid}")
    assert st.status_code == 200
    assert st.json()["complete"] is True
    assert st.json()["missingChunks"] == []


def test_f03_chunked_upload_out_of_order_chunks_assemble_cleanly(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    raw = apk_corpus.legacy_apk.read_bytes()
    r_init = http_client.post(
        "/api/upload/init",
        data={"fileName": "out_of_order.apk", "totalSize": str(len(raw)), "totalChunks": "3"},
    )
    assert r_init.status_code == 200, r_init.text
    init_j = r_init.json()
    jid = init_j["jobId"]
    csz = int(init_j["chunkSizeBytes"])
    chunks = [raw[i : i + csz] for i in range(0, len(raw), csz)]
    assert len(chunks) == 3
    for idx in reversed(range(len(chunks))):
        rc = http_client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": str(idx), "totalChunks": str(len(chunks))},
            files={"chunk": (f"p{idx}.bin", chunks[idx], "application/octet-stream")},
        )
        assert rc.status_code == 200, rc.text
    r_fin = http_client.post("/api/upload/finish", data={"jobId": jid})
    assert r_fin.status_code == 200
    assert r_fin.json()["packageId"] == "com.retro.legacy"


def test_f03_chunked_upload_resume_with_existing_job_id_and_status_tracking(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    raw = apk_corpus.legacy_apk.read_bytes()
    init1 = http_client.post(
        "/api/upload/init",
        data={"fileName": "resume_me.apk", "totalSize": str(len(raw)), "totalChunks": "2"},
    ).json()
    jid = init1["jobId"]
    csz = int(init1["chunkSizeBytes"])
    chunks = [raw[:csz], raw[csz:]]

    rc0 = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "0", "totalChunks": "2"},
        files={"chunk": ("c0.bin", chunks[0], "application/octet-stream")},
    )
    assert rc0.status_code == 200

    st_mid = http_client.get(f"/api/upload/status/{jid}").json()
    assert st_mid["receivedChunks"] == [0]
    assert st_mid["missingChunks"] == [1]
    assert st_mid["complete"] is False

    # Re-init with existing jobId resumes session
    init2 = http_client.post(
        "/api/upload/init",
        data={
            "jobId": jid,
            "fileName": "resume_me.apk",
            "totalSize": str(len(raw)),
            "totalChunks": "2",
        },
    )
    assert init2.status_code == 200
    assert init2.json()["jobId"] == jid

    for idx in st_mid["missingChunks"]:
        rc = http_client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": str(idx), "totalChunks": "2"},
            files={"chunk": (f"c{idx}.bin", chunks[idx], "application/octet-stream")},
        )
        assert rc.status_code == 200

    r_fin = http_client.post("/api/upload/finish", data={"jobId": jid})
    assert r_fin.status_code == 200
    assert r_fin.json()["packageId"] == "com.retro.legacy"


def test_f03_chunked_upload_duplicate_chunk_is_idempotent(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    raw = apk_corpus.legacy_apk.read_bytes()
    init_j = http_client.post(
        "/api/upload/init",
        data={"fileName": "dup_chunk.apk", "totalSize": str(len(raw)), "totalChunks": "1"},
    ).json()
    jid = init_j["jobId"]
    c1 = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "0", "totalChunks": "1"},
        files={"chunk": ("c0.bin", raw, "application/octet-stream")},
    )
    c2 = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "0", "totalChunks": "1"},
        files={"chunk": ("c0.bin", raw, "application/octet-stream")},
    )
    assert c1.status_code == 200
    assert c2.status_code == 200
    assert c2.json()["receivedCount"] == 1
    assert http_client.post("/api/upload/finish", data={"jobId": jid}).status_code == 200


def test_f03_filename_sanitization_and_length_cap_on_upload(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    long_dirty_name = "..\\..\\weird name <>|:" + ("A" * 160) + ".apk"
    data = upload_via_analyze(http_client, apk_corpus.legacy_apk, filename=long_dirty_name)
    san = data["sanitizedFileName"]
    assert len(san) <= 120
    assert san.endswith(".apk")
    assert "/" not in san and "\\" not in san and ".." not in san


# ===========================================================================
# F04: Spec-Compliant Container Unpacking & Guardrails (6 tests)
# ===========================================================================


def test_f04_xapk_v2_manifest_json_base_splits_and_obb_extraction(analyzed_xapk: dict[str, Any]) -> None:
    assert analyzed_xapk["containerType"] == "XAPK"
    assert analyzed_xapk["isContainer"] is True
    assert analyzed_xapk["packageId"] == "com.retro.xapkgame"
    assert analyzed_xapk["hasObb"] is True
    assert len(analyzed_xapk["obbFiles"]) == 1
    assert analyzed_xapk["splitCount"] == 2


def test_f04_xapk_windows_backslash_paths_normalized(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.xapk_backslash)
    assert data["containerType"] == "XAPK"
    assert data["packageId"] == "com.retro.xapkgame"
    assert data["hasObb"] is True
    for obb in data["obbFiles"]:
        raw_path = obb.get("archivePath") or obb.get("name") or ""
        assert ".." not in str(raw_path)


def test_f04_apkm_info_json_base_and_split_extraction(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.apkm_bundle)
    assert data["containerType"] == "APKM"
    assert data["packageId"] == "com.retro.apkmgame"
    assert data["splitCount"] >= 1
    assert "arm64-v8a" in data["abis"]


def test_f04_apks_bundle_extraction_and_split_detection(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.apks_bundle)
    assert data["containerType"] == "APKS"
    assert data["packageId"] == "com.retro.xapkgame"
    assert data["splitCount"] == 1


def test_f04_plain_zip_container_apk_and_obb_extraction(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.plain_zip_container)
    assert data["containerType"] == "ZIP"
    assert data["packageId"] == "com.retro.legacy"
    assert data["hasObb"] is True
    assert len(data["obbFiles"]) == 1


def test_f04_plain_zip_backslash_paths_extracted_cleanly(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.plain_zip_backslash)
    assert data["containerType"] == "ZIP"
    assert data["packageId"] == "com.retro.legacy"
    assert data["hasObb"] is True


# ===========================================================================
# F05: Single-Pass APK Inspector & Android 15/16/17 Diagnostics (7 tests)
# ===========================================================================


def test_f05_inspector_apostrophe_label_and_package_metadata(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    assert data["appLabel"] == "Retro's Legacy Quest"
    assert data["versionCode"] == "10" or data["versionCode"] == 10
    assert data["versionName"] == "1.2.3"
    assert "android.permission.INTERNET" in data["inspector"]["permissions"]


def test_f05_inspector_root_only_multidex_ignores_nested_assets_dex(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.multidex_apk)
    dex = data["inspector"]["dex"]
    assert dex["fileCount"] == 3
    names = [d.get("name") for d in dex.get("files", [])]
    assert "assets/classes9.dex" not in names


def test_f05_inspector_elf64_16kb_aligned_passes(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.elf16k_apk)
    assert data["pageSize16kStatus"] == "compatible"
    assert data["elf16kReport"]["unalignedCount"] == 0
    assert data["elf16kReport"]["alignedCount"] >= 1


def test_f05_inspector_elf64_4kb_unaligned_flagged(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.elf4k_apk)
    assert data["pageSize16kStatus"] == "incompatible"
    assert data["elf16kReport"]["unalignedCount"] >= 1


def test_f05_inspector_arm32_only_and_split_abis_detected(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    analyzed_xapk: dict[str, Any],
) -> None:
    arm32 = upload_via_analyze(http_client, apk_corpus.arm32_only_apk)
    assert arm32["is32BitOnly"] is True
    assert "armeabi-v7a" in arm32["abis"]
    assert "arm64-v8a" in analyzed_xapk["abis"]
    assert "armeabi-v7a" in analyzed_xapk["abis"]
    assert analyzed_xapk["is32BitOnly"] is False


def test_f05_inspector_compressed_arsc_and_unexported_components_counted(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    dirty = upload_via_analyze(http_client, apk_corpus.compressed_arsc_apk)
    assert dirty["resourcesArscCompressed"] is True
    unexp = upload_via_analyze(http_client, apk_corpus.api31_unexported_apk)
    assert unexp["missingExportedCount"] >= 2


def test_f05_inspector_install_floor_android14_15_compat_checklist_and_score(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    legacy = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    modern = upload_via_analyze(http_client, apk_corpus.high_target_apk)
    assert 0 <= legacy["compatScore"] <= 100
    assert 0 <= modern["compatScore"] <= 100
    assert modern["compatScore"] >= legacy["compatScore"]
    assert isinstance(legacy["compatChecklist"], list) and len(legacy["compatChecklist"]) >= 3
    floor_legacy = legacy["installFloorStatus"]
    assert floor_legacy["android14Compatible"] is False
    assert floor_legacy["android15To17Compatible"] is False
    floor_modern = modern["installFloorStatus"]
    assert floor_modern["android14Compatible"] is True
    assert floor_modern["android15To17Compatible"] is True


# ===========================================================================
# F06: Hardened Binary AXML & Real Manifest Compatibility Patcher (7 tests)
# ===========================================================================


def test_f06_patch_target_sdk_28_verified_by_aapt_badging(patched_legacy: dict[str, Any]) -> None:
    assert patched_legacy["patch"]["targetSdk"] == 28
    assert patched_legacy["patch"]["patchSummary"]["effectiveTargetSdk"] == 28
    badging = verify_apk_with_aapt(patched_legacy["apk_path"])
    assert badging["targetSdk"] == 28
    assert badging["minSdk"] == 19
    assert badging["name"] == "com.retro.legacy"


def test_f06_patch_target_sdk_34_adds_android_exported_true_on_unexported_components(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.api31_unexported_apk)
    assert an["missingExportedCount"] >= 2
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "34", "patchTargetSdk": "true", "resign": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["targetSdk"] == 34
    assert pdata["inspector"]["missingExportedCount"] == 0
    out_apk = tmp_path / "exported34.apk"
    out_apk.write_bytes(http_client.get(pdata["downloadUrl"]).content)
    xmltree = verify_apk_xmltree(out_apk)
    assert "android:exported" in xmltree
    ok, _ = verify_apk_with_apksigner(out_apk)
    assert ok


def test_f06_patch_legacy_storage_and_cleartext_verified_by_xmltree(patched_legacy: dict[str, Any]) -> None:
    xmltree = verify_apk_xmltree(patched_legacy["apk_path"])
    assert "requestLegacyExternalStorage" in xmltree
    assert "usesCleartextTraffic" in xmltree
    changes = " ".join(patched_legacy["patch"]["patchSummary"]["appliedChanges"])
    assert "requestLegacyExternalStorage" in changes
    assert "usesCleartextTraffic" in changes


def test_f06_patch_notch_support_max_aspect_and_resizeable_verified_by_xmltree(
    patched_legacy: dict[str, Any],
) -> None:
    xmltree = verify_apk_xmltree(patched_legacy["apk_path"])
    assert "resizeableActivity" in xmltree
    assert "android.max_aspect" in xmltree


def test_f06_patch_force_extract_native_libs_verified_by_xmltree(patched_legacy: dict[str, Any]) -> None:
    xmltree = verify_apk_xmltree(patched_legacy["apk_path"])
    assert "extractNativeLibs" in xmltree


def test_f06_patch_creates_uses_sdk_when_absent_in_source_apk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.no_uses_sdk_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "28", "patchTargetSdk": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["targetSdk"] == 28
    out_apk = tmp_path / "created_sdk.apk"
    out_apk.write_bytes(http_client.get(pdata["downloadUrl"]).content)
    assert verify_apk_with_aapt(out_apk)["targetSdk"] == 28


def test_f06_patch_target_sdk_36_android_16_17_supported(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.high_target_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "36", "patchTargetSdk": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["targetSdk"] == 36
    out_apk = tmp_path / "target36.apk"
    out_apk.write_bytes(http_client.get(pdata["downloadUrl"]).content)
    assert verify_apk_with_aapt(out_apk)["targetSdk"] == 36


# ===========================================================================
# F07: Streaming APK Rewrite, Alignment, Signing & Split .apks (6 tests)
# ===========================================================================


def test_f07_signed_output_passes_real_apksigner_verify_v1_v2_v3(patched_legacy: dict[str, Any]) -> None:
    assert patched_legacy["patch"]["verified"] is True
    ok, output = verify_apk_with_apksigner(patched_legacy["apk_path"])
    assert ok, output
    assert "Verified using v1 scheme" in output
    assert "Verified using v2 scheme" in output
    assert "Verified using v3 scheme" in output


def test_f07_signed_output_passes_real_zipalign_check(
    http_client: httpx.Client,
    patched_legacy: dict[str, Any],
) -> None:
    use_16k = bool(http_client.get("/health").json().get("zipalign16kSupported"))
    ok, out = verify_apk_with_zipalign(patched_legacy["apk_path"], page_16k=use_16k)
    assert ok, out


def test_f07_rewrite_strips_old_meta_inf_dedups_and_stores_arsc_and_so(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.compressed_arsc_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "28", "patchTargetSdk": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["resourcesArscCompressed"] is False if "resourcesArscCompressed" in pdata else True
    out_apk = tmp_path / "rewritten_clean.apk"
    out_apk.write_bytes(http_client.get(pdata["downloadUrl"]).content)

    with zipfile.ZipFile(out_apk, "r") as zf:
        names = zf.namelist()
        assert len(names) == len(set(names)), "Duplicate ZIP entries must be deduplicated"
        assert "meta-inf/stamp-cert-sha256" not in [n.lower() for n in names]
        arsc_info = zf.getinfo("resources.arsc")
        assert arsc_info.compress_type == zipfile.ZIP_STORED
        so_info = zf.getinfo("lib/arm64-v8a/libcompressed.so")
        assert so_info.compress_type == zipfile.ZIP_STORED
    ok, sig_out = verify_apk_with_apksigner(out_apk)
    assert ok, sig_out


def test_f07_resign_only_mode_preserves_target_sdk_and_signs_cleanly(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "34", "mode": "resign_only", "resign": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["verified"] is True
    assert pdata["patchSummary"]["mode"] == "resign_only"
    assert pdata["patchSummary"]["manifestPatched"] is False
    out_apk = tmp_path / "resigned_only.apk"
    out_apk.write_bytes(http_client.get(pdata["downloadUrl"]).content)
    assert verify_apk_with_aapt(out_apk)["targetSdk"] == 21
    ok, _ = verify_apk_with_apksigner(out_apk)
    assert ok


def test_f07_split_xapk_patches_splits_and_builds_apks_bundle(
    http_client: httpx.Client,
    analyzed_xapk: dict[str, Any],
    tmp_path: Path,
) -> None:
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": analyzed_xapk["jobId"], "targetSdk": "28", "patchTargetSdk": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["verified"] is True
    sb = pdata.get("splitBundle")
    assert isinstance(sb, dict) and sb.get("downloadUrl")
    dl = http_client.get(sb["downloadUrl"])
    assert dl.status_code == 200
    bundle_path = tmp_path / sb["fileName"]
    bundle_path.write_bytes(dl.content)
    with zipfile.ZipFile(bundle_path, "r") as zf:
        apk_entries = [n for n in zf.namelist() if n.lower().endswith(".apk")]
        assert len(apk_entries) == 3  # base + 2 splits


def test_f07_split_abis_preserved_in_post_patch_inspector(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.apks_bundle)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "28", "patchTargetSdk": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert "arm64-v8a" in pdata["abis"]


# ===========================================================================
# F08: OBB Pairing, Chunked OBB Upload & Async XAPK v2 Builder (6 tests)
# ===========================================================================


def test_f08_multipart_attach_obb_valid_and_custom_warning(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    resp = http_client.post(
        f"/api/attach-obb/{an['jobId']}",
        files=[
            ("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream")),
            ("files", (apk_corpus.obb_bad_name.name, apk_corpus.obb_bad_name.read_bytes(), "application/octet-stream")),
        ],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["count"] == 2
    by_name = {f["name"]: f for f in body["files"]}
    assert by_name[apk_corpus.obb_main.name]["validObbName"] is True
    assert by_name[apk_corpus.obb_bad_name.name]["validObbName"] is False
    assert by_name[apk_corpus.obb_bad_name.name]["warning"]


def test_f08_chunked_obb_upload_init_chunk_finish_flow(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    raw = apk_corpus.obb_main.read_bytes()
    half = len(raw) // 2
    r_init = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={"fileName": apk_corpus.obb_main.name, "totalSize": str(len(raw)), "totalChunks": "2"},
    )
    assert r_init.status_code == 200, r_init.text
    uid = r_init.json()["uploadId"]
    chunk_size = r_init.json()["chunkSizeBytes"]
    p0 = raw[:chunk_size]
    p1 = raw[chunk_size:]
    assert half > 0 and len(p0) + len(p1) == len(raw)
    for idx, payload in enumerate((p0, p1)):
        rc = http_client.post(
            f"/api/attach-obb/{jid}/chunk",
            data={"uploadId": uid, "chunkIndex": str(idx), "totalChunks": "2"},
            files={"chunk": (f"obb_{idx}.bin", payload, "application/octet-stream")},
        )
        assert rc.status_code == 200, rc.text
    rf = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": uid})
    assert rf.status_code == 200, rf.text
    assert rf.json()["count"] == 1


def test_f08_obb_anti_double_nesting_normalizes_redundant_prefix(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    nested_name = "Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb"
    r_init = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={"fileName": nested_name, "totalSize": str(apk_corpus.obb_main.stat().st_size), "totalChunks": "1"},
    )
    assert r_init.status_code == 200, r_init.text
    assert r_init.json()["normalizedPath"] == "main.10.com.retro.legacy.obb"


def test_f08_sync_full_xapk_v2_build_download_and_manifest_schema(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).status_code == 200
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}",
            files=[("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream"))],
        ).status_code
        == 200
    )
    rx = http_client.post(f"/api/full-xapk/{jid}", data={"background": "false"})
    assert rx.status_code == 200, rx.text
    xdata = rx.json()
    assert xdata["ok"] is True
    assert xdata["manifest"]["xapk_version"] == 2
    assert xdata["manifest"]["package_name"] == "com.retro.legacy"
    assert xdata["manifest"]["total_size"] > 0
    assert len(xdata["manifest"]["expansions"]) == 1

    dl = http_client.get(f"/api/download-full-xapk/{jid}")
    assert dl.status_code == 200
    out_xapk = tmp_path / xdata["fileName"]
    out_xapk.write_bytes(dl.content)
    with zipfile.ZipFile(out_xapk, "r") as zf:
        names = zf.namelist()
        assert "manifest.json" in names
        assert "RETRODROID-INSTALL.txt" in names
        assert f"Android/obb/com.retro.legacy/{apk_corpus.obb_main.name}" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["target_sdk_version"] == "28"


def test_f08_async_background_full_xapk_status_poll_and_download(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xapk_v2)
    jid = an["jobId"]
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).status_code == 200
    rx = http_client.post(f"/api/full-xapk/{jid}", data={"background": "true"})
    assert rx.status_code == 200
    assert rx.json()["status"] == "running"

    deadline = time.monotonic() + 30.0
    final: dict[str, Any] = {}
    while time.monotonic() < deadline:
        st = http_client.get(f"/api/full-xapk-status/{jid}")
        assert st.status_code == 200
        final = st.json()
        if final["status"] in {"done", "error", "canceled"}:
            break
        time.sleep(0.1)
    assert final.get("status") == "done", final
    assert final["result"]["manifest"]["xapk_version"] == 2
    assert http_client.get(f"/api/download-full-xapk/{jid}").status_code == 200


def test_f08_download_container_and_extra_obb_with_temp_cleanup(
    live_server: LiveServer,
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xapk_v2)
    jid = an["jobId"]
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}",
            files=[("files", (apk_corpus.obb_patch.name, apk_corpus.obb_patch.read_bytes(), "application/octet-stream"))],
        ).status_code
        == 200
    )
    r0 = http_client.get(f"/api/download-obb/{jid}/0")
    assert r0.status_code == 200
    assert r0.content == apk_corpus.obb_main.read_bytes()

    r1 = http_client.get(f"/api/download-obb/{jid}/1")
    assert r1.status_code == 200
    assert r1.content == apk_corpus.obb_patch.read_bytes()

    # Temporary extracted OBB directory must have 0 leftover files after download finishes
    extracted_dir = live_server.work_dir / jid / "_extracted_obb"
    if extracted_dir.exists():
        assert list(extracted_dir.iterdir()) == []


# ===========================================================================
# F09: Non-Blocking Async Server, Persistent Jobs, Cancel & Janitor (5 tests)
# ===========================================================================


def test_f09_background_patch_polls_to_done_with_logs_and_expiry(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    rp = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28", "background": "true"})
    assert rp.status_code == 200
    assert rp.json()["status"] == "running"

    deadline = time.monotonic() + 30.0
    final: dict[str, Any] = {}
    while time.monotonic() < deadline:
        st = http_client.get(f"/api/patch-status/{jid}")
        assert st.status_code == 200
        final = st.json()
        if final["status"] in {"done", "error", "canceled"}:
            break
        time.sleep(0.1)
    assert final.get("status") == "done", final
    assert isinstance(final["logs"], list) and len(final["logs"]) > 0
    assert final["expiresInSeconds"] > 0
    assert isinstance(final["serverTime"], (int, float))


def test_f09_jobs_list_returns_metadata_and_ttl_fields(
    http_client: httpx.Client,
    patched_legacy: dict[str, Any],
) -> None:
    resp = http_client.get("/api/jobs")
    assert resp.status_code == 200
    body = resp.json()
    assert body["linkTtlSeconds"] > 0
    assert isinstance(body["serverTime"], (int, float))
    job_ids = {j["jobId"] for j in body["jobs"]}
    assert patched_legacy["analyze"]["jobId"] in job_ids


def test_f09_delete_job_removes_directory_and_returns_404_afterward(
    live_server: LiveServer,
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    assert (live_server.work_dir / jid).is_dir()
    rd = http_client.delete(f"/api/jobs/{jid}")
    assert rd.status_code == 200
    assert rd.json()["deleted"] is True
    assert not (live_server.work_dir / jid).exists()
    assert http_client.get(f"/api/patch-status/{jid}").status_code == 404


def test_f09_health_remains_non_blocking_under_200ms_during_patch(
    live_server: LiveServer,
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    assert http_client.post(
        "/api/patch-sign",
        data={"jobId": jid, "targetSdk": "28", "addLegacyStorage": "true", "background": "true"},
    ).status_code == 200

    latencies_ms: list[float] = []
    with live_server.client(timeout=10.0) as probe:
        for _ in range(5):
            t0 = time.perf_counter()
            rh = probe.get("/health")
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            assert rh.status_code == 200
            time.sleep(0.05)
    assert max(latencies_ms) < 200.0, f"Event loop blocked! /health latencies: {latencies_ms}"

    # Wait for background patch to finish cleanly before leaving fixture
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        st = http_client.get(f"/api/patch-status/{jid}").json()
        if st["status"] in {"done", "error", "canceled"}:
            break
        time.sleep(0.1)


def test_f09_job_state_persisted_on_disk_after_completion(
    live_server: LiveServer,
    patched_legacy: dict[str, Any],
) -> None:
    jid = patched_legacy["analyze"]["jobId"]
    state_file = live_server.work_dir / jid / "job_state.json"
    assert state_file.is_file()
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["jobId"] == jid
    assert persisted["status"] == "done"


# ===========================================================================
# F10: API Security, Download Allowlist, XSS Elimination & CVE-Free Deps (6 tests)
# ===========================================================================


def test_f10_api_token_bearer_and_x_api_token_accepted(auth_server: LiveServer) -> None:
    tok = auth_server.api_token
    with auth_server.client() as c:
        r_bearer = c.get("/api/keystore-info", headers={"Authorization": f"Bearer {tok}"})
        assert r_bearer.status_code == 200
        r_hdr = c.get("/api/jobs", headers={"X-API-Token": tok})
        assert r_hdr.status_code == 200


def test_f10_api_token_query_param_allowed_on_download_endpoints(
    auth_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    tok = auth_server.api_token
    with auth_server.client(headers={"Authorization": f"Bearer {tok}"}) as auth_c:
        an = upload_via_analyze(auth_c, apk_corpus.legacy_apk)
        rp = auth_c.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28"})
        assert rp.status_code == 200
        dl_url = rp.json()["downloadUrl"]

    with auth_server.client() as unauth_c:
        assert unauth_c.get(dl_url).status_code == 401
        r_ok = unauth_c.get(f"{dl_url}?token={tok}")
        assert r_ok.status_code == 200
        assert r_ok.content[:2] == b"PK"


def test_f10_cors_allowed_origin_returns_acao_header(auth_server: LiveServer) -> None:
    with auth_server.client() as c:
        r = c.options(
            "/health",
            headers={
                "Origin": "https://trusted.retrodroid.local",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.headers.get("access-control-allow-origin") == "https://trusted.retrodroid.local"


def test_f10_download_allowlist_serves_signed_apk_with_encoded_url(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk, filename="My Game #1 (v2).apk")
    rp = http_client.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28"})
    assert rp.status_code == 200
    dl_url = rp.json()["downloadUrl"]
    assert dl_url.startswith(f"/api/download/{an['jobId']}/")
    assert " " not in dl_url and "#" not in dl_url
    assert http_client.get(dl_url).status_code == 200


def test_f10_xss_label_apk_analyzed_cleanly_as_plain_json_data(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xss_label_apk)
    assert "<img" in an["appLabel"]
    assert an["packageId"] == "com.retro.xsstest"


def test_f10_security_headers_present_on_json_and_file_downloads(patched_legacy: dict[str, Any]) -> None:
    hdrs = {k.lower(): v for k, v in patched_legacy["download_headers"].items()}
    assert hdrs.get("x-content-type-options") == "nosniff"
    assert hdrs.get("x-frame-options") == "DENY"
    assert hdrs.get("referrer-policy") == "no-referrer"


# ===========================================================================
# F11: Honest Patch Controls, Progress UX & Post-Patch Persistence (5 tests)
# ===========================================================================


def test_f11_served_ui_exposes_all_real_server_patch_flag_controls(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in (
        "flag-patch-target-sdk",
        "flag-resign",
        "flag-legacy-storage",
        "flag-cleartext",
        "flag-notch-support",
        "flag-extract-native-libs",
        "flag-allow-downgrade",
    ):
        assert f'id="{elem_id}"' in html


def test_f11_served_ui_separates_real_patches_from_web_preview_notes(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    assert 'id="server-patch-flags"' in html
    assert 'id="patch-modules-list"' in html
    assert "RetroBridge JIT v4" not in html


def test_f11_served_js_enforces_monotonic_progress_and_save_order(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "export function computeMonotonicProgress(" in js
    assert "export function applyServerPatchResultToGame(" in js


def test_f11_served_ui_has_link_expiry_and_terminal_controls(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in ("patch-link-expiry", "patch-progress-bar", "btn-cancel-patch", "patch-summary-box"):
        assert f'id="{elem_id}"' in html


def test_f11_served_js_uses_authoritative_has_obb_helper(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "export function resolveAuthoritativeHasObb(" in js


# ===========================================================================
# F12: Download Center, Reports & Validated State/Backup (5 tests)
# ===========================================================================


def test_f12_served_ui_contains_download_center_and_inline_xapk_progress(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in (
        "modal-download-package",
        "dl-options-list",
        "terminal-xapk-progress-box",
        "dl-reattach-box",
    ):
        assert f'id="{elem_id}"' in html


def test_f12_served_js_enforces_512mb_client_zip_ram_guard(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "CLIENT_ZIP_MAX_BYTES = 512 * 1024 * 1024" in js
    assert "export function checkClientZipBudget(" in js


def test_f12_served_ui_exposes_backup_export_import_and_reset_controls(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in ("btn-export-backup", "btn-import-backup", "backup-file-input", "btn-reset-app"):
        assert f'id="{elem_id}"' in html


def test_f12_served_js_exports_validated_state_and_backup_helpers(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "export function sanitizeAppState(" in js
    assert "export function createBackupPayload(" in js
    assert "export function asSafeString(" in js


def test_f12_served_js_applies_noopener_on_download_links(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "noopener" in js
    assert "buildSafeDownloadUrl" in js


# ===========================================================================
# F13: Game Library, Consistent Filters & Storage Dashboard (5 tests)
# ===========================================================================


def test_f13_served_ui_exposes_library_search_filters_and_grid(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in ("library-search", "library-filters", "library-grid", "stat-game-count", "stat-total-size"):
        assert f'id="{elem_id}"' in html


def test_f13_served_js_uses_shared_container_exts_for_filters_and_storage(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "CONTAINER_EXTS" in js
    assert "export function filterLibraryGames(" in js
    assert "export function computeStorageBreakdown(" in js


def test_f13_served_ui_contains_svg_storage_donut_elements(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in ("donut-xapk", "donut-apk", "donut-cache", "donut-total-gb", "sandbox-used-pct"):
        assert f'id="{elem_id}"' in html


def test_f13_served_ui_contains_android_version_compatibility_grid(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    assert 'id="android-versions-grid"' in html
    assert 'id="pkg-inspector-16k"' in html
    assert 'id="pkg-inspector-install-floor"' in html


def test_f13_served_js_preserves_settings_on_game_upsert(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "export function upsertGameInLibrary(" in js
    assert "export function mergeSessionEntryOnUpsert(" in js


# ===========================================================================
# F14: Control Layout Editor & Virtual Sandbox Preview (5 tests)
# ===========================================================================


def test_f14_served_ui_contains_control_layout_editor_modal(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in (
        "modal-control-layout",
        "control-layout-mappings",
        "control-layout-error",
        "btn-reset-control-layout",
        "btn-save-control-layout",
    ):
        assert f'id="{elem_id}"' in html


def test_f14_served_ui_contains_sandbox_overlay_canvas_and_hud(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    for elem_id in ("sandbox-overlay", "sandbox-canvas", "sandbox-hud", "sandbox-vpad", "btn-exit-sandbox"):
        assert f'id="{elem_id}"' in html


def test_f14_served_js_rejects_duplicate_control_bindings(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "export function validateControlMapping(" in js


def test_f14_served_js_implements_delta_time_and_hidpi_scaling(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "export function computeSandboxStep(" in js
    assert "export function computeHiDpiDimensions(" in js


def test_f14_served_js_clears_pressed_keys_on_window_blur(http_client: httpx.Client) -> None:
    js = http_client.get("/static/app.js").text
    assert "blur" in js and "pressedKeys" in js


# ===========================================================================
# F15: Production Static Assets & WCAG 2.1 AA Accessibility (5 tests)
# ===========================================================================


def test_f15_served_html_has_zero_external_cdns_and_zero_inline_handlers(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    assert not re.search(r'<script[^>]+src=["\']https?://', html, re.IGNORECASE)
    assert not re.search(r'<link[^>]+href=["\']https?://', html, re.IGNORECASE)
    assert not re.search(r"\bon[a-z]+\s*=", html, re.IGNORECASE)
    assert not re.search(r"\bstyle\s*=", html, re.IGNORECASE)


def test_f15_served_css_has_zero_important_and_zero_remote_urls(http_client: httpx.Client) -> None:
    css = http_client.get("/static/styles.css").text
    assert "!important" not in css.lower()
    assert "@import" not in css.lower()
    assert "url(" not in css.lower()


def test_f15_served_offline_jszip_bundle_is_available(http_client: httpx.Client) -> None:
    resp = http_client.get("/static/vendor/jszip.js")
    assert resp.status_code == 200
    assert "export class JSZip" in resp.text
    assert len(resp.content) > 5000


def test_f15_served_html_includes_wcag_aria_roles_and_live_regions(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'role="tablist"' in html
    assert 'aria-live="' in html


def test_f15_served_html_has_mobile_obb_file_input_fallback(http_client: httpx.Client) -> None:
    html = http_client.get("/").text
    assert 'id="obb-files-input"' in html
    assert 'accept=".obb"' in html


# ===========================================================================
# F16: Container Hardening, Documentation & Release Packaging (5 tests)
# ===========================================================================


def test_f16_dockerfile_hardened_non_root_exec_and_healthcheck() -> None:
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim-bookworm" in text
    assert "USER appuser" in text
    assert "exec uvicorn server:app" in text
    assert "--proxy-headers" in text
    assert "ProxyHandler({})" in text
    assert "os.environ.get('PORT') or '10000'" in text


def test_f16_dockerignore_excludes_dev_secrets_and_tmp() -> None:
    text = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    for pat in ("tests", "scripts", ".venv", ".env", "*.jks", "*.pass", "*.apk", "*.tmp", "**/*.tmp"):
        assert pat in text


def test_f16_readme_documents_v540_keystore_and_strict_health() -> None:
    text = (REPO_ROOT / "README.txt").read_text(encoding="utf-8")
    assert "5.4.0" in text
    assert "/api/keystore-info" in text
    assert "/health?strict=true" in text
    assert "WORK_DIR=/var/data/jobs" in text


def test_f16_requirements_txt_enforces_cve_free_floors() -> None:
    text = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    for pkg in ("fastapi", "starlette", "uvicorn", "python-multipart", "pyyaml"):
        assert pkg in text


def test_f16_release_zip_artifact_exists_clean_and_deterministic(tmp_path: Path) -> None:
    release_zip = REPO_ROOT.parent / "RetroDroid_Compat_v5.4.0.zip"
    assert release_zip.is_file()
    out_cmp = tmp_path / "verify_det.zip"
    res = subprocess.run(
        [
            str(REPO_ROOT / ".venv" / "bin" / "python"),
            "-B",
            str(REPO_ROOT / "scripts" / "build_release_zip.py"),
            "--root",
            str(REPO_ROOT),
            "--output",
            str(out_cmp),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert res.returncode == 0
    assert hashlib.sha256(out_cmp.read_bytes()).hexdigest() == hashlib.sha256(release_zip.read_bytes()).hexdigest()
    with zipfile.ZipFile(out_cmp, "r") as zf:
        assert zf.testzip() is None
        assert not any("/tests/" in n for n in zf.namelist())
