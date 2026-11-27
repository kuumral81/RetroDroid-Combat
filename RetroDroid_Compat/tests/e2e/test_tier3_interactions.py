"""Opaque-box E2E Tier 3 Pairwise Cross-Feature Interaction Tests (20 tests).

Verifies multi-feature combinations against live ``uvicorn server:app`` instances and real
Android CLI tools (``aapt``, ``zipalign``, ``apksigner``).
"""

from __future__ import annotations

import json
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

from tests.e2e.conftest import (
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


def _poll_until_terminal(client: httpx.Client, url: str, timeout: float = 45.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        r = client.get(url)
        assert r.status_code == 200, f"poll {url} failed ({r.status_code}): {r.text}"
        last = r.json()
        if last.get("status") in {"done", "error", "canceled", "interrupted"}:
            return last
        time.sleep(0.1)
    raise AssertionError(f"Timed out polling {url}; last state={last}")


def test_t3_chunked_resume_plus_all_5_manifest_flags_verified_by_cli(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    raw = apk_corpus.legacy_apk.read_bytes()
    init1 = http_client.post(
        "/api/upload/init",
        data={"fileName": "resumed_flags.apk", "totalSize": str(len(raw)), "totalChunks": "2"},
    ).json()
    jid = init1["jobId"]
    csz = int(init1["chunkSizeBytes"])
    chunks = [raw[:csz], raw[csz:]]
    assert (
        http_client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": "0", "totalChunks": "2"},
            files={"chunk": ("c0.bin", chunks[0], "application/octet-stream")},
        ).status_code
        == 200
    )

    st = http_client.get(f"/api/upload/status/{jid}").json()
    assert st["missingChunks"] == [1]

    # Resume and finish remaining chunk
    assert (
        http_client.post(
            "/api/upload/init",
            data={"jobId": jid, "fileName": "resumed_flags.apk", "totalSize": str(len(raw)), "totalChunks": "2"},
        ).status_code
        == 200
    )
    assert (
        http_client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": "1", "totalChunks": "2"},
            files={"chunk": ("c1.bin", chunks[1], "application/octet-stream")},
        ).status_code
        == 200
    )
    assert http_client.post("/api/upload/finish", data={"jobId": jid}).status_code == 200

    rp = http_client.post(
        "/api/patch-sign",
        data={
            "jobId": jid,
            "targetSdk": "34",
            "patchTargetSdk": "true",
            "addLegacyStorage": "true",
            "enableCleartext": "true",
            "addNotchSupport": "true",
            "forceExtractNativeLibs": "true",
            "resign": "true",
        },
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["verified"] is True
    out = tmp_path / "all_flags_signed.apk"
    out.write_bytes(http_client.get(pdata["downloadUrl"]).content)

    badging = verify_apk_with_aapt(out)
    assert badging["targetSdk"] == 34
    xmltree = verify_apk_xmltree(out)
    for attr in (
        "requestLegacyExternalStorage",
        "usesCleartextTraffic",
        "resizeableActivity",
        "android.max_aspect",
        "extractNativeLibs",
        "android:exported",
    ):
        assert attr in xmltree, f"Missing {attr} in patched manifest xmltree"

    use_16k = bool(http_client.get("/health").json().get("zipalign16kSupported"))
    ok_align, msg_align = verify_apk_with_zipalign(out, page_16k=use_16k)
    assert ok_align, msg_align
    ok_sig, msg_sig = verify_apk_with_apksigner(out)
    assert ok_sig, msg_sig


def test_t3_xapk_splits_plus_chunked_extra_obb_plus_async_full_xapk_v2(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xapk_v2)
    jid = an["jobId"]

    rp = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28", "patchTargetSdk": "true"})
    assert rp.status_code == 200, rp.text
    assert rp.json()["verified"] is True

    # Attach extra patch OBB via chunked OBB endpoints
    obb_bytes = apk_corpus.obb_patch.read_bytes()
    r_init = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={"fileName": "patch.42.com.retro.xapkgame.obb", "totalSize": str(len(obb_bytes)), "totalChunks": "2"},
    )
    assert r_init.status_code == 200, r_init.text
    uid = r_init.json()["uploadId"]
    csz = r_init.json()["chunkSizeBytes"]
    for idx, part in enumerate((obb_bytes[:csz], obb_bytes[csz:])):
        rc = http_client.post(
            f"/api/attach-obb/{jid}/chunk",
            data={"uploadId": uid, "chunkIndex": str(idx), "totalChunks": "2"},
            files={"chunk": (f"p{idx}.bin", part, "application/octet-stream")},
        )
        assert rc.status_code == 200
    assert http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": uid}).status_code == 200

    # Build Full XAPK asynchronously
    rx = http_client.post(f"/api/full-xapk/{jid}", data={"background": "true"})
    assert rx.status_code == 200
    final = _poll_until_terminal(http_client, f"/api/full-xapk-status/{jid}")
    assert final["status"] == "done", final

    dl = http_client.get(f"/api/download-full-xapk/{jid}")
    assert dl.status_code == 200
    xapk_out = tmp_path / "full_with_splits_and_2obbs.xapk"
    xapk_out.write_bytes(dl.content)

    with zipfile.ZipFile(xapk_out, "r") as zf:
        names = zf.namelist()
        assert "manifest.json" in names
        assert "icon.png" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["xapk_version"] == 2
        assert len(manifest["split_apks"]) == 3  # base + 2 splits
        assert len(manifest["expansions"]) == 2  # container main OBB + extra patch OBB
        assert manifest["total_size"] > 0

        # Independently verify inner signed base APK via apksigner
        base_entry = next(s["file"] for s in manifest["split_apks"] if s["id"] == "base")
        extracted_base = tmp_path / base_entry
        extracted_base.write_bytes(zf.read(base_entry))
        ok_sig, sig_msg = verify_apk_with_apksigner(extracted_base)
        assert ok_sig, sig_msg


def test_t3_api_token_plus_download_query_token_plus_bare_401_plus_cors(
    auth_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    tok = auth_server.api_token
    with auth_server.client(headers={"Authorization": f"Bearer {tok}"}) as auth_c:
        an = upload_via_analyze(auth_c, apk_corpus.legacy_apk)
        rp = auth_c.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28"})
        assert rp.status_code == 200
        dl_url = rp.json()["downloadUrl"]

    with auth_server.client() as c:
        assert c.get(dl_url).status_code == 401
        r_good = c.get(f"{dl_url}?token={tok}", headers={"Origin": "https://trusted.retrodroid.local"})
        assert r_good.status_code == 200
        assert r_good.headers.get("access-control-allow-origin") == "https://trusted.retrodroid.local"
        r_bad_cors = c.get(f"{dl_url}?token={tok}", headers={"Origin": "https://evil.invalid"})
        assert r_bad_cors.status_code == 200
        assert r_bad_cors.headers.get("access-control-allow-origin") is None


def test_t3_background_patch_cancel_then_delete_job(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xapk_v2)
    jid = an["jobId"]
    rp = http_client.post(
        "/api/patch-sign",
        data={
            "jobId": jid,
            "targetSdk": "34",
            "addLegacyStorage": "true",
            "enableCleartext": "true",
            "background": "true",
        },
    )
    assert rp.status_code == 200

    # Immediately request cancellation while multi-split apktool pipeline is running
    rc = http_client.post(f"/api/patch-cancel/{jid}")
    assert rc.status_code in (200, 409)  # 200 if caught mid-flight, 409 if already finished fast

    final = _poll_until_terminal(http_client, f"/api/patch-status/{jid}")
    assert final["status"] in {"canceled", "done"}
    if rc.status_code == 200:
        assert final["status"] == "canceled"

    # Wait briefly for worker thread finally block to release patch slot, then DELETE must succeed
    deadline = time.monotonic() + 10.0
    deleted = False
    while time.monotonic() < deadline:
        rd = http_client.delete(f"/api/jobs/{jid}")
        if rd.status_code == 200:
            assert rd.json()["deleted"] is True
            deleted = True
            break
        assert rd.status_code == 409, f"Unexpected delete status: {rd.status_code} {rd.text}"
        time.sleep(0.1)
    assert deleted, "Slot was not released after cancel for DELETE /api/jobs/{jid}"


def test_t3_server_restart_persistence_from_job_state_json(
    server_factory: Any,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    shared_work = tmp_path / "persist_work"
    shared_ks = tmp_path / "persist_ks" / "retrodroid.jks"

    srv1 = server_factory(work_dir=shared_work, keystore_path=shared_ks)
    with srv1.client() as c1:
        an = upload_via_analyze(c1, apk_corpus.legacy_apk)
        jid = an["jobId"]
        rp = c1.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"})
        assert rp.status_code == 200
        dl_url = rp.json()["downloadUrl"]
        assert (
            c1.post(
                f"/api/attach-obb/{jid}",
                files=[("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream"))],
            ).status_code
            == 200
        )
    srv1.stop()

    # Boot brand-new uvicorn process pointing at the exact same WORK_DIR + KEYSTORE_PATH
    srv2 = server_factory(work_dir=shared_work, keystore_path=shared_ks)
    with srv2.client() as c2:
        jobs = c2.get("/api/jobs").json()["jobs"]
        assert any(j["jobId"] == jid for j in jobs)
        st = c2.get(f"/api/patch-status/{jid}").json()
        assert st["status"] == "done"
        assert c2.get(dl_url).status_code == 200
        rx = c2.post(f"/api/full-xapk/{jid}")
        assert rx.status_code == 200
        assert c2.get(f"/api/download-full-xapk/{jid}").status_code == 200


def test_t3_repatch_then_resign_only_preserves_source_and_upgrades_sdk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]

    r1 = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).json()
    assert r1["targetSdk"] == 28
    assert r1["repatchAvailable"] is True

    r2 = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "34"}).json()
    assert r2["targetSdk"] == 34
    out34 = tmp_path / "repatched34.apk"
    out34.write_bytes(http_client.get(r2["downloadUrl"]).content)
    assert verify_apk_with_aapt(out34)["targetSdk"] == 34

    r3 = http_client.post("/api/patch-sign", data={"jobId": jid, "mode": "resign_only", "resign": "true"}).json()
    assert r3["verified"] is True
    out_rs = tmp_path / "resigned_after_repatch.apk"
    out_rs.write_bytes(http_client.get(r3["downloadUrl"]).content)
    ok_sig, msg = verify_apk_with_apksigner(out_rs)
    assert ok_sig, msg


def test_t3_elf64_16kb_vs_4kb_plus_split_abi_preservation_post_patch(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an16 = upload_via_analyze(http_client, apk_corpus.elf16k_apk)
    p16 = http_client.post("/api/patch-sign", data={"jobId": an16["jobId"], "targetSdk": "34"}).json()
    assert p16["pageSize16kStatus"] == "compatible"
    assert "arm64-v8a" in p16["abis"]

    an4 = upload_via_analyze(http_client, apk_corpus.elf4k_apk)
    p4 = http_client.post("/api/patch-sign", data={"jobId": an4["jobId"], "targetSdk": "34"}).json()
    assert p4["pageSize16kStatus"] == "incompatible"


def test_t3_apkm_info_json_plus_api34_patch_plus_signed_apks_bundle(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.apkm_bundle)
    rp = http_client.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "34"})
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert "arm64-v8a" in pdata["abis"]
    sb = pdata["splitBundle"]
    dl = http_client.get(sb["downloadUrl"])
    assert dl.status_code == 200
    bundle = tmp_path / sb["fileName"]
    bundle.write_bytes(dl.content)

    with zipfile.ZipFile(bundle, "r") as zf:
        apk_members = [n for n in zf.namelist() if n.endswith(".apk")]
        assert len(apk_members) >= 2
        for member in apk_members:
            extracted = tmp_path / Path(member).name
            extracted.write_bytes(zf.read(member))
            ok_sig, sig_msg = verify_apk_with_apksigner(extracted)
            assert ok_sig, f"{member}: {sig_msg}"


def test_t3_plain_zip_backslash_plus_container_obb_download_plus_full_xapk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.plain_zip_backslash)
    jid = an["jobId"]
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).status_code == 200
    robb = http_client.get(f"/api/download-obb/{jid}/0")
    assert robb.status_code == 200
    assert robb.content == apk_corpus.obb_main.read_bytes()

    rx = http_client.post(f"/api/full-xapk/{jid}")
    assert rx.status_code == 200
    xapk = tmp_path / "from_win_zip.xapk"
    xapk.write_bytes(http_client.get(f"/api/download-full-xapk/{jid}").content)
    with zipfile.ZipFile(xapk, "r") as zf:
        assert all("\\" not in n for n in zf.namelist())


def test_t3_multipart_obb_append_vs_chunked_replace_existing_and_full_xapk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).status_code == 200

    # 1) Attach main OBB via multipart
    r1 = http_client.post(
        f"/api/attach-obb/{jid}",
        files=[("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream"))],
    )
    assert r1.status_code == 200 and r1.json()["count"] == 1

    # 2) Append patch OBB via chunked endpoint (replaceExisting=false) -> count 2
    pbytes = apk_corpus.obb_patch.read_bytes()
    init_append = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={
            "fileName": apk_corpus.obb_patch.name,
            "totalSize": str(len(pbytes)),
            "totalChunks": "1",
            "replaceExisting": "false",
        },
    ).json()
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}/chunk",
            data={"uploadId": init_append["uploadId"], "chunkIndex": "0", "totalChunks": "1"},
            files={"chunk": ("c.bin", pbytes, "application/octet-stream")},
        ).status_code
        == 200
    )
    fin_append = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": init_append["uploadId"]}).json()
    assert fin_append["count"] == 2

    # 3) Replace all OBBs via chunked endpoint (replaceExisting=true) -> count 1
    init_rep = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={
            "fileName": apk_corpus.obb_patch.name,
            "totalSize": str(len(pbytes)),
            "totalChunks": "1",
            "replaceExisting": "true",
        },
    ).json()
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}/chunk",
            data={"uploadId": init_rep["uploadId"], "chunkIndex": "0", "totalChunks": "1"},
            files={"chunk": ("c.bin", pbytes, "application/octet-stream")},
        ).status_code
        == 200
    )
    fin_rep = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": init_rep["uploadId"]}).json()
    assert fin_rep["count"] == 1

    rx = http_client.post(f"/api/full-xapk/{jid}").json()
    assert len(rx["manifest"]["expansions"]) == 1


def test_t3_downgrade_protection_then_explicit_override_on_same_job(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.high_target_apk)
    jid = an["jobId"]
    r_keep = http_client.post(
        "/api/patch-sign",
        data={"jobId": jid, "targetSdk": "28", "allowDowngrade": "false"},
    ).json()
    assert r_keep["targetSdk"] == 34
    assert r_keep["patchSummary"]["skippedDowngrade"] is True

    r_down = http_client.post(
        "/api/patch-sign",
        data={"jobId": jid, "targetSdk": "28", "allowDowngrade": "true"},
    ).json()
    assert r_down["targetSdk"] == 28
    assert r_down["patchSummary"]["skippedDowngrade"] is False


def test_t3_compressed_arsc_plus_duplicates_plus_legacy_storage_patch(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.compressed_arsc_apk)
    assert an["resourcesArscCompressed"] is True
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "28", "addLegacyStorage": "true"},
    )
    assert rp.status_code == 200
    out = tmp_path / "dirty_fixed.apk"
    out.write_bytes(http_client.get(rp.json()["downloadUrl"]).content)
    with zipfile.ZipFile(out, "r") as zf:
        assert zf.getinfo("resources.arsc").compress_type == zipfile.ZIP_STORED
        assert len(zf.namelist()) == len(set(zf.namelist()))
    assert "requestLegacyExternalStorage" in verify_apk_xmltree(out)
    ok_sig, _ = verify_apk_with_apksigner(out)
    assert ok_sig


def test_t3_no_uses_sdk_plus_manifest_flags_plus_apksigner(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.no_uses_sdk_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={
            "jobId": an["jobId"],
            "targetSdk": "31",
            "enableCleartext": "true",
            "addNotchSupport": "true",
        },
    )
    assert rp.status_code == 200
    out = tmp_path / "nosdk_patched.apk"
    out.write_bytes(http_client.get(rp.json()["downloadUrl"]).content)
    assert verify_apk_with_aapt(out)["targetSdk"] == 31
    tree = verify_apk_xmltree(out)
    assert "usesCleartextTraffic" in tree
    assert "android.max_aspect" in tree
    ok_sig, _ = verify_apk_with_apksigner(out)
    assert ok_sig


def test_t3_unverified_resign_false_repatched_with_resign_true_unlocks_full_xapk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}",
            files=[("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream"))],
        ).status_code
        == 200
    )
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28", "resign": "false"}).status_code == 200
    assert http_client.post(f"/api/full-xapk/{jid}").status_code == 400
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28", "resign": "true"}).status_code == 200
    assert http_client.post(f"/api/full-xapk/{jid}").status_code == 200


def test_t3_chunked_upload_with_auth_token_plus_range_download_with_query_token(
    auth_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    tok = auth_server.api_token
    with auth_server.client(headers={"X-API-Token": tok}) as auth_c:
        _, fin = upload_via_chunks(auth_c, apk_corpus.legacy_apk, chunk_size=4096)
        rp = auth_c.post("/api/patch-sign", data={"jobId": fin["jobId"], "targetSdk": "28"})
        assert rp.status_code == 200
        dl_url = rp.json()["downloadUrl"]

    with auth_server.client() as c:
        r_part = c.get(f"{dl_url}?token={tok}", headers={"Range": "bytes=0-63"})
        assert r_part.status_code == 206
        assert len(r_part.content) == 64
        assert r_part.content[:2] == b"PK"


def test_t3_degraded_server_allows_analyze_and_resign_false_but_blocks_resign_true(
    degraded_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    with degraded_server.client() as c:
        an = upload_via_analyze(c, apk_corpus.legacy_apk)
        r_unsigned = c.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28", "resign": "false"})
        assert r_unsigned.status_code == 200
        assert r_unsigned.json()["verified"] is False
        r_signed = c.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28", "resign": "true"})
        assert r_signed.status_code >= 500


def test_t3_concurrency_slot_limit_429_and_same_job_conflict_409(
    auth_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    tok = auth_server.api_token
    with auth_server.client(headers={"Authorization": f"Bearer {tok}"}) as c:
        an_a = upload_via_analyze(c, apk_corpus.xapk_v2)
        an_b = upload_via_analyze(c, apk_corpus.legacy_apk)
        jid_a, jid_b = an_a["jobId"], an_b["jobId"]

        ra = c.post(
            "/api/patch-sign",
            data={"jobId": jid_a, "targetSdk": "34", "addLegacyStorage": "true", "background": "true"},
        )
        assert ra.status_code == 200
        r_same = c.post("/api/patch-sign", data={"jobId": jid_a, "targetSdk": "28"})
        r_other = c.post("/api/patch-sign", data={"jobId": jid_b, "targetSdk": "28"})
        assert r_same.status_code in (409, 200)
        assert r_other.status_code in (429, 200)
        if r_same.status_code == 409:
            assert r_other.status_code == 429

        _poll_until_terminal(c, f"/api/patch-status/{jid_a}")
        if r_other.status_code == 429:
            deadline = time.monotonic() + 10.0
            started_b = False
            while time.monotonic() < deadline:
                rb = c.post("/api/patch-sign", data={"jobId": jid_b, "targetSdk": "28"})
                if rb.status_code == 200:
                    started_b = True
                    break
                assert rb.status_code == 429, f"Unexpected status: {rb.status_code} {rb.text}"
                time.sleep(0.1)
            assert started_b, "Slot was not released after job A finished"


def test_t3_interrupted_in_flight_job_marked_interrupted_on_restart(
    server_factory: Any,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    shared_work = tmp_path / "interrupt_work"
    shared_ks = tmp_path / "interrupt_ks" / "retrodroid.jks"
    srv1 = server_factory(work_dir=shared_work, keystore_path=shared_ks)
    with srv1.client() as c1:
        an = upload_via_analyze(c1, apk_corpus.legacy_apk)
        jid = an["jobId"]
    srv1.stop()

    # Simulate server crash mid-patch by writing status="running" to job_state.json
    state_file = shared_work / jid / "job_state.json"
    state = json.loads(state_file.read_text(encoding="utf-8"))
    state["status"] = "running"
    state["stage"] = "Simulating crash mid-patch"
    state_file.write_text(json.dumps(state), encoding="utf-8")

    srv2 = server_factory(work_dir=shared_work, keystore_path=shared_ks)
    with srv2.client() as c2:
        st = c2.get(f"/api/patch-status/{jid}").json()
        assert st["status"] == "interrupted"
        # Job is unlocked and can now be patched cleanly
        assert c2.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).status_code == 200


def test_t3_xss_apk_full_pipeline_and_keystore_cert_consistency(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xss_label_apk)
    jid = an["jobId"]
    rp = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"})
    assert rp.status_code == 200
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}",
            files=[("files", ("main.9.com.retro.xsstest.obb", b"XSS_OBB" * 64, "application/octet-stream"))],
        ).status_code
        == 200
    )
    rx = http_client.post(f"/api/full-xapk/{jid}").json()
    assert "<img" in rx["manifest"]["name"]

    signed_apk = tmp_path / "xss_signed.apk"
    signed_apk.write_bytes(http_client.get(rp.json()["downloadUrl"]).content)
    ok_sig, sig_out = verify_apk_with_apksigner(signed_apk)
    assert ok_sig, sig_out
    ks_sha = http_client.get("/api/keystore-info").json()["sha256"].replace(":", "").lower()
    assert ks_sha in sig_out.replace(":", "").lower()


def test_t3_delete_job_blocked_with_409_while_active_then_succeeds(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.xapk_v2)
    jid = an["jobId"]
    assert (
        http_client.post(
            "/api/patch-sign",
            data={"jobId": jid, "targetSdk": "34", "addLegacyStorage": "true", "background": "true"},
        ).status_code
        == 200
    )
    rd_busy = http_client.delete(f"/api/jobs/{jid}")
    assert rd_busy.status_code in (409, 200)
    if rd_busy.status_code == 409:
        _poll_until_terminal(http_client, f"/api/patch-status/{jid}")
        deadline = time.monotonic() + 10.0
        deleted = False
        while time.monotonic() < deadline:
            rd = http_client.delete(f"/api/jobs/{jid}")
            if rd.status_code == 200:
                deleted = True
                break
            assert rd.status_code == 409, f"Unexpected delete status: {rd.status_code} {rd.text}"
            time.sleep(0.1)
        assert deleted, "Slot was not released after patch completion for DELETE"
