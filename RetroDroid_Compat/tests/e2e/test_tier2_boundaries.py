"""Opaque-box E2E Tier 2 Boundary, Corner & Negative/Error-Handling Tests (>= 80 tests).

Exercises invalid job IDs, missing resources, upload chunking bounds, hostile/corrupt archives,
patch-sign SDK/mode/downgrade bounds, OBB collisions, download allowlist & Range bounds,
API_TOKEN authentication enforcement, CORS denial, rate limiting, and degraded health states
against live ``uvicorn server:app`` instances.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.e2e.conftest import LiveServer, upload_via_analyze
from tests.e2e.fixtures_apk import E2ECorpus, verify_apk_with_aapt

INVALID_JOB_IDS = [
    "short",
    "UPPERCASE123",
    "zzzzzzzzzzzz",
    "0123456789abc",
    "../secret123",
    "0123456789a_",
]

MISSING_JOB_ID = "deadbeef0000"


@pytest.fixture(scope="module")
def t2_patched_job(http_client: httpx.Client, apk_corpus: E2ECorpus) -> dict[str, Any]:
    """One analyzed + patched legacy APK job for download/range/allowlist negative tests."""
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    rp = http_client.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28"})
    assert rp.status_code == 200, rp.text
    return {"analyze": an, "patch": rp.json()}


# ===========================================================================
# 1. Invalid job_id validation (400) across endpoints (18 tests)
# ===========================================================================


@pytest.mark.parametrize("bad_id", INVALID_JOB_IDS)
def test_t2_invalid_job_id_rejected_on_patch_status(http_client: httpx.Client, bad_id: str) -> None:
    if "/" in bad_id:
        resp = http_client.get(f"/api/patch-status/{bad_id}")
        assert resp.status_code in (400, 404)
    else:
        assert http_client.get(f"/api/patch-status/{bad_id}").status_code == 400


@pytest.mark.parametrize(
    ("method", "path", "data"),
    [
        ("GET", "/api/upload/status/BADJOBID1234", None),
        ("POST", "/api/upload/finish", {"jobId": "BADJOBID1234"}),
        ("POST", "/api/patch-sign", {"jobId": "BADJOBID1234"}),
        ("POST", "/api/patch-cancel/BADJOBID1234", None),
        ("DELETE", "/api/jobs/BADJOBID1234", None),
        ("POST", "/api/attach-obb/BADJOBID1234/init", {"fileName": "a.obb", "totalSize": "10", "totalChunks": "1"}),
        ("POST", "/api/attach-obb/BADJOBID1234/finish", {"uploadId": "0123456789ab"}),
        ("POST", "/api/full-xapk/BADJOBID1234", None),
        ("GET", "/api/full-xapk-status/BADJOBID1234", None),
        ("GET", "/api/download-full-xapk/BADJOBID1234", None),
        ("GET", "/api/download/BADJOBID1234/game.apk", None),
        ("GET", "/api/download-obb/BADJOBID1234/0", None),
    ],
)
def test_t2_invalid_job_id_returns_400_on_all_job_routes(
    http_client: httpx.Client,
    method: str,
    path: str,
    data: dict[str, str] | None,
) -> None:
    resp = http_client.request(method, path, data=data)
    assert resp.status_code == 400, f"{method} {path} returned {resp.status_code}: {resp.text}"


# ===========================================================================
# 2. Missing valid-format job_id returns 404 across endpoints (10 tests)
# ===========================================================================


@pytest.mark.parametrize(
    ("method", "path", "data"),
    [
        ("GET", f"/api/upload/status/{MISSING_JOB_ID}", None),
        ("POST", "/api/upload/finish", {"jobId": MISSING_JOB_ID}),
        ("POST", "/api/patch-sign", {"jobId": MISSING_JOB_ID}),
        ("GET", f"/api/patch-status/{MISSING_JOB_ID}", None),
        ("POST", f"/api/patch-cancel/{MISSING_JOB_ID}", None),
        ("DELETE", f"/api/jobs/{MISSING_JOB_ID}", None),
        ("POST", f"/api/full-xapk/{MISSING_JOB_ID}", None),
        ("GET", f"/api/full-xapk-status/{MISSING_JOB_ID}", None),
        ("GET", f"/api/download-full-xapk/{MISSING_JOB_ID}", None),
        ("GET", f"/api/download-obb/{MISSING_JOB_ID}/0", None),
    ],
)
def test_t2_unknown_job_id_returns_404(
    http_client: httpx.Client,
    method: str,
    path: str,
    data: dict[str, str] | None,
) -> None:
    resp = http_client.request(method, path, data=data)
    assert resp.status_code == 404, f"{method} {path} returned {resp.status_code}: {resp.text}"


# ===========================================================================
# 3. Upload init / chunk / finish boundary & negative cases (18 tests)
# ===========================================================================


def test_t2_analyze_rejects_empty_zero_byte_file(http_client: httpx.Client, apk_corpus: E2ECorpus) -> None:
    resp = http_client.post(
        "/api/analyze",
        files={"file": ("empty.apk", apk_corpus.empty_apk.read_bytes(), "application/octet-stream")},
    )
    assert resp.status_code == 400


@pytest.mark.parametrize(
    ("payload", "expected_status"),
    [
        ({"fileName": "a.apk", "totalSize": "0", "totalChunks": "1"}, 400),
        ({"fileName": "a.apk", "totalSize": "-5", "totalChunks": "1"}, 400),
        ({"fileName": "a.apk", "totalSize": str(6000 * 1024 * 1024), "totalChunks": "800"}, 413),
        ({"fileName": "a.apk", "totalSize": "1024", "totalChunks": "0"}, 400),
        ({"fileName": "a.apk", "totalSize": "1024", "totalChunks": "-1"}, 400),
        ({"fileName": "a.apk", "totalSize": "10", "totalChunks": "11"}, 400),
        ({"fileName": "a.apk", "totalSize": str(20 * 1024 * 1024), "totalChunks": "1"}, 400),
        ({"fileName": "a.apk", "totalSize": "100000", "totalChunks": "30000"}, 400),
        ({"fileName": "malware.exe", "totalSize": "1024", "totalChunks": "1"}, 400),
        ({"fileName": "notes.txt", "totalSize": "1024", "totalChunks": "1"}, 400),
        ({"fileName": "main.1.pkg.obb", "totalSize": "1024", "totalChunks": "1", "purpose": "obb"}, 400),
    ],
)
def test_t2_upload_init_rejects_invalid_bounds_and_purpose(
    http_client: httpx.Client,
    payload: dict[str, str],
    expected_status: int,
) -> None:
    resp = http_client.post("/api/upload/init", data=payload)
    assert resp.status_code == expected_status, f"{payload} -> {resp.status_code}: {resp.text}"


def test_t2_analyze_rejects_unsupported_extension(http_client: httpx.Client) -> None:
    resp = http_client.post(
        "/api/analyze",
        files={"file": ("script.sh", b"#!/bin/sh\necho hi\n", "application/octet-stream")},
    )
    assert resp.status_code == 400


def test_t2_upload_chunk_rejects_negative_and_oob_indices(http_client: httpx.Client) -> None:
    init_j = http_client.post(
        "/api/upload/init",
        data={"fileName": "bounds.apk", "totalSize": "2048", "totalChunks": "2"},
    ).json()
    jid = init_j["jobId"]
    r_neg = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "-1", "totalChunks": "2"},
        files={"chunk": ("c.bin", b"A" * 1024, "application/octet-stream")},
    )
    r_oob = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "2", "totalChunks": "2"},
        files={"chunk": ("c.bin", b"A" * 1024, "application/octet-stream")},
    )
    assert r_neg.status_code == 400
    assert r_oob.status_code == 400


def test_t2_upload_chunk_rejects_mismatched_total_chunks_and_zero_bytes(http_client: httpx.Client) -> None:
    init_j = http_client.post(
        "/api/upload/init",
        data={"fileName": "mismatch.apk", "totalSize": "2048", "totalChunks": "2"},
    ).json()
    jid = init_j["jobId"]
    r_mis = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "0", "totalChunks": "3"},
        files={"chunk": ("c.bin", b"A" * 1024, "application/octet-stream")},
    )
    r_zero = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "0", "totalChunks": "2"},
        files={"chunk": ("c.bin", b"", "application/octet-stream")},
    )
    assert r_mis.status_code == 400
    assert r_zero.status_code == 400


def test_t2_upload_chunk_rejects_wrong_byte_length(http_client: httpx.Client) -> None:
    init_j = http_client.post(
        "/api/upload/init",
        data={"fileName": "shortchunk.apk", "totalSize": "2048", "totalChunks": "2"},
    ).json()
    jid = init_j["jobId"]
    r_short = http_client.post(
        "/api/upload/chunk",
        data={"jobId": jid, "chunkIndex": "0", "totalChunks": "2"},
        files={"chunk": ("c.bin", b"A" * 100, "application/octet-stream")},
    )
    assert r_short.status_code == 400


def test_t2_upload_finish_rejects_missing_chunks(http_client: httpx.Client) -> None:
    init_j = http_client.post(
        "/api/upload/init",
        data={"fileName": "incomplete.apk", "totalSize": "2048", "totalChunks": "2"},
    ).json()
    jid = init_j["jobId"]
    assert (
        http_client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": "0", "totalChunks": "2"},
            files={"chunk": ("c.bin", b"A" * 1024, "application/octet-stream")},
        ).status_code
        == 200
    )
    r_fin = http_client.post("/api/upload/finish", data={"jobId": jid})
    assert r_fin.status_code == 400


def test_t2_upload_finish_duplicate_call_returns_409(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    raw = apk_corpus.legacy_apk.read_bytes()
    init_j = http_client.post(
        "/api/upload/init",
        data={"fileName": "once.apk", "totalSize": str(len(raw)), "totalChunks": "1"},
    ).json()
    jid = init_j["jobId"]
    assert (
        http_client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": "0", "totalChunks": "1"},
            files={"chunk": ("c.bin", raw, "application/octet-stream")},
        ).status_code
        == 200
    )
    assert http_client.post("/api/upload/finish", data={"jobId": jid}).status_code == 200
    assert http_client.post("/api/upload/finish", data={"jobId": jid}).status_code == 409


# ===========================================================================
# 4. Hostile & corrupt containers / APKs (7 tests)
# ===========================================================================


@pytest.mark.parametrize(
    "fixture_attr",
    [
        "zip_slip_xapk",
        "encrypted_zip",
        "corrupt_axml_apk",
        "missing_manifest_apk",
        "duplicate_apk_zip",
        "garbage_apk",
    ],
)
def test_t2_hostile_or_corrupt_archive_rejected_cleanly(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    fixture_attr: str,
) -> None:
    target_file: Path = getattr(apk_corpus, fixture_attr)
    resp = http_client.post(
        "/api/analyze",
        files={"file": (target_file.name, target_file.read_bytes(), "application/octet-stream")},
    )
    assert resp.status_code in (400, 422), f"{fixture_attr} unexpectedly returned {resp.status_code}: {resp.text}"


def test_t2_traversal_filename_never_writes_outside_job_dir(
    live_server: LiveServer,
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    data = upload_via_analyze(http_client, apk_corpus.legacy_apk, filename="../../../outside_escape.apk")
    assert not (live_server.work_dir / "outside_escape.apk").exists()
    assert not (live_server.work_dir.parent / "outside_escape.apk").exists()
    assert "/" not in data["sanitizedFileName"]


# ===========================================================================
# 5. Patch-sign boundary & negative cases (13 tests)
# ===========================================================================


@pytest.mark.parametrize("bad_mode", ["invalid_mode", "SIGN_ONLY", "patch_only"])
def test_t2_patch_sign_rejects_invalid_mode(
    http_client: httpx.Client,
    t2_patched_job: dict[str, Any],
    bad_mode: str,
) -> None:
    resp = http_client.post(
        "/api/patch-sign",
        data={"jobId": t2_patched_job["analyze"]["jobId"], "mode": bad_mode},
    )
    assert resp.status_code == 400


@pytest.mark.parametrize("bad_sdk", ["0", "-5", "101", "999"])
def test_t2_patch_sign_rejects_out_of_range_target_sdk(
    http_client: httpx.Client,
    t2_patched_job: dict[str, Any],
    bad_sdk: str,
) -> None:
    resp = http_client.post(
        "/api/patch-sign",
        data={"jobId": t2_patched_job["analyze"]["jobId"], "targetSdk": bad_sdk},
    )
    assert resp.status_code == 400


def test_t2_allow_downgrade_false_preserves_higher_target_sdk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.high_target_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "28", "allowDowngrade": "false"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["targetSdk"] == 34
    assert pdata["patchSummary"]["skippedDowngrade"] is True


def test_t2_allow_downgrade_true_permits_explicit_downgrade(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.high_target_apk)
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "28", "allowDowngrade": "true"},
    )
    assert rp.status_code == 200, rp.text
    pdata = rp.json()
    assert pdata["targetSdk"] == 28
    assert pdata["patchSummary"]["skippedDowngrade"] is False
    out = tmp_path / "downgraded28.apk"
    out.write_bytes(http_client.get(pdata["downloadUrl"]).content)
    assert verify_apk_with_aapt(out)["targetSdk"] == 28


def test_t2_min_sdk_floor_enforced_prevents_target_below_min_sdk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.high_target_apk)  # minSdk=24, targetSdk=34
    rp = http_client.post(
        "/api/patch-sign",
        data={"jobId": an["jobId"], "targetSdk": "19", "allowDowngrade": "true"},
    )
    assert rp.status_code == 200, rp.text
    assert rp.json()["targetSdk"] >= 24


def test_t2_resign_false_returns_unverified_and_blocks_full_xapk(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    rp = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28", "resign": "false"})
    assert rp.status_code == 200, rp.text
    assert rp.json()["verified"] is False
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}",
            files=[("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream"))],
        ).status_code
        == 200
    )
    rx = http_client.post(f"/api/full-xapk/{jid}")
    assert rx.status_code == 400


def test_t2_patch_cancel_on_completed_job_returns_409(
    http_client: httpx.Client,
    t2_patched_job: dict[str, Any],
) -> None:
    resp = http_client.post(f"/api/patch-cancel/{t2_patched_job['analyze']['jobId']}")
    assert resp.status_code == 409


def test_t2_full_xapk_before_patch_returns_409_and_without_obb_returns_400(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    assert http_client.post(f"/api/full-xapk/{jid}").status_code == 409
    assert http_client.get(f"/api/full-xapk-status/{jid}").status_code == 404
    assert http_client.get(f"/api/download-full-xapk/{jid}").status_code == 404
    assert http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"}).status_code == 200
    assert http_client.post(f"/api/full-xapk/{jid}").status_code == 400


# ===========================================================================
# 6. OBB boundary & collision cases (6 tests)
# ===========================================================================


def test_t2_attach_obb_rejects_non_obb_extension_and_zero_bytes(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    r_ext = http_client.post(
        f"/api/attach-obb/{jid}",
        files=[("files", ("not_obb.zip", b"1234", "application/octet-stream"))],
    )
    r_zero = http_client.post(
        f"/api/attach-obb/{jid}",
        files=[("files", ("main.10.com.retro.legacy.obb", b"", "application/octet-stream"))],
    )
    assert r_ext.status_code == 400
    assert r_zero.status_code == 400


def test_t2_chunked_obb_init_rejects_non_obb_extension_and_incomplete_apk_job(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    r_ext = http_client.post(
        f"/api/attach-obb/{an['jobId']}/init",
        data={"fileName": "bad.txt", "totalSize": "128", "totalChunks": "1"},
    )
    assert r_ext.status_code == 400

    init_incomplete = http_client.post(
        "/api/upload/init",
        data={"fileName": "unfinished.apk", "totalSize": "1024", "totalChunks": "1"},
    ).json()
    r_inc = http_client.post(
        f"/api/attach-obb/{init_incomplete['jobId']}/init",
        data={"fileName": "main.1.pkg.obb", "totalSize": "128", "totalChunks": "1"},
    )
    assert r_inc.status_code == 409


def test_t2_obb_ancestor_descendant_path_collision_rejected(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    r1 = http_client.post(
        f"/api/attach-obb/{jid}",
        files=[("files", ("folder.obb", b"OBB_AS_FILE" * 16, "application/octet-stream"))],
    )
    assert r1.status_code == 200
    r2 = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={"fileName": "folder.obb/nested.obb", "totalSize": "64", "totalChunks": "1"},
    )
    if r2.status_code == 200:
        uid = r2.json()["uploadId"]
        assert (
            http_client.post(
                f"/api/attach-obb/{jid}/chunk",
                data={"uploadId": uid, "chunkIndex": "0", "totalChunks": "1"},
                files={"chunk": ("c.bin", b"X" * 64, "application/octet-stream")},
            ).status_code
            == 200
        )
        r_fin = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": uid})
        assert r_fin.status_code in (400, 422)
    else:
        assert r2.status_code in (400, 422)


def test_t2_chunked_obb_finish_missing_chunk_and_unknown_upload_id(
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    r_unk = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": MISSING_JOB_ID})
    assert r_unk.status_code == 404
    r_bad_uid = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": "INVALID"})
    assert r_bad_uid.status_code == 400

    init_obb = http_client.post(
        f"/api/attach-obb/{jid}/init",
        data={"fileName": "main.10.com.retro.legacy.obb", "totalSize": "2048", "totalChunks": "2"},
    ).json()
    r_miss = http_client.post(f"/api/attach-obb/{jid}/finish", data={"uploadId": init_obb["uploadId"]})
    assert r_miss.status_code == 400


@pytest.mark.parametrize(("obb_index", "expected"), [(-1, 400), (99, 404)])
def test_t2_download_obb_invalid_or_oob_index(
    http_client: httpx.Client,
    t2_patched_job: dict[str, Any],
    obb_index: int,
    expected: int,
) -> None:
    jid = t2_patched_job["analyze"]["jobId"]
    assert http_client.get(f"/api/download-obb/{jid}/{obb_index}").status_code == expected


# ===========================================================================
# 7. Download allowlist, Range bounds, Auth, CORS, Rate limit & Degraded (16 tests)
# ===========================================================================


@pytest.mark.parametrize(
    "forbidden_name",
    [
        "upload_meta.json",
        "job_state.json",
        "patch_result.json",
        "legacy_game.apk",
        "container_meta.json",
        "nonexistent_secret.pass",
    ],
)
def test_t2_download_allowlist_blocks_non_output_files_with_403(
    http_client: httpx.Client,
    t2_patched_job: dict[str, Any],
    forbidden_name: str,
) -> None:
    jid = t2_patched_job["analyze"]["jobId"]
    resp = http_client.get(f"/api/download/{jid}/{forbidden_name}")
    assert resp.status_code == 403, f"{forbidden_name} -> {resp.status_code}: {resp.text}"


def test_t2_download_range_206_416_and_malformed(
    http_client: httpx.Client,
    t2_patched_job: dict[str, Any],
) -> None:
    dl_url = t2_patched_job["patch"]["downloadUrl"]
    r206 = http_client.get(dl_url, headers={"Range": "bytes=0-15"})
    assert r206.status_code == 206
    assert len(r206.content) == 16
    assert r206.content[:2] == b"PK"

    r416 = http_client.get(dl_url, headers={"Range": "bytes=999999999-"})
    assert r416.status_code == 416

    r_bad = http_client.get(dl_url, headers={"Range": "bytes=not-a-range"})
    assert r_bad.status_code in (400, 416)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/keystore-info"),
        ("GET", "/api/jobs"),
        ("POST", "/api/upload/init"),
        ("GET", f"/api/download/{MISSING_JOB_ID}/a.apk"),
        ("GET", f"/api/download-obb/{MISSING_JOB_ID}/0"),
    ],
)
def test_t2_api_token_blocks_unauthenticated_requests_with_401(
    auth_server: LiveServer,
    method: str,
    path: str,
) -> None:
    with auth_server.client() as c:
        resp = c.request(method, path)
        assert resp.status_code == 401
        assert "bearer" in resp.headers.get("www-authenticate", "").lower()


def test_t2_api_token_rejects_wrong_token_and_query_param_on_non_download(auth_server: LiveServer) -> None:
    with auth_server.client() as c:
        assert c.get("/api/jobs", headers={"Authorization": "Bearer wrong-token"}).status_code == 401
        assert c.get(f"/api/jobs?token={auth_server.api_token}").status_code == 401
        h = c.get("/health")
        assert h.status_code == 200
        assert h.json()["authRequired"] is True


def test_t2_cors_disallowed_origin_receives_no_acao_header(auth_server: LiveServer) -> None:
    with auth_server.client() as c:
        r = c.get("/health", headers={"Origin": "https://evil.attacker.example"})
        assert r.status_code == 200
        assert r.headers.get("access-control-allow-origin") is None


def test_t2_rate_limit_enforces_429_with_retry_after(server_factory: Any) -> None:
    srv = server_factory(rate_limit_per_min=3)
    statuses: list[int] = []
    retry_after: str | None = None
    with srv.client() as c:
        for _ in range(6):
            r = c.get("/api/jobs")
            statuses.append(r.status_code)
            if r.status_code == 429:
                retry_after = r.headers.get("retry-after")
                break
    assert 429 in statuses, f"Expected 429 rate limit, got {statuses}"
    assert retry_after is not None and int(retry_after) >= 1


def test_t2_degraded_server_health_strict_503_and_patch_failure_preserves_keystore(
    degraded_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    with degraded_server.client() as c:
        r_live = c.get("/health")
        assert r_live.status_code == 200
        assert r_live.json()["status"] == "degraded"
        assert r_live.json()["healthy"] is False

        r_strict = c.get("/health?strict=true")
        assert r_strict.status_code == 503

        an = upload_via_analyze(c, apk_corpus.legacy_apk)
        rp = c.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28", "resign": "true"})
        assert rp.status_code >= 500
    assert degraded_server.keystore_path.read_bytes() == b"NOT_A_VALID_JKS_KEYSTORE_DO_NOT_DELETE"
