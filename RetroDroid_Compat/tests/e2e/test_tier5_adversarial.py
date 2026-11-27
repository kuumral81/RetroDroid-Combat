"""White-box Tier 5 Adversarial Hardening E2E Tests (26 tests).

Directly proves every one of the 8 surgical Tier-5 fixes (M2 ASGI cancellation notes #1 & #2,
M3 hostile object-to-primitive defensive coercion #3, M4 strict archive_prefix / case-insensitive
exclusions / static symlink rejection / Dockerfile HEALTHCHECK empty PORT & HTTP_PROXY immunity /
README /api/keystore-info & strict health docs / .dockerignore *.tmp parity #4–#8), plus live
TCP RST mid-download cleanup, job-directory symlink attacks, keystore secret argv/HTTP isolation,
and source archive immutability.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import anyio
import anyio.lowlevel
import httpx
import pytest

import server as server_mod
from retrodroid.config import Settings
from retrodroid.jobs import JobManager
from tests.e2e.conftest import REPO_ROOT, LiveServer, upload_via_analyze
from tests.e2e.fixtures_apk import E2ECorpus

EXPECTED_V531_SHA256 = "d0e91199c51e882d02d03f8eae7a9d8c8b6c4c5c0ad22662e81cc3dfb133ad8f"


def _load_build_release_zip_module() -> Any:
    script_path = REPO_ROOT / "scripts" / "build_release_zip.py"
    spec = importlib.util.spec_from_file_location("tier5_build_release_zip", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_settings(tmp_path: Path) -> Settings:
    return Settings(
        WORK_DIR=tmp_path / "work",
        KEYSTORE_PATH=tmp_path / "ks" / "retrodroid.jks",
        RATE_LIMIT_PER_MIN=0,
        MAX_CONCURRENT_PATCHES=1,
    )


def _find_route_endpoint(app: Any, path: str, method: str = "POST") -> Any:
    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"Route {method} {path} not found")


# ===========================================================================
# Fix #1: M2 ASGI Cancellation Note 1 — api_patch_sign & api_full_xapk slot release
# ===========================================================================


def test_t5_fix1_api_patch_sign_cancelled_error_releases_patch_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External asyncio.CancelledError during api_patch_sign _prepare MUST release patch slot & active_refs."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "a1b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    jm.create_state(jid, status="analyzed")

    endpoint = _find_route_endpoint(app, "/api/patch-sign", "POST")
    entered = threading.Event()
    release_blocker = threading.Event()

    def _blocking_resolve(_dir: Path) -> Path:
        entered.set()
        release_blocker.wait(timeout=5.0)
        return jdir / "missing.apk"

    monkeypatch.setattr(server_mod, "_resolve_source_apk", _blocking_resolve)

    async def _exercise() -> None:
        task = asyncio.create_task(
            endpoint(
                jobId=jid,
                targetSdk=28,
                mode="patch_and_sign",
                resign=True,
                background=False,
                patchTargetSdk=True,
                addLegacyStorage=False,
                enableCleartext=False,
                addNotchSupport=False,
                forceExtractNativeLibs=False,
                allowDowngrade=False,
            )
        )
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert jm.active_patch_count == 1
        assert jm.is_patch_active(jid) is True

        task.cancel()
        release_blocker.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_exercise())
    assert jm.active_patch_count == 0
    assert jm.is_patch_active(jid) is False
    assert jm.active_refs(jid) == 0


def test_t5_fix1_api_full_xapk_cancelled_error_releases_patch_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External asyncio.CancelledError during api_full_xapk _prepare MUST release patch slot & active_refs."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "b1b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    jm.create_state(jid, status="done")

    endpoint = _find_route_endpoint(app, "/api/full-xapk/{job_id}", "POST")
    entered = threading.Event()
    release_blocker = threading.Event()
    orig_get_state = jm.get_job_state

    def _blocking_get_state(job_id: str) -> dict[str, Any] | None:
        entered.set()
        release_blocker.wait(timeout=5.0)
        return orig_get_state(job_id)

    monkeypatch.setattr(jm, "get_job_state", _blocking_get_state)

    async def _exercise() -> None:
        task = asyncio.create_task(endpoint(job_id=jid, background=False))
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert jm.active_patch_count == 1

        task.cancel()
        release_blocker.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_exercise())
    assert jm.active_patch_count == 0
    assert jm.is_patch_active(jid) is False
    assert jm.active_refs(jid) == 0


def test_t5_fix1_background_worker_start_base_exception_releases_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A BaseException when spawning background worker thread MUST fail operation & release patch slot."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "c1b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    fake_apk = jdir / "base.apk"
    fake_apk.write_bytes(b"PK\x03\x04")
    jm.create_state(jid, status="analyzed")

    endpoint = _find_route_endpoint(app, "/api/patch-sign", "POST")
    monkeypatch.setattr(server_mod, "_resolve_source_apk", lambda _d: fake_apk)

    orig_thread = threading.Thread

    class _SimulatedBaseError(BaseException):
        pass

    class _ExplodingPatchThread(orig_thread):
        def start(self) -> None:
            if self.name.startswith("patch-"):
                raise _SimulatedBaseError("simulated BaseException during thread start")
            super().start()

    monkeypatch.setattr(server_mod.threading, "Thread", _ExplodingPatchThread)

    async def _exercise() -> None:
        with pytest.raises(_SimulatedBaseError):
            await endpoint(
                jobId=jid,
                targetSdk=28,
                mode="patch_and_sign",
                resign=False,
                background=True,
                patchTargetSdk=True,
                addLegacyStorage=False,
                enableCleartext=False,
                addNotchSupport=False,
                forceExtractNativeLibs=False,
                allowDowngrade=False,
            )

    asyncio.run(_exercise())
    assert jm.active_patch_count == 0
    assert jm.active_refs(jid) == 0
    state = jm.get_job_state(jid)
    assert state is not None and state["status"] == "error"


def test_t5_fix1_sync_api_patch_sign_queued_executor_cancel_releases_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_D: Cancelling sync api_patch_sign while queued on a 1-worker ThreadPoolExecutor MUST NOT leak slot/429."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "a2b2c3d4e5f6"
    other_jid = "a3b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    fake_apk = jdir / "base.apk"
    fake_apk.write_bytes(b"PK\x03\x04")
    jm.create_state(jid, status="analyzed")
    (cfg.WORK_DIR / other_jid).mkdir(parents=True, exist_ok=True)
    jm.create_state(other_jid, status="analyzed")

    endpoint = _find_route_endpoint(app, "/api/patch-sign", "POST")
    monkeypatch.setattr(server_mod, "_resolve_source_apk", lambda _d: fake_apk)

    runner_called = {"v": False}

    def _forbid_pipeline(**_kw: Any) -> dict[str, Any]:
        runner_called["v"] = True
        return {"verified": True}

    monkeypatch.setattr(server_mod, "patch_and_sign_pipeline", _forbid_pipeline)

    blocker_entered = threading.Event()
    release_blocker = threading.Event()
    orig_start_op = jm.start_operation

    async def _exercise() -> None:
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            loop.set_default_executor(pool)

            def _hold_pool() -> None:
                blocker_entered.set()
                release_blocker.wait(timeout=5.0)

            def _start_op_and_saturate(*args: Any, **kwargs: Any) -> dict[str, Any]:
                res = orig_start_op(*args, **kwargs)
                pool.submit(_hold_pool)
                return res

            monkeypatch.setattr(jm, "start_operation", _start_op_and_saturate)

            task = asyncio.create_task(
                endpoint(
                    jobId=jid,
                    targetSdk=28,
                    mode="patch_and_sign",
                    resign=False,
                    background=False,
                    patchTargetSdk=True,
                    addLegacyStorage=False,
                    enableCleartext=False,
                    addNotchSupport=False,
                    forceExtractNativeLibs=False,
                    allowDowngrade=False,
                )
            )
            while not blocker_entered.is_set():
                await asyncio.sleep(0.01)
            # Allow coroutine to progress past _start_op and queue _run_sync_op behind _hold_pool
            await asyncio.sleep(0.05)
            assert jm.active_patch_count == 1

            task.cancel()
            await asyncio.sleep(0.02)
            release_blocker.set()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(_exercise())
    assert runner_called["v"] is False
    assert jm.active_patch_count == 0
    assert jm.active_refs(jid) == 0
    state = jm.get_job_state(jid)
    assert state is not None and state["status"] != "running"
    # Verify no permanent server-wide 429 DoS: another job can immediately reserve the patch slot
    jm.reserve_patch_slot(other_jid)
    jm.release_patch_slot(other_jid)
    assert jm.active_patch_count == 0


def test_t5_fix1_sync_api_full_xapk_queued_executor_cancel_releases_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_D2: Cancelling sync api_full_xapk while queued on a 1-worker ThreadPoolExecutor MUST NOT leak slot."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "b2b2c3d4e5f6"
    other_jid = "b3b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    (jdir / "extra_obb").mkdir(parents=True, exist_ok=True)
    (jdir / "extra_obb" / "main.1.com.test.obb").write_bytes(b"OBB" * 64)
    jm.create_state(jid, status="done", result={"verified": True, "fileName": "signed.apk"})
    (cfg.WORK_DIR / other_jid).mkdir(parents=True, exist_ok=True)
    jm.create_state(other_jid, status="analyzed")

    endpoint = _find_route_endpoint(app, "/api/full-xapk/{job_id}", "POST")
    builder_called = {"v": False}

    def _forbid_build(**_kw: Any) -> dict[str, Any]:
        builder_called["v"] = True
        return {"fileName": "full.xapk"}

    monkeypatch.setattr(server_mod, "build_full_xapk", _forbid_build)

    blocker_entered = threading.Event()
    release_blocker = threading.Event()
    orig_start_op = jm.start_operation

    async def _exercise() -> None:
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            loop.set_default_executor(pool)

            def _hold_pool() -> None:
                blocker_entered.set()
                release_blocker.wait(timeout=5.0)

            def _start_op_and_saturate(*args: Any, **kwargs: Any) -> dict[str, Any]:
                res = orig_start_op(*args, **kwargs)
                pool.submit(_hold_pool)
                return res

            monkeypatch.setattr(jm, "start_operation", _start_op_and_saturate)

            task = asyncio.create_task(endpoint(job_id=jid, background=False))
            while not blocker_entered.is_set():
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            assert jm.active_patch_count == 1

            task.cancel()
            await asyncio.sleep(0.02)
            release_blocker.set()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(_exercise())
    assert builder_called["v"] is False
    assert jm.active_patch_count == 0
    assert jm.active_refs(jid) == 0
    state = jm.get_job_state(jid)
    assert state is not None
    full = state.get("fullXapk")
    assert isinstance(full, dict) and full.get("status") != "running"
    jm.reserve_patch_slot(other_jid)
    jm.release_patch_slot(other_jid)


def test_t5_fix1_start_operation_cancel_marks_failed_and_releases_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_E: Cancelling during start_operation on patch-sign & full-xapk MUST NOT leave status='running'."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager

    # Case 1: api_patch_sign cancelled while start_operation is in flight (after writing status='running')
    patch_jid = "c2b2c3d4e5f6"
    pdir = cfg.WORK_DIR / patch_jid
    pdir.mkdir(parents=True, exist_ok=True)
    fake_apk = pdir / "base.apk"
    fake_apk.write_bytes(b"PK\x03\x04")
    jm.create_state(patch_jid, status="analyzed")
    monkeypatch.setattr(server_mod, "_resolve_source_apk", lambda _d: fake_apk)

    # Case 2: api_full_xapk cancelled while start_operation is in flight
    xapk_jid = "c3b2c3d4e5f6"
    xdir = cfg.WORK_DIR / xapk_jid
    (xdir / "extra_obb").mkdir(parents=True, exist_ok=True)
    (xdir / "extra_obb" / "main.1.com.test.obb").write_bytes(b"OBB" * 32)
    jm.create_state(xapk_jid, status="done", result={"verified": True, "fileName": "signed.apk"})

    patch_ep = _find_route_endpoint(app, "/api/patch-sign", "POST")
    xapk_ep = _find_route_endpoint(app, "/api/full-xapk/{job_id}", "POST")
    orig_start_op = jm.start_operation

    async def _run_cancel_case(coro: Any, entered: threading.Event, release: threading.Event) -> None:
        task = asyncio.create_task(coro)
        while not entered.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Release AFTER await task to also prove zero deadlock
        release.set()

    for kind in ("patch", "fullXapk"):
        entered = threading.Event()
        release = threading.Event()

        def _slow_start_op(
            job_id: str,
            section: str = "patch",
            stage: str = "",
            _entered: threading.Event = entered,
            _release: threading.Event = release,
        ) -> dict[str, Any]:
            res = orig_start_op(job_id, section, stage)
            _entered.set()
            _release.wait(timeout=5.0)
            return res

        monkeypatch.setattr(jm, "start_operation", _slow_start_op)
        if kind == "patch":
            coro = patch_ep(
                jobId=patch_jid,
                targetSdk=28,
                mode="patch_and_sign",
                resign=False,
                background=False,
                patchTargetSdk=True,
                addLegacyStorage=False,
                enableCleartext=False,
                addNotchSupport=False,
                forceExtractNativeLibs=False,
                allowDowngrade=False,
            )
        else:
            coro = xapk_ep(job_id=xapk_jid, background=False)
        asyncio.run(_run_cancel_case(coro, entered, release))

    assert jm.active_patch_count == 0
    assert jm.active_refs(patch_jid) == 0
    assert jm.active_refs(xapk_jid) == 0
    pstate = jm.get_job_state(patch_jid)
    xstate = jm.get_job_state(xapk_jid)
    assert pstate is not None and pstate["status"] != "running"
    assert xstate is not None and isinstance(xstate.get("fullXapk"), dict)
    assert xstate["fullXapk"]["status"] != "running"


# ===========================================================================
# Fix #2: M2 ASGI Cancellation Note 2 / H1 — _hold_active_async & _ManagedFileResponse
# ===========================================================================


def test_t5_fix2_hold_active_async_level_triggered_anyio_cancel_scope_no_leak(tmp_path: Path) -> None:
    """Level-triggered anyio.CancelScope cancellation inside _hold_active_async MUST release active_refs."""
    cfg = _make_settings(tmp_path)
    jm = JobManager(settings_getter=lambda: cfg)
    jid = "d1b2c3d4e5f6"
    (cfg.WORK_DIR / jid).mkdir(parents=True, exist_ok=True)

    async def _exercise() -> None:
        with anyio.CancelScope() as scope:
            async with server_mod._hold_active_async(jm, jid):
                assert jm.active_refs(jid) == 1
                scope.cancel()
                await anyio.sleep(10)

    anyio.run(_exercise)
    assert jm.active_refs(jid) == 0


def test_t5_fix2_hold_active_async_sync_fallback_no_double_decrement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If asyncio.to_thread fails during _hold_active_async release, sync fallback decrements EXACTLY once."""
    cfg = _make_settings(tmp_path)
    jm = JobManager(settings_getter=lambda: cfg)
    jid = "e1b2c3d4e5f6"
    (cfg.WORK_DIR / jid).mkdir(parents=True, exist_ok=True)
    # Pre-hold one concurrent active reference so refcount starts at 1 -> 2 -> must end at 1 (not 0!)
    jm.acquire_active(jid)

    orig_to_thread = asyncio.to_thread
    calls = {"count": 0}

    async def _flaky_to_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 2:
            raise asyncio.CancelledError("forced cancel during release")
        return await orig_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", _flaky_to_thread)

    async def _exercise() -> None:
        with pytest.raises(asyncio.CancelledError):
            async with server_mod._hold_active_async(jm, jid):
                assert jm.active_refs(jid) == 2

    asyncio.run(_exercise())
    assert jm.active_refs(jid) == 1
    jm.release_active(jid)
    assert jm.active_refs(jid) == 0


def test_t5_fix2_managed_file_response_anyio_cancel_scope_cleans_temp_obb_and_active_ref(
    tmp_path: Path,
) -> None:
    """Cancelling an enclosing anyio.CancelScope mid-stream MUST delete temp OBB & release active_refs."""
    cfg = _make_settings(tmp_path)
    jm = JobManager(settings_getter=lambda: cfg)
    jid = "f1b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    obb_dir = jdir / "_extracted_obb"
    obb_dir.mkdir(parents=True, exist_ok=True)
    temp_obb = obb_dir / "temp_cancel_test.obb"
    temp_obb.write_bytes(b"Z" * (256 * 1024))
    jm.acquire_active(jid)

    resp = server_mod._ManagedFileResponse(
        path=temp_obb,
        filename="main.1.pkg.obb",
        media_type="application/octet-stream",
        cleanup_fn=lambda: server_mod._cleanup_temp_obb_and_release(temp_obb, jm, jid),
    )

    async def _exercise() -> None:
        with anyio.CancelScope() as scope:
            async def _receive() -> dict[str, Any]:
                await anyio.Event().wait()
                return {"type": "http.disconnect"}

            async def _send(message: dict[str, Any]) -> None:
                if message.get("type") == "http.response.body":
                    scope.cancel()
                    await anyio.lowlevel.checkpoint()

            scope_dict = {
                "type": "http",
                "method": "GET",
                "path": f"/api/download-obb/{jid}/0",
                "headers": [],
            }
            await resp(scope_dict, _receive, _send)

    anyio.run(_exercise)
    assert not temp_obb.exists(), "Temp OBB leaked after level-triggered CancelScope cancellation!"
    assert jm.active_refs(jid) == 0


def test_t5_fix2_managed_file_response_sync_fallback_when_to_thread_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If asyncio.to_thread fails inside _ManagedFileResponse finally, sync fallback still cleans up once."""
    cfg = _make_settings(tmp_path)
    jm = JobManager(settings_getter=lambda: cfg)
    jid = "01b2c3d4e5f6"
    (cfg.WORK_DIR / jid).mkdir(parents=True, exist_ok=True)
    temp_obb = cfg.WORK_DIR / jid / "temp_sync_fallback.obb"
    temp_obb.write_bytes(b"DATA" * 1024)
    jm.acquire_active(jid)
    cleanup_calls = {"n": 0}

    def _cleanup() -> None:
        cleanup_calls["n"] += 1
        server_mod._cleanup_temp_obb_and_release(temp_obb, jm, jid)

    resp = server_mod._ManagedFileResponse(
        path=temp_obb,
        filename="main.1.pkg.obb",
        media_type="application/octet-stream",
        cleanup_fn=_cleanup,
    )

    async def _boom_to_thread(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("threadpool shutdown during cleanup")

    monkeypatch.setattr(asyncio, "to_thread", _boom_to_thread)

    async def _exercise() -> None:
        async def _receive() -> dict[str, Any]:
            await asyncio.Event().wait()
            return {"type": "http.disconnect"}

        async def _send(_message: dict[str, Any]) -> None:
            return None

        scope_dict = {"type": "http", "method": "GET", "path": "/", "headers": []}
        with pytest.raises(RuntimeError, match="threadpool shutdown"):
            await resp(scope_dict, _receive, _send)

    asyncio.run(_exercise())
    assert cleanup_calls["n"] == 1
    assert not temp_obb.exists()
    assert jm.active_refs(jid) == 0


def test_t5_fix2_download_obb_cancel_during_extract_cleans_ref_and_temp_obb(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_B: Cancelling api_download_obb during OBB extraction MUST clean _extracted_obb/ and unlock DELETE."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "11b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    archive_path = jdir / "game.xapk"
    zip_entry = "Android/obb/com.test.app/main.1.com.test.app.obb"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(zip_entry, b"OBB_PAYLOAD" * 8192)
    (jdir / "container_meta.json").write_text(
        json.dumps(
            {
                "archive": str(archive_path),
                "obbFiles": [{"name": "main.1.com.test.app.obb", "zipEntry": zip_entry}],
            }
        ),
        encoding="utf-8",
    )
    jm.create_state(jid, status="analyzed")

    endpoint = _find_route_endpoint(app, "/api/download-obb/{job_id}/{obb_index}", "GET")
    orig_extract = server_mod._extract_unique_container_obb
    entered = threading.Event()
    release = threading.Event()
    created_paths: list[Path] = []

    def _slow_extract(*args: Any, **kwargs: Any) -> tuple[Path, str]:
        unique_path, safe_name = orig_extract(*args, **kwargs)
        created_paths.append(unique_path)
        entered.set()
        release.wait(timeout=5.0)
        return unique_path, safe_name

    monkeypatch.setattr(server_mod, "_extract_unique_container_obb", _slow_extract)

    async def _exercise() -> int:
        task = asyncio.create_task(endpoint(job_id=jid, obb_index=0))
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert jm.active_refs(jid) == 1
        assert len(created_paths) == 1 and created_paths[0].is_file()

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        # Wait for worker thread cleanup to complete before issuing DELETE
        deadline = time.monotonic() + 5.0
        while jm.active_refs(jid) != 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            del_resp = await client.delete(f"/api/jobs/{jid}")
            return del_resp.status_code

    delete_status = asyncio.run(_exercise())
    assert jm.active_refs(jid) == 0
    extracted_dir = jdir / "_extracted_obb"
    assert not extracted_dir.exists() or list(extracted_dir.iterdir()) == []
    assert delete_status == 200


def test_t5_fix2_hold_active_async_cancel_during_acquire_no_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_C: Cancelling _hold_active_async during acquire_active MUST release active_refs without deadlocking."""
    cfg = _make_settings(tmp_path)
    jm = JobManager(settings_getter=lambda: cfg)
    jid = "21b2c3d4e5f6"
    (cfg.WORK_DIR / jid).mkdir(parents=True, exist_ok=True)

    orig_acquire = jm.acquire_active
    entered = threading.Event()
    release = threading.Event()

    def _slow_acquire(job_id: str) -> None:
        orig_acquire(job_id)
        entered.set()
        release.wait(timeout=5.0)

    monkeypatch.setattr(jm, "acquire_active", _slow_acquire)

    async def _exercise() -> None:
        async def _holder() -> None:
            async with server_mod._hold_active_async(jm, jid):
                await asyncio.sleep(10)

        task = asyncio.create_task(_holder())
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert jm.active_refs(jid) == 1

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()

    asyncio.run(_exercise())
    assert jm.active_refs(jid) == 0


def test_t5_fix2_api_download_cancel_during_resolve_no_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_G: Cancelling api_download during _resolve/acquire_active MUST NOT leak active_refs."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "31b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    signed_name = "game_patched_signed.apk"
    (jdir / signed_name).write_bytes(b"PK\x03\x04SIGNED_APK")
    (jdir / "patch_result.json").write_text(json.dumps({"fileName": signed_name, "verified": True}), encoding="utf-8")
    jm.create_state(jid, status="done", result={"fileName": signed_name, "verified": True})

    endpoint = _find_route_endpoint(app, "/api/download/{job_id}/{filename}", "GET")
    orig_acquire = jm.acquire_active
    entered = threading.Event()
    release = threading.Event()

    def _slow_acquire(job_id: str) -> None:
        orig_acquire(job_id)
        entered.set()
        release.wait(timeout=5.0)

    monkeypatch.setattr(jm, "acquire_active", _slow_acquire)

    async def _exercise() -> None:
        task = asyncio.create_task(endpoint(job_id=jid, filename=signed_name))
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert jm.active_refs(jid) == 1

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()

    asyncio.run(_exercise())
    assert jm.active_refs(jid) == 0


def test_t5_fix2_api_download_full_xapk_cancel_during_resolve_no_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ATTACK_G2: Cancelling api_download_full_xapk during _resolve/acquire_active MUST NOT leak active_refs."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "41b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    xapk_name = "game_full.xapk"
    (jdir / xapk_name).write_bytes(b"PK\x03\x04FULL_XAPK")
    jm.create_state(jid, status="done", fullXapk={"status": "done", "result": {"fileName": xapk_name}})

    endpoint = _find_route_endpoint(app, "/api/download-full-xapk/{job_id}", "GET")
    orig_acquire = jm.acquire_active
    entered = threading.Event()
    release = threading.Event()

    def _slow_acquire(job_id: str) -> None:
        orig_acquire(job_id)
        entered.set()
        release.wait(timeout=5.0)

    monkeypatch.setattr(jm, "acquire_active", _slow_acquire)

    async def _exercise() -> None:
        task = asyncio.create_task(endpoint(job_id=jid))
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert jm.active_refs(jid) == 1

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()

    asyncio.run(_exercise())
    assert jm.active_refs(jid) == 0


def test_t5_fix2_download_constructor_dual_fault_single_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dual fault (_ManagedFileResponse.__init__ raising + cancel after cleanup) MUST decrement active_refs ONCE."""
    cfg = _make_settings(tmp_path)
    app = server_mod.create_app(settings=cfg)
    jm: JobManager = app.state.job_manager
    jid = "51b2c3d4e5f6"
    jdir = cfg.WORK_DIR / jid
    jdir.mkdir(parents=True, exist_ok=True)
    archive_path = jdir / "game.xapk"
    zip_entry = "Android/obb/com.test.dual/main.1.com.test.dual.obb"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(zip_entry, b"DUAL_FAULT_OBB" * 2048)
    (jdir / "container_meta.json").write_text(
        json.dumps(
            {
                "archive": str(archive_path),
                "obbFiles": [{"name": "main.1.com.test.dual.obb", "zipEntry": zip_entry}],
            }
        ),
        encoding="utf-8",
    )
    jm.create_state(jid, status="analyzed")
    # Pre-hold 1 concurrent download active_ref so refcount starts at 1 -> 2 -> must end at 1 (never 0!)
    jm.acquire_active(jid)

    endpoint = _find_route_endpoint(app, "/api/download-obb/{job_id}/{obb_index}", "GET")

    def _boom_init(self: Any, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("simulated _ManagedFileResponse.__init__ failure")

    monkeypatch.setattr(server_mod._ManagedFileResponse, "__init__", _boom_init)

    orig_to_thread = asyncio.to_thread
    calls = {"n": 0}

    async def _dual_fault_to_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        res = await orig_to_thread(func, *args, **kwargs)
        if calls["n"] == 2:
            # Cleanup ran inside threadpool; now raise CancelledError BEFORE _run_cleanup_shielded sets done=True
            # so its finally block ALSO calls func() synchronously!
            raise asyncio.CancelledError("simulated dual-fault task cancel after threadpool cleanup")
        return res

    monkeypatch.setattr(asyncio, "to_thread", _dual_fault_to_thread)

    async def _exercise() -> None:
        with pytest.raises(asyncio.CancelledError):
            await endpoint(job_id=jid, obb_index=0)

    asyncio.run(_exercise())
    assert calls["n"] == 2
    assert jm.active_refs(jid) == 1, "Dual fault double-decremented a concurrent download's active_refs!"
    extracted_dir = jdir / "_extracted_obb"
    assert not extracted_dir.exists() or list(extracted_dir.iterdir()) == []
    jm.release_active(jid)
    assert jm.active_refs(jid) == 0


# ===========================================================================
# Fix #3: M3 Defensive Coercion — hostile {toString:1, valueOf:1} in Node
# ===========================================================================


def test_t5_fix3_hostile_object_to_primitive_in_sanitize_app_state_via_node() -> None:
    """Direct sanitizeAppState/normalizeGame calls with hostile {toString:1, valueOf:1} MUST never throw."""
    node_script = """
import assert from 'node:assert/strict';
import { sanitizeAppState, normalizeGame, validateRenderApiUrl, escapeHtml } from './static/app.js';

const raw = JSON.parse('{"games":[{"id":{"toString":1,"valueOf":1},"name":{"toString":1},"sizeMB":{"valueOf":1}}],"renderApiUrl":{"toString":1},"cacheMB":{"valueOf":1}}');
const clean = sanitizeAppState(raw);
assert.equal(clean.renderApiUrl, '');
assert.equal(clean.games.length, 1);
assert.equal(clean.games[0].id, 'recovered-0');
assert.equal(clean.games[0].sizeMB, 0);

const np = Object.create(null);
assert.equal(normalizeGame({ id: np, ext: np, packageId: np, legacyApi: np }).id, 'recovered-0');
assert.equal(validateRenderApiUrl(np).valid, false);
assert.equal(escapeHtml({ toString: 1, valueOf: 1 }), '');
console.log('TIER5_NODE_COERCION_OK');
"""
    res = subprocess.run(
        ["node", "--input-type=module", "-e", node_script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert res.returncode == 0, f"stdout={res.stdout}\nstderr={res.stderr}"
    assert "TIER5_NODE_COERCION_OK" in res.stdout


# ===========================================================================
# Fixes #4 & #5: build_release_zip strict archive_prefix, case-insensitive patterns, static symlink
# ===========================================================================


def test_t5_fix4_build_release_zip_rejects_malicious_archive_prefixes_and_cleans_tmp(tmp_path: Path) -> None:
    mod = _load_build_release_zip_module()
    out_zip = tmp_path / "blocked.zip"
    for bad in ("..\x00safe", "/abs", "evil\nbar", "C:evil", ".", "..", " leading", "trailing "):
        with pytest.raises(ValueError, match="Invalid archive_prefix"):
            mod.build_release_zip(REPO_ROOT, out_zip, archive_prefix=bad)
        assert not out_zip.exists()
        assert list(tmp_path.glob("*.tmp")) == []

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for cli_bad in ("/abs", "C:evil", "evil\nbar"):
        proc = subprocess.run(
            [
                sys.executable,
                "-B",
                str(REPO_ROOT / "scripts" / "build_release_zip.py"),
                "--root",
                str(REPO_ROOT),
                "--output",
                str(out_zip),
                "--prefix",
                cli_bad,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert proc.returncode != 0
        assert not out_zip.exists()
        assert list(tmp_path.glob("*.tmp")) == []


def test_t5_fix5_build_release_zip_case_insensitive_exclusions_bak_jks_pass(tmp_path: Path) -> None:
    mod = _load_build_release_zip_module()
    repo = tmp_path / "case_excl_repo"
    repo.mkdir()
    for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt", "server.py"):
        shutil.copy2(REPO_ROOT / rel, repo / rel)
    shutil.copytree(REPO_ROOT / "retrodroid", repo / "retrodroid")
    shutil.copytree(REPO_ROOT / "static", repo / "static")

    decoys = (
        "static/vendor/x.BAK.js",
        "static/vendor/y.JKS.txt",
        "static/vendor/z.PASS.txt",
        "retrodroid/old.BAK.py",
    )
    for d in decoys:
        (repo / d).write_text("SHOULD_NOT_BE_PACKAGED\n", encoding="utf-8")

    out = tmp_path / "clean.zip"
    mod.build_release_zip(repo, out)
    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
        for d in decoys:
            assert f"RetroDroid_Compat_v5.4.0/{d}" not in names


def test_t5_fix5_build_release_zip_rejects_static_retrodroid_and_vendor_symlinks(tmp_path: Path) -> None:
    mod = _load_build_release_zip_module()

    for sym_target_rel in ("static", "retrodroid", "static/vendor"):
        repo = tmp_path / f"sym_{sym_target_rel.replace('/', '_')}"
        repo.mkdir()
        for rel in (".dockerignore", "Dockerfile", "README.txt", "index.html", "requirements.txt", "server.py"):
            shutil.copy2(REPO_ROOT / rel, repo / rel)
        shutil.copytree(REPO_ROOT / "retrodroid", repo / "retrodroid")
        shutil.copytree(REPO_ROOT / "static", repo / "static")

        victim = repo / sym_target_rel
        backup_real = repo / f"_moved_{sym_target_rel.replace('/', '_')}"
        victim.rename(backup_real)
        victim.symlink_to(backup_real)

        out = tmp_path / f"out_{sym_target_rel.replace('/', '_')}.zip"
        with pytest.raises(ValueError, match="symlink"):
            mod.build_release_zip(repo, out)
        assert not out.exists()


# ===========================================================================
# Fixes #6, #7, #8: Dockerfile HEALTHCHECK, README.txt, .dockerignore
# ===========================================================================


def test_t5_fix6_dockerfile_healthcheck_empty_port_and_http_proxy_immunity() -> None:
    df_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    hc_line = next(line for line in df_text.splitlines() if "urllib.request" in line)
    cmd_json = hc_line[hc_line.index("[") :].strip()
    snippet = json.loads(cmd_json)[2]
    assert "ProxyHandler({})" in snippet
    assert "os.environ.get('PORT') or '10000'" in snippet

    class _OkHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, format: str, *args: Any) -> None:
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # Must bypass hostile HTTP_PROXY / http_proxy completely
        env_proxy = os.environ.copy()
        env_proxy["PORT"] = str(port)
        env_proxy["HTTP_PROXY"] = "http://127.0.0.1:1"
        env_proxy["http_proxy"] = "http://dead-proxy.invalid:9999"
        env_proxy["PYTHONDONTWRITEBYTECODE"] = "1"
        res = subprocess.run(
            [sys.executable, "-c", snippet],
            env=env_proxy,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert res.returncode == 0, res.stderr

        # Empty PORT="" must NOT fail with invalid port URL syntax (resolves to 10000)
        env_empty = env_proxy.copy()
        env_empty["PORT"] = ""
        probe = subprocess.run(
            [sys.executable, "-c", "import os; print(f\"http://127.0.0.1:{os.environ.get('PORT') or '10000'}/health\")"],
            env=env_empty,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        assert probe.stdout.strip() == "http://127.0.0.1:10000/health"
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=3)


def test_t5_fix7_readme_accurate_keystore_info_and_strict_health_docs() -> None:
    text = (REPO_ROOT / "README.txt").read_text(encoding="utf-8")
    assert "`/health` ve `/api/keystore-info`" not in text
    assert "`/api/keystore-info`" in text
    assert "`persistent: false`" in text
    assert "GET /health" in text
    assert "GET /health?strict=true" in text
    assert "HTTP 503" in text


def test_t5_fix8_dockerignore_excludes_tmp_patterns_parity() -> None:
    lines = {line.strip() for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()}
    assert "*.tmp" in lines
    assert "**/*.tmp" in lines


# ===========================================================================
# Additional Tier 5 Adversarial Probing: TCP RST, Symlinks, Secrets, Immutability
# ===========================================================================


def test_t5_live_tcp_rst_mid_download_cleans_up_active_ref_and_temp_obb(
    live_server: LiveServer,
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    """Abrupt TCP RST mid-stream on /api/download-obb MUST clean _extracted_obb/ and unlock DELETE."""
    an = upload_via_analyze(http_client, apk_corpus.xapk_v2)
    jid = an["jobId"]

    sock = socket.create_connection(("127.0.0.1", live_server.port), timeout=10)
    try:
        # Configure SO_LINGER(1, 0) so close() sends an immediate TCP RST packet
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        req = f"GET /api/download-obb/{jid}/0 HTTP/1.1\r\nHost: 127.0.0.1:{live_server.port}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        first_chunk = sock.recv(128)
        assert b"200 OK" in first_chunk
    finally:
        sock.close()

    # Wait briefly for server ASGI disconnect handler + shielded finally cleanup to finish
    extracted_dir = live_server.work_dir / jid / "_extracted_obb"
    deadline = time.monotonic() + 10.0
    deleted = False
    while time.monotonic() < deadline:
        leftover = list(extracted_dir.iterdir()) if extracted_dir.exists() else []
        if not leftover:
            rd = http_client.delete(f"/api/jobs/{jid}")
            if rd.status_code == 200:
                deleted = True
                break
        time.sleep(0.1)
    assert deleted, "Server leaked active_ref or _extracted_obb temp file after client TCP RST!"


def test_t5_symlink_planted_inside_job_dir_and_extra_obb_blocked_with_403(
    live_server: LiveServer,
    http_client: httpx.Client,
    apk_corpus: E2ECorpus,
) -> None:
    """Symlinks planted in job dir or extra_obb/ MUST be blocked with 403 and never disclose target."""
    an = upload_via_analyze(http_client, apk_corpus.legacy_apk)
    jid = an["jobId"]
    rp = http_client.post("/api/patch-sign", data={"jobId": jid, "targetSdk": "28"})
    assert rp.status_code == 200
    signed_name = rp.json()["fileName"]

    # Replace allowlisted signed APK with a symlink to /etc/hostname
    signed_path = live_server.work_dir / jid / signed_name
    signed_path.unlink()
    signed_path.symlink_to("/etc/hostname")
    r_dl = http_client.get(rp.json()["downloadUrl"])
    assert r_dl.status_code == 403

    # Also attach an OBB, then replace the stored OBB with a symlink to /etc/hostname
    assert (
        http_client.post(
            f"/api/attach-obb/{jid}",
            files=[("files", (apk_corpus.obb_main.name, apk_corpus.obb_main.read_bytes(), "application/octet-stream"))],
        ).status_code
        == 200
    )
    stored_obb = live_server.work_dir / jid / "extra_obb" / apk_corpus.obb_main.name
    stored_obb.unlink()
    stored_obb.symlink_to("/etc/hostname")
    r_obb = http_client.get(f"/api/download-obb/{jid}/0")
    assert r_obb.status_code == 403


def test_t5_keystore_password_never_in_argv_or_http_responses(
    live_server: LiveServer,
    http_client: httpx.Client,
) -> None:
    """Keystore secret must use env passing in source code and NEVER leak in HTTP responses or job JSON."""
    ks_src = (REPO_ROOT / "retrodroid" / "keystore.py").read_text(encoding="utf-8")
    patcher_src = (REPO_ROOT / "retrodroid" / "patcher.py").read_text(encoding="utf-8")
    assert "-storepass:env" in ks_src
    assert "env:RD_KS_PASS" in patcher_src

    secret = Path(f"{live_server.keystore_path}.pass").read_text(encoding="utf-8").strip()
    assert len(secret) >= 6
    for path in ("/health", "/api/keystore-info", "/api/jobs"):
        body = http_client.get(path).text
        assert secret not in body, f"Keystore secret leaked in {path}!"


def test_t5_source_v531_zip_immutability_and_v540_release_hygiene() -> None:
    """Original v5.3.1 zip must remain byte-for-byte untouched and v5.4.0 zip must exclude tests/e2e/."""
    v531 = REPO_ROOT.parent / "RetroDroid_Compat_v5.3.1_temiz.zip"
    assert v531.is_file()
    assert hashlib.sha256(v531.read_bytes()).hexdigest() == EXPECTED_V531_SHA256

    v540 = REPO_ROOT.parent / "RetroDroid_Compat_v5.4.0.zip"
    assert v540.is_file()
    with zipfile.ZipFile(v540, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        assert not any("/tests/" in n or "/scripts/" in n for n in names)
        server_txt = zf.read("RetroDroid_Compat_v5.4.0/server.py").decode("utf-8")
        assert "_run_cleanup_shielded" in server_txt
        app_js = zf.read("RetroDroid_Compat_v5.4.0/static/app.js").decode("utf-8")
        assert "export function asSafeString(" in app_js
        df_txt = zf.read("RetroDroid_Compat_v5.4.0/Dockerfile").decode("utf-8")
        assert "ProxyHandler({})" in df_txt
        di_txt = zf.read("RetroDroid_Compat_v5.4.0/.dockerignore").decode("utf-8")
        assert "*.tmp" in di_txt
        rm_txt = zf.read("RetroDroid_Compat_v5.4.0/README.txt").decode("utf-8")
        assert "GET /health?strict=true" in rm_txt
