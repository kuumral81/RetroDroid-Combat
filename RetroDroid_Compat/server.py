"""RetroDroid Compat v5.4.0 — Thin, non-blocking async FastAPI composition root.

Entrypoint preserved for deployment & tooling: ``uvicorn server:app``.
All heavy Android toolchain, archive, keystore, and job-state operations live in
``retrodroid.*`` and are offloaded off the asyncio event loop via ``asyncio.to_thread``
or dedicated background worker threads.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import math
import os
import shutil
import threading
import time
import urllib.parse
import uuid
import zipfile
from collections import deque
from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, TypeVar

import anyio
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from retrodroid.axml import patch_binary_axml_target_sdk
from retrodroid.config import (
    APP_VERSION,
    DEFAULT_ALLOWED_ORIGINS,
    SUPPORTED_EXTS,
    ApkInspectionError,
    CommandCanceledError,
    CommandTimeoutError,
    InvalidArchiveError,
    PayloadTooLargeError,
    RetroDroidError,
    Settings,
    ToolNotFoundError,
    configure_logging,
    copy_stream_limited,
    ensure_work_dir,
    get_logger,
    get_settings,
    is_valid_job_id,
    log_job_context,
    probe_android_tools,
    safe_url_download,
    sanitize_filename,
    write_json_atomic,
)
from retrodroid.containers import (
    build_full_xapk,
    extract_container_obb_atomic,
    normalize_obb_relpath,
    unpack_container_if_needed,
    validate_obb_filename,
)
from retrodroid.inspector import inspect_apk, inspect_elf_16k_alignment
from retrodroid.jobs import (
    ConcurrencyLimitError,
    InvalidJobIdError,
    JobConflictError,
    JobManager,
    JobNotFoundError,
)
from retrodroid.keystore import (
    KeystoreError,
    KeystoreState,
    ensure_signing_keystore,
    get_keystore_info,
    get_keystore_state,
)
from retrodroid.patcher import (
    ManifestPatchOptions,
    PatchError,
    align_and_sign_apk,
    build_slim_manifest_apk,
    detect_zipalign_16k,
    patch_and_sign_pipeline,
    patch_manifest_xml_apktool,
    stream_rewrite_apk,
)

__all__ = [
    "APP_VERSION",
    "BASE_DIR",
    "DEFAULT_ALLOWED_ORIGINS",
    "SUPPORTED_EXTS",
    "ApkInspectionError",
    "CommandCanceledError",
    "CommandTimeoutError",
    "ConcurrencyLimitError",
    "InvalidArchiveError",
    "InvalidJobIdError",
    "JobConflictError",
    "JobManager",
    "JobNotFoundError",
    "KeystoreError",
    "KeystoreState",
    "ManifestPatchOptions",
    "PatchError",
    "PayloadTooLargeError",
    "RetroDroidError",
    "Settings",
    "ToolNotFoundError",
    "align_and_sign_apk",
    "app",
    "build_full_xapk",
    "build_slim_manifest_apk",
    "copy_stream_limited",
    "create_app",
    "detect_zipalign_16k",
    "ensure_signing_keystore",
    "extract_container_obb_atomic",
    "get_keystore_info",
    "get_keystore_state",
    "get_settings",
    "inspect_apk",
    "inspect_elf_16k_alignment",
    "is_valid_job_id",
    "normalize_obb_relpath",
    "patch_and_sign_pipeline",
    "patch_binary_axml_target_sdk",
    "patch_manifest_xml_apktool",
    "probe_android_tools",
    "safe_url_download",
    "sanitize_filename",
    "stream_rewrite_apk",
    "unpack_container_if_needed",
    "validate_obb_filename",
    "write_json_atomic",
]

BASE_DIR = Path(__file__).resolve().parent
_LOG = get_logger("retrodroid.server")

_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Permissions-Policy",
        (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        ),
    ),
)

_TOOL_NAMES: tuple[str, ...] = ("aapt", "apktool", "zipalign", "apksigner", "java", "keytool")
_STREAM_BUF_SIZE = 1024 * 1024  # 1 MiB


# ---------------------------------------------------------------------------
# Pure-ASGI Security & Traffic Middlewares
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware:
    """Outermost ASGI middleware attaching hardened security headers to EVERY HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def _send_with_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = MutableHeaders(scope=message)
                for key, value in _SECURITY_HEADERS:
                    headers[key] = value
            await send(message)

        try:
            await self.app(scope, receive, _send_with_headers)
        except Exception:
            _LOG.exception("Unhandled exception escaped application stack")
            if response_started:
                raise
            resp = JSONResponse(
                status_code=500,
                content={"detail": "Sunucu iç hatası."},
                headers=dict(_SECURITY_HEADERS),
            )
            await resp(scope, receive, send)


class DynamicCORSMiddleware:
    """CORS middleware dynamically synchronized with ``Settings.ALLOWED_ORIGINS`` (no wildcard+creds)."""

    def __init__(self, app: ASGIApp, cfg_fn: Callable[[], Settings]) -> None:
        self.app = app
        self._cfg_fn = cfg_fn
        self._lock = threading.Lock()
        self._cached_origins: tuple[str, ...] | None = None
        self._cors_app: CORSMiddleware | None = None

    def _get_cors_app(self) -> CORSMiddleware:
        origins = tuple(self._cfg_fn().ALLOWED_ORIGINS)
        with self._lock:
            if self._cors_app is None or self._cached_origins != origins:
                self._cached_origins = origins
                self._cors_app = CORSMiddleware(
                    self.app,
                    allow_origins=list(origins),
                    allow_credentials=False,
                    allow_methods=["GET", "POST", "DELETE", "OPTIONS", "HEAD"],
                    allow_headers=["Authorization", "X-API-Token", "Content-Type", "Accept", "Origin"],
                    expose_headers=["Content-Disposition"],
                )
            return self._cors_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        await self._get_cors_app()(scope, receive, send)


class RateLimitMiddleware:
    """Per-IP 60-second sliding-window rate limiter controlled by ``RATE_LIMIT_PER_MIN``."""

    def __init__(self, app: ASGIApp, cfg_fn: Callable[[], Settings]) -> None:
        self.app = app
        self._cfg_fn = cfg_fn
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}
        self._last_prune = time.monotonic()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = int(self._cfg_fn().RATE_LIMIT_PER_MIN)
        if limit <= 0:
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "/")
        if method == "OPTIONS" or path == "/" or path.startswith("/static/"):
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        ip = str(client[0]) if client and client[0] else "unknown"
        now = time.monotonic()
        cutoff = now - 60.0
        retry_after: int | None = None

        with self._lock:
            if now - self._last_prune >= 60.0 or len(self._buckets) > 512:
                stale = [k for k, dq in self._buckets.items() if not dq or dq[-1] <= cutoff]
                for k in stale:
                    self._buckets.pop(k, None)
                self._last_prune = now

            bucket = self._buckets.setdefault(ip, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, math.ceil(60.0 - (now - bucket[0])))
            else:
                bucket.append(now)

        if retry_after is not None:
            resp = JSONResponse(
                status_code=429,
                content={"detail": "Çok fazla istek gönderildi. Lütfen kısa bir süre sonra tekrar deneyin."},
                headers={"Retry-After": str(retry_after)},
            )
            await resp(scope, receive, send)
            return

        await self.app(scope, receive, send)


class ApiTokenAuthMiddleware:
    """Optional API token enforcement on ``/api/*`` with constant-time comparison."""

    def __init__(self, app: ASGIApp, cfg_fn: Callable[[], Settings]) -> None:
        self.app = app
        self._cfg_fn = cfg_fn

    @staticmethod
    def _extract_token(scope: Scope, method: str, path: str) -> str:
        bearer_tok = ""
        header_tok = ""
        for raw_k, raw_v in scope.get("headers") or ():
            key = raw_k.decode("latin-1").lower()
            if key == "authorization":
                val = raw_v.decode("latin-1").strip()
                if len(val) >= 7 and val[:7].lower() == "bearer ":
                    bearer_tok = val[7:].strip()
            elif key == "x-api-token":
                header_tok = raw_v.decode("latin-1").strip()

        if bearer_tok:
            return bearer_tok
        if header_tok:
            return header_tok

        # Query ?token= is accepted ONLY for browser GET/HEAD download links under /api/download*
        if method in {"GET", "HEAD"} and path.startswith("/api/download"):
            qs = (scope.get("query_string") or b"").decode("latin-1")
            params = urllib.parse.parse_qs(qs, keep_blank_values=False)
            vals = params.get("token")
            if vals:
                return vals[0].strip()
        return ""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        expected = self._cfg_fn().API_TOKEN
        if not expected:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "/")
        if path != "/api" and not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET").upper()
        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        candidate = self._extract_token(scope, method, path)
        if not candidate or not hmac.compare_digest(
            candidate.encode("utf-8"),
            expected.encode("utf-8"),
        ):
            resp = JSONResponse(
                status_code=401,
                content={"detail": "Yetkisiz erişim. Geçerli bir API anahtarı gereklidir."},
                headers={"WWW-Authenticate": "Bearer"},
            )
            await resp(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Internal Helpers (pure sync I/O helpers intended to run via asyncio.to_thread)
# ---------------------------------------------------------------------------


def _read_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_json_dict(path: Path) -> dict[str, Any] | None:
    data = _read_json_file(path)
    return data if isinstance(data, dict) else None


def _read_json_list(path: Path) -> list[dict[str, Any]] | None:
    data = _read_json_file(path)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return None


async def _run_cleanup_shielded(fn: Callable[[], None]) -> None:
    """Run an idempotent cleanup callback off the event loop, shielded from ASGI cancellation."""
    done = False
    try:
        with anyio.CancelScope(shield=True):
            await asyncio.to_thread(fn)
        done = True
    finally:
        if not done:
            fn()


_T = TypeVar("_T")


@asynccontextmanager
async def _hold_active_async(job_manager: JobManager, job_id: str) -> AsyncIterator[None]:
    state_lock = threading.Lock()
    state = {"aborted": False, "acquired": False, "released": False}

    def _acquire() -> bool:
        with state_lock:
            if state["aborted"]:
                return False
        job_manager.acquire_active(job_id)
        release_now = False
        with state_lock:
            if state["aborted"]:
                state["released"] = True
                release_now = True
            else:
                state["acquired"] = True
        if release_now:
            job_manager.release_active(job_id)
            return False
        return True

    def _release_once() -> None:
        with state_lock:
            if not state["acquired"] or state["released"]:
                return
            state["released"] = True
        job_manager.release_active(job_id)

    try:
        acquired = await asyncio.to_thread(_acquire)
        if not acquired:
            raise asyncio.CancelledError
        yield
    finally:
        should_release = False
        with state_lock:
            state["aborted"] = True
            if state["acquired"] and not state["released"]:
                should_release = True
        if should_release:
            await _run_cleanup_shielded(_release_once)


async def _start_reserved_operation(
    job_manager: JobManager,
    job_id: str,
    section: str,
    stage: str,
    prepare_fn: Callable[[], _T],
) -> _T:
    """Prepare and start a reserved patch/XAPK operation safely under ASGI cancellation."""
    lock = threading.Lock()
    # phase: "pending" -> "starting" -> "started" | "failed"
    state = {"phase": "pending", "aborted": False, "cleaned": False}

    def _start_op() -> bool:
        with lock:
            if state["aborted"]:
                return False
            state["phase"] = "starting"
        succeeded = False
        try:
            job_manager.start_operation(job_id, section, stage)
            succeeded = True
        finally:
            cleanup_now = False
            with lock:
                state["phase"] = "started" if succeeded else "failed"
                if state["aborted"] and not state["cleaned"]:
                    state["cleaned"] = True
                    cleanup_now = True
            if cleanup_now:
                if succeeded:
                    job_manager.fail_operation(job_id, "İşlem başlatılırken iptal edildi.", section)
                job_manager.release_patch_slot(job_id)
        return not cleanup_now

    try:
        prepared = await asyncio.to_thread(prepare_fn)
        started = await asyncio.to_thread(_start_op)
        if not started:
            raise asyncio.CancelledError
        return prepared
    except BaseException:
        cleanup_mode: str | None = None
        with lock:
            state["aborted"] = True
            phase = state["phase"]
            if phase != "starting" and not state["cleaned"]:
                cleanup_mode = "fail_and_release" if phase == "started" else "release_only"

        if cleanup_mode is not None:

            def _cleanup_once() -> None:
                with lock:
                    if state["cleaned"]:
                        return
                    state["cleaned"] = True
                if cleanup_mode == "fail_and_release":
                    job_manager.fail_operation(job_id, "İşlem başlatılırken iptal edildi.", section)
                job_manager.release_patch_slot(job_id)

            await _run_cleanup_shielded(_cleanup_once)
        raise


async def _execute_sync_reserved_operation(
    job_manager: JobManager,
    job_id: str,
    section: str,
    runner: Callable[
        [
            threading.Event,
            Callable[[Any], None],
            Callable[[str], None],
            Callable[[int, str], None],
        ],
        dict[str, Any],
    ],
) -> dict[str, Any]:
    """Run a reserved synchronous operation off-loop, releasing slot & failing if cancelled while queued."""
    lock = threading.Lock()
    state = {"entered": False, "aborted": False, "cleaned": False}

    def _run_sync_op() -> dict[str, Any] | None:
        with lock:
            if state["aborted"]:
                return None
            state["entered"] = True
        return job_manager.execute_operation(
            job_id,
            section,
            runner,
            reraise=True,
        )

    try:
        result = await asyncio.to_thread(_run_sync_op)
    except BaseException:
        should_cleanup = False
        with lock:
            if not state["entered"]:
                state["aborted"] = True
                should_cleanup = not state["cleaned"]
        if should_cleanup:

            def _fail_and_release_once() -> None:
                with lock:
                    if state["cleaned"]:
                        return
                    state["cleaned"] = True
                job_manager.fail_operation(job_id, "İşlem başlatılırken iptal edildi.", section)
                job_manager.release_patch_slot(job_id)

            await _run_cleanup_shielded(_fail_and_release_once)
        raise

    if result is None:
        raise asyncio.CancelledError
    return result


def _resolve_chunk_plan(
    total_size: int,
    requested_chunks: int | None,
    cfg: Settings,
) -> tuple[int, int]:
    """Return ``(total_chunks, chunk_size_bytes)`` validating client chunking parameters."""
    if total_size <= 0:
        raise HTTPException(status_code=400, detail="Dosya boyutu 0 bayt veya negatif olamaz.")
    if total_size > cfg.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Dosya boyutu {cfg.MAX_UPLOAD_MB} MB sınırını aşıyor.",
        )

    default_chunk_bytes = cfg.chunk_size_bytes
    default_chunks = math.ceil(total_size / default_chunk_bytes)

    if requested_chunks is None:
        return default_chunks, default_chunk_bytes

    if requested_chunks <= 0:
        raise HTTPException(status_code=400, detail="Geçersiz parça sayısı (totalChunks).")
    if requested_chunks > cfg.MAX_ARCHIVE_ENTRIES:
        raise HTTPException(status_code=400, detail="Parça sayısı izin verilen sınırı aşıyor.")
    if requested_chunks > total_size:
        raise HTTPException(status_code=400, detail="Parça sayısı dosya bayt boyutundan büyük olamaz.")

    if requested_chunks == default_chunks:
        return default_chunks, default_chunk_bytes

    if requested_chunks < default_chunks:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Parça boyutu sunucu sınırını ({cfg.CHUNK_SIZE_MB} MB) aşıyor; "
                f"en az {default_chunks} parça gereklidir."
            ),
        )

    custom_chunk_bytes = math.ceil(total_size / requested_chunks)
    if custom_chunk_bytes > default_chunk_bytes or (requested_chunks - 1) * custom_chunk_bytes >= total_size:
        raise HTTPException(status_code=400, detail="totalChunks değeri dosya boyutuyla tutarlı değil.")
    return requested_chunks, custom_chunk_bytes


async def _stream_upload_to_file(
    upload: UploadFile,
    dest_path: Path,
    *,
    max_bytes: int,
    exact_expected: int | None = None,
    label: str = "Dosya",
) -> int:
    """Stream an ``UploadFile`` to ``dest_path`` with all disk writes off the event loop."""

    def _open_write() -> Any:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        return dest_path.open("wb")

    fp = await asyncio.to_thread(_open_write)
    written = 0
    try:
        while True:
            part = await upload.read(_STREAM_BUF_SIZE)
            if not part:
                break
            written += len(part)
            if exact_expected is not None and written > exact_expected:
                raise HTTPException(status_code=413, detail=f"{label} beklenen boyutu aşıyor.")
            if written > max_bytes:
                raise HTTPException(status_code=413, detail=f"{label} izin verilen boyut sınırını aşıyor.")
            await asyncio.to_thread(fp.write, part)
        await asyncio.to_thread(fp.flush)
    finally:
        await asyncio.to_thread(fp.close)
    return written


def _extract_apk_info_summary(info: dict[str, Any]) -> dict[str, Any]:
    inspector = info.get("inspector") if isinstance(info.get("inspector"), dict) else {}
    return {
        "packageId": info.get("packageId"),
        "appLabel": info.get("appLabel"),
        "versionName": info.get("versionName"),
        "versionCode": info.get("versionCode"),
        "minSdk": info.get("minSdk"),
        "targetSdk": info.get("targetSdk"),
        "iconPath": info.get("iconPath"),
        "inspector": {
            "permissions": list(inspector.get("permissions") or []),
        },
    }


def _build_analyze_response(
    job_id: str,
    apk_path: Path,
    sanitized_name: str,
    original_name: str,
    container_info: dict[str, Any],
    info: dict[str, Any],
) -> dict[str, Any]:
    apk_size = apk_path.stat().st_size
    obb_files = list(container_info.get("obbFiles") or [])
    split_apks = list(container_info.get("splitApks") or [])
    payload = dict(info)
    payload.update(
        {
            "jobId": job_id,
            "fileName": apk_path.name,
            "originalFileName": original_name,
            "sanitizedFileName": sanitized_name,
            "sizeBytes": apk_size,
            "sizeMB": round(apk_size / (1024 * 1024), 2),
            "containerType": container_info.get("containerType", "APK"),
            "innerApkName": container_info.get("innerApkName"),
            "splitApks": split_apks,
            "obbFiles": obb_files,
            "hasObb": bool(obb_files),
            "serverTime": time.time(),
        }
    )
    return payload


def _resolve_source_apk(job_dir: Path) -> Path:
    """Locate the base APK for ``job_dir``, handling both plain APKs and ``_extracted/`` containers."""
    jdir_resolved = job_dir.resolve()
    upload_meta = _read_json_dict(job_dir / "upload_meta.json") or {}
    if upload_meta and upload_meta.get("complete") is False:
        raise HTTPException(
            status_code=409,
            detail="Yükleme henüz tamamlanmadı. Önce /api/upload/finish çağırın.",
        )
    container_meta = _read_json_dict(job_dir / "container_meta.json") or {}
    patch_result = _read_json_dict(job_dir / "patch_result.json") or {}

    def _valid_candidate(cand: Path | None) -> Path | None:
        if cand is None:
            return None
        try:
            resolved = cand.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(jdir_resolved):
            return None
        if resolved.is_file() and resolved.suffix.lower() == ".apk":
            return resolved
        return None

    for raw_path in (upload_meta.get("targetApkPath"), container_meta.get("extractedApkPath")):
        if isinstance(raw_path, str) and raw_path.strip():
            found = _valid_candidate(Path(raw_path))
            if found is not None:
                return found

    target_name = upload_meta.get("targetApkName") or container_meta.get("innerApkName")
    if isinstance(target_name, str) and target_name.strip():
        safe_base = Path(target_name.replace("\\", "/")).name
        for cand in (job_dir / "_extracted" / safe_base, job_dir / safe_base):
            found = _valid_candidate(cand)
            if found is not None:
                return found

    for key in ("sanitizedFileName", "fileName"):
        raw_name = upload_meta.get(key)
        if isinstance(raw_name, str) and raw_name.strip():
            safe_base = Path(raw_name.replace("\\", "/")).name
            found = _valid_candidate(job_dir / safe_base)
            if found is not None:
                return found

    excluded = {str(patch_result.get("fileName") or "").lower()}
    extracted_dir = job_dir / "_extracted"
    if extracted_dir.is_dir():
        for cand in sorted(extracted_dir.glob("*.apk")):
            found = _valid_candidate(cand)
            if found is not None:
                return found

    for cand in sorted(job_dir.glob("*.apk")):
        low = cand.name.lower()
        if low in excluded or low.endswith(("_uyumlu.apk", "_patched.apk")):
            continue
        found = _valid_candidate(cand)
        if found is not None:
            return found

    if upload_meta.get("repatchAvailable") is False:
        raise HTTPException(
            status_code=404,
            detail="Büyük kaynak APK disk temizliği nedeniyle kaldırıldı; yeniden yamalama için dosyayı tekrar yükleyin.",
        )
    raise HTTPException(status_code=404, detail="Kaynak APK dosyası bulunamadı.")


def _ensure_ready_keystore(cfg: Settings) -> KeystoreState:
    """Return a ready ``KeystoreState`` for ``cfg.KEYSTORE_PATH``, initializing if needed."""
    state = get_keystore_state()
    if state is not None and state.ready and state.path == cfg.KEYSTORE_PATH and state.path.is_file():
        return state
    return ensure_signing_keystore(cfg)


def _get_job_pkg_and_ver(job_dir: Path) -> tuple[str, str]:
    upload_meta = _read_json_dict(job_dir / "upload_meta.json") or {}
    apk_info = upload_meta.get("apkInfo") if isinstance(upload_meta.get("apkInfo"), dict) else {}
    patch_result = _read_json_dict(job_dir / "patch_result.json") or {}
    package_id = str(apk_info.get("packageId") or patch_result.get("packageId") or "").strip()
    version_code = str(apk_info.get("versionCode") or patch_result.get("versionCode") or "1").strip()
    return package_id, version_code


def _public_obb_list(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": str(rec.get("name") or ""),
            "normalizedPath": str(rec.get("normalizedPath") or rec.get("name") or ""),
            "sizeBytes": int(rec.get("sizeBytes") or 0),
            "validObbName": bool(rec.get("validObbName", False)),
            "warning": rec.get("warning"),
        }
        for rec in records
    ]


def _collect_download_allowlist(job_dir: Path, job_manager: JobManager, job_id: str) -> set[str]:
    """Build the strict allowlist of downloadable output artifact filenames for ``job_id``."""
    allowlist: set[str] = set()

    def _add(name: Any) -> None:
        if isinstance(name, str) and name.strip():
            cleaned = name.strip()
            if "/" not in cleaned and "\\" not in cleaned and "\x00" not in cleaned and cleaned not in (".", ".."):
                allowlist.add(cleaned)

    def _add_patch_result(res: Any) -> None:
        if not isinstance(res, dict):
            return
        _add(res.get("fileName"))
        split_bundle = res.get("splitBundle")
        if isinstance(split_bundle, dict):
            _add(split_bundle.get("fileName"))
            _add(split_bundle.get("name"))

    _add_patch_result(_read_json_dict(job_dir / "patch_result.json"))

    state = job_manager.get_job_state(job_id)
    if isinstance(state, dict):
        _add_patch_result(state.get("result"))
        full = state.get("fullXapk")
        if isinstance(full, dict):
            full_res = full.get("result")
            if isinstance(full_res, dict):
                _add(full_res.get("fileName"))

    # Defense-in-depth: never allow metadata JSON or raw uploaded archive through /api/download
    forbidden = {
        "upload_meta.json",
        "container_meta.json",
        "patch_result.json",
        "job_state.json",
        "extra_obb_meta.json",
        ".last_activity",
    }
    upload_meta = _read_json_dict(job_dir / "upload_meta.json")
    if isinstance(upload_meta, dict):
        for k in ("fileName", "sanitizedFileName"):
            val = upload_meta.get(k)
            if isinstance(val, str) and val.strip():
                forbidden.add(Path(val.replace("\\", "/")).name)

    return {name for name in allowlist if name not in forbidden and not name.endswith((".pass", ".jks", ".json"))}


def _extract_unique_container_obb(
    job_dir: Path,
    container_meta: dict[str, Any],
    obb_index: int,
    max_bytes: int,
) -> tuple[Path, str]:
    """Extract container OBB to a unique per-request temp file under ``_extracted_obb/``."""
    obbs = container_meta.get("obbFiles") if isinstance(container_meta, dict) else None
    if not isinstance(obbs, list) or obb_index < 0 or obb_index >= len(obbs):
        raise HTTPException(status_code=404, detail="OBB indeksi geçersiz.")

    obb_meta = obbs[obb_index]
    zip_entry = obb_meta.get("zipEntry")
    if not isinstance(zip_entry, str) or not zip_entry:
        raise InvalidArchiveError("OBB arşiv giriş yolu eksik.")
    norm_entry = zip_entry.replace("\\", "/")
    if norm_entry.startswith("/") or ".." in norm_entry.split("/") or "\x00" in norm_entry:
        raise InvalidArchiveError("OBB arşiv giriş yolu güvenli değil.")

    archive_raw = container_meta.get("archive")
    archive_path = Path(str(archive_raw)) if archive_raw else None
    if archive_path is None or not archive_path.is_file():
        raise HTTPException(status_code=404, detail="Kaynak konteyner arşivi bulunamadı.")

    safe_name = sanitize_filename(str(obb_meta.get("name") or f"obb_{obb_index}.obb"), default="main.obb")
    out_dir = job_dir / "_extracted_obb"
    out_dir.mkdir(parents=True, exist_ok=True)
    unique_path = out_dir / f"dl_{obb_index}_{uuid.uuid4().hex}_{safe_name}"

    try:
        with zipfile.ZipFile(archive_path, "r") as zarch:
            try:
                zinfo = zarch.getinfo(zip_entry)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=f"OBB girdisi arşivde bulunamadı: {zip_entry}") from exc
            if zinfo.flag_bits & 0x1:
                raise InvalidArchiveError("Şifreli OBB girdisi çıkarılamaz.")
            with zarch.open(zinfo, "r") as rfp, unique_path.open("wb") as wfp:
                copy_stream_limited(rfp, wfp, max_bytes, f"OBB ({safe_name})")
        with contextlib.suppress(OSError):
            os.chmod(unique_path, 0o644)
        return unique_path, safe_name
    except Exception:
        unique_path.unlink(missing_ok=True)
        raise


def _cleanup_temp_obb_and_release(temp_path: Path | None, job_manager: JobManager, job_id: str) -> None:
    """Delete per-request temp OBB file without rmdir-racing shared _extracted_obb, then release active ref."""
    try:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    finally:
        job_manager.release_active(job_id)


class _DownloadCleanupGuard:
    """Thread-safe ownership handoff ensuring active_ref & temp OBB cleanup runs exactly once across all races."""

    def __init__(self, job_manager: JobManager, job_id: str) -> None:
        self._job_manager = job_manager
        self._job_id = job_id
        self._lock = threading.Lock()
        self._aborted = False
        self._acquired = False
        self._handed_off = False
        self._cleaned = False
        self._temp_path: Path | None = None

    def acquire_in_worker(self) -> bool:
        """Acquire active_ref in worker thread; returns False (auto-releasing) if caller already aborted."""
        with self._lock:
            if self._aborted:
                return False
        self._job_manager.acquire_active(self._job_id)
        release_now = False
        with self._lock:
            self._acquired = True
            if self._aborted and not self._cleaned:
                self._cleaned = True
                release_now = True
        if release_now:
            self._job_manager.release_active(self._job_id)
            return False
        return True

    def set_temp_path(self, temp_path: Path) -> None:
        with self._lock:
            self._temp_path = temp_path

    def commit_handoff(self) -> bool:
        """Atomically transfer cleanup ownership to async caller; cleans up immediately if already aborted."""
        cleanup_now = False
        temp_path: Path | None = None
        with self._lock:
            if self._aborted:
                if self._acquired and not self._cleaned:
                    self._cleaned = True
                    cleanup_now = True
                    temp_path = self._temp_path
            else:
                self._handed_off = True
                return True
        if cleanup_now:
            _cleanup_temp_obb_and_release(temp_path, self._job_manager, self._job_id)
        return False

    def abort_in_worker(self) -> None:
        """Clean up acquired active_ref (and temp_path if recorded) when worker raises before handoff."""
        cleanup_now = False
        temp_path: Path | None = None
        with self._lock:
            if self._acquired and not self._cleaned:
                self._cleaned = True
                cleanup_now = True
                temp_path = self._temp_path
        if cleanup_now:
            _cleanup_temp_obb_and_release(temp_path, self._job_manager, self._job_id)

    def cleanup_once(self) -> None:
        """Idempotent single-shot cleanup callback for _ManagedFileResponse and caller-owned except paths."""
        cleanup_now = False
        temp_path: Path | None = None
        with self._lock:
            if self._acquired and not self._cleaned:
                self._cleaned = True
                cleanup_now = True
                temp_path = self._temp_path
        if cleanup_now:
            _cleanup_temp_obb_and_release(temp_path, self._job_manager, self._job_id)

    def abort_from_caller(self) -> bool:
        """Mark aborted from async except BaseException; return True iff caller owns cleanup now."""
        with self._lock:
            self._aborted = True
            return self._handed_off and self._acquired and not self._cleaned


class _ManagedFileResponse(FileResponse):
    """FileResponse subclass guaranteeing idempotent cleanup on all outcomes (200, 206, 400, 416, errors)."""

    def __init__(
        self,
        *args: Any,
        cleanup_fn: Callable[[], None],
        **kwargs: Any,
    ) -> None:
        kwargs.pop("background", None)
        super().__init__(*args, **kwargs)
        self._cleanup_fn = cleanup_fn
        self._cleanup_lock = threading.Lock()
        self._cleaned = False

    def _run_cleanup_once(self) -> None:
        with self._cleanup_lock:
            if self._cleaned:
                return
            self._cleaned = True
        self._cleanup_fn()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await _run_cleanup_shielded(self._run_cleanup_once)


def _path_has_symlink_within(root: Path, target_unres: Path) -> bool:
    """Return True if ``target_unres`` or any intermediate segment under ``root`` is a symlink."""
    try:
        rel = target_unres.relative_to(root)
    except ValueError:
        return True
    cur = root
    for part in rel.parts:
        cur = cur / part
        if cur.is_symlink():
            return True
    return False


def _obb_path_parts(norm_rel: str) -> tuple[str, ...]:
    return tuple(part.lower() for part in Path(norm_rel.replace("\\", "/")).parts if part not in ("", "."))


def _check_obb_path_collision(new_norm_rel: str, existing_norm_rels: Iterable[str]) -> None:
    """Reject ancestor/descendant (file-vs-directory) collisions among normalized OBB relative paths."""
    new_parts = _obb_path_parts(new_norm_rel)
    if not new_parts:
        raise InvalidArchiveError("OBB dosya yolu geçersiz.")
    for existing in existing_norm_rels:
        ex_parts = _obb_path_parts(existing)
        if not ex_parts or new_parts == ex_parts:
            continue
        shorter = min(len(new_parts), len(ex_parts))
        if new_parts[:shorter] == ex_parts[:shorter]:
            raise InvalidArchiveError(
                f"OBB dosya/klasör yolu çakışması: '{new_norm_rel}' ile '{existing}' birlikte kullanılamaz."
            )


def _sanitize_upload_filename(
    raw_name: str,
    supported_exts: tuple[str, ...],
    *,
    default_stem: str = "paket",
) -> str:
    """Validate and sanitize an uploaded archive filename without falling back to a valid .apk on traversal."""
    norm_raw = raw_name.replace("\\", "/")
    raw_parts = [part for part in norm_raw.split("/") if part]
    raw_base = raw_parts[-1].strip() if raw_parts else ""
    if not raw_base or raw_base in {".", ".."} or not raw_base.rstrip(" ."):
        raise HTTPException(status_code=400, detail="Geçersiz dosya adı.")

    sanitized = sanitize_filename(raw_name, default=f"{default_stem}.invalid", max_len=120)
    if not sanitized.lower().endswith(supported_exts):
        raise HTTPException(
            status_code=400,
            detail="Desteklenen biçimler: .apk, .xapk, .apks, .apkm, .zip",
        )
    return sanitized


# ---------------------------------------------------------------------------
# FastAPI Application Factory
# ---------------------------------------------------------------------------


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and wire the RetroDroid Compat v5.4.0 FastAPI application."""
    cfg_fn: Callable[[], Settings] = (lambda: settings) if settings is not None else get_settings
    job_manager = JobManager(settings_getter=cfg_fn)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configure_logging()
        cfg = cfg_fn()
        await asyncio.to_thread(ensure_work_dir, cfg)
        await asyncio.to_thread(probe_android_tools)
        try:
            await asyncio.to_thread(ensure_signing_keystore, cfg)
        except RetroDroidError as exc:
            _LOG.warning("Keystore startup degraded: %s", exc.detail)
        except (OSError, RuntimeError, ValueError) as exc:
            _LOG.warning("Keystore startup unexpected failure: %s", exc)
        await asyncio.to_thread(job_manager.load_persisted_jobs)

        stop_event = asyncio.Event()

        async def _janitor_loop() -> None:
            while not stop_event.is_set():
                cur_cfg = cfg_fn()
                interval = min(60.0, max(5.0, float(cur_cfg.JOB_TTL_SECONDS) / 2.0))
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
                    break
                except TimeoutError:
                    pass
                try:
                    await asyncio.to_thread(job_manager.cleanup_old_jobs)
                except (RetroDroidError, OSError, RuntimeError) as exc:
                    _LOG.warning("Periodic janitor error: %s", exc)

        janitor_task = asyncio.create_task(_janitor_loop(), name="retrodroid-janitor")
        try:
            yield
        finally:
            stop_event.set()
            janitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await janitor_task

    application = FastAPI(
        title="RetroDroid Compat API",
        version=APP_VERSION,
        lifespan=lifespan,
    )
    application.state.job_manager = job_manager
    application.state.get_settings = cfg_fn

    # Exception handlers
    @application.exception_handler(RetroDroidError)
    async def _handle_retrodroid_error(_request: Request, exc: RetroDroidError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @application.exception_handler(Exception)
    async def _handle_unexpected_error(_request: Request, _exc: Exception) -> JSONResponse:
        _LOG.exception("Unhandled API error")
        return JSONResponse(status_code=500, content={"detail": "Sunucu iç hatası."})

    # Pure-ASGI middleware stack (added innermost -> outermost)
    application.add_middleware(ApiTokenAuthMiddleware, cfg_fn=cfg_fn)
    application.add_middleware(RateLimitMiddleware, cfg_fn=cfg_fn)
    application.add_middleware(DynamicCORSMiddleware, cfg_fn=cfg_fn)
    application.add_middleware(SecurityHeadersMiddleware)

    # ------------------------------------------------------------------ F01: UI, Static, Health, Keystore
    @application.get("/", response_class=HTMLResponse)
    async def serve_ui() -> HTMLResponse:
        def _read_index() -> str:
            idx = BASE_DIR / "index.html"
            if idx.is_file():
                return idx.read_text(encoding="utf-8")
            return f"<h3>RetroDroid Compat API v{APP_VERSION} aktif. <a href='/docs'>/docs</a></h3>"

        html = await asyncio.to_thread(_read_index)
        return HTMLResponse(content=html, status_code=200)

    @application.get("/static/{asset_path:path}")
    async def serve_static(asset_path: str) -> FileResponse:
        def _resolve_static() -> Path:
            static_dir = BASE_DIR / "static"
            if not static_dir.is_dir() or static_dir.is_symlink():
                raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.")
            if not asset_path or "\x00" in asset_path or "\\" in asset_path:
                raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.")
            segments = asset_path.split("/")
            if any(seg in ("", ".", "..") or seg.startswith(".") for seg in segments):
                raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.")
            root_resolved = static_dir.resolve()
            cur = root_resolved
            for seg in segments:
                cur = cur / seg
                if cur.is_symlink():
                    raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.")
            try:
                target = cur.resolve()
            except OSError as exc:
                raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.") from exc
            if not target.is_relative_to(root_resolved) or not target.is_file():
                raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.")
            rel_parts = target.relative_to(root_resolved).parts
            if not rel_parts or any(part.startswith(".") for part in rel_parts):
                raise HTTPException(status_code=404, detail="Statik dosya bulunamadı.")
            return target

        target_path = await asyncio.to_thread(_resolve_static)
        return FileResponse(path=target_path)

    @application.get("/health")
    async def health(strict: bool = False) -> JSONResponse:
        def _collect() -> tuple[dict[str, Any], bool]:
            cfg = cfg_fn()
            wd = cfg.WORK_DIR if cfg.WORK_DIR.is_dir() else ensure_work_dir(cfg)
            free_mb = 0
            try:
                free_mb = int(shutil.disk_usage(wd).free / (1024 * 1024))
            except OSError:
                free_mb = 0

            tool_info = probe_android_tools()
            tools = dict(tool_info["tools"])
            tool_versions = dict(tool_info["toolVersions"])
            zipalign_16k = bool(tool_info["zipalign16kSupported"])
            ks_info = get_keystore_info()
            ks_state = get_keystore_state()
            ks_path_raw = ks_info.get("path")
            ks_path = (
                ks_state.path
                if ks_state is not None
                else (Path(str(ks_path_raw)) if ks_path_raw else cfg.KEYSTORE_PATH)
            )
            ks_ready = bool(ks_info.get("ready")) and ks_path.is_file()
            all_tools = all(bool(tools.get(name)) for name in _TOOL_NAMES)
            healthy = bool(all_tools and ks_ready)

            payload: dict[str, Any] = {
                "status": "ok" if healthy else "degraded",
                "healthy": healthy,
                "version": APP_VERSION,
                "engine": f"RetroDroid Compat Server v{APP_VERSION}",
                "serverTime": time.time(),
                "diskFreeMB": free_mb,
                "freeDiskMB": free_mb,
                "workDir": str(cfg.WORK_DIR),
                "maxUploadMB": cfg.MAX_UPLOAD_MB,
                "chunkSizeMB": cfg.CHUNK_SIZE_MB,
                "jobTtlSeconds": cfg.JOB_TTL_SECONDS,
                "maxConcurrentPatches": cfg.MAX_CONCURRENT_PATCHES,
                "activePatches": job_manager.active_patch_count,
                "keystoreReady": ks_ready,
                "keystoreFingerprintSha256": ks_info.get("sha256") if ks_ready else None,
                "authRequired": cfg.auth_required,
                "tools": tools,
                "toolVersions": tool_versions,
                "zipalign16kSupported": zipalign_16k,
                "supportedFormats": list(cfg.SUPPORTED_EXTS),
                "fastBinaryAxml": True,
            }
            return payload, healthy

        payload, healthy = await asyncio.to_thread(_collect)
        status_code = 503 if (strict and not healthy) else 200
        return JSONResponse(status_code=status_code, content=payload)

    @application.get("/api/keystore-info")
    async def api_keystore_info() -> dict[str, Any]:
        def _info() -> dict[str, Any]:
            info = dict(get_keystore_info())
            if info.get("ready"):
                ks_path_raw = info.get("path")
                if not ks_path_raw or not Path(str(ks_path_raw)).is_file():
                    info["ready"] = False
            return info

        return await asyncio.to_thread(_info)

    # ------------------------------------------------------------------ F03: Resumable Chunked Upload & Analyze
    @application.post("/api/upload/init")
    async def api_upload_init(
        fileName: str = Form(...),
        totalSize: int = Form(...),
        totalChunks: int | None = Form(None),
        jobId: str | None = Form(None),
        purpose: str = Form("apk"),
    ) -> dict[str, Any]:
        cfg = cfg_fn()
        raw_name = (fileName or "").strip()
        if not raw_name:
            raise HTTPException(status_code=400, detail="Dosya adı boş olamaz.")

        purpose_norm = (purpose or "apk").strip().lower()
        if purpose_norm == "obb":
            raise HTTPException(
                status_code=400,
                detail="OBB yüklemeleri için /api/attach-obb/{job_id}/init uç noktasını kullanın.",
            )
        if purpose_norm != "apk":
            raise HTTPException(status_code=400, detail="Geçersiz yükleme amacı (purpose).")

        sanitized = _sanitize_upload_filename(raw_name, cfg.SUPPORTED_EXTS, default_stem="paket")

        resolved_chunks, chunk_size_bytes = _resolve_chunk_plan(int(totalSize), totalChunks, cfg)

        if jobId is not None and jobId.strip():
            job_id = job_manager.validate_job_id(jobId.strip())
        else:
            job_id = job_manager.new_job_id()

        def _init_on_disk() -> dict[str, Any]:
            ensure_work_dir(cfg)
            jdir = job_manager.job_dir(job_id)
            meta_file = jdir / "upload_meta.json"
            if meta_file.is_file():
                existing = _read_json_dict(meta_file) or {}
                if (
                    existing.get("status") == "uploading"
                    and existing.get("sanitizedFileName") == sanitized
                    and int(existing.get("totalSize") or 0) == int(totalSize)
                    and int(existing.get("totalChunks") or 0) == resolved_chunks
                ):
                    job_manager.touch_activity(job_id)
                    return {
                        "jobId": job_id,
                        "fileName": existing.get("fileName", raw_name),
                        "sanitizedFileName": sanitized,
                        "totalSize": int(totalSize),
                        "totalChunks": resolved_chunks,
                        "chunkSizeMB": int(existing.get("chunkSizeMB", cfg.CHUNK_SIZE_MB)),
                        "chunkSizeBytes": int(existing.get("chunkSizeBytes", chunk_size_bytes)),
                        "maxUploadMB": cfg.MAX_UPLOAD_MB,
                    }
                raise JobConflictError("Bu iş kimliği başka bir oturum için zaten kullanılıyor.")

            jdir.mkdir(parents=True, exist_ok=True)
            now = time.time()
            meta: dict[str, Any] = {
                "jobId": job_id,
                "fileName": raw_name,
                "sanitizedFileName": sanitized,
                "purpose": purpose_norm,
                "totalSize": int(totalSize),
                "totalChunks": resolved_chunks,
                "chunkSizeMB": cfg.CHUNK_SIZE_MB,
                "chunkSizeBytes": chunk_size_bytes,
                "receivedChunks": [],
                "receivedBytes": 0,
                "complete": False,
                "status": "uploading",
                "createdAt": now,
                "updatedAt": now,
            }
            write_json_atomic(meta_file, meta)
            job_manager.create_state(job_id, status="uploading", stage="Yükleniyor", fileName=sanitized)
            job_manager.touch_activity(job_id)
            return {
                "jobId": job_id,
                "fileName": raw_name,
                "sanitizedFileName": sanitized,
                "totalSize": int(totalSize),
                "totalChunks": resolved_chunks,
                "chunkSizeMB": cfg.CHUNK_SIZE_MB,
                "chunkSizeBytes": chunk_size_bytes,
                "maxUploadMB": cfg.MAX_UPLOAD_MB,
            }

        with log_job_context(job_id):
            return await asyncio.to_thread(_init_on_disk)

    @application.get("/api/upload/status/{job_id}")
    async def api_upload_status(job_id: str) -> dict[str, Any]:
        job_manager.validate_job_id(job_id)
        cfg = cfg_fn()

        def _read_status() -> dict[str, Any]:
            jdir = job_manager.require_job_dir(job_id)
            meta = _read_json_dict(jdir / "upload_meta.json")
            if meta is None:
                raise JobNotFoundError("Yükleme oturumu bulunamadı.")
            total_chunks = int(meta.get("totalChunks") or 0)
            received = sorted(int(c) for c in (meta.get("receivedChunks") or []))
            received_set = set(received)
            missing = [i for i in range(total_chunks) if i not in received_set]
            complete = bool(meta.get("complete", False))
            status = str(meta.get("status") or ("complete" if complete else "uploading"))
            return {
                "jobId": job_id,
                "fileName": meta.get("fileName"),
                "sanitizedFileName": meta.get("sanitizedFileName") or meta.get("fileName"),
                "totalSize": int(meta.get("totalSize") or 0),
                "totalChunks": total_chunks,
                "chunkSizeMB": int(meta.get("chunkSizeMB") or cfg.CHUNK_SIZE_MB),
                "chunkSizeBytes": int(meta.get("chunkSizeBytes") or cfg.chunk_size_bytes),
                "receivedChunks": received,
                "missingChunks": missing,
                "receivedBytes": int(meta.get("receivedBytes") or 0),
                "complete": complete,
                "status": status,
            }

        return await asyncio.to_thread(_read_status)

    @application.post("/api/upload/chunk")
    async def api_upload_chunk(
        chunk: Annotated[UploadFile, File(...)],
        jobId: str = Form(...),
        chunkIndex: int = Form(...),
        totalChunks: int | None = Form(None),
    ) -> dict[str, Any]:
        temp_path: Path | None = None
        try:
            job_manager.validate_job_id(jobId)
            cfg = cfg_fn()

            def _preflight() -> tuple[Path, int, int, int]:
                jdir = job_manager.require_job_dir(jobId)
                meta = _read_json_dict(jdir / "upload_meta.json")
                if meta is None:
                    raise JobNotFoundError("Yükleme oturumu bulunamadı.")
                if meta.get("complete"):
                    raise JobConflictError("Yükleme zaten tamamlandı.")
                tot_chunks = int(meta.get("totalChunks") or 0)
                tot_size = int(meta.get("totalSize") or 0)
                c_bytes = int(meta.get("chunkSizeBytes") or cfg.chunk_size_bytes)
                if totalChunks is not None and int(totalChunks) != tot_chunks:
                    raise HTTPException(status_code=400, detail="totalChunks oturum bilgisiyle uyuşmuyor.")
                if tot_chunks <= 0 or chunkIndex < 0 or chunkIndex >= tot_chunks:
                    raise HTTPException(status_code=400, detail="Geçersiz parça indeksi (chunkIndex).")
                expected = min(c_bytes, tot_size - chunkIndex * c_bytes)
                if expected <= 0:
                    raise HTTPException(status_code=400, detail="Geçersiz parça boyutu.")
                return jdir, tot_chunks, tot_size, c_bytes

            async with _hold_active_async(job_manager, jobId):
                jdir, tot_chunks, tot_size, chunk_size_bytes = await asyncio.to_thread(_preflight)
                expected_size = min(chunk_size_bytes, tot_size - chunkIndex * chunk_size_bytes)
                temp_path = jdir / f".chunk_{chunkIndex}_{uuid.uuid4().hex[:8]}.tmp"

                written = await _stream_upload_to_file(
                    chunk,
                    temp_path,
                    max_bytes=expected_size,
                    exact_expected=expected_size,
                    label="Parça",
                )
                if written == 0:
                    raise HTTPException(status_code=400, detail="Boş (0 bayt) parça yüklenemez.")
                if written != expected_size:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Eksik parça: {written}/{expected_size} bayt alındı.",
                    )

                def _commit_chunk() -> dict[str, Any]:
                    ulock = job_manager.get_upload_lock(jobId)
                    with ulock:
                        meta_file = jdir / "upload_meta.json"
                        meta = _read_json_dict(meta_file)
                        if meta is None:
                            raise JobNotFoundError("Yükleme oturumu bulunamadı.")
                        if meta.get("complete"):
                            raise JobConflictError("Yükleme zaten tamamlandı.")

                        received = {int(c) for c in (meta.get("receivedChunks") or [])}
                        if chunkIndex in received:
                            job_manager.touch_activity(jobId)
                            return {
                                "ok": True,
                                "jobId": jobId,
                                "chunkIndex": chunkIndex,
                                "receivedCount": len(received),
                                "totalChunks": tot_chunks,
                                "receivedBytes": int(meta.get("receivedBytes") or 0),
                                "duplicate": True,
                            }

                        sanitized = str(meta.get("sanitizedFileName") or meta.get("fileName") or "paket.apk")
                        dest = jdir / sanitized
                        open_mode = "r+b" if dest.exists() else "wb"
                        assert temp_path is not None
                        with dest.open(open_mode) as out_fp, temp_path.open("rb") as part_fp:
                            out_fp.seek(chunkIndex * chunk_size_bytes)
                            shutil.copyfileobj(part_fp, out_fp, _STREAM_BUF_SIZE)
                            out_fp.flush()
                            os.fsync(out_fp.fileno())

                        received.add(chunkIndex)
                        meta["receivedChunks"] = sorted(received)
                        meta["receivedBytes"] = sum(
                            min(chunk_size_bytes, tot_size - idx * chunk_size_bytes) for idx in received
                        )
                        meta["updatedAt"] = time.time()
                        write_json_atomic(meta_file, meta)
                        job_manager.touch_activity(jobId)
                        return {
                            "ok": True,
                            "jobId": jobId,
                            "chunkIndex": chunkIndex,
                            "receivedCount": len(received),
                            "totalChunks": tot_chunks,
                            "receivedBytes": int(meta["receivedBytes"]),
                            "duplicate": False,
                        }

                return await asyncio.to_thread(_commit_chunk)
        finally:
            if temp_path is not None:
                await asyncio.to_thread(temp_path.unlink, True)
            with contextlib.suppress(Exception):
                await chunk.close()

    @application.post("/api/upload/finish")
    async def api_upload_finish(jobId: str = Form(...)) -> dict[str, Any]:
        job_manager.validate_job_id(jobId)
        cfg = cfg_fn()
        failed_wipe = False

        def _finish_sync() -> dict[str, Any]:
            nonlocal failed_wipe
            with log_job_context(jobId):
                jdir = job_manager.require_job_dir(jobId)
                if job_manager.is_patch_active(jobId):
                    raise JobConflictError("Aktif bir işlem sürerken yükleme sonlandırılamaz.")
                pre_meta = _read_json_dict(jdir / "upload_meta.json")
                if pre_meta is None:
                    raise JobNotFoundError("Yükleme oturumu bulunamadı.")
                if pre_meta.get("complete"):
                    raise JobConflictError("Yükleme zaten tamamlandı.")

                ulock = job_manager.get_upload_lock(jobId)
                jlock = job_manager.get_job_lock(jobId)
                with ulock, jlock:
                    if job_manager.is_patch_active(jobId):
                        raise JobConflictError("Aktif bir işlem sürerken yükleme sonlandırılamaz.")
                    meta_file = jdir / "upload_meta.json"
                    meta = _read_json_dict(meta_file)
                    if meta is None:
                        raise JobNotFoundError("Yükleme oturumu bulunamadı.")
                    if meta.get("complete"):
                        raise JobConflictError("Yükleme zaten tamamlandı.")

                    sanitized = str(meta.get("sanitizedFileName") or meta.get("fileName") or "")
                    original_name = str(meta.get("fileName") or sanitized)
                    uploaded_path = jdir / sanitized
                    expected_size = int(meta.get("totalSize") or 0)
                    total_chunks = int(meta.get("totalChunks") or 0)
                    received = {int(c) for c in (meta.get("receivedChunks") or [])}

                    if expected_size <= 0:
                        raise HTTPException(status_code=400, detail="Boş (0 bayt) dosya yüklenemez.")
                    if expected_size > cfg.max_upload_bytes:
                        raise HTTPException(status_code=413, detail=f"Dosya {cfg.MAX_UPLOAD_MB} MB sınırını aşıyor.")
                    if total_chunks <= 0 or len(received) != total_chunks or any(
                        i not in received for i in range(total_chunks)
                    ):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Dosya eksik yüklendi: {len(received)}/{total_chunks} parça alındı.",
                        )
                    if not uploaded_path.is_file():
                        raise HTTPException(status_code=400, detail="Yüklenen dosya bulunamadı.")
                    actual_size = uploaded_path.stat().st_size
                    if actual_size <= 0 or actual_size != expected_size or int(meta.get("receivedBytes") or 0) != expected_size:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Yükleme boyutu uyuşmuyor: {actual_size}/{expected_size} bayt.",
                        )

                    try:
                        apk_path, container_info = unpack_container_if_needed(
                            uploaded_path,
                            jdir,
                            max_entries=cfg.MAX_ARCHIVE_ENTRIES,
                            max_bytes=cfg.MAX_DECOMPRESSED_BYTES,
                        )
                        info = inspect_apk(apk_path, container_info)
                    except Exception:
                        failed_wipe = True
                        shutil.rmtree(jdir, ignore_errors=True)
                        job_manager.pop_upload_lock(jobId)
                        raise

                    meta.update(
                        {
                            "fileName": original_name,
                            "sanitizedFileName": sanitized,
                            "complete": True,
                            "status": "complete",
                            "targetApkName": apk_path.name,
                            "targetApkPath": str(apk_path.resolve()),
                            "repatchAvailable": True,
                            "containerType": container_info.get("containerType", "APK"),
                            "innerApkName": container_info.get("innerApkName"),
                            "splitApks": container_info.get("splitApks", []),
                            "obbFiles": container_info.get("obbFiles", []),
                            "hasObb": bool(container_info.get("obbFiles")),
                            "apkInfo": _extract_apk_info_summary(info),
                            "updatedAt": time.time(),
                        }
                    )
                    write_json_atomic(meta_file, meta)
                    job_manager.create_state(
                        jobId,
                        status="analyzed",
                        stage="Analiz edildi",
                        fileName=sanitized,
                        targetSdk=info.get("targetSdk"),
                    )
                    job_manager.pop_upload_lock(jobId)
                    return _build_analyze_response(
                        jobId,
                        apk_path,
                        sanitized,
                        original_name,
                        container_info,
                        info,
                    )

        try:
            async with _hold_active_async(job_manager, jobId):
                return await asyncio.to_thread(_finish_sync)
        except Exception:
            if failed_wipe:
                await asyncio.to_thread(job_manager.forget_job, jobId)
            raise

    @application.post("/api/analyze")
    async def api_analyze(file: Annotated[UploadFile, File(...)]) -> dict[str, Any]:
        cfg = cfg_fn()
        job_id = job_manager.new_job_id()
        jdir: Path | None = None
        try:
            raw_name = (file.filename if file.filename is not None else "uygulama.apk").strip()
            sanitized = _sanitize_upload_filename(raw_name, cfg.SUPPORTED_EXTS, default_stem="uygulama")

            def _prepare_dir() -> Path:
                ensure_work_dir(cfg)
                d = job_manager.job_dir(job_id)
                d.mkdir(parents=True, exist_ok=True)
                return d

            jdir = await asyncio.to_thread(_prepare_dir)
            uploaded_path = jdir / sanitized

            async with _hold_active_async(job_manager, job_id):
                written = await _stream_upload_to_file(
                    file,
                    uploaded_path,
                    max_bytes=cfg.max_upload_bytes,
                    label="Dosya",
                )
                if written == 0:
                    raise HTTPException(status_code=400, detail="Boş (0 bayt) dosya yüklenemez.")

                def _unpack_and_inspect() -> dict[str, Any]:
                    with log_job_context(job_id):
                        assert jdir is not None
                        apk_path, container_info = unpack_container_if_needed(
                            uploaded_path,
                            jdir,
                            max_entries=cfg.MAX_ARCHIVE_ENTRIES,
                            max_bytes=cfg.MAX_DECOMPRESSED_BYTES,
                        )
                        info = inspect_apk(apk_path, container_info)
                        now = time.time()
                        meta = {
                            "jobId": job_id,
                            "fileName": raw_name,
                            "sanitizedFileName": sanitized,
                            "purpose": "apk",
                            "totalSize": written,
                            "totalChunks": 1,
                            "chunkSizeMB": cfg.CHUNK_SIZE_MB,
                            "chunkSizeBytes": cfg.chunk_size_bytes,
                            "receivedChunks": [0],
                            "receivedBytes": written,
                            "complete": True,
                            "status": "complete",
                            "targetApkName": apk_path.name,
                            "targetApkPath": str(apk_path.resolve()),
                            "repatchAvailable": True,
                            "containerType": container_info.get("containerType", "APK"),
                            "innerApkName": container_info.get("innerApkName"),
                            "splitApks": container_info.get("splitApks", []),
                            "obbFiles": container_info.get("obbFiles", []),
                            "hasObb": bool(container_info.get("obbFiles")),
                            "apkInfo": _extract_apk_info_summary(info),
                            "createdAt": now,
                            "updatedAt": now,
                        }
                        write_json_atomic(jdir / "upload_meta.json", meta)
                        job_manager.create_state(
                            job_id,
                            status="analyzed",
                            stage="Analiz edildi",
                            fileName=sanitized,
                            targetSdk=info.get("targetSdk"),
                        )
                        return _build_analyze_response(
                            job_id,
                            apk_path,
                            sanitized,
                            raw_name,
                            container_info,
                            info,
                        )

                return await asyncio.to_thread(_unpack_and_inspect)
        except Exception:
            if jdir is not None:
                await asyncio.to_thread(shutil.rmtree, jdir, True)
                await asyncio.to_thread(job_manager.forget_job, job_id)
            raise
        finally:
            with contextlib.suppress(Exception):
                await file.close()

    # ------------------------------------------------------------------ F06 & F07: Patch & Sign Pipeline
    @application.post("/api/patch-sign")
    async def api_patch_sign(
        jobId: str = Form(...),
        targetSdk: int = Form(28),
        mode: str = Form("patch_and_sign"),
        resign: bool = Form(True),
        background: bool = Form(False),
        patchTargetSdk: bool = Form(True),
        addLegacyStorage: bool = Form(False),
        enableCleartext: bool = Form(False),
        addNotchSupport: bool = Form(False),
        forceExtractNativeLibs: bool = Form(False),
        allowDowngrade: bool = Form(False),
    ) -> dict[str, Any]:
        job_manager.validate_job_id(jobId)
        if mode not in {"patch_and_sign", "resign_only"}:
            raise HTTPException(status_code=400, detail="Geçersiz işlem modu (patch_and_sign | resign_only).")
        if targetSdk < 1 or targetSdk > 100:
            raise HTTPException(status_code=400, detail="Geçersiz targetSdk değeri.")

        cfg = cfg_fn()
        jdir = await asyncio.to_thread(job_manager.require_job_dir, jobId)

        opts = ManifestPatchOptions(
            target_sdk=int(targetSdk),
            patch_target_sdk=bool(patchTargetSdk),
            add_legacy_storage=bool(addLegacyStorage),
            enable_cleartext=bool(enableCleartext),
            add_notch_support=bool(addNotchSupport),
            force_extract_native_libs=bool(forceExtractNativeLibs),
            allow_downgrade=bool(allowDowngrade),
        )

        job_manager.reserve_patch_slot(jobId)

        def _prepare() -> tuple[Path, KeystoreState | None]:
            src = _resolve_source_apk(jdir)
            ks = _ensure_ready_keystore(cfg) if resign else get_keystore_state()
            return src, ks

        src_apk, ks_state = await _start_reserved_operation(
            job_manager,
            jobId,
            "patch",
            "İşlem başlatılıyor",
            _prepare,
        )

        def _runner(
            cancel_event: threading.Event,
            on_proc: Callable[[Any], None],
            append_log: Callable[[str], None],
            progress_cb: Callable[[int, str], None],
        ) -> dict[str, Any]:
            with log_job_context(jobId):
                return patch_and_sign_pipeline(
                    job_id=jobId,
                    job_dir=jdir,
                    src_apk=src_apk,
                    keystore_state=ks_state,
                    options=opts,
                    mode=mode,
                    resign=bool(resign),
                    append_log=append_log,
                    progress_cb=progress_cb,
                    cancel_event=cancel_event,
                    on_proc=on_proc,
                    settings=cfg,
                )

        if background:
            try:
                worker = threading.Thread(
                    target=job_manager.execute_operation,
                    args=(jobId, "patch", _runner),
                    kwargs={"reraise": False},
                    daemon=True,
                    name=f"patch-{jobId}",
                )
                worker.start()
            except BaseException:
                bg_lock = threading.Lock()
                bg_cleaned = False

                def _fail_and_release() -> None:
                    nonlocal bg_cleaned
                    with bg_lock:
                        if bg_cleaned:
                            return
                        bg_cleaned = True
                    job_manager.fail_operation(jobId, "Arka plan iş parçacığı başlatılamadı.", "patch")
                    job_manager.release_patch_slot(jobId)

                await _run_cleanup_shielded(_fail_and_release)
                raise
            return {
                "jobId": jobId,
                "status": "running",
                "progress": 0,
                "stage": "İşlem başlatılıyor",
                "pollUrl": f"/api/patch-status/{jobId}",
                "pollIntervalMs": 1000,
                "serverTime": time.time(),
            }

        return await _execute_sync_reserved_operation(job_manager, jobId, "patch", _runner)

    @application.get("/api/patch-status/{job_id}")
    async def api_patch_status(job_id: str) -> dict[str, Any]:
        job_manager.validate_job_id(job_id)

        def _read() -> dict[str, Any]:
            state = job_manager.require_job_state(job_id)
            return {
                "jobId": job_id,
                "status": state.get("status"),
                "progress": state.get("progress", 0),
                "stage": state.get("stage", ""),
                "logs": list(state.get("logs") or []),
                "result": state.get("result"),
                "error": state.get("error"),
                "createdAt": state.get("createdAt"),
                "updatedAt": state.get("updatedAt"),
                "finishedAt": state.get("finishedAt"),
                "serverTime": time.time(),
                "expiresInSeconds": job_manager.expires_in(job_id),
            }

        return await asyncio.to_thread(_read)

    # ------------------------------------------------------------------ F09: Cancel, Jobs List & Delete
    @application.post("/api/patch-cancel/{job_id}")
    async def api_patch_cancel(job_id: str) -> dict[str, Any]:
        return await asyncio.to_thread(job_manager.request_cancel, job_id)

    @application.get("/api/jobs")
    async def api_jobs() -> dict[str, Any]:
        cfg = cfg_fn()
        jobs = await asyncio.to_thread(job_manager.list_jobs)
        return {
            "jobs": jobs,
            "linkTtlSeconds": cfg.JOB_TTL_SECONDS,
            "serverTime": time.time(),
        }

    @application.delete("/api/jobs/{job_id}")
    async def api_delete_job(job_id: str) -> dict[str, Any]:
        return await asyncio.to_thread(job_manager.delete_job, job_id)

    # ------------------------------------------------------------------ F08: OBB Attach (Multipart + Chunked)
    @application.post("/api/attach-obb/{job_id}")
    async def api_attach_obb(
        job_id: str,
        files: Annotated[list[UploadFile], File(...)],
    ) -> dict[str, Any]:
        cfg = cfg_fn()
        staging_dir: Path | None = None
        try:
            job_manager.validate_job_id(job_id)
            if not files:
                raise HTTPException(status_code=400, detail="En az bir OBB dosyası seçin.")
            if len(files) > cfg.MAX_ARCHIVE_ENTRIES:
                raise HTTPException(status_code=413, detail="Çok fazla OBB dosyası seçildi.")

            def _preflight() -> tuple[Path, str, str]:
                jdir = job_manager.require_job_dir(job_id)
                upload_meta = _read_json_dict(jdir / "upload_meta.json")
                if upload_meta is None:
                    raise JobNotFoundError("APK yükleme işi bulunamadı veya süresi doldu.")
                if upload_meta.get("complete") is False:
                    raise JobConflictError("APK yüklemesi henüz tamamlanmadı. Önce /api/upload/finish çağırın.")
                if job_manager.is_patch_active(job_id):
                    raise JobConflictError("Aktif bir yamalama veya paketleme sürerken OBB eklenemez.")
                pkg, ver = _get_job_pkg_and_ver(jdir)
                return jdir, pkg, ver

            async with _hold_active_async(job_manager, job_id):
                jdir, package_id, version_code = await asyncio.to_thread(_preflight)
                target_dir = jdir / "extra_obb"
                staging_dir = jdir / f".extra_obb_stage_{uuid.uuid4().hex[:8]}"
                await asyncio.to_thread(staging_dir.mkdir, parents=True, exist_ok=True)
                staging_resolved = staging_dir.resolve()

                disk_records: list[dict[str, Any]] = []
                seen_norm: set[str] = set()
                seen_norm_list: list[str] = []
                total_bytes = 0

                for upload in files:
                    raw_name = (upload.filename or "").strip()
                    if not raw_name:
                        raise InvalidArchiveError("OBB dosya adı boş olamaz.")
                    # Always validate path safety first (blocks traversal even for non-.obb names)
                    norm_rel = normalize_obb_relpath(raw_name, package_id)
                    if not Path(norm_rel).name.lower().endswith(".obb"):
                        continue
                    if norm_rel.lower() in seen_norm:
                        raise InvalidArchiveError(f"Aynı yola sahip yinelenen OBB dosyası: {norm_rel}")
                    _check_obb_path_collision(norm_rel, seen_norm_list)
                    seen_norm.add(norm_rel.lower())
                    seen_norm_list.append(norm_rel)

                    staged_file = (staging_resolved / norm_rel).resolve()
                    if not staged_file.is_relative_to(staging_resolved):
                        raise InvalidArchiveError("OBB dosya yolu güvenli değil.")

                    remaining_cap = cfg.max_upload_bytes - total_bytes
                    try:
                        written = await _stream_upload_to_file(
                            upload,
                            staged_file,
                            max_bytes=remaining_cap,
                            label="OBB dosyası",
                        )
                    except (FileExistsError, IsADirectoryError, NotADirectoryError) as exc:
                        raise InvalidArchiveError(f"OBB dosya/klasör yolu çakışması: {norm_rel}") from exc
                    if written == 0:
                        raise InvalidArchiveError("Boş (0 bayt) OBB dosyası kabul edilmiyor.")

                    total_bytes += written
                    val = validate_obb_filename(norm_rel, package_id, version_code)
                    final_path = (target_dir / norm_rel).resolve()
                    disk_records.append(
                        {
                            "filePath": str(final_path),
                            "normalizedPath": norm_rel,
                            "name": Path(norm_rel).name,
                            "sizeBytes": written,
                            "validObbName": bool(val.get("valid")),
                            "warning": val.get("warning"),
                            "suggestedName": val.get("suggestedName"),
                        }
                    )

                if not disk_records:
                    raise HTTPException(status_code=400, detail="Seçimde geçerli .obb dosyası bulunamadı.")

                def _commit_staged() -> dict[str, Any]:
                    assert staging_dir is not None
                    with job_manager.get_job_lock(job_id):
                        if job_manager.is_patch_active(job_id):
                            raise JobConflictError("Aktif bir yamalama veya paketleme sürerken OBB eklenemez.")
                        old_trash: Path | None = None
                        if target_dir.exists():
                            old_trash = jdir / f".extra_obb_old_{uuid.uuid4().hex[:8]}"
                            os.replace(target_dir, old_trash)
                        os.replace(staging_dir, target_dir)
                        write_json_atomic(jdir / "extra_obb_meta.json", disk_records)
                        job_manager.touch_activity(job_id)
                        if old_trash is not None:
                            shutil.rmtree(old_trash, ignore_errors=True)
                    public_files = _public_obb_list(disk_records)
                    return {
                        "ok": True,
                        "jobId": job_id,
                        "count": len(public_files),
                        "totalSizeBytes": total_bytes,
                        "sizeBytes": total_bytes,
                        "files": public_files,
                    }

                return await asyncio.to_thread(_commit_staged)
        except Exception:
            if staging_dir is not None and staging_dir.exists():
                await asyncio.to_thread(shutil.rmtree, staging_dir, True)
            raise
        finally:
            for upload in files:
                with contextlib.suppress(Exception):
                    await upload.close()

    @application.post("/api/attach-obb/{job_id}/init")
    async def api_attach_obb_init(
        job_id: str,
        fileName: str = Form(...),
        totalSize: int = Form(...),
        totalChunks: int | None = Form(None),
        replaceExisting: bool = Form(False),
    ) -> dict[str, Any]:
        job_manager.validate_job_id(job_id)
        cfg = cfg_fn()
        resolved_chunks, chunk_size_bytes = _resolve_chunk_plan(int(totalSize), totalChunks, cfg)

        def _init_obb_session() -> dict[str, Any]:
            jdir = job_manager.require_job_dir(job_id)
            upload_meta = _read_json_dict(jdir / "upload_meta.json")
            if upload_meta is None:
                raise JobNotFoundError("APK yükleme işi bulunamadı veya süresi doldu.")
            if upload_meta.get("complete") is False:
                raise JobConflictError("APK yüklemesi henüz tamamlanmadı. Önce /api/upload/finish çağırın.")
            if job_manager.is_patch_active(job_id):
                raise JobConflictError("Aktif bir işlem sürerken OBB yüklenemez.")

            package_id, _ = _get_job_pkg_and_ver(jdir)
            norm_rel = normalize_obb_relpath(fileName, package_id)
            if not Path(norm_rel).name.lower().endswith(".obb"):
                raise HTTPException(status_code=400, detail="OBB dosyası .obb uzantılı olmalıdır.")

            upload_id = job_manager.new_job_id()
            sessions_dir = jdir / ".obb_uploads"
            sessions_dir.mkdir(parents=True, exist_ok=True)
            session_meta = {
                "uploadId": upload_id,
                "jobId": job_id,
                "fileName": fileName,
                "normalizedPath": norm_rel,
                "totalSize": int(totalSize),
                "totalChunks": resolved_chunks,
                "chunkSizeMB": cfg.CHUNK_SIZE_MB,
                "chunkSizeBytes": chunk_size_bytes,
                "receivedChunks": [],
                "receivedBytes": 0,
                "replaceExisting": bool(replaceExisting),
                "createdAt": time.time(),
            }
            write_json_atomic(sessions_dir / f"{upload_id}.json", session_meta)
            job_manager.touch_activity(job_id)
            return {
                "ok": True,
                "jobId": job_id,
                "uploadId": upload_id,
                "fileName": fileName,
                "normalizedPath": norm_rel,
                "totalSize": int(totalSize),
                "totalChunks": resolved_chunks,
                "chunkSizeMB": cfg.CHUNK_SIZE_MB,
                "chunkSizeBytes": chunk_size_bytes,
                "maxUploadMB": cfg.MAX_UPLOAD_MB,
            }

        async with _hold_active_async(job_manager, job_id):
            return await asyncio.to_thread(_init_obb_session)

    @application.post("/api/attach-obb/{job_id}/chunk")
    async def api_attach_obb_chunk(
        job_id: str,
        chunk: Annotated[UploadFile, File(...)],
        uploadId: str = Form(...),
        chunkIndex: int = Form(...),
        totalChunks: int | None = Form(None),
    ) -> dict[str, Any]:
        temp_path: Path | None = None
        try:
            job_manager.validate_job_id(job_id)
            job_manager.validate_job_id(uploadId)
            cfg = cfg_fn()

            def _preflight() -> tuple[Path, Path, int, int, int]:
                jdir = job_manager.require_job_dir(job_id)
                if job_manager.is_patch_active(job_id):
                    raise JobConflictError("Aktif bir işlem sürerken OBB parçası yüklenemez.")
                session_file = jdir / ".obb_uploads" / f"{uploadId}.json"
                meta = _read_json_dict(session_file)
                if meta is None:
                    raise JobNotFoundError("OBB yükleme oturumu bulunamadı.")
                tot_chunks = int(meta.get("totalChunks") or 0)
                tot_size = int(meta.get("totalSize") or 0)
                c_bytes = int(meta.get("chunkSizeBytes") or cfg.chunk_size_bytes)
                if totalChunks is not None and int(totalChunks) != tot_chunks:
                    raise HTTPException(status_code=400, detail="totalChunks oturum bilgisiyle uyuşmuyor.")
                if tot_chunks <= 0 or chunkIndex < 0 or chunkIndex >= tot_chunks:
                    raise HTTPException(status_code=400, detail="Geçersiz parça indeksi (chunkIndex).")
                return jdir, session_file, tot_chunks, tot_size, c_bytes

            async with _hold_active_async(job_manager, job_id):
                jdir, session_file, tot_chunks, tot_size, chunk_size_bytes = await asyncio.to_thread(_preflight)
                expected_size = min(chunk_size_bytes, tot_size - chunkIndex * chunk_size_bytes)
                temp_path = jdir / ".obb_uploads" / f".{uploadId}_{chunkIndex}_{uuid.uuid4().hex[:8]}.tmp"

                written = await _stream_upload_to_file(
                    chunk,
                    temp_path,
                    max_bytes=expected_size,
                    exact_expected=expected_size,
                    label="OBB parçası",
                )
                if written == 0:
                    raise HTTPException(status_code=400, detail="Boş (0 bayt) parça yüklenemez.")
                if written != expected_size:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Eksik OBB parçası: {written}/{expected_size} bayt alındı.",
                    )

                def _commit() -> dict[str, Any]:
                    assert temp_path is not None
                    with job_manager.get_upload_lock(job_id):
                        meta = _read_json_dict(session_file)
                        if meta is None:
                            raise JobNotFoundError("OBB yükleme oturumu bulunamadı.")
                        received = {int(c) for c in (meta.get("receivedChunks") or [])}
                        if chunkIndex in received:
                            job_manager.touch_activity(job_id)
                            return {
                                "ok": True,
                                "jobId": job_id,
                                "uploadId": uploadId,
                                "chunkIndex": chunkIndex,
                                "receivedCount": len(received),
                                "totalChunks": tot_chunks,
                                "receivedBytes": int(meta.get("receivedBytes") or 0),
                                "duplicate": True,
                            }

                        part_target = jdir / ".obb_uploads" / f"{uploadId}.part"
                        open_mode = "r+b" if part_target.exists() else "wb"
                        with part_target.open(open_mode) as out_fp, temp_path.open("rb") as part_fp:
                            out_fp.seek(chunkIndex * chunk_size_bytes)
                            shutil.copyfileobj(part_fp, out_fp, _STREAM_BUF_SIZE)
                            out_fp.flush()
                            os.fsync(out_fp.fileno())

                        received.add(chunkIndex)
                        meta["receivedChunks"] = sorted(received)
                        meta["receivedBytes"] = sum(
                            min(chunk_size_bytes, tot_size - idx * chunk_size_bytes) for idx in received
                        )
                        meta["updatedAt"] = time.time()
                        write_json_atomic(session_file, meta)
                        job_manager.touch_activity(job_id)
                        return {
                            "ok": True,
                            "jobId": job_id,
                            "uploadId": uploadId,
                            "chunkIndex": chunkIndex,
                            "receivedCount": len(received),
                            "totalChunks": tot_chunks,
                            "receivedBytes": int(meta["receivedBytes"]),
                            "duplicate": False,
                        }

                return await asyncio.to_thread(_commit)
        finally:
            if temp_path is not None:
                await asyncio.to_thread(temp_path.unlink, True)
            with contextlib.suppress(Exception):
                await chunk.close()

    @application.post("/api/attach-obb/{job_id}/finish")
    async def api_attach_obb_finish(
        job_id: str,
        uploadId: str = Form(...),
    ) -> dict[str, Any]:
        job_manager.validate_job_id(job_id)
        job_manager.validate_job_id(uploadId)
        cfg = cfg_fn()

        def _finish_obb_sync() -> dict[str, Any]:
            jdir = job_manager.require_job_dir(job_id)
            with job_manager.get_upload_lock(job_id), job_manager.get_job_lock(job_id):
                if job_manager.is_patch_active(job_id):
                    raise JobConflictError("Aktif bir işlem sürerken OBB tamamlanamaz.")
                sessions_dir = jdir / ".obb_uploads"
                session_file = sessions_dir / f"{uploadId}.json"
                part_target = sessions_dir / f"{uploadId}.part"
                meta = _read_json_dict(session_file)
                if meta is None:
                    raise JobNotFoundError("OBB yükleme oturumu bulunamadı.")

                total_chunks = int(meta.get("totalChunks") or 0)
                total_size = int(meta.get("totalSize") or 0)
                received = {int(c) for c in (meta.get("receivedChunks") or [])}
                if total_chunks <= 0 or len(received) != total_chunks or any(
                    i not in received for i in range(total_chunks)
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=f"OBB dosyası eksik yüklendi: {len(received)}/{total_chunks} parça alındı.",
                    )
                if not part_target.is_file() or part_target.stat().st_size != total_size:
                    raise HTTPException(status_code=400, detail="OBB dosya boyutu uyuşmuyor.")

                package_id, version_code = _get_job_pkg_and_ver(jdir)
                norm_rel = normalize_obb_relpath(str(meta.get("normalizedPath") or ""), package_id)
                replace_existing = bool(meta.get("replaceExisting", False))

                target_dir = jdir / "extra_obb"
                target_root = target_dir.resolve()
                dest = (target_root / norm_rel).resolve()
                if not dest.is_relative_to(target_root) or dest == target_root:
                    raise InvalidArchiveError("OBB dosya yolu güvenli değil.")

                existing_records = [] if replace_existing else (_read_json_list(jdir / "extra_obb_meta.json") or [])
                kept_records = [
                    rec
                    for rec in existing_records
                    if str(rec.get("normalizedPath") or "").lower() != norm_rel.lower()
                ]
                if not replace_existing:
                    _check_obb_path_collision(
                        norm_rel,
                        [str(rec.get("normalizedPath") or "") for rec in kept_records],
                    )

                projected_total = sum(int(rec.get("sizeBytes") or 0) for rec in kept_records) + total_size
                if projected_total > cfg.max_upload_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Toplam OBB boyutu {cfg.MAX_UPLOAD_MB} MB sınırını aşıyor.",
                    )

                if replace_existing and target_dir.exists():
                    shutil.rmtree(target_dir, ignore_errors=True)
                target_dir.mkdir(parents=True, exist_ok=True)
                target_root = target_dir.resolve()
                dest = (target_root / norm_rel).resolve()
                if not dest.is_relative_to(target_root) or dest == target_root:
                    raise InvalidArchiveError("OBB dosya yolu güvenli değil.")

                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(part_target, dest)
                except (FileExistsError, IsADirectoryError, NotADirectoryError) as exc:
                    raise InvalidArchiveError(f"OBB dosya/klasör yolu çakışması: {norm_rel}") from exc
                with contextlib.suppress(OSError):
                    os.chmod(dest, 0o644)

                val = validate_obb_filename(norm_rel, package_id, version_code)
                kept_records.append(
                    {
                        "filePath": str(dest),
                        "normalizedPath": norm_rel,
                        "name": Path(norm_rel).name,
                        "sizeBytes": total_size,
                        "validObbName": bool(val.get("valid")),
                        "warning": val.get("warning"),
                        "suggestedName": val.get("suggestedName"),
                    }
                )
                write_json_atomic(jdir / "extra_obb_meta.json", kept_records)
                session_file.unlink(missing_ok=True)
                with contextlib.suppress(OSError):
                    sessions_dir.rmdir()
                if not sessions_dir.exists():
                    job_manager.pop_upload_lock(job_id)
                job_manager.touch_activity(job_id)

                public_files = _public_obb_list(kept_records)
                total_bytes = sum(int(r.get("sizeBytes") or 0) for r in kept_records)
                return {
                    "ok": True,
                    "jobId": job_id,
                    "count": len(public_files),
                    "totalSizeBytes": total_bytes,
                    "sizeBytes": total_bytes,
                    "files": public_files,
                }

        async with _hold_active_async(job_manager, job_id):
            return await asyncio.to_thread(_finish_obb_sync)

    # ------------------------------------------------------------------ F08: Full XAPK v2 Build & Status
    @application.post("/api/full-xapk/{job_id}")
    async def api_full_xapk(
        job_id: str,
        background: bool = Form(False),
    ) -> dict[str, Any]:
        job_manager.validate_job_id(job_id)
        cfg = cfg_fn()
        jdir = await asyncio.to_thread(job_manager.require_job_dir, job_id)

        job_manager.reserve_patch_slot(job_id)

        def _prepare() -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, Any]] | None, dict[str, Any]]:
            with job_manager.get_job_lock(job_id):
                state = job_manager.get_job_state(job_id) or {}
                patch_res: dict[str, Any] | None = None
                if state.get("status") == "done" and isinstance(state.get("result"), dict):
                    patch_res = dict(state["result"])
                if patch_res is None:
                    patch_res = _read_json_dict(jdir / "patch_result.json")
                if patch_res is None:
                    raise JobConflictError("Önce APK yamalama ve imzalama işlemi tamamlanmalıdır.")
                if patch_res.get("verified") is not True:
                    raise HTTPException(
                        status_code=400,
                        detail="Tam XAPK için APK'nın apksigner ile imzalanıp doğrulanması gerekir.",
                    )

                cm = _read_json_dict(jdir / "container_meta.json")
                extra_obb = _read_json_list(jdir / "extra_obb_meta.json")
                upload_meta = _read_json_dict(jdir / "upload_meta.json") or {}
                apk_info = upload_meta.get("apkInfo") if isinstance(upload_meta.get("apkInfo"), dict) else {}

                has_container_obb = bool(cm and cm.get("obbFiles"))
                has_extra_obb = bool(extra_obb) or (
                    (jdir / "extra_obb").is_dir() and any((jdir / "extra_obb").rglob("*.obb"))
                )
                if not has_container_obb and not has_extra_obb:
                    raise HTTPException(
                        status_code=400,
                        detail="Bu APK işi için OBB bulunamadı. Önce OBB ekleyin veya OBB içeren bir XAPK yükleyin.",
                    )

                # Merge pre-patch metadata with post-patch result taking precedence (e.g. targetSdk)
                merged_info: dict[str, Any] = dict(apk_info)
                for key, value in patch_res.items():
                    if value is not None and value != "":
                        merged_info[key] = value
                post_insp = patch_res.get("inspector") if isinstance(patch_res.get("inspector"), dict) else {}
                pre_insp = apk_info.get("inspector") if isinstance(apk_info.get("inspector"), dict) else {}
                merged_insp = dict(pre_insp)
                merged_insp.update(post_insp)
                if not merged_insp.get("permissions") and pre_insp.get("permissions"):
                    merged_insp["permissions"] = list(pre_insp["permissions"])
                if merged_insp:
                    merged_info["inspector"] = merged_insp

                return patch_res, cm, extra_obb, merged_info

        patch_res, container_meta, extra_obb_meta, merged_apk_info = await _start_reserved_operation(
            job_manager,
            job_id,
            "fullXapk",
            "Tam XAPK hazırlanıyor",
            _prepare,
        )

        def _runner(
            cancel_event: threading.Event,
            _on_proc: Callable[[Any], None],
            _append_log: Callable[[str], None],
            progress_cb: Callable[[int, str], None],
        ) -> dict[str, Any]:
            with log_job_context(job_id):
                res = build_full_xapk(
                    job_dir=jdir,
                    patch_result=patch_res,
                    container_meta=container_meta,
                    extra_obb_meta=extra_obb_meta,
                    progress_cb=progress_cb,
                    cancel_event=cancel_event,
                    apk_info=merged_apk_info,
                    max_bytes=cfg.MAX_DECOMPRESSED_BYTES,
                )
                res["serverTime"] = time.time()
                return res

        if background:
            try:
                worker = threading.Thread(
                    target=job_manager.execute_operation,
                    args=(job_id, "fullXapk", _runner),
                    kwargs={"reraise": False},
                    daemon=True,
                    name=f"xapk-{job_id}",
                )
                worker.start()
            except BaseException:
                bg_lock = threading.Lock()
                bg_cleaned = False

                def _fail_and_release() -> None:
                    nonlocal bg_cleaned
                    with bg_lock:
                        if bg_cleaned:
                            return
                        bg_cleaned = True
                    job_manager.fail_operation(job_id, "Arka plan XAPK iş parçacığı başlatılamadı.", "fullXapk")
                    job_manager.release_patch_slot(job_id)

                await _run_cleanup_shielded(_fail_and_release)
                raise
            return {
                "jobId": job_id,
                "status": "running",
                "progress": 0,
                "stage": "Tam XAPK hazırlanıyor",
                "pollUrl": f"/api/full-xapk-status/{job_id}",
                "pollIntervalMs": 1000,
                "serverTime": time.time(),
            }

        return await _execute_sync_reserved_operation(job_manager, job_id, "fullXapk", _runner)

    @application.get("/api/full-xapk-status/{job_id}")
    async def api_full_xapk_status(job_id: str) -> dict[str, Any]:
        job_manager.validate_job_id(job_id)

        def _read() -> dict[str, Any]:
            state = job_manager.require_job_state(job_id)
            full = state.get("fullXapk")
            if not isinstance(full, dict):
                raise JobNotFoundError("Tam XAPK işlemi henüz başlatılmadı.")
            return {
                "jobId": job_id,
                "status": full.get("status"),
                "progress": full.get("progress", 0),
                "stage": full.get("stage", ""),
                "result": full.get("result"),
                "error": full.get("error"),
                "updatedAt": full.get("updatedAt"),
                "finishedAt": full.get("finishedAt"),
                "serverTime": time.time(),
                "expiresInSeconds": job_manager.expires_in(job_id),
            }

        return await asyncio.to_thread(_read)

    # ------------------------------------------------------------------ F08 & F10: Strict Downloads
    @application.get("/api/download-full-xapk/{job_id}")
    async def api_download_full_xapk(job_id: str) -> FileResponse:
        job_manager.validate_job_id(job_id)
        guard = _DownloadCleanupGuard(job_manager, job_id)

        def _resolve() -> Path | None:
            jdir = job_manager.require_job_dir(job_id)
            state = job_manager.get_job_state(job_id) or {}
            full = state.get("fullXapk")
            full_res = full.get("result") if isinstance(full, dict) else None
            file_name = full_res.get("fileName") if isinstance(full_res, dict) else None
            if not isinstance(file_name, str) or not file_name.strip():
                raise HTTPException(
                    status_code=404,
                    detail="Tam XAPK bulunamadı. Önce XAPK oluşturma işlemini başlatın.",
                )
            if "/" in file_name or "\\" in file_name or "\x00" in file_name or Path(file_name).name != file_name:
                raise HTTPException(status_code=403, detail="Geçersiz çıktı dosya adı.")
            raw_target = jdir / file_name
            if raw_target.is_symlink():
                raise HTTPException(status_code=403, detail="Sembolik bağlantılar indirilemez.")
            jdir_resolved = jdir.resolve()
            target = raw_target.resolve()
            if target.parent != jdir_resolved or target.name != file_name or not target.is_file():
                raise HTTPException(status_code=404, detail="Tam XAPK dosyası bulunamadı veya süresi doldu.")
            if not guard.acquire_in_worker():
                return None
            if not guard.commit_handoff():
                return None
            return target

        try:
            target = await asyncio.to_thread(_resolve)
            if target is None:
                raise asyncio.CancelledError
            return _ManagedFileResponse(
                path=target,
                filename=target.name,
                media_type="application/octet-stream",
                cleanup_fn=guard.cleanup_once,
            )
        except BaseException:
            if guard.abort_from_caller():
                await _run_cleanup_shielded(guard.cleanup_once)
            raise

    @application.get("/api/download/{job_id}/{filename}")
    async def api_download(job_id: str, filename: str) -> FileResponse:
        job_manager.validate_job_id(job_id)
        if not filename or "/" in filename or "\\" in filename or "\x00" in filename or filename in (".", ".."):
            raise HTTPException(status_code=400, detail="Geçersiz dosya adı.")
        guard = _DownloadCleanupGuard(job_manager, job_id)

        def _resolve() -> Path | None:
            jdir = job_manager.require_job_dir(job_id)
            allowlist = _collect_download_allowlist(jdir, job_manager, job_id)
            if filename not in allowlist:
                raise HTTPException(
                    status_code=403,
                    detail="Bu dosya indirme için izinli çıktı listesinde değil.",
                )
            raw_target = jdir / filename
            if raw_target.is_symlink():
                raise HTTPException(status_code=403, detail="Sembolik bağlantılar indirilemez.")
            jdir_resolved = jdir.resolve()
            target = raw_target.resolve()
            if target.parent != jdir_resolved or target.name != filename or not target.is_file():
                raise HTTPException(status_code=404, detail="İmzalı dosya bulunamadı veya süresi doldu.")
            if not guard.acquire_in_worker():
                return None
            if not guard.commit_handoff():
                return None
            return target

        try:
            target = await asyncio.to_thread(_resolve)
            if target is None:
                raise asyncio.CancelledError
            media = (
                "application/vnd.android.package-archive"
                if target.suffix.lower() == ".apk"
                else "application/octet-stream"
            )
            return _ManagedFileResponse(
                path=target,
                filename=target.name,
                media_type=media,
                cleanup_fn=guard.cleanup_once,
            )
        except BaseException:
            if guard.abort_from_caller():
                await _run_cleanup_shielded(guard.cleanup_once)
            raise

    @application.get("/api/download-obb/{job_id}/{obb_index}")
    async def api_download_obb(job_id: str, obb_index: int) -> FileResponse:
        job_manager.validate_job_id(job_id)
        if obb_index < 0:
            raise HTTPException(status_code=400, detail="OBB indeksi negatif olamaz.")
        cfg = cfg_fn()
        guard = _DownloadCleanupGuard(job_manager, job_id)

        def _prepare_obb() -> tuple[Path, str] | None:
            jdir = job_manager.require_job_dir(job_id)
            cm = _read_json_dict(jdir / "container_meta.json")
            container_obbs = list(cm.get("obbFiles") or []) if isinstance(cm, dict) else []
            extra_obbs = _read_json_list(jdir / "extra_obb_meta.json") or []

            if obb_index < len(container_obbs):
                if not guard.acquire_in_worker():
                    return None
                try:
                    assert cm is not None
                    unique_path, safe_name = _extract_unique_container_obb(
                        jdir,
                        cm,
                        obb_index,
                        cfg.MAX_DECOMPRESSED_BYTES,
                    )
                    guard.set_temp_path(unique_path)
                except BaseException:
                    guard.abort_in_worker()
                    raise
                if not guard.commit_handoff():
                    return None
                return unique_path, safe_name

            extra_idx = obb_index - len(container_obbs)
            if 0 <= extra_idx < len(extra_obbs):
                rec = extra_obbs[extra_idx]
                extra_dir = jdir / "extra_obb"
                if extra_dir.is_symlink():
                    raise HTTPException(status_code=403, detail="Sembolik bağlantılar indirilemez.")
                extra_root = extra_dir.resolve()
                norm_rel = str(rec.get("normalizedPath") or "").strip()
                raw_path_str = rec.get("filePath") or rec.get("path")
                if norm_rel:
                    norm_clean = norm_rel.replace("\\", "/")
                    norm_parts = Path(norm_clean).parts
                    if norm_clean.startswith("/") or ".." in norm_parts or "\x00" in norm_clean:
                        raise HTTPException(status_code=403, detail="Ek OBB dosya yolu güvenli değil.")
                    raw_cand = extra_root / norm_clean
                    if _path_has_symlink_within(extra_root, raw_cand):
                        raise HTTPException(status_code=403, detail="Sembolik bağlantılar indirilemez.")
                elif raw_path_str:
                    raw_cand = Path(str(raw_path_str))
                    if raw_cand.is_symlink():
                        raise HTTPException(status_code=403, detail="Sembolik bağlantılar indirilemez.")
                    if raw_cand.is_relative_to(extra_root) and _path_has_symlink_within(extra_root, raw_cand):
                        raise HTTPException(status_code=403, detail="Sembolik bağlantılar indirilemez.")
                else:
                    raise HTTPException(status_code=404, detail="Ek OBB dosyası bulunamadı.")

                try:
                    resolved = raw_cand.resolve()
                except OSError as exc:
                    raise HTTPException(status_code=404, detail="Ek OBB dosyası bulunamadı.") from exc
                if not resolved.is_relative_to(extra_root) or not resolved.is_file():
                    raise HTTPException(status_code=404, detail="Ek OBB dosyası bulunamadı.")
                safe_name = sanitize_filename(str(rec.get("name") or resolved.name), default="main.obb")
                if not guard.acquire_in_worker():
                    return None
                if not guard.commit_handoff():
                    return None
                return resolved, safe_name

            raise HTTPException(status_code=404, detail="OBB kaydı bulunamadı.")

        try:
            prepared = await asyncio.to_thread(_prepare_obb)
            if prepared is None:
                raise asyncio.CancelledError
            file_path, download_name = prepared
            return _ManagedFileResponse(
                path=file_path,
                filename=download_name,
                media_type="application/octet-stream",
                cleanup_fn=guard.cleanup_once,
            )
        except BaseException:
            if guard.abort_from_caller():
                await _run_cleanup_shielded(guard.cleanup_once)
            raise

    return application


app = create_app()
