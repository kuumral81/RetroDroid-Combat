"""Framework-free job registry, persistent state, cancellation and janitor for RetroDroid Compat v5.4.0.

This module deliberately depends only on the standard library and ``retrodroid.config`` so the
HTTP layer (``server.py``) stays a thin composition root. All methods are synchronous and
thread-safe; callers on the asyncio event loop must invoke the blocking ones through
``asyncio.to_thread``.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from retrodroid.config import (
    CommandCanceledError,
    RetroDroidError,
    Settings,
    get_logger,
    get_settings,
    is_valid_job_id,
    write_json_atomic,
)

__all__ = [
    "ACTIVE_STATUSES",
    "ConcurrencyLimitError",
    "InvalidJobIdError",
    "JobConflictError",
    "JobManager",
    "JobNotFoundError",
]

ACTIVE_STATUSES = frozenset({"queued", "running", "processing"})
STATE_FILE = "job_state.json"
ACTIVITY_FILE = ".last_activity"
MAX_LOG_LINES = 1000
INTERRUPTED_STAGE = "Sunucu yeniden başlatıldığı için kesildi"
INTERRUPTED_ERROR = "İşlem sunucu yeniden başlatıldığı için kesintiye uğradı."
CANCELED_ERROR = "İşlem iptal edildi."
INTERNAL_ERROR = "Sunucu iç hatası."

_log = get_logger("retrodroid.jobs")


class InvalidJobIdError(RetroDroidError):
    """Raised when a job id does not match ``^[0-9a-f]{12}$``."""

    def __init__(self, detail: str = "Geçersiz iş kimliği.", *, status_code: int = 400) -> None:
        super().__init__(detail, status_code=status_code)


class JobNotFoundError(RetroDroidError):
    """Raised when a job does not exist (memory or disk)."""

    def __init__(self, detail: str = "İş bulunamadı.", *, status_code: int = 404) -> None:
        super().__init__(detail, status_code=status_code)


class JobConflictError(RetroDroidError):
    """Raised when the requested operation conflicts with the job's current activity."""

    def __init__(self, detail: str = "İş şu anda meşgul.", *, status_code: int = 409) -> None:
        super().__init__(detail, status_code=status_code)


class ConcurrencyLimitError(RetroDroidError):
    """Raised when all heavy patch slots are in use."""

    def __init__(self, detail: str = "Tüm işlem yuvaları dolu.", *, status_code: int = 429) -> None:
        super().__init__(detail, status_code=status_code)


def _read_json_dict(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _signal_process_tree(proc: subprocess.Popen[Any], sig: int = signal.SIGTERM) -> None:
    """Send ``sig`` to the child's process group (never our own group), falling back to terminate()."""
    if proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        if pgid != os.getpgrp():
            os.killpg(pgid, sig)
            return
    except (ProcessLookupError, PermissionError, OSError):
        pass
    with contextlib.suppress(OSError):
        proc.terminate()


def _blank_section(status: str = "idle") -> dict[str, Any]:
    return {
        "status": status,
        "progress": 0,
        "stage": "",
        "logs": [],
        "result": None,
        "error": None,
        "startedAt": None,
        "finishedAt": None,
        "updatedAt": time.time(),
    }


class JobManager:
    """Thread-safe registry of job state, locks, active references, cancellation and TTL janitor."""

    def __init__(self, settings_getter: Callable[[], Settings] = get_settings) -> None:
        self._get_settings = settings_getter
        self._lock = threading.RLock()
        self._active_refs: dict[str, int] = {}
        self._patch_slots: set[str] = set()
        self._job_locks: dict[str, threading.RLock] = {}
        self._upload_locks: dict[str, threading.Lock] = {}
        self._persist_locks: dict[str, threading.Lock] = {}
        self._jobs: dict[tuple[Path, str], dict[str, Any]] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._running_procs: dict[str, set[subprocess.Popen[Any]]] = {}

    # ------------------------------------------------------------------ paths / ids
    def settings(self) -> Settings:
        return self._get_settings()

    def work_dir(self) -> Path:
        return Path(self.settings().WORK_DIR)

    @staticmethod
    def new_job_id() -> str:
        return uuid.uuid4().hex[:12]

    @staticmethod
    def validate_job_id(job_id: Any) -> str:
        if not isinstance(job_id, str) or not is_valid_job_id(job_id):
            raise InvalidJobIdError()
        return job_id

    def job_dir(self, job_id: str) -> Path:
        self.validate_job_id(job_id)
        return self.work_dir() / job_id

    def job_exists(self, job_id: str) -> bool:
        return self.job_dir(job_id).is_dir()

    def require_job_dir(self, job_id: str) -> Path:
        jdir = self.job_dir(job_id)
        if not jdir.is_dir():
            raise JobNotFoundError()
        return jdir

    def _key(self, job_id: str) -> tuple[Path, str]:
        return (self.work_dir().resolve(), job_id)

    # ------------------------------------------------------------------ locks & activity refs
    def acquire_active(self, job_id: str) -> None:
        """Increment the active reference count for ``job_id`` and update activity heartbeat."""
        self.validate_job_id(job_id)
        with self._lock:
            self._active_refs[job_id] = self._active_refs.get(job_id, 0) + 1
        self.touch_activity(job_id)

    def release_active(self, job_id: str) -> None:
        """Decrement the active reference count for ``job_id`` and update activity heartbeat."""
        with self._lock:
            left = self._active_refs.get(job_id, 0) - 1
            if left > 0:
                self._active_refs[job_id] = left
            else:
                self._active_refs.pop(job_id, None)
        self.touch_activity(job_id)

    @contextlib.contextmanager
    def hold_active(self, job_id: str) -> Iterator[None]:
        """Reference-counted guard that keeps the janitor and delete away from a job."""
        self.acquire_active(job_id)
        try:
            yield
        finally:
            self.release_active(job_id)

    def active_refs(self, job_id: str) -> int:
        with self._lock:
            return self._active_refs.get(job_id, 0)

    def is_busy(self, job_id: str) -> bool:
        with self._lock:
            return self._active_refs.get(job_id, 0) > 0 or job_id in self._patch_slots

    def get_job_lock(self, job_id: str) -> threading.RLock:
        self.validate_job_id(job_id)
        with self._lock:
            return self._job_locks.setdefault(job_id, threading.RLock())

    def get_upload_lock(self, job_id: str) -> threading.Lock:
        self.validate_job_id(job_id)
        with self._lock:
            return self._upload_locks.setdefault(job_id, threading.Lock())

    def pop_upload_lock(self, job_id: str) -> None:
        with self._lock:
            self._upload_locks.pop(job_id, None)

    def lock_counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "jobLocks": len(self._job_locks),
                "uploadLocks": len(self._upload_locks),
                "activeRefs": len(self._active_refs),
                "patchSlots": len(self._patch_slots),
                "cancelEvents": len(self._cancel_events),
                "cachedJobs": len(self._jobs),
            }

    # ------------------------------------------------------------------ patch slots
    def reserve_patch_slot(self, job_id: str) -> None:
        """Reserve a heavy operation slot (patch / full XAPK); 409 same job, 429 pool full."""
        self.validate_job_id(job_id)
        cfg = self.settings()
        with self._lock:
            if job_id in self._patch_slots:
                raise JobConflictError("Bu iş için bir işlem zaten çalışıyor.")
            if len(self._patch_slots) >= max(1, int(cfg.MAX_CONCURRENT_PATCHES)):
                raise ConcurrencyLimitError("Sunucu şu anda başka bir yamalama işlemi yürütüyor; lütfen bekleyin.")
            self._patch_slots.add(job_id)
            self._active_refs[job_id] = self._active_refs.get(job_id, 0) + 1
            self._cancel_events[job_id] = threading.Event()
            self._running_procs[job_id] = set()

    def release_patch_slot(self, job_id: str) -> None:
        with self._lock:
            if job_id not in self._patch_slots:
                return
            self._patch_slots.discard(job_id)
            left = self._active_refs.get(job_id, 0) - 1
            if left > 0:
                self._active_refs[job_id] = left
            else:
                self._active_refs.pop(job_id, None)
            self._cancel_events.pop(job_id, None)
            self._running_procs.pop(job_id, None)
        self.touch_activity(job_id)

    def is_patch_active(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._patch_slots

    @property
    def active_patch_count(self) -> int:
        with self._lock:
            return len(self._patch_slots)

    # ------------------------------------------------------------------ cancellation
    def begin_cancellable_op(
        self, job_id: str
    ) -> tuple[threading.Event, Callable[[subprocess.Popen[Any]], None]]:
        with self._lock:
            ev = self._cancel_events.setdefault(job_id, threading.Event())
            self._running_procs.setdefault(job_id, set())

        def on_proc(proc: subprocess.Popen[Any]) -> None:
            with self._lock:
                procs = self._running_procs.setdefault(job_id, set())
                for old in [p for p in procs if p.poll() is not None]:
                    procs.discard(old)
                canceled = ev.is_set()
                if not canceled:
                    procs.add(proc)
            if canceled:
                _signal_process_tree(proc, signal.SIGTERM)

        return ev, on_proc

    def end_cancellable_op(self, job_id: str) -> None:
        with self._lock:
            self._cancel_events.pop(job_id, None)
            self._running_procs.pop(job_id, None)

    def request_cancel(self, job_id: str) -> dict[str, Any]:
        self.validate_job_id(job_id)
        with self._lock:
            state, _ = self._load_state_locked(job_id)
            if state is None:
                raise JobNotFoundError()
            ev = self._cancel_events.get(job_id)
            section_name: str | None = None
            if state.get("status") in ACTIVE_STATUSES:
                section_name = "patch"
            else:
                full = state.get("fullXapk")
                if isinstance(full, dict) and full.get("status") in ACTIVE_STATUSES:
                    section_name = "fullXapk"
            if ev is None or section_name is None or job_id not in self._patch_slots:
                raise JobConflictError("İptal edilebilecek aktif bir işlem yok.")
            ev.set()
            now = time.time()
            sec = self._section(state, section_name)
            sec["status"] = "canceled"
            sec["stage"] = "İptal ediliyor"
            sec["updatedAt"] = now
            state["updatedAt"] = now
            procs = list(self._running_procs.get(job_id, ()))
        for proc in procs:
            _signal_process_tree(proc, signal.SIGTERM)
        self._persist_snapshot(job_id)
        return {"ok": True, "jobId": job_id, "status": "canceled"}

    # ------------------------------------------------------------------ activity heartbeat
    def touch_activity(self, job_id: str) -> float:
        now = time.time()
        if not is_valid_job_id(job_id):
            return now
        try:
            jdir = self.work_dir() / job_id
            if jdir.is_dir():
                (jdir / ACTIVITY_FILE).touch(exist_ok=True)
        except OSError:
            pass
        return now

    @staticmethod
    def get_last_activity(job_dir: Path) -> float:
        latest = 0.0
        for name in (
            ACTIVITY_FILE,
            STATE_FILE,
            "upload_meta.json",
            "patch_result.json",
            "container_meta.json",
            "extra_obb_meta.json",
        ):
            try:
                latest = max(latest, (job_dir / name).stat().st_mtime)
            except OSError:
                continue
        try:
            latest = max(latest, job_dir.stat().st_mtime)
        except OSError:
            pass
        return latest

    def expires_in(self, job_id: str) -> int:
        cfg = self.settings()
        ttl = int(cfg.JOB_TTL_SECONDS)
        jdir = self.work_dir() / job_id
        if self.is_busy(job_id):
            return ttl
        last = self.get_last_activity(jdir)
        return min(ttl, max(0, int(ttl - (time.time() - last))))

    # ------------------------------------------------------------------ state persistence
    @staticmethod
    def _section(state: dict[str, Any], section: str) -> dict[str, Any]:
        if section == "patch":
            return state
        sec = state.get("fullXapk")
        if not isinstance(sec, dict):
            sec = _blank_section()
            state["fullXapk"] = sec
        return sec

    def _synthesize_state(self, job_dir: Path, job_id: str) -> dict[str, Any] | None:
        if not job_dir.is_dir():
            return None
        try:
            created = job_dir.stat().st_mtime
        except OSError:
            created = time.time()
        patch_result = _read_json_dict(job_dir / "patch_result.json")
        upload_meta = _read_json_dict(job_dir / "upload_meta.json")
        if patch_result is not None:
            status, progress, stage, result = "done", 100, "Tamamlandı", patch_result
        elif upload_meta is not None and upload_meta.get("complete"):
            status, progress, stage, result = "analyzed", 0, "Analiz edildi", None
        else:
            status, progress, stage, result = "uploading", 0, "Yükleniyor", None
        return {
            "jobId": job_id,
            "status": status,
            "progress": progress,
            "stage": stage,
            "logs": [],
            "result": result,
            "error": None,
            "createdAt": created,
            "updatedAt": created,
            "finishedAt": created if status == "done" else None,
        }

    @staticmethod
    def _mark_stale_active_interrupted(state: dict[str, Any], now: float) -> bool:
        changed = False
        if state.get("status") in ACTIVE_STATUSES:
            state.update(
                status="interrupted",
                stage=INTERRUPTED_STAGE,
                error=INTERRUPTED_ERROR,
                finishedAt=now,
                updatedAt=now,
            )
            changed = True
        full = state.get("fullXapk")
        if isinstance(full, dict) and full.get("status") in ACTIVE_STATUSES:
            full.update(
                status="interrupted",
                stage=INTERRUPTED_STAGE,
                error=INTERRUPTED_ERROR,
                finishedAt=now,
                updatedAt=now,
            )
            state["updatedAt"] = now
            changed = True
        return changed

    def _load_state_locked(self, job_id: str) -> tuple[dict[str, Any] | None, bool]:
        key = self._key(job_id)
        state = self._jobs.get(key)
        if state is not None:
            if (key[0] / job_id).is_dir():
                return state, False
            self._jobs.pop(key, None)
            return None, False
        jdir = key[0] / job_id
        if not jdir.is_dir():
            return None, False
        state = _read_json_dict(jdir / STATE_FILE)
        if state is None or state.get("jobId") != job_id:
            state = self._synthesize_state(jdir, job_id)
        if state is None:
            return None, False
        recovered = False
        if job_id not in self._patch_slots:
            recovered = self._mark_stale_active_interrupted(state, time.time())
        self._jobs[key] = state
        return state, recovered

    def _persist_snapshot(self, job_id: str) -> None:
        """Atomically persist the latest state for ``job_id`` without holding ``self._lock``."""
        with self._lock:
            plock = self._persist_locks.setdefault(job_id, threading.Lock())
        with plock:
            with self._lock:
                state = self._jobs.get(self._key(job_id))
                if state is None:
                    return
                snapshot = copy.deepcopy(state)
                jdir = self.work_dir() / job_id
            if not jdir.is_dir():
                return
            try:
                write_json_atomic(jdir / STATE_FILE, snapshot)
                (jdir / ACTIVITY_FILE).touch(exist_ok=True)
            except OSError as exc:
                _log.warning("job_state yazılamadı: %s", exc, extra={"jobId": job_id})

    def create_state(self, job_id: str, status: str = "analyzed", **extra: Any) -> dict[str, Any]:
        """Create (or reset) the persistent state record for an existing job directory."""
        self.validate_job_id(job_id)
        now = time.time()
        with self._lock:
            state: dict[str, Any] = {
                "jobId": job_id,
                "status": status,
                "progress": 0,
                "stage": "",
                "logs": [],
                "result": None,
                "error": None,
                "createdAt": now,
                "updatedAt": now,
                "finishedAt": None,
            }
            existing, _ = self._load_state_locked(job_id)
            if existing is not None and isinstance(existing.get("createdAt"), (int, float)):
                state["createdAt"] = existing["createdAt"]
            state.update(extra)
            self._jobs[self._key(job_id)] = state
            snapshot = copy.deepcopy(state)
        self._persist_snapshot(job_id)
        return snapshot

    def mutate(self, job_id: str, fn: Callable[[dict[str, Any]], None], *, persist: bool = True) -> dict[str, Any]:
        self.validate_job_id(job_id)
        with self._lock:
            state, recovered = self._load_state_locked(job_id)
            if state is None:
                raise JobNotFoundError()
            fn(state)
            state["updatedAt"] = time.time()
            snapshot = copy.deepcopy(state)
        if persist or recovered:
            self._persist_snapshot(job_id)
        return snapshot

    def set_status(self, job_id: str, status: str, stage: str = "", **extra: Any) -> dict[str, Any]:
        def _apply(state: dict[str, Any]) -> None:
            state["status"] = status
            state["stage"] = stage
            state.update(extra)

        return self.mutate(job_id, _apply)

    def get_job_state(self, job_id: str) -> dict[str, Any] | None:
        self.validate_job_id(job_id)
        with self._lock:
            state, recovered = self._load_state_locked(job_id)
            snapshot = copy.deepcopy(state) if state is not None else None
        if recovered:
            self._persist_snapshot(job_id)
        return snapshot

    def require_job_state(self, job_id: str) -> dict[str, Any]:
        state = self.get_job_state(job_id)
        if state is None:
            raise JobNotFoundError()
        return state

    # ------------------------------------------------------------------ operation lifecycle
    def start_operation(self, job_id: str, section: str = "patch", stage: str = "Kuyruğa alındı") -> dict[str, Any]:
        now = time.time()

        def _apply(state: dict[str, Any]) -> None:
            sec = self._section(state, section)
            if section == "patch":
                state["fullXapk"] = None
            sec.update(
                status="running",
                progress=0,
                stage=stage,
                logs=[],
                result=None,
                error=None,
                startedAt=now,
                finishedAt=None,
            )

        return self.mutate(job_id, _apply)

    def append_log(self, job_id: str, line: str, section: str = "patch") -> None:
        text = str(line)

        def _apply(state: dict[str, Any]) -> None:
            sec = self._section(state, section)
            logs = sec.setdefault("logs", [])
            logs.append(text)
            if len(logs) > MAX_LOG_LINES:
                del logs[: len(logs) - MAX_LOG_LINES]

        with contextlib.suppress(RetroDroidError):
            self.mutate(job_id, _apply, persist=False)

    def update_progress(self, job_id: str, progress: int, stage: str, section: str = "patch") -> None:
        def _apply(state: dict[str, Any]) -> None:
            sec = self._section(state, section)
            if sec.get("status") == "canceled":
                return
            sec["progress"] = max(0, min(100, int(progress)))
            sec["stage"] = str(stage)
            sec["status"] = "running"
            sec["updatedAt"] = time.time()

        with contextlib.suppress(RetroDroidError):
            self.mutate(job_id, _apply)

    def complete_operation(self, job_id: str, result: dict[str, Any], section: str = "patch") -> bool:
        now = time.time()
        completed = False

        def _apply(state: dict[str, Any]) -> None:
            nonlocal completed
            sec = self._section(state, section)
            ev = self._cancel_events.get(job_id)
            if sec.get("status") == "canceled" or (ev is not None and ev.is_set()):
                sec.update(
                    status="canceled",
                    stage="İptal edildi",
                    error=CANCELED_ERROR,
                    finishedAt=now,
                    updatedAt=now,
                )
                return
            sec.update(status="done", progress=100, stage="Tamamlandı", result=result, error=None, finishedAt=now)
            sec["updatedAt"] = now
            completed = True

        with contextlib.suppress(RetroDroidError):
            self.mutate(job_id, _apply)
        return completed

    def fail_operation(self, job_id: str, error: str, section: str = "patch", status: str = "error") -> None:
        now = time.time()

        def _apply(state: dict[str, Any]) -> None:
            sec = self._section(state, section)
            sec.update(status=status, stage="İptal edildi" if status == "canceled" else "Hata", error=error)
            sec["finishedAt"] = now
            sec["updatedAt"] = now

        with contextlib.suppress(RetroDroidError):
            self.mutate(job_id, _apply)

    def execute_operation(
        self,
        job_id: str,
        section: str,
        runner: Callable[
            [
                threading.Event,
                Callable[[subprocess.Popen[Any]], None],
                Callable[[str], None],
                Callable[[int, str], None],
            ],
            dict[str, Any],
        ],
        *,
        reraise: bool = False,
    ) -> dict[str, Any] | None:
        """Run ``runner`` for a job whose patch slot is already reserved; always releases the slot."""
        try:
            ev, on_proc = self.begin_cancellable_op(job_id)
            try:
                result = runner(
                    ev,
                    on_proc,
                    lambda line: self.append_log(job_id, line, section),
                    lambda pct, stage: self.update_progress(job_id, pct, stage, section),
                )
            except CommandCanceledError:
                self.fail_operation(job_id, CANCELED_ERROR, section, status="canceled")
                if reraise:
                    raise
                return None
            except Exception as exc:
                canceled = ev.is_set()
                if isinstance(exc, RetroDroidError):
                    message = exc.detail
                else:
                    message = INTERNAL_ERROR
                    _log.exception("İşlem beklenmedik şekilde başarısız oldu", extra={"jobId": job_id})
                self.fail_operation(
                    job_id,
                    CANCELED_ERROR if canceled else message,
                    section,
                    status="canceled" if canceled else "error",
                )
                if reraise:
                    raise
                return None
            if ev.is_set() or not self.complete_operation(job_id, result, section):
                self.fail_operation(job_id, CANCELED_ERROR, section, status="canceled")
                if reraise:
                    raise CommandCanceledError()
                return None
            return result
        finally:
            self.release_patch_slot(job_id)

    # ------------------------------------------------------------------ restart recovery & listing
    def load_persisted_jobs(self) -> int:
        """Load job states from disk; mark operations that were running before a restart as interrupted."""
        wd = self.work_dir()
        if not wd.is_dir():
            return 0
        loaded = 0
        now = time.time()
        recovered_ids: list[str] = []
        for child in sorted(wd.iterdir()):
            if not is_valid_job_id(child.name) or not child.is_dir():
                continue
            state = _read_json_dict(child / STATE_FILE)
            if state is None or state.get("jobId") != child.name:
                state = self._synthesize_state(child, child.name)
            if state is None:
                continue
            with self._lock:
                changed = False
                if child.name not in self._patch_slots:
                    changed = self._mark_stale_active_interrupted(state, now)
                self._jobs[(wd.resolve(), child.name)] = state
                loaded += 1
            if changed:
                recovered_ids.append(child.name)
        for jid in recovered_ids:
            self._persist_snapshot(jid)
        return loaded

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        wd = self.work_dir()
        if not wd.is_dir():
            return []
        items: list[dict[str, Any]] = []
        for child in list(wd.iterdir()):
            try:
                if not is_valid_job_id(child.name) or not child.is_dir():
                    continue
                state = self.get_job_state(child.name)
                if state is None:
                    continue
                result = state.get("result") if isinstance(state.get("result"), dict) else {}
                upload_meta = _read_json_dict(child / "upload_meta.json") or {}
                apk_info = upload_meta.get("apkInfo") if isinstance(upload_meta.get("apkInfo"), dict) else {}
                full = state.get("fullXapk") if isinstance(state.get("fullXapk"), dict) else None
                full_res = full.get("result") if full and isinstance(full.get("result"), dict) else {}
                items.append(
                    {
                        "jobId": child.name,
                        "status": state.get("status"),
                        "progress": state.get("progress", 0),
                        "stage": state.get("stage", ""),
                        "fileName": (
                            result.get("fileName")
                            or upload_meta.get("sanitizedFileName")
                            or upload_meta.get("fileName")
                        ),
                        "packageId": result.get("packageId") or apk_info.get("packageId"),
                        "appLabel": result.get("appLabel") or apk_info.get("appLabel"),
                        "targetSdk": result.get("targetSdk") or state.get("targetSdk") or apk_info.get("targetSdk"),
                        "hasResult": bool(result),
                        "downloadUrl": result.get("downloadUrl"),
                        "fullXapkStatus": full.get("status") if full else None,
                        "fullXapkDownloadUrl": full_res.get("downloadUrl"),
                        "error": state.get("error"),
                        "createdAt": state.get("createdAt"),
                        "updatedAt": state.get("updatedAt"),
                        "finishedAt": state.get("finishedAt"),
                        "expiresInSeconds": self.expires_in(child.name),
                    }
                )
            except OSError:
                continue
        items.sort(key=lambda it: it.get("createdAt") or 0, reverse=True)
        return items[: max(1, int(limit))]

    # ------------------------------------------------------------------ deletion & janitor
    def _forget_locked(self, job_id: str) -> None:
        for key in [k for k in self._jobs if k[1] == job_id]:
            self._jobs.pop(key, None)
        self._job_locks.pop(job_id, None)
        self._upload_locks.pop(job_id, None)
        self._persist_locks.pop(job_id, None)
        self._cancel_events.pop(job_id, None)
        self._running_procs.pop(job_id, None)

    def forget_job(self, job_id: str) -> None:
        """Prune in-memory state and lock entries for a job whose directory no longer exists."""
        with self._lock:
            if self._active_refs.get(job_id, 0) > 0 or job_id in self._patch_slots:
                return
            if (self.work_dir() / job_id).is_dir():
                return
            self._forget_locked(job_id)

    def _detach_dir_locked(self, job_id: str, job_dir: Path) -> Path:
        """Atomically rename ``job_dir`` out of view under lock so rmtree can run unlocked."""
        trash = job_dir.parent / f"_trash_{job_id}_{uuid.uuid4().hex[:8]}"
        try:
            os.replace(job_dir, trash)
            return trash
        except OSError:
            return job_dir

    def delete_job(self, job_id: str) -> dict[str, Any]:
        self.validate_job_id(job_id)
        trash: Path | None = None
        with self._lock:
            if self._active_refs.get(job_id, 0) > 0 or job_id in self._patch_slots:
                raise JobConflictError("Aktif bir işlem sürerken iş silinemez.")
            jdir = self.work_dir() / job_id
            if not jdir.is_dir():
                raise JobNotFoundError()
            trash = self._detach_dir_locked(job_id, jdir)
            self._forget_locked(job_id)
        if trash is not None:
            shutil.rmtree(trash, ignore_errors=True)
        return {"ok": True, "jobId": job_id, "deleted": True}

    def _prune_orphans_locked(self) -> None:
        for key in [k for k in self._jobs if not (k[0] / k[1]).is_dir()]:
            if self._active_refs.get(key[1], 0) <= 0 and key[1] not in self._patch_slots:
                self._jobs.pop(key, None)
        wd = self.work_dir()
        for registry in (
            self._job_locks,
            self._upload_locks,
            self._persist_locks,
            self._cancel_events,
            self._running_procs,
        ):
            for jid in list(registry):
                if (
                    not (wd / jid).is_dir()
                    and self._active_refs.get(jid, 0) <= 0
                    and jid not in self._patch_slots
                ):
                    registry.pop(jid, None)

    def cleanup_old_jobs(self, keep_job_id: str | None = None) -> int:
        """Remove expired (TTL) and, under low disk, oldest inactive jobs; never touches busy jobs."""
        cfg = self.settings()
        wd = self.work_dir()
        if not wd.is_dir():
            return 0
        now = time.time()
        ttl = float(cfg.JOB_TTL_SECONDS)
        candidates: list[tuple[float, str, Path]] = []
        for child in list(wd.iterdir()):
            name = child.name
            if name.startswith("_trash_") and child.is_dir():
                with contextlib.suppress(OSError):
                    if now - child.stat().st_mtime > 60.0:
                        shutil.rmtree(child, ignore_errors=True)
                continue
            if name.startswith("_") or not is_valid_job_id(name) or not child.is_dir():
                continue
            if name == keep_job_id or self.is_busy(name):
                continue
            candidates.append((self.get_last_activity(child), name, child))
        candidates.sort()
        removed = 0
        survivors: list[tuple[float, str, Path]] = []
        for last, name, child in candidates:
            if now - last > ttl and self._remove_if_idle(name, child, min_age_seconds=ttl):
                removed += 1
            else:
                survivors.append((last, name, child))
        floor = cfg.disk_free_floor_bytes
        min_age = min(120.0, ttl)
        for last, name, child in survivors:
            try:
                free = shutil.disk_usage(wd).free
            except OSError:
                break
            if free >= floor:
                break
            if now - last >= min_age and self._remove_if_idle(name, child, min_age_seconds=min_age):
                removed += 1
        with self._lock:
            self._prune_orphans_locked()
        return removed

    def _remove_if_idle(
        self,
        job_id: str,
        job_dir: Path,
        *,
        min_age_seconds: float | None = None,
    ) -> bool:
        trash: Path | None = None
        with self._lock:
            if self._active_refs.get(job_id, 0) > 0 or job_id in self._patch_slots:
                return False
            if not job_dir.is_dir():
                self._forget_locked(job_id)
                return False
            if min_age_seconds is not None and (time.time() - self.get_last_activity(job_dir)) < float(min_age_seconds):
                return False
            trash = self._detach_dir_locked(job_id, job_dir)
            self._forget_locked(job_id)
        if trash is not None:
            shutil.rmtree(trash, ignore_errors=True)
        return True
