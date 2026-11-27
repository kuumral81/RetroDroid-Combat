"""Configuration, sanitization, subprocess orchestration, and structured logging for RetroDroid Compat."""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

APP_VERSION: str = "5.4.0"

SUPPORTED_EXTS: tuple[str, ...] = (".apk", ".xapk", ".apks", ".apkm", ".zip")

DEFAULT_ALLOWED_ORIGINS: tuple[str, ...] = (
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:10000",
    "http://127.0.0.1:10000",
)

JOB_ID_RE = re.compile(r"\A[0-9a-f]{12}\Z")

_KNOWN_EXTS: frozenset[str] = frozenset(
    {
        ".apk",
        ".xapk",
        ".apks",
        ".apkm",
        ".zip",
        ".obb",
        ".json",
        ".txt",
        ".png",
        ".xml",
        ".jks",
    }
)

_WINDOWS_RESERVED_NAMES: frozenset[str] = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

_JAVA_TOOLS: frozenset[str] = frozenset({"java", "keytool", "apktool", "apksigner"})

_REDACTED_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "pass",
        "ks_pass",
        "storepass",
        "keypass",
        "secret",
        "token",
        "api_token",
        "api_key",
        "api-key",
        "apikey",
        "keystore_pass",
        "rd_ks_pass",
        "authorization",
    }
)

_REDACTED_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "storepass",
    "keypass",
    "ks_pass",
    "authorization",
    "api_key",
    "api-key",
    "apikey",
)

_WATCHED_ENV_VARS: tuple[str, ...] = (
    "WORK_DIR",
    "KEYSTORE_PATH",
    "KEYSTORE_PASS",
    "KEYSTORE_ALIAS",
    "KEYSTORE_AUTO_REGEN",
    "MAX_UPLOAD_MB",
    "CHUNK_SIZE_MB",
    "JOB_TTL_SECONDS",
    "DISK_FREE_FLOOR_MB",
    "MAX_CONCURRENT_PATCHES",
    "MAX_ARCHIVE_ENTRIES",
    "MAX_DECOMPRESSED_BYTES",
    "API_TOKEN",
    "API_ACCESS_TOKEN",
    "ALLOWED_ORIGINS",
    "RATE_LIMIT_PER_MIN",
    "JAVA_HEAP_MB",
)

CURRENT_JOB_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "retrodroid_job_id",
    default=None,
)

_SETTINGS_LOCK = threading.Lock()
_SETTINGS_CACHE: tuple[tuple[str | None, ...], Settings] | None = None

_TOOLS_LOCK = threading.Lock()
_TOOLS_CACHE: dict[str, Any] | None = None

_LOG = logging.getLogger("retrodroid.config")


# ---------------------------------------------------------------------------
# Domain Exceptions (framework-decoupled; mapped to HTTP in server.py)
# ---------------------------------------------------------------------------


class RetroDroidError(Exception):
    """Base domain error carrying an HTTP status code and user-safe detail message."""

    def __init__(self, detail: str, *, status_code: int = 500) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class PayloadTooLargeError(RetroDroidError):
    """Raised when an upload, archive, or stream exceeds configured byte/entry bounds."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=413)


class InvalidArchiveError(RetroDroidError, ValueError):
    """Raised when a ZIP/XAPK/APKM/APKS archive or path is malformed or unsafe."""

    def __init__(self, detail: str, *, status_code: int = 400) -> None:
        super().__init__(detail, status_code=status_code)


class ApkInspectionError(RetroDroidError, ValueError):
    """Raised when an APK cannot be opened, lacks a manifest, or fails metadata inspection."""

    def __init__(self, detail: str, *, status_code: int = 400) -> None:
        super().__init__(detail, status_code=status_code)


class ToolNotFoundError(RetroDroidError):
    """Raised when a required Android or Java CLI tool is missing from PATH."""

    def __init__(self, tool_name: str, detail: str | None = None) -> None:
        msg = detail or (
            f"'{tool_name}' aracı sunucuda bulunamadı. "
            "openjdk-17, apktool, aapt, zipalign ve apksigner kurulu olduğundan emin olun."
        )
        super().__init__(msg, status_code=500)
        self.tool_name = tool_name


class CommandTimeoutError(RetroDroidError):
    """Raised when a subprocess exceeds its configured timeout."""

    def __init__(self, cmd_name: str, timeout: float, output: str = "") -> None:
        msg = f"'{cmd_name}' işlemi zaman aşımına uğradı ({timeout}s)."
        super().__init__(msg, status_code=504)
        self.cmd_name = cmd_name
        self.timeout = timeout
        self.output = output


class CommandCanceledError(RetroDroidError):
    """Raised when an operation or subprocess is canceled via a cancel_event."""

    def __init__(self, cmd_name: str = "") -> None:
        msg = f"'{cmd_name}' işlemi iptal edildi." if cmd_name else "İşlem iptal edildi."
        super().__init__(msg, status_code=409)
        self.cmd_name = cmd_name


# ---------------------------------------------------------------------------
# Identifiers & Env Parsing
# ---------------------------------------------------------------------------


def is_valid_job_id(job_id: str) -> bool:
    """Validate that a job_id is strictly 12 lowercase hexadecimal characters."""
    return isinstance(job_id, str) and bool(JOB_ID_RE.match(job_id))


def _env_int(
    name: str,
    default: int,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError:
            _LOG.warning(
                "Invalid integer environment variable %s=%r; using default %d",
                name,
                raw,
                default,
            )
            value = default
    if min_value is not None and value < min_value:
        value = min_value
    if max_value is not None and value > max_value:
        value = max_value
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    norm = raw.strip().lower()
    if norm in {"1", "true", "yes", "y", "on"}:
        return True
    if norm in {"0", "false", "no", "n", "off"}:
        return False
    _LOG.warning(
        "Invalid boolean environment variable %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


def _env_origins(name: str = "ALLOWED_ORIGINS") -> list[str]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return list(DEFAULT_ALLOWED_ORIGINS)
    seen: set[str] = set()
    origins: list[str] = []
    for token in raw.split(","):
        cleaned = token.strip()
        if not cleaned:
            continue
        if cleaned != "*":
            cleaned = cleaned.rstrip("/")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            origins.append(cleaned)
    return origins if origins else list(DEFAULT_ALLOWED_ORIGINS)


def _env_api_token() -> str:
    primary = os.environ.get("API_TOKEN", "").strip()
    if primary:
        return primary
    return os.environ.get("API_ACCESS_TOKEN", "").strip()


def resolve_keystore_path(desired: Path, work_dir: Path) -> tuple[Path, bool]:
    """Return a writable keystore path and whether the desired path (non-fallback) was used."""
    desired_path = Path(desired)
    work_path = Path(work_dir)
    fallback_dir = work_path / "_keystore"
    try:
        is_ephemeral_fallback = desired_path.resolve().is_relative_to(fallback_dir.resolve())
    except OSError:
        is_ephemeral_fallback = False

    try:
        desired_path.parent.mkdir(parents=True, exist_ok=True)
        if is_ephemeral_fallback:
            try:
                os.chmod(desired_path.parent, 0o700)
            except OSError:
                pass
        probe = desired_path.parent / f".rd_write_probe.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.close(fd)
        finally:
            try:
                os.unlink(probe)
            except OSError:
                pass
        return desired_path, (not is_ephemeral_fallback)
    except OSError:
        fallback = fallback_dir / "retrodroid.jks"
        try:
            fallback.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(fallback.parent, 0o700)
        except OSError:
            pass
        return fallback, False


# ---------------------------------------------------------------------------
# Settings Dataclass & Dynamic Reload Cache
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Settings:
    """Application configuration parsed from environment variables."""

    APP_VERSION: str = APP_VERSION
    WORK_DIR: Path = Path("/tmp/retrodroid_jobs")
    KEYSTORE_PATH: Path = Path("/var/data/retrodroid.jks")
    KEYSTORE_PERSISTENT: bool = False
    KEYSTORE_PASS: str = field(default="", repr=False)
    KEYSTORE_ALIAS: str = "retrodroid"
    KEYSTORE_AUTO_REGEN: bool = False
    MAX_UPLOAD_MB: int = 5120
    CHUNK_SIZE_MB: int = 8
    JOB_TTL_SECONDS: int = 3600
    DISK_FREE_FLOOR_MB: int = 1500
    MAX_CONCURRENT_PATCHES: int = 1
    MAX_ARCHIVE_ENTRIES: int = 25000
    MAX_DECOMPRESSED_BYTES: int = 10 * 1024**3
    API_TOKEN: str = field(default="", repr=False)
    ALLOWED_ORIGINS: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_ORIGINS))
    RATE_LIMIT_PER_MIN: int = 120
    JAVA_HEAP_MB: int = 256
    SUPPORTED_EXTS: tuple[str, ...] = SUPPORTED_EXTS

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_MB * 1024 * 1024

    @property
    def chunk_size_bytes(self) -> int:
        return self.CHUNK_SIZE_MB * 1024 * 1024

    @property
    def disk_free_floor_bytes(self) -> int:
        return self.DISK_FREE_FLOOR_MB * 1024 * 1024

    @property
    def auth_required(self) -> bool:
        return bool(self.API_TOKEN)


def _env_snapshot() -> tuple[str | None, ...]:
    return tuple(os.environ.get(var) for var in _WATCHED_ENV_VARS)


def _build_settings() -> Settings:
    raw_work = os.environ.get("WORK_DIR", "").strip()
    work_dir = Path(raw_work) if raw_work else Path("/tmp/retrodroid_jobs")

    raw_ks = os.environ.get("KEYSTORE_PATH", "").strip()
    desired_ks = Path(raw_ks) if raw_ks else Path("/var/data/retrodroid.jks")
    ks_path, ks_persistent = resolve_keystore_path(desired_ks, work_dir)

    ks_alias = os.environ.get("KEYSTORE_ALIAS", "").strip() or "retrodroid"

    return Settings(
        APP_VERSION=APP_VERSION,
        WORK_DIR=work_dir,
        KEYSTORE_PATH=ks_path,
        KEYSTORE_PERSISTENT=ks_persistent,
        KEYSTORE_PASS=os.environ.get("KEYSTORE_PASS", "").strip(),
        KEYSTORE_ALIAS=ks_alias,
        KEYSTORE_AUTO_REGEN=_env_bool("KEYSTORE_AUTO_REGEN", False),
        MAX_UPLOAD_MB=_env_int("MAX_UPLOAD_MB", 5120, min_value=1, max_value=102400),
        CHUNK_SIZE_MB=_env_int("CHUNK_SIZE_MB", 8, min_value=1, max_value=256),
        JOB_TTL_SECONDS=_env_int("JOB_TTL_SECONDS", 3600, min_value=1),
        DISK_FREE_FLOOR_MB=_env_int("DISK_FREE_FLOOR_MB", 1500, min_value=0),
        MAX_CONCURRENT_PATCHES=_env_int("MAX_CONCURRENT_PATCHES", 1, min_value=1, max_value=32),
        MAX_ARCHIVE_ENTRIES=_env_int("MAX_ARCHIVE_ENTRIES", 25000, min_value=1),
        MAX_DECOMPRESSED_BYTES=_env_int(
            "MAX_DECOMPRESSED_BYTES",
            10 * 1024**3,
            min_value=1024 * 1024,
        ),
        API_TOKEN=_env_api_token(),
        ALLOWED_ORIGINS=_env_origins("ALLOWED_ORIGINS"),
        RATE_LIMIT_PER_MIN=_env_int("RATE_LIMIT_PER_MIN", 120, min_value=0),
        JAVA_HEAP_MB=_env_int("JAVA_HEAP_MB", 256, min_value=64, max_value=8192),
        SUPPORTED_EXTS=SUPPORTED_EXTS,
    )


def get_settings(reload: bool = False) -> Settings:
    """Return current Settings, automatically reloading whenever watched env vars change."""
    global _SETTINGS_CACHE
    snap = _env_snapshot()
    with _SETTINGS_LOCK:
        if not reload and _SETTINGS_CACHE is not None and _SETTINGS_CACHE[0] == snap:
            return _SETTINGS_CACHE[1]
        settings = _build_settings()
        _SETTINGS_CACHE = (snap, settings)
        return settings


def reset_settings_cache() -> None:
    """Clear the cached Settings snapshot (useful for tests)."""
    global _SETTINGS_CACHE
    with _SETTINGS_LOCK:
        _SETTINGS_CACHE = None


def ensure_work_dir(settings: Settings | None = None) -> Path:
    """Ensure WORK_DIR exists with clean directory permissions and return it."""
    cfg = settings or get_settings()
    cfg.WORK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(cfg.WORK_DIR, 0o755)
    except OSError:
        pass
    return cfg.WORK_DIR


# ---------------------------------------------------------------------------
# Filename Sanitization, URL Encoding, Atomic JSON
# ---------------------------------------------------------------------------


def _sanitize_once(name: str | None, fallback_stem: str, max_len: int) -> str | None:
    raw = "" if name is None else str(name)
    raw = re.sub(r"[\x00-\x1f\x7f]", "", raw)
    raw = raw.replace("\\", "/")
    parts = [p for p in raw.split("/") if p]
    base = parts[-1] if parts else ""

    if len(base) >= 2 and base[1] == ":" and base[0].isalpha():
        base = base[2:]

    base = base.strip().rstrip(" .")
    if not base:
        return None

    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    cleaned = re.sub(r"\.{2,}", ".", cleaned)

    if "." in cleaned:
        raw_stem, _, raw_ext = cleaned.rpartition(".")
        raw_ext = raw_ext.rstrip("._-")
        candidate_ext = f".{raw_ext}" if raw_ext else ""
        stem = raw_stem.lstrip("._-").rstrip(".")

        if not stem and candidate_ext.lower() in _KNOWN_EXTS:
            stem = fallback_stem
            ext = candidate_ext
        elif not stem and raw_stem == "":
            stem = raw_ext.lstrip("._-")
            ext = ""
        else:
            ext = candidate_ext
    else:
        stem = cleaned.lstrip("._-")
        ext = ""

    if not stem or not re.search(r"[A-Za-z0-9]", stem):
        if ext and ext.lower() in _KNOWN_EXTS:
            stem = fallback_stem
        else:
            return None

    if len(ext) >= max_len:
        ext = ext[: max(1, max_len // 4)]

    max_stem_len = max_len - len(ext)
    if len(stem) > max_stem_len:
        stem = stem[:max_stem_len].rstrip("._-") or "f"

    first_token = stem.split(".")[0].upper()
    if first_token in _WINDOWS_RESERVED_NAMES:
        if max_stem_len >= len("file_") + len(first_token):
            prefixed = f"file_{stem}"
        else:
            prefixed = f"f_{stem}"
        if len(prefixed) > max_stem_len:
            prefixed = prefixed[:max_stem_len].rstrip("._-") or "f"
        stem = prefixed

    return f"{stem}{ext}"


def sanitize_filename(name: str, default: str = "file.apk", max_len: int = 120) -> str:
    """Sanitize an untrusted filename into a safe ASCII basename of length <= max_len."""
    limit = max(8, int(max_len))
    default_clean = _sanitize_once(default, "file", limit) or "file.apk"
    fallback_stem = Path(default_clean).stem or "file"
    sanitized = _sanitize_once(name, fallback_stem, limit)
    return sanitized if sanitized else default_clean


def safe_url_download(job_id: str, filename: str) -> str:
    """Build a strictly percent-encoded /api/download URL."""
    return (
        f"/api/download/"
        f"{urllib.parse.quote(str(job_id), safe='')}/"
        f"{urllib.parse.quote(str(filename), safe='')}"
    )


def write_json_atomic(path: Path, data: Any) -> None:
    """Serialize data to UTF-8 JSON and atomically replace path via fsync + os.replace."""
    target = Path(path)
    payload = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / (
        f".{target.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.tmp"
    )
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        try:
            os.fchmod(fd, 0o644)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as fp:
            fd = -1
            fp.write(payload)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, target)
        try:
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Subprocess Execution, JAVA_TOOL_OPTIONS Cleanup & Stream Copy
# ---------------------------------------------------------------------------


def clean_java_output(stderr: str | None, stdout: str | None = "") -> str:
    """Strip JVM JAVA_TOOL_OPTIONS/_JAVA_OPTIONS banner lines and combine output cleanly."""
    parts: list[str] = []
    for text in (stderr or "", stdout or ""):
        if not text:
            continue
        lines = [
            line
            for line in text.replace("\r\n", "\n").splitlines()
            if not line.lstrip().startswith(("Picked up JAVA_TOOL_OPTIONS:", "Picked up _JAVA_OPTIONS:"))
        ]
        joined = "\n".join(lines).strip()
        if joined:
            parts.append(joined)
    return "\n".join(parts).strip()


@dataclass
class CmdResult:
    """Structured result from run_cmd."""

    returncode: int
    stdout: str
    stderr: str
    cmd_name: str
    elapsed_seconds: float
    timed_out: bool = False
    canceled: bool = False

    @property
    def clean_output(self) -> str:
        return clean_java_output(self.stderr, self.stdout)


def _terminate_process_tree(proc: subprocess.Popen[str]) -> tuple[str, str]:
    out = ""
    err = ""
    has_killpg = hasattr(os, "killpg")
    if has_killpg:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
    elif proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass

    communicated = False
    try:
        out, err = proc.communicate(timeout=1.0)
        communicated = True
    except subprocess.TimeoutExpired:
        pass

    # Always escalate SIGKILL to the process group even when proc.communicate()
    # returned cleanly: if the direct child exited on SIGTERM while a grandchild
    # in PGID == proc.pid had redirected stdio (e.g. DEVNULL or JVM internal
    # pipes) and ignored/stalled on SIGTERM, communicate() returns early on EOF.
    # On POSIX, the PGID stays reserved while any member survives and raises
    # ProcessLookupError (~0 ms) when no members remain.
    if has_killpg:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            if not communicated and proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
    elif not communicated and proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass

    if not communicated:
        try:
            out, err = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
    return out or "", err or ""


def run_cmd(
    cmd: list[str],
    timeout: int = 180,
    env: dict[str, str] | None = None,
    cancel_event: threading.Event | None = None,
    on_proc: Callable[[subprocess.Popen[str]], None] | None = None,
    *,
    cwd: Path | str | None = None,
    umask: int | None = None,
    java_heap_mb: int | None = None,
) -> CmdResult:
    """Run an external command with deadlock-free pipe draining, timeout, and cancel support."""
    if not cmd:
        raise ValueError("cmd must be a non-empty list of strings")

    cmd_name = Path(cmd[0]).name
    if cancel_event is not None and cancel_event.is_set():
        raise CommandCanceledError(cmd_name)

    run_env = os.environ.copy()
    caller_set_java_opts = False
    if env:
        caller_set_java_opts = "JAVA_TOOL_OPTIONS" in env
        run_env.update(env)

    if cmd_name in _JAVA_TOOLS and not caller_set_java_opts:
        heap = java_heap_mb if java_heap_mb is not None else get_settings().JAVA_HEAP_MB
        existing_opts = run_env.get("JAVA_TOOL_OPTIONS", "").strip()
        if re.search(r"-Xmx\S+", existing_opts):
            run_env["JAVA_TOOL_OPTIONS"] = re.sub(r"-Xmx\S+", f"-Xmx{heap}m", existing_opts)
        else:
            run_env["JAVA_TOOL_OPTIONS"] = f"{existing_opts} -Xmx{heap}m".strip()

    popen_kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "env": run_env,
        "start_new_session": True,
    }
    if cwd is not None:
        popen_kwargs["cwd"] = str(cwd)
    if umask is not None:
        popen_kwargs["umask"] = umask

    started = time.monotonic()
    try:
        proc: subprocess.Popen[str] = subprocess.Popen(cmd, **popen_kwargs)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(cmd_name) from exc

    terminated = False
    try:
        if on_proc is not None:
            on_proc(proc)

        deadline = started + max(0.05, float(timeout))
        while True:
            if cancel_event is not None and cancel_event.is_set():
                terminated = True
                _terminate_process_tree(proc)
                raise CommandCanceledError(cmd_name)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminated = True
                out, err = _terminate_process_tree(proc)
                raise CommandTimeoutError(cmd_name, timeout, output=clean_java_output(err, out))

            slice_timeout = min(0.1, remaining) if cancel_event is not None else remaining
            try:
                stdout, stderr = proc.communicate(timeout=slice_timeout)
                elapsed = time.monotonic() - started
                return CmdResult(
                    returncode=proc.returncode if proc.returncode is not None else -1,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    cmd_name=cmd_name,
                    elapsed_seconds=elapsed,
                )
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        if not terminated:
            _terminate_process_tree(proc)
        raise


def copy_stream_limited(
    src: BinaryIO,
    dst: BinaryIO,
    max_bytes: int,
    label: str = "Dosya",
    *,
    chunk_size: int = 1024 * 1024,
    cancel_event: threading.Event | None = None,
) -> int:
    """Stream bytes from src to dst, failing before exceeding max_bytes."""
    if max_bytes < 0:
        raise PayloadTooLargeError(f"{label} izin verilen boyut sınırını ({max_bytes} bayt) aşıyor.")

    total = 0
    read_size = max(4096, int(chunk_size))
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise CommandCanceledError("copy_stream")
        block = src.read(read_size)
        if not block:
            break
        if total + len(block) > max_bytes:
            raise PayloadTooLargeError(
                f"{label} izin verilen boyut sınırını ({max_bytes} bayt) aşıyor."
            )
        dst.write(block)
        total += len(block)
    return total


# ---------------------------------------------------------------------------
# Structured JSON Logging with jobId Context & Secret Redaction
# ---------------------------------------------------------------------------


@contextmanager
def log_job_context(job_id: str | None) -> Iterator[None]:
    """Bind a jobId into the current execution context for structured logs."""
    token = CURRENT_JOB_ID.set(job_id)
    try:
        yield
    finally:
        CURRENT_JOB_ID.reset(token)


def _is_sensitive_key(key: str) -> bool:
    low = key.lower()
    return (
        low in _REDACTED_KEYS
        or low.endswith(("_pass", "-pass"))
        or any(secret_key in low for secret_key in _REDACTED_SUBSTRINGS)
    )


def _redact_value(key: str, value: Any) -> Any:
    if key and _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value("", item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value("", item) for item in value)
    return value


class StructuredJsonFormatter(logging.Formatter):
    """Single-line UTF-8 JSON log formatter with jobId correlation and secret redaction."""

    _RESERVED_ATTRS: frozenset[str] = frozenset(
        {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "taskName",
            "jobId",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        job_id = getattr(record, "jobId", None) or CURRENT_JOB_ID.get()
        payload: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "jobId": job_id,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in self._RESERVED_ATTRS or key.startswith("_"):
                continue
            payload[key] = _redact_value(key, value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class JobLoggerAdapter(logging.LoggerAdapter):
    """LoggerAdapter injecting a fixed jobId into LogRecord extras."""

    def process(self, msg: Any, kwargs: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        extra = dict(self.extra or {})
        if "extra" in kwargs and isinstance(kwargs["extra"], dict):
            extra.update(kwargs["extra"])
        kwargs["extra"] = extra
        return msg, kwargs


def configure_logging(level: str | int | None = None) -> logging.Logger:
    """Idempotently configure the root retrodroid logger with StructuredJsonFormatter."""
    logger = logging.getLogger("retrodroid")
    if level is None:
        raw_level = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
        resolved_level: int | str = raw_level if raw_level else "INFO"
    else:
        resolved_level = level
    try:
        logger.setLevel(resolved_level)
    except (ValueError, TypeError):
        logger.setLevel(logging.INFO)

    if not any(getattr(h, "_retrodroid_json", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        handler._retrodroid_json = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str = "retrodroid", job_id: str | None = None) -> logging.Logger | JobLoggerAdapter:
    """Return a retrodroid logger, optionally bound to a specific job_id."""
    logger = logging.getLogger(name)
    if job_id is not None:
        return JobLoggerAdapter(logger, {"jobId": job_id})
    return logger


# ---------------------------------------------------------------------------
# Cached Android CLI Toolchain Probe
# ---------------------------------------------------------------------------


def _first_clean_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def probe_android_tools(force: bool = False) -> dict[str, Any]:
    """Probe availability, versions, and zipalign 16 KB support for Android build tools."""
    global _TOOLS_CACHE
    with _TOOLS_LOCK:
        if not force and _TOOLS_CACHE is not None:
            return {
                "tools": dict(_TOOLS_CACHE["tools"]),
                "toolVersions": dict(_TOOLS_CACHE["toolVersions"]),
                "zipalign16kSupported": bool(_TOOLS_CACHE["zipalign16kSupported"]),
            }

    tool_names = ("aapt", "apktool", "zipalign", "apksigner", "java", "keytool")
    tools: dict[str, bool] = {name: bool(shutil.which(name)) for name in tool_names}
    versions: dict[str, str] = {}
    zipalign_16k = False

    def _safe_probe(cmd: list[str]) -> str:
        try:
            res = run_cmd(cmd, timeout=10)
            return res.clean_output
        except RetroDroidError:
            return ""

    if tools["aapt"]:
        versions["aapt"] = _first_clean_line(_safe_probe(["aapt", "version"])) or "installed"
    if tools["apktool"]:
        versions["apktool"] = _first_clean_line(_safe_probe(["apktool", "--version"])) or "installed"
    if tools["apksigner"]:
        versions["apksigner"] = _first_clean_line(_safe_probe(["apksigner", "--version"])) or "installed"
    if tools["java"]:
        versions["java"] = _first_clean_line(_safe_probe(["java", "-version"])) or "installed"
    if tools["keytool"]:
        # OpenJDK 17 keytool rejects `-version` with RC=1; never execute `keytool -version`.
        versions["keytool"] = versions.get("java") or "OpenJDK keytool"
    if tools["zipalign"]:
        usage = _safe_probe(["zipalign"])
        zipalign_16k = bool(
            re.search(r"(?:^|\s)-P\s+(?:<pagesize|16\b)", usage)
            or re.search(r"(?:^|\s)-P\b.*(?:[Pp]age|[Kk]i[Bb]|16)", usage)
        )
        versions["zipalign"] = "installed (16KB -P)" if zipalign_16k else "installed (4KB -p)"

    result = {
        "tools": tools,
        "toolVersions": versions,
        "zipalign16kSupported": zipalign_16k,
    }
    with _TOOLS_LOCK:
        _TOOLS_CACHE = result
    return {
        "tools": dict(tools),
        "toolVersions": dict(versions),
        "zipalign16kSupported": zipalign_16k,
    }
