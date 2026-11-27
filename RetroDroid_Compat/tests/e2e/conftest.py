"""Live uvicorn subprocess server fixtures and session-cached E2E corpus for RetroDroid Compat v5.4.0."""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.e2e.fixtures_apk import E2ECorpus, build_e2e_corpus

REPO_ROOT = Path(__file__).resolve().parents[2]
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
PYTHON_EXE = str(VENV_PYTHON) if VENV_PYTHON.is_file() else sys.executable

PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


def _clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV_KEYS}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT)
    if extra:
        env.update(extra)
    return env


@dataclass
class LiveServer:
    """Running live uvicorn server handle with isolated work_dir, keystore_path, and HTTP helpers."""

    base_url: str
    port: int
    work_dir: Path
    keystore_path: Path
    api_token: str
    process: subprocess.Popen[str]

    def client(self, *, timeout: float = 120.0, headers: dict[str, str] | None = None) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            trust_env=False,
            timeout=timeout,
            headers=headers,
        )

    def stop(self) -> None:
        if self.process.poll() is not None:
            return
        with contextlib.suppress(ProcessLookupError, OSError):
            self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, OSError):
                self.process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=5)


def start_live_uvicorn(
    work_dir: Path,
    keystore_path: Path,
    *,
    api_token: str = "",
    allowed_origins: str | None = None,
    rate_limit_per_min: int = 0,
    max_concurrent_patches: int = 2,
    chunk_size_mb: int = 8,
    job_ttl_seconds: int = 3600,
    extra_env: dict[str, str] | None = None,
    startup_timeout: float = 25.0,
) -> LiveServer:
    """Spawn a real ``uvicorn server:app`` process and wait until ``GET /health`` responds 200."""
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    work_dir.mkdir(parents=True, exist_ok=True)
    keystore_path.parent.mkdir(parents=True, exist_ok=True)

    origins = allowed_origins if allowed_origins is not None else f"{base_url},http://localhost:{port}"
    env_overrides: dict[str, str] = {
        "WORK_DIR": str(work_dir),
        "KEYSTORE_PATH": str(keystore_path),
        "API_TOKEN": api_token,
        "ALLOWED_ORIGINS": origins,
        "RATE_LIMIT_PER_MIN": str(rate_limit_per_min),
        "MAX_CONCURRENT_PATCHES": str(max_concurrent_patches),
        "CHUNK_SIZE_MB": str(chunk_size_mb),
        "JOB_TTL_SECONDS": str(job_ttl_seconds),
        "LOG_LEVEL": "WARNING",
    }
    if extra_env:
        env_overrides.update(extra_env)

    proc = subprocess.Popen(
        [
            PYTHON_EXE,
            "-B",
            "-m",
            "uvicorn",
            "server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--timeout-keep-alive",
            "120",
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=_clean_env(env_overrides),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    deadline = time.monotonic() + startup_timeout
    last_err: str = ""
    with httpx.Client(base_url=base_url, trust_env=False, timeout=2.0) as probe:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stdout_txt = proc.stdout.read() if proc.stdout else ""
                stderr_txt = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(
                    f"uvicorn exited prematurely (code={proc.returncode}):\nSTDOUT:\n{stdout_txt}\nSTDERR:\n{stderr_txt}"
                )
            try:
                resp = probe.get("/health")
                if resp.status_code == 200:
                    return LiveServer(
                        base_url=base_url,
                        port=port,
                        work_dir=work_dir,
                        keystore_path=keystore_path,
                        api_token=api_token,
                        process=proc,
                    )
            except httpx.HTTPError as exc:
                last_err = str(exc)
            time.sleep(0.1)

    with contextlib.suppress(OSError):
        proc.kill()
    stdout_txt = proc.stdout.read() if proc.stdout else ""
    stderr_txt = proc.stderr.read() if proc.stderr else ""
    raise RuntimeError(
        f"uvicorn failed to become healthy within {startup_timeout}s ({last_err}).\n"
        f"STDOUT:\n{stdout_txt}\nSTDERR:\n{stderr_txt}"
    )


def upload_via_analyze(client: httpx.Client, file_path: Path, filename: str | None = None) -> dict[str, Any]:
    """Upload a file via ``POST /api/analyze`` and return parsed JSON response (asserting 200)."""
    fname = filename or file_path.name
    with file_path.open("rb") as fp:
        resp = client.post("/api/analyze", files={"file": (fname, fp, "application/octet-stream")})
    assert resp.status_code == 200, f"POST /api/analyze failed ({resp.status_code}): {resp.text}"
    return resp.json()


def upload_via_chunks(
    client: httpx.Client,
    file_path: Path,
    *,
    filename: str | None = None,
    chunk_size: int = 8192,
    job_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Perform full init -> chunk*N -> finish flow and return ``(init_json, finish_json)``."""
    raw = file_path.read_bytes()
    fname = filename or file_path.name
    total_size = len(raw)
    total_chunks = max(1, (total_size + chunk_size - 1) // chunk_size)
    init_data: dict[str, Any] = {
        "fileName": fname,
        "totalSize": str(total_size),
        "totalChunks": str(total_chunks),
    }
    if job_id:
        init_data["jobId"] = job_id
    r_init = client.post("/api/upload/init", data=init_data)
    assert r_init.status_code == 200, f"init failed ({r_init.status_code}): {r_init.text}"
    init_json = r_init.json()
    jid = init_json["jobId"]
    srv_chunk_size = int(init_json["chunkSizeBytes"])
    srv_total_chunks = int(init_json["totalChunks"])

    for idx in range(srv_total_chunks):
        part = raw[idx * srv_chunk_size : (idx + 1) * srv_chunk_size]
        r_chunk = client.post(
            "/api/upload/chunk",
            data={"jobId": jid, "chunkIndex": str(idx), "totalChunks": str(srv_total_chunks)},
            files={"chunk": (f"chunk_{idx}.bin", part, "application/octet-stream")},
        )
        assert r_chunk.status_code == 200, f"chunk {idx} failed ({r_chunk.status_code}): {r_chunk.text}"

    r_fin = client.post("/api/upload/finish", data={"jobId": jid})
    assert r_fin.status_code == 200, f"finish failed ({r_fin.status_code}): {r_fin.text}"
    return init_json, r_fin.json()


@pytest.fixture(scope="session")
def apk_corpus(tmp_path_factory: pytest.TempPathFactory) -> E2ECorpus:
    """Session-cached genuine synthetic APK/XAPK/APKM/APKS/ZIP corpus."""
    return build_e2e_corpus(tmp_path_factory.mktemp("e2e_corpus"))


@pytest.fixture(scope="session")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    """Primary open live uvicorn server shared across opaque-box E2E tests."""
    root = tmp_path_factory.mktemp("e2e_live_open")
    srv = start_live_uvicorn(
        work_dir=root / "work",
        keystore_path=root / "ks" / "retrodroid.jks",
        api_token="",
        rate_limit_per_min=0,
        max_concurrent_patches=2,
    )
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture(scope="session")
def http_client(live_server: LiveServer) -> Iterator[httpx.Client]:
    """Proxy-stripped httpx client bound to ``live_server``."""
    with live_server.client() as client:
        yield client


@pytest.fixture(scope="session")
def auth_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    """Live uvicorn server with API_TOKEN, strict ALLOWED_ORIGINS, and single concurrent patch slot."""
    root = tmp_path_factory.mktemp("e2e_live_auth")
    srv = start_live_uvicorn(
        work_dir=root / "work",
        keystore_path=root / "ks" / "retrodroid.jks",
        api_token="e2e-secret-token-9482",
        allowed_origins="https://trusted.retrodroid.local",
        rate_limit_per_min=0,
        max_concurrent_patches=1,
    )
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture(scope="session")
def degraded_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    """Live uvicorn server booted with a corrupt keystore and KEYSTORE_AUTO_REGEN=false."""
    root = tmp_path_factory.mktemp("e2e_live_degraded")
    ks_path = root / "ks" / "corrupt_retrodroid.jks"
    ks_path.parent.mkdir(parents=True, exist_ok=True)
    ks_path.write_bytes(b"NOT_A_VALID_JKS_KEYSTORE_DO_NOT_DELETE")
    os.chmod(ks_path, 0o600)
    srv = start_live_uvicorn(
        work_dir=root / "work",
        keystore_path=ks_path,
        api_token="",
        rate_limit_per_min=0,
        extra_env={"KEYSTORE_AUTO_REGEN": "false", "KEYSTORE_PASS": "CorruptPass123"},
    )
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def server_factory(tmp_path: Path) -> Iterator[Callable[..., LiveServer]]:
    """Per-test factory to spin up isolated disposable uvicorn instances with guaranteed teardown."""
    spawned: list[LiveServer] = []

    def _spawn(**kwargs: Any) -> LiveServer:
        idx = len(spawned)
        work_dir = Path(kwargs.pop("work_dir", tmp_path / f"srv_{idx}" / "work"))
        keystore_path = Path(kwargs.pop("keystore_path", tmp_path / f"srv_{idx}" / "ks" / "retrodroid.jks"))
        srv = start_live_uvicorn(work_dir=work_dir, keystore_path=keystore_path, **kwargs)
        spawned.append(srv)
        return srv

    try:
        yield _spawn
    finally:
        for srv in reversed(spawned):
            srv.stop()
