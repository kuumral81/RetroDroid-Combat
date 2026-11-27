"""Secure RSA-2048 JKS keystore lifecycle with env-var secret passing and flock safety."""

from __future__ import annotations

import fcntl
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from retrodroid.config import (
    RetroDroidError,
    Settings,
    get_logger,
    get_settings,
    resolve_keystore_path,
    run_cmd,
)

_LOG = get_logger("retrodroid.keystore")

_STATE_LOCK = threading.Lock()
_CURRENT_STATE: KeystoreState | None = None

_MIN_PASSWORD_LEN = 6


class KeystoreError(RetroDroidError):
    """Raised when the signing keystore cannot be verified, unlocked, or generated."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=500)


@dataclass(frozen=True)
class KeystoreState:
    """Verified keystore state; stores secret password privately with repr/compare disabled."""

    path: Path
    alias: str = "retrodroid"
    ready: bool = False
    persistent: bool = False
    sha256: str | None = None
    subject: str | None = None
    valid_until: str | None = None
    algorithm: str | None = None
    error: str | None = None
    _password: str = field(default="", repr=False, compare=False)

    def get_signing_env(
        self,
        base_env: dict[str, str] | None = None,
        env_var: str = "RD_KS_PASS",
    ) -> dict[str, str]:
        """Return a subprocess environment containing the keystore secret (never pass in argv)."""
        if not self.ready or not self._password:
            raise KeystoreError("İmzalama anahtarı hazır değil veya parola yüklenmedi.")
        env = dict(os.environ if base_env is None else base_env)
        env[env_var] = self._password
        return env

    def to_public_dict(self) -> dict[str, Any]:
        """Return safe public certificate metadata (NEVER contains passwords or secrets)."""
        return {
            "ready": self.ready,
            "alias": self.alias,
            "algorithm": self.algorithm,
            "sha256": self.sha256,
            "subject": self.subject,
            "validUntil": self.valid_until,
            "persistent": self.persistent,
            "path": str(self.path),
        }


def get_keystore_state() -> KeystoreState | None:
    """Return the cached KeystoreState if ensure_signing_keystore has run."""
    with _STATE_LOCK:
        return _CURRENT_STATE


def get_keystore_info() -> dict[str, Any]:
    """Return safe public metadata for /api/keystore-info (never returns password)."""
    with _STATE_LOCK:
        state = _CURRENT_STATE
    if state is not None:
        return state.to_public_dict()
    cfg = get_settings()
    return {
        "ready": False,
        "alias": cfg.KEYSTORE_ALIAS,
        "algorithm": None,
        "sha256": None,
        "subject": None,
        "validUntil": None,
        "persistent": cfg.KEYSTORE_PERSISTENT,
        "path": str(cfg.KEYSTORE_PATH),
    }


def reset_keystore_state() -> None:
    """Clear the cached KeystoreState (intended for tests)."""
    global _CURRENT_STATE
    with _STATE_LOCK:
        _CURRENT_STATE = None


def _set_state(state: KeystoreState) -> KeystoreState:
    global _CURRENT_STATE
    with _STATE_LOCK:
        _CURRENT_STATE = state
    return state


def _set_failed_state(
    ks_path: Path,
    alias: str,
    persistent: bool,
    error: str,
) -> KeystoreState:
    return _set_state(
        KeystoreState(
            path=ks_path,
            alias=alias,
            ready=False,
            persistent=persistent,
            error=error,
        )
    )


def _write_pass_atomic(path: Path, secret: str) -> None:
    """Atomically write a keystore password file with strict 0o600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        payload = (secret + "\n").encode("utf-8")
        with os.fdopen(fd, "wb") as fp:
            fd = -1
            fp.write(payload)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
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


def _backup_keystore(ks_path: Path) -> Path:
    """Non-destructively move an unreadable/corrupt keystore to a timestamped .bak file."""
    ts = int(time.time())
    candidate = ks_path.with_name(f"{ks_path.name}.bak.{ts}")
    suffix = 1
    while candidate.exists():
        candidate = ks_path.with_name(f"{ks_path.name}.bak.{ts}.{suffix}")
        suffix += 1
    os.replace(ks_path, candidate)
    try:
        os.chmod(candidate, 0o600)
    except OSError:
        pass
    _LOG.warning("Backed up invalid keystore to %s before regeneration", candidate)
    return candidate


def _parse_keytool_entries(output: str) -> list[dict[str, str | None]]:
    """Parse `keytool -list -v` output into structured certificate entries."""
    normalized = output.replace("\r\n", "\n")
    chunks = re.split(r"(?m)^Alias name:\s*", normalized)
    entries: list[dict[str, str | None]] = []
    for chunk in chunks[1:]:
        lines = chunk.splitlines()
        if not lines:
            continue
        alias = lines[0].strip()
        body = "\n".join(lines[1:])

        entry_type_m = re.search(r"(?m)^Entry type:\s*(.+?)\s*$", body)
        subject_m = re.search(r"(?m)^Owner:\s*(.+?)\s*$", body)
        valid_m = re.search(r"(?m)^Valid from:.*?\buntil:\s*(.+?)\s*$", body)
        sha256_m = re.search(r"(?m)^\s*SHA-?256:\s*([0-9A-Fa-f:]+)\s*$", body)
        alg_m = re.search(r"(?m)^Signature algorithm name:\s*(.+?)\s*$", body)

        entries.append(
            {
                "alias": alias,
                "entry_type": entry_type_m.group(1).strip() if entry_type_m else None,
                "subject": subject_m.group(1).strip() if subject_m else None,
                "valid_until": valid_m.group(1).strip() if valid_m else None,
                "sha256": sha256_m.group(1).strip().upper() if sha256_m else None,
                "algorithm": alg_m.group(1).strip() if alg_m else None,
            }
        )
    return entries


def _verify_keystore_metadata(
    ks_path: Path,
    password: str,
    *,
    preferred_alias: str,
) -> dict[str, str | None]:
    """Verify a JKS/PKCS12 keystore with `keytool -list -v` using env-var password passing."""
    res = run_cmd(
        [
            "keytool",
            "-list",
            "-v",
            "-keystore",
            str(ks_path),
            "-storepass:env",
            "RD_KS_PASS",
        ],
        timeout=30,
        env={"RD_KS_PASS": password, "LC_ALL": "C", "LANG": "C"},
    )
    if res.returncode != 0:
        detail = res.clean_output[-400:] or "keytool doğrulama hatası"
        raise KeystoreError(f"Keystore doğrulanamadı: {detail}")

    entries = _parse_keytool_entries(res.stdout)
    private_entries = [e for e in entries if e.get("entry_type") == "PrivateKeyEntry"]
    if not private_entries:
        raise KeystoreError("Keystore içinde geçerli PrivateKeyEntry bulunamadı.")

    selected: dict[str, str | None] | None = None
    for entry in private_entries:
        alias = entry.get("alias") or ""
        if alias.lower() == preferred_alias.lower():
            selected = entry
            break
    if selected is None:
        if len(private_entries) == 1:
            selected = private_entries[0]
        else:
            raise KeystoreError(
                f"Keystore içinde '{preferred_alias}' takma adına sahip PrivateKeyEntry bulunamadı."
            )

    if not selected.get("sha256"):
        raise KeystoreError("Keystore sertifikasının SHA-256 parmak izi okunamadı.")

    return selected


def ensure_signing_keystore(settings: Settings | None = None) -> KeystoreState:
    """Ensure a valid RSA-2048 signing keystore exists, verified via `keytool -list -v`."""
    cfg = settings or get_settings()
    ks_path, resolved_persistent = resolve_keystore_path(cfg.KEYSTORE_PATH, cfg.WORK_DIR)
    persistent = (
        bool(cfg.KEYSTORE_PERSISTENT and resolved_persistent)
        if ks_path == cfg.KEYSTORE_PATH
        else resolved_persistent
    )
    if ks_path.parent.name == "_keystore":
        try:
            os.chmod(ks_path.parent, 0o700)
        except OSError:
            pass

    lock_path = ks_path.parent / f".{ks_path.name}.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            os.fchmod(lock_fd, 0o600)
        except OSError:
            pass
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        pass_file = ks_path.with_suffix(ks_path.suffix + ".pass")
        password_from_env = bool(cfg.KEYSTORE_PASS)
        password = ""

        if password_from_env:
            if len(cfg.KEYSTORE_PASS) < _MIN_PASSWORD_LEN:
                msg = "KEYSTORE_PASS en az 6 karakter olmalıdır."
                _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, msg)
                raise KeystoreError(msg)
            password = cfg.KEYSTORE_PASS
        else:
            if pass_file.is_file():
                try:
                    os.chmod(pass_file, 0o600)
                except OSError:
                    pass
                password = pass_file.read_text(encoding="utf-8").strip()
                if len(password) < _MIN_PASSWORD_LEN:
                    if ks_path.exists():
                        if not cfg.KEYSTORE_AUTO_REGEN:
                            msg = (
                                "Keystore parola dosyası (.pass) geçersiz veya 6 karakterden kısa. "
                                "Mevcut keystore korunuyor; düzeltin veya KEYSTORE_AUTO_REGEN=true ayarlayın."
                            )
                            _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, msg)
                            raise KeystoreError(msg)
                        _backup_keystore(ks_path)
                    password = secrets.token_urlsafe(32)
                    _write_pass_atomic(pass_file, password)
            else:
                if ks_path.exists():
                    if not cfg.KEYSTORE_AUTO_REGEN:
                        msg = (
                            "Mevcut keystore için parola bulunamadı (KEYSTORE_PASS veya .pass eksik). "
                            "Mevcut keystore silinmedi; doğru parolayı sağlayın veya "
                            "KEYSTORE_AUTO_REGEN=true ayarlayın."
                        )
                        _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, msg)
                        raise KeystoreError(msg)
                    _backup_keystore(ks_path)
                password = secrets.token_urlsafe(32)
                _write_pass_atomic(pass_file, password)

        # Verify existing keystore before trusting it
        if ks_path.exists():
            try:
                meta = _verify_keystore_metadata(
                    ks_path,
                    password,
                    preferred_alias=cfg.KEYSTORE_ALIAS,
                )
            except KeystoreError as exc:
                if not cfg.KEYSTORE_AUTO_REGEN:
                    _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, exc.detail)
                    raise
                _backup_keystore(ks_path)
                if not password_from_env:
                    password = secrets.token_urlsafe(32)
                    _write_pass_atomic(pass_file, password)
            else:
                try:
                    os.chmod(ks_path, 0o600)
                except OSError:
                    pass
                state = KeystoreState(
                    path=ks_path,
                    alias=str(meta.get("alias") or cfg.KEYSTORE_ALIAS),
                    ready=True,
                    persistent=persistent,
                    sha256=meta.get("sha256"),
                    subject=meta.get("subject"),
                    valid_until=meta.get("valid_until"),
                    algorithm=meta.get("algorithm"),
                    error=None,
                    _password=password,
                )
                return _set_state(state)

        # Generate a fresh RSA-2048 JKS keystore atomically with umask=0o077
        tmp_ks = ks_path.parent / f".{ks_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
        try:
            gen_res = run_cmd(
                [
                    "keytool",
                    "-genkeypair",
                    "-keystore",
                    str(tmp_ks),
                    "-storetype",
                    "JKS",
                    "-alias",
                    cfg.KEYSTORE_ALIAS,
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-sigalg",
                    "SHA256withRSA",
                    "-validity",
                    "10000",
                    "-storepass:env",
                    "RD_KS_PASS",
                    "-keypass:env",
                    "RD_KS_PASS",
                    "-dname",
                    "CN=RetroDroid Compat, OU=Compat, O=RetroDroid, C=TR",
                ],
                timeout=90,
                env={"RD_KS_PASS": password, "LC_ALL": "C", "LANG": "C"},
                umask=0o077,
            )
            if gen_res.returncode != 0 or not tmp_ks.is_file():
                msg = f"İmzalama anahtarı oluşturulamadı: {gen_res.clean_output[-500:]}"
                _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, msg)
                raise KeystoreError(msg)

            meta = _verify_keystore_metadata(
                tmp_ks,
                password,
                preferred_alias=cfg.KEYSTORE_ALIAS,
            )
            try:
                os.chmod(tmp_ks, 0o600)
            except OSError:
                pass
            os.replace(tmp_ks, ks_path)
            try:
                os.chmod(ks_path, 0o600)
            except OSError:
                pass

            state = KeystoreState(
                path=ks_path,
                alias=str(meta.get("alias") or cfg.KEYSTORE_ALIAS),
                ready=True,
                persistent=persistent,
                sha256=meta.get("sha256"),
                subject=meta.get("subject"),
                valid_until=meta.get("valid_until"),
                algorithm=meta.get("algorithm"),
                error=None,
                _password=password,
            )
            return _set_state(state)
        except Exception as exc:
            try:
                tmp_ks.unlink(missing_ok=True)
            except OSError:
                pass
            if isinstance(exc, KeystoreError):
                _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, exc.detail)
                raise
            detail = f"Keystore oluşturma hatası: {exc}"
            _set_failed_state(ks_path, cfg.KEYSTORE_ALIAS, persistent, detail)
            raise KeystoreError(detail) from exc
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
