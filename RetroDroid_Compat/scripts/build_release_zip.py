"""Deterministic release archive builder for RetroDroid Compat v5.4.0."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import re
import stat
import uuid
import zipfile
from pathlib import Path
from typing import Any

DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_ZIP = DEFAULT_REPO_ROOT.parent / "RetroDroid_Compat_v5.4.0.zip"
DEFAULT_ARCHIVE_PREFIX = "RetroDroid_Compat_v5.4.0"
FIXED_ZIP_DATETIME: tuple[int, int, int, int, int, int] = (2026, 1, 1, 0, 0, 0)

_UNIX_SYSTEM = 3
_DIR_EXTERNAL_ATTR = ((stat.S_IFDIR | 0o755) << 16) | 0x10
_FILE_EXTERNAL_ATTR = (stat.S_IFREG | 0o644) << 16

_ROOT_ALLOWLIST: tuple[str, ...] = (
    ".dockerignore",
    "Dockerfile",
    "README.txt",
    "index.html",
    "requirements.txt",
    "server.py",
)

_STATIC_ROOT_ALLOWLIST: tuple[str, ...] = (
    "static/app.js",
    "static/styles.css",
)

_ALLOWED_VENDOR_EXTS: frozenset[str] = frozenset({".js", ".css", ".txt", ".json", ".map"})

_REQUIRED_REL_PATHS: tuple[str, ...] = (
    ".dockerignore",
    "Dockerfile",
    "README.txt",
    "index.html",
    "requirements.txt",
    "server.py",
    "retrodroid/__init__.py",
    "retrodroid/config.py",
    "retrodroid/keystore.py",
    "retrodroid/axml.py",
    "retrodroid/inspector.py",
    "retrodroid/patcher.py",
    "retrodroid/containers.py",
    "retrodroid/jobs.py",
    "static/styles.css",
    "static/app.js",
    "static/vendor/jszip.js",
)

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".github",
        ".agents",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "node_modules",
        "tests",
        "scripts",
    }
)

_EXCLUDED_NAME_PATTERNS: tuple[str, ...] = (
    ".git",
    ".gitignore",
    ".env",
    ".env.*",
    "*.py[cod]",
    "*$py.class",
    "*.jks",
    "*.jks.*",
    "*.keystore",
    "*.keystore.*",
    "*.pass",
    "*.pass.*",
    "*.bak*",
    "*.apk",
    "*.xapk",
    "*.apks",
    "*.apkm",
    "*.obb",
    "*.zip",
    "*.log",
    "*.tmp",
    ".DS_Store",
    "Thumbs.db",
)

_TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".py",
        ".html",
        ".css",
        ".js",
        ".mjs",
        ".txt",
        ".md",
        ".json",
        ".yml",
        ".yaml",
        ".map",
    }
)

_TEXT_BASENAMES: frozenset[str] = frozenset(
    {
        "Dockerfile",
        ".dockerignore",
    }
)


def _is_excluded_relpath(rel_posix: str) -> bool:
    """Return True if a POSIX relative path matches any defense-in-depth exclusion rule."""
    parts = [p for p in rel_posix.split("/") if p]
    if not parts:
        return True
    for part in parts[:-1]:
        if part in _EXCLUDED_DIR_NAMES or part.startswith("."):
            return True
    leaf = parts[-1]
    if leaf in _EXCLUDED_DIR_NAMES:
        return True
    if leaf != ".dockerignore" and leaf.startswith("."):
        return True
    leaf_lower = leaf.lower()
    return any(fnmatch.fnmatchcase(leaf_lower, pat.lower()) for pat in _EXCLUDED_NAME_PATTERNS)


def _is_text_deliverable(path: Path) -> bool:
    """Return True when a production deliverable is expected to be UTF-8 LF text."""
    return path.name in _TEXT_BASENAMES or path.suffix.lower() in _TEXT_SUFFIXES


def _normalize_text_bytes(raw: bytes, rel_posix: str) -> tuple[bytes, bool]:
    """Validate UTF-8 text, strip CR/CRLF to LF, and guarantee a trailing LF newline."""
    if b"\x00" in raw:
        raise ValueError(f"Null byte detected in text deliverable: {rel_posix}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Non-UTF-8 content in text deliverable {rel_posix}: {exc}") from exc

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    out = normalized.encode("utf-8")
    return out, (out != raw)


def _collect_deliverables(repo_root: Path) -> list[tuple[str, Path]]:
    """Collect sorted `(rel_posix, abs_path)` production deliverables under `repo_root`."""
    if not repo_root.is_dir():
        raise FileNotFoundError(f"Repository root directory does not exist: {repo_root}")

    root_resolved = repo_root.resolve()
    candidates: dict[str, Path] = {}

    def _add_candidate(rel_posix: str, abs_path: Path) -> None:
        if _is_excluded_relpath(rel_posix):
            return
        if abs_path.is_symlink():
            raise ValueError(f"Refusing to package symlink deliverable: {rel_posix}")
        resolved = abs_path.resolve()
        if not resolved.is_relative_to(root_resolved):
            raise ValueError(f"Deliverable escapes repository root: {rel_posix}")
        if not resolved.is_file():
            return
        candidates[rel_posix] = resolved

    for rel in _ROOT_ALLOWLIST:
        _add_candidate(rel, repo_root / rel)

    retrodroid_dir = repo_root / "retrodroid"
    if retrodroid_dir.is_symlink():
        raise ValueError("Refusing to package symlink directory: retrodroid")
    if retrodroid_dir.is_dir():
        for child in sorted(retrodroid_dir.iterdir(), key=lambda p: p.name):
            if child.suffix == ".py" and not child.name.startswith("."):
                _add_candidate(f"retrodroid/{child.name}", child)

    static_dir = repo_root / "static"
    if static_dir.is_symlink():
        raise ValueError("Refusing to package symlink directory: static")

    for rel in _STATIC_ROOT_ALLOWLIST:
        _add_candidate(rel, repo_root / rel)

    vendor_dir = static_dir / "vendor"
    if vendor_dir.is_symlink():
        raise ValueError("Refusing to package symlink directory: static/vendor")
    if vendor_dir.is_dir():
        for child in sorted(vendor_dir.iterdir(), key=lambda p: p.name):
            if child.suffix.lower() in _ALLOWED_VENDOR_EXTS and not child.name.startswith("."):
                _add_candidate(f"static/vendor/{child.name}", child)

    missing = [req for req in _REQUIRED_REL_PATHS if req not in candidates]
    if missing:
        raise FileNotFoundError(
            f"Missing required production deliverable(s) in {repo_root}: {', '.join(missing)}"
        )

    return sorted(candidates.items(), key=lambda item: item[0])


def _make_dir_zipinfo(arc_dir: str) -> zipfile.ZipInfo:
    arc_norm = arc_dir.rstrip("/") + "/"
    zinfo = zipfile.ZipInfo(filename=arc_norm, date_time=FIXED_ZIP_DATETIME)
    zinfo.create_system = _UNIX_SYSTEM
    zinfo.compress_type = zipfile.ZIP_STORED
    zinfo.external_attr = _DIR_EXTERNAL_ATTR
    zinfo.flag_bits = 0
    return zinfo


def _make_file_zipinfo(arc_file: str) -> zipfile.ZipInfo:
    zinfo = zipfile.ZipInfo(filename=arc_file, date_time=FIXED_ZIP_DATETIME)
    zinfo.create_system = _UNIX_SYSTEM
    zinfo.compress_type = zipfile.ZIP_DEFLATED
    zinfo.external_attr = _FILE_EXTERNAL_ATTR
    zinfo.flag_bits = 0
    return zinfo


def build_release_zip(
    repo_root: Path,
    output_zip: Path,
    *,
    archive_prefix: str = DEFAULT_ARCHIVE_PREFIX,
) -> dict[str, Any]:
    """Build a deterministic, clean, LF-normalized v5.4.0 release ZIP archive atomically."""
    src_root = Path(repo_root)
    dst_zip = Path(output_zip)
    if (
        not isinstance(archive_prefix, str)
        or archive_prefix in {".", ".."}
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", archive_prefix) is None
    ):
        raise ValueError(f"Invalid archive_prefix: {archive_prefix!r}")
    prefix = archive_prefix

    deliverables = _collect_deliverables(src_root)

    dir_set: set[str] = {f"{prefix}/"}
    for rel_posix, _ in deliverables:
        parts = rel_posix.split("/")
        for depth in range(1, len(parts)):
            sub_dir = "/".join(parts[:depth])
            dir_set.add(f"{prefix}/{sub_dir}/")

    sorted_dirs = sorted(dir_set)
    prepared_files: list[tuple[str, bytes]] = []
    normalized_files: list[str] = []

    for rel_posix, abs_path in deliverables:
        raw_bytes = abs_path.read_bytes()
        if _is_text_deliverable(abs_path):
            payload, changed = _normalize_text_bytes(raw_bytes, rel_posix)
            if changed:
                normalized_files.append(rel_posix)
        else:
            payload = raw_bytes
        prepared_files.append((f"{prefix}/{rel_posix}", payload))

    combined_entries: list[tuple[str, zipfile.ZipInfo, bytes, bool]] = [
        (arc_dir.rstrip("/") + "/", _make_dir_zipinfo(arc_dir), b"", True)
        for arc_dir in sorted_dirs
    ] + [
        (arc_file, _make_file_zipinfo(arc_file), payload, False)
        for arc_file, payload in prepared_files
    ]
    combined_entries.sort(key=lambda item: item[0])

    dst_zip.parent.mkdir(parents=True, exist_ok=True)
    tmp_zip = dst_zip.parent / f".{dst_zip.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    fd = os.open(tmp_zip, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        try:
            os.fchmod(fd, 0o644)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as raw_fp:
            fd = -1
            with zipfile.ZipFile(
                raw_fp,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as zf:
                for _, zinfo, payload, is_dir in combined_entries:
                    if is_dir:
                        zf.writestr(zinfo, b"", compress_type=zipfile.ZIP_STORED)
                    else:
                        zf.writestr(
                            zinfo,
                            payload,
                            compress_type=zipfile.ZIP_DEFLATED,
                            compresslevel=9,
                        )
            raw_fp.flush()
            os.fsync(raw_fp.fileno())

        with zipfile.ZipFile(tmp_zip, mode="r") as verify_zf:
            bad_member = verify_zf.testzip()
            if bad_member is not None:
                raise RuntimeError(f"Corrupt ZIP entry detected after build: {bad_member}")
            entry_names = verify_zf.namelist()

        os.replace(tmp_zip, dst_zip)
        try:
            os.chmod(dst_zip, 0o644)
        except OSError:
            pass
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp_zip.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    digest = hashlib.sha256(dst_zip.read_bytes()).hexdigest()
    size_bytes = dst_zip.stat().st_size
    return {
        "output_zip": str(dst_zip),
        "archive_prefix": prefix,
        "sha256": digest,
        "size_bytes": size_bytes,
        "dir_count": len(sorted_dirs),
        "file_count": len(prepared_files),
        "entries": entry_names,
        "normalized_files": normalized_files,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build deterministic RetroDroid Compat v5.4.0 release archive.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Path to RetroDroid_Compat repository root (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_ZIP,
        help="Destination path for release .zip (default: %(default)s)",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default=DEFAULT_ARCHIVE_PREFIX,
        help="Top-level directory prefix inside archive (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    summary = build_release_zip(args.root, args.output, archive_prefix=args.prefix)
    print(
        f"Built {summary['output_zip']} "
        f"({summary['file_count']} files, {summary['dir_count']} dirs, "
        f"{summary['size_bytes']} bytes, sha256={summary['sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
