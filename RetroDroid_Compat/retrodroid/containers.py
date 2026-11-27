"""Spec-compliant XAPK/APKM/APKS/ZIP container unpacker, OBB path normalizer, icon extractor, and XAPK v2 builder."""

from __future__ import annotations

import io
import json
import os
import posixpath
import re
import threading
import uuid
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from retrodroid.config import (
    CommandCanceledError,
    InvalidArchiveError,
    PayloadTooLargeError,
    RetroDroidError,
    copy_stream_limited,
    get_settings,
    run_cmd,
    sanitize_filename,
    write_json_atomic,
)

__all__ = [
    "InvalidArchiveError",
    "build_full_xapk",
    "extract_apk_icon_png",
    "extract_container_obb_atomic",
    "normalize_obb_relpath",
    "unpack_container_if_needed",
    "validate_obb_filename",
]

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_OBB_NAME_RE = re.compile(
    r"^(main|patch)\.(\d+)\.([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)\.obb$"
)
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_DPI_ORDER: dict[str, int] = {
    "xxxhdpi": 6,
    "xxhdpi": 5,
    "xhdpi": 4,
    "hdpi": 3,
    "mdpi": 2,
    "ldpi": 1,
}


def _normalize_zip_path(raw: str) -> str:
    """Normalize ZIP member path backslashes and reject traversal/absolute/null paths."""
    if "\x00" in raw:
        raise InvalidArchiveError("Arşiv dosya yolu geçersiz NUL baytı içeriyor.")
    norm = raw.replace("\\", "/")
    if norm.startswith(("/", "~")) or _WINDOWS_DRIVE_RE.match(norm):
        raise InvalidArchiveError(f"Arşiv içinde güvensiz mutlak yol tespit edildi: {raw!r}")
    parts = [p for p in norm.split("/") if p and p != "."]
    if any(part == ".." for part in parts):
        raise InvalidArchiveError(f"Arşiv içinde dizin geçişi (..) tespit edildi: {raw!r}")
    return "/".join(parts)


def _is_macos_metadata(norm_path: str) -> bool:
    parts = norm_path.split("/")
    if parts and parts[0] == "__MACOSX":
        return True
    base = parts[-1] if parts else ""
    return base.startswith("._")


def _read_zip_json_limited(
    z: zipfile.ZipFile,
    item: zipfile.ZipInfo,
    limit: int = 2 * 1024 * 1024,
) -> dict[str, Any] | None:
    if item.file_size < 0 or item.file_size > limit:
        return None
    buf = io.BytesIO()
    try:
        with z.open(item, "r") as rfp:
            copy_stream_limited(rfp, buf, limit, f"Manifest ({item.filename})")
        parsed = json.loads(buf.getvalue().decode("utf-8", errors="replace"))
        return parsed if isinstance(parsed, dict) else None
    except (
        ValueError,
        OSError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
        EOFError,
        RuntimeError,
        PayloadTooLargeError,
    ):
        return None


def _match_apk_entry(
    candidate: str | None,
    inner_apks: list[tuple[zipfile.ZipInfo, str]],
) -> tuple[zipfile.ZipInfo, str] | None:
    if not candidate or not isinstance(candidate, str):
        return None
    cand_norm = candidate.replace("\\", "/").strip().lstrip("./")
    if not cand_norm:
        return None
    cand_low = cand_norm.lower()
    cand_base = posixpath.basename(cand_low)

    for pair in inner_apks:
        if pair[1].lower() == cand_low:
            return pair
    for pair in inner_apks:
        if posixpath.basename(pair[1]).lower() == cand_base:
            return pair
    return None


def _score_base_apk(pair: tuple[zipfile.ZipInfo, str]) -> tuple[int, int, int]:
    info, norm = pair
    base = posixpath.basename(norm).lower()
    depth = norm.count("/")
    if base == "base.apk":
        tier = 0
    elif base.startswith(("config.", "split_config.", "split.")):
        tier = 2
    else:
        tier = 1
    return (tier, depth, -int(info.file_size or 0))


def unpack_container_if_needed(
    uploaded_path: Path,
    job_dir: Path,
    max_entries: int = 25000,
    max_bytes: int | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Validate and unpack XAPK/APKM/APKS/ZIP containers with manifest-first base APK resolution."""
    up = Path(uploaded_path)
    jdir = Path(job_dir)
    limit = int(max_bytes) if max_bytes is not None else get_settings().MAX_DECOMPRESSED_BYTES

    default_meta: dict[str, Any] = {
        "isContainer": False,
        "containerType": "APK",
        "archive": str(up),
        "extractedApkPath": str(up),
        "innerApkName": up.name,
        "manifestSource": None,
        "splitApks": [],
        "obbFiles": [],
    }

    try:
        z = zipfile.ZipFile(up, "r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, zlib.error, EOFError, RuntimeError) as exc:
        raise InvalidArchiveError("Geçerli bir ZIP/APK/XAPK arşivi değil veya bozuk.") from exc

    with z:
        infos = z.infolist()
        if len(infos) > max_entries:
            raise PayloadTooLargeError(
                f"Arşiv çok fazla dosya içeriyor ({len(infos)} > {max_entries})."
            )

        total_declared = 0
        normalized_items: list[tuple[zipfile.ZipInfo, str]] = []
        has_root_manifest = False

        for info in infos:
            if info.flag_bits & 0x1:
                raise InvalidArchiveError(
                    f"Şifreli arşiv girdisi desteklenmiyor: {info.filename!r}"
                )
            if info.file_size < 0 or info.file_size > limit:
                raise PayloadTooLargeError(
                    f"Arşiv girdisi boyut sınırını aşıyor ({info.filename}: {info.file_size} bayt)."
                )
            total_declared += info.file_size
            if total_declared > limit:
                raise PayloadTooLargeError(
                    f"Arşiv toplam açılmış boyutu sınırı aşıyor ({total_declared} > {limit} bayt)."
                )

            norm = _normalize_zip_path(info.filename)
            if info.is_dir() or info.filename.endswith(("/", "\\")) or not norm:
                continue
            if norm == "AndroidManifest.xml":
                has_root_manifest = True
            normalized_items.append((info, norm))

        if has_root_manifest:
            return up, default_meta

        inner_apks: list[tuple[zipfile.ZipInfo, str]] = []
        inner_obbs: list[tuple[zipfile.ZipInfo, str]] = []
        manifest_json_items: list[tuple[zipfile.ZipInfo, str]] = []
        info_json_items: list[tuple[zipfile.ZipInfo, str]] = []

        seen_apk_bases: set[str] = set()
        seen_sanitized_apk_bases: set[str] = set()

        for info, norm in normalized_items:
            if _is_macos_metadata(norm):
                continue
            base = posixpath.basename(norm)
            low_base = base.lower()

            if low_base.endswith(".apk"):
                sanitized_base = sanitize_filename(base, default="app.apk").lower()
                if low_base in seen_apk_bases or sanitized_base in seen_sanitized_apk_bases:
                    raise InvalidArchiveError(
                        f"Arşivde çakışan APK dosya adı tespit edildi: {base!r}"
                    )
                seen_apk_bases.add(low_base)
                seen_sanitized_apk_bases.add(sanitized_base)
                inner_apks.append((info, norm))
            elif low_base.endswith(".obb"):
                inner_obbs.append((info, norm))
            elif low_base == "manifest.json":
                manifest_json_items.append((info, norm))
            elif low_base == "info.json":
                info_json_items.append((info, norm))

        if not inner_apks:
            return up, default_meta

        chosen: tuple[zipfile.ZipInfo, str] | None = None
        manifest_source: str | None = None
        parsed_xapk_manifest: dict[str, Any] | None = None
        parsed_apkm_info: dict[str, Any] | None = None

        # Priority 1: XAPK manifest.json
        manifest_json_items.sort(key=lambda pair: pair[1].count("/"))
        for mj_info, _ in manifest_json_items:
            parsed = _read_zip_json_limited(z, mj_info)
            if not parsed:
                continue
            if parsed_xapk_manifest is None and any(
                key in parsed
                for key in ("xapk_version", "expansions", "split_apks", "package_name", "apk")
            ):
                parsed_xapk_manifest = parsed
            split_defs = parsed.get("split_apks")
            if isinstance(split_defs, list):
                for sdef in split_defs:
                    if isinstance(sdef, dict) and str(sdef.get("id", "")).lower() == "base":
                        chosen = _match_apk_entry(sdef.get("file"), inner_apks)
                        if chosen is not None:
                            manifest_source = "xapk_manifest.json"
                            parsed_xapk_manifest = parsed
                            break
            if chosen is None and isinstance(parsed.get("apk"), str):
                chosen = _match_apk_entry(parsed.get("apk"), inner_apks)
                if chosen is not None:
                    manifest_source = "xapk_manifest.json"
                    parsed_xapk_manifest = parsed
            if chosen is None and isinstance(parsed.get("package_name"), str):
                chosen = _match_apk_entry(f"{parsed['package_name']}.apk", inner_apks)
                if chosen is not None:
                    manifest_source = "xapk_manifest.json"
                    parsed_xapk_manifest = parsed
            if chosen is not None:
                break

        # Priority 2: APKM info.json
        if chosen is None:
            info_json_items.sort(key=lambda pair: pair[1].count("/"))
            for ij_info, _ in info_json_items:
                parsed = _read_zip_json_limited(z, ij_info)
                if not parsed:
                    continue
                if parsed_apkm_info is None and any(
                    key in parsed
                    for key in ("base_apk", "pname", "apkm_version", "bundle_version")
                ):
                    parsed_apkm_info = parsed
                if isinstance(parsed.get("base_apk"), str):
                    chosen = _match_apk_entry(parsed.get("base_apk"), inner_apks)
                    if chosen is not None:
                        manifest_source = "apkm_info.json"
                        parsed_apkm_info = parsed
                if chosen is None:
                    chosen = _match_apk_entry("base.apk", inner_apks)
                    if chosen is not None:
                        manifest_source = "apkm_info.json"
                        parsed_apkm_info = parsed
                if chosen is None and isinstance(parsed.get("pname"), str):
                    chosen = _match_apk_entry(f"{parsed['pname']}.apk", inner_apks)
                    if chosen is not None:
                        manifest_source = "apkm_info.json"
                        parsed_apkm_info = parsed
                if chosen is not None:
                    break

        # Priority 3: Heuristic score_base fallback
        if chosen is None:
            chosen = min(inner_apks, key=_score_base_apk)
            manifest_source = "heuristic"

        chosen_info, chosen_norm = chosen
        safe_base_name = sanitize_filename(posixpath.basename(chosen_norm), default="base.apk")
        extracted_dir = jdir / "_extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(extracted_dir, 0o755)
        except OSError:
            pass
        extracted_apk = extracted_dir / safe_base_name

        tmp_apk = extracted_dir / f".{safe_base_name}.{uuid.uuid4().hex[:8]}.tmp"
        try:
            with z.open(chosen_info, "r") as rfp, open(tmp_apk, "wb") as wfp:
                copy_stream_limited(rfp, wfp, limit, f"Taban APK ({safe_base_name})")
            try:
                os.chmod(tmp_apk, 0o644)
            except OSError:
                pass
            os.replace(tmp_apk, extracted_apk)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError) as exc:
            tmp_apk.unlink(missing_ok=True)
            raise InvalidArchiveError(
                f"Konteyner arşivi bozuk, kesik veya şifreli: {exc}"
            ) from exc
        except Exception:
            tmp_apk.unlink(missing_ok=True)
            raise

        # Build split APK list (all inner APKs other than chosen base)
        split_apks: list[dict[str, Any]] = []
        for sp_info, sp_norm in inner_apks:
            if sp_info.filename == chosen_info.filename:
                continue
            sp_safe = sanitize_filename(posixpath.basename(sp_norm), default="split.apk")
            split_apks.append(
                {
                    "name": sp_safe,
                    "zipEntry": sp_info.filename,
                    "normalizedEntry": sp_norm,
                    "sizeBytes": int(sp_info.file_size or 0),
                }
            )

        # Consult XAPK manifest.json expansions metadata (if present) for OBB install paths
        expansion_install_paths: dict[str, str] = {}
        if parsed_xapk_manifest and isinstance(parsed_xapk_manifest.get("expansions"), list):
            for exp in parsed_xapk_manifest["expansions"]:
                if not isinstance(exp, dict):
                    continue
                exp_file = exp.get("file")
                exp_install = exp.get("install_path")
                if not isinstance(exp_file, str) or not isinstance(exp_install, str):
                    continue
                try:
                    norm_file = _normalize_zip_path(exp_file)
                    norm_install = _normalize_zip_path(exp_install)
                except InvalidArchiveError:
                    continue
                if norm_file and norm_install and norm_install.lower().endswith(".obb"):
                    expansion_install_paths[norm_file.lower()] = norm_install

        # Build disambiguated OBB catalog (preserving exact original zipEntry)
        obb_base_counts: dict[str, int] = {}
        raw_obbs: list[tuple[zipfile.ZipInfo, str, str]] = []
        for obb_info, obb_norm in inner_obbs:
            safe_obb = sanitize_filename(posixpath.basename(obb_norm), default="main.obb")
            key = safe_obb.lower()
            obb_base_counts[key] = obb_base_counts.get(key, 0) + 1
            raw_obbs.append((obb_info, obb_norm, safe_obb))

        obb_files: list[dict[str, Any]] = []
        used_obb_names: set[str] = set()
        for idx, (obb_info, obb_norm, safe_obb) in enumerate(raw_obbs):
            was_disambiguated = (
                obb_base_counts.get(safe_obb.lower(), 0) > 1 or safe_obb.lower() in used_obb_names
            )
            if was_disambiguated:
                disamb = sanitize_filename(f"{idx}_{safe_obb}", default=f"{idx}_main.obb")
                counter = 1
                while disamb.lower() in used_obb_names:
                    disamb = sanitize_filename(
                        f"{idx}_{counter}_{safe_obb}",
                        default=f"{idx}_{counter}_main.obb",
                    )
                    counter += 1
                final_name = disamb
            else:
                final_name = safe_obb
            used_obb_names.add(final_name.lower())
            obb_entry: dict[str, Any] = {
                "name": final_name,
                "originalName": posixpath.basename(obb_norm),
                "disambiguated": was_disambiguated,
                "zipEntry": obb_info.filename,
                "normalizedEntry": obb_norm,
                "sizeBytes": int(obb_info.file_size or 0),
            }
            install_path = expansion_install_paths.get(obb_norm.lower())
            if install_path:
                obb_entry["installPath"] = install_path
            obb_files.append(obb_entry)

        ext_low = up.suffix.lower()
        is_xapk_manifest = parsed_xapk_manifest is not None and any(
            key in parsed_xapk_manifest
            for key in ("xapk_version", "expansions", "split_apks", "package_name")
        )
        if ext_low == ".xapk" or manifest_source == "xapk_manifest.json" or is_xapk_manifest:
            container_type = "XAPK"
        elif ext_low == ".apkm" or manifest_source == "apkm_info.json" or parsed_apkm_info is not None:
            container_type = "APKM"
        elif ext_low == ".apks":
            container_type = "APKS"
        else:
            container_type = "ZIP"

        meta: dict[str, Any] = {
            "isContainer": True,
            "containerType": container_type,
            "archive": str(up),
            "extractedApkPath": str(extracted_apk),
            "innerApkName": safe_base_name,
            "chosenZipEntry": chosen_info.filename,
            "manifestSource": manifest_source,
            "splitApks": split_apks,
            "obbFiles": obb_files,
        }
        write_json_atomic(jdir / "container_meta.json", meta)
        return extracted_apk, meta


# ---------------------------------------------------------------------------
# OBB Path Normalizer & Filename Validator
# ---------------------------------------------------------------------------


def normalize_obb_relpath(raw_name: str, package_id: str) -> str:
    """Normalize an OBB relative path to prevent Android/obb/<pkg>/<pkg>/ double-nesting."""
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise InvalidArchiveError("OBB dosya yolu boş olamaz.")
    if "\x00" in raw_name:
        raise InvalidArchiveError("OBB dosya yolu geçersiz NUL baytı içeriyor.")

    norm = raw_name.strip().replace("\\", "/")
    if norm.startswith(("/", "~")) or _WINDOWS_DRIVE_RE.match(norm):
        raise InvalidArchiveError(f"OBB dosya yolu mutlak olamaz: {raw_name!r}")

    parts = [p for p in norm.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise InvalidArchiveError(f"OBB dosya yolu güvensiz dizin geçişi içeriyor: {raw_name!r}")

    pkg = (package_id or "").strip().lower()

    # Step 1: drop everything up through the LAST .../android/obb/ prefix
    while True:
        lower_parts = [p.lower() for p in parts]
        last_ao_idx: int | None = None
        for i in range(len(lower_parts) - 1):
            if lower_parts[i] == "android" and lower_parts[i + 1] == "obb" and i + 2 < len(parts):
                last_ao_idx = i
        if last_ao_idx is None:
            break
        parts = parts[last_ao_idx + 2 :]

    # Step 2: drop leading "obb" segments
    while len(parts) > 1 and parts[0].lower() == "obb":
        parts = parts[1:]

    # Step 3: drop leading <package_id> segments
    while len(parts) > 1 and pkg and parts[0].lower() == pkg:
        parts = parts[1:]

    # Step 4: drop wrapper folders preceding the LAST <package_id> directory segment
    if len(parts) > 1 and pkg:
        last_pkg_idx: int | None = None
        for i, seg in enumerate(parts[:-1]):
            if seg.lower() == pkg:
                last_pkg_idx = i
        if last_pkg_idx is not None:
            parts = parts[last_pkg_idx + 1 :]

    sanitized_parts = [sanitize_filename(seg, default="obb_file") for seg in parts]
    return "/".join(sanitized_parts)


def validate_obb_filename(
    name: str,
    package_id: str,
    version_code: str | int | None = None,
) -> dict[str, Any]:
    """Validate canonical Android OBB filename `(main|patch).<versionCode>.<packageId>.obb`."""
    pkg = (package_id or "").strip()
    ver_str = str(version_code).strip() if version_code not in (None, "") else "1"
    if not ver_str.isdigit():
        ver_str = "1"
    suggested = f"main.{ver_str}.{pkg}.obb" if pkg else f"main.{ver_str}.com.example.app.obb"

    base = posixpath.basename(str(name or "").replace("\\", "/"))
    match = _OBB_NAME_RE.fullmatch(base)
    if not match:
        return {
            "valid": False,
            "kind": None,
            "versionCode": None,
            "obbPackageId": None,
            "packageMatches": False,
            "warning": (
                f"'{base}' standart Android OBB adlandırma kuralına "
                f"((main|patch).<versionCode>.<packageId>.obb) uymuyor. Önerilen: {suggested}"
            ),
            "suggestedName": suggested,
        }

    kind = match.group(1)
    obb_ver = int(match.group(2))
    obb_pkg = match.group(3)
    pkg_matches = bool(pkg and obb_pkg == pkg)

    warning: str | None = None
    if pkg and not pkg_matches:
        warning = (
            f"OBB paket adı ('{obb_pkg}') APK paket adıyla ('{pkg}') birebir eşleşmiyor. "
            f"Önerilen: {kind}.{obb_ver}.{pkg}.obb"
        )
        suggested = f"{kind}.{obb_ver}.{pkg}.obb"

    return {
        "valid": pkg_matches if pkg else True,
        "kind": kind,
        "versionCode": obb_ver,
        "obbPackageId": obb_pkg,
        "packageMatches": pkg_matches,
        "warning": warning,
        "suggestedName": suggested,
    }


# ---------------------------------------------------------------------------
# Icon Extraction, Atomic OBB Extraction & XAPK v2 Builder
# ---------------------------------------------------------------------------


def _read_png_entry_if_valid(
    z: zipfile.ZipFile,
    entry_name: str,
    max_bytes: int,
) -> bytes | None:
    try:
        info = z.getinfo(entry_name)
    except KeyError:
        return None
    if info.is_dir() or info.file_size <= len(PNG_MAGIC) or info.file_size > max_bytes:
        return None
    buf = io.BytesIO()
    try:
        with z.open(info, "r") as rfp:
            copy_stream_limited(rfp, buf, max_bytes, f"Icon ({entry_name})")
        raw = buf.getvalue()
        return raw if raw.startswith(PNG_MAGIC) else None
    except (
        OSError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
        EOFError,
        RuntimeError,
        PayloadTooLargeError,
    ):
        return None


def _dpi_rank(entry_name: str) -> int:
    low = entry_name.lower()
    for token, rank in _DPI_ORDER.items():
        if token in low:
            return rank
    return 0


def extract_apk_icon_png(
    apk_path: Path,
    preferred_icon_path: str | None = None,
    max_bytes: int = 4 * 1024 * 1024,
) -> bytes | None:
    """Extract the highest-DPI valid PNG icon from an APK (bounded by max_bytes)."""
    path = Path(apk_path)
    if not path.is_file():
        return None

    try:
        with zipfile.ZipFile(path, "r") as z:
            if preferred_icon_path and preferred_icon_path.lower().endswith(".png"):
                data = _read_png_entry_if_valid(z, preferred_icon_path, max_bytes)
                if data is not None:
                    return data

            # Try aapt dump badging icon declarations
            try:
                res = run_cmd(["aapt", "dump", "badging", str(path)], timeout=20)
                if res.returncode == 0 and res.stdout:
                    out = res.stdout.replace("\r\n", "\n")
                    dpi_icons = sorted(
                        (
                            (int(dpi), p)
                            for dpi, p in re.findall(
                                r"^application-icon-(\d+):'([^']+\.png)'",
                                out,
                                re.IGNORECASE | re.MULTILINE,
                            )
                        ),
                        key=lambda pair: pair[0],
                        reverse=True,
                    )
                    app_m = re.search(
                        r"^application:.*?icon='([^']+\.png)'",
                        out,
                        re.IGNORECASE | re.MULTILINE,
                    )
                    candidates = [p for _, p in dpi_icons]
                    if app_m:
                        candidates.append(app_m.group(1))
                    for cand in candidates:
                        data = _read_png_entry_if_valid(z, cand, max_bytes)
                        if data is not None:
                            return data
            except RetroDroidError:
                pass

            # Fallback: ranked ZIP scan of res/(mipmap|drawable)*/...*.png
            png_candidates: list[tuple[tuple[int, int, int, int], str]] = []
            for item in z.infolist():
                if item.is_dir():
                    continue
                fname = item.filename
                low = fname.lower()
                if not low.endswith(".png"):
                    continue
                if not re.match(r"^res/(?:mipmap|drawable)[^/]*/.+\.png$", low):
                    continue
                if item.file_size <= len(PNG_MAGIC) or item.file_size > max_bytes:
                    continue
                is_mipmap = 1 if low.startswith("res/mipmap") else 0
                base = posixpath.basename(low)
                name_score = 2 if "ic_launcher" in base else (1 if "icon" in base else 0)
                dpi_score = _dpi_rank(low)
                png_candidates.append(((is_mipmap, name_score, dpi_score, item.file_size), fname))

            png_candidates.sort(key=lambda pair: pair[0], reverse=True)
            for _, fname in png_candidates:
                data = _read_png_entry_if_valid(z, fname, max_bytes)
                if data is not None:
                    return data
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, zlib.error, EOFError, RuntimeError):
        return None
    return None


def extract_container_obb_atomic(
    job_dir: Path,
    container_meta: dict[str, Any],
    obb_index: int,
    max_bytes: int | None = None,
) -> Path:
    """Atomically extract and cache a container OBB entry by index into job_dir/_extracted_obb/."""
    jdir = Path(job_dir)
    limit = int(max_bytes) if max_bytes is not None else get_settings().MAX_DECOMPRESSED_BYTES

    obb_files = container_meta.get("obbFiles") if isinstance(container_meta, dict) else None
    if not isinstance(obb_files, list) or obb_index < 0 or obb_index >= len(obb_files):
        raise InvalidArchiveError(f"Geçersiz OBB indeksi: {obb_index}", status_code=404)

    obb_meta = obb_files[obb_index]
    zip_entry = obb_meta.get("zipEntry")
    if not isinstance(zip_entry, str) or not zip_entry:
        raise InvalidArchiveError("OBB arşiv giriş yolu eksik.")
    _normalize_zip_path(zip_entry)

    archive_raw = container_meta.get("archive")
    archive_path = Path(archive_raw) if archive_raw else None
    if archive_path is None or not archive_path.is_file():
        raise InvalidArchiveError("Kaynak konteyner arşivi bulunamadı.", status_code=404)

    safe_name = sanitize_filename(str(obb_meta.get("name") or f"obb_{obb_index}.obb"), default="main.obb")
    out_dir = jdir / "_extracted_obb"
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{obb_index}_{safe_name}"
    if target.is_file():
        return target

    tmp = out_dir / f".{target.name}.{uuid.uuid4().hex[:8]}.tmp"
    try:
        with zipfile.ZipFile(archive_path, "r") as zarch:
            info = zarch.getinfo(zip_entry)
            if info.flag_bits & 0x1:
                raise InvalidArchiveError("Şifreli OBB girdisi çıkarılamaz.")
            with zarch.open(info, "r") as rfp, open(tmp, "wb") as wfp:
                copy_stream_limited(rfp, wfp, limit, f"OBB ({safe_name})")
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
        os.replace(tmp, target)
        return target
    except KeyError as exc:
        tmp.unlink(missing_ok=True)
        raise InvalidArchiveError(f"OBB girdisi arşivde bulunamadı: {zip_entry}", status_code=404) from exc
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError) as exc:
        tmp.unlink(missing_ok=True)
        raise InvalidArchiveError(f"OBB arşivi bozuk, kesik veya şifreli: {exc}") from exc
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def build_full_xapk(
    job_dir: Path,
    patch_result: dict[str, Any],
    container_meta: dict[str, Any] | None,
    extra_obb_meta: list[dict[str, Any]] | None,
    progress_cb: Callable[[int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
    *,
    apk_info: dict[str, Any] | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Atomically build a spec-compliant XAPK v2 archive with signed APK(s), icon, and OBBs."""
    jdir = Path(job_dir)
    limit = int(max_bytes) if max_bytes is not None else get_settings().MAX_DECOMPRESSED_BYTES

    def _progress(pct: int, stage: str) -> None:
        if progress_cb is not None:
            progress_cb(pct, stage)

    def _check_cancel(stage: str) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise CommandCanceledError(stage)

    if not patch_result or patch_result.get("verified") is not True:
        raise InvalidArchiveError(
            "Tam XAPK oluşturmak için doğrulanmış ve imzalanmış APK gereklidir."
        )

    signed_name = str(patch_result.get("fileName") or "")
    signed_apk = jdir / signed_name
    if not signed_name or not signed_apk.is_file():
        raise InvalidArchiveError("İmzalanmış APK dosyası bulunamadı.", status_code=404)

    info = apk_info or patch_result
    package_id = str(info.get("packageId") or patch_result.get("packageId") or "").strip()
    if not package_id or package_id == "bilinmiyor":
        package_id = sanitize_filename(signed_apk.stem, default="com.retrodroid.app")

    app_label = str(info.get("appLabel") or patch_result.get("appLabel") or signed_apk.stem)
    version_code = str(info.get("versionCode") or patch_result.get("versionCode") or "1")
    version_name = str(info.get("versionName") or patch_result.get("versionName") or "1.0")
    min_sdk = str(info.get("minSdk") or patch_result.get("minSdk") or "1")
    target_sdk = str(info.get("targetSdk") or patch_result.get("targetSdk") or "28")

    inspector_block = (
        info.get("inspector")
        if isinstance(info.get("inspector"), dict)
        else patch_result.get("inspector")
    )
    permissions: list[str] = []
    if isinstance(inspector_block, dict) and isinstance(inspector_block.get("permissions"), list):
        permissions = [str(p) for p in inspector_block["permissions"]]

    # Collect OBB sources: container OBBs + attached extra OBBs
    obb_sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen_targets: set[str] = set()

    if container_meta and container_meta.get("obbFiles"):
        archive_raw = container_meta.get("archive")
        archive_path = Path(archive_raw) if archive_raw else None
        if archive_path is not None and archive_path.is_file():
            for idx, obb in enumerate(container_meta["obbFiles"]):
                zip_entry = obb.get("zipEntry")
                if not isinstance(zip_entry, str) or not zip_entry:
                    raise InvalidArchiveError("OBB arşiv giriş yolu eksik.")
                raw_rel = str(
                    obb.get("installPath")
                    or obb.get("normalizedEntry")
                    or obb.get("name")
                    or f"obb_{idx}.obb"
                )
                norm_rel = normalize_obb_relpath(raw_rel, package_id)
                # Preserve disambiguated name when two container OBBs shared a basename
                # (without clobbering explicit XAPK expansions[].install_path or benign sanitization)
                obb_display = str(obb.get("name") or "")
                if "disambiguated" in obb:
                    is_disambiguated = bool(obb.get("disambiguated"))
                else:
                    orig_name = obb.get("originalName")
                    is_disambiguated = bool(
                        obb_display
                        and isinstance(orig_name, str)
                        and orig_name
                        and obb_display != sanitize_filename(orig_name, default="main.obb")
                    )
                if is_disambiguated and obb_display and not obb.get("installPath"):
                    norm_rel = normalize_obb_relpath(obb_display, package_id)
                target_zip_path = f"Android/obb/{package_id}/{norm_rel}"
                if target_zip_path.lower() in seen_targets:
                    raise InvalidArchiveError(
                        f"Çakışan OBB hedef yolu tespit edildi: {target_zip_path}"
                    )
                seen_targets.add(target_zip_path.lower())

                val = validate_obb_filename(norm_rel, package_id, version_code)
                if val.get("warning"):
                    warnings.append(str(val["warning"]))
                obb_sources.append(
                    {
                        "source": "container",
                        "archivePath": archive_path,
                        "zipEntry": zip_entry,
                        "targetPath": target_zip_path,
                        "sizeBytes": int(obb.get("sizeBytes") or 0),
                    }
                )

    try:
        jdir_resolved = jdir.resolve()
    except (RuntimeError, OSError) as exc:
        raise InvalidArchiveError("İş dizini yolu çözümlenemedi.") from exc

    raw_extra_dir = jdir / "extra_obb"
    try:
        if raw_extra_dir.is_symlink():
            raise InvalidArchiveError("Ek OBB dizini sembolik bağlantı olamaz.")
        extra_dir = raw_extra_dir.resolve()
    except InvalidArchiveError:
        raise
    except (RuntimeError, OSError) as exc:
        raise InvalidArchiveError("Ek OBB dizin yolu çözümlenemedi.") from exc
    if not extra_dir.is_relative_to(jdir_resolved):
        raise InvalidArchiveError("Ek OBB yolu izin verilen dizin dışına çıkıyor.")

    def _resolve_within_extra(target: Path) -> Path:
        try:
            resolved = target.resolve()
        except (RuntimeError, OSError, ValueError) as exc:
            raise InvalidArchiveError("Ek OBB yolu çözümlenemedi.") from exc
        if not resolved.is_relative_to(extra_dir):
            raise InvalidArchiveError("Ek OBB yolu izin verilen dizin dışına çıkıyor.")
        return resolved

    extra_entries: list[tuple[Path, str]] = []
    if extra_obb_meta:
        for item in extra_obb_meta:
            raw_path = item.get("path") or item.get("filePath")
            rel_hint = str(item.get("normalizedPath") or item.get("name") or "")
            if raw_path:
                cand = _resolve_within_extra(Path(raw_path))
            elif rel_hint:
                cand = _resolve_within_extra(extra_dir / rel_hint)
            else:
                continue
            if cand.is_file():
                extra_entries.append((cand, rel_hint or cand.relative_to(extra_dir).as_posix()))
    elif extra_dir.is_dir():
        try:
            extra_candidates = sorted(extra_dir.rglob("*"))
        except (RuntimeError, OSError) as exc:
            raise InvalidArchiveError("Ek OBB dizini okunamadı.") from exc
        for cand in extra_candidates:
            if cand.name.startswith("."):
                continue
            cand_resolved = _resolve_within_extra(cand)
            if cand_resolved.is_file():
                extra_entries.append((cand_resolved, cand_resolved.relative_to(extra_dir).as_posix()))

    for cand_path, rel_hint in extra_entries:
        norm_rel = normalize_obb_relpath(rel_hint, package_id)
        target_zip_path = f"Android/obb/{package_id}/{norm_rel}"
        if target_zip_path.lower() in seen_targets:
            raise InvalidArchiveError(f"Çakışan OBB hedef yolu tespit edildi: {target_zip_path}")
        seen_targets.add(target_zip_path.lower())

        val = validate_obb_filename(norm_rel, package_id, version_code)
        if val.get("warning"):
            warnings.append(str(val["warning"]))
        try:
            obb_size = int(cand_path.stat().st_size)
        except OSError as exc:
            raise InvalidArchiveError(f"Ek OBB dosyası okunamadı: {exc}") from exc
        obb_sources.append(
            {
                "source": "disk",
                "diskPath": cand_path,
                "targetPath": target_zip_path,
                "sizeBytes": obb_size,
            }
        )

    if not obb_sources:
        raise InvalidArchiveError(
            "Tam XAPK oluşturmak için en az bir OBB dosyası bulunmalıdır."
        )

    # Check if signed split bundle exists
    split_bundle = patch_result.get("splitBundle") if isinstance(patch_result, dict) else None
    split_bundle_path: Path | None = None
    if isinstance(split_bundle, dict) and split_bundle.get("fileName"):
        cand_bundle = jdir / str(split_bundle["fileName"])
        if cand_bundle.is_file():
            split_bundle_path = cand_bundle

    has_splits = split_bundle_path is not None
    base_apk_entry_name = "base.apk" if has_splits else sanitize_filename(f"{package_id}.apk", default="base.apk")

    _check_cancel("extract_icon")
    _progress(15, "Uygulama simgesi çıkarılıyor")
    preferred_icon = info.get("iconPath") if isinstance(info, dict) else None
    icon_bytes = extract_apk_icon_png(signed_apk, preferred_icon_path=preferred_icon)

    def _safe_resolve(path_obj: Path) -> Path | None:
        try:
            return path_obj.resolve()
        except (OSError, RuntimeError, ValueError):
            return None

    protected_candidates: list[Path | str | None] = [
        signed_apk,
        split_bundle_path,
    ]
    if isinstance(container_meta, dict):
        protected_candidates.append(container_meta.get("archive"))
        protected_candidates.append(container_meta.get("extractedApkPath"))
    disk_cm_path = jdir / "container_meta.json"
    if disk_cm_path.is_file():
        try:
            disk_cm = json.loads(disk_cm_path.read_text(encoding="utf-8"))
            if isinstance(disk_cm, dict):
                protected_candidates.append(disk_cm.get("archive"))
                protected_candidates.append(disk_cm.get("extractedApkPath"))
        except (OSError, ValueError):
            pass

    upload_meta_path = jdir / "upload_meta.json"
    if upload_meta_path.is_file():
        try:
            upload_meta = json.loads(upload_meta_path.read_text(encoding="utf-8"))
            if isinstance(upload_meta, dict):
                for meta_key in ("sanitizedFileName", "fileName"):
                    raw_up_name = upload_meta.get(meta_key)
                    if not isinstance(raw_up_name, str) or not raw_up_name:
                        continue
                    base = raw_up_name.replace("\\", "/").rsplit("/", 1)[-1]
                    if base not in ("", ".", "..") and "\x00" not in base:
                        protected_candidates.append(jdir / base)
                    if raw_up_name.strip():
                        sanitized = sanitize_filename(raw_up_name, default="file.bin")
                        if sanitized not in ("", ".", ".."):
                            protected_candidates.append(jdir / sanitized)
        except (OSError, ValueError):
            pass

    protected_paths: set[Path] = set()
    for cand_raw in protected_candidates:
        if not cand_raw:
            continue
        resolved_cand = _safe_resolve(Path(cand_raw))
        if resolved_cand is not None:
            protected_paths.add(resolved_cand)

    safe_stem = sanitize_filename(package_id, default="app", max_len=80)
    output_name = sanitize_filename(
        f"{safe_stem}_RetroDroid_Full_Signed.xapk",
        default="RetroDroid_Full_Signed.xapk",
    )
    output_path = jdir / output_name
    stem_prefix = safe_stem[:75].rstrip("._-") or "app"
    while (resolved_out := _safe_resolve(output_path)) is not None and resolved_out in protected_paths:
        tok = uuid.uuid4().hex[:6]
        output_name = sanitize_filename(
            f"{stem_prefix}_{tok}_RetroDroid_Full_Signed.xapk",
            default=f"app_{tok}_RetroDroid_Full_Signed.xapk",
            max_len=120,
        )
        output_path = jdir / output_name
    tmp_path = jdir / f".{output_name}.{uuid.uuid4().hex[:8]}.tmp"

    total_payload_bytes = 0
    split_manifest_entries: list[dict[str, str]] = []
    expansions: list[dict[str, str]] = []

    try:
        _check_cancel("write_xapk")
        _progress(25, "Tam XAPK arşivi paketleniyor")
        with zipfile.ZipFile(tmp_path, "w", allowZip64=True) as zout:
            # 1. Signed base APK
            base_size = signed_apk.stat().st_size
            b_info = zipfile.ZipInfo(base_apk_entry_name)
            b_info.date_time = (1980, 1, 1, 0, 0, 0)
            b_info.compress_type = zipfile.ZIP_STORED
            with (
                open(signed_apk, "rb") as bfp,
                zout.open(b_info, "w", force_zip64=(base_size >= 0xFFFFFFFF)) as wfp,
            ):
                written = copy_stream_limited(
                    bfp,
                    wfp,
                    limit,
                    base_apk_entry_name,
                    cancel_event=cancel_event,
                )
            total_payload_bytes += written
            if has_splits:
                split_manifest_entries.append({"file": base_apk_entry_name, "id": "base"})

            # 2. Signed split APKs (if present)
            if split_bundle_path is not None:
                _progress(45, "İmzalı split APK dosyaları ekleniyor")
                used_xapk_splits: set[str] = {base_apk_entry_name.lower()}
                with zipfile.ZipFile(split_bundle_path, "r") as zsplit:
                    for sp_idx, item in enumerate(zsplit.infolist()):
                        _check_cancel("write_splits")
                        norm_item = item.filename.replace("\\", "/")
                        if item.is_dir() or item.filename.lower() == "base.apk":
                            continue
                        sp_file = sanitize_filename(
                            posixpath.basename(norm_item),
                            default=f"split_{sp_idx}.apk",
                        )
                        if sp_file.lower() in used_xapk_splits:
                            base_sp = sp_file
                            sp_file = sanitize_filename(
                                f"split_{sp_idx}_{base_sp}",
                                default=f"split_{sp_idx}.apk",
                            )
                            dedup_n = 1
                            while sp_file.lower() in used_xapk_splits:
                                sp_file = sanitize_filename(
                                    f"split_{sp_idx}_{dedup_n}_{base_sp}",
                                    default=f"split_{sp_idx}_{dedup_n}.apk",
                                )
                                dedup_n += 1
                        used_xapk_splits.add(sp_file.lower())
                        sp_info = zipfile.ZipInfo(sp_file)
                        sp_info.date_time = (1980, 1, 1, 0, 0, 0)
                        sp_info.compress_type = zipfile.ZIP_STORED
                        with (
                            zsplit.open(item, "r") as rfp,
                            zout.open(
                                sp_info,
                                "w",
                                force_zip64=(item.file_size >= 0xFFFFFFFF),
                            ) as wfp,
                        ):
                            written = copy_stream_limited(
                                rfp,
                                wfp,
                                max(0, limit - total_payload_bytes),
                                sp_file,
                                cancel_event=cancel_event,
                            )
                        total_payload_bytes += written
                        split_id = Path(sp_file).stem
                        split_manifest_entries.append({"file": sp_file, "id": split_id})

            # 3. icon.png (if extracted)
            if icon_bytes is not None:
                ic_info = zipfile.ZipInfo("icon.png")
                ic_info.date_time = (1980, 1, 1, 0, 0, 0)
                ic_info.compress_type = zipfile.ZIP_STORED
                zout.writestr(ic_info, icon_bytes)
                total_payload_bytes += len(icon_bytes)

            # 4. OBB expansion files under Android/obb/<package_id>/
            _progress(60, "OBB veri dosyaları paketleniyor")
            for obb_idx, obb_src in enumerate(obb_sources):
                _check_cancel("write_obb")
                tpath = obb_src["targetPath"]
                o_info = zipfile.ZipInfo(tpath)
                o_info.date_time = (1980, 1, 1, 0, 0, 0)
                o_info.compress_type = zipfile.ZIP_STORED
                expected_size = int(obb_src.get("sizeBytes") or 0)
                remaining = max(0, limit - total_payload_bytes)

                if obb_src["source"] == "container":
                    with zipfile.ZipFile(obb_src["archivePath"], "r") as zarch:
                        try:
                            zitem = zarch.getinfo(obb_src["zipEntry"])
                        except KeyError as exc:
                            raise InvalidArchiveError(
                                f"OBB girdisi arşivde bulunamadı: {obb_src['zipEntry']}",
                                status_code=404,
                            ) from exc
                        with (
                            zarch.open(zitem, "r") as rfp,
                            zout.open(
                                o_info,
                                "w",
                                force_zip64=(max(expected_size, zitem.file_size) >= 0xFFFFFFFF),
                            ) as wfp,
                        ):
                            written = copy_stream_limited(
                                rfp,
                                wfp,
                                remaining,
                                tpath,
                                cancel_event=cancel_event,
                            )
                else:
                    disk_p: Path = obb_src["diskPath"]
                    with (
                        open(disk_p, "rb") as rfp,
                        zout.open(
                            o_info,
                            "w",
                            force_zip64=(expected_size >= 0xFFFFFFFF),
                        ) as wfp,
                    ):
                        written = copy_stream_limited(
                            rfp,
                            wfp,
                            remaining,
                            tpath,
                            cancel_event=cancel_event,
                        )
                total_payload_bytes += written
                expansions.append(
                    {
                        "file": tpath,
                        "install_location": "EXTERNAL_STORAGE",
                        "install_path": tpath,
                    }
                )
                pct = 60 + int(30 * (obb_idx + 1) / max(1, len(obb_sources)))
                _progress(pct, f"OBB paketlendi ({obb_idx + 1}/{len(obb_sources)})")

            # 5. XAPK v2 manifest.json
            manifest: dict[str, Any] = {
                "xapk_version": 2,
                "package_name": package_id,
                "name": app_label,
                "version_code": version_code,
                "version_name": version_name,
                "min_sdk_version": min_sdk,
                "target_sdk_version": target_sdk,
                "total_size": total_payload_bytes,
                "permissions": permissions,
                "apk": base_apk_entry_name,
                "expansions": expansions,
                "obb": [e["file"] for e in expansions],
                "signed_apk_verified": True,
            }
            if icon_bytes is not None:
                manifest["icon"] = "icon.png"
            if split_manifest_entries:
                manifest["split_apks"] = split_manifest_entries

            mj_info = zipfile.ZipInfo("manifest.json")
            mj_info.date_time = (1980, 1, 1, 0, 0, 0)
            mj_info.compress_type = zipfile.ZIP_STORED
            zout.writestr(mj_info, json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))

            # 6. Install instructions
            readme_lines = [
                f"RetroDroid Compat Full XAPK v2 — {app_label} ({package_id})",
                f"Sürüm: {version_name} (code: {version_code}) | targetSdk: {target_sdk}",
                "",
                "Kurulum:",
                "1. ZArchiver / SAI / XAPK Installer ile bu .xapk dosyasını açıp kurun.",
                f"2. Manuel kurulumda OBB dosyalarını Android/obb/{package_id}/ klasörüne kopyalayın.",
            ]
            rd_info = zipfile.ZipInfo("RETRODROID-INSTALL.txt")
            rd_info.date_time = (1980, 1, 1, 0, 0, 0)
            rd_info.compress_type = zipfile.ZIP_STORED
            zout.writestr(rd_info, "\n".join(readme_lines).encode("utf-8"))

        try:
            os.chmod(tmp_path, 0o644)
        except OSError:
            pass
        os.replace(tmp_path, output_path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError) as exc:
        tmp_path.unlink(missing_ok=True)
        raise InvalidArchiveError(
            f"Kaynak arşiv okunamadı (bozuk, kesik veya şifreli): {exc}"
        ) from exc
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    out_size = output_path.stat().st_size
    _progress(100, "Tam XAPK hazır")
    return {
        "ok": True,
        "jobId": jdir.name,
        "fileName": output_name,
        "downloadUrl": f"/api/download-full-xapk/{jdir.name}",
        "sizeBytes": out_size,
        "sizeMB": round(out_size / (1024 * 1024), 2),
        "hasIcon": icon_bytes is not None,
        "manifest": manifest,
        "warnings": warnings,
    }
