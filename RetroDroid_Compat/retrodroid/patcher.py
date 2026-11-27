"""Manifest patching (Binary AXML & Slim-Apktool), streaming APK rewrite, alignment, signing, and split bundling."""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from retrodroid.axml import patch_binary_axml_target_sdk
from retrodroid.config import (
    CommandCanceledError,
    InvalidArchiveError,
    PayloadTooLargeError,
    RetroDroidError,
    Settings,
    clean_java_output,
    copy_stream_limited,
    get_logger,
    get_settings,
    safe_url_download,
    sanitize_filename,
    write_json_atomic,
)
from retrodroid.inspector import count_missing_exported_components, inspect_apk
from retrodroid.keystore import KeystoreError, KeystoreState

__all__ = [
    "ANDROID_NS",
    "DEFAULT_SLIM_MAX_BYTES",
    "MAX_TARGET_SDK",
    "MIN_TARGET_SDK",
    "ManifestPatchOptions",
    "PatchError",
    "SlimApkTooLargeError",
    "align_and_sign_apk",
    "build_slim_manifest_apk",
    "detect_zipalign_16k",
    "patch_and_sign_pipeline",
    "patch_manifest_xml_apktool",
    "read_apktool_yml_sdk_info",
    "stream_rewrite_apk",
    "update_apktool_yml",
]

ANDROID_NS = "http://schemas.android.com/apk/res/android"
MIN_TARGET_SDK = 24  # Android 15/16/17 install floor (Android 14 requires >= 23)
MAX_TARGET_SDK = 36  # Android 16 (API 36)
DEFAULT_SLIM_MAX_BYTES = 150 * 1024 * 1024

_ROOT_DEX_RE = re.compile(r"^classes[0-9]*\.dex$")
_METAINFO_TAG = "tag:yaml.org,2002:brut.androlib.meta.MetaInfo"
_LOG = get_logger("retrodroid.patcher")

ET.register_namespace("android", ANDROID_NS)


class SlimApkTooLargeError(RetroDroidError, ValueError):
    """Raised before writing slim APK if projected resource payload exceeds max_bytes."""

    def __init__(self, detail: str, *, projected_bytes: int = 0) -> None:
        super().__init__(detail, status_code=413)
        self.projected_bytes = projected_bytes


class PatchError(RetroDroidError):
    """Raised when APK rewriting, alignment, signing, or split bundling fails."""

    def __init__(self, detail: str, *, status_code: int = 500) -> None:
        super().__init__(detail, status_code=status_code)


@dataclass
class ManifestPatchOptions:
    """Declarative server-side AndroidManifest.xml patching options."""

    target_sdk: int = 28
    patch_target_sdk: bool = True
    add_legacy_storage: bool = False
    enable_cleartext: bool = False
    add_notch_support: bool = False
    force_extract_native_libs: bool = False
    allow_downgrade: bool = False

    def clamped_target_sdk(self) -> int:
        return max(MIN_TARGET_SDK, min(MAX_TARGET_SDK, int(self.target_sdk)))

    def needs_structural_patch(self) -> bool:
        return bool(
            self.add_legacy_storage
            or self.enable_cleartext
            or self.add_notch_support
            or self.force_extract_native_libs
        )


# ---------------------------------------------------------------------------
# Safe YAML Loader for apktool.yml (!!brut.androlib.meta.MetaInfo only)
# ---------------------------------------------------------------------------


class _ApktoolSafeLoader(yaml.SafeLoader):
    """SafeLoader subclass allowing ONLY apktool's MetaInfo YAML tag."""


def _construct_apktool_metainfo(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return None


_ApktoolSafeLoader.add_constructor(_METAINFO_TAG, _construct_apktool_metainfo)


def _parse_int_sdk(raw: Any) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    if text.isdigit():
        val = int(text)
        return val if val > 0 else None
    return None


def read_apktool_yml_sdk_info(yml_path: Path) -> tuple[int | None, int | None]:
    """Read (minSdkVersion, targetSdkVersion) integers from apktool.yml safely."""
    path = Path(yml_path)
    if not path.is_file():
        return None, None
    try:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.load(text, Loader=_ApktoolSafeLoader)
    except (yaml.YAMLError, OSError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    sdk_info = data.get("sdkInfo")
    if not isinstance(sdk_info, dict):
        return None, None
    return _parse_int_sdk(sdk_info.get("minSdkVersion")), _parse_int_sdk(
        sdk_info.get("targetSdkVersion")
    )


def update_apktool_yml(yml_path: Path, target_sdk: int) -> bool:
    """Safely update sdkInfo.targetSdkVersion in apktool.yml via PyYAML SafeLoader."""
    path = Path(yml_path)
    if not path.is_file():
        return False
    try:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    header_tag = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "---":
            continue
        if re.fullmatch(r"!!brut\.androlib\.meta\.MetaInfo", stripped) or re.fullmatch(
            r"---\s+!!brut\.androlib\.meta\.MetaInfo", stripped
        ):
            header_tag = "!!brut.androlib.meta.MetaInfo\n"
        break

    try:
        data = yaml.load(text, Loader=_ApktoolSafeLoader)
    except yaml.YAMLError:
        return False

    if not isinstance(data, dict):
        return False

    sdk_info = data.get("sdkInfo")
    if not isinstance(sdk_info, dict):
        sdk_info = {}
        data["sdkInfo"] = sdk_info

    # Ensure existing numeric SDK strings stay strings for SnakeYAML Map<String, String>
    for key in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
        if key in sdk_info and isinstance(sdk_info[key], int) and not isinstance(sdk_info[key], bool):
            sdk_info[key] = str(sdk_info[key])

    sdk_info["targetSdkVersion"] = str(int(target_sdk))

    dumped = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=4096,
    )
    payload = (header_tag + dumped).encode("utf-8")

    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.fchmod(fd, 0o644)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as fp:
            fp.write(payload)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, path)
        return True
    except OSError:
        tmp.unlink(missing_ok=True)
        return False


# ---------------------------------------------------------------------------
# Manifest XML Patcher (for apktool-decoded AndroidManifest.xml)
# ---------------------------------------------------------------------------


def _register_xml_namespaces(manifest_path: Path) -> None:
    ET.register_namespace("android", ANDROID_NS)
    try:
        for _, ns_pair in ET.iterparse(str(manifest_path), events=("start-ns",)):
            prefix, uri = ns_pair
            if prefix and prefix != "android" and uri:
                ET.register_namespace(prefix, uri)
    except (ET.ParseError, OSError):
        pass


def patch_manifest_xml_apktool(
    manifest_path: Path,
    opts: ManifestPatchOptions,
    *,
    known_min_sdk: int | None = None,
    known_target_sdk: int | None = None,
    force_exported_api31: bool = False,
) -> dict[str, Any]:
    """Patch decoded AndroidManifest.xml with SDK floor, downgrade protection, and compat flags."""
    path = Path(manifest_path)
    if not path.is_file():
        return {
            "changed": False,
            "appliedChanges": [],
            "oldMinSdk": None,
            "oldTargetSdk": None,
            "newTargetSdk": None,
            "skippedDowngrade": False,
            "error": "AndroidManifest.xml bulunamadı.",
        }

    _register_xml_namespaces(path)
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        return {
            "changed": False,
            "appliedChanges": [],
            "oldMinSdk": None,
            "oldTargetSdk": None,
            "newTargetSdk": None,
            "skippedDowngrade": False,
            "error": f"AndroidManifest.xml ayrıştırılamadı: {exc}",
        }

    ns = f"{{{ANDROID_NS}}}"
    min_attr = f"{ns}minSdkVersion"
    target_attr = f"{ns}targetSdkVersion"
    exported_attr = f"{ns}exported"
    legacy_attr = f"{ns}requestLegacyExternalStorage"
    cleartext_attr = f"{ns}usesCleartextTraffic"
    extract_attr = f"{ns}extractNativeLibs"
    resizeable_attr = f"{ns}resizeableActivity"
    name_attr = f"{ns}name"
    value_attr = f"{ns}value"

    uses_sdk = root.find("uses-sdk")
    xml_min = _parse_int_sdk(uses_sdk.attrib.get(min_attr)) if uses_sdk is not None else None
    xml_target = _parse_int_sdk(uses_sdk.attrib.get(target_attr)) if uses_sdk is not None else None

    old_min = xml_min if xml_min is not None else known_min_sdk
    old_target = xml_target if xml_target is not None else known_target_sdk

    changed = False
    applied_changes: list[str] = []
    skipped_downgrade = False
    new_target: int | None = old_target

    if opts.patch_target_sdk:
        requested = opts.clamped_target_sdk()
        effective_target = max(requested, old_min) if old_min is not None else requested

        if (
            old_target is not None
            and old_target > requested
            and old_target >= effective_target
            and not opts.allow_downgrade
        ):
            skipped_downgrade = True
            new_target = old_target
        elif old_target == effective_target:
            # Already at the exact effective target (in XML or apktool.yml); skip no-op edits.
            new_target = effective_target
        else:
            if uses_sdk is None:
                uses_sdk = ET.Element("uses-sdk")
                root.insert(0, uses_sdk)
                if old_min is not None:
                    uses_sdk.set(min_attr, str(old_min))
            if uses_sdk.attrib.get(target_attr) != str(effective_target):
                uses_sdk.set(target_attr, str(effective_target))
                changed = True
                old_disp = str(old_target) if old_target is not None else "none"
                applied_changes.append(f"targetSdkVersion:{old_disp}->{effective_target}")
            new_target = effective_target

    active_target = new_target if new_target is not None else (old_target or 0)
    app_el = root.find("application")
    if app_el is not None:
        if opts.add_legacy_storage and app_el.attrib.get(legacy_attr) != "true":
            app_el.set(legacy_attr, "true")
            changed = True
            applied_changes.append("requestLegacyExternalStorage=true")

        if opts.enable_cleartext and app_el.attrib.get(cleartext_attr) != "true":
            app_el.set(cleartext_attr, "true")
            changed = True
            applied_changes.append("usesCleartextTraffic=true")

        if opts.force_extract_native_libs and app_el.attrib.get(extract_attr) != "true":
            app_el.set(extract_attr, "true")
            changed = True
            applied_changes.append("extractNativeLibs=true")

        if opts.add_notch_support:
            if app_el.attrib.get(resizeable_attr) != "true":
                app_el.set(resizeable_attr, "true")
                changed = True
                applied_changes.append("resizeableActivity=true")

            max_aspect_nodes = [
                md
                for md in app_el.findall("meta-data")
                if md.attrib.get(name_attr) == "android.max_aspect"
            ]
            if not max_aspect_nodes:
                ET.SubElement(
                    app_el,
                    "meta-data",
                    {name_attr: "android.max_aspect", value_attr: "2.4"},
                )
                changed = True
                applied_changes.append("android.max_aspect=2.4")
            else:
                primary_node = max_aspect_nodes[0]
                aspect_updated = False
                if primary_node.attrib.get(value_attr) != "2.4":
                    primary_node.set(value_attr, "2.4")
                    aspect_updated = True
                for dup_node in max_aspect_nodes[1:]:
                    app_el.remove(dup_node)
                    aspect_updated = True
                if aspect_updated:
                    changed = True
                    applied_changes.append("android.max_aspect=2.4")

        if active_target >= 31 or force_exported_api31:
            exported_added = 0
            for tag in ("activity", "activity-alias", "service", "receiver"):
                for comp in app_el.findall(tag):
                    if comp.find("intent-filter") is not None and exported_attr not in comp.attrib:
                        comp.set(exported_attr, "true")
                        exported_added += 1
            if exported_added > 0:
                changed = True
                applied_changes.append(f"android:exported=true({exported_added})")

    if changed:
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
        try:
            tree.write(tmp, encoding="utf-8", xml_declaration=True)
            try:
                os.chmod(tmp, 0o644)
            except OSError:
                pass
            os.replace(tmp, path)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            return {
                "changed": False,
                "appliedChanges": [],
                "oldMinSdk": old_min,
                "oldTargetSdk": old_target,
                "newTargetSdk": new_target,
                "skippedDowngrade": skipped_downgrade,
                "error": f"AndroidManifest.xml yazılamadı: {exc}",
            }

    return {
        "changed": changed,
        "appliedChanges": applied_changes,
        "oldMinSdk": old_min,
        "oldTargetSdk": old_target,
        "newTargetSdk": new_target,
        "skippedDowngrade": skipped_downgrade,
    }


# ---------------------------------------------------------------------------
# ZIP Timestamp Clamp, Slim APK Builder & Streaming APK Rewriter
# ---------------------------------------------------------------------------


def _clamp_zip_datetime(dt: tuple[int, ...] | Any) -> tuple[int, int, int, int, int, int]:
    """Clamp pre-1980 or invalid DOS ZIP timestamps (e.g. (1980, 0, 0, ...)) to 1980-01-01."""
    try:
        y, mo, d, h, mi, s = (int(dt[0]), int(dt[1]), int(dt[2]), int(dt[3]), int(dt[4]), int(dt[5]))
    except (TypeError, ValueError, IndexError):
        return (1980, 1, 1, 0, 0, 0)
    if 1980 <= y <= 2107 and 1 <= mo <= 12 and 1 <= d <= 31 and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59:
        return (y, mo, d, h, mi, s)
    return (1980, 1, 1, 0, 0, 0)


def _is_signature_meta_entry(name: str) -> bool:
    """Return True for top-level META-INF JAR signature & stamp entries (case-insensitive)."""
    if name.endswith(("/", "\\")):
        return False
    parts = [p for p in name.replace("\\", "/").split("/") if p and p != "."]
    if len(parts) != 2 or parts[0].upper() != "META-INF":
        return False
    rel = parts[1].upper()
    return (
        rel.endswith((".SF", ".RSA", ".DSA", ".EC", ".MF"))
        or rel.startswith("SIG-")
        or rel == "STAMP-CERT-SHA256"
    )


def build_slim_manifest_apk(
    src_apk: Path,
    dst_apk: Path,
    max_bytes: int = DEFAULT_SLIM_MAX_BYTES,
    *,
    cancel_event: threading.Event | None = None,
) -> int:
    """Build a lightweight resource-only APK for fast apktool decode/rebuild without DEX/assets/libs."""
    src = Path(src_apk)
    dst = Path(dst_apk)
    if src.resolve() == dst.resolve():
        raise PatchError("Slim APK hedefi kaynak APK ile aynı olamaz.")

    try:
        with zipfile.ZipFile(src, "r") as zin:
            selected: list[zipfile.ZipInfo] = []
            seen: set[str] = set()
            for item in zin.infolist():
                name = item.filename
                if item.is_dir():
                    continue
                up = name.replace("\\", "/").upper()
                if up.startswith(("ASSETS/", "LIB/", "META-INF/")):
                    continue
                if _ROOT_DEX_RE.fullmatch(name):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                selected.append(item)

            projected = sum(max(0, item.file_size) for item in selected)
            if projected > max_bytes:
                raise SlimApkTooLargeError(
                    f"Slim APK kaynak boyutu sınırı aşıyor ({projected} > {max_bytes} bayt).",
                    projected_bytes=projected,
                )

            dst.parent.mkdir(parents=True, exist_ok=True)
            total_written = 0
            try:
                with zipfile.ZipFile(dst, "w", allowZip64=True) as zout:
                    for item in selected:
                        info = zipfile.ZipInfo(item.filename)
                        info.date_time = _clamp_zip_datetime(item.date_time)
                        info.compress_type = (
                            item.compress_type
                            if item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                            else zipfile.ZIP_DEFLATED
                        )
                        info.external_attr = item.external_attr
                        remaining = max_bytes - total_written
                        with (
                            zin.open(item, "r") as rfp,
                            zout.open(info, "w", force_zip64=(item.file_size >= 0xFFFFFFFF)) as wfp,
                        ):
                            total_written += copy_stream_limited(
                                rfp,
                                wfp,
                                remaining,
                                f"Slim APK ({item.filename})",
                                cancel_event=cancel_event,
                            )
            except Exception:
                dst.unlink(missing_ok=True)
                raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError) as exc:
        dst.unlink(missing_ok=True)
        raise InvalidArchiveError(f"APK arşivi bozuk, kesik veya şifreli: {exc}") from exc

    return total_written


def stream_rewrite_apk(
    src_apk: Path,
    dst_apk: Path,
    manifest_override: bytes | None = None,
    arsc_override: bytes | None = None,
    res_overrides: dict[str, bytes] | None = None,
    max_decompressed_bytes: int | None = None,
    *,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Stream-copy an APK stripping META-INF signatures, deduplicating entries, enforcing ZIP_STORED."""
    src = Path(src_apk)
    dst = Path(dst_apk)
    if src.resolve() == dst.resolve():
        raise PatchError("Yeniden yazım hedefi kaynak APK ile aynı olamaz.")

    limit = (
        int(max_decompressed_bytes)
        if max_decompressed_bytes is not None
        else get_settings().MAX_DECOMPRESSED_BYTES
    )

    seen: set[str] = set()
    entries_written = 0
    stripped_sig_count = 0
    deduplicated_count = 0
    stored_forced_count = 0
    timestamps_clamped = 0
    res_overrides_applied = 0
    total_decompressed = 0

    def _write_bytes_counted(
        zout: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        payload: bytes,
        label: str,
    ) -> None:
        nonlocal total_decompressed, entries_written
        if total_decompressed + len(payload) > limit:
            raise PayloadTooLargeError(
                f"{label} izin verilen toplam açılmış boyut sınırını ({limit} bayt) aşıyor."
            )
        with zout.open(info, "w", force_zip64=(len(payload) >= 0xFFFFFFFF)) as wfp:
            wfp.write(payload)
        total_decompressed += len(payload)
        entries_written += 1

    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (
            zipfile.ZipFile(src, "r") as zin,
            zipfile.ZipFile(dst, "w", allowZip64=True) as zout,
        ):
            for item in zin.infolist():
                if cancel_event is not None and cancel_event.is_set():
                    raise CommandCanceledError("stream_rewrite_apk")

                name = item.filename
                if item.is_dir():
                    continue
                if _is_signature_meta_entry(name):
                    stripped_sig_count += 1
                    continue
                if name in seen:
                    deduplicated_count += 1
                    continue
                seen.add(name)

                info = zipfile.ZipInfo(name)
                clamped_dt = _clamp_zip_datetime(item.date_time)
                if tuple(item.date_time) != clamped_dt:
                    timestamps_clamped += 1
                info.date_time = clamped_dt
                info.external_attr = item.external_attr

                must_store = name == "resources.arsc" or name.lower().endswith(".so")
                if must_store:
                    if item.compress_type != zipfile.ZIP_STORED:
                        stored_forced_count += 1
                    info.compress_type = zipfile.ZIP_STORED
                else:
                    info.compress_type = (
                        item.compress_type
                        if item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        else zipfile.ZIP_DEFLATED
                    )

                if name == "AndroidManifest.xml" and manifest_override is not None:
                    _write_bytes_counted(zout, info, manifest_override, "AndroidManifest.xml")
                elif name == "resources.arsc" and arsc_override is not None:
                    info.compress_type = zipfile.ZIP_STORED
                    _write_bytes_counted(zout, info, arsc_override, "resources.arsc")
                elif res_overrides is not None and name in res_overrides:
                    res_overrides_applied += 1
                    _write_bytes_counted(zout, info, res_overrides[name], f"Kaynak ({name})")
                else:
                    remaining = limit - total_decompressed
                    with (
                        zin.open(item, "r") as rfp,
                        zout.open(info, "w", force_zip64=(item.file_size >= 0xFFFFFFFF)) as wfp,
                    ):
                        total_decompressed += copy_stream_limited(
                            rfp,
                            wfp,
                            remaining,
                            f"APK içeriği ({name})",
                            cancel_event=cancel_event,
                        )
                    entries_written += 1

            # Append any new override entries that did not exist in the source APK
            if manifest_override is not None and "AndroidManifest.xml" not in seen:
                info = zipfile.ZipInfo("AndroidManifest.xml")
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.compress_type = zipfile.ZIP_DEFLATED
                _write_bytes_counted(zout, info, manifest_override, "AndroidManifest.xml")
                seen.add("AndroidManifest.xml")

            if arsc_override is not None and "resources.arsc" not in seen:
                info = zipfile.ZipInfo("resources.arsc")
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.compress_type = zipfile.ZIP_STORED
                _write_bytes_counted(zout, info, arsc_override, "resources.arsc")
                seen.add("resources.arsc")

            if res_overrides:
                for res_name, res_bytes in res_overrides.items():
                    if res_name in seen:
                        continue
                    info = zipfile.ZipInfo(res_name)
                    info.date_time = (1980, 1, 1, 0, 0, 0)
                    info.compress_type = (
                        zipfile.ZIP_STORED
                        if (res_name == "resources.arsc" or res_name.lower().endswith(".so"))
                        else zipfile.ZIP_DEFLATED
                    )
                    res_overrides_applied += 1
                    _write_bytes_counted(zout, info, res_bytes, f"Kaynak ({res_name})")
                    seen.add(res_name)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError) as exc:
        dst.unlink(missing_ok=True)
        raise InvalidArchiveError(f"APK arşivi bozuk, kesik veya şifreli: {exc}") from exc
    except Exception:
        dst.unlink(missing_ok=True)
        raise

    return {
        "entriesWritten": entries_written,
        "strippedSignatureEntries": stripped_sig_count,
        "deduplicatedCount": deduplicated_count,
        "storedForcedCount": stored_forced_count,
        "timestampsClamped": timestamps_clamped,
        "resOverridesApplied": res_overrides_applied,
        "totalDecompressedBytes": total_decompressed,
    }


# ---------------------------------------------------------------------------
# zipalign 16 KB Detection & Atomic Align + Sign + Verify
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def detect_zipalign_16k() -> bool:
    """Detect whether the installed `zipalign` supports 16 KB page alignment (`-P 16`)."""
    try:
        from retrodroid.config import run_cmd

        res = run_cmd(["zipalign", "--help"], timeout=10)
        text = f"{res.stdout}\n{res.stderr}"
    except RetroDroidError:
        return False
    return bool(
        re.search(r"(?:^|\s)-P\s+<", text)
        or re.search(r"(?:^|\s)-P\b.*(?:[Pp]age|[Kk]i[Bb]|16)", text)
    )


def align_and_sign_apk(
    src_apk: Path,
    dst_apk: Path,
    keystore_state: KeystoreState | None,
    resign: bool = True,
    timeout: int = 300,
    verify_out: list[str] | None = None,
    cancel_event: threading.Event | None = None,
    on_proc: Callable[[subprocess.Popen[str]], None] | None = None,
) -> list[str]:
    """Run zipalign (16 KB if supported else 4 KB) and apksigner v1+v2+v3 via env password."""
    from retrodroid.config import run_cmd

    src = Path(src_apk)
    dst = Path(dst_apk)
    dst.parent.mkdir(parents=True, exist_ok=True)
    step_logs: list[str] = []

    token = uuid.uuid4().hex[:10]
    aligned_tmp = dst.parent / f".{dst.name}.{token}.aligned.apk"
    signed_tmp = dst.parent / f".{dst.name}.{token}.signed.apk"

    try:
        if cancel_event is not None and cancel_event.is_set():
            raise CommandCanceledError("zipalign")

        use_16k = detect_zipalign_16k()
        align_cmd = (
            ["zipalign", "-P", "16", "-f", "4", str(src), str(aligned_tmp)]
            if use_16k
            else ["zipalign", "-f", "-p", "4", str(src), str(aligned_tmp)]
        )
        align_res = run_cmd(
            align_cmd,
            timeout=timeout,
            cancel_event=cancel_event,
            on_proc=on_proc,
        )
        if align_res.returncode != 0 or not aligned_tmp.is_file():
            detail = align_res.clean_output[-500:] or "zipalign başarısız"
            raise PatchError(f"zipalign hatası: {detail}")

        step_logs.append(
            "zipalign tamamlandı (16 KB -P 16 + 4B hizalama)."
            if use_16k
            else "zipalign tamamlandı (4 KB -p + 4B hizalama)."
        )

        if not resign:
            os.replace(aligned_tmp, dst)
            step_logs.append("Yeniden imzalama devre dışı; hizalanmış APK kaydedildi.")
            return step_logs

        if keystore_state is None or not keystore_state.ready or not keystore_state.path.is_file():
            raise KeystoreError("İmzalama anahtarı hazır değil veya keystore dosyası bulunamadı.")

        # Password passed strictly through child env (never in subprocess argv)
        signing_env = keystore_state.get_signing_env(env_var="RD_KS_PASS")

        sign_cmd = [
            "apksigner",
            "sign",
            "--ks",
            str(keystore_state.path),
        ]
        if keystore_state.alias:
            sign_cmd.extend(["--ks-key-alias", keystore_state.alias])
        sign_cmd.extend(
            [
                "--ks-pass",
                "env:RD_KS_PASS",
                "--key-pass",
                "env:RD_KS_PASS",
                "--v1-signing-enabled",
                "true",
                "--v2-signing-enabled",
                "true",
                "--v3-signing-enabled",
                "true",
                "--out",
                str(signed_tmp),
                str(aligned_tmp),
            ]
        )

        sign_res = run_cmd(
            sign_cmd,
            timeout=timeout,
            env=signing_env,
            cancel_event=cancel_event,
            on_proc=on_proc,
        )
        if sign_res.returncode != 0 or not signed_tmp.is_file():
            detail = sign_res.clean_output[-500:] or "apksigner başarısız"
            raise PatchError(f"apksigner imzalama hatası: {detail}")

        verify_res = run_cmd(
            ["apksigner", "verify", "--verbose", "--print-certs", str(signed_tmp)],
            timeout=min(timeout, 120),
            cancel_event=cancel_event,
            on_proc=on_proc,
        )
        cleaned_verify = clean_java_output(verify_res.stderr, verify_res.stdout)
        if verify_res.returncode != 0:
            raise PatchError(f"apksigner doğrulama hatası: {cleaned_verify[-500:]}")

        if verify_out is not None:
            verify_out.append(cleaned_verify)

        os.replace(signed_tmp, dst)
        step_logs.append("apksigner v1+v2+v3 imzalama ve doğrulama başarılı.")
        return step_logs
    finally:
        aligned_tmp.unlink(missing_ok=True)
        signed_tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Full Patch & Sign Pipeline Orchestrator
# ---------------------------------------------------------------------------


def _diff_rebuilt_res_entries(slim_apk: Path, rebuilt_apk: Path) -> dict[str, bytes]:
    """Return ONLY added or modified res/ entries from rebuilt_apk compared against slim_apk."""
    baseline: dict[str, tuple[int, int]] = {}
    with zipfile.ZipFile(slim_apk, "r") as zorig:
        for item in zorig.infolist():
            if not item.is_dir() and item.filename.startswith("res/"):
                baseline[item.filename] = (item.CRC, item.file_size)

    overrides: dict[str, bytes] = {}
    with zipfile.ZipFile(rebuilt_apk, "r") as znew:
        for item in znew.infolist():
            if item.is_dir() or not item.filename.startswith("res/"):
                continue
            prev = baseline.get(item.filename)
            if prev is None or prev != (item.CRC, item.file_size):
                overrides[item.filename] = znew.read(item.filename)
    return overrides


def _load_json_if_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _safe_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _patch_feature_split_exported(
    sp_raw: Path,
    work_dir: Path,
    fw_dir: Path,
    effective_target: int,
    *,
    cancel_event: threading.Event | None = None,
    on_proc: Callable[[subprocess.Popen[str]], None] | None = None,
) -> tuple[bytes | None, bytes | None, dict[str, bytes] | None, bool]:
    """Patch missing android:exported on an API 31+ feature split APK using slim apktool."""
    from retrodroid.config import run_cmd

    sp_token = uuid.uuid4().hex[:8]
    sp_slim = work_dir / f"split_slim_{sp_token}.apk"
    sp_dec = work_dir / f"split_dec_{sp_token}"
    sp_rebuilt = work_dir / f"split_rebuilt_{sp_token}.apk"

    build_slim_manifest_apk(sp_raw, sp_slim, max_bytes=DEFAULT_SLIM_MAX_BYTES, cancel_event=cancel_event)
    dec_res = run_cmd(
        ["apktool", "d", "-s", "-f", "-p", str(fw_dir), str(sp_slim), "-o", str(sp_dec)],
        timeout=180,
        cancel_event=cancel_event,
        on_proc=on_proc,
    )
    if dec_res.returncode != 0:
        raise PatchError(f"Split apktool d hatası: {dec_res.clean_output[-300:]}")

    yml_min, yml_target = read_apktool_yml_sdk_info(sp_dec / "apktool.yml")
    sp_opts = ManifestPatchOptions(target_sdk=effective_target, patch_target_sdk=False)
    xml_res = patch_manifest_xml_apktool(
        sp_dec / "AndroidManifest.xml",
        sp_opts,
        known_min_sdk=yml_min,
        known_target_sdk=yml_target,
        force_exported_api31=True,
    )
    if not xml_res.get("changed"):
        return None, None, None, False

    bld_res = run_cmd(
        ["apktool", "b", "-p", str(fw_dir), str(sp_dec), "-o", str(sp_rebuilt)],
        timeout=180,
        cancel_event=cancel_event,
        on_proc=on_proc,
    )
    if bld_res.returncode != 0 or not sp_rebuilt.is_file():
        raise PatchError(f"Split apktool b hatası: {bld_res.clean_output[-300:]}")

    with zipfile.ZipFile(sp_rebuilt, "r") as zr:
        manifest_bytes = zr.read("AndroidManifest.xml") if "AndroidManifest.xml" in zr.namelist() else None
        arsc_bytes = zr.read("resources.arsc") if "resources.arsc" in zr.namelist() else None
    res_ov = _diff_rebuilt_res_entries(sp_slim, sp_rebuilt)
    return manifest_bytes, arsc_bytes, (res_ov or None), True


def patch_and_sign_pipeline(
    job_id: str,
    job_dir: Path,
    src_apk: Path,
    keystore_state: KeystoreState | None,
    options: ManifestPatchOptions | None = None,
    mode: str = "patch_and_sign",
    resign: bool = True,
    append_log: Callable[[str], None] | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
    on_proc: Callable[[subprocess.Popen[str]], None] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Run the complete isolated manifest patch, rewrite, align, sign, verify, and split pipeline."""
    from retrodroid.config import run_cmd

    cfg = settings or get_settings()
    opts = options or ManifestPatchOptions()
    jdir = Path(job_dir)
    src = Path(src_apk)
    if not src.is_file():
        raise PatchError("Kaynak APK dosyası bulunamadı.", status_code=404)

    logs: list[str] = []

    def _log(msg: str) -> None:
        logs.append(msg)
        if append_log is not None:
            append_log(msg)

    def _progress(pct: int, stage: str) -> None:
        if progress_cb is not None:
            progress_cb(pct, stage)

    def _check_canceled(stage: str) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise CommandCanceledError(stage)

    work_dir = jdir / "_work" / uuid.uuid4().hex
    work_dir.mkdir(parents=True, exist_ok=True)
    fw_dir = work_dir / "_fw"
    fw_dir.mkdir(parents=True, exist_ok=True)

    target_sdk = opts.clamped_target_sdk()
    container_meta = _load_json_if_file(jdir / "container_meta.json")
    archive_path: Path | None = None
    if container_meta:
        raw_archive = container_meta.get("archive")
        if raw_archive:
            archive_path = Path(raw_archive)

    protected_outputs: set[Path] = set()
    src_resolved = _safe_resolve(src)
    if src_resolved is not None:
        protected_outputs.add(src_resolved)
    if archive_path is not None:
        arch_resolved = _safe_resolve(archive_path)
        if arch_resolved is not None:
            protected_outputs.add(arch_resolved)

    base_stem = sanitize_filename(src.stem, default="app", max_len=100)
    out_name = sanitize_filename(f"{base_stem}_uyumlu.apk", default="app_uyumlu.apk")
    signed = jdir / out_name
    signed_resolved = _safe_resolve(signed)
    if signed_resolved is not None and signed_resolved in protected_outputs:
        signed_prefix = base_stem[:90].rstrip("._-") or "app"
        while True:
            out_name = sanitize_filename(
                f"{signed_prefix}_{uuid.uuid4().hex[:6]}_patched.apk",
                default="app_patched.apk",
            )
            signed = jdir / out_name
            signed_resolved = _safe_resolve(signed)
            if signed_resolved is None or signed_resolved not in protected_outputs:
                break

    manifest_override: bytes | None = None
    arsc_override: bytes | None = None
    res_overrides: dict[str, bytes] | None = None

    method = "resign_only"
    manifest_patched = False
    skipped_downgrade = False
    applied_changes: list[str] = []
    fallback_reason: str | None = None
    old_target_sdk: int | None = None
    effective_target_sdk: int | None = None
    binary_axml_tried = False

    try:
        _check_canceled("init")
        _progress(10, "Kaynak APK hazırlanıyor")
        _log(f"İşlem başlatıldı: mode={mode}, targetSdk={target_sdk}, resign={resign}")

        should_patch_manifest = mode == "patch_and_sign" and (
            opts.patch_target_sdk or opts.needs_structural_patch()
        )

        if should_patch_manifest:
            use_fast_axml = (
                opts.patch_target_sdk
                and not opts.needs_structural_patch()
                and target_sdk < 31
            )
            need_slim_apktool = not use_fast_axml

            if use_fast_axml:
                _check_canceled("binary_axml")
                _progress(20, "Hızlı Binary AXML yaması deneniyor")
                binary_axml_tried = True
                try:
                    with zipfile.ZipFile(src, "r") as zin:
                        raw_manifest = zin.read("AndroidManifest.xml")
                except (
                    zipfile.BadZipFile,
                    zipfile.LargeZipFile,
                    zlib.error,
                    EOFError,
                    RuntimeError,
                    KeyError,
                ) as exc:
                    raise InvalidArchiveError(
                        f"APK manifesti okunamadı (bozuk, eksik veya şifreli): {exc}"
                    ) from exc
                axml_res = patch_binary_axml_target_sdk(
                    raw_manifest,
                    target_sdk,
                    allow_downgrade=opts.allow_downgrade,
                )
                old_target_sdk = axml_res.get("oldTargetSdk")
                effective_target_sdk = axml_res.get("effectiveTargetSdk")

                if axml_res.get("patched"):
                    method = "binary_axml"
                    if axml_res["data"] != raw_manifest:
                        manifest_override = axml_res["data"]
                    if old_target_sdk != effective_target_sdk:
                        manifest_patched = True
                        applied_changes.append(
                            f"targetSdkVersion:{old_target_sdk}->{effective_target_sdk}"
                        )
                        _log(
                            f"Binary AXML yaması başarılı: targetSdk {old_target_sdk} -> {effective_target_sdk}"
                        )
                    else:
                        manifest_patched = False
                        _log(
                            f"Binary AXML: targetSdkVersion zaten {effective_target_sdk}; değişiklik gerekmedi."
                        )
                elif axml_res.get("skippedDowngrade"):
                    method = "binary_axml"
                    manifest_patched = False
                    skipped_downgrade = True
                    _log(axml_res.get("reason") or "Düşürme atlandı.")
                else:
                    _log(
                        f"Binary AXML uygulanamadı ({axml_res.get('reason') or axml_res.get('error')}); "
                        "Slim-Apktool yoluna geçiliyor."
                    )
                    need_slim_apktool = True

            if need_slim_apktool:
                _check_canceled("slim_apktool")
                _progress(25, "Slim-Apktool manifest yaması çalışıyor")
                slim_apk = work_dir / "slim_manifest.apk"
                dec_dir = work_dir / "decoded"
                rebuilt_slim = work_dir / "rebuilt_slim.apk"

                try:
                    build_slim_manifest_apk(
                        src,
                        slim_apk,
                        max_bytes=DEFAULT_SLIM_MAX_BYTES,
                        cancel_event=cancel_event,
                    )
                    dec_res = run_cmd(
                        [
                            "apktool",
                            "d",
                            "-s",
                            "-f",
                            "-p",
                            str(fw_dir),
                            str(slim_apk),
                            "-o",
                            str(dec_dir),
                        ],
                        timeout=240,
                        cancel_event=cancel_event,
                        on_proc=on_proc,
                    )
                    if dec_res.returncode != 0:
                        raise PatchError(f"apktool d başarısız: {dec_res.clean_output[-500:]}")

                    yml_path = dec_dir / "apktool.yml"
                    yml_min, yml_target = read_apktool_yml_sdk_info(yml_path)
                    xml_res = patch_manifest_xml_apktool(
                        dec_dir / "AndroidManifest.xml",
                        opts,
                        known_min_sdk=yml_min,
                        known_target_sdk=yml_target,
                    )
                    if xml_res.get("error"):
                        raise PatchError(str(xml_res["error"]))

                    old_target_sdk = xml_res.get("oldTargetSdk")
                    effective_target_sdk = xml_res.get("newTargetSdk")
                    skipped_downgrade = bool(xml_res.get("skippedDowngrade"))
                    applied_changes = list(xml_res.get("appliedChanges") or [])

                    yml_updated = False
                    if (
                        opts.patch_target_sdk
                        and not skipped_downgrade
                        and xml_res.get("newTargetSdk") is not None
                        and yml_target != int(xml_res["newTargetSdk"])
                    ):
                        yml_updated = update_apktool_yml(yml_path, int(xml_res["newTargetSdk"]))

                    if xml_res.get("changed") or yml_updated:
                        _check_canceled("apktool_build")
                        _progress(45, "Apktool ile manifest yeniden derleniyor")
                        bld_res = run_cmd(
                            [
                                "apktool",
                                "b",
                                "-p",
                                str(fw_dir),
                                str(dec_dir),
                                "-o",
                                str(rebuilt_slim),
                            ],
                            timeout=240,
                            cancel_event=cancel_event,
                            on_proc=on_proc,
                        )
                        if bld_res.returncode != 0 or not rebuilt_slim.is_file():
                            raise PatchError(f"apktool b başarısız: {bld_res.clean_output[-500:]}")

                        with zipfile.ZipFile(rebuilt_slim, "r") as zreb:
                            names = set(zreb.namelist())
                            if "AndroidManifest.xml" in names:
                                manifest_override = zreb.read("AndroidManifest.xml")
                            if "resources.arsc" in names:
                                arsc_override = zreb.read("resources.arsc")
                        diff_res = _diff_rebuilt_res_entries(slim_apk, rebuilt_slim)
                        if diff_res:
                            res_overrides = diff_res

                        method = "slim_apktool"
                        manifest_patched = True
                        _log(
                            f"Slim-Apktool yaması tamamlandı: {', '.join(applied_changes) or 'güncellendi'}"
                        )
                    else:
                        method = "slim_apktool"
                        manifest_patched = False
                        _log("Manifest zaten istenen ayarları içeriyor veya düşürme atlandı.")

                except (CommandCanceledError, InvalidArchiveError):
                    raise
                except (SlimApkTooLargeError, PatchError, RetroDroidError, OSError) as exc:
                    fallback_reason = str(getattr(exc, "detail", exc))[-500:]
                    _log(f"Slim-Apktool başarısız (yedek moda geçiliyor): {fallback_reason}")

                    # Reset any partial state from an aborted Slim-Apktool attempt (e.g., apktool b failure)
                    manifest_override = None
                    arsc_override = None
                    res_overrides = None
                    manifest_patched = False
                    applied_changes = []
                    skipped_downgrade = False
                    effective_target_sdk = None

                    fallback_done = False
                    if opts.patch_target_sdk and target_sdk < 31 and not binary_axml_tried:
                        try:
                            with zipfile.ZipFile(src, "r") as zin:
                                raw_manifest = zin.read("AndroidManifest.xml")
                            axml_fb = patch_binary_axml_target_sdk(
                                raw_manifest,
                                target_sdk,
                                allow_downgrade=opts.allow_downgrade,
                            )
                            if axml_fb.get("oldTargetSdk") is not None:
                                old_target_sdk = axml_fb.get("oldTargetSdk")
                            if axml_fb.get("effectiveTargetSdk") is not None:
                                effective_target_sdk = axml_fb.get("effectiveTargetSdk")

                            if axml_fb.get("patched"):
                                method = "fallback_binary_axml"
                                if axml_fb["data"] != raw_manifest:
                                    manifest_override = axml_fb["data"]
                                if old_target_sdk != effective_target_sdk:
                                    manifest_patched = True
                                    applied_changes = [
                                        f"targetSdkVersion:{old_target_sdk}->{effective_target_sdk}"
                                    ]
                                    _log(
                                        f"Yedek Binary AXML yaması başarılı: "
                                        f"{old_target_sdk} -> {effective_target_sdk}"
                                    )
                                else:
                                    manifest_patched = False
                                    applied_changes = []
                                    _log(
                                        f"Yedek Binary AXML: targetSdkVersion zaten "
                                        f"{effective_target_sdk}; değişiklik gerekmedi."
                                    )
                                fallback_done = True
                            elif axml_fb.get("skippedDowngrade"):
                                method = "fallback_binary_axml"
                                manifest_patched = False
                                skipped_downgrade = True
                                applied_changes = []
                                fallback_done = True
                                _log(axml_fb.get("reason") or "Yedek Binary AXML: Düşürme atlandı.")
                        except (
                            RetroDroidError,
                            zipfile.BadZipFile,
                            zipfile.LargeZipFile,
                            zlib.error,
                            EOFError,
                            RuntimeError,
                            KeyError,
                            OSError,
                        ) as fb_exc:
                            _log(f"Yedek Binary AXML denemesi başarısız: {fb_exc}")

                    if not fallback_done:
                        method = "fallback_resign"
                        manifest_patched = False
                        applied_changes = []
                        _log("Güvenli yeniden imzalama (resign) yedek modu kullanılıyor.")

        # Streaming APK rewrite (strips old META-INF, enforces ZIP_STORED on resources.arsc & .so)
        _check_canceled("stream_rewrite")
        _progress(60, "APK akış yeniden yazımı çalışıyor")
        sanitized_apk = work_dir / "sanitized.apk"
        rewrite_stats = stream_rewrite_apk(
            src,
            sanitized_apk,
            manifest_override=manifest_override,
            arsc_override=arsc_override,
            res_overrides=res_overrides,
            max_decompressed_bytes=cfg.MAX_DECOMPRESSED_BYTES,
            cancel_event=cancel_event,
        )
        _log(
            f"APK yeniden yazıldı: {rewrite_stats['entriesWritten']} dosya, "
            f"{rewrite_stats['strippedSignatureEntries']} eski imza temizlendi."
        )

        # Align, Sign & Verify
        _check_canceled("align_sign")
        _progress(75, "zipalign ve apksigner çalışıyor")
        verify_out: list[str] = []
        align_logs = align_and_sign_apk(
            sanitized_apk,
            signed,
            keystore_state,
            resign=resign,
            timeout=300,
            verify_out=verify_out,
            cancel_event=cancel_event,
            on_proc=on_proc,
        )
        for line in align_logs:
            _log(line)
        sanitized_apk.unlink(missing_ok=True)

        # Post-patch inspection preserving container split ABIs
        _check_canceled("inspect_post")
        _progress(85, "Çıktı APK doğrulanıyor")
        preverified = verify_out[0] if (resign and verify_out) else None
        post_info = inspect_apk(
            signed,
            container_info=container_meta,
            preverified_sig_text=preverified,
        )

        # Split APK processing & atomic .apks bundle assembly
        split_bundle_info: dict[str, Any] | None = None
        patched_split_names: list[str] = []

        if (
            container_meta
            and container_meta.get("splitApks")
            and archive_path is not None
            and archive_path.is_file()
        ):
            _check_canceled("splits")
            _progress(90, "Split APK paketleri işleniyor")
            bundle_stem = sanitize_filename(signed.stem, default="app", max_len=95)
            bundle_name = sanitize_filename(
                f"{bundle_stem}_SplitPaket.apks",
                default="app_SplitPaket.apks",
            )
            bundle_path = jdir / bundle_name
            bundle_protected: set[Path] = set(protected_outputs)
            if signed_resolved is not None:
                bundle_protected.add(signed_resolved)
            bundle_resolved = _safe_resolve(bundle_path)
            if bundle_resolved is not None and bundle_resolved in bundle_protected:
                bundle_prefix = bundle_stem[:85].rstrip("._-") or "app"
                while True:
                    bundle_name = sanitize_filename(
                        f"{bundle_prefix}_{uuid.uuid4().hex[:6]}_SplitPaket.apks",
                        default="app_SplitPaket.apks",
                    )
                    bundle_path = jdir / bundle_name
                    bundle_resolved = _safe_resolve(bundle_path)
                    if bundle_resolved is None or bundle_resolved not in bundle_protected:
                        break
            bundle_tmp = work_dir / f".{bundle_name}.{uuid.uuid4().hex[:8]}.tmp"

            eff_post_target = int(
                post_info.get("targetSdk") or effective_target_sdk or target_sdk
            )
            split_entries = container_meta.get("splitApks") or []

            try:
                with (
                    zipfile.ZipFile(archive_path, "r") as zarch,
                    zipfile.ZipFile(bundle_tmp, "w", allowZip64=True) as zbundle,
                ):
                    # Write signed base.apk
                    base_info = zipfile.ZipInfo("base.apk")
                    base_info.date_time = (1980, 1, 1, 0, 0, 0)
                    base_info.compress_type = zipfile.ZIP_STORED
                    base_size = signed.stat().st_size
                    with (
                        open(signed, "rb") as bfp,
                        zbundle.open(
                            base_info,
                            "w",
                            force_zip64=(base_size >= 0xFFFFFFFF),
                        ) as wfp,
                    ):
                        copy_stream_limited(
                            bfp,
                            wfp,
                            cfg.MAX_DECOMPRESSED_BYTES,
                            "base.apk",
                            cancel_event=cancel_event,
                        )

                    used_split_names: set[str] = {"base.apk"}
                    for sp_idx, sp in enumerate(split_entries):
                        _check_canceled("split_item")
                        if not isinstance(sp, dict):
                            raise InvalidArchiveError(
                                f"Split girdisi eksik veya geçersiz: split_{sp_idx}.apk",
                                status_code=404,
                            )
                        zip_entry = sp["zipEntry"] if "zipEntry" in sp else sp.get("name")
                        sp_name = sanitize_filename(
                            str(sp.get("name") or f"split_{sp_idx}.apk"),
                            default=f"split_{sp_idx}.apk",
                        )
                        if sp_name.lower() in used_split_names:
                            base_sp = sp_name
                            sp_name = sanitize_filename(
                                f"split_{sp_idx}_{base_sp}",
                                default=f"split_{sp_idx}.apk",
                            )
                            dedup_n = 1
                            while sp_name.lower() in used_split_names:
                                sp_name = sanitize_filename(
                                    f"split_{sp_idx}_{dedup_n}_{base_sp}",
                                    default=f"split_{sp_idx}_{dedup_n}.apk",
                                )
                                dedup_n += 1
                        used_split_names.add(sp_name.lower())

                        sp_raw = work_dir / f"sp_raw_{sp_idx}.apk"
                        sp_san = work_dir / f"sp_san_{sp_idx}.apk"
                        sp_out = work_dir / f"sp_out_{sp_idx}.apk"

                        if not isinstance(zip_entry, str) or not zip_entry:
                            raise InvalidArchiveError(
                                f"Split girdisi eksik veya geçersiz: {sp_name}",
                                status_code=404,
                            )
                        try:
                            sp_zinfo = zarch.getinfo(zip_entry)
                        except KeyError as exc:
                            raise InvalidArchiveError(
                                f"Split girdisi arşivde bulunamadı: {zip_entry}",
                                status_code=404,
                            ) from exc
                        if sp_zinfo.flag_bits & 0x1:
                            raise InvalidArchiveError(
                                f"Şifreli split girdisi desteklenmiyor: {zip_entry}"
                            )

                        with zarch.open(sp_zinfo, "r") as rfp, open(sp_raw, "wb") as wfp:
                            copy_stream_limited(
                                rfp,
                                wfp,
                                cfg.MAX_DECOMPRESSED_BYTES,
                                f"Split APK ({sp_name})",
                                cancel_event=cancel_event,
                            )

                        sp_manifest_ov: bytes | None = None
                        sp_arsc_ov: bytes | None = None
                        sp_res_ov: dict[str, bytes] | None = None

                        if (
                            mode == "patch_and_sign"
                            and eff_post_target >= 31
                            and count_missing_exported_components(sp_raw) > 0
                        ):
                            try:
                                sp_manifest_ov, sp_arsc_ov, sp_res_ov, sp_changed = (
                                    _patch_feature_split_exported(
                                        sp_raw,
                                        work_dir,
                                        fw_dir,
                                        eff_post_target,
                                        cancel_event=cancel_event,
                                        on_proc=on_proc,
                                    )
                                )
                                if sp_changed:
                                    patched_split_names.append(sp_name)
                                    _log(
                                        f"Split APK ({sp_name}) API 31+ android:exported ile yamalandı."
                                    )
                            except CommandCanceledError:
                                raise
                            except (RetroDroidError, zipfile.BadZipFile, KeyError, OSError) as sp_exc:
                                _log(
                                    f"Split APK ({sp_name}) manifest yaması atlandı: {sp_exc}"
                                )

                        stream_rewrite_apk(
                            sp_raw,
                            sp_san,
                            manifest_override=sp_manifest_ov,
                            arsc_override=sp_arsc_ov,
                            res_overrides=sp_res_ov,
                            max_decompressed_bytes=cfg.MAX_DECOMPRESSED_BYTES,
                            cancel_event=cancel_event,
                        )
                        align_and_sign_apk(
                            sp_san,
                            sp_out,
                            keystore_state,
                            resign=resign,
                            timeout=240,
                            cancel_event=cancel_event,
                            on_proc=on_proc,
                        )

                        sp_info = zipfile.ZipInfo(sp_name)
                        sp_info.date_time = (1980, 1, 1, 0, 0, 0)
                        sp_info.compress_type = zipfile.ZIP_STORED
                        sp_out_size = sp_out.stat().st_size
                        with (
                            open(sp_out, "rb") as sfp,
                            zbundle.open(
                                sp_info,
                                "w",
                                force_zip64=(sp_out_size >= 0xFFFFFFFF),
                            ) as wfp,
                        ):
                            copy_stream_limited(
                                sfp,
                                wfp,
                                cfg.MAX_DECOMPRESSED_BYTES,
                                sp_name,
                                cancel_event=cancel_event,
                            )

                        sp_raw.unlink(missing_ok=True)
                        sp_san.unlink(missing_ok=True)
                        sp_out.unlink(missing_ok=True)

                os.replace(bundle_tmp, bundle_path)
                b_size = bundle_path.stat().st_size
                split_bundle_info = {
                    "fileName": bundle_name,
                    "downloadUrl": safe_url_download(job_id, bundle_name),
                    "sizeBytes": b_size,
                    "sizeMB": round(b_size / (1024 * 1024), 2),
                    "splitCount": len(split_entries),
                    "patchedSplits": patched_split_names,
                }
                _log(f"Split paketi oluşturuldu: {bundle_name} ({len(split_entries)} split).")
            except KeyError as exc:
                bundle_tmp.unlink(missing_ok=True)
                raise InvalidArchiveError(
                    f"Split girdisi arşivde bulunamadı: {exc}",
                    status_code=404,
                ) from exc
            except (
                zipfile.BadZipFile,
                zipfile.LargeZipFile,
                zlib.error,
                EOFError,
                RuntimeError,
            ) as exc:
                bundle_tmp.unlink(missing_ok=True)
                raise InvalidArchiveError(
                    f"Split arşivi okunamadı (bozuk, kesik veya şifreli): {exc}"
                ) from exc
            except Exception:
                bundle_tmp.unlink(missing_ok=True)
                raise

        # Safe src_apk retention (CRIT-06): delete ONLY AFTER verified signed output AND low disk
        try:
            src_size_mb = src.stat().st_size / (1024 * 1024)
            free_mb = shutil.disk_usage(jdir).free / (1024 * 1024)
            is_needed_archive = bool(
                archive_path is not None
                and archive_path.is_file()
                and src.resolve() == archive_path.resolve()
                and bool((container_meta or {}).get("obbFiles"))
            )
            if (
                src_size_mb > 180.0
                and free_mb < float(cfg.DISK_FREE_FLOOR_MB)
                and signed.is_file()
                and bool(post_info["inspector"]["signature"]["verified"])
                and src.resolve() != signed.resolve()
                and not is_needed_archive
            ):
                src.unlink(missing_ok=True)
                _log(
                    f"Düşük disk alanı ({free_mb:.0f} MB < {cfg.DISK_FREE_FLOOR_MB} MB) nedeniyle "
                    "büyük kaynak APK temizlendi."
                )
        except OSError:
            pass

        repatch_available = src.is_file()
        upload_meta_path = jdir / "upload_meta.json"
        if not repatch_available and upload_meta_path.is_file():
            upload_meta = _load_json_if_file(upload_meta_path)
            if upload_meta is not None:
                upload_meta["repatchAvailable"] = False
                write_json_atomic(upload_meta_path, upload_meta)

        signed_size = signed.stat().st_size
        obb_downloads = [
            {
                "index": idx,
                "name": obb.get("name"),
                "sizeBytes": obb.get("sizeBytes", 0),
                "downloadUrl": f"/api/download-obb/{job_id}/{idx}",
            }
            for idx, obb in enumerate((container_meta or {}).get("obbFiles") or [])
        ]

        patch_summary: dict[str, Any] = {
            "mode": mode,
            "method": method,
            "manifestPatched": manifest_patched,
            "requestedTargetSdk": target_sdk if opts.patch_target_sdk else None,
            "oldTargetSdk": old_target_sdk,
            "effectiveTargetSdk": post_info.get("targetSdk") or effective_target_sdk,
            "skippedDowngrade": skipped_downgrade,
            "appliedChanges": applied_changes,
            "fallbackReason": fallback_reason,
            "patchedSplits": patched_split_names,
            "resigned": resign,
        }

        result: dict[str, Any] = {
            "ok": True,
            "jobId": job_id,
            "fileName": signed.name,
            "downloadUrl": safe_url_download(job_id, signed.name),
            "sizeBytes": signed_size,
            "sizeMB": round(signed_size / (1024 * 1024), 2),
            "verified": bool(post_info["inspector"]["signature"]["verified"]),
            "packageId": post_info["packageId"],
            "appLabel": post_info["appLabel"],
            "versionName": post_info["versionName"],
            "versionCode": post_info["versionCode"],
            "minSdk": post_info["minSdk"],
            "targetSdk": post_info["targetSdk"],
            "abis": post_info["abis"],
            "is32BitOnly": post_info["is32BitOnly"],
            "iconPath": post_info.get("iconPath"),
            "warnings": post_info["warnings"],
            "inspector": post_info["inspector"],
            "installFloorStatus": post_info["installFloorStatus"],
            "pageSize16kStatus": post_info["pageSize16kStatus"],
            "elf16kReport": post_info["elf16kReport"],
            "compatChecklist": post_info["compatChecklist"],
            "compatScore": post_info["compatScore"],
            "splitBundle": split_bundle_info,
            "obbDownloads": obb_downloads,
            "patchSummary": patch_summary,
            "rewriteStats": rewrite_stats,
            "repatchAvailable": repatch_available,
            "logs": logs,
            "serverTime": time.time(),
        }

        write_json_atomic(jdir / "patch_result.json", result)
        _progress(100, "Tamamlandı")
        return result
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            work_dir.parent.rmdir()
        except OSError:
            pass
