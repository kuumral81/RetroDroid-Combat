"""Single-pass APK inspector with ELF64 16 KB page-size audit and Android 14-17 compatibility scoring."""

from __future__ import annotations

import re
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

from retrodroid.config import (
    ApkInspectionError,
    RetroDroidError,
    clean_java_output,
    run_cmd,
)

__all__ = [
    "ApkInspectionError",
    "compute_install_floor_status",
    "count_missing_exported_components",
    "inspect_apk",
    "inspect_elf_16k_alignment",
    "parse_xmltree_manifest",
]

ROOT_DEX_RE = re.compile(r"^classes(?:[0-9]+)?\.dex$")

SPLIT_ABI_RE = re.compile(
    r"(?:^|(?<=[^a-z0-9]))"
    r"(arm64(?:[_-]v8a)?|armeabi[_-]v7a|armv7a?|armeabi(?![_-]v7a?)|"
    r"x86[_-]64|x86(?![_-]?64)|mips[_-]?64|mips(?![_-]?64))"
    r"(?=$|[^a-z0-9])"
)

PERM_RE = re.compile(r"^uses-permission(?:-[A-Za-z0-9_-]+)?:\s*(?:name=)?'([^']+)'", re.MULTILINE)

ABI_32: frozenset[str] = frozenset({"armeabi", "armeabi-v7a", "x86", "mips"})
ABI_64: frozenset[str] = frozenset({"arm64-v8a", "x86_64", "mips64"})
EXPORTABLE_TAGS: frozenset[str] = frozenset({"activity", "activity-alias", "service", "receiver"})

MAX_ELF_PHDR_END = 1024 * 1024  # 1 MiB header safety bound
MAX_REPORT_ITEMS = 50
ELF_PT_LOAD = 1
PAGE_SIZE_16K = 16384


def _canonicalize_abi_token(token: str) -> str | None:
    low = token.lower().replace("_", "-")
    if low in ("arm64", "arm64-v8a"):
        return "arm64-v8a"
    if low in ("armeabi-v7a", "armv7", "armv7a"):
        return "armeabi-v7a"
    if low == "armeabi":
        return "armeabi"
    if low in ("x86-64", "x86_64"):
        return "x86_64"
    if low == "x86":
        return "x86"
    if low in ("mips64", "mips-64"):
        return "mips64"
    if low == "mips":
        return "mips"
    return None


def _extract_split_abis(container_info: dict[str, Any] | None) -> set[str]:
    found: set[str] = set()
    if not container_info or not isinstance(container_info, dict):
        return found
    for sp in container_info.get("splitApks") or []:
        if isinstance(sp, dict):
            candidate = f"{sp.get('name', '')} {sp.get('zipEntry', '')}".lower()
        else:
            candidate = str(sp).lower()
        for match in SPLIT_ABI_RE.findall(candidate):
            canon = _canonicalize_abi_token(match)
            if canon:
                found.add(canon)
    return found


def inspect_elf_16k_alignment(elf_bytes: bytes) -> dict[str, Any]:
    """Pure-Python ELF64 PT_LOAD p_align inspector checking Android 15+ 16 KB alignment."""
    if not isinstance(elf_bytes, (bytes, bytearray, memoryview)):
        return {
            "valid": False,
            "is64Bit": False,
            "elfClass": None,
            "endian": None,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": "ELF verisi geçerli bayt dizisi değil.",
        }

    buf = bytes(elf_bytes)
    n = len(buf)
    if n < 16 or buf[:4] != b"\x7fELF":
        return {
            "valid": False,
            "is64Bit": False,
            "elfClass": None,
            "endian": None,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": "Geçersiz ELF sihirli başlığı (\\x7fELF bulunamadı).",
        }

    ei_class = buf[4]
    ei_data = buf[5]
    if ei_data == 1:
        endian_fmt = "<"
        endian_name = "little"
    elif ei_data == 2:
        endian_fmt = ">"
        endian_name = "big"
    else:
        return {
            "valid": False,
            "is64Bit": ei_class == 2,
            "elfClass": 64 if ei_class == 2 else (32 if ei_class == 1 else None),
            "endian": None,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": f"Bilinmeyen ELF bayt sırası (EI_DATA={ei_data}).",
        }

    if ei_class == 1:
        if n < 52:
            return {
                "valid": False,
                "is64Bit": False,
                "elfClass": 32,
                "endian": endian_name,
                "aligned16k": None,
                "minAlign": None,
                "ptLoadAlignments": [],
                "ptLoadCount": 0,
                "error": "Kesik ELF32 başlığı (< 52 bayt).",
            }
        return {
            "valid": True,
            "is64Bit": False,
            "elfClass": 32,
            "endian": endian_name,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": None,
        }

    if ei_class != 2:
        return {
            "valid": False,
            "is64Bit": False,
            "elfClass": None,
            "endian": endian_name,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": f"Bilinmeyen ELF sınıfı (EI_CLASS={ei_class}).",
        }

    if n < 64:
        return {
            "valid": False,
            "is64Bit": True,
            "elfClass": 64,
            "endian": endian_name,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": "Kesik ELF64 başlığı (< 64 bayt).",
        }

    e_phoff = struct.unpack_from(f"{endian_fmt}Q", buf, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from(f"{endian_fmt}HH", buf, 54)

    if e_phnum == 0xFFFF:
        return {
            "valid": False,
            "is64Bit": True,
            "elfClass": 64,
            "endian": endian_name,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": "Genişletilmiş ELF64 program başlığı (PN_XNUM) desteklenmiyor.",
        }

    if e_phnum > 0 and e_phentsize < 56:
        return {
            "valid": False,
            "is64Bit": True,
            "elfClass": 64,
            "endian": endian_name,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": f"Geçersiz ELF64 e_phentsize ({e_phentsize} < 56).",
        }

    ph_end = e_phoff + e_phnum * e_phentsize
    if e_phnum > 0 and (e_phoff < 64 or ph_end > n):
        return {
            "valid": False,
            "is64Bit": True,
            "elfClass": 64,
            "endian": endian_name,
            "aligned16k": None,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": f"ELF64 program başlık tablosu kesik veya sınır dışı (son={ph_end}, boyut={n}).",
        }

    aligns: list[int] = []
    for idx in range(e_phnum):
        off = e_phoff + idx * e_phentsize
        p_type = struct.unpack_from(f"{endian_fmt}I", buf, off)[0]
        if p_type == ELF_PT_LOAD:
            p_align = struct.unpack_from(f"{endian_fmt}Q", buf, off + 48)[0]
            aligns.append(p_align)

    if not aligns:
        return {
            "valid": True,
            "is64Bit": True,
            "elfClass": 64,
            "endian": endian_name,
            "aligned16k": False,
            "minAlign": None,
            "ptLoadAlignments": [],
            "ptLoadCount": 0,
            "error": "PT_LOAD segmenti bulunamadı",
        }

    is_aligned = all(a >= PAGE_SIZE_16K and (a & (a - 1)) == 0 for a in aligns)
    return {
        "valid": True,
        "is64Bit": True,
        "elfClass": 64,
        "endian": endian_name,
        "aligned16k": is_aligned,
        "minAlign": min(aligns),
        "ptLoadAlignments": aligns,
        "ptLoadCount": len(aligns),
        "error": None,
    }


def _inspect_zip_elf_entry(z: zipfile.ZipFile, item: zipfile.ZipInfo) -> dict[str, Any]:
    """Read ONLY the ELF64 header + program header table from a ZIP member (<= 1 MiB)."""
    with z.open(item, "r") as sf:
        ehdr = sf.read(64)
        if len(ehdr) < 64 or ehdr[:4] != b"\x7fELF" or ehdr[4] != 2 or ehdr[5] not in (1, 2):
            return inspect_elf_16k_alignment(ehdr)

        endian_fmt = "<" if ehdr[5] == 1 else ">"
        e_phoff = struct.unpack_from(f"{endian_fmt}Q", ehdr, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(f"{endian_fmt}HH", ehdr, 54)
        if e_phnum == 0 or e_phnum == 0xFFFF or e_phentsize < 56:
            return inspect_elf_16k_alignment(ehdr)

        needed_end = e_phoff + e_phnum * e_phentsize
        if needed_end > MAX_ELF_PHDR_END:
            return {
                "valid": False,
                "is64Bit": True,
                "elfClass": 64,
                "endian": "little" if endian_fmt == "<" else "big",
                "aligned16k": None,
                "minAlign": None,
                "ptLoadAlignments": [],
                "ptLoadCount": 0,
                "error": f"ELF64 program başlık tablosu konumu sınırı aşıyor ({needed_end} bayt)",
            }

        rest = sf.read(needed_end - 64) if needed_end > 64 else b""
        return inspect_elf_16k_alignment(ehdr + rest)


def _parse_xmltree_bool(raw_val: str) -> bool | None:
    bm = re.search(r"\(type 0x12\)0x([0-9a-fA-F]+)", raw_val)
    if bm:
        return int(bm.group(1), 16) != 0
    low = raw_val.strip().lower()
    if low in ("true", '"true"'):
        return True
    if low in ("false", '"false"'):
        return False
    return None


def parse_xmltree_manifest(xmltree_text: str) -> dict[str, Any]:
    """Parse `aapt dump xmltree <apk> AndroidManifest.xml` output for API 31+ exported audit."""
    stack: list[dict[str, Any]] = []
    missing_components: list[dict[str, str]] = []
    missing_count = 0
    manifest_flags: dict[str, bool | None] = {
        "requestLegacyExternalStorage": None,
        "usesCleartextTraffic": None,
        "extractNativeLibs": None,
        "resizeableActivity": None,
    }

    def _finalize(node: dict[str, Any]) -> None:
        nonlocal missing_count
        if node["tag"] in EXPORTABLE_TAGS and node["has_intent_filter"] and not node["has_exported"]:
            missing_count += 1
            if len(missing_components) < MAX_REPORT_ITEMS:
                missing_components.append(
                    {"tag": str(node["tag"]), "name": str(node.get("name") or "")}
                )

    for line in (xmltree_text or "").replace("\r\n", "\n").splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if stripped.startswith("E:"):
            em = re.match(r"^E:\s*([^\s(]+)", stripped)
            if not em:
                continue
            tag = em.group(1)
            while stack and stack[-1]["indent"] >= indent:
                _finalize(stack.pop())

            if tag == "intent-filter" and stack and stack[-1]["tag"] in EXPORTABLE_TAGS:
                stack[-1]["has_intent_filter"] = True

            stack.append(
                {
                    "indent": indent,
                    "tag": tag,
                    "has_exported": False,
                    "has_intent_filter": False,
                    "name": "",
                }
            )
        elif stripped.startswith("A:"):
            if not stack or stack[-1]["indent"] >= indent:
                continue
            am = re.match(r"^A:\s*([^(=]*?)(?:\((0x[0-9a-fA-F]+)\))?=(.*)$", stripped)
            if not am:
                continue
            attr_name = am.group(1).strip()
            res_id = (am.group(2) or "").lower()
            raw_val = am.group(3).strip()
            cur = stack[-1]

            if cur["tag"] in EXPORTABLE_TAGS:
                if attr_name in ("android:exported", "exported") or res_id == "0x01010010":
                    cur["has_exported"] = True
                elif attr_name in ("android:name", "name") or res_id == "0x01010003":
                    nm = re.search(r'"([^"]*)"', raw_val)
                    cur["name"] = nm.group(1) if nm else raw_val
            elif cur["tag"] == "application":
                if (
                    attr_name in ("android:requestLegacyExternalStorage", "requestLegacyExternalStorage")
                    or res_id == "0x01010603"
                ):
                    manifest_flags["requestLegacyExternalStorage"] = _parse_xmltree_bool(raw_val)
                elif (
                    attr_name in ("android:usesCleartextTraffic", "usesCleartextTraffic")
                    or res_id == "0x010104ec"
                ):
                    manifest_flags["usesCleartextTraffic"] = _parse_xmltree_bool(raw_val)
                elif (
                    attr_name in ("android:extractNativeLibs", "extractNativeLibs")
                    or res_id == "0x010104ea"
                ):
                    manifest_flags["extractNativeLibs"] = _parse_xmltree_bool(raw_val)
                elif (
                    attr_name in ("android:resizeableActivity", "resizeableActivity")
                    or res_id == "0x010104f6"
                ):
                    manifest_flags["resizeableActivity"] = _parse_xmltree_bool(raw_val)

    while stack:
        _finalize(stack.pop())

    return {
        "missingExportedCount": missing_count,
        "missingExportedComponents": missing_components,
        "manifestFlags": manifest_flags,
    }


def _inspect_xmltree(apk_path: Path) -> tuple[int | None, list[dict[str, str]], dict[str, bool | None]]:
    default_flags: dict[str, bool | None] = {
        "requestLegacyExternalStorage": None,
        "usesCleartextTraffic": None,
        "extractNativeLibs": None,
        "resizeableActivity": None,
    }
    try:
        res = run_cmd(["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"], timeout=90)
        if res.returncode != 0:
            return None, [], default_flags
        parsed = parse_xmltree_manifest(res.stdout)
        return (
            int(parsed["missingExportedCount"]),
            list(parsed["missingExportedComponents"]),
            dict(parsed["manifestFlags"]),
        )
    except RetroDroidError:
        return None, [], default_flags


def count_missing_exported_components(apk_path: Path) -> int:
    """Return the count of <activity|activity-alias|service|receiver> with <intent-filter> lacking exported."""
    count, _, _ = _inspect_xmltree(Path(apk_path))
    return count if count is not None else 0


def compute_install_floor_status(target_sdk: int, min_sdk: int = 0) -> dict[str, Any]:
    """Evaluate Android 14 (API 23) and Android 15-17 (API 24) install-block policy."""
    t_sdk = int(target_sdk or 0)
    m_sdk = int(min_sdk or 0)
    effective = t_sdk if t_sdk > 0 else max(0, m_sdk)

    if effective <= 0:
        status = "unknown"
        a14_ok = False
        a15_ok = False
        summary = "targetSdkVersion belirtilmemiş; Android 14+ kurulum uyumluluğu belirsiz."
    elif effective < 23:
        status = "blocked_android14_plus"
        a14_ok = False
        a15_ok = False
        summary = (
            f"targetSdk {effective} < 23: Android 14 (min API 23) ve Android 15-17 "
            "(min API 24) cihazlarda doğrudan kurulum engellenir."
        )
    elif effective == 23:
        status = "blocked_android15_plus"
        a14_ok = True
        a15_ok = False
        summary = (
            "targetSdk 23: Android 14'te kurulabilir ancak Android 15/16/17 "
            "(min API 24) cihazlarda kurulum engellenir."
        )
    else:
        status = "ok"
        a14_ok = True
        a15_ok = True
        summary = f"targetSdk {effective} >= 24: Android 14 ve Android 15-17 kurulum eşiklerini karşılar."

    return {
        "status": status,
        "effectiveTargetSdk": effective,
        "android14MinSdk": 23,
        "android15To17MinSdk": 24,
        "android14Compatible": a14_ok,
        "android15To17Compatible": a15_ok,
        "summary": summary,
    }


def _parse_badging_package_meta(badging_out: str) -> tuple[str, str, str]:
    pkg_line_m = re.search(r"^package:[^\r\n]*", badging_out, re.MULTILINE)
    if pkg_line_m:
        pkg_line = pkg_line_m.group(0)
        pkg_m = re.search(r"(?:^package:\s*|\s)name='([^']+)'", pkg_line)
        vc_m = re.search(r"(?:^package:\s*|\s)versionCode='([^']*)'", pkg_line)
        vn_m = re.search(r"(?:^package:\s*|\s)versionName='([^']*)'", pkg_line)
    else:
        pkg_m = None
        vc_m = re.search(r"^versionCode='([^']*)'", badging_out, re.MULTILINE)
        vn_m = re.search(r"^versionName='([^']*)'", badging_out, re.MULTILINE)
    package_id = pkg_m.group(1) if pkg_m else "bilinmiyor"
    version_code = vc_m.group(1) if vc_m else ""
    version_name = vn_m.group(1) if vn_m else ""
    return package_id, version_code, version_name


def _parse_app_label(badging_out: str, fallback: str) -> str:
    m = re.search(r"^application-label:'(.*)'\s*$", badging_out, re.MULTILINE)
    if m and m.group(1):
        return m.group(1)
    m = re.search(r"^application-label-[A-Za-z0-9_-]+:'(.*)'\s*$", badging_out, re.MULTILINE)
    if m and m.group(1):
        return m.group(1)
    m = re.search(r"^application:\s*label='(.*)'\s+icon='", badging_out, re.MULTILINE)
    if m and m.group(1):
        return m.group(1)
    return fallback


def _select_icon_path(badging_out: str, zip_entry_names: set[str]) -> str | None:
    raster_exts = (".png", ".webp", ".jpg", ".jpeg")
    candidates: list[tuple[int, str]] = []
    for dpi_s, icon_p in re.findall(r"^application-icon-(\d+):'([^']+)'", badging_out, re.MULTILINE):
        if icon_p in zip_entry_names:
            candidates.append((int(dpi_s), icon_p))
    candidates.sort(key=lambda pair: pair[0], reverse=True)

    app_icon_m = re.search(r"^application:.*?icon='([^']+)'", badging_out, re.MULTILINE)
    if app_icon_m and app_icon_m.group(1) in zip_entry_names:
        candidates.append((0, app_icon_m.group(1)))

    for _, path in candidates:
        if path.lower().endswith(raster_exts):
            return path
    return candidates[0][1] if candidates else None


def _dex_sort_key(entry: dict[str, Any]) -> int:
    name = str(entry.get("name") or "")
    m = re.fullmatch(r"classes(\d*)\.dex", name)
    if m and m.group(1):
        return int(m.group(1))
    return 0


def _build_compat_checklist(
    *,
    install_floor: dict[str, Any],
    has_native_libs: bool,
    is_32bit_only: bool,
    abi_list: list[str],
    signature_info: dict[str, Any],
    page_size_status: str,
    resources_arsc_compressed: bool,
    missing_exported_count: int | None,
) -> tuple[list[dict[str, Any]], int]:
    effective = int(install_floor.get("effectiveTargetSdk") or 0)
    checklist: list[dict[str, Any]] = []
    score = 100

    # 1. target_sdk_floor
    if effective >= 24:
        checklist.append(
            {
                "id": "target_sdk_floor",
                "status": "pass",
                "impact": 0,
                "message": install_floor["summary"],
            }
        )
    elif effective == 23:
        score -= 15
        checklist.append(
            {
                "id": "target_sdk_floor",
                "status": "warn",
                "impact": -15,
                "message": install_floor["summary"],
            }
        )
    elif effective == 0:
        score -= 20
        checklist.append(
            {
                "id": "target_sdk_floor",
                "status": "warn",
                "impact": -20,
                "message": install_floor["summary"],
            }
        )
    else:
        score -= 30
        checklist.append(
            {
                "id": "target_sdk_floor",
                "status": "fail",
                "impact": -30,
                "message": install_floor["summary"],
            }
        )

    # 2. abi_64bit
    if not has_native_libs:
        checklist.append(
            {
                "id": "abi_64bit",
                "status": "pass",
                "impact": 0,
                "message": "Saf Java/DEX paketi (yerel .so mimari kısıtı yok).",
            }
        )
    elif is_32bit_only:
        score -= 25
        checklist.append(
            {
                "id": "abi_64bit",
                "status": "fail",
                "impact": -25,
                "message": (
                    f"Sadece 32-bit yerel kütüphaneler bulundu ({', '.join(abi_list)}). "
                    "64-bit zorunlu cihazlarda donanım uyumsuzluğu oluşur."
                ),
            }
        )
    else:
        checklist.append(
            {
                "id": "abi_64bit",
                "status": "pass",
                "impact": 0,
                "message": f"64-bit yerel kütüphane desteği mevcut ({', '.join(abi_list)}).",
            }
        )

    # 3. signature_scheme
    sig_verified = bool(signature_info.get("verified"))
    has_modern_sig = bool(
        signature_info.get("v2") or signature_info.get("v3") or signature_info.get("v31")
    )
    if sig_verified and has_modern_sig:
        checklist.append(
            {
                "id": "signature_scheme",
                "status": "pass",
                "impact": 0,
                "message": "APK v2/v3 modern imza şemasıyla doğrulanmıştır.",
            }
        )
    elif sig_verified:
        score -= 10
        checklist.append(
            {
                "id": "signature_scheme",
                "status": "warn",
                "impact": -10,
                "message": "APK yalnızca v1 (JAR) imzalı; Android 11+ (API 30+) için v2/v3 imza gerekir.",
            }
        )
    else:
        score -= 20
        checklist.append(
            {
                "id": "signature_scheme",
                "status": "fail",
                "impact": -20,
                "message": "APK imzası geçersiz veya eksik; yeniden imzalama gereklidir.",
            }
        )

    # 4. page_size_16k
    if page_size_status in ("compatible", "not_applicable_pure_java"):
        checklist.append(
            {
                "id": "page_size_16k",
                "status": "pass",
                "impact": 0,
                "message": (
                    "Tüm 64-bit ELF .so kütüphaneleri 16 KB sayfa hizalamasını destekliyor."
                    if page_size_status == "compatible"
                    else "Yerel .so kütüphanesi yok; 16 KB sayfa boyutu kısıtı uygulanmaz."
                ),
            }
        )
    elif page_size_status == "not_applicable_32bit_only":
        checklist.append(
            {
                "id": "page_size_16k",
                "status": "info",
                "impact": 0,
                "message": "Yalnızca 32-bit yerel kütüphaneler mevcut; 64-bit 16 KB ELF testi uygulanmaz.",
            }
        )
    elif page_size_status == "incompatible":
        score -= 10
        checklist.append(
            {
                "id": "page_size_16k",
                "status": "warn",
                "impact": -10,
                "message": "Bazı 64-bit ELF .so kütüphaneleri 4 KB (0x1000) hizalı; 16 KB Android 15+ cihazlarda sorun çıkarabilir.",
            }
        )
    else:
        score -= 3
        checklist.append(
            {
                "id": "page_size_16k",
                "status": "warn",
                "impact": -3,
                "message": "64-bit ELF 16 KB sayfa hizalaması tam doğrulanamadı (split APK veya okunamayan ELF).",
            }
        )

    # 5. resources_arsc_uncompressed
    if not resources_arsc_compressed:
        checklist.append(
            {
                "id": "resources_arsc_uncompressed",
                "status": "pass",
                "impact": 0,
                "message": "resources.arsc sıkıştırılmamış (ZIP_STORED) veya mevcut değil.",
            }
        )
    else:
        score -= 10
        checklist.append(
            {
                "id": "resources_arsc_uncompressed",
                "status": "fail" if effective >= 30 else "warn",
                "impact": -10,
                "message": "resources.arsc sıkıştırılmış (ZIP_DEFLATED); Android 11+ (API 30+) kurulumunda reddedilir.",
            }
        )

    # 6. api31_exported
    if missing_exported_count is None:
        checklist.append(
            {
                "id": "api31_exported",
                "status": "info",
                "impact": 0,
                "message": "android:exported denetimi çalıştırılamadı.",
            }
        )
    elif missing_exported_count == 0:
        checklist.append(
            {
                "id": "api31_exported",
                "status": "pass",
                "impact": 0,
                "message": "intent-filter içeren tüm bileşenlerde android:exported tanımlı.",
            }
        )
    elif effective >= 31:
        score -= 15
        checklist.append(
            {
                "id": "api31_exported",
                "status": "fail",
                "impact": -15,
                "message": (
                    f"API 31+ hedeflenirken {missing_exported_count} bileşende intent-filter olmasına rağmen "
                    "android:exported eksik."
                ),
            }
        )
    else:
        score -= 5
        checklist.append(
            {
                "id": "api31_exported",
                "status": "warn",
                "impact": -5,
                "message": (
                    f"{missing_exported_count} bileşende android:exported eksik; "
                    "API 31+ hedeflenirse otomatik eklenmelidir."
                ),
            }
        )

    return checklist, max(0, min(100, score))


def inspect_apk(
    apk_path: Path,
    container_info: dict[str, Any] | None = None,
    preverified_sig_text: str | None = None,
) -> dict[str, Any]:
    """Perform a single-pass ZIP, ELF64-16KB, aapt badging/xmltree, and apksigner inspection."""
    path = Path(apk_path)
    if not path.is_file():
        raise ApkInspectionError("APK dosyası bulunamadı.", status_code=400)

    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError as exc:
        raise ApkInspectionError(f"APK dosyası okunamadı: {exc}", status_code=400) from exc

    if len(head) < 2 or head[:2] != b"PK":
        raise ApkInspectionError("Geçerli bir APK/ZIP arşivi değil (PK başlığı yok).", status_code=400)

    has_manifest = False
    has_arsc = False
    resources_arsc_compressed = False
    base_abis: set[str] = set()
    zip_entry_names: set[str] = set()
    dex_entries: list[dict[str, Any]] = []
    seen_dex: set[str] = set()
    dex_total_methods = 0
    dex_total_classes = 0
    signature_files: list[str] = []

    elf_checked = 0
    elf_aligned = 0
    elf_unaligned = 0
    elf_invalid = 0
    elf_aligned_files: list[str] = []
    elf_unaligned_files: list[str] = []
    elf_invalid_files: list[str] = []

    try:
        with zipfile.ZipFile(path, "r") as z:
            for item in z.infolist():
                name = item.filename
                if item.is_dir():
                    continue
                zip_entry_names.add(name)

                if name == "AndroidManifest.xml":
                    has_manifest = True
                elif name == "resources.arsc":
                    has_arsc = True
                    resources_arsc_compressed = item.compress_type != zipfile.ZIP_STORED
                elif name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) >= 3 and parts[1]:
                        abi = parts[1]
                        base_abis.add(abi)
                        if abi in ABI_64:
                            elf_checked += 1
                            try:
                                elf_res = _inspect_zip_elf_entry(z, item)
                            except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error, EOFError) as exc:
                                elf_res = {"valid": False, "aligned16k": None, "error": str(exc)}
                            if elf_res.get("valid") and elf_res.get("aligned16k") is True:
                                elf_aligned += 1
                                if len(elf_aligned_files) < MAX_REPORT_ITEMS:
                                    elf_aligned_files.append(name)
                            elif elf_res.get("valid") and elf_res.get("aligned16k") is False:
                                elf_unaligned += 1
                                if len(elf_unaligned_files) < MAX_REPORT_ITEMS:
                                    elf_unaligned_files.append(name)
                            else:
                                elf_invalid += 1
                                if len(elf_invalid_files) < MAX_REPORT_ITEMS:
                                    elf_invalid_files.append(name)
                elif ROOT_DEX_RE.fullmatch(name):
                    if name in seen_dex:
                        continue
                    seen_dex.add(name)
                    dex_ver = ""
                    methods = 0
                    classes = 0
                    try:
                        with z.open(item, "r") as df:
                            header = df.read(112)
                        if len(header) >= 100 and header[:4] == b"dex\n":
                            dex_ver = header[4:7].decode("ascii", errors="ignore")
                            byteorder = "big" if header[40:44] == b"\x12\x34\x56\x78" else "little"
                            methods = int.from_bytes(header[88:92], byteorder)
                            classes = int.from_bytes(header[96:100], byteorder)
                    except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error, EOFError):
                        pass
                    dex_total_methods += methods
                    dex_total_classes += classes
                    dex_entries.append(
                        {
                            "name": name,
                            "version": dex_ver,
                            "sizeBytes": item.file_size,
                            "methods": methods,
                            "classes": classes,
                        }
                    )
                elif name.upper().startswith("META-INF/"):
                    up = name.upper()
                    if (
                        up.endswith((".RSA", ".DSA", ".EC", ".SF"))
                        or up.startswith("META-INF/SIG-")
                        or up == "META-INF/STAMP-CERT-SHA256"
                    ):
                        signature_files.append(name)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, zlib.error, EOFError, struct.error) as exc:
        raise ApkInspectionError("APK arşivi bozuk veya yarım inmiş.", status_code=400) from exc

    if not has_manifest:
        raise ApkInspectionError(
            "Bu dosyanın içinde AndroidManifest.xml bulunamadı. Geçerli bir Android paketi değil.",
            status_code=400,
        )

    dex_entries.sort(key=_dex_sort_key)

    # Stage 2: Merge split ABIs
    split_abis = _extract_split_abis(container_info)
    all_abis = base_abis | split_abis
    abi_list = sorted(all_abis)
    has_native_libs = bool(abi_list)
    has_32 = any(a in ABI_32 for a in abi_list)
    has_64 = any(a in ABI_64 for a in abi_list)
    is_32bit_only = bool(has_32 and not has_64)

    # Stage 3: Single aapt dump badging call (conditional permissions fallback)
    proc = run_cmd(["aapt", "dump", "badging", str(path)], timeout=90)
    if proc.returncode != 0:
        detail = clean_java_output(proc.stderr, proc.stdout)[:500] or "aapt analiz hatası"
        raise ApkInspectionError(f"APK metadata analizi başarısız: {detail}", status_code=400)

    out = (proc.stdout or "").replace("\r\n", "\n")
    package_id, version_code, version_name = _parse_badging_package_meta(out)
    min_m = re.search(r"^sdkVersion:'(\d+)'", out, re.MULTILINE)
    tgt_m = re.search(r"^targetSdkVersion:'(\d+)'", out, re.MULTILINE)

    app_label = _parse_app_label(out, path.stem)
    min_sdk = int(min_m.group(1)) if min_m else 0
    target_sdk = int(tgt_m.group(1)) if tgt_m else 0
    icon_path = _select_icon_path(out, zip_entry_names)

    permissions = sorted(set(PERM_RE.findall(out)))
    if not permissions:
        try:
            perm_proc = run_cmd(["aapt", "dump", "permissions", str(path)], timeout=90)
            if perm_proc.returncode == 0 and perm_proc.stdout:
                permissions = sorted(
                    set(PERM_RE.findall(perm_proc.stdout.replace("\r\n", "\n")))
                )
        except RetroDroidError:
            pass

    # Stage 4: API 31+ unexported component audit
    missing_exported_count, missing_exported_components, manifest_flags = _inspect_xmltree(path)

    # Stage 5: apksigner verify (or reuse preverified output)
    if preverified_sig_text is not None:
        sig_text = clean_java_output("", preverified_sig_text)
        sig_ok = True
    else:
        try:
            sig_proc = run_cmd(
                ["apksigner", "verify", "--verbose", "--print-certs", str(path)],
                timeout=90,
            )
            sig_text = clean_java_output(sig_proc.stderr, sig_proc.stdout)
            sig_ok = sig_proc.returncode == 0
        except RetroDroidError as exc:
            sig_text = exc.detail
            sig_ok = False

    v1 = bool(re.search(r"Verified using v1 scheme \(JAR signing\):\s*true", sig_text, re.IGNORECASE))
    v2 = bool(
        re.search(
            r"Verified using v2 scheme \(APK Signature Scheme v2\):\s*true",
            sig_text,
            re.IGNORECASE,
        )
    )
    v3 = bool(
        re.search(
            r"Verified using v3 scheme \(APK Signature Scheme v3\):\s*true",
            sig_text,
            re.IGNORECASE,
        )
    )
    v31 = bool(re.search(r"Verified using v3\.1 scheme.*?:\s*true", sig_text, re.IGNORECASE))
    sha_m = re.search(r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", sig_text, re.IGNORECASE)
    cert_sha256 = sha_m.group(1).lower() if sha_m else None

    if sig_ok:
        schemes = [name for name, flag in (("v1", v1), ("v2", v2), ("v3", v3), ("v3.1", v31)) if flag]
        sig_msg = f"İmza doğrulandı ({', '.join(schemes) if schemes else 'geçerli'})."
    else:
        sig_msg = (sig_text[:280] if sig_text else "İmza doğrulanamadı veya eksik.")

    signature_info: dict[str, Any] = {
        "verified": sig_ok,
        "v1": v1,
        "v2": v2,
        "v3": v3,
        "v31": v31,
        "certificateSha256": cert_sha256,
        "message": sig_msg,
        "signatureFiles": sorted(set(signature_files)),
    }

    # Stage 6: 16 KB ELF status, install floor, checklist, score & contextual warnings
    if not has_native_libs:
        page_size_16k_status = "not_applicable_pure_java"
        elf_summary = "Yerel .so kütüphanesi bulunmuyor (Saf Java/DEX)."
    elif is_32bit_only:
        page_size_16k_status = "not_applicable_32bit_only"
        elf_summary = "Yalnızca 32-bit yerel kütüphaneler bulundu; 64-bit 16 KB hizalama uygulanmaz."
    elif elf_unaligned > 0:
        page_size_16k_status = "incompatible"
        elf_summary = (
            f"{elf_unaligned}/{elf_checked} 64-bit ELF .so dosyası 16 KB (0x4000) hizalı değil."
        )
    elif elf_checked > 0 and elf_aligned == elf_checked and elf_invalid == 0:
        page_size_16k_status = "compatible"
        elf_summary = f"İncelenen tüm 64-bit ELF .so dosyaları ({elf_aligned}) 16 KB hizalı."
    else:
        page_size_16k_status = "unknown"
        if elf_checked == 0 and any(a in ABI_64 for a in split_abis):
            elf_summary = "64-bit yerel kütüphaneler ayrı split APK içinde; taban APK'da doğrulanamadı."
        else:
            elf_summary = (
                f"64-bit ELF hizalaması doğrulanamadı (incelenen={elf_checked}, geçersiz={elf_invalid})."
            )

    elf16k_report: dict[str, Any] = {
        "status": page_size_16k_status,
        "checkedCount": elf_checked,
        "alignedCount": elf_aligned,
        "unalignedCount": elf_unaligned,
        "invalidCount": elf_invalid,
        "unalignedFiles": elf_unaligned_files,
        "alignedFiles": elf_aligned_files,
        "invalidFiles": elf_invalid_files,
        "summary": elf_summary,
    }

    install_floor_status = compute_install_floor_status(target_sdk, min_sdk)
    compat_checklist, compat_score = _build_compat_checklist(
        install_floor=install_floor_status,
        has_native_libs=has_native_libs,
        is_32bit_only=is_32bit_only,
        abi_list=abi_list,
        signature_info=signature_info,
        page_size_status=page_size_16k_status,
        resources_arsc_compressed=resources_arsc_compressed,
        missing_exported_count=missing_exported_count,
    )

    split_apks = (container_info or {}).get("splitApks") or []
    obb_files = (container_info or {}).get("obbFiles") or []
    is_container = bool(container_info and container_info.get("isContainer"))

    warnings: list[str] = []
    if is_container:
        ctype = container_info.get("containerType", "CONTAINER") if container_info else "CONTAINER"
        warnings.append(
            f"{ctype} paketi açıldı: {len(split_apks)} split APK, {len(obb_files)} OBB dosyası tespit edildi."
        )
    if is_32bit_only:
        warnings.append(
            f"Sadece 32-bit yerel kütüphaneler tespit edildi ({', '.join(abi_list)}). "
            "64-bit zorunlu modern cihazlarda donanım mimarisi kısıtı oluşabilir."
        )

    eff_sdk = install_floor_status["effectiveTargetSdk"]
    if 0 < eff_sdk < 23:
        warnings.append(
            f"targetSdk ({eff_sdk}) Android 14 (min API 23) ve Android 15-17 (min API 24) "
            "kurulum eşiğinin altında; uyumluluk yaması ile yükseltilmesi önerilir."
        )
    elif eff_sdk == 23:
        warnings.append(
            "targetSdk (23) Android 15/16/17 (min API 24) kurulum eşiğinin altında; "
            "API 24+ değerine yükseltilmesi önerilir."
        )
    elif target_sdk == 0 and min_sdk == 0:
        warnings.append(
            "AndroidManifest.xml içinde targetSdkVersion belirtilmemiş; modern Android sürümlerinde "
            "kurulum reddedilebilir."
        )

    if page_size_16k_status == "incompatible":
        warnings.append(
            f"16 KB bellek sayfası uyarısı: {elf_unaligned} adet 64-bit .so dosyası 4 KB hizalı."
        )
    if resources_arsc_compressed:
        warnings.append(
            "resources.arsc sıkıştırılmış (ZIP_DEFLATED); yeniden paketleme sırasında ZIP_STORED yapılmalıdır."
        )
    if missing_exported_count and missing_exported_count > 0:
        if eff_sdk >= 31:
            warnings.append(
                f"API 31+ uyumluluk hatası: intent-filter içeren {missing_exported_count} bileşende "
                "android:exported özniteliği eksik."
            )
        else:
            warnings.append(
                f"intent-filter içeren {missing_exported_count} bileşende android:exported eksik "
                "(API 31+ hedeflendiğinde eklenmesi gerekir)."
            )

    inspector_block: dict[str, Any] = {
        "permissions": permissions,
        "permissionCount": len(permissions),
        "dex": {
            "files": dex_entries,
            "fileCount": len(dex_entries),
            "totalMethods": dex_total_methods,
            "totalClasses": dex_total_classes,
        },
        "signature": signature_info,
        "installFloorStatus": install_floor_status,
        "pageSize16kStatus": page_size_16k_status,
        "elf16k": elf16k_report,
        "resourcesArscCompressed": resources_arsc_compressed,
        "missingExportedCount": missing_exported_count,
        "missingExportedComponents": missing_exported_components,
        "manifestFlags": manifest_flags,
        "compatChecklist": compat_checklist,
        "compatScore": compat_score,
    }

    return {
        "packageId": package_id,
        "appLabel": app_label,
        "versionName": version_name,
        "versionCode": version_code,
        "minSdk": min_sdk,
        "targetSdk": target_sdk,
        "abis": abi_list if abi_list else ["Saf Java/DEX (Mimari Bağımsız)"],
        "is32BitOnly": is_32bit_only,
        "hasResourcesArsc": has_arsc,
        "isContainer": is_container,
        "splitCount": len(split_apks),
        "obbFiles": obb_files,
        "warnings": warnings,
        "inspector": inspector_block,
        "hasNativeLibs": has_native_libs,
        "iconPath": icon_path,
        "resourcesArscCompressed": resources_arsc_compressed,
        "missingExportedCount": missing_exported_count,
        "installFloorStatus": install_floor_status,
        "pageSize16kStatus": page_size_16k_status,
        "elf16kReport": elf16k_report,
        "compatChecklist": compat_checklist,
        "compatScore": compat_score,
    }
