"""Comprehensive unit and real-toolchain integration tests for RetroDroid Compat v5.4.0 core engines."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import stat
import struct
import subprocess
import sys
import threading
import time
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import retrodroid
from retrodroid.axml import (
    ANDROID_NS_URI,
    ATTR_MIN_SDK,
    ATTR_TARGET_SDK,
    NO_INDEX,
    RES_STRING_POOL_TYPE,
    RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_TYPE,
    TYPE_INT_DEC,
    TYPE_INT_HEX,
    TYPE_REFERENCE,
    TYPE_STRING,
    UTF8_FLAG,
    patch_binary_axml_target_sdk,
)
from retrodroid.config import (
    APP_VERSION,
    ApkInspectionError,
    CmdResult,
    CommandCanceledError,
    CommandTimeoutError,
    InvalidArchiveError,
    PayloadTooLargeError,
    Settings,
    StructuredJsonFormatter,
    ToolNotFoundError,
    clean_java_output,
    copy_stream_limited,
    get_logger,
    get_settings,
    is_valid_job_id,
    log_job_context,
    probe_android_tools,
    reset_settings_cache,
    resolve_keystore_path,
    run_cmd,
    safe_url_download,
    sanitize_filename,
    write_json_atomic,
)
from retrodroid.containers import (
    PNG_MAGIC,
    build_full_xapk,
    extract_apk_icon_png,
    extract_container_obb_atomic,
    normalize_obb_relpath,
    unpack_container_if_needed,
    validate_obb_filename,
)
from retrodroid.inspector import (
    compute_install_floor_status,
    count_missing_exported_components,
    inspect_apk,
    inspect_elf_16k_alignment,
    parse_xmltree_manifest,
)
from retrodroid.keystore import (
    KeystoreError,
    ensure_signing_keystore,
    get_keystore_info,
    reset_keystore_state,
)
from retrodroid.patcher import (
    ManifestPatchOptions,
    SlimApkTooLargeError,
    build_slim_manifest_apk,
    detect_zipalign_16k,
    patch_and_sign_pipeline,
    patch_manifest_xml_apktool,
    read_apktool_yml_sdk_info,
    stream_rewrite_apk,
    update_apktool_yml,
)

FRAMEWORK_RES = Path("/usr/share/android-framework-res/framework-res.apk")


# ---------------------------------------------------------------------------
# Deterministic Synthetic Android Artifact Builders (On-The-Fly in tmp_path)
# ---------------------------------------------------------------------------


def make_minimal_png() -> bytes:
    """Create a valid 1x1 RGBA PNG image with proper chunk CRCs."""

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\x10\xb9\x81\xff")
    return PNG_MAGIC + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def make_minimal_dex(version: str = "035", method_count: int = 42, class_count: int = 7) -> bytes:
    """Create a valid 112-byte DEX header with accurate SHA-1 and Adler-32 checksums."""
    buf = bytearray(112)
    buf[0:8] = f"dex\n{version}\x00".encode("ascii")
    struct.pack_into("<I", buf, 32, 112)  # file_size
    struct.pack_into("<I", buf, 36, 112)  # header_size
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", buf, 88, method_count)  # method_ids_size
    struct.pack_into("<I", buf, 96, class_count)  # class_defs_size
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def make_minimal_elf64(
    p_align: int | list[int] = 0x4000,
    num_loads: int = 2,
    endian: str = "<",
) -> bytes:
    """Create a minimal valid ELF64 binary with PT_LOAD program headers."""
    aligns = p_align if isinstance(p_align, list) else [p_align] * num_loads
    ei_data = 1 if endian == "<" else 2
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # ELFCLASS64
    ehdr[5] = ei_data
    ehdr[6] = 1  # EV_CURRENT
    struct.pack_into(f"{endian}HHI", ehdr, 16, 3, 183, 1)  # ET_DYN, EM_AARCH64, EV_CURRENT
    struct.pack_into(f"{endian}Q", ehdr, 32, 64)  # e_phoff
    struct.pack_into(f"{endian}HHH", ehdr, 52, 64, 56, len(aligns))  # ehsize, phentsize, phnum

    phdrs = bytearray()
    for align in aligns:
        ph = bytearray(56)
        struct.pack_into(f"{endian}II", ph, 0, 1, 5)  # PT_LOAD, PF_R|PF_X
        struct.pack_into(f"{endian}Q", ph, 48, align)  # p_align
        phdrs.extend(ph)

    return bytes(ehdr + phdrs)


def make_minimal_elf32(endian: str = "<") -> bytes:
    """Create a minimal valid 52-byte ELF32 header."""
    ehdr = bytearray(52)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 1  # ELFCLASS32
    ehdr[5] = 1 if endian == "<" else 2
    ehdr[6] = 1
    struct.pack_into(f"{endian}HH", ehdr, 16, 3, 40)  # ET_DYN, EM_ARM
    return bytes(ehdr)


def _encode_axml_string_pool(strings: list[str], *, utf8: bool = True) -> bytes:
    offsets: list[int] = []
    blob = bytearray()
    for s in strings:
        offsets.append(len(blob))
        if utf8:
            utf16_len = len(s.encode("utf-16le")) // 2
            raw = s.encode("utf-8")
            if utf16_len >= 0x80:
                blob.extend(bytes([0x80 | (utf16_len >> 8), utf16_len & 0xFF]))
            else:
                blob.append(utf16_len)
            if len(raw) >= 0x80:
                blob.extend(bytes([0x80 | (len(raw) >> 8), len(raw) & 0xFF]))
            else:
                blob.append(len(raw))
            blob.extend(raw)
            blob.append(0)
        else:
            u16 = s.encode("utf-16le")
            char_len = len(u16) // 2
            if char_len >= 0x8000:
                blob.extend(struct.pack("<HH", 0x8000 | (char_len >> 16), char_len & 0xFFFF))
            else:
                blob.extend(struct.pack("<H", char_len))
            blob.extend(u16)
            blob.extend(b"\x00\x00")
    while len(blob) % 4 != 0:
        blob.append(0)

    hdr_size = 28
    strings_start = hdr_size + len(strings) * 4
    csize = strings_start + len(blob)
    flags = UTF8_FLAG if utf8 else 0
    header = struct.pack(
        "<HHIIIIII",
        RES_STRING_POOL_TYPE,
        hdr_size,
        csize,
        len(strings),
        0,
        flags,
        strings_start,
        0,
    )
    offset_bytes = struct.pack(f"<{len(offsets)}I", *offsets) if offsets else b""
    return header + offset_bytes + bytes(blob)


def make_synthetic_axml(
    *,
    tag_name: str = "uses-sdk",
    attrs: list[tuple[int, int, int, int]] | None = None,
    extra_strings: list[str] | None = None,
    utf8: bool = True,
    use_android_ns: bool = True,
    elem_ns_idx: int = NO_INDEX,
    attr_ns_override: int | None = None,
) -> bytes:
    """Build a valid synthetic AXML document for testing StringPool, tags, types, and order."""
    # String table:
    # 0 -> minSdkVersion (resId ATTR_MIN_SDK)
    # 1 -> targetSdkVersion (resId ATTR_TARGET_SDK)
    # 2 -> tag_name
    # 3 -> ANDROID_NS_URI
    # 4+ -> extra_strings
    strings = ["minSdkVersion", "targetSdkVersion", tag_name, ANDROID_NS_URI]
    if extra_strings:
        strings.extend(extra_strings)
    res_map = [ATTR_MIN_SDK, ATTR_TARGET_SDK]

    sp_chunk = _encode_axml_string_pool(strings, utf8=utf8)
    rm_chunk = struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + len(res_map) * 4) + struct.pack(
        f"<{len(res_map)}I", *res_map
    )

    attr_list = attrs or []
    attr_bytes = bytearray()
    ns_idx = attr_ns_override if attr_ns_override is not None else (3 if use_android_ns else NO_INDEX)
    for name_idx, raw_val, val_type, val_data in attr_list:
        attr_bytes.extend(
            struct.pack("<IIIHBBI", ns_idx, name_idx, raw_val, 8, 0, val_type, val_data)
        )

    elem_hdr = struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, 16, 16 + 20 + len(attr_bytes), 1, NO_INDEX)
    elem_ext = struct.pack("<IIHHHHHH", elem_ns_idx, 2, 20, 20, len(attr_list), 0, 0, 0)
    elem_chunk = elem_hdr + elem_ext + bytes(attr_bytes)

    body = sp_chunk + rm_chunk + elem_chunk
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body)) + body


def build_synthetic_apk(
    out_path: Path,
    *,
    package: str = "com.retro.legacy",
    label: str = "Retro's Legacy",
    version_code: int = 10,
    version_name: str = "1.2.3",
    min_sdk: int | str | None = 14,
    target_sdk: int | str | None = 19,
    permissions: list[str] | None = None,
    include_unexported_components: bool = True,
    split_name: str | None = None,
    add_root_dex: bool = True,
    add_second_dex: bool = False,
    add_assets_dex: bool = False,
    native_libs: dict[str, bytes] | None = None,
    compress_arsc: bool = False,
    compress_so: bool = False,
    extra_entries: list[tuple[str, bytes, int, tuple[int, int, int, int, int, int] | None]] | None = None,
    duplicate_entry: tuple[str, bytes] | None = None,
) -> Path:
    """Compile a genuine Android APK via real `aapt package` and enrich ZIP entries."""
    build_dir = out_path.parent / f"_synth_{out_path.stem}_{os.getpid()}_{time.time_ns()}"
    res_dir = build_dir / "res" / "drawable"
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / "icon.png").write_bytes(make_minimal_png())

    perm_list = (
        ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE"]
        if permissions is None
        else permissions
    )
    perm_xml = "\n".join(
        f'    <uses-permission android:name="{p}" />' for p in perm_list
    )

    sdk_attrs: list[str] = []
    if min_sdk is not None:
        sdk_attrs.append(f'android:minSdkVersion="{min_sdk}"')
    if target_sdk is not None:
        sdk_attrs.append(f'android:targetSdkVersion="{target_sdk}"')
    uses_sdk_xml = f"    <uses-sdk {' '.join(sdk_attrs)} />" if sdk_attrs else ""

    split_attr = f' split="{split_name}"' if split_name else ""
    safe_label = (
        label.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

    comp_xml = ""
    if include_unexported_components:
        comp_xml = """
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        """
    else:
        comp_xml = """
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        """

    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}"{split_attr}>
{uses_sdk_xml}
{perm_xml}
    <application android:label="{safe_label}" android:icon="@drawable/icon">
{comp_xml}
    </application>
</manifest>
"""
    manifest_file = build_dir / "AndroidManifest.xml"
    manifest_file.write_text(manifest_xml, encoding="utf-8")

    raw_apk = build_dir / "raw.apk"
    res = subprocess.run(
        [
            "aapt",
            "package",
            "-f",
            "-M",
            str(manifest_file),
            "-S",
            str(build_dir / "res"),
            "-I",
            str(FRAMEWORK_RES),
            "-F",
            str(raw_apk),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"aapt package failed: {res.stderr}\n{res.stdout}"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(raw_apk, "r") as zin, zipfile.ZipFile(out_path, "w", allowZip64=True) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            zinfo = zipfile.ZipInfo(item.filename)
            zinfo.date_time = item.date_time
            if item.filename == "resources.arsc":
                zinfo.compress_type = zipfile.ZIP_DEFLATED if compress_arsc else zipfile.ZIP_STORED
            else:
                zinfo.compress_type = item.compress_type
            zout.writestr(zinfo, data)

        if add_root_dex:
            zout.writestr("classes.dex", make_minimal_dex("035", 42, 7))
        if add_second_dex:
            zout.writestr("classes2.dex", make_minimal_dex("037", 15, 3))
        if add_assets_dex:
            zout.writestr("assets/classes.dex", make_minimal_dex("035", 999, 99))

        for lib_path, lib_bytes in (native_libs or {}).items():
            linfo = zipfile.ZipInfo(lib_path)
            linfo.date_time = (2024, 1, 1, 0, 0, 0)
            linfo.compress_type = zipfile.ZIP_DEFLATED if compress_so else zipfile.ZIP_STORED
            zout.writestr(linfo, lib_bytes)

        for entry_name, payload, ctype, dt in extra_entries or []:
            einfo = zipfile.ZipInfo(entry_name)
            einfo.date_time = dt if dt is not None else (2024, 1, 1, 0, 0, 0)
            einfo.compress_type = ctype
            zout.writestr(einfo, payload)

        if duplicate_entry is not None:
            dname, dbytes = duplicate_entry
            zout.writestr(dname, dbytes)
            zout.writestr(dname, dbytes)

    return out_path


def _inject_zero_dos_timestamp_zip(src_zip: Path, dst_zip: Path, target_entry: str) -> None:
    """Zero out DOS date/time fields in local+central ZIP headers for testing timestamp clamping."""
    raw = bytearray(src_zip.read_bytes())
    name_bytes = target_entry.encode("utf-8")
    # Local file header signature PK\x03\x04 -> mod time/date at +10..+14
    idx = 0
    while True:
        pos = raw.find(b"PK\x03\x04", idx)
        if pos < 0:
            break
        nlen = struct.unpack_from("<H", raw, pos + 26)[0]
        if raw[pos + 30 : pos + 30 + nlen] == name_bytes:
            raw[pos + 10 : pos + 14] = b"\x00\x00\x00\x00"
        idx = pos + 4
    # Central directory header PK\x01\x02 -> mod time/date at +12..+16
    idx = 0
    while True:
        pos = raw.find(b"PK\x01\x02", idx)
        if pos < 0:
            break
        nlen = struct.unpack_from("<H", raw, pos + 28)[0]
        if raw[pos + 46 : pos + 46 + nlen] == name_bytes:
            raw[pos + 12 : pos + 16] = b"\x00\x00\x00\x00"
        idx = pos + 4
    dst_zip.write_bytes(bytes(raw))


@pytest.fixture
def isolated_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Create a real verified keystore inside tmp_path for integration tests."""
    reset_settings_cache()
    reset_keystore_state()
    work_dir = tmp_path / "work"
    ks_path = tmp_path / "ks_dir" / "retrodroid.jks"
    monkeypatch.setenv("WORK_DIR", str(work_dir))
    monkeypatch.setenv("KEYSTORE_PATH", str(ks_path))
    monkeypatch.delenv("KEYSTORE_PASS", raising=False)
    monkeypatch.delenv("KEYSTORE_AUTO_REGEN", raising=False)
    state = ensure_signing_keystore(get_settings(reload=True))
    yield state
    reset_keystore_state()
    reset_settings_cache()


# ===========================================================================
# 1. Bootstrap & Toolchain Tests
# ===========================================================================


def test_version_and_android_toolchain_probe() -> None:
    assert APP_VERSION == "5.4.0"
    assert retrodroid.__version__ == "5.4.0"
    assert FRAMEWORK_RES.is_file()

    probe = probe_android_tools(force=True)
    for tool in ("aapt", "apktool", "zipalign", "apksigner", "java", "keytool"):
        assert probe["tools"][tool] is True, f"Tool missing: {tool}"
        assert probe["toolVersions"][tool], f"Missing version for {tool}"
    assert probe["zipalign16kSupported"] is False
    detect_zipalign_16k.cache_clear()
    assert detect_zipalign_16k() is False


# ===========================================================================
# 2. config.py Tests
# ===========================================================================


def test_settings_env_parsing_masking_and_readonly_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_settings_cache()
    ro_dir = tmp_path / "readonly_ks"
    ro_dir.mkdir(mode=0o755)
    os.chmod(ro_dir, 0o555)
    work_dir = tmp_path / "work"

    try:
        monkeypatch.setenv("WORK_DIR", str(work_dir))
        monkeypatch.setenv("KEYSTORE_PATH", str(ro_dir / "retrodroid.jks"))
        monkeypatch.setenv("KEYSTORE_PASS", "super-secret-pass")
        monkeypatch.setenv("API_ACCESS_TOKEN", "legacy-token")
        monkeypatch.setenv("API_TOKEN", "primary-token")
        monkeypatch.setenv("MAX_UPLOAD_MB", "not_a_number")
        monkeypatch.setenv("KEYSTORE_AUTO_REGEN", "maybe")
        monkeypatch.setenv("ALLOWED_ORIGINS", " https://a.example.com/ , http://localhost:3000/ , https://a.example.com ")
        monkeypatch.setenv("JAVA_HEAP_MB", "512")

        cfg = get_settings()
        assert cfg.WORK_DIR == work_dir
        assert cfg.KEYSTORE_PATH == work_dir / "_keystore" / "retrodroid.jks"
        assert cfg.KEYSTORE_PERSISTENT is False
        assert cfg.MAX_UPLOAD_MB == 5120
        assert cfg.KEYSTORE_AUTO_REGEN is False
        assert cfg.API_TOKEN == "primary-token"
        assert cfg.auth_required is True
        assert cfg.ALLOWED_ORIGINS == ["https://a.example.com", "http://localhost:3000"]
        assert cfg.JAVA_HEAP_MB == 512

        # Secrets must never appear in repr(cfg)
        cfg_repr = repr(cfg)
        assert "super-secret-pass" not in cfg_repr
        assert "primary-token" not in cfg_repr

        # Dynamic reload on env change (API_TOKEN cleared -> falls back to API_ACCESS_TOKEN)
        monkeypatch.delenv("API_TOKEN")
        cfg2 = get_settings()
        assert cfg2.API_TOKEN == "legacy-token"
    finally:
        os.chmod(ro_dir, 0o755)
        reset_settings_cache()


def test_is_valid_job_id() -> None:
    assert is_valid_job_id("0123456789ab") is True
    assert is_valid_job_id("0123456789AB") is False
    assert is_valid_job_id("0123456789ab\n") is False
    assert is_valid_job_id("../123456789") is False
    assert is_valid_job_id("short") is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (r"C:\Users\a\b\game.apk", "game.apk"),
        ("../../etc/passwd", "passwd"),
        ('a" onmouseover="alert(1).apk', "a__onmouseover__alert_1_.apk"),
        ("game.apk...", "game.apk"),
        (".apk", "file.apk"),
        ("___.apk", "file.apk"),
        ("🎮.xapk", "file.xapk"),
        ("...", "file.apk"),
        ("", "file.apk"),
        ("   ", "file.apk"),
        ("CON.apk", "file_CON.apk"),
        ("nul", "file_nul"),
        ("lpt1.xapk", "file_lpt1.xapk"),
        ("com.rockstar.gtavc.v1.2.apk", "com.rockstar.gtavc.v1.2.apk"),
        ("main.100.com.game.obb", "main.100.com.game.obb"),
    ],
)
def test_sanitize_filename_edge_cases(raw: str, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def test_sanitize_filename_length_cap_and_safe_url_download() -> None:
    long_name = ("a" * 200) + ".xapk"
    sanitized = sanitize_filename(long_name, max_len=120)
    assert len(sanitized) <= 120
    assert sanitized.endswith(".xapk")

    url = safe_url_download("abcdef012345", 'game #1?a=b%20"x".apk')
    assert url.startswith("/api/download/abcdef012345/")
    assert "#" not in url and "?" not in url and '"' not in url and " " not in url
    assert "%23" in url and "%3F" in url and "%25" in url


def test_write_json_atomic_and_failure_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    write_json_atomic(target, {"ok": True, "count": 3})
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True, "count": 3}
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert list(tmp_path.glob("*.tmp")) == []

    # Serialization error must not leave orphan .tmp files
    with pytest.raises(TypeError):
        write_json_atomic(tmp_path / "bad.json", {"bad": object()})
    assert list(tmp_path.glob("*.tmp")) == []


def test_clean_java_output_and_copy_stream_limited() -> None:
    cleaned = clean_java_output(
        "Picked up JAVA_TOOL_OPTIONS: -Xmx256m\nPicked up _JAVA_OPTIONS: -Xms64m\n",
        "keytool error: Keystore was tampered with",
    )
    assert "JAVA_TOOL_OPTIONS" not in cleaned
    assert "_JAVA_OPTIONS" not in cleaned
    assert "Keystore was tampered with" in cleaned

    # Exact boundary succeeds
    dst_ok = io.BytesIO()
    written = copy_stream_limited(io.BytesIO(b"A" * 1024), dst_ok, 1024, "Test")
    assert written == 1024
    assert dst_ok.getvalue() == b"A" * 1024

    # Boundary + 1 fails BEFORE writing exceeding chunk
    dst_fail = io.BytesIO()
    with pytest.raises(PayloadTooLargeError) as exc_info:
        copy_stream_limited(io.BytesIO(b"B" * 8192), dst_fail, 4096, "Test", chunk_size=4096)
    assert exc_info.value.status_code == 413
    assert len(dst_fail.getvalue()) <= 4096


def test_run_cmd_large_output_cancel_timeout_missing_and_secret_isolation() -> None:
    # >256 KB simultaneous stdout + stderr without pipe deadlock
    res = run_cmd(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('O'*300000); sys.stderr.write('E'*300000)",
        ],
        timeout=15,
    )
    assert res.returncode == 0
    assert len(res.stdout) == 300000
    assert len(res.stderr) == 300000

    # Cancel event terminates subprocess cleanly
    cancel_ev = threading.Event()
    timer = threading.Timer(0.25, cancel_ev.set)
    timer.start()
    try:
        with pytest.raises(CommandCanceledError) as cancel_exc:
            run_cmd(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=10,
                cancel_event=cancel_ev,
                env={"RD_KS_PASS": "TOP_SECRET_12345"},
            )
        assert "TOP_SECRET_12345" not in str(cancel_exc.value)
    finally:
        timer.cancel()

    # Timeout raises CommandTimeoutError without leaking secret env
    with pytest.raises(CommandTimeoutError) as to_exc:
        run_cmd(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=1,
            env={"RD_KS_PASS": "TOP_SECRET_99999"},
        )
    assert to_exc.value.status_code == 504
    assert "TOP_SECRET_99999" not in str(to_exc.value)

    # Missing binary raises ToolNotFoundError
    with pytest.raises(ToolNotFoundError) as nf_exc:
        run_cmd(["definitely_nonexistent_tool_xyz_123"])
    assert nf_exc.value.tool_name == "definitely_nonexistent_tool_xyz_123"


def test_structured_json_logging_job_id_and_secret_redaction() -> None:
    formatter = StructuredJsonFormatter()
    logger = logging.getLogger("retrodroid.test_fmt")
    with log_job_context("abcdef012345"):
        rec = logger.makeRecord(
            logger.name,
            logging.INFO,
            __file__,
            1,
            "patch finished",
            (),
            None,
            extra={"password": "leak", "api_token": "tok", "stage": "sign"},
        )
        parsed = json.loads(formatter.format(rec))
    assert parsed["jobId"] == "abcdef012345"
    assert parsed["msg"] == "patch finished"
    assert parsed["password"] == "[REDACTED]"
    assert parsed["api_token"] == "[REDACTED]"
    assert parsed["stage"] == "sign"

    adapter = get_logger("retrodroid.test_fmt", job_id="112233445566")
    _, kwargs = adapter.process("hello", {})
    assert kwargs["extra"]["jobId"] == "112233445566"


# ===========================================================================
# 3. keystore.py Tests (Real OpenJDK 17 keytool)
# ===========================================================================


def test_keystore_lifecycle_permissions_secret_isolation_and_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_settings_cache()
    reset_keystore_state()
    work_dir = tmp_path / "work"
    ks_path = tmp_path / "persistent" / "retrodroid.jks"
    pass_path = ks_path.with_suffix(".jks.pass")

    monkeypatch.setenv("WORK_DIR", str(work_dir))
    monkeypatch.setenv("KEYSTORE_PATH", str(ks_path))
    monkeypatch.delenv("KEYSTORE_PASS", raising=False)
    monkeypatch.delenv("KEYSTORE_AUTO_REGEN", raising=False)

    # Spy on subprocess.Popen to prove passwords NEVER appear in argv
    seen_argvs: list[list[str]] = []
    real_popen = subprocess.Popen

    def _spy_popen(cmd, *args, **kwargs):
        seen_argvs.append([str(c) for c in cmd])
        return real_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", _spy_popen)

    try:
        state = ensure_signing_keystore(get_settings(reload=True))
        assert state.ready is True
        assert state.persistent is True
        assert state.alias == "retrodroid"
        assert state.algorithm == "SHA256withRSA"
        assert state.sha256 and len(state.sha256.replace(":", "")) == 64
        assert state.subject and "RetroDroid" in state.subject
        assert state.valid_until

        # Strict 0o600 permissions even under VM umask=0000
        assert stat.S_IMODE(ks_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(pass_path.stat().st_mode) == 0o600

        secret = pass_path.read_text(encoding="utf-8").strip()
        assert len(secret) >= 6
        assert secret not in repr(state)
        pub = get_keystore_info()
        assert pub["ready"] is True
        assert pub["sha256"] == state.sha256
        assert secret not in json.dumps(pub)

        # Verify password NEVER appeared in any keytool argv
        assert seen_argvs, "Expected keytool subprocess invocations"
        for argv in seen_argvs:
            assert all(secret not in token for token in argv), f"Secret leaked in argv: {argv}"

        # Reject KEYSTORE_PASS < 6 chars
        monkeypatch.setenv("KEYSTORE_PASS", "12345")
        with pytest.raises(KeystoreError):
            ensure_signing_keystore(get_settings(reload=True))
        assert get_keystore_info()["ready"] is False

        # Wrong KEYSTORE_PASS with KEYSTORE_AUTO_REGEN=False MUST preserve .jks byte-identical
        orig_bytes = ks_path.read_bytes()
        monkeypatch.setenv("KEYSTORE_PASS", "wrong-password-123")
        monkeypatch.setenv("KEYSTORE_AUTO_REGEN", "false")
        with pytest.raises(KeystoreError):
            ensure_signing_keystore(get_settings(reload=True))
        assert ks_path.read_bytes() == orig_bytes
        assert get_keystore_info()["ready"] is False

        # Missing .pass file with KEYSTORE_AUTO_REGEN=False MUST preserve .jks byte-identical
        monkeypatch.delenv("KEYSTORE_PASS")
        pass_backup = pass_path.read_text(encoding="utf-8")
        pass_path.unlink()
        with pytest.raises(KeystoreError):
            ensure_signing_keystore(get_settings(reload=True))
        assert ks_path.read_bytes() == orig_bytes

        # KEYSTORE_AUTO_REGEN=True backs up existing keystore to .bak.* and regenerates cleanly
        monkeypatch.setenv("KEYSTORE_AUTO_REGEN", "true")
        regen_state = ensure_signing_keystore(get_settings(reload=True))
        assert regen_state.ready is True
        assert regen_state.sha256 != state.sha256
        backups = list(ks_path.parent.glob("retrodroid.jks.bak.*"))
        assert len(backups) == 1
        assert backups[0].read_bytes() == orig_bytes
        assert pass_backup  # silence unused check
    finally:
        reset_keystore_state()
        reset_settings_cache()


def test_keystore_concurrent_startup_flock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reset_settings_cache()
    reset_keystore_state()
    monkeypatch.setenv("WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("KEYSTORE_PATH", str(tmp_path / "ks" / "retrodroid.jks"))
    monkeypatch.delenv("KEYSTORE_PASS", raising=False)
    cfg = get_settings(reload=True)

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            states = list(pool.map(lambda _: ensure_signing_keystore(cfg), range(4)))
        fingerprints = {s.sha256 for s in states}
        assert len(fingerprints) == 1
        assert all(s.ready for s in states)
    finally:
        reset_keystore_state()
        reset_settings_cache()


# ===========================================================================
# 4. axml.py Tests
# ===========================================================================


def test_axml_real_aapt_manifest_upgrade_and_reverify(tmp_path: Path) -> None:
    apk = build_synthetic_apk(tmp_path / "legacy.apk", min_sdk=14, target_sdk=19)
    with zipfile.ZipFile(apk, "r") as z:
        raw_manifest = z.read("AndroidManifest.xml")

    res = patch_binary_axml_target_sdk(raw_manifest, 28)
    assert res["patched"] is True
    assert res["oldMinSdk"] == 14
    assert res["oldTargetSdk"] == 19
    assert res["newTargetSdk"] == 28
    assert res["effectiveTargetSdk"] == 28
    assert res["skippedDowngrade"] is False
    assert res["error"] is None

    # Write patched manifest back into a test APK and confirm via real `aapt dump badging`
    patched_apk = tmp_path / "patched.apk"
    stream_rewrite_apk(apk, patched_apk, manifest_override=res["data"])
    badging = run_cmd(["aapt", "dump", "badging", str(patched_apk)], timeout=30)
    assert badging.returncode == 0
    assert "targetSdkVersion:'28'" in badging.stdout
    assert "sdkVersion:'14'" in badging.stdout


def test_axml_stringpool_utf8_utf16_tag_check_floor_downgrade_and_types() -> None:
    # 1. UTF-16LE StringPool + targetSdk BEFORE minSdk (attribute order independence + minSdk floor)
    axml_u16 = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[
            (1, NO_INDEX, TYPE_INT_DEC, 24),  # targetSdkVersion=24 FIRST
            (0, NO_INDEX, TYPE_INT_DEC, 29),  # minSdkVersion=29 SECOND
        ],
        utf8=False,
    )
    res_floor = patch_binary_axml_target_sdk(axml_u16, 28)
    assert res_floor["patched"] is True
    assert res_floor["oldMinSdk"] == 29
    assert res_floor["oldTargetSdk"] == 24
    assert res_floor["effectiveTargetSdk"] == 29

    # 2. UTF-8 >127-byte 2-byte length string + enclosing tag verification (<other-tag> ignored!)
    axml_other = make_synthetic_axml(
        tag_name="other-tag",
        attrs=[(1, NO_INDEX, TYPE_INT_DEC, 19)],
        extra_strings=["x" * 200],
        utf8=True,
    )
    res_other = patch_binary_axml_target_sdk(axml_other, 28)
    assert res_other["patched"] is False
    assert res_other["data"] == axml_other
    assert res_other["error"] is None

    # 3. allow_downgrade=False skips 33 -> 28; allow_downgrade=True clamps 33 -> minSdk=29
    axml_high = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[
            (0, NO_INDEX, TYPE_INT_DEC, 29),
            (1, NO_INDEX, TYPE_INT_DEC, 33),
        ],
        utf8=True,
    )
    res_skip = patch_binary_axml_target_sdk(axml_high, 28, allow_downgrade=False)
    assert res_skip["patched"] is False
    assert res_skip["skippedDowngrade"] is True
    assert res_skip["effectiveTargetSdk"] == 33
    assert res_skip["data"] == axml_high

    res_allow = patch_binary_axml_target_sdk(axml_high, 28, allow_downgrade=True)
    assert res_allow["patched"] is True
    assert res_allow["skippedDowngrade"] is False
    assert res_allow["effectiveTargetSdk"] == 29

    # 4. Already matching old_target == effective_target returns patched=True
    axml_eq = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[(0, NO_INDEX, TYPE_INT_DEC, 19), (1, NO_INDEX, TYPE_INT_HEX, 28)],
    )
    res_eq = patch_binary_axml_target_sdk(axml_eq, 28)
    assert res_eq["patched"] is True
    assert res_eq["effectiveTargetSdk"] == 28
    assert res_eq["skippedDowngrade"] is False

    # 5. TYPE_STRING ('M') and TYPE_REFERENCE rejected cleanly without misreading index as SDK
    axml_str = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[(0, NO_INDEX, TYPE_STRING, 4), (1, 4, TYPE_STRING, 4)],
        extra_strings=["M"],
    )
    res_str = patch_binary_axml_target_sdk(axml_str, 28)
    assert res_str["patched"] is False
    assert res_str["oldMinSdk"] is None
    assert res_str["oldTargetSdk"] is None
    assert res_str["error"] is None
    assert "'M'" in (res_str["reason"] or "")

    axml_ref = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[(1, NO_INDEX, TYPE_REFERENCE, 0x7F040001)],
    )
    res_ref = patch_binary_axml_target_sdk(axml_ref, 28)
    assert res_ref["patched"] is False
    assert res_ref["error"] is None


@pytest.mark.parametrize(
    "bad_axml",
    [
        b"",
        b"\x03\x00\x08",
        struct.pack("<HHI", 0x9999, 8, 8),  # wrong file type
        struct.pack("<HHI", RES_XML_TYPE, 0, 8),  # fhdr < 8
        struct.pack("<HHI", RES_XML_TYPE, 8, 9999),  # fsize > len
        struct.pack("<HHI", RES_XML_TYPE, 8, 16) + struct.pack("<HHI", 0x0180, 16, 8),  # chdr > csize
        struct.pack("<HHI", RES_XML_TYPE, 8, 16) + struct.pack("<HHI", 0x0180, 8, 0),  # csize == 0
        struct.pack("<HHI", RES_XML_TYPE, 8, 12) + b"\x00\x00\x00\x00",  # trailing < 8B
        struct.pack("<HHI", RES_XML_TYPE, 8, 36)
        + struct.pack("<HHIIIIII", RES_STRING_POOL_TYPE, 28, 28, 0xFFFFFFFF, 0, 0, 28, 0),  # huge string_count
        # START_ELEMENT without StringPool
        struct.pack("<HHI", RES_XML_TYPE, 8, 44)
        + struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, 16, 36, 1, NO_INDEX)
        + struct.pack("<IIHHHHHH", NO_INDEX, 0, 20, 20, 0, 0, 0, 0),
        # attr_size < 20 with attr_count > 0
        struct.pack("<HHI", RES_XML_TYPE, 8, 44)
        + struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, 16, 36, 1, NO_INDEX)
        + struct.pack("<IIHHHHHH", NO_INDEX, 0, 20, 4, 1, 0, 0, 0),
    ],
)
def test_axml_corrupt_inputs_never_crash(bad_axml: bytes) -> None:
    res = patch_binary_axml_target_sdk(bad_axml, 28)
    assert res["patched"] is False
    assert res["error"]
    assert res["data"] == bad_axml


# ===========================================================================
# 5. inspector.py Tests
# ===========================================================================


def test_elf64_16k_alignment_all_cases() -> None:
    # Aligned 16 KB (LE) and 64 KB (BE)
    r_ok = inspect_elf_16k_alignment(make_minimal_elf64(0x4000, 2, "<"))
    assert r_ok["valid"] is True and r_ok["aligned16k"] is True and r_ok["minAlign"] == 16384

    r_be = inspect_elf_16k_alignment(make_minimal_elf64(0x10000, 1, ">"))
    assert r_be["valid"] is True and r_be["aligned16k"] is True and r_be["endian"] == "big"

    # Unaligned 4 KB, mixed 16 KB + 4 KB, non-power-of-two 24576, zero
    assert inspect_elf_16k_alignment(make_minimal_elf64(0x1000))["aligned16k"] is False
    assert inspect_elf_16k_alignment(make_minimal_elf64([0x4000, 0x1000]))["aligned16k"] is False
    assert inspect_elf_16k_alignment(make_minimal_elf64([24576]))["aligned16k"] is False
    assert inspect_elf_16k_alignment(make_minimal_elf64([0]))["aligned16k"] is False

    # 0 PT_LOAD
    r_zero = inspect_elf_16k_alignment(make_minimal_elf64([]))
    assert r_zero["valid"] is True and r_zero["aligned16k"] is False and r_zero["ptLoadCount"] == 0

    # ELF32
    r_32 = inspect_elf_16k_alignment(make_minimal_elf32())
    assert r_32["valid"] is True and r_32["is64Bit"] is False and r_32["aligned16k"] is None

    # Invalid / truncated
    assert inspect_elf_16k_alignment(b"not-an-elf")["valid"] is False
    assert inspect_elf_16k_alignment(make_minimal_elf64(0x4000)[:70])["valid"] is False


def test_parse_xmltree_manifest_edge_cases() -> None:
    xmltree = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=2)
    E: application (line=5)
      A: android:requestLegacyExternalStorage(0x01010603)=(type 0x12)0xffffffff
      A: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0x0
      A: android:extractNativeLibs(0x010104ea)=(type 0x12)0xffffffff
      E: activity (line=10)
        A: android:name(0x01010003)=".UnexportedMain" (Raw: ".UnexportedMain")
        E: meta-data (line=11)
        E: intent-filter (line=12)
      E: activity-alias (line=20)
        A: (0x01010003)=".ObfuscatedExported"
        A: (0x01010010)=(type 0x12)0xffffffff
        E: intent-filter (line=21)
      E: service (line=30)
        A: android:name(0x01010003)=".UnexportedSvc"
        N: extra=http://example.com/ns
        E: intent-filter (line=31)
      E: provider (line=40)
        A: android:name(0x01010003)=".IgnoredProvider"
        E: intent-filter (line=41)
"""
    parsed = parse_xmltree_manifest(xmltree)
    assert parsed["missingExportedCount"] == 2
    names = [c["name"] for c in parsed["missingExportedComponents"]]
    assert names == [".UnexportedMain", ".UnexportedSvc"]
    assert parsed["manifestFlags"]["requestLegacyExternalStorage"] is True
    assert parsed["manifestFlags"]["usesCleartextTraffic"] is False
    assert parsed["manifestFlags"]["extractNativeLibs"] is True


def test_inspector_real_apk_diagnostics_and_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    # 1. Non-APK / missing AndroidManifest.xml MUST fail BEFORE invoking aapt
    def _forbid_aapt(cmd, *args, **kwargs):
        raise AssertionError(f"aapt should not be called before manifest gate: {cmd}")

    not_zip = tmp_path / "bad.apk"
    not_zip.write_bytes(b"NOT_A_ZIP")
    no_manifest = tmp_path / "no_manifest.apk"
    with zipfile.ZipFile(no_manifest, "w") as z:
        z.writestr("classes.dex", make_minimal_dex())

    monkeypatch.setattr("retrodroid.inspector.run_cmd", _forbid_aapt)
    with pytest.raises(ApkInspectionError):
        inspect_apk(not_zip)
    with pytest.raises(ApkInspectionError):
        inspect_apk(no_manifest)
    monkeypatch.undo()

    # 2. Full APK inspection with apostrophe label, root-only DEX, compressed arsc, 4KB ELF64, split ABIs
    apk_4k = build_synthetic_apk(
        tmp_path / "game_4k.apk",
        package="com.test.assassin",
        label="Assassin's Creed: Altair's Chronicles",
        min_sdk=14,
        target_sdk=19,
        add_root_dex=True,
        add_second_dex=True,
        add_assets_dex=True,
        native_libs={
            "lib/arm64-v8a/libgame.so": make_minimal_elf64(0x1000),
            "lib/armeabi-v7a/libgame.so": make_minimal_elf32(),
        },
        compress_arsc=True,
        compress_so=True,
    )

    # Spy on run_cmd to prove `aapt dump permissions` is NOT spawned when badging lists permissions
    cmds_called: list[list[str]] = []
    real_run_cmd = run_cmd

    def _spy_run_cmd(cmd, *args, **kwargs):
        cmds_called.append(list(cmd))
        return real_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr("retrodroid.inspector.run_cmd", _spy_run_cmd)
    container_info = {
        "isContainer": True,
        "containerType": "XAPK",
        "splitApks": [
            {"name": "config.armeabi_v7a.apk"},
            {"name": "config.x86_64.apk"},
            {"name": "config.mips.apk"},
            {"name": "config.mips64.apk"},
        ],
        "obbFiles": [],
    }
    info = inspect_apk(apk_4k, container_info=container_info)
    monkeypatch.undo()

    assert not any(c[:3] == ["aapt", "dump", "permissions"] for c in cmds_called)
    assert info["appLabel"] == "Assassin's Creed: Altair's Chronicles"
    assert info["packageId"] == "com.test.assassin"
    assert info["inspector"]["dex"]["fileCount"] == 2  # assets/classes.dex ignored!
    assert [d["name"] for d in info["inspector"]["dex"]["files"]] == ["classes.dex", "classes2.dex"]
    assert info["inspector"]["dex"]["totalMethods"] == 57
    assert info["resourcesArscCompressed"] is True
    assert info["pageSize16kStatus"] == "incompatible"
    assert info["elf16kReport"]["unalignedCount"] == 1
    assert info["missingExportedCount"] == 2
    assert info["installFloorStatus"]["status"] == "blocked_android14_plus"
    # Verify exact split ABI parsing (no false `armeabi` from `armeabi_v7a` or `x86` from `x86_64`)
    assert set(info["abis"]) == {"arm64-v8a", "armeabi-v7a", "x86_64", "mips", "mips64"}
    assert "armeabi" not in info["abis"]
    assert "x86" not in info["abis"]
    assert all("API 28'e yükseltilecek" not in w for w in info["warnings"])

    # 3. Install floor API 23 vs API 24 verdicts
    assert compute_install_floor_status(23)["status"] == "blocked_android15_plus"
    assert compute_install_floor_status(23)["android14Compatible"] is True
    assert compute_install_floor_status(23)["android15To17Compatible"] is False
    assert compute_install_floor_status(24)["status"] == "ok"

    # 4. 16 KB aligned + patched + signed APK has strictly higher compatScore
    apk_16k = build_synthetic_apk(
        tmp_path / "game_16k.apk",
        min_sdk=19,
        target_sdk=19,
        native_libs={"lib/arm64-v8a/libok.so": make_minimal_elf64(0x4000)},
        compress_arsc=True,
    )
    pre_score = inspect_apk(apk_16k)["compatScore"]
    job_dir = tmp_path / "score_job"
    job_dir.mkdir()
    pipe = patch_and_sign_pipeline(
        "abcdef012345",
        job_dir,
        apk_16k,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert pipe["compatScore"] > pre_score
    assert pipe["pageSize16kStatus"] == "compatible"
    assert pipe["inspector"]["resourcesArscCompressed"] is False


# ===========================================================================
# 6. patcher.py Unit Tests
# ===========================================================================


def test_manifest_options_xml_patcher_and_apktool_yml(tmp_path: Path) -> None:
    assert ManifestPatchOptions(target_sdk=20).clamped_target_sdk() == 24
    assert ManifestPatchOptions(target_sdk=99).clamped_target_sdk() == 36

    # XML without <uses-sdk>, with dist namespace, and unexported component
    xml_path = tmp_path / "AndroidManifest.xml"
    xml_path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:dist="http://schemas.android.com/apk/distribution"
    package="com.test.xml">
    <dist:module dist:instant="false" />
    <application android:label="Test">
        <meta-data android:name="android.max_aspect" android:value="1.86" />
        <activity android:name=".Main">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
        encoding="utf-8",
    )

    opts = ManifestPatchOptions(
        target_sdk=34,
        add_legacy_storage=True,
        enable_cleartext=True,
        add_notch_support=True,
        force_extract_native_libs=True,
    )
    res = patch_manifest_xml_apktool(xml_path, opts, known_min_sdk=21, known_target_sdk=19)
    assert res["changed"] is True
    assert res["newTargetSdk"] == 34
    text = xml_path.read_text(encoding="utf-8")
    assert "xmlns:dist=" in text
    assert 'android:targetSdkVersion="34"' in text
    assert 'android:minSdkVersion="21"' in text
    assert 'android:requestLegacyExternalStorage="true"' in text
    assert 'android:usesCleartextTraffic="true"' in text
    assert 'android:extractNativeLibs="true"' in text
    assert 'android:resizeableActivity="true"' in text
    assert 'android:value="2.4"' in text
    assert 'android:exported="true"' in text

    # Downgrade guard via known_min_sdk / known_target_sdk
    res_dg = patch_manifest_xml_apktool(
        xml_path,
        ManifestPatchOptions(target_sdk=28, allow_downgrade=False),
        known_min_sdk=29,
        known_target_sdk=34,
    )
    assert res_dg["skippedDowngrade"] is True
    assert res_dg["newTargetSdk"] == 34

    # update_apktool_yml across all 7 variants
    yml_variants = [
        ("metainfo", "!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nsdkInfo:\n  minSdkVersion: '19'\n  targetSdkVersion: '19'\n"),
        ("plain", "apkFileName: app.apk\nsdkInfo:\n  minSdkVersion: 19\n  targetSdkVersion: 19\n"),
        ("null_sdk", "!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nsdkInfo: null\n"),
        ("empty_sdk", "!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nsdkInfo: {}\n"),
        ("codename", "!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nsdkInfo:\n  targetSdkVersion: 'M'\n"),
        ("null_target", "!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nsdkInfo:\n  targetSdkVersion: null\n"),
        ("missing_sdk", "apkFileName: app.apk\n"),
    ]
    for name, content in yml_variants:
        yp = tmp_path / f"{name}.yml"
        yp.write_text(content, encoding="utf-8")
        assert update_apktool_yml(yp, 28) is True
        _re_min, re_tgt = read_apktool_yml_sdk_info(yp)
        assert re_tgt == 28, f"Variant {name} failed"
        raw_out = yp.read_text(encoding="utf-8")
        if content.startswith("!!brut.androlib.meta.MetaInfo"):
            assert raw_out.startswith("!!brut.androlib.meta.MetaInfo\n")
        assert "'28'" in raw_out or '"28"' in raw_out

    # Corrupt list YAML returns False safely
    bad_yml = tmp_path / "list.yml"
    bad_yml.write_text("- a\n- b\n", encoding="utf-8")
    assert update_apktool_yml(bad_yml, 28) is False


def test_slim_apk_prewrite_limit_and_stream_rewrite_apk(tmp_path: Path) -> None:
    apk = build_synthetic_apk(
        tmp_path / "src.apk",
        native_libs={"lib/arm64-v8a/liba.so": make_minimal_elf64(0x4000)},
        compress_arsc=True,
        compress_so=True,
        extra_entries=[
            ("meta-inf/cert.sf", b"sig", zipfile.ZIP_DEFLATED, None),
            ("META-INF/CERT.RSA", b"rsa", zipfile.ZIP_DEFLATED, None),
            ("META-INF/MANIFEST.MF", b"mf", zipfile.ZIP_DEFLATED, None),
            ("META-INF/SIG-1", b"sig1", zipfile.ZIP_DEFLATED, None),
            ("META-INF/STAMP-CERT-SHA256", b"stamp", zipfile.ZIP_DEFLATED, None),
            ("META-INF/services/com.example.Svc", b"keep", zipfile.ZIP_DEFLATED, None),
            ("assets/big.bin", b"A" * 50000, zipfile.ZIP_DEFLATED, None),
        ],
        duplicate_entry=("res/raw/dup.txt", b"hello"),
    )

    # Zero DOS timestamp entry to verify clamping
    apk_zero_dt = tmp_path / "src_zero_dt.apk"
    _inject_zero_dos_timestamp_zip(apk, apk_zero_dt, "res/raw/dup.txt")

    # 1. Pre-write slim limit rejection leaves dst_apk ABSENT
    slim_fail = tmp_path / "slim_should_not_exist.apk"
    with pytest.raises(SlimApkTooLargeError):
        build_slim_manifest_apk(apk_zero_dt, slim_fail, max_bytes=10)
    assert not slim_fail.exists()

    # 2. Valid slim APK strips assets/, lib/, META-INF/, classes*.dex
    slim_ok = tmp_path / "slim_ok.apk"
    build_slim_manifest_apk(apk_zero_dt, slim_ok, max_bytes=10 * 1024 * 1024)
    with zipfile.ZipFile(slim_ok, "r") as zs:
        snames = zs.namelist()
        assert "AndroidManifest.xml" in snames
        assert not any(n.upper().startswith(("ASSETS/", "LIB/", "META-INF/")) for n in snames)
        assert "classes.dex" not in snames

    # 3. stream_rewrite_apk: META-INF strip, dedup, ZIP_STORED, timestamp clamp, res_overrides
    rewritten = tmp_path / "rewritten.apk"
    stats = stream_rewrite_apk(
        apk_zero_dt,
        rewritten,
        res_overrides={
            "res/drawable/icon.png": make_minimal_png(),
            "res/raw/added.txt": b"new-resource",
        },
    )
    assert stats["strippedSignatureEntries"] == 5
    assert stats["deduplicatedCount"] == 1
    assert stats["storedForcedCount"] >= 2
    assert stats["timestampsClamped"] >= 1
    assert stats["resOverridesApplied"] == 2

    with zipfile.ZipFile(rewritten, "r") as zr:
        names = zr.namelist()
        assert names.count("res/raw/dup.txt") == 1
        assert "META-INF/services/com.example.Svc" in names
        assert not any(n.upper().endswith((".SF", ".RSA", ".MF")) for n in names)
        assert "META-INF/STAMP-CERT-SHA256" not in names
        assert zr.getinfo("resources.arsc").compress_type == zipfile.ZIP_STORED
        assert zr.getinfo("lib/arm64-v8a/liba.so").compress_type == zipfile.ZIP_STORED
        assert zr.getinfo("res/raw/dup.txt").date_time == (1980, 1, 1, 0, 0, 0)
        assert zr.read("res/raw/added.txt") == b"new-resource"

    # 4. Cumulative decompression cap aborts & removes dst_apk
    bomb_apk = tmp_path / "bomb.apk"
    with zipfile.ZipFile(bomb_apk, "w", compression=zipfile.ZIP_DEFLATED) as zb:
        for i in range(5):
            zb.writestr(f"assets/chunk_{i}.bin", b"\x00" * 100_000)
    bomb_out = tmp_path / "bomb_out.apk"
    with pytest.raises(PayloadTooLargeError):
        stream_rewrite_apk(bomb_apk, bomb_out, max_decompressed_bytes=250_000)
    assert not bomb_out.exists()


def test_detect_zipalign_16k_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    detect_zipalign_16k.cache_clear()
    monkeypatch.setattr(
        "retrodroid.config.run_cmd",
        lambda *a, **k: CmdResult(2, "", "  -P <pagesize_kb> align .so to 16 KiB", "zipalign", 0.01),
    )
    assert detect_zipalign_16k() is True

    detect_zipalign_16k.cache_clear()
    monkeypatch.setattr(
        "retrodroid.config.run_cmd",
        lambda *a, **k: CmdResult(2, "", "  -p  memory page alignment for stored shared object files", "zipalign", 0.01),
    )
    assert detect_zipalign_16k() is False
    detect_zipalign_16k.cache_clear()


# ===========================================================================
# 7. patcher.py Real Toolchain Integration Tests
# ===========================================================================


def test_pipeline_binary_axml_real_toolchain_and_repatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    job_dir = tmp_path / "job_axml"
    job_dir.mkdir()
    # Reserved filename `sanitized.apk` to verify ZERO self-truncation!
    src_apk = build_synthetic_apk(
        job_dir / "sanitized.apk",
        min_sdk=14,
        target_sdk=19,
        native_libs={"lib/arm64-v8a/libcore.so": make_minimal_elf64(0x4000)},
        compress_arsc=True,
        compress_so=True,
    )

    seen_argvs: list[list[str]] = []
    real_popen = subprocess.Popen

    def _spy(cmd, *a, **k):
        seen_argvs.append([str(c) for c in cmd])
        return real_popen(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", _spy)
    secret = isolated_keystore.get_signing_env()["RD_KS_PASS"]

    res = patch_and_sign_pipeline(
        "aa11bb22cc33",
        job_dir,
        src_apk,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    monkeypatch.undo()

    assert res["ok"] is True
    assert res["verified"] is True
    assert res["targetSdk"] == 28
    assert res["patchSummary"]["method"] == "binary_axml"
    assert res["patchSummary"]["manifestPatched"] is True
    assert res["repatchAvailable"] is True
    assert src_apk.is_file()
    assert not (job_dir / "_work").exists()

    signed_path = job_dir / res["fileName"]
    assert signed_path.is_file()

    # Verify via real zipalign -c -p 4 & apksigner verify
    za = run_cmd(["zipalign", "-c", "-p", "4", str(signed_path)], timeout=30)
    assert za.returncode == 0
    vs = run_cmd(["apksigner", "verify", "--verbose", str(signed_path)], timeout=30)
    assert vs.returncode == 0
    assert "Verified using v1 scheme (JAR signing): true" in vs.stdout
    assert "Verified using v2 scheme (APK Signature Scheme v2): true" in vs.stdout
    assert "Verified using v3 scheme (APK Signature Scheme v3): true" in vs.stdout

    # Confirm password NEVER appeared in any subprocess argv
    for argv in seen_argvs:
        assert all(secret not in tok for tok in argv)

    # Second re-patch on same job_dir works because src_apk was retained
    res2 = patch_and_sign_pipeline(
        "aa11bb22cc33",
        job_dir,
        src_apk,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=30),
    )
    assert res2["targetSdk"] == 30
    assert res2["verified"] is True


def test_pipeline_slim_apktool_all_flags_missing_target_codename_and_downgrade(
    tmp_path: Path, isolated_keystore
) -> None:
    # 1. Slim-Apktool API 34 + all 4 structural flags + API 31+ android:exported
    job1 = tmp_path / "job_apktool"
    job1.mkdir()
    src1 = build_synthetic_apk(job1 / "legacy.apk", min_sdk=19, target_sdk=19, include_unexported_components=True)
    res1 = patch_and_sign_pipeline(
        "bb11cc22dd33",
        job1,
        src1,
        isolated_keystore,
        options=ManifestPatchOptions(
            target_sdk=34,
            add_legacy_storage=True,
            enable_cleartext=True,
            add_notch_support=True,
            force_extract_native_libs=True,
        ),
    )
    assert res1["verified"] is True
    assert res1["targetSdk"] == 34
    assert res1["patchSummary"]["method"] == "slim_apktool"
    assert res1["inspector"]["missingExportedCount"] == 0
    flags = res1["inspector"]["manifestFlags"]
    assert flags["requestLegacyExternalStorage"] is True
    assert flags["usesCleartextTraffic"] is True
    assert flags["extractNativeLibs"] is True
    assert flags["resizeableActivity"] is True
    xmltree = run_cmd(
        ["aapt", "dump", "xmltree", str(job1 / res1["fileName"]), "AndroidManifest.xml"],
        timeout=30,
    ).stdout
    assert "android.max_aspect" in xmltree

    # 2. Missing targetSdkVersion APK auto-routes to Slim-Apktool and creates targetSdkVersion
    job2 = tmp_path / "job_notarget"
    job2.mkdir()
    src2 = build_synthetic_apk(job2 / "notarget.apk", min_sdk=14, target_sdk=None)
    res2 = patch_and_sign_pipeline(
        "cc11dd22ee33",
        job2,
        src2,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert res2["verified"] is True
    assert res2["targetSdk"] == 28
    assert res2["patchSummary"]["method"] == "slim_apktool"

    # 3. Codename targetSdk="M" routes to Slim-Apktool and updates apktool.yml cleanly
    job3 = tmp_path / "job_codename"
    job3.mkdir()
    src3 = build_synthetic_apk(job3 / "codename.apk", min_sdk=19, target_sdk="M")
    res3 = patch_and_sign_pipeline(
        "dd11ee22ff33",
        job3,
        src3,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert res3["verified"] is True
    assert res3["targetSdk"] == 28
    assert res3["patchSummary"]["method"] == "slim_apktool"

    # 4. minSdk=29, targetSdk=33 with target_sdk=28, allow_downgrade=False, enable_cleartext=True
    job4 = tmp_path / "job_nodowngrade"
    job4.mkdir()
    src4 = build_synthetic_apk(
        job4 / "modern.apk",
        min_sdk=29,
        target_sdk=33,
        include_unexported_components=False,
    )
    res4 = patch_and_sign_pipeline(
        "ee11ff220011",
        job4,
        src4,
        isolated_keystore,
        options=ManifestPatchOptions(
            target_sdk=28,
            allow_downgrade=False,
            enable_cleartext=True,
        ),
    )
    assert res4["verified"] is True
    assert res4["targetSdk"] == 33
    assert res4["patchSummary"]["skippedDowngrade"] is True
    assert res4["inspector"]["manifestFlags"]["usesCleartextTraffic"] is True


def test_pipeline_apktool_failure_fallbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    real_run_cmd = run_cmd

    def _fail_apktool(cmd, *args, **kwargs):
        if cmd and Path(cmd[0]).name == "apktool":
            return CmdResult(1, "", "Simulated apktool resource table crash", "apktool", 0.01)
        return real_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr("retrodroid.config.run_cmd", _fail_apktool)

    # Case A: target_sdk < 31 with structural flag fails apktool -> falls back to Binary AXML
    job_a = tmp_path / "job_fb_axml"
    job_a.mkdir()
    src_a = build_synthetic_apk(job_a / "a.apk", min_sdk=14, target_sdk=19)
    res_a = patch_and_sign_pipeline(
        "112233445566",
        job_a,
        src_a,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28, enable_cleartext=True),
    )
    assert res_a["verified"] is True
    assert res_a["targetSdk"] == 28
    assert res_a["patchSummary"]["method"] == "fallback_binary_axml"
    assert "Simulated apktool resource table crash" in (res_a["patchSummary"]["fallbackReason"] or "")

    # Case B: target_sdk >= 31 fails apktool -> falls back to safe resign
    job_b = tmp_path / "job_fb_resign"
    job_b.mkdir()
    src_b = build_synthetic_apk(job_b / "b.apk", min_sdk=14, target_sdk=19)
    res_b = patch_and_sign_pipeline(
        "665544332211",
        job_b,
        src_b,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=34),
    )
    assert res_b["verified"] is True
    assert res_b["patchSummary"]["method"] == "fallback_resign"
    assert res_b["patchSummary"]["manifestPatched"] is False
    assert "Simulated apktool resource table crash" in (res_b["patchSummary"]["fallbackReason"] or "")


# ===========================================================================
# 8. containers.py & Split XAPK / APKM / Full XAPK v2 Tests
# ===========================================================================


def test_containers_unpack_manifest_first_security_and_obb_disambiguation(tmp_path: Path) -> None:
    base_apk = build_synthetic_apk(
        tmp_path / "real_base.apk",
        package="com.retro.splitgame",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=True,
    )
    # Feature split LARGER than base.apk (to prove manifest.json beats score_base!)
    feature_apk = build_synthetic_apk(
        tmp_path / "feature_dlc.apk",
        package="com.retro.splitgame",
        split_name="feature_dlc",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=True,
        extra_entries=[("assets/big_dlc.bin", b"Z" * 100_000, zipfile.ZIP_STORED, None)],
    )
    config_arm64 = build_synthetic_apk(
        tmp_path / "config.arm64_v8a.apk",
        package="com.retro.splitgame",
        split_name="config.arm64_v8a",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
        native_libs={"lib/arm64-v8a/libsplit.so": make_minimal_elf64(0x4000)},
    )

    # Build XAPK with Windows backslashes, manifest.json, and duplicate OBB basenames in two subdirs
    xapk_path = tmp_path / "base.apk"  # Same basename as inner base APK -> tests no self-truncation!
    xapk_manifest = {
        "xapk_version": 2,
        "package_name": "com.retro.splitgame",
        "split_apks": [
            {"file": "apks\\base.apk", "id": "base"},
            {"file": "apks\\feature_dlc.apk", "id": "feature_dlc"},
            {"file": "apks\\config.arm64_v8a.apk", "id": "config.arm64_v8a"},
        ],
    }
    with zipfile.ZipFile(xapk_path, "w") as zx:
        zx.writestr("manifest.json", json.dumps(xapk_manifest))
        zx.writestr("apks\\base.apk", base_apk.read_bytes())
        zx.writestr("apks\\feature_dlc.apk", feature_apk.read_bytes())
        zx.writestr("apks\\config.arm64_v8a.apk", config_arm64.read_bytes())
        zx.writestr("Android/obb/com.retro.splitgame/dir1/main.10.com.retro.splitgame.obb", b"OBB_ONE")
        zx.writestr("Android/obb/com.retro.splitgame/dir2/main.10.com.retro.splitgame.obb", b"OBB_TWO")

    job_dir = tmp_path / "job_xapk"
    job_dir.mkdir()
    extracted, meta = unpack_container_if_needed(xapk_path, job_dir)
    assert meta["isContainer"] is True
    assert meta["containerType"] == "XAPK"
    assert meta["manifestSource"] == "xapk_manifest.json"
    assert extracted.parent == job_dir / "_extracted"
    assert extracted.resolve() != xapk_path.resolve()
    assert extracted.read_bytes() == base_apk.read_bytes()
    assert len(meta["splitApks"]) == 2
    assert len(meta["obbFiles"]) == 2
    assert meta["obbFiles"][0]["name"] != meta["obbFiles"][1]["name"]

    # Atomic extraction of both disambiguated OBBs yields distinct payloads
    obb0 = extract_container_obb_atomic(job_dir, meta, 0)
    obb1 = extract_container_obb_atomic(job_dir, meta, 1)
    assert obb0.read_bytes() == b"OBB_ONE"
    assert obb1.read_bytes() == b"OBB_TWO"
    assert list((job_dir / "_extracted_obb").glob("*.tmp")) == []

    # APKM info.json resolution
    apkm_path = tmp_path / "bundle.apkm"
    with zipfile.ZipFile(apkm_path, "w") as zm:
        zm.writestr("info.json", json.dumps({"pname": "com.retro.splitgame", "base_apk": "real_base.apk"}))
        zm.writestr("real_base.apk", base_apk.read_bytes())
        zm.writestr("feature_dlc.apk", feature_apk.read_bytes())
    apkm_job = tmp_path / "job_apkm"
    apkm_job.mkdir()
    ext_apkm, apkm_meta = unpack_container_if_needed(apkm_path, apkm_job)
    assert apkm_meta["containerType"] == "APKM"
    assert apkm_meta["manifestSource"] == "apkm_info.json"
    assert ext_apkm.read_bytes() == base_apk.read_bytes()


def test_containers_adversarial_zip_guardrails(tmp_path: Path) -> None:
    def _write_zip(name: str, entries: list[tuple[str, bytes]]) -> Path:
        p = tmp_path / name
        with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for k, v in entries:
                z.writestr(k, v)
        return p

    # 1. Path traversal (POSIX & Windows backslash & drive letter)
    for idx, evil_name in enumerate(["../evil.apk", "apks\\..\\..\\evil.apk", "C:\\evil.apk", "/abs/evil.apk"]):
        zpath = _write_zip(f"trav_{idx}.xapk", [(evil_name, b"PK\x03\x04")])
        with pytest.raises(InvalidArchiveError):
            unpack_container_if_needed(zpath, tmp_path / f"j_trav_{idx}")

    # 2. Encrypted entry flag
    enc_path = _write_zip("enc.xapk", [("base.apk", b"PK\x03\x04")])
    raw = bytearray(enc_path.read_bytes())
    cd_pos = raw.find(b"PK\x01\x02")
    assert cd_pos >= 0
    raw[cd_pos + 8] |= 0x01
    enc_path.write_bytes(bytes(raw))
    with pytest.raises(InvalidArchiveError):
        unpack_container_if_needed(enc_path, tmp_path / "j_enc")

    # 3. Too many entries
    many_path = _write_zip("many.xapk", [(f"f_{i}.txt", b"x") for i in range(12)])
    with pytest.raises(PayloadTooLargeError):
        unpack_container_if_needed(many_path, tmp_path / "j_many", max_entries=5)

    # 4. High-ratio ZIP bomb exceeding max_bytes
    bomb_path = _write_zip("bomb.xapk", [("base.apk", b"\x00" * (2 * 1024 * 1024))])
    with pytest.raises(PayloadTooLargeError):
        unpack_container_if_needed(bomb_path, tmp_path / "j_bomb", max_bytes=512 * 1024)

    # 5. Duplicate sanitized APK names (`a!1.apk` and `a?1.apk` both sanitize to `a_1.apk`)
    dup_path = _write_zip("dup.xapk", [("a!1.apk", b"1"), ("a?1.apk", b"2")])
    with pytest.raises(InvalidArchiveError):
        unpack_container_if_needed(dup_path, tmp_path / "j_dup")


def test_obb_normalizer_and_validator() -> None:
    pkg = "com.rockstar.gtavc"
    assert normalize_obb_relpath(f"Android/obb/{pkg}/main.10.{pkg}.obb", pkg) == f"main.10.{pkg}.obb"
    assert normalize_obb_relpath(f"sdcard/Android/obb/{pkg}/{pkg}/main.10.{pkg}.obb", pkg) == f"main.10.{pkg}.obb"
    assert normalize_obb_relpath(f"obb\\{pkg}\\patch.10.{pkg}.obb", pkg) == f"patch.10.{pkg}.obb"
    assert normalize_obb_relpath(f"my_dump/{pkg}/main.10.{pkg}.obb", pkg) == f"main.10.{pkg}.obb"

    with pytest.raises(InvalidArchiveError):
        normalize_obb_relpath("../escape.obb", pkg)
    with pytest.raises(InvalidArchiveError):
        normalize_obb_relpath("/etc/passwd", pkg)

    ok = validate_obb_filename(f"main.10.{pkg}.obb", pkg, 10)
    assert ok["valid"] is True and ok["kind"] == "main" and ok["packageMatches"] is True and ok["warning"] is None

    wrong_case = validate_obb_filename("main.10.com.Rockstar.gtavc.obb", pkg, 10)
    assert wrong_case["valid"] is False and wrong_case["packageMatches"] is False and wrong_case["warning"]

    bad_name = validate_obb_filename("data.obb", pkg, 10)
    assert bad_name["valid"] is False and bad_name["suggestedName"] == f"main.10.{pkg}.obb"


def test_split_xapk_pipeline_and_full_xapk_v2_builder(
    tmp_path: Path, isolated_keystore
) -> None:
    base_apk = build_synthetic_apk(
        tmp_path / "s_base.apk",
        package="com.retro.fullxapk",
        label="Retro's Full XAPK",
        version_code=25,
        version_name="2.5",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=True,
    )
    feature_split = build_synthetic_apk(
        tmp_path / "s_feature.apk",
        package="com.retro.fullxapk",
        split_name="feature_maps",
        version_code=25,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=True,
    )
    abi_split = build_synthetic_apk(
        tmp_path / "s_arm64.apk",
        package="com.retro.fullxapk",
        split_name="config.arm64_v8a",
        version_code=25,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
        native_libs={"lib/arm64-v8a/libengine.so": make_minimal_elf64(0x4000)},
    )

    xapk_in = tmp_path / "game_in.xapk"
    with zipfile.ZipFile(xapk_in, "w") as zx:
        zx.writestr(
            "manifest.json",
            json.dumps(
                {
                    "xapk_version": 2,
                    "package_name": "com.retro.fullxapk",
                    "split_apks": [
                        {"file": "base.apk", "id": "base"},
                        {"file": "feature_maps.apk", "id": "feature_maps"},
                        {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"},
                    ],
                }
            ),
        )
        zx.writestr("base.apk", base_apk.read_bytes())
        zx.writestr("feature_maps.apk", feature_split.read_bytes())
        zx.writestr("config.arm64_v8a.apk", abi_split.read_bytes())
        zx.writestr(
            "Android/obb/com.retro.fullxapk/com.retro.fullxapk/main.25.com.retro.fullxapk.obb",
            b"MAIN_OBB_PAYLOAD",
        )

    job_dir = tmp_path / "abcdef123456"
    job_dir.mkdir()
    extracted_base, container_meta = unpack_container_if_needed(xapk_in, job_dir)

    # Patch to API 34 -> preserves split ABIs, patches unexported feature split, builds signed .apks
    patch_res = patch_and_sign_pipeline(
        "abcdef123456",
        job_dir,
        extracted_base,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=34),
    )
    assert patch_res["verified"] is True
    assert patch_res["targetSdk"] == 34
    assert "arm64-v8a" in patch_res["abis"]  # Split ABI preserved post-patch!
    assert patch_res["splitBundle"] is not None
    assert "feature_maps.apk" in patch_res["patchSummary"]["patchedSplits"]

    # Verify base + splits inside .apks share identical signing certificate SHA-256 and 0 missing exported
    bundle_path = job_dir / patch_res["splitBundle"]["fileName"]
    base_cert = patch_res["inspector"]["signature"]["certificateSha256"]
    assert base_cert
    with zipfile.ZipFile(bundle_path, "r") as zb:
        assert set(zb.namelist()) == {"base.apk", "feature_maps.apk", "config.arm64_v8a.apk"}
        for sp_name in ("feature_maps.apk", "config.arm64_v8a.apk"):
            sp_file = tmp_path / f"verify_{sp_name}"
            sp_file.write_bytes(zb.read(sp_name))
            sp_info = inspect_apk(sp_file)
            assert sp_info["inspector"]["signature"]["verified"] is True
            assert sp_info["inspector"]["signature"]["certificateSha256"] == base_cert
            assert count_missing_exported_components(sp_file) == 0

    # Attach extra patch OBB inside job_dir/extra_obb and build Full XAPK v2
    extra_dir = job_dir / "extra_obb"
    extra_dir.mkdir()
    extra_obb = extra_dir / "patch.25.com.retro.fullxapk.obb"
    extra_obb.write_bytes(b"PATCH_OBB_PAYLOAD")

    icon_bytes = extract_apk_icon_png(job_dir / patch_res["fileName"])
    assert icon_bytes is not None and icon_bytes.startswith(PNG_MAGIC)

    full_res = build_full_xapk(
        job_dir,
        patch_res,
        container_meta,
        [{"name": extra_obb.name, "path": str(extra_obb)}],
    )
    assert full_res["ok"] is True
    assert full_res["hasIcon"] is True
    full_path = job_dir / full_res["fileName"]
    assert full_path.is_file()
    assert list(job_dir.glob("*.tmp")) == []

    with zipfile.ZipFile(full_path, "r") as zfull:
        names = set(zfull.namelist())
        assert "manifest.json" in names
        assert "icon.png" in names
        assert zfull.read("icon.png").startswith(PNG_MAGIC)
        assert "base.apk" in names
        assert "feature_maps.apk" in names
        assert "config.arm64_v8a.apk" in names
        assert "RETRODROID-INSTALL.txt" in names
        # Anti-double-nesting verified!
        assert "Android/obb/com.retro.fullxapk/main.25.com.retro.fullxapk.obb" in names
        assert "Android/obb/com.retro.fullxapk/patch.25.com.retro.fullxapk.obb" in names
        assert not any("com.retro.fullxapk/com.retro.fullxapk" in n for n in names)

        m = json.loads(zfull.read("manifest.json").decode("utf-8"))
        assert m["xapk_version"] == 2
        assert m["package_name"] == "com.retro.fullxapk"
        assert m["icon"] == "icon.png"
        assert m["signed_apk_verified"] is True
        assert m["total_size"] > 0
        assert len(m["expansions"]) == 2
        assert len(m["split_apks"]) == 3
        assert "android.permission.INTERNET" in m["permissions"]


# ===========================================================================
# 9. Iteration 2 Remediation Regression & M2 Integration Seam Tests
# ===========================================================================


def _corrupt_zip_entry_payload(src_zip: Path, dst_zip: Path, entry_name: str) -> None:
    """Flip bytes inside a specific ZIP member's payload to trigger bad CRC or zlib.error."""
    raw = bytearray(src_zip.read_bytes())
    target_bytes = entry_name.encode("utf-8")
    pos = 0
    flipped = False
    while True:
        idx = raw.find(b"PK\x03\x04", pos)
        if idx < 0:
            break
        nlen, elen = struct.unpack_from("<HH", raw, idx + 26)
        name_slice = bytes(raw[idx + 30 : idx + 30 + nlen])
        if name_slice == target_bytes:
            data_off = idx + 30 + nlen + elen
            # Corrupt first few bytes of payload (bad deflate header / CRC mismatch)
            for j in range(min(4, len(raw) - data_off)):
                raw[data_off + j] ^= 0xFF
            flipped = True
            break
        pos = idx + 4
    assert flipped, f"Entry {entry_name!r} not found in {src_zip}"
    dst_zip.write_bytes(bytes(raw))


def _set_zip_entry_encrypted_flag(src_zip: Path, dst_zip: Path, entry_name: str) -> None:
    """Set ZIP general-purpose bit 0 (encrypted) on local and central headers for a member."""
    raw = bytearray(src_zip.read_bytes())
    target_bytes = entry_name.encode("utf-8")
    pos = 0
    while True:
        idx = raw.find(b"PK\x03\x04", pos)
        if idx < 0:
            break
        nlen = struct.unpack_from("<H", raw, idx + 26)[0]
        if bytes(raw[idx + 30 : idx + 30 + nlen]) == target_bytes:
            raw[idx + 6] |= 0x01
        pos = idx + 4
    pos = 0
    while True:
        idx = raw.find(b"PK\x01\x02", pos)
        if idx < 0:
            break
        nlen = struct.unpack_from("<H", raw, idx + 28)[0]
        if bytes(raw[idx + 46 : idx + 46 + nlen]) == target_bytes:
            raw[idx + 8] |= 0x01
        pos = idx + 4
    dst_zip.write_bytes(bytes(raw))


def _wait_pid_dead(pid: int, timeout: float = 1.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        # In containers where PID 1 does not immediately reap orphaned children,
        # a terminated process transitions to zombie ('Z') or dead ('X'/'x') state.
        stat_path = Path(f"/proc/{pid}/stat")
        try:
            stat_txt = stat_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return True
        rparen = stat_txt.rfind(")")
        if rparen >= 0:
            after = stat_txt[rparen + 1 :].lstrip()
            if after and after[0] in ("Z", "X", "x"):
                return True
        time.sleep(0.05)
    return False


def test_r1_01_fallback_keystore_persistent_stays_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_settings_cache()
    reset_keystore_state()
    ro_dir = tmp_path / "ro_var_data"
    ro_dir.mkdir(mode=0o755)
    os.chmod(ro_dir, 0o555)
    work_dir = tmp_path / "work"

    try:
        monkeypatch.setenv("WORK_DIR", str(work_dir))
        monkeypatch.setenv("KEYSTORE_PATH", str(ro_dir / "retrodroid.jks"))
        monkeypatch.delenv("KEYSTORE_PASS", raising=False)
        monkeypatch.delenv("KEYSTORE_AUTO_REGEN", raising=False)

        cfg = get_settings(reload=True)
        expected_fallback = work_dir / "_keystore" / "retrodroid.jks"
        assert cfg.KEYSTORE_PATH == expected_fallback
        assert cfg.KEYSTORE_PERSISTENT is False
        assert get_keystore_info()["persistent"] is False

        # Calling resolve_keystore_path a second time on fallback path must remain idempotent
        second_path, second_persistent = resolve_keystore_path(cfg.KEYSTORE_PATH, cfg.WORK_DIR)
        assert second_path == expected_fallback
        assert second_persistent is False

        # ensure_signing_keystore must preserve persistent=False
        state = ensure_signing_keystore(cfg)
        assert state.ready is True
        assert state.path == expected_fallback
        assert state.persistent is False
        assert get_keystore_info()["persistent"] is False

        # Re-invoking ensure_signing_keystore() without explicit settings still yields persistent=False
        state2 = ensure_signing_keystore()
        assert state2.ready is True
        assert state2.persistent is False
        assert get_keystore_info()["persistent"] is False

        # Explicit Settings(KEYSTORE_PERSISTENT=False) on a writable dir must not upgrade to True
        writable_ks = tmp_path / "custom_nonpersist" / "retrodroid.jks"
        custom_cfg = Settings(
            WORK_DIR=work_dir,
            KEYSTORE_PATH=writable_ks,
            KEYSTORE_PERSISTENT=False,
        )
        state3 = ensure_signing_keystore(custom_cfg)
        assert state3.ready is True
        assert state3.path == writable_ks
        assert state3.persistent is False
        assert get_keystore_info()["persistent"] is False
    finally:
        os.chmod(ro_dir, 0o755)
        reset_keystore_state()
        reset_settings_cache()


def test_r1_02_and_c3_corrupt_deflate_streams_and_mips64_elf(tmp_path: Path) -> None:
    # 1. Corrupt deflate streams inside .so and .dex must never leak uncaught zlib.error / EOFError
    base_apk = build_synthetic_apk(
        tmp_path / "clean_deflate.apk",
        native_libs={"lib/arm64-v8a/libbad.so": make_minimal_elf64(0x4000) + b"\x00" * 4096},
        compress_so=True,
        add_root_dex=True,
        add_second_dex=True,
    )
    corrupt_so_apk = tmp_path / "corrupt_so_deflate.apk"
    _corrupt_zip_entry_payload(base_apk, corrupt_so_apk, "lib/arm64-v8a/libbad.so")
    corrupt_both_apk = tmp_path / "corrupt_so_and_dex.apk"
    _corrupt_zip_entry_payload(corrupt_so_apk, corrupt_both_apk, "classes2.dex")

    info = inspect_apk(corrupt_both_apk)
    assert info["elf16kReport"]["checkedCount"] == 1
    assert info["elf16kReport"]["invalidCount"] == 1
    assert "lib/arm64-v8a/libbad.so" in info["elf16kReport"]["invalidFiles"]
    assert info["pageSize16kStatus"] == "unknown"
    assert info["inspector"]["dex"]["fileCount"] == 2

    # 2. C-3 hardening: mips64 in ABI_64 must be audited for 16 KB ELF64 alignment
    mips64_16k = build_synthetic_apk(
        tmp_path / "mips64_16k.apk",
        native_libs={"lib/mips64/libm64.so": make_minimal_elf64(0x4000)},
    )
    m16_info = inspect_apk(mips64_16k)
    assert m16_info["abis"] == ["mips64"]
    assert m16_info["is32BitOnly"] is False
    assert m16_info["elf16kReport"]["checkedCount"] == 1
    assert m16_info["elf16kReport"]["alignedCount"] == 1
    assert m16_info["pageSize16kStatus"] == "compatible"

    mips64_4k = build_synthetic_apk(
        tmp_path / "mips64_4k.apk",
        native_libs={"lib/mips64/libm64_4k.so": make_minimal_elf64(0x1000)},
    )
    m4_info = inspect_apk(mips64_4k)
    assert m4_info["elf16kReport"]["checkedCount"] == 1
    assert m4_info["elf16kReport"]["unalignedCount"] == 1
    assert m4_info["pageSize16kStatus"] == "incompatible"


def test_c1_01_terminate_process_tree_kills_orphan_and_trapped_grandchildren(
    tmp_path: Path,
) -> None:
    # 1. Early-exiting shell with background grandchild on timeout
    pid_file_1 = tmp_path / "gc1.pid"
    t0 = time.monotonic()
    with pytest.raises(CommandTimeoutError):
        run_cmd(["sh", "-c", f"sleep 30 & echo $! > {pid_file_1}"], timeout=0.4)
    elapsed_1 = time.monotonic() - t0
    gc1 = int(pid_file_1.read_text(encoding="utf-8").strip())
    assert _wait_pid_dead(gc1), f"Orphan grandchild {gc1} survived timeout"
    assert elapsed_1 < 2.2

    # 2. Early-exiting shell with background grandchild on cancel_event
    pid_file_2 = tmp_path / "gc2.pid"
    cancel_2 = threading.Event()
    timer_2 = threading.Timer(0.25, cancel_2.set)
    timer_2.start()
    t0 = time.monotonic()
    try:
        with pytest.raises(CommandCanceledError):
            run_cmd(
                ["sh", "-c", f"sleep 30 & echo $! > {pid_file_2}"],
                timeout=10,
                cancel_event=cancel_2,
            )
    finally:
        timer_2.cancel()
    elapsed_2 = time.monotonic() - t0
    gc2 = int(pid_file_2.read_text(encoding="utf-8").strip())
    assert _wait_pid_dead(gc2), f"Orphan grandchild {gc2} survived cancel"
    assert elapsed_2 < 2.0

    # 3. Grandchild ignoring SIGTERM on timeout -> must escalate to SIGKILL on process group
    pid_file_3 = tmp_path / "gc3.pid"
    with pytest.raises(CommandTimeoutError):
        run_cmd(
            ["sh", "-c", f"sh -c 'trap \"\" TERM; exec sleep 30' & echo $! > {pid_file_3}; wait"],
            timeout=0.4,
        )
    gc3 = int(pid_file_3.read_text(encoding="utf-8").strip())
    assert _wait_pid_dead(gc3), f"SIGTERM-trapping grandchild {gc3} survived timeout SIGKILL"

    # 4. Grandchild ignoring SIGTERM on cancel_event -> must escalate to SIGKILL on process group
    pid_file_4 = tmp_path / "gc4.pid"
    cancel_4 = threading.Event()
    timer_4 = threading.Timer(0.25, cancel_4.set)
    timer_4.start()
    try:
        with pytest.raises(CommandCanceledError):
            run_cmd(
                ["sh", "-c", f"sh -c 'trap \"\" TERM; exec sleep 30' & echo $! > {pid_file_4}; wait"],
                timeout=10,
                cancel_event=cancel_4,
            )
    finally:
        timer_4.cancel()
    gc4 = int(pid_file_4.read_text(encoding="utf-8").strip())
    assert _wait_pid_dead(gc4), f"SIGTERM-trapping grandchild {gc4} survived cancel SIGKILL"


def test_c1_02_and_c1_03_axml_oob_namespace_and_unsigned_sdk_bounds() -> None:
    # C1-02 (a): Out-of-bounds non-NO_INDEX element namespace index must NOT match <uses-sdk>
    oob_elem_ns = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[(1, NO_INDEX, TYPE_INT_DEC, 22)],
        elem_ns_idx=9999,
    )
    res_oob_elem = patch_binary_axml_target_sdk(oob_elem_ns, 28)
    assert res_oob_elem["patched"] is False
    assert res_oob_elem["data"] == oob_elem_ns

    # C1-02 (b): Out-of-bounds non-NO_INDEX attribute namespace index must NOT match android:
    oob_attr_ns = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[(1, NO_INDEX, TYPE_INT_DEC, 22)],
        attr_ns_override=9999,
    )
    res_oob_attr = patch_binary_axml_target_sdk(oob_attr_ns, 28)
    assert res_oob_attr["patched"] is False
    assert res_oob_attr["data"] == oob_attr_ns

    # C1-02 (c): Valid empty-string namespace index on <uses-sdk> still patches cleanly
    empty_ns_axml = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[(1, NO_INDEX, TYPE_INT_DEC, 22)],
        extra_strings=[""],
        elem_ns_idx=4,
    )
    res_empty_ns = patch_binary_axml_target_sdk(empty_ns_axml, 28)
    assert res_empty_ns["patched"] is True
    assert res_empty_ns["newTargetSdk"] == 28

    # C1-03 (a): Corrupt unsigned minSdkVersion=0xFFFFFFFF (-1) must NOT clamp targetSdk to 4294967295
    corrupt_min = make_synthetic_axml(
        tag_name="uses-sdk",
        attrs=[
            (0, NO_INDEX, TYPE_INT_DEC, 0xFFFFFFFF),
            (1, NO_INDEX, TYPE_INT_DEC, 22),
        ],
    )
    res_corrupt_min = patch_binary_axml_target_sdk(corrupt_min, 28)
    assert res_corrupt_min["patched"] is True
    assert res_corrupt_min["oldMinSdk"] is None
    assert res_corrupt_min["oldTargetSdk"] == 22
    assert res_corrupt_min["newTargetSdk"] == 28
    assert res_corrupt_min["effectiveTargetSdk"] == 28

    # C1-03 (b): Corrupt unsigned targetSdkVersion=0xFFFFFFFF or 0 must be rejected cleanly
    for bad_target in (0, 0xFFFFFFFF):
        corrupt_tgt = make_synthetic_axml(
            tag_name="uses-sdk",
            attrs=[(1, NO_INDEX, TYPE_INT_DEC, bad_target)],
        )
        res_bad_tgt = patch_binary_axml_target_sdk(corrupt_tgt, 28)
        assert res_bad_tgt["patched"] is False
        assert res_bad_tgt["oldTargetSdk"] is None
        assert res_bad_tgt["data"] == corrupt_tgt


def test_c1_04_and_config_hardening_reserved_truncation_bounds_and_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # C1-04: Post-truncation Windows reserved name bypass blocked at default & small max_len
    r_default = sanitize_filename("CON" + "_" * 113 + "x.apk")
    assert r_default != "CON.apk"
    assert len(r_default) <= 120
    assert r_default.endswith(".apk")
    assert Path(r_default).stem.split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL"}

    r_small = sanitize_filename("CON_xxxxxxxxxxxx.apk", max_len=8)
    assert r_small != "CON.apk"
    assert len(r_small) <= 8
    assert r_small.endswith(".apk")
    assert Path(r_small).stem.split(".")[0].upper() != "CON"

    r_com1 = sanitize_filename("COM1" + "-" * 112 + "z.apk")
    assert r_com1 != "COM1.apk"
    assert Path(r_com1).stem.split(".")[0].upper() != "COM1"

    # C-1: JOB_TTL_SECONDS & MAX_ARCHIVE_ENTRIES lower bound is 1 (defaults remain 3600 / 25000)
    reset_settings_cache()
    try:
        monkeypatch.delenv("JOB_TTL_SECONDS", raising=False)
        monkeypatch.delenv("MAX_ARCHIVE_ENTRIES", raising=False)
        defaults = get_settings(reload=True)
        assert defaults.JOB_TTL_SECONDS == 3600
        assert defaults.MAX_ARCHIVE_ENTRIES == 25000

        monkeypatch.setenv("JOB_TTL_SECONDS", "1")
        monkeypatch.setenv("MAX_ARCHIVE_ENTRIES", "1")
        low_cfg = get_settings(reload=True)
        assert low_cfg.JOB_TTL_SECONDS == 1
        assert low_cfg.MAX_ARCHIVE_ENTRIES == 1
    finally:
        reset_settings_cache()

    # C-2: _redact_value recurses into list/tuple and matches *_pass/storepass/keypass/api_key/authorization
    formatter = StructuredJsonFormatter()
    logger = logging.getLogger("retrodroid.test_redact_deep")
    rec = logger.makeRecord(
        logger.name,
        logging.INFO,
        __file__,
        1,
        "audit event",
        (),
        None,
        extra={
            "nested_list": [
                {"password": "SecretPW1", "ks_pass": "SecretPW2", "db_pass": "SecretPW3"},
                ("safe_item", {"storepass": "SecretPW4", "KeyPass": "SecretPW5"}),
            ],
            "headers": {
                "Authorization": "Bearer SecretTok6",
                "X-API_KEY": "SecretKey7",
                "tests_passed": 51,
            },
        },
    )
    formatted = formatter.format(rec)
    for leaked in (
        "SecretPW1",
        "SecretPW2",
        "SecretPW3",
        "SecretPW4",
        "SecretPW5",
        "SecretTok6",
        "SecretKey7",
    ):
        assert leaked not in formatted
    parsed = json.loads(formatted)
    assert parsed["nested_list"][0]["password"] == "[REDACTED]"
    assert parsed["nested_list"][0]["ks_pass"] == "[REDACTED]"
    assert parsed["nested_list"][0]["db_pass"] == "[REDACTED]"
    assert parsed["nested_list"][1][0] == "safe_item"
    assert parsed["nested_list"][1][1]["storepass"] == "[REDACTED]"
    assert parsed["nested_list"][1][1]["KeyPass"] == "[REDACTED]"
    assert parsed["headers"]["Authorization"] == "[REDACTED]"
    assert parsed["headers"]["X-API_KEY"] == "[REDACTED]"
    assert parsed["headers"]["tests_passed"] == 51


def test_r2_01_and_c2_02_long_120_char_filename_no_overwrite_and_work_dir_cleanup(
    tmp_path: Path, isolated_keystore
) -> None:
    # Case A: 120-char upload filename (`a`*116 + `.apk`) must NOT overwrite src_apk
    job_a = tmp_path / "job_long120"
    job_a.mkdir()
    src_a = build_synthetic_apk(job_a / ("a" * 116 + ".apk"), min_sdk=14, target_sdk=19)
    orig_sha_a = hashlib.sha256(src_a.read_bytes()).hexdigest()

    res_a = patch_and_sign_pipeline(
        "aa00bb11cc22",
        job_a,
        src_a,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    signed_a = job_a / res_a["fileName"]
    assert signed_a.is_file()
    assert signed_a.resolve() != src_a.resolve()
    assert len(res_a["fileName"]) <= 120
    assert res_a["fileName"].endswith("_uyumlu.apk")
    assert hashlib.sha256(src_a.read_bytes()).hexdigest() == orig_sha_a
    assert res_a["verified"] is True
    assert res_a["targetSdk"] == 28
    assert res_a["repatchAvailable"] is True
    # C2-02: empty job_dir/_work parent directory removed cleanly
    assert not (job_a / "_work").exists()

    # Case B: Exact-collision filename (`a`*100 + `_uyumlu.apk`) triggers distinct UUID `_patched.apk`
    job_b = tmp_path / "job_exact_coll"
    job_b.mkdir()
    src_b = build_synthetic_apk(job_b / ("a" * 100 + "_uyumlu.apk"), min_sdk=14, target_sdk=19)
    orig_sha_b = hashlib.sha256(src_b.read_bytes()).hexdigest()

    res_b = patch_and_sign_pipeline(
        "bb00cc11dd22",
        job_b,
        src_b,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    signed_b = job_b / res_b["fileName"]
    assert signed_b.is_file()
    assert signed_b.resolve() != src_b.resolve()
    assert len(res_b["fileName"]) <= 120
    assert res_b["fileName"].endswith("_patched.apk")
    assert hashlib.sha256(src_b.read_bytes()).hexdigest() == orig_sha_b
    assert not (job_b / "_work").exists()

    # Case C: 120-char base APK in a split container preserves `_SplitPaket.apks` suffix
    job_c = tmp_path / "job_long_split"
    job_c.mkdir()
    long_base_name = "b" * 116 + ".apk"
    split_xapk = tmp_path / "long_split_in.xapk"
    split_cfg = build_synthetic_apk(
        tmp_path / "long_split_cfg.apk",
        package="com.retro.legacy",
        split_name="config.arm64_v8a",
        min_sdk=14,
        target_sdk=19,
        include_unexported_components=False,
    )
    with zipfile.ZipFile(split_xapk, "w") as zs:
        zs.writestr(long_base_name, src_a.read_bytes())
        zs.writestr("config.arm64_v8a.apk", split_cfg.read_bytes())
    ext_c, _ = unpack_container_if_needed(split_xapk, job_c)
    res_c = patch_and_sign_pipeline(
        "cc11dd22ee44",
        job_c,
        ext_c,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert res_c["splitBundle"] is not None
    bname = res_c["splitBundle"]["fileName"]
    assert len(bname) <= 120
    assert bname.endswith("_SplitPaket.apks")
    assert not (job_c / "_work").exists()


def test_r2_04_and_c4_noop_target_downgrade_yaml_and_xml_hardening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    # 1. R2-04: Already API 34 + exported=true must NOT emit targetSdkVersion:34->34 or run apktool b
    job_noop = tmp_path / "job_noop34"
    job_noop.mkdir()
    src_34 = build_synthetic_apk(
        job_noop / "already34.apk",
        min_sdk=24,
        target_sdk=34,
        include_unexported_components=False,
    )
    seen_cmds: list[list[str]] = []
    real_run_cmd = run_cmd

    def _spy_cmd(cmd, *args, **kwargs):
        seen_cmds.append(list(cmd))
        return real_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr("retrodroid.config.run_cmd", _spy_cmd)
    res_noop = patch_and_sign_pipeline(
        "cc00dd11ee22",
        job_noop,
        src_34,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=34),
    )
    monkeypatch.undo()

    assert res_noop["verified"] is True
    assert res_noop["targetSdk"] == 34
    assert res_noop["patchSummary"]["manifestPatched"] is False
    assert res_noop["patchSummary"]["appliedChanges"] == []
    assert res_noop["iconPath"] is not None
    assert not any(
        len(c) >= 2 and Path(c[0]).name == "apktool" and c[1] == "b" for c in seen_cmds
    ), f"Unexpected no-op apktool b call: {seen_cmds}"

    # 2. OBS-1: Already targetSdk=28 with enable_cleartext=True must NOT emit targetSdkVersion:28->28
    job_28 = tmp_path / "job_28_clear"
    job_28.mkdir()
    src_28 = build_synthetic_apk(
        job_28 / "already28.apk",
        min_sdk=19,
        target_sdk=28,
        include_unexported_components=False,
    )
    res_28 = patch_and_sign_pipeline(
        "dd00ee11ff22",
        job_28,
        src_28,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28, patch_target_sdk=True, enable_cleartext=True),
    )
    assert res_28["verified"] is True
    assert res_28["targetSdk"] == 28
    assert res_28["patchSummary"]["appliedChanges"] == ["usesCleartextTraffic=true"]

    # 3. R2-04 downgrade alignment with axml.py: old_target == old_min == 29, requested=28
    xml_dg = tmp_path / "dg_align.xml"
    xml_dg.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.dg">
    <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="29" />
    <application android:label="DG" />
</manifest>
""",
        encoding="utf-8",
    )
    res_dg = patch_manifest_xml_apktool(
        xml_dg,
        ManifestPatchOptions(target_sdk=28, allow_downgrade=False),
    )
    assert res_dg["skippedDowngrade"] is True
    assert res_dg["changed"] is False
    assert res_dg["newTargetSdk"] == 29
    assert res_dg["appliedChanges"] == []

    # 4. C-4: Deduplicate & update ALL duplicate android.max_aspect nodes
    xml_dup = tmp_path / "dup_aspect.xml"
    xml_dup.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.aspect">
    <application android:label="Aspect">
        <meta-data android:name="android.max_aspect" android:value="1.86" />
        <meta-data android:name="android.max_aspect" android:value="2.1" />
    </application>
</manifest>
""",
        encoding="utf-8",
    )
    res_asp1 = patch_manifest_xml_apktool(
        xml_dup,
        ManifestPatchOptions(patch_target_sdk=False, add_notch_support=True),
    )
    assert res_asp1["changed"] is True
    updated_xml = xml_dup.read_text(encoding="utf-8")
    assert updated_xml.count("android.max_aspect") == 1
    assert 'android:value="2.4"' in updated_xml
    assert 'android:value="2.1"' not in updated_xml
    res_asp2 = patch_manifest_xml_apktool(
        xml_dup,
        ManifestPatchOptions(patch_target_sdk=False, add_notch_support=True),
    )
    assert res_asp2["changed"] is False

    # 5. C-4: update_apktool_yml empty file, scalar under !!MetaInfo, and leading --- before !!MetaInfo
    empty_yml = tmp_path / "empty.yml"
    empty_yml.write_text("", encoding="utf-8")
    assert update_apktool_yml(empty_yml, 28) is False
    assert empty_yml.read_text(encoding="utf-8") == ""

    scalar_meta_yml = tmp_path / "scalar_meta.yml"
    scalar_meta_yml.write_text("!!brut.androlib.meta.MetaInfo\nhello_scalar\n", encoding="utf-8")
    assert update_apktool_yml(scalar_meta_yml, 28) is False
    assert "hello_scalar" in scalar_meta_yml.read_text(encoding="utf-8")

    doc_start_yml = tmp_path / "doc_start.yml"
    doc_start_yml.write_text(
        "---\n!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nsdkInfo: {}\n",
        encoding="utf-8",
    )
    assert update_apktool_yml(doc_start_yml, 31) is True
    doc_start_out = doc_start_yml.read_text(encoding="utf-8")
    assert doc_start_out.startswith("!!brut.androlib.meta.MetaInfo\n")
    assert read_apktool_yml_sdk_info(doc_start_yml) == (None, 31)

    # 6. C-4: Consecutive slashes in META-INF//CERT.SF stripped while META-INF//services/* kept
    slash_apk = build_synthetic_apk(
        tmp_path / "double_slash_meta.apk",
        extra_entries=[
            ("META-INF//CERT.SF", b"sig", zipfile.ZIP_DEFLATED, None),
            ("META-INF///STAMP-CERT-SHA256", b"stamp", zipfile.ZIP_DEFLATED, None),
            ("META-INF//services/com.example.Keep", b"keep", zipfile.ZIP_DEFLATED, None),
        ],
    )
    slash_out = tmp_path / "double_slash_out.apk"
    slash_stats = stream_rewrite_apk(slash_apk, slash_out)
    assert slash_stats["strippedSignatureEntries"] == 2
    with zipfile.ZipFile(slash_out, "r") as zsl:
        names = set(zsl.namelist())
        assert "META-INF//CERT.SF" not in names
        assert "META-INF///STAMP-CERT-SHA256" not in names
        assert "META-INF//services/com.example.Keep" in names


def test_r2_02_r2_03_c2_03_c2_04_and_c5_containers_and_xapk_fixes(
    tmp_path: Path, isolated_keystore
) -> None:
    # 1. C2-03: normalize_obb_relpath strips repeated Android/obb/ and multi-level wrappers
    pkg = "com.retro.nested"
    assert (
        normalize_obb_relpath(f"Android/obb/Android/obb/{pkg}/main.1.{pkg}.obb", pkg)
        == f"main.1.{pkg}.obb"
    )
    assert (
        normalize_obb_relpath(
            f"Android/obb/{pkg}/Android/obb/{pkg}/main.1.{pkg}.obb", pkg
        )
        == f"main.1.{pkg}.obb"
    )
    assert (
        normalize_obb_relpath(f"Backups/MyGame/{pkg}/main.1.{pkg}.obb", pkg)
        == f"main.1.{pkg}.obb"
    )

    # 2a. C-5: XAPK uploaded as .zip with heuristic base APK + manifest.json (xapk_version/expansions) + `./`
    base_apk = build_synthetic_apk(
        tmp_path / "nested_base.apk",
        package=pkg,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    split_base_case = build_synthetic_apk(
        tmp_path / "nested_split_Base.apk",
        package=pkg,
        split_name="config.armeabi_v7a",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    xapk_heuristic_zip = tmp_path / "heuristic_xapk.zip"
    with zipfile.ZipFile(xapk_heuristic_zip, "w") as zx:
        zx.writestr(
            "manifest.json",
            json.dumps(
                {
                    "xapk_version": 2,
                    "package_name": pkg,
                    "expansions": [
                        {
                            "file": f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb",
                            "install_location": "EXTERNAL_STORAGE",
                            "install_path": f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb",
                        }
                    ],
                }
            ),
        )
        zx.writestr("./custom_game.apk", base_apk.read_bytes())
        zx.writestr(f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb", b"DOUBLE_NESTED_OBB")

    heur_job = tmp_path / "heur_xapk_job"
    heur_job.mkdir()
    _, heur_meta = unpack_container_if_needed(xapk_heuristic_zip, heur_job)
    assert heur_meta["manifestSource"] == "heuristic"
    assert heur_meta["containerType"] == "XAPK"
    assert heur_meta["innerApkName"] == "custom_game.apk"
    assert heur_meta["obbFiles"][0].get("installPath") == f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb"

    # 2b. R2-03 + C-5: XAPK uploaded as .zip with manifest.json selecting `./app.apk` + `apks/./Base.apk` split
    xapk_as_zip = tmp_path / "uploaded_as_zip.zip"
    with zipfile.ZipFile(xapk_as_zip, "w") as zx:
        zx.writestr(
            "manifest.json",
            json.dumps(
                {
                    "xapk_version": 2,
                    "package_name": pkg,
                    "apk": "./app.apk",
                    "expansions": [
                        {
                            "file": f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb",
                            "install_location": "EXTERNAL_STORAGE",
                            "install_path": f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb",
                        }
                    ],
                }
            ),
        )
        # `./` dot segment + `Base.apk` case-variant split (R2-03)
        zx.writestr("./app.apk", base_apk.read_bytes())
        zx.writestr("apks/./Base.apk", split_base_case.read_bytes())
        zx.writestr(f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb", b"DOUBLE_NESTED_OBB")

    job_dir = tmp_path / "ef01ab23cd45"
    job_dir.mkdir()
    extracted, cmeta = unpack_container_if_needed(xapk_as_zip, job_dir)
    assert cmeta["containerType"] == "XAPK"
    assert cmeta["innerApkName"] == "app.apk"
    assert cmeta["obbFiles"][0].get("installPath") == f"Android/obb/Android/obb/{pkg}/main.10.{pkg}.obb"

    # R2-03: patch_and_sign_pipeline disambiguates case-variant `Base.apk` inside .apks
    patch_res = patch_and_sign_pipeline(
        "ef01ab23cd45",
        job_dir,
        extracted,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert patch_res["verified"] is True
    assert patch_res["splitBundle"] is not None
    bundle_path = job_dir / patch_res["splitBundle"]["fileName"]
    with zipfile.ZipFile(bundle_path, "r") as zb:
        bnames = zb.namelist()
        assert len(bnames) == 2
        assert len({n.lower() for n in bnames}) == 2
        assert "base.apk" in bnames
        assert "Base.apk" not in bnames

    # R2-02: Positional progress_cb and cancel_event work per PROJECT.md:202
    progress_events: list[tuple[int, str]] = []
    cancel_ev = threading.Event()
    full_res = build_full_xapk(
        job_dir,
        patch_res,
        cmeta,
        None,
        lambda pct, stage: progress_events.append((pct, stage)),
        cancel_ev,
    )
    assert full_res["ok"] is True
    assert progress_events and progress_events[-1][0] == 100
    assert [p for p, _ in progress_events] == sorted(p for p, _ in progress_events)
    with zipfile.ZipFile(job_dir / full_res["fileName"], "r") as zf:
        znames = set(zf.namelist())
        # C2-03 end-to-end: NO double-nested Android/obb/<pkg>/Android/obb/<pkg>/!
        assert f"Android/obb/{pkg}/main.10.{pkg}.obb" in znames
        assert not any("Android/obb/Android/obb" in n for n in znames)
        assert not any(f"{pkg}/{pkg}" in n for n in znames)

    # R2-03 in containers.py: hand-crafted .apks with Base.apk + Config.apk + config.apk
    hand_bundle = job_dir / patch_res["splitBundle"]["fileName"]
    signed_bytes = (job_dir / patch_res["fileName"]).read_bytes()
    with zipfile.ZipFile(hand_bundle, "w") as zh:
        zh.writestr("base.apk", signed_bytes)
        zh.writestr("Base.apk", signed_bytes)
        zh.writestr("Config.apk", signed_bytes)
        zh.writestr("config.apk", signed_bytes)
    full_res2 = build_full_xapk(job_dir, patch_res, cmeta, None)
    with zipfile.ZipFile(job_dir / full_res2["fileName"], "r") as zf2:
        apk_entries = [n for n in zf2.namelist() if n.endswith(".apk")]
        assert len(apk_entries) == len({n.lower() for n in apk_entries})
        assert "Base.apk" not in apk_entries

    # C-5: Symlink escape guard in extra_dir.rglob("*") raises InvalidArchiveError (400)
    outside_secret = tmp_path / "outside_secret.obb"
    outside_secret.write_bytes(b"SECRET")
    extra_dir = job_dir / "extra_obb"
    extra_dir.mkdir(exist_ok=True)
    escape_link = extra_dir / "escape.obb"
    escape_link.symlink_to(outside_secret)
    with pytest.raises(InvalidArchiveError) as sym_exc:
        build_full_xapk(job_dir, patch_res, None, None)
    assert sym_exc.value.status_code == 400
    escape_link.unlink()

    # C2-04: Corrupt CRC in container base APK & OBB, and encrypted/corrupt APK in rewrite/slim
    crc_container = tmp_path / "crc_container.xapk"
    with zipfile.ZipFile(crc_container, "w", compression=zipfile.ZIP_STORED) as zc:
        zc.writestr("base.apk", base_apk.read_bytes())
        zc.writestr(f"Android/obb/{pkg}/main.10.{pkg}.obb", b"OBB_STORED_PAYLOAD_DATA")

    crc_bad_base = tmp_path / "crc_bad_base.xapk"
    _corrupt_zip_entry_payload(crc_container, crc_bad_base, "base.apk")
    bad_base_job = tmp_path / "j_bad_base"
    bad_base_job.mkdir()
    with pytest.raises(InvalidArchiveError) as e_base:
        unpack_container_if_needed(crc_bad_base, bad_base_job)
    assert e_base.value.status_code == 400
    assert list((bad_base_job / "_extracted").glob("*.tmp")) == []

    crc_bad_obb = tmp_path / "crc_bad_obb.xapk"
    _corrupt_zip_entry_payload(crc_container, crc_bad_obb, f"Android/obb/{pkg}/main.10.{pkg}.obb")
    bad_obb_job = tmp_path / "j_bad_obb"
    bad_obb_job.mkdir()
    _, bad_obb_meta = unpack_container_if_needed(crc_bad_obb, bad_obb_job)
    with pytest.raises(InvalidArchiveError) as e_obb:
        extract_container_obb_atomic(bad_obb_job, bad_obb_meta, 0)
    assert e_obb.value.status_code == 400
    assert list((bad_obb_job / "_extracted_obb").glob("*.tmp")) == []

    # C2-04 in build_full_xapk: corrupt CRC container OBB raises InvalidArchiveError (400), no .tmp
    with pytest.raises(InvalidArchiveError) as e_xapk_obb:
        build_full_xapk(job_dir, patch_res, bad_obb_meta, None)
    assert e_xapk_obb.value.status_code == 400
    assert list(job_dir.glob("*.tmp")) == []

    # Encrypted APK entry raises InvalidArchiveError (400) in stream_rewrite_apk & build_slim_manifest_apk
    enc_apk = tmp_path / "encrypted_entry.apk"
    _set_zip_entry_encrypted_flag(base_apk, enc_apk, "AndroidManifest.xml")
    enc_out = tmp_path / "enc_out.apk"
    with pytest.raises(InvalidArchiveError) as e_rw:
        stream_rewrite_apk(enc_apk, enc_out)
    assert e_rw.value.status_code == 400
    assert not enc_out.exists()

    slim_enc_out = tmp_path / "slim_enc_out.apk"
    with pytest.raises(InvalidArchiveError) as e_slim:
        build_slim_manifest_apk(enc_apk, slim_enc_out)
    assert e_slim.value.status_code == 400
    assert not slim_enc_out.exists()


def test_m2_pipeline_seams_callbacks_modes_low_disk_missing_uses_sdk_and_single_xapk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    # 1. Pipeline M2 hooks: append_log, progress_cb, on_proc, and missing <uses-sdk> completely
    job_hooks = tmp_path / "001122334455"
    job_hooks.mkdir()
    no_sdk_apk = build_synthetic_apk(
        job_hooks / "no_uses_sdk.apk",
        package="com.retro.nousessdk",
        min_sdk=None,
        target_sdk=None,
        include_unexported_components=False,
    )
    hook_logs: list[str] = []
    hook_progress: list[tuple[int, str]] = []
    hook_procs: list[int] = []
    res_hooks = patch_and_sign_pipeline(
        "001122334455",
        job_hooks,
        no_sdk_apk,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
        append_log=hook_logs.append,
        progress_cb=lambda pct, stage: hook_progress.append((pct, stage)),
        on_proc=lambda p: hook_procs.append(p.pid),
    )
    assert res_hooks["verified"] is True
    assert res_hooks["targetSdk"] == 28
    assert res_hooks["patchSummary"]["method"] == "slim_apktool"
    assert res_hooks["iconPath"] is not None
    assert hook_logs == res_hooks["logs"] and len(hook_logs) >= 4
    assert hook_progress and hook_progress[-1][0] == 100
    assert [p for p, _ in hook_progress] == sorted(p for p, _ in hook_progress)
    assert len(hook_procs) >= 2
    assert not (job_hooks / "_work").exists()

    # 2. cancel_event aborts pipeline cleanly and removes _work
    cancel_now = threading.Event()
    cancel_now.set()
    with pytest.raises(CommandCanceledError) as cancel_pipe:
        patch_and_sign_pipeline(
            "001122334455",
            job_hooks,
            no_sdk_apk,
            isolated_keystore,
            cancel_event=cancel_now,
        )
    assert cancel_pipe.value.status_code == 409
    assert not (job_hooks / "_work").exists()

    # 3. mode="resign_only" preserves targetSdk=19 and signs with v1+v2+v3
    job_ro = tmp_path / "112233445500"
    job_ro.mkdir()
    src_ro = build_synthetic_apk(job_ro / "ro.apk", min_sdk=14, target_sdk=19)
    res_ro = patch_and_sign_pipeline(
        "112233445500",
        job_ro,
        src_ro,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
        mode="resign_only",
    )
    assert res_ro["verified"] is True
    assert res_ro["targetSdk"] == 19
    assert res_ro["patchSummary"]["method"] == "resign_only"
    assert res_ro["patchSummary"]["manifestPatched"] is False

    # 4. resign=False produces unverified patched APK (and build_full_xapk rejects unverified APK)
    job_nosign = tmp_path / "223344556600"
    job_nosign.mkdir()
    src_ns = build_synthetic_apk(job_nosign / "nosign.apk", min_sdk=14, target_sdk=19)
    res_ns = patch_and_sign_pipeline(
        "223344556600",
        job_nosign,
        src_ns,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
        resign=False,
    )
    assert res_ns["verified"] is False
    assert res_ns["targetSdk"] == 28
    assert res_ns["patchSummary"]["resigned"] is False
    with pytest.raises(InvalidArchiveError) as unv_exc:
        build_full_xapk(job_nosign, res_ns, None, None)
    assert unv_exc.value.status_code == 400

    # 5. Single-APK build_full_xapk (no splitBundle) + iconPath avoids extra aapt + error paths
    extra_dir = job_hooks / "extra_obb"
    extra_dir.mkdir()
    single_obb = extra_dir / "main.10.com.retro.nousessdk.obb"
    single_obb.write_bytes(b"SINGLE_OBB_CONTENT")

    # Error path: no OBBs raises InvalidArchiveError (400)
    with pytest.raises(InvalidArchiveError):
        build_full_xapk(job_ro, res_ro, None, None)

    # Error path: extra_obb_meta path traversal raises InvalidArchiveError (400)
    with pytest.raises(InvalidArchiveError):
        build_full_xapk(job_hooks, res_hooks, None, [{"name": "../../etc/passwd", "path": "/etc/passwd"}])

    # Single-APK build_full_xapk uses patch_res["iconPath"] without spawning aapt
    aapt_calls: list[list[str]] = []
    real_run_cmd = run_cmd

    def _spy_containers_cmd(cmd, *args, **kwargs):
        aapt_calls.append(list(cmd))
        return real_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr("retrodroid.containers.run_cmd", _spy_containers_cmd)
    single_xapk = build_full_xapk(
        job_hooks,
        res_hooks,
        None,
        [{"name": single_obb.name, "path": str(single_obb)}],
    )
    monkeypatch.undo()

    assert single_xapk["ok"] is True
    assert single_xapk["hasIcon"] is True
    assert aapt_calls == [], f"Expected zero aapt calls when iconPath is in patch_res, got {aapt_calls}"
    with zipfile.ZipFile(job_hooks / single_xapk["fileName"], "r") as zsingle:
        snames = set(zsingle.namelist())
        assert "com.retro.nousessdk.apk" in snames
        assert "icon.png" in snames
        assert "Android/obb/com.retro.nousessdk/main.10.com.retro.nousessdk.obb" in snames
        manifest_s = json.loads(zsingle.read("manifest.json").decode("utf-8"))
        assert "split_apks" not in manifest_s
        assert manifest_s["apk"] == "com.retro.nousessdk.apk"

    # Cancel event passed positionally into build_full_xapk cleans up temp & raises 409
    cancel_xapk = threading.Event()
    cancel_xapk.set()
    with pytest.raises(CommandCanceledError) as cx_exc:
        build_full_xapk(job_hooks, res_hooks, None, None, None, cancel_xapk)
    assert cx_exc.value.status_code == 409
    assert list(job_hooks.glob("*.tmp")) == []

    # 6. C-4 Low-disk src_apk deletion: blocked when resign=False (unverified), executes when verified
    job_disk = tmp_path / "334455667788"
    job_disk.mkdir()
    big_src = job_disk / "large_game.apk"
    small_seed = build_synthetic_apk(tmp_path / "seed_large.apk", min_sdk=14, target_sdk=19)
    # Build a real >180 MB APK using a ZIP_STORED zero pad entry (fast streaming, low RAM)
    with zipfile.ZipFile(small_seed, "r") as zin, zipfile.ZipFile(big_src, "w", allowZip64=True) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        pad_info = zipfile.ZipInfo("assets/pad_181mb.bin")
        pad_info.date_time = (2024, 1, 1, 0, 0, 0)
        pad_info.compress_type = zipfile.ZIP_STORED
        zero_mb = b"\x00" * (1024 * 1024)
        with zout.open(pad_info, "w") as pfp:
            for _ in range(181):
                pfp.write(zero_mb)

    upload_meta_path = job_disk / "upload_meta.json"
    write_json_atomic(upload_meta_path, {"fileName": big_src.name, "repatchAvailable": True})
    low_disk_cfg = Settings(
        WORK_DIR=tmp_path / "work",
        KEYSTORE_PATH=isolated_keystore.path,
        KEYSTORE_PERSISTENT=True,
        DISK_FREE_FLOOR_MB=10_000_000,
    )

    try:
        # Unverified (resign=False) MUST NOT delete big_src even under low disk
        res_disk_unv = patch_and_sign_pipeline(
            "334455667788",
            job_disk,
            big_src,
            isolated_keystore,
            options=ManifestPatchOptions(target_sdk=28),
            resign=False,
            settings=low_disk_cfg,
        )
        assert res_disk_unv["verified"] is False
        assert big_src.is_file()
        assert res_disk_unv["repatchAvailable"] is True
        assert json.loads(upload_meta_path.read_text(encoding="utf-8"))["repatchAvailable"] is True

        # Verified (resign=True) under low disk deletes big_src and sets repatchAvailable=False
        res_disk_ver = patch_and_sign_pipeline(
            "334455667788",
            job_disk,
            big_src,
            isolated_keystore,
            options=ManifestPatchOptions(target_sdk=28),
            resign=True,
            settings=low_disk_cfg,
        )
        assert res_disk_ver["verified"] is True
        assert not big_src.exists()
        assert res_disk_ver["repatchAvailable"] is False
        assert json.loads(upload_meta_path.read_text(encoding="utf-8"))["repatchAvailable"] is False
    finally:
        big_src.unlink(missing_ok=True)
        for p in job_disk.glob("*.apk"):
            p.unlink(missing_ok=True)


# ===========================================================================
# 10. Iteration 3 Regression Tests (DEF-I2-02..DEF-I2-06 & Polish)
# ===========================================================================


def test_def_i2_02_reuploaded_apks_and_xapk_archives_not_overwritten(
    tmp_path: Path, isolated_keystore
) -> None:
    """DEF-I2-02: Re-uploaded .apks, container .apk, and Full .xapk archives are never overwritten."""
    base_src = build_synthetic_apk(
        tmp_path / "seed_base_reup.apk",
        package="com.retro.reupapks",
        version_code=10,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    split_src = build_synthetic_apk(
        tmp_path / "seed_split_arm64.apk",
        package="com.retro.reupapks",
        version_code=10,
        split_name="config.arm64_v8a",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )

    # Case A: Re-uploaded base_uyumlu_SplitPaket.apks with embedded OBB
    job_apks = tmp_path / "1234567890ab"
    job_apks.mkdir()
    reup_apks = job_apks / "base_uyumlu_SplitPaket.apks"
    with zipfile.ZipFile(reup_apks, "w", allowZip64=True) as zout:
        zout.write(base_src, "base.apk")
        zout.write(split_src, "config.arm64_v8a.apk")
        zout.writestr(
            "Android/obb/com.retro.reupapks/main.10.com.retro.reupapks.obb",
            b"PRESERVED_OBB_BYTES",
        )
    orig_apks_sha = hashlib.sha256(reup_apks.read_bytes()).hexdigest()

    ext_a, cmeta_a = unpack_container_if_needed(reup_apks, job_apks)
    res_a = patch_and_sign_pipeline(
        "1234567890ab",
        job_apks,
        ext_a,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert res_a["verified"] is True
    assert res_a["splitBundle"] is not None
    bundle_name = res_a["splitBundle"]["fileName"]
    bundle_path = job_apks / bundle_name
    assert bundle_path.is_file()
    assert bundle_path.resolve() != reup_apks.resolve()
    assert len(bundle_name) <= 120
    assert bundle_name.endswith("_SplitPaket.apks")
    assert res_a["splitBundle"]["downloadUrl"] == safe_url_download("1234567890ab", bundle_name)
    assert hashlib.sha256(reup_apks.read_bytes()).hexdigest() == orig_apks_sha
    assert extract_container_obb_atomic(job_apks, cmeta_a, 0).read_bytes() == b"PRESERVED_OBB_BYTES"
    assert not (job_apks / "_work").exists()

    # Subsequent Full XAPK build works cleanly with intact source archive OBB + disambiguated splits
    full_from_apks = build_full_xapk(job_apks, res_a, cmeta_a, None)
    assert full_from_apks["ok"] is True
    with zipfile.ZipFile(job_apks / full_from_apks["fileName"], "r") as zfa:
        assert (
            zfa.read("Android/obb/com.retro.reupapks/main.10.com.retro.reupapks.obb")
            == b"PRESERVED_OBB_BYTES"
        )
        assert "config.arm64_v8a.apk" in set(zfa.namelist())

    # Case B: Container archive uploaded as base_uyumlu.apk (signed vs archive_path collision)
    job_cont_apk = tmp_path / "1234567890ac"
    job_cont_apk.mkdir()
    reup_cont_apk = job_cont_apk / "base_uyumlu.apk"
    with zipfile.ZipFile(reup_cont_apk, "w", allowZip64=True) as zout:
        zout.write(base_src, "base.apk")
        zout.write(split_src, "config.arm64_v8a.apk")
        zout.writestr(
            "Android/obb/com.retro.reupapks/main.10.com.retro.reupapks.obb",
            b"CONT_APK_OBB",
        )
    orig_cont_sha = hashlib.sha256(reup_cont_apk.read_bytes()).hexdigest()

    ext_c, cmeta_c = unpack_container_if_needed(reup_cont_apk, job_cont_apk)
    assert cmeta_c["containerType"] != "APK"
    res_c = patch_and_sign_pipeline(
        "1234567890ac",
        job_cont_apk,
        ext_c,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert res_c["verified"] is True
    assert res_c["fileName"] != "base_uyumlu.apk"
    assert res_c["fileName"].endswith("_patched.apk")
    assert len(res_c["fileName"]) <= 120
    assert (job_cont_apk / res_c["fileName"]).resolve() != reup_cont_apk.resolve()
    assert hashlib.sha256(reup_cont_apk.read_bytes()).hexdigest() == orig_cont_sha
    assert res_c["splitBundle"] is not None
    assert (job_cont_apk / res_c["splitBundle"]["fileName"]).is_file()
    assert extract_container_obb_atomic(job_cont_apk, cmeta_c, 0).read_bytes() == b"CONT_APK_OBB"

    # Case C: Re-uploaded <pkg>_RetroDroid_Full_Signed.xapk + disk fallback + 80-char packageId cap
    job_xapk = tmp_path / "ab12cd34ef56"
    job_xapk.mkdir()
    base_x = build_synthetic_apk(
        tmp_path / "seed_base_reupx.apk",
        package="com.retro.reupxapk",
        version_code=10,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    reup_xapk = job_xapk / "com.retro.reupxapk_RetroDroid_Full_Signed.xapk"
    xapk_manifest = {
        "xapk_version": 2,
        "package_name": "com.retro.reupxapk",
        "apk": "base.apk",
        "expansions": [
            {
                "file": "Android/obb/com.retro.reupxapk/main.10.com.retro.reupxapk.obb",
                "install_location": "EXTERNAL_STORAGE",
                "install_path": "Android/obb/com.retro.reupxapk/main.10.com.retro.reupxapk.obb",
            }
        ],
    }
    with zipfile.ZipFile(reup_xapk, "w", allowZip64=True) as zout:
        zout.writestr("manifest.json", json.dumps(xapk_manifest))
        zout.write(base_x, "base.apk")
        zout.writestr(
            "Android/obb/com.retro.reupxapk/main.10.com.retro.reupxapk.obb",
            b"REUP_XAPK_OBB",
        )
    orig_xapk_sha = hashlib.sha256(reup_xapk.read_bytes()).hexdigest()

    ext_x, cmeta_x = unpack_container_if_needed(reup_xapk, job_xapk)
    patch_x = patch_and_sign_pipeline(
        "ab12cd34ef56",
        job_xapk,
        ext_x,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    full_x = build_full_xapk(job_xapk, patch_x, cmeta_x, None)
    assert full_x["ok"] is True
    out_name = full_x["fileName"]
    out_path = job_xapk / out_name
    assert out_path.is_file()
    assert out_path.resolve() != reup_xapk.resolve()
    assert len(out_name) <= 120
    assert out_name.endswith("_RetroDroid_Full_Signed.xapk")
    assert full_x["downloadUrl"] == f"/api/download-full-xapk/{job_xapk.name}"
    assert hashlib.sha256(reup_xapk.read_bytes()).hexdigest() == orig_xapk_sha
    assert list(job_xapk.glob("*.tmp")) == []
    with zipfile.ZipFile(out_path, "r") as zfx:
        fnames = set(zfx.namelist())
        assert "manifest.json" in fnames
        assert "com.retro.reupxapk.apk" in fnames
        assert (
            zfx.read("Android/obb/com.retro.reupxapk/main.10.com.retro.reupxapk.obb")
            == b"REUP_XAPK_OBB"
        )

    # Sub-case C2: container_meta=None with container_meta.json on disk still protects archive
    extra_x = job_xapk / "extra_obb"
    extra_x.mkdir(exist_ok=True)
    (extra_x / "patch.10.com.retro.reupxapk.obb").write_bytes(b"EXTRA_OBB")
    full_x2 = build_full_xapk(job_xapk, patch_x, None, None)
    assert (job_xapk / full_x2["fileName"]).resolve() != reup_xapk.resolve()
    assert hashlib.sha256(reup_xapk.read_bytes()).hexdigest() == orig_xapk_sha

    # Sub-case C3: 80-char packageId collision boundary stays <= 120 chars & preserves suffix
    long_pkg = "com." + "p" * 76
    long_coll = job_xapk / f"{long_pkg}_RetroDroid_Full_Signed.xapk"
    long_coll.write_bytes(b"SENTINEL_LONG_XAPK")
    res_long = build_full_xapk(
        job_xapk,
        patch_x,
        {"archive": str(long_coll), "obbFiles": []},
        None,
        apk_info={"packageId": long_pkg},
    )
    assert len(res_long["fileName"]) <= 120
    assert res_long["fileName"].endswith("_RetroDroid_Full_Signed.xapk")
    assert (job_xapk / res_long["fileName"]).resolve() != long_coll.resolve()
    assert long_coll.read_bytes() == b"SENTINEL_LONG_XAPK"


def test_def_i2_03_fallback_binary_axml_noop_and_downgrade_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    """DEF-I2-03: fallback_binary_axml matches primary binary_axml on no-op, downgrade, and aborted apktool b."""
    real_run_cmd = run_cmd

    def _fail_apktool_all(cmd, *args, **kwargs):
        if cmd and Path(cmd[0]).name == "apktool":
            return CmdResult(1, "", "Simulated apktool decode failure", "apktool", 0.01)
        return real_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr("retrodroid.config.run_cmd", _fail_apktool_all)

    # Case A: No-op (28 -> 28) with structural flag
    job_a = tmp_path / "f30100000001"
    job_a.mkdir()
    src_a = build_synthetic_apk(
        job_a / "noop28.apk",
        package="com.retro.fbnoop",
        min_sdk=19,
        target_sdk=28,
        include_unexported_components=False,
    )
    res_a = patch_and_sign_pipeline(
        "f30100000001",
        job_a,
        src_a,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28, enable_cleartext=True),
    )
    ps_a = res_a["patchSummary"]
    assert res_a["verified"] is True
    assert res_a["targetSdk"] == 28
    assert ps_a["method"] == "fallback_binary_axml"
    assert ps_a["manifestPatched"] is False
    assert ps_a["appliedChanges"] == []
    assert ps_a["oldTargetSdk"] == 28
    assert ps_a["effectiveTargetSdk"] == 28
    assert ps_a["skippedDowngrade"] is False
    assert "Simulated apktool decode failure" in (ps_a["fallbackReason"] or "")

    # Case B: Downgrade guard (min=29, target=29, req=28, allow_downgrade=False)
    job_b = tmp_path / "f30100000002"
    job_b.mkdir()
    src_b = build_synthetic_apk(
        job_b / "dg29.apk",
        package="com.retro.fbdg",
        min_sdk=29,
        target_sdk=29,
        include_unexported_components=False,
    )
    res_b = patch_and_sign_pipeline(
        "f30100000002",
        job_b,
        src_b,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28, allow_downgrade=False, enable_cleartext=True),
    )
    ps_b = res_b["patchSummary"]
    assert res_b["verified"] is True
    assert res_b["targetSdk"] == 29
    assert ps_b["method"] == "fallback_binary_axml"
    assert ps_b["manifestPatched"] is False
    assert ps_b["skippedDowngrade"] is True
    assert ps_b["oldTargetSdk"] == 29
    assert ps_b["effectiveTargetSdk"] == 29
    assert ps_b["appliedChanges"] == []
    assert "Simulated apktool decode failure" in (ps_b["fallbackReason"] or "")

    # Case C: Positive control (21 -> 28) with structural flag
    job_c = tmp_path / "f30100000003"
    job_c.mkdir()
    src_c = build_synthetic_apk(
        job_c / "up21.apk",
        package="com.retro.fbup",
        min_sdk=19,
        target_sdk=21,
        include_unexported_components=False,
    )
    res_c = patch_and_sign_pipeline(
        "f30100000003",
        job_c,
        src_c,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28, enable_cleartext=True),
    )
    ps_c = res_c["patchSummary"]
    assert res_c["verified"] is True
    assert res_c["targetSdk"] == 28
    assert ps_c["method"] == "fallback_binary_axml"
    assert ps_c["manifestPatched"] is True
    assert ps_c["appliedChanges"] == ["targetSdkVersion:21->28"]
    assert ps_c["oldTargetSdk"] == 21
    assert ps_c["effectiveTargetSdk"] == 28
    assert ps_c["skippedDowngrade"] is False

    # Case D: Only apktool b fails (real apktool d + XML edit ran first) -> zero stale state leak
    def _fail_apktool_build_only(cmd, *args, **kwargs):
        if cmd and Path(cmd[0]).name == "apktool" and len(cmd) > 1 and cmd[1] == "b":
            return CmdResult(1, "", "Simulated apktool build failure", "apktool", 0.01)
        return real_run_cmd(cmd, *args, **kwargs)

    monkeypatch.setattr("retrodroid.config.run_cmd", _fail_apktool_build_only)
    job_d = tmp_path / "f30100000004"
    job_d.mkdir()
    src_d = build_synthetic_apk(
        job_d / "aborted_b.apk",
        package="com.retro.fbabort",
        min_sdk=19,
        target_sdk=28,
        include_unexported_components=False,
    )
    res_d = patch_and_sign_pipeline(
        "f30100000004",
        job_d,
        src_d,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28, enable_cleartext=True),
    )
    ps_d = res_d["patchSummary"]
    assert res_d["verified"] is True
    assert res_d["targetSdk"] == 28
    assert ps_d["method"] == "fallback_binary_axml"
    assert ps_d["manifestPatched"] is False
    assert ps_d["appliedChanges"] == []
    assert ps_d["skippedDowngrade"] is False
    assert "Simulated apktool build failure" in (ps_d["fallbackReason"] or "")
    assert res_d["inspector"]["manifestFlags"]["usesCleartextTraffic"] is not True


def test_def_i2_04_circular_symlinks_in_extra_obb_raise_invalid_archive(
    tmp_path: Path, isolated_keystore
) -> None:
    """DEF-I2-04: Circular symlinks and extra_obb directory symlinks raise InvalidArchiveError(400)."""
    job_dir = tmp_path / "cd34ef560123"
    job_dir.mkdir()
    src_apk = build_synthetic_apk(
        job_dir / "symtest.apk",
        package="com.retro.symtest",
        version_code=10,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    patch_res = patch_and_sign_pipeline(
        "cd34ef560123",
        job_dir,
        src_apk,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert patch_res["verified"] is True

    extra_dir = job_dir / "extra_obb"
    extra_dir.mkdir()
    os.symlink("b.obb", extra_dir / "a.obb")
    os.symlink("a.obb", extra_dir / "b.obb")

    # Case A: rglob mutual circular symlink
    with pytest.raises(InvalidArchiveError) as exc_a:
        build_full_xapk(job_dir, patch_res, None, None)
    assert exc_a.value.status_code == 400

    # Case B: explicit extra_obb_meta (both absolute path and relative name)
    with pytest.raises(InvalidArchiveError) as exc_b1:
        build_full_xapk(
            job_dir,
            patch_res,
            None,
            [{"name": "a.obb", "path": str(extra_dir / "a.obb")}],
        )
    assert exc_b1.value.status_code == 400

    with pytest.raises(InvalidArchiveError) as exc_b2:
        build_full_xapk(job_dir, patch_res, None, [{"name": "a.obb"}])
    assert exc_b2.value.status_code == 400

    # Case C: self-loop directory symlink
    (extra_dir / "a.obb").unlink()
    (extra_dir / "b.obb").unlink()
    os.symlink("loopdir", extra_dir / "loopdir")

    with pytest.raises(InvalidArchiveError) as exc_c1:
        build_full_xapk(job_dir, patch_res, None, None)
    assert exc_c1.value.status_code == 400

    with pytest.raises(InvalidArchiveError) as exc_c2:
        build_full_xapk(job_dir, patch_res, None, [{"name": "loopdir/x.obb"}])
    assert exc_c2.value.status_code == 400

    # Case D: embedded NUL byte in extra_obb_meta
    with pytest.raises(InvalidArchiveError) as exc_nul:
        build_full_xapk(job_dir, patch_res, None, [{"name": "bad\x00.obb"}])
    assert exc_nul.value.status_code == 400

    # Case E: extra_obb directory itself replaced with a symlink
    (extra_dir / "loopdir").unlink()
    extra_dir.rmdir()
    os.symlink(str(tmp_path), extra_dir)
    with pytest.raises(InvalidArchiveError) as exc_d:
        build_full_xapk(job_dir, patch_res, None, None)
    assert exc_d.value.status_code == 400

    assert list(job_dir.glob("*.tmp")) == []


def test_def_i2_05_space_obb_preserves_install_path_vs_duplicate_disambiguation(
    tmp_path: Path, isolated_keystore
) -> None:
    """DEF-I2-05: Benign filename sanitization preserves expansions[].install_path while duplicate OBBs disambiguate."""
    base_apk = build_synthetic_apk(
        tmp_path / "seed_space_obb.apk",
        package="com.retro.spaceobb",
        version_code=5,
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )

    # Case A: Space & special chars in source file with canonical expansions[].install_path
    job_a = tmp_path / "e50100000001"
    job_a.mkdir()
    xapk_a = job_a / "space_game.xapk"
    canonical_main = "Android/obb/com.retro.spaceobb/main.5.com.retro.spaceobb.obb"
    manifest_a = {
        "xapk_version": 2,
        "package_name": "com.retro.spaceobb",
        "apk": "base.apk",
        "expansions": [
            {
                "file": "obb_files/my game data (v5).obb",
                "install_location": "EXTERNAL_STORAGE",
                "install_path": canonical_main,
            }
        ],
    }
    with zipfile.ZipFile(xapk_a, "w", allowZip64=True) as zout:
        zout.writestr("manifest.json", json.dumps(manifest_a))
        zout.write(base_apk, "base.apk")
        zout.writestr("obb_files/my game data (v5).obb", b"SPACE_OBB_DATA")

    ext_a, cmeta_a = unpack_container_if_needed(xapk_a, job_a)
    assert cmeta_a["obbFiles"][0]["disambiguated"] is False
    assert cmeta_a["obbFiles"][0]["name"] != cmeta_a["obbFiles"][0]["originalName"]

    patch_a = patch_and_sign_pipeline(
        "e50100000001",
        job_a,
        ext_a,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    full_a = build_full_xapk(job_a, patch_a, cmeta_a, None)
    assert full_a["warnings"] == []
    with zipfile.ZipFile(job_a / full_a["fileName"], "r") as zfa:
        names_a = set(zfa.namelist())
        assert canonical_main in names_a
        assert zfa.read(canonical_main) == b"SPACE_OBB_DATA"
        assert not any("my_game_data" in n for n in names_a)
        m_a = json.loads(zfa.read("manifest.json").decode("utf-8"))
        assert m_a["expansions"][0]["install_path"] == canonical_main

    # Case B: Legacy container_meta dict lacking "disambiguated" key
    legacy_cmeta_a = {
        **cmeta_a,
        "obbFiles": [
            {k: v for k, v in obb.items() if k != "disambiguated"}
            for obb in cmeta_a["obbFiles"]
        ],
    }
    full_b = build_full_xapk(job_a, patch_a, legacy_cmeta_a, None)
    assert full_b["warnings"] == []
    with zipfile.ZipFile(job_a / full_b["fileName"], "r") as zfb:
        assert canonical_main in set(zfb.namelist())
        assert zfb.read(canonical_main) == b"SPACE_OBB_DATA"

    # Case C: Genuine duplicate basenames without expansions (with & without "disambiguated" key)
    job_c = tmp_path / "e50100000002"
    job_c.mkdir()
    xapk_c = job_c / "dup_obb_game.zip"
    with zipfile.ZipFile(xapk_c, "w", allowZip64=True) as zout:
        zout.write(base_apk, "base.apk")
        zout.writestr("dir1/main.5.com.retro.spaceobb.obb", b"DUP_ONE")
        zout.writestr("dir2/main.5.com.retro.spaceobb.obb", b"DUP_TWO")

    ext_c, cmeta_c = unpack_container_if_needed(xapk_c, job_c)
    assert len(cmeta_c["obbFiles"]) == 2
    assert all(obb["disambiguated"] is True for obb in cmeta_c["obbFiles"])
    assert cmeta_c["obbFiles"][0]["name"] != cmeta_c["obbFiles"][1]["name"]
    assert cmeta_c["obbFiles"][0]["name"].startswith("0_")
    assert cmeta_c["obbFiles"][1]["name"].startswith("1_")

    patch_c = patch_and_sign_pipeline(
        "e50100000002",
        job_c,
        ext_c,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    full_c = build_full_xapk(job_c, patch_c, cmeta_c, None)
    with zipfile.ZipFile(job_c / full_c["fileName"], "r") as zfc:
        p0 = f"Android/obb/com.retro.spaceobb/{cmeta_c['obbFiles'][0]['name']}"
        p1 = f"Android/obb/com.retro.spaceobb/{cmeta_c['obbFiles'][1]['name']}"
        assert zfc.read(p0) == b"DUP_ONE"
        assert zfc.read(p1) == b"DUP_TWO"

    legacy_cmeta_c = {
        **cmeta_c,
        "obbFiles": [
            {k: v for k, v in obb.items() if k != "disambiguated"}
            for obb in cmeta_c["obbFiles"]
        ],
    }
    full_c_leg = build_full_xapk(job_c, patch_c, legacy_cmeta_c, None)
    with zipfile.ZipFile(job_c / full_c_leg["fileName"], "r") as zfcl:
        assert zfcl.read(p0) == b"DUP_ONE"
        assert zfcl.read(p1) == b"DUP_TWO"

    # Case D: Duplicate source basenames mapped to distinct canonical expansions[].install_path
    job_d = tmp_path / "e50100000003"
    job_d.mkdir()
    xapk_d = job_d / "dup_src_distinct_install.xapk"
    canonical_patch = "Android/obb/com.retro.spaceobb/patch.5.com.retro.spaceobb.obb"
    manifest_d = {
        "xapk_version": 2,
        "package_name": "com.retro.spaceobb",
        "apk": "base.apk",
        "expansions": [
            {
                "file": "src1/data.obb",
                "install_location": "EXTERNAL_STORAGE",
                "install_path": canonical_main,
            },
            {
                "file": "src2/data.obb",
                "install_location": "EXTERNAL_STORAGE",
                "install_path": canonical_patch,
            },
        ],
    }
    with zipfile.ZipFile(xapk_d, "w", allowZip64=True) as zout:
        zout.writestr("manifest.json", json.dumps(manifest_d))
        zout.write(base_apk, "base.apk")
        zout.writestr("src1/data.obb", b"MAIN_D")
        zout.writestr("src2/data.obb", b"PATCH_D")

    ext_d, cmeta_d = unpack_container_if_needed(xapk_d, job_d)
    assert all(obb["disambiguated"] is True for obb in cmeta_d["obbFiles"])
    patch_d = patch_and_sign_pipeline(
        "e50100000003",
        job_d,
        ext_d,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    full_d = build_full_xapk(job_d, patch_d, cmeta_d, None)
    assert full_d["warnings"] == []
    with zipfile.ZipFile(job_d / full_d["fileName"], "r") as zfd:
        assert zfd.read(canonical_main) == b"MAIN_D"
        assert zfd.read(canonical_patch) == b"PATCH_D"


def test_def_i2_06_and_polish_missing_split_api_key_package_anchor_dot_meta_inf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_keystore
) -> None:
    """DEF-I2-06 missing split zipEntry (404) + api-key redaction + ^package: anchor + ./META-INF/ strip."""
    from retrodroid.inspector import _parse_badging_package_meta
    from retrodroid.patcher import _is_signature_meta_entry

    # Case A: DEF-I2-06 missing & empty split zipEntry raise InvalidArchiveError(404)
    base_apk = build_synthetic_apk(
        tmp_path / "seed_miss_split.apk",
        package="com.retro.misssplit",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    job_miss = tmp_path / "de2600112233"
    job_miss.mkdir()
    valid_cont = job_miss / "valid_container.xapk"
    with zipfile.ZipFile(valid_cont, "w", allowZip64=True) as zout:
        zout.write(base_apk, "base.apk")

    ext_miss, cmeta_miss = unpack_container_if_needed(valid_cont, job_miss)
    cmeta_miss["splitApks"] = [{"name": "missing_split.apk", "zipEntry": "nonexistent.apk"}]
    write_json_atomic(job_miss / "container_meta.json", cmeta_miss)

    with pytest.raises(InvalidArchiveError) as exc_miss:
        patch_and_sign_pipeline(
            "de2600112233",
            job_miss,
            ext_miss,
            isolated_keystore,
            options=ManifestPatchOptions(target_sdk=28),
        )
    assert exc_miss.value.status_code == 404
    assert list(job_miss.glob("*.tmp")) == []
    assert not (job_miss / "_work").exists()

    # Empty zipEntry also produces InvalidArchiveError(404)
    cmeta_miss["splitApks"] = [{"name": "", "zipEntry": ""}]
    write_json_atomic(job_miss / "container_meta.json", cmeta_miss)
    with pytest.raises(InvalidArchiveError) as exc_empty:
        patch_and_sign_pipeline(
            "de2600112233",
            job_miss,
            ext_miss,
            isolated_keystore,
            options=ManifestPatchOptions(target_sdk=28),
        )
    assert exc_empty.value.status_code == 404
    assert not (job_miss / "_work").exists()

    # Case B: Polish 1 — hyphenated "api-key" redaction in StructuredJsonFormatter
    fmt = StructuredJsonFormatter()
    rec = logging.LogRecord(
        name="retrodroid.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="header audit",
        args=(),
        exc_info=None,
    )
    rec.headers = {
        "X-Api-Key": "SecretHyphenKey1",
        "api-key": "SecretHyphenKey2",
        "x-retrodroid-api-key": "SecretHyphenKey3",
        "apiLevel": 34,
        "tests_passed": 65,
    }
    formatted = fmt.format(rec)
    assert "SecretHyphenKey1" not in formatted
    assert "SecretHyphenKey2" not in formatted
    assert "SecretHyphenKey3" not in formatted
    parsed_log = json.loads(formatted)
    assert parsed_log["headers"]["X-Api-Key"] == "[REDACTED]"
    assert parsed_log["headers"]["api-key"] == "[REDACTED]"
    assert parsed_log["headers"]["x-retrodroid-api-key"] == "[REDACTED]"
    assert parsed_log["headers"]["apiLevel"] == 34
    assert parsed_log["headers"]["tests_passed"] == 65

    # Case C: Polish 2 — ^package: anchoring blocks spoofed application-label metadata
    apk_spoof = build_synthetic_apk(
        tmp_path / "spoof_label.apk",
        package="com.retro.spoof",
        label="Evil versionName='FAKE' versionCode='999' App",
        version_code=7,
        version_name="2.1",
        min_sdk=19,
        target_sdk=28,
        include_unexported_components=False,
    )
    info_real = inspect_apk(apk_spoof)
    assert info_real["packageId"] == "com.retro.spoof"
    assert info_real["versionCode"] == "7"
    assert info_real["versionName"] == "2.1"

    real_run_cmd = run_cmd

    def _strip_pkg_version_name(cmd, *args, **kwargs):
        res = real_run_cmd(cmd, *args, **kwargs)
        if cmd and Path(cmd[0]).name == "aapt" and cmd[1:3] == ["dump", "badging"]:
            lines = (res.stdout or "").splitlines()
            if lines and lines[0].startswith("package:"):
                lines[0] = lines[0].replace(" versionName='2.1'", "")
            return CmdResult(
                res.returncode,
                "\n".join(lines) + "\n",
                res.stderr,
                res.cmd_name,
                res.elapsed_seconds,
            )
        return res

    monkeypatch.setattr("retrodroid.inspector.run_cmd", _strip_pkg_version_name)
    info_omitted = inspect_apk(apk_spoof)
    monkeypatch.undo()
    assert info_omitted["packageId"] == "com.retro.spoof"
    assert info_omitted["versionCode"] == "7"
    assert info_omitted["versionName"] == ""

    # Direct fallback check when ^package: line is absent
    assert _parse_badging_package_meta("versionCode='5'\nversionName='1.0'\n") == ("bilinmiyor", "5", "1.0")
    assert _parse_badging_package_meta(
        "application-label:'Evil versionCode=\\'999\\' versionName=\\'FAKE\\''\n"
    ) == ("bilinmiyor", "", "")

    # Case D: Polish 3 — ./META-INF/ normalization in _is_signature_meta_entry & stream_rewrite_apk
    assert _is_signature_meta_entry("./META-INF/CERT.SF") is True
    assert _is_signature_meta_entry("././META-INF//STAMP-CERT-SHA256") is True
    assert _is_signature_meta_entry(".\\META-INF\\CERT.RSA") is True
    assert _is_signature_meta_entry("META-INF/./SIG-X") is True
    assert _is_signature_meta_entry("./META-INF/services/com.example.Keep") is False
    assert _is_signature_meta_entry("../META-INF/CERT.SF") is False
    assert _is_signature_meta_entry("META-INF/CERT.SF/") is False

    apk_dot_meta = build_synthetic_apk(
        tmp_path / "dot_meta_inf.apk",
        package="com.retro.dotmeta",
        min_sdk=19,
        target_sdk=28,
        include_unexported_components=False,
        extra_entries=[
            ("./META-INF/CERT.SF", b"sig1", zipfile.ZIP_DEFLATED, None),
            ("././META-INF//STAMP-CERT-SHA256", b"stamp", zipfile.ZIP_DEFLATED, None),
            (".\\META-INF\\CERT.RSA", b"sig2", zipfile.ZIP_DEFLATED, None),
            ("META-INF/./SIG-X", b"sig3", zipfile.ZIP_DEFLATED, None),
            ("./META-INF/services/com.example.Keep", b"svc", zipfile.ZIP_DEFLATED, None),
            ("sub/./META-INF/CERT.SF", b"nested", zipfile.ZIP_DEFLATED, None),
            ("../META-INF/CERT.SF", b"parent_meta", zipfile.ZIP_DEFLATED, None),
        ],
    )
    rewritten_dot = tmp_path / "dot_meta_inf_out.apk"
    rw_stats = stream_rewrite_apk(apk_dot_meta, rewritten_dot)
    assert rw_stats["strippedSignatureEntries"] == 4
    with zipfile.ZipFile(rewritten_dot, "r") as zrw:
        rw_names = set(zrw.namelist())
        assert "./META-INF/CERT.SF" not in rw_names
        assert "././META-INF//STAMP-CERT-SHA256" not in rw_names
        assert ".\\META-INF\\CERT.RSA" not in rw_names
        assert "META-INF/./SIG-X" not in rw_names
        assert "./META-INF/services/com.example.Keep" in rw_names
        assert "sub/./META-INF/CERT.SF" in rw_names
        assert "../META-INF/CERT.SF" in rw_names


# ===========================================================================
# 11. Iteration 4 Regression Tests (CHAL1-01, DEF-I3-C2-01, DEF-I3-C2-02)
# ===========================================================================


def test_chal1_01_terminate_process_tree_kills_redirected_stdio_grandchildren(
    tmp_path: Path,
) -> None:
    """CHAL1-01: _terminate_process_tree escalates SIGKILL to redirected-stdio grandchildren."""
    import signal

    def _spawn_redirected_cmd(pid_file: Path) -> list[str]:
        grandchild_code = (
            "import os, signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"fp = open({str(pid_file)!r}, 'w', encoding='utf-8'); "
            "fp.write(str(os.getpid())); fp.flush(); fp.close(); "
            "time.sleep(60)"
        )
        child_code = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {grandchild_code!r}], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "time.sleep(60)"
        )
        return [sys.executable, "-c", child_code]

    # Case 1: Timeout path (CommandTimeoutError)
    pf_timeout = tmp_path / "gc_devnull_timeout.pid"
    gc_timeout_pid: int | None = None
    try:
        t0 = time.monotonic()
        with pytest.raises(CommandTimeoutError):
            run_cmd(_spawn_redirected_cmd(pf_timeout), timeout=0.6)
        elapsed_t = time.monotonic() - t0
        assert pf_timeout.is_file(), "Redirected-stdio grandchild did not start before timeout"
        gc_timeout_pid = int(pf_timeout.read_text(encoding="utf-8").strip())
        assert _wait_pid_dead(gc_timeout_pid), (
            f"DEVNULL-redirected SIGTERM-ignoring grandchild {gc_timeout_pid} survived timeout"
        )
        assert elapsed_t < 2.5
    finally:
        if gc_timeout_pid is None and pf_timeout.is_file():
            txt = pf_timeout.read_text(encoding="utf-8").strip()
            if txt.isdigit():
                gc_timeout_pid = int(txt)
        if gc_timeout_pid is not None:
            try:
                os.kill(gc_timeout_pid, signal.SIGKILL)
            except OSError:
                pass

    # Case 2: Cancel path (CommandCanceledError)
    pf_cancel = tmp_path / "gc_devnull_cancel.pid"
    cancel_ev = threading.Event()
    gc_cancel_pid: int | None = None

    def _trigger_cancel() -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if pf_cancel.is_file() and pf_cancel.read_text(encoding="utf-8").strip().isdigit():
                time.sleep(0.05)
                break
            time.sleep(0.02)
        cancel_ev.set()

    canceler = threading.Thread(target=_trigger_cancel, daemon=True)
    canceler.start()
    try:
        t0 = time.monotonic()
        with pytest.raises(CommandCanceledError):
            run_cmd(_spawn_redirected_cmd(pf_cancel), timeout=15, cancel_event=cancel_ev)
        elapsed_c = time.monotonic() - t0
        canceler.join(timeout=2.0)
        assert pf_cancel.is_file(), "Redirected-stdio grandchild did not start before cancel"
        gc_cancel_pid = int(pf_cancel.read_text(encoding="utf-8").strip())
        assert _wait_pid_dead(gc_cancel_pid), (
            f"DEVNULL-redirected SIGTERM-ignoring grandchild {gc_cancel_pid} survived cancel"
        )
        assert elapsed_c < 3.0
    finally:
        cancel_ev.set()
        canceler.join(timeout=2.0)
        if gc_cancel_pid is None and pf_cancel.is_file():
            txt = pf_cancel.read_text(encoding="utf-8").strip()
            if txt.isdigit():
                gc_cancel_pid = int(txt)
        if gc_cancel_pid is not None:
            try:
                os.kill(gc_cancel_pid, signal.SIGKILL)
            except OSError:
                pass


def test_def_i3_c2_01_falsy_split_zip_entry_never_falls_back_to_name(
    tmp_path: Path, isolated_keystore
) -> None:
    """DEF-I3-C2-01: Explicit falsy/non-string zipEntry raises InvalidArchiveError(404); omitted key falls back."""
    base_apk = build_synthetic_apk(
        tmp_path / "seed_falsy_base.apk",
        package="com.retro.falsysplit",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )
    split_apk = build_synthetic_apk(
        tmp_path / "seed_falsy_arm64.apk",
        package="com.retro.falsysplit",
        min_sdk=19,
        target_sdk=19,
        include_unexported_components=False,
    )

    job_dir = tmp_path / "f13c20100001"
    job_dir.mkdir()
    xapk_path = job_dir / "split_container.xapk"
    with zipfile.ZipFile(xapk_path, "w", allowZip64=True) as zout:
        zout.write(base_apk, "base.apk")
        zout.write(split_apk, "config.arm64_v8a.apk")

    ext_base, cmeta = unpack_container_if_needed(xapk_path, job_dir)
    assert len(cmeta["splitApks"]) == 1

    falsy_cases: list[object] = [
        {"name": "base.apk", "zipEntry": ""},
        {"name": "config.arm64_v8a.apk", "zipEntry": ""},
        {"name": "config.arm64_v8a.apk", "zipEntry": None},
        {"name": "config.arm64_v8a.apk", "zipEntry": 0},
        {"name": "config.arm64_v8a.apk", "zipEntry": False},
        {"name": "config.arm64_v8a.apk", "zipEntry": []},
        {"name": "config.arm64_v8a.apk", "zipEntry": {}},
        "config.arm64_v8a.apk",
    ]
    for bad_split in falsy_cases:
        cmeta_bad = {**cmeta, "splitApks": [bad_split]}
        write_json_atomic(job_dir / "container_meta.json", cmeta_bad)
        with pytest.raises(InvalidArchiveError) as exc_info:
            patch_and_sign_pipeline(
                "f13c20100001",
                job_dir,
                ext_base,
                isolated_keystore,
                options=ManifestPatchOptions(target_sdk=28),
            )
        assert exc_info.value.status_code == 404, f"Expected 404 for {bad_split!r}"
        assert list(job_dir.glob("*.tmp")) == []
        assert list(job_dir.glob("*.apks")) == []
        assert not (job_dir / "_work").exists()

    # Legacy fallback: omitted "zipEntry" key must still resolve via sp["name"]
    cmeta_legacy = {**cmeta, "splitApks": [{"name": "config.arm64_v8a.apk"}]}
    write_json_atomic(job_dir / "container_meta.json", cmeta_legacy)
    res_legacy = patch_and_sign_pipeline(
        "f13c20100001",
        job_dir,
        ext_base,
        isolated_keystore,
        options=ManifestPatchOptions(target_sdk=28),
    )
    assert res_legacy["ok"] is True
    assert res_legacy["splitBundle"] is not None
    assert res_legacy["splitBundle"]["splitCount"] == 1
    bundle_path = job_dir / res_legacy["splitBundle"]["fileName"]
    assert bundle_path.is_file()
    with zipfile.ZipFile(bundle_path, "r") as zb:
        assert set(zb.namelist()) == {"base.apk", "config.arm64_v8a.apk"}
    assert not (job_dir / "_work").exists()


def test_def_i3_c2_02_upload_meta_sanitized_filename_and_windows_path_protected(
    tmp_path: Path, isolated_keystore
) -> None:
    """DEF-I3-C2-02: build_full_xapk protects upload_meta sanitizedFileName and Windows backslash paths."""
    pkg = "com.retro.upmeta"
    canonical_name = f"{pkg}_RetroDroid_Full_Signed.xapk"
    seed_apk = build_synthetic_apk(
        tmp_path / "seed_upmeta.apk",
        package=pkg,
        version_code=12,
        min_sdk=19,
        target_sdk=28,
        include_unexported_components=False,
    )

    def _setup_job(job_id: str, upload_meta: dict[str, object], sentinel: bytes | None) -> tuple[Path, dict]:
        jdir = tmp_path / job_id
        jdir.mkdir()
        src_apk = jdir / "game_src.apk"
        src_apk.write_bytes(seed_apk.read_bytes())
        patch_res = patch_and_sign_pipeline(
            job_id,
            jdir,
            src_apk,
            isolated_keystore,
            options=ManifestPatchOptions(target_sdk=28),
        )
        obb_dir = jdir / "extra_obb"
        obb_dir.mkdir()
        (obb_dir / f"main.12.{pkg}.obb").write_bytes(b"OBB_PAYLOAD_UPMETA")
        # Ensure container_meta.json is absent so only upload_meta.json protects the upload
        assert not (jdir / "container_meta.json").exists()
        write_json_atomic(jdir / "upload_meta.json", upload_meta)
        if sentinel is not None:
            (jdir / canonical_name).write_bytes(sentinel)
        return jdir, patch_res

    # Case A: Both Windows backslash fileName and sanitizedFileName match canonical Full XAPK name
    sentinel_a = b"ORIGINAL_UPLOAD_SENTINEL_BOTH"
    job_a, patch_a = _setup_job(
        "f13c20200001",
        {
            "fileName": rf"C:\Users\Player\{canonical_name}",
            "sanitizedFileName": canonical_name,
        },
        sentinel_a,
    )
    res_a = build_full_xapk(job_a, patch_a, None, None)
    assert (job_a / canonical_name).read_bytes() == sentinel_a
    assert res_a["fileName"] != canonical_name
    assert len(res_a["fileName"]) <= 120
    assert res_a["fileName"].endswith("_RetroDroid_Full_Signed.xapk")
    with zipfile.ZipFile(job_a / res_a["fileName"], "r") as zfa:
        assert f"Android/obb/{pkg}/main.12.{pkg}.obb" in set(zfa.namelist())

    # Case B: Windows backslash fileName ONLY (no sanitizedFileName)
    sentinel_b = b"ORIGINAL_UPLOAD_SENTINEL_WINONLY"
    job_b, patch_b = _setup_job(
        "f13c20200002",
        {"fileName": rf"C:\Users\Player\{canonical_name}"},
        sentinel_b,
    )
    res_b = build_full_xapk(job_b, patch_b, None, None)
    assert (job_b / canonical_name).read_bytes() == sentinel_b
    assert res_b["fileName"] != canonical_name
    assert len(res_b["fileName"]) <= 120
    assert res_b["fileName"].endswith("_RetroDroid_Full_Signed.xapk")

    # Case C: Non-colliding fileName but sanitizedFileName matches canonical output
    sentinel_c = b"ORIGINAL_UPLOAD_SENTINEL_SANONLY"
    job_c, patch_c = _setup_job(
        "f13c20200003",
        {
            "fileName": r"C:\Users\Player\other_display_name.xapk",
            "sanitizedFileName": canonical_name,
        },
        sentinel_c,
    )
    res_c = build_full_xapk(job_c, patch_c, None, None)
    assert (job_c / canonical_name).read_bytes() == sentinel_c
    assert res_c["fileName"] != canonical_name
    assert len(res_c["fileName"]) <= 120
    assert res_c["fileName"].endswith("_RetroDroid_Full_Signed.xapk")

    # Case D: Windows path fileName with spaces whose sanitize_filename collides with canonical output
    sentinel_d = b"ORIGINAL_UPLOAD_SENTINEL_SPACES"
    job_d, patch_d = _setup_job(
        "f13c20200004",
        {"fileName": rf"C:\Users\Player\{pkg} RetroDroid Full Signed.xapk"},
        sentinel_d,
    )
    res_d = build_full_xapk(job_d, patch_d, None, None)
    assert (job_d / canonical_name).read_bytes() == sentinel_d
    assert res_d["fileName"] != canonical_name
    assert len(res_d["fileName"]) <= 120
    assert res_d["fileName"].endswith("_RetroDroid_Full_Signed.xapk")

    # Case E: Non-colliding upload_meta.json keeps repeated builds 100% idempotent
    job_e, patch_e = _setup_job(
        "f13c20200005",
        {
            "fileName": r"C:\Games\game_src.apk",
            "sanitizedFileName": "game_src.apk",
        },
        None,
    )
    res_e1 = build_full_xapk(job_e, patch_e, None, None)
    res_e2 = build_full_xapk(job_e, patch_e, None, None)
    assert res_e1["fileName"] == canonical_name
    assert res_e2["fileName"] == canonical_name
    assert sorted(p.name for p in job_e.glob("*_RetroDroid_Full_Signed.xapk")) == [canonical_name]
