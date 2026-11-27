"""Real Android toolchain synthetic APK/XAPK/APKM/APKS/ZIP/ELF16K fixture builders for E2E tests.

All APK fixtures are compiled on-the-fly using real ``aapt`` against ``framework-res.apk`` and
optionally signed with real ``keytool``/``apksigner`` so every opaque-box E2E test exercises
genuine Android binaries rather than mocked stubs.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FRAMEWORK_RES = Path("/usr/share/android-framework-res/framework-res.apk")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def make_minimal_png(width: int = 2, height: int = 2) -> bytes:
    """Return a valid minimal RGBA PNG image."""

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    row = b"\x00" + (b"\x10\xb9\x81\xff" * width)
    idat = zlib.compress(row * height)
    return PNG_MAGIC + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def make_minimal_dex(version: str = "035", method_count: int = 32, class_count: int = 5) -> bytes:
    """Return a minimal valid DEX header matching Android dex magic + checksums."""
    buf = bytearray(112)
    buf[0:8] = f"dex\n{version}\x00".encode("ascii")
    struct.pack_into("<I", buf, 32, 112)
    struct.pack_into("<I", buf, 36, 112)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<I", buf, 88, method_count)
    struct.pack_into("<I", buf, 96, class_count)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def make_elf64_so(p_align: int = 16384, num_load_segments: int = 2) -> bytes:
    """Build a valid little-endian ELF64 shared library header with configurable PT_LOAD alignment."""
    ehdr_size = 64
    phdr_size = 56
    buf = bytearray(ehdr_size + phdr_size * num_load_segments + 64)
    # e_ident: magic, ELFCLASS64(2), ELFDATA2LSB(1), EV_CURRENT(1)
    buf[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    # e_type=ET_DYN(3), e_machine=EM_AARCH64(183), e_version=1
    struct.pack_into("<HHI", buf, 16, 3, 183, 1)
    # e_entry=0, e_phoff=64, e_shoff=0
    struct.pack_into("<QQQ", buf, 24, 0, ehdr_size, 0)
    # e_flags=0, e_ehsize=64, e_phentsize=56, e_phnum=num_load_segments, e_shentsize=0, e_shnum=0, e_shstrndx=0
    struct.pack_into("<IHHHHHH", buf, 48, 0, ehdr_size, phdr_size, num_load_segments, 0, 0, 0)
    for idx in range(num_load_segments):
        off = ehdr_size + idx * phdr_size
        # p_type=PT_LOAD(1), p_flags=PF_R|PF_X(5) or PF_R|PF_W(6)
        p_flags = 5 if idx == 0 else 6
        p_offset = 0 if idx == 0 else 0x1000
        p_vaddr = 0 if idx == 0 else 0x1000
        struct.pack_into(
            "<IIQQQQQQ",
            buf,
            off,
            1,  # p_type = PT_LOAD
            p_flags,
            p_offset,
            p_vaddr,
            p_vaddr,
            0x200,
            0x200,
            p_align,
        )
    return bytes(buf)


def make_elf32_so(p_align: int = 4096) -> bytes:
    """Build a minimal valid little-endian ELF32 shared library header (armeabi-v7a)."""
    ehdr_size = 52
    phdr_size = 32
    buf = bytearray(ehdr_size + phdr_size + 32)
    buf[0:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHI", buf, 16, 3, 40, 1)  # ET_DYN, EM_ARM
    struct.pack_into("<III", buf, 24, 0, ehdr_size, 0)
    struct.pack_into("<IHHHHHH", buf, 36, 0, ehdr_size, phdr_size, 1, 0, 0, 0)
    struct.pack_into("<IIIIIIII", buf, ehdr_size, 1, 0, 0, 0, 0x100, 0x100, 5, p_align)
    return bytes(buf)


def build_real_apk(
    out_path: Path,
    *,
    package: str = "com.retro.legacy",
    label: str = "Retro's Quest",
    version_code: int = 10,
    version_name: str = "1.2.3",
    min_sdk: int | None = 19,
    target_sdk: int | None = 21,
    include_unexported: bool = True,
    split_name: str | None = None,
    extra_entries: dict[str, tuple[bytes, int]] | None = None,
    compress_arsc: bool = False,
    pre_1980_entry: bool = False,
    add_duplicate_entry: bool = False,
    add_fake_meta_inf: bool = False,
    dex_count: int = 1,
    nested_fake_dex: bool = False,
    permissions: tuple[str, ...] = (
        "android.permission.INTERNET",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ),
) -> Path:
    """Compile a genuine APK with ``aapt package`` and assemble custom ZIP payloads."""
    build_dir = out_path.parent / f"_build_{out_path.stem}_{os.getpid()}_{time.time_ns()}"
    res_dir = build_dir / "res" / "drawable"
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / "icon.png").write_bytes(make_minimal_png())

    split_attr = f' split="{split_name}"' if split_name else ""
    safe_label = (
        label.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    if include_unexported:
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

    uses_sdk_attrs: list[str] = []
    if min_sdk is not None:
        uses_sdk_attrs.append(f'android:minSdkVersion="{min_sdk}"')
    if target_sdk is not None:
        uses_sdk_attrs.append(f'android:targetSdkVersion="{target_sdk}"')
    uses_sdk_line = f"    <uses-sdk {' '.join(uses_sdk_attrs)} />" if uses_sdk_attrs else ""

    perm_lines = "\n".join(f'    <uses-permission android:name="{perm}" />' for perm in permissions)
    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}"{split_attr}>
{uses_sdk_line}
{perm_lines}
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
    if res.returncode != 0:
        raise RuntimeError(f"aapt package failed: {res.stderr}\n{res.stdout}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(raw_apk, "r") as zin, zipfile.ZipFile(out_path, "w") as zout:
        for item in zin.infolist():
            info = zipfile.ZipInfo(item.filename)
            info.date_time = item.date_time
            if item.filename == "resources.arsc":
                info.compress_type = zipfile.ZIP_DEFLATED if compress_arsc else zipfile.ZIP_STORED
            else:
                info.compress_type = item.compress_type
            zout.writestr(info, zin.read(item.filename))

        for idx in range(dex_count):
            dex_name = "classes.dex" if idx == 0 else f"classes{idx + 1}.dex"
            dex_info = zipfile.ZipInfo(dex_name, date_time=(2024, 1, 1, 0, 0, 0))
            dex_info.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(dex_info, make_minimal_dex(method_count=32 + idx * 10))

        if nested_fake_dex:
            nested_info = zipfile.ZipInfo("assets/classes9.dex", date_time=(2024, 1, 1, 0, 0, 0))
            nested_info.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(nested_info, make_minimal_dex())

        if extra_entries:
            for name, (data, ctype) in extra_entries.items():
                zinfo = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
                zinfo.compress_type = ctype
                zout.writestr(zinfo, data)

        if pre_1980_entry:
            # Write raw DOS date 0x0021 (1980-01-01) then test standard valid file or clamp path
            old_info = zipfile.ZipInfo("assets/old_asset.txt", date_time=(1980, 1, 1, 0, 0, 0))
            old_info.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(old_info, b"legacy-1980-asset")

        if add_duplicate_entry:
            dup_info1 = zipfile.ZipInfo("assets/dup.txt", date_time=(2024, 1, 1, 0, 0, 0))
            dup_info1.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(dup_info1, b"first-copy")
            dup_info2 = zipfile.ZipInfo("assets/dup.txt", date_time=(2024, 1, 1, 0, 0, 0))
            dup_info2.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(dup_info2, b"second-copy")

        if add_fake_meta_inf:
            for meta_name, payload in (
                ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n"),
                ("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n"),
                ("META-INF/CERT.RSA", b"FAKE_PKCS7"),
                ("meta-inf/stamp-cert-sha256", b"0" * 64),
            ):
                minfo = zipfile.ZipInfo(meta_name, date_time=(2024, 1, 1, 0, 0, 0))
                minfo.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(minfo, payload)

    shutil.rmtree(build_dir, ignore_errors=True)
    return out_path


def sign_apk_with_temp_keystore(apk_path: Path, out_path: Path, work_dir: Path) -> Path:
    """Sign an APK using a freshly generated RSA-2048 keystore via real keytool + apksigner."""
    ks_path = work_dir / "_fixture_sign.jks"
    ks_pass = "FixturePass123!"
    env = os.environ.copy()
    env["FIXTURE_KS_PASS"] = ks_pass
    if not ks_path.exists():
        res = subprocess.run(
            [
                "keytool",
                "-genkeypair",
                "-v",
                "-keystore",
                str(ks_path),
                "-alias",
                "fixturekey",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "365",
                "-dname",
                "CN=RetroDroid E2E Fixture, O=RetroDroid, C=TR",
                "-storepass:env",
                "FIXTURE_KS_PASS",
                "-keypass:env",
                "FIXTURE_KS_PASS",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"keytool failed: {res.stderr}")
    res_sign = subprocess.run(
        [
            "apksigner",
            "sign",
            "--ks",
            str(ks_path),
            "--ks-key-alias",
            "fixturekey",
            "--ks-pass",
            "env:FIXTURE_KS_PASS",
            "--key-pass",
            "env:FIXTURE_KS_PASS",
            "--out",
            str(out_path),
            str(apk_path),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if res_sign.returncode != 0:
        raise RuntimeError(f"apksigner sign failed: {res_sign.stderr}")
    return out_path


def build_xapk_container(
    out_path: Path,
    *,
    base_apk: Path,
    split_apks: list[tuple[str, Path]] | None = None,
    obb_entries: list[tuple[str, bytes]] | None = None,
    package: str = "com.retro.xapkgame",
    name: str = "Retro XAPK Adventure",
    version_code: int = 42,
    version_name: str = "2.1.0",
    use_backslashes: bool = False,
) -> Path:
    """Create a spec-compliant XAPK v2 container with manifest.json, splits, OBBs, and icon.png."""
    split_list: list[dict[str, str]] = [{"id": "base", "file": base_apk.name}]
    for split_id, sp in split_apks or []:
        split_list.append({"id": split_id, "file": sp.name})

    expansions: list[dict[str, str]] = []
    for rel_path, _ in obb_entries or []:
        expansions.append(
            {
                "file": rel_path.replace("/", "\\") if use_backslashes else rel_path,
                "install_location": "EXTERNAL_STORAGE",
                "install_path": rel_path,
            }
        )

    manifest = {
        "xapk_version": 2,
        "package_name": package,
        "name": name,
        "version_code": str(version_code),
        "version_name": version_name,
        "split_apks": split_list,
        "expansions": expansions,
    }
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2).encode("utf-8"))
        zf.writestr("icon.png", make_minimal_png(4, 4))
        zf.write(base_apk, arcname=base_apk.name)
        for _, sp in split_apks or []:
            zf.write(sp, arcname=sp.name)
        for rel_path, data in obb_entries or []:
            arc = rel_path.replace("/", "\\") if use_backslashes else rel_path
            zf.writestr(arc, data)
    return out_path


def build_apkm_container(
    out_path: Path,
    *,
    base_apk: Path,
    split_apks: list[Path],
    package: str = "com.retro.apkmgame",
) -> Path:
    """Create a realistic APKM container with info.json + base.apk + split APKs."""
    info = {
        "pname": package,
        "release_version": "3.0.1",
        "arches": ["arm64-v8a", "armeabi-v7a"],
    }
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("info.json", json.dumps(info).encode("utf-8"))
        zf.write(base_apk, arcname="base.apk")
        for sp in split_apks:
            zf.write(sp, arcname=sp.name)
    return out_path


def build_apks_bundle(out_path: Path, *, base_apk: Path, split_apks: list[Path]) -> Path:
    """Create a standard APKS split bundle."""
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.write(base_apk, arcname="splits/base-master.apk")
        for sp in split_apks:
            zf.write(sp, arcname=f"splits/{sp.name}")
    return out_path


def build_plain_zip_container(
    out_path: Path,
    *,
    base_apk: Path,
    obb_entries: list[tuple[str, bytes]] | None = None,
    use_backslashes: bool = False,
) -> Path:
    """Create a plain ZIP archive containing an APK and optional OBB files."""
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        apk_arc = f"game\\{base_apk.name}" if use_backslashes else f"game/{base_apk.name}"
        zf.write(base_apk, arcname=apk_arc)
        for rel_path, data in obb_entries or []:
            arc = rel_path.replace("/", "\\") if use_backslashes else rel_path
            zf.writestr(arc, data)
    return out_path


def build_zip_slip_archive(out_path: Path, inner_apk: Path) -> Path:
    """Create a hostile ZIP container with path traversal member names."""
    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("../../escaped_payload.apk", inner_apk.read_bytes())
    return out_path


def build_encrypted_zip_archive(out_path: Path) -> Path:
    """Create a ZIP file with general purpose encryption flag bit (0x1) set."""
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("base.apk", b"fake-encrypted-payload")
    raw = bytearray(out_path.read_bytes())
    # Set bit 0 of GP bit flag in LFH (offset 6) and CDH (find PK\x01\x02)
    raw[6] |= 0x01
    cdh_pos = raw.find(b"PK\x01\x02")
    assert cdh_pos > 0
    raw[cdh_pos + 8] |= 0x01
    out_path.write_bytes(bytes(raw))
    return out_path


def build_corrupt_axml_apk(out_path: Path) -> Path:
    """Create a ZIP containing truncated/corrupt binary AndroidManifest.xml."""
    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00\xff\xff\xff\x7f\x01\x00")
        zf.writestr("classes.dex", make_minimal_dex())
    return out_path


def build_missing_manifest_zip(out_path: Path) -> Path:
    """Create a valid ZIP file that does NOT contain AndroidManifest.xml."""
    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("README.txt", b"Not an APK at all")
    return out_path


def build_duplicate_apk_container(out_path: Path, apk_bytes: bytes) -> Path:
    """Create a ZIP container with two different directories holding identical APK basenames."""
    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("dirA/same_name.apk", apk_bytes)
        zf.writestr("dirB/same_name.apk", apk_bytes)
    return out_path


# ---------------------------------------------------------------------------
# Real CLI Artifact Verifiers (used by E2E Tiers 1–4)
# ---------------------------------------------------------------------------


def verify_apk_with_aapt(apk_path: Path) -> dict[str, Any]:
    """Run ``aapt dump badging`` and return parsed package/version/sdk/label fields."""
    res = subprocess.run(
        ["aapt", "dump", "badging", str(apk_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if res.returncode != 0:
        raise AssertionError(f"aapt dump badging failed ({res.returncode}): {res.stderr}")
    text = res.stdout
    out: dict[str, Any] = {"raw": text}
    for line in text.splitlines():
        if line.startswith("package:"):
            for key in ("name", "versionCode", "versionName"):
                marker = f"{key}='"
                if marker in line:
                    start = line.index(marker) + len(marker)
                    end = line.index("'", start)
                    out[key] = line[start:end]
        elif line.startswith("sdkVersion:'"):
            out["minSdk"] = int(line.split("'")[1])
        elif line.startswith("targetSdkVersion:'"):
            out["targetSdk"] = int(line.split("'")[1])
        elif line.startswith("application-label:'"):
            out["label"] = line[len("application-label:'") : -1]
    return out


def verify_apk_xmltree(apk_path: Path) -> str:
    """Run ``aapt dump xmltree <apk> AndroidManifest.xml`` and return stdout."""
    res = subprocess.run(
        ["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if res.returncode != 0:
        raise AssertionError(f"aapt dump xmltree failed: {res.stderr}")
    return res.stdout


def verify_apk_with_zipalign(apk_path: Path, page_16k: bool = False) -> tuple[bool, str]:
    """Run ``zipalign -c`` against an output APK and return ``(ok, output)``."""
    cmd = ["zipalign", "-c", "-P", "16", "4", str(apk_path)] if page_16k else ["zipalign", "-c", "-p", "4", str(apk_path)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    return res.returncode == 0, (res.stdout + "\n" + res.stderr).strip()


def verify_apk_with_apksigner(apk_path: Path) -> tuple[bool, str]:
    """Run ``apksigner verify --verbose --print-certs`` and return ``(ok, output)``."""
    res = subprocess.run(
        ["apksigner", "verify", "--verbose", "--print-certs", str(apk_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return res.returncode == 0, (res.stdout + "\n" + res.stderr).strip()


# ---------------------------------------------------------------------------
# Session-Cached Fixture Corpus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class E2ECorpus:
    """Immutable paths to all session-cached genuine synthetic Android fixtures."""

    root: Path
    legacy_apk: Path
    legacy_signed_apk: Path
    api31_unexported_apk: Path
    high_target_apk: Path
    no_uses_sdk_apk: Path
    elf16k_apk: Path
    elf4k_apk: Path
    arm32_only_apk: Path
    compressed_arsc_apk: Path
    multidex_apk: Path
    xss_label_apk: Path
    split_arm64_apk: Path
    split_arm32_apk: Path
    xapk_v2: Path
    xapk_backslash: Path
    apkm_bundle: Path
    apks_bundle: Path
    plain_zip_container: Path
    plain_zip_backslash: Path
    obb_main: Path
    obb_patch: Path
    obb_bad_name: Path
    corrupt_axml_apk: Path
    zip_slip_xapk: Path
    encrypted_zip: Path
    missing_manifest_apk: Path
    duplicate_apk_zip: Path
    garbage_apk: Path
    empty_apk: Path


def build_e2e_corpus(root: Path) -> E2ECorpus:
    """Build all real-toolchain E2E fixtures once per pytest session under ``root``."""
    root.mkdir(parents=True, exist_ok=True)

    legacy_apk = build_real_apk(
        root / "legacy_game.apk",
        package="com.retro.legacy",
        label="Retro's Legacy Quest",
        version_code=10,
        version_name="1.2.3",
        min_sdk=19,
        target_sdk=21,
        include_unexported=True,
        extra_entries={
            "lib/arm64-v8a/libgame.so": (make_elf64_so(16384), zipfile.ZIP_STORED),
        },
    )
    legacy_signed_apk = sign_apk_with_temp_keystore(legacy_apk, root / "legacy_signed.apk", root)

    api31_unexported_apk = build_real_apk(
        root / "api31_unexported.apk",
        package="com.retro.unexported",
        label="Unexported Action",
        version_code=15,
        version_name="1.5.0",
        min_sdk=24,
        target_sdk=30,
        include_unexported=True,
    )

    high_target_apk = build_real_apk(
        root / "high_target34.apk",
        package="com.retro.modern34",
        label="Modern Target 34",
        version_code=34,
        version_name="3.4.0",
        min_sdk=24,
        target_sdk=34,
        include_unexported=False,
    )

    no_uses_sdk_apk = build_real_apk(
        root / "no_uses_sdk.apk",
        package="com.retro.nosdk",
        label="No UsesSdk App",
        version_code=5,
        version_name="0.5.0",
        min_sdk=None,
        target_sdk=None,
        include_unexported=False,
    )

    elf16k_apk = build_real_apk(
        root / "elf16k_aligned.apk",
        package="com.retro.elf16k",
        label="ELF 16KB Ready",
        version_code=20,
        version_name="2.0.0",
        min_sdk=24,
        target_sdk=28,
        include_unexported=False,
        extra_entries={
            "lib/arm64-v8a/libengine16k.so": (make_elf64_so(16384), zipfile.ZIP_STORED),
        },
    )

    elf4k_apk = build_real_apk(
        root / "elf4k_unaligned.apk",
        package="com.retro.elf4k",
        label="ELF 4KB Legacy",
        version_code=21,
        version_name="2.1.0",
        min_sdk=24,
        target_sdk=28,
        include_unexported=False,
        extra_entries={
            "lib/arm64-v8a/libengine4k.so": (make_elf64_so(4096), zipfile.ZIP_STORED),
        },
    )

    arm32_only_apk = build_real_apk(
        root / "arm32_only.apk",
        package="com.retro.arm32",
        label="ARM32 Classic",
        version_code=7,
        version_name="1.0.7",
        min_sdk=16,
        target_sdk=22,
        include_unexported=False,
        extra_entries={
            "lib/armeabi-v7a/libold32.so": (make_elf32_so(4096), zipfile.ZIP_STORED),
        },
    )

    compressed_arsc_apk = build_real_apk(
        root / "compressed_arsc_dirty.apk",
        package="com.retro.dirty",
        label="Dirty Archive APK",
        version_code=8,
        version_name="1.0.8",
        min_sdk=21,
        target_sdk=26,
        include_unexported=False,
        compress_arsc=True,
        pre_1980_entry=True,
        add_duplicate_entry=False,
        add_fake_meta_inf=True,
        extra_entries={
            "lib/arm64-v8a/libcompressed.so": (make_elf64_so(16384), zipfile.ZIP_DEFLATED),
        },
    )

    multidex_apk = build_real_apk(
        root / "multidex_game.apk",
        package="com.retro.multidex",
        label="MultiDEX Adventure",
        version_code=12,
        version_name="1.2.0",
        min_sdk=21,
        target_sdk=28,
        include_unexported=False,
        dex_count=3,
        nested_fake_dex=True,
    )

    xss_label_apk = build_real_apk(
        root / "xss_label_game.apk",
        package="com.retro.xsstest",
        label='<img src=x onerror="window.__XSS_FIRED=1">XSS Game',
        version_code=9,
        version_name="1.0.9",
        min_sdk=21,
        target_sdk=23,
        include_unexported=True,
    )

    split_arm64_apk = build_real_apk(
        root / "config.arm64_v8a.apk",
        package="com.retro.xapkgame",
        label="Split ARM64",
        version_code=42,
        version_name="2.1.0",
        min_sdk=21,
        target_sdk=23,
        include_unexported=False,
        split_name="config.arm64_v8a",
        extra_entries={
            "lib/arm64-v8a/libsplit64.so": (make_elf64_so(16384), zipfile.ZIP_STORED),
        },
    )

    split_arm32_apk = build_real_apk(
        root / "config.armeabi_v7a.apk",
        package="com.retro.xapkgame",
        label="Split ARM32",
        version_code=42,
        version_name="2.1.0",
        min_sdk=21,
        target_sdk=23,
        include_unexported=False,
        split_name="config.armeabi_v7a",
        extra_entries={
            "lib/armeabi-v7a/libsplit32.so": (make_elf32_so(4096), zipfile.ZIP_STORED),
        },
    )

    xapk_base_apk = build_real_apk(
        root / "com.retro.xapkgame.apk",
        package="com.retro.xapkgame",
        label="Retro XAPK Adventure",
        version_code=42,
        version_name="2.1.0",
        min_sdk=21,
        target_sdk=23,
        include_unexported=True,
    )

    obb_payload_main = b"RETRODROID_OBB_MAIN_PAYLOAD_" + (b"0123456789ABCDEF" * 512)
    obb_payload_patch = b"RETRODROID_OBB_PATCH_PAYLOAD_" + (b"FEDCBA9876543210" * 256)

    obb_main = root / "main.10.com.retro.legacy.obb"
    obb_main.write_bytes(obb_payload_main)
    obb_patch = root / "patch.10.com.retro.legacy.obb"
    obb_patch.write_bytes(obb_payload_patch)
    obb_bad_name = root / "custom_data_pack.obb"
    obb_bad_name.write_bytes(b"CUSTOM_OBB_DATA_BYTES" * 128)

    xapk_v2 = build_xapk_container(
        root / "retro_adventure.xapk",
        base_apk=xapk_base_apk,
        split_apks=[("config.arm64_v8a", split_arm64_apk), ("config.armeabi_v7a", split_arm32_apk)],
        obb_entries=[("Android/obb/com.retro.xapkgame/main.42.com.retro.xapkgame.obb", obb_payload_main)],
        package="com.retro.xapkgame",
        name="Retro XAPK Adventure",
        version_code=42,
        version_name="2.1.0",
    )

    xapk_backslash = build_xapk_container(
        root / "retro_backslash.xapk",
        base_apk=xapk_base_apk,
        split_apks=[("config.arm64_v8a", split_arm64_apk)],
        obb_entries=[("Android/obb/com.retro.xapkgame/main.42.com.retro.xapkgame.obb", obb_payload_main)],
        package="com.retro.xapkgame",
        name="Retro Backslash XAPK",
        version_code=42,
        version_name="2.1.0",
        use_backslashes=True,
    )

    apkm_base_apk = build_real_apk(
        root / "apkm_base.apk",
        package="com.retro.apkmgame",
        label="Retro APKM Title",
        version_code=30,
        version_name="3.0.1",
        min_sdk=21,
        target_sdk=26,
        include_unexported=False,
    )
    apkm_split_apk = build_real_apk(
        root / "split_config.arm64_v8a.apk",
        package="com.retro.apkmgame",
        label="APKM Split ARM64",
        version_code=30,
        version_name="3.0.1",
        min_sdk=21,
        target_sdk=26,
        include_unexported=False,
        split_name="config.arm64_v8a",
        extra_entries={
            "lib/arm64-v8a/libapkm.so": (make_elf64_so(16384), zipfile.ZIP_STORED),
        },
    )
    apkm_bundle = build_apkm_container(
        root / "retro_mirror.apkm",
        base_apk=apkm_base_apk,
        split_apks=[apkm_split_apk],
        package="com.retro.apkmgame",
    )

    apks_bundle = build_apks_bundle(
        root / "retro_splits.apks",
        base_apk=xapk_base_apk,
        split_apks=[split_arm64_apk],
    )

    plain_zip_container = build_plain_zip_container(
        root / "retro_bundle.zip",
        base_apk=legacy_apk,
        obb_entries=[("Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb", obb_payload_main)],
    )

    plain_zip_backslash = build_plain_zip_container(
        root / "retro_win_bundle.zip",
        base_apk=legacy_apk,
        obb_entries=[("Android/obb/com.retro.legacy/main.10.com.retro.legacy.obb", obb_payload_main)],
        use_backslashes=True,
    )

    corrupt_axml_apk = build_corrupt_axml_apk(root / "corrupt_axml.apk")
    zip_slip_xapk = build_zip_slip_archive(root / "zip_slip.xapk", legacy_apk)
    encrypted_zip = build_encrypted_zip_archive(root / "encrypted.xapk")
    missing_manifest_apk = build_missing_manifest_zip(root / "no_manifest.apk")
    duplicate_apk_zip = build_duplicate_apk_container(root / "dup_apks.zip", legacy_apk.read_bytes())

    garbage_apk = root / "garbage.apk"
    garbage_apk.write_bytes(b"THIS_IS_DEFINITELY_NOT_A_ZIP_OR_APK_FILE_1234567890")
    empty_apk = root / "empty.apk"
    empty_apk.write_bytes(b"")

    return E2ECorpus(
        root=root,
        legacy_apk=legacy_apk,
        legacy_signed_apk=legacy_signed_apk,
        api31_unexported_apk=api31_unexported_apk,
        high_target_apk=high_target_apk,
        no_uses_sdk_apk=no_uses_sdk_apk,
        elf16k_apk=elf16k_apk,
        elf4k_apk=elf4k_apk,
        arm32_only_apk=arm32_only_apk,
        compressed_arsc_apk=compressed_arsc_apk,
        multidex_apk=multidex_apk,
        xss_label_apk=xss_label_apk,
        split_arm64_apk=split_arm64_apk,
        split_arm32_apk=split_arm32_apk,
        xapk_v2=xapk_v2,
        xapk_backslash=xapk_backslash,
        apkm_bundle=apkm_bundle,
        apks_bundle=apks_bundle,
        plain_zip_container=plain_zip_container,
        plain_zip_backslash=plain_zip_backslash,
        obb_main=obb_main,
        obb_patch=obb_patch,
        obb_bad_name=obb_bad_name,
        corrupt_axml_apk=corrupt_axml_apk,
        zip_slip_xapk=zip_slip_xapk,
        encrypted_zip=encrypted_zip,
        missing_manifest_apk=missing_manifest_apk,
        duplicate_apk_zip=duplicate_apk_zip,
        garbage_apk=garbage_apk,
        empty_apk=empty_apk,
    )
