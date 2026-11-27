"""Hardened binary Android XML (AXML) parser and in-place targetSdkVersion patcher."""

from __future__ import annotations

import struct
from typing import Any

# AOSP ResourceTypes.h chunk types
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# android.R.attr resource IDs
ATTR_MIN_SDK = 0x0101020C
ATTR_TARGET_SDK = 0x01010270

# Res_value dataType constants
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 1 << 8  # 0x0100
ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"
NO_INDEX = 0xFFFFFFFF


class _AXMLStringPool:
    """Bounds-checked lazy O(1) decoder for AXML RES_STRING_POOL_TYPE (UTF-8 & UTF-16LE)."""

    def __init__(self, buf: bytes | bytearray, chunk_pos: int, chdr: int, csize: int) -> None:
        chunk_end = chunk_pos + csize
        if chdr < 28 or chunk_pos + chdr > chunk_end:
            raise ValueError("AXML StringPool başlık boyutu geçersiz")

        string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<5I",
            buf,
            chunk_pos + 8,
        )
        max_offsets = (csize - chdr) // 4
        if (
            string_count > max_offsets
            or style_count > max_offsets
            or string_count + style_count > max_offsets
        ):
            raise ValueError("AXML StringPool dizin tablosu boyutu chunk sınırlarını aşıyor")

        offsets_start = chunk_pos + chdr
        offsets_end = offsets_start + (string_count + style_count) * 4

        if string_count > 0:
            if strings_start < chdr or chunk_pos + strings_start < offsets_end:
                raise ValueError("AXML StringPool stringsStart geçersiz")
            if chunk_pos + strings_start > chunk_end:
                raise ValueError("AXML StringPool stringsStart chunk sınırını aşıyor")

        strings_abs = chunk_pos + strings_start
        if style_count > 0 and strings_start < styles_start <= csize:
            data_end = chunk_pos + styles_start
        else:
            data_end = chunk_end

        self._buf = buf
        self.string_count = string_count
        self.is_utf8 = bool(flags & UTF8_FLAG)
        self._offsets_start = offsets_start
        self._strings_abs = strings_abs
        self._data_end = data_end
        self._cache: dict[int, str | None] = {}

    def get(self, idx: int) -> str | None:
        if idx < 0 or idx >= self.string_count:
            return None
        if idx in self._cache:
            return self._cache[idx]

        rel = struct.unpack_from("<I", self._buf, self._offsets_start + idx * 4)[0]
        off = self._strings_abs + rel
        if off < self._strings_abs or off >= self._data_end:
            self._cache[idx] = None
            return None

        decoded: str | None
        if self.is_utf8:
            # 1- or 2-byte UTF-16 character length prefix
            b0 = self._buf[off]
            off += 1
            if b0 & 0x80:
                if off >= self._data_end:
                    self._cache[idx] = None
                    return None
                off += 1

            # 1- or 2-byte UTF-8 byte length prefix
            if off >= self._data_end:
                self._cache[idx] = None
                return None
            b0 = self._buf[off]
            off += 1
            if b0 & 0x80:
                if off >= self._data_end:
                    self._cache[idx] = None
                    return None
                byte_len = ((b0 & 0x7F) << 8) | self._buf[off]
                off += 1
            else:
                byte_len = b0

            if off + byte_len > self._data_end:
                self._cache[idx] = None
                return None
            decoded = bytes(self._buf[off : off + byte_len]).decode("utf-8", errors="replace")
        else:
            # 1- or 2-uint16 UTF-16 code unit length prefix
            if off + 2 > self._data_end:
                self._cache[idx] = None
                return None
            u0 = struct.unpack_from("<H", self._buf, off)[0]
            off += 2
            if u0 & 0x8000:
                if off + 2 > self._data_end:
                    self._cache[idx] = None
                    return None
                u1 = struct.unpack_from("<H", self._buf, off)[0]
                off += 2
                char_len = ((u0 & 0x7FFF) << 16) | u1
            else:
                char_len = u0

            byte_len = char_len * 2
            if off + byte_len > self._data_end:
                self._cache[idx] = None
                return None
            decoded = bytes(self._buf[off : off + byte_len]).decode("utf-16le", errors="replace")

        self._cache[idx] = decoded
        return decoded


def _make_result(
    *,
    patched: bool,
    data: bytes,
    old_min: int | None = None,
    old_target: int | None = None,
    new_target: int | None = None,
    effective_target: int | None = None,
    skipped_downgrade: bool = False,
    reason: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "patched": patched,
        "data": data,
        "oldMinSdk": old_min,
        "oldTargetSdk": old_target,
        "newTargetSdk": new_target,
        "effectiveTargetSdk": effective_target,
        "skippedDowngrade": skipped_downgrade,
        "reason": reason,
        "error": error,
    }


def patch_binary_axml_target_sdk(
    axml_bytes: bytes,
    new_target_sdk: int,
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    """Safely patch android:targetSdkVersion inside <uses-sdk> of a binary AndroidManifest.xml.

    Never raises struct.error or IndexError on malformed/corrupt binary input; always returns
    a 9-key dictionary containing ``patched``, ``data``, ``oldMinSdk``, ``oldTargetSdk``,
    ``newTargetSdk``, ``effectiveTargetSdk``, ``skippedDowngrade``, ``reason``, and ``error``.
    """
    if not isinstance(axml_bytes, (bytes, bytearray, memoryview)):
        err = "AXML verisi bayt dizisi (bytes) olmalıdır."
        return _make_result(patched=False, data=b"", reason=err, error=err)

    raw_bytes = bytes(axml_bytes)

    if isinstance(new_target_sdk, bool) or not isinstance(new_target_sdk, int):
        err = "Hedef targetSdkVersion geçerli bir tam sayı olmalıdır."
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    if new_target_sdk < 1 or new_target_sdk > 0x7FFFFFFF:
        err = f"Hedef targetSdkVersion geçerli aralık dışında: {new_target_sdk}"
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    n = len(raw_bytes)
    if n < 8:
        err = "AXML dosyası çok kısa (< 8 bayt)."
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    buf = bytearray(raw_bytes)
    ftype, fhdr, fsize = struct.unpack_from("<HHI", buf, 0)
    if ftype != RES_XML_TYPE:
        err = f"Geçersiz AXML dosya başlığı (tip=0x{ftype:04x})."
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    if fhdr < 8 or fhdr > n:
        err = f"Geçersiz AXML başlık boyutu (fhdr={fhdr}, boyut={n})."
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    if fsize < fhdr or fsize > n:
        err = f"Bozuk veya kesik AXML boyutu (fsize={fsize}, gerçek={n})."
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    end = fsize
    pos = fhdr
    string_pool: _AXMLStringPool | None = None
    res_map: list[int] = []

    found_uses_sdk = False
    patched = False
    old_min: int | None = None
    old_target: int | None = None
    new_target: int | None = None
    effective_target: int | None = None
    skipped_downgrade = False
    reason: str | None = None

    while pos + 8 <= end:
        ctype, chdr, csize = struct.unpack_from("<HHI", buf, pos)
        if csize < 8 or chdr < 8 or chdr > csize or pos + csize > end:
            err = (
                f"Bozuk AXML chunk sınırları (pos={pos}, type=0x{ctype:04x}, "
                f"chdr={chdr}, csize={csize})."
            )
            return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

        chunk_end = pos + csize

        if ctype == RES_STRING_POOL_TYPE and string_pool is None:
            try:
                string_pool = _AXMLStringPool(buf, pos, chdr, csize)
            except ValueError as exc:
                err = str(exc)
                return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            count = (csize - chdr) // 4
            if count > 0:
                res_map = list(struct.unpack_from(f"<{count}I", buf, pos + chdr))
            else:
                res_map = []

        elif ctype == RES_XML_START_ELEMENT_TYPE:
            ext_off = pos + chdr
            if chdr < 16 or ext_off + 20 > chunk_end:
                err = f"Bozuk START_ELEMENT chunk başlığı (pos={pos})."
                return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

            ns_idx, name_idx, attr_start, attr_size, attr_count, _, _, _ = struct.unpack_from(
                "<IIHHHHHH",
                buf,
                ext_off,
            )
            if attr_start < 20:
                err = f"Bozuk START_ELEMENT attributeStart ({attr_start} < 20)."
                return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

            if attr_count > 0:
                if attr_size < 20:
                    err = f"Bozuk START_ELEMENT attributeSize ({attr_size} < 20)."
                    return _make_result(patched=False, data=raw_bytes, reason=err, error=err)
                attrs_base = ext_off + attr_start
                if attrs_base + attr_count * attr_size > chunk_end:
                    err = "START_ELEMENT öznitelik tablosu chunk sınırını aşıyor."
                    return _make_result(patched=False, data=raw_bytes, reason=err, error=err)
            else:
                attrs_base = ext_off + attr_start

            if string_pool is None:
                err = "AXML StringPool eksik (etiket adı doğrulanamadı)."
                return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

            tag_name = string_pool.get(name_idx)
            tag_ns_ok = ns_idx == NO_INDEX or string_pool.get(ns_idx) == ""

            if tag_name == "uses-sdk" and tag_ns_ok and not found_uses_sdk:
                found_uses_sdk = True
                elem_min: int | None = None
                target_attr: tuple[int, int, int] | None = None

                # Pass 1: inspect all <uses-sdk> attributes before mutating bytes
                for idx in range(attr_count):
                    a_off = attrs_base + idx * attr_size
                    a_ns, a_name, _raw_val, val_size, _val_res0, val_type, val_data = (
                        struct.unpack_from("<IIIHBBI", buf, a_off)
                    )
                    if val_size < 8:
                        err = f"Bozuk Res_value boyutu ({val_size} < 8) <uses-sdk> içinde."
                        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

                    if a_ns != NO_INDEX:
                        attr_ns = string_pool.get(a_ns)
                        if attr_ns != ANDROID_NS_URI:
                            continue

                    res_id = res_map[a_name] if 0 <= a_name < len(res_map) else 0
                    if res_id == ATTR_MIN_SDK:
                        if val_type in (TYPE_INT_DEC, TYPE_INT_HEX) and 1 <= val_data <= 0x7FFFFFFF:
                            elem_min = val_data
                        else:
                            elem_min = None
                    elif res_id == ATTR_TARGET_SDK:
                        target_attr = (a_off, val_type, val_data)

                old_min = elem_min

                # Pass 2: decide upgrade / floor clamp / downgrade skip
                if target_attr is None:
                    reason = "<uses-sdk> içinde android:targetSdkVersion özniteliği bulunamadı."
                else:
                    t_off, t_type, t_data = target_attr
                    if t_type not in (TYPE_INT_DEC, TYPE_INT_HEX):
                        old_target = None
                        if t_type == TYPE_STRING:
                            str_val = string_pool.get(t_data)
                            reason = (
                                f"targetSdkVersion metin türünde ({str_val!r}); "
                                "Binary AXML yaması uygulanamadı."
                            )
                        elif t_type == TYPE_REFERENCE:
                            reason = (
                                f"targetSdkVersion kaynak referansı türünde (0x{t_data:08x}); "
                                "Binary AXML yaması uygulanamadı."
                            )
                        else:
                            reason = (
                                f"targetSdkVersion desteklenmeyen değer türünde (0x{t_type:02x}); "
                                "Binary AXML yaması uygulanamadı."
                            )
                    elif not (1 <= t_data <= 0x7FFFFFFF):
                        old_target = None
                        reason = (
                            f"targetSdkVersion geçerli pozitif tam sayı aralığında değil (0x{t_data:08x}); "
                            "Binary AXML yaması uygulanamadı."
                        )
                    else:
                        old_target = t_data
                        eff = max(new_target_sdk, elem_min) if elem_min is not None else new_target_sdk
                        if not allow_downgrade and old_target > new_target_sdk and old_target >= eff:
                            skipped_downgrade = True
                            new_target = old_target
                            effective_target = old_target
                            reason = (
                                f"Mevcut targetSdkVersion ({old_target}) hedeflenen değerden "
                                f"({new_target_sdk}) yüksek; düşürme atlandı."
                            )
                        elif old_target == eff:
                            # Already at the exact effective target; mark patched=True so callers
                            # do not wastefully fall through to apktool.
                            if t_type != TYPE_INT_DEC:
                                struct.pack_into("<IHBBI", buf, t_off + 8, NO_INDEX, 8, 0, TYPE_INT_DEC, eff)
                            patched = True
                            new_target = eff
                            effective_target = eff
                            skipped_downgrade = False
                            if elem_min is not None and eff > new_target_sdk:
                                reason = (
                                    f"minSdkVersion ({elem_min}) tabanı nedeniyle "
                                    f"targetSdkVersion {eff} olarak korundu."
                                )
                        else:
                            struct.pack_into("<IHBBI", buf, t_off + 8, NO_INDEX, 8, 0, TYPE_INT_DEC, eff)
                            patched = True
                            new_target = eff
                            effective_target = eff
                            skipped_downgrade = False
                            if elem_min is not None and eff > new_target_sdk:
                                reason = (
                                    f"minSdkVersion ({elem_min}) tabanı nedeniyle "
                                    f"hedef SDK {eff} olarak ayarlandı."
                                )

        pos += csize

    if pos != end:
        err = f"AXML sonunda kesik veri tespit edildi (pos={pos}, end={end})."
        return _make_result(patched=False, data=raw_bytes, reason=err, error=err)

    if not found_uses_sdk:
        reason = "<uses-sdk> etiketi bulunamadı."

    return _make_result(
        patched=patched,
        data=bytes(buf) if patched else raw_bytes,
        old_min=old_min,
        old_target=old_target,
        new_target=new_target,
        effective_target=effective_target,
        skipped_downgrade=skipped_downgrade,
        reason=reason,
        error=None,
    )
