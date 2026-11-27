/**
 * RetroDroid Compat v5.4.0 — Pure-JS Offline ZIP32/ZIP64 Engine (JSZip-compatible API)
 *
 * Implements PKWARE APPNOTE.TXT ZIP32 & ZIP64 archive writing and reading with:
 * - Genuine IEEE 802.3 CRC-32 (0xEDB88320) with chunked Blob/File streaming
 * - STORE (method 0, zero-copy Blob assembly) and DEFLATE (method 8 via CompressionStream)
 * - UTF-8 filename flag (bit 11 / 0x0800), DOS timestamps >= 1980-01-01, Unix file modes
 * - Strict path normalization & path-traversal rejection
 * - Full reader (`JSZip.loadAsync`) with CRC-32 verification & DEFLATE decompression
 */

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');

const ZIP_CHUNK_BYTES = 4 * 1024 * 1024; // 4 MiB streaming CRC chunks
const MAX_UINT16 = 0xffff;
const MAX_UINT32 = 0xffffffff;
const FLAG_UTF8 = 0x0800;

const SIG_LFH = 0x04034b50;
const SIG_CDH = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const EXTRA_ZIP64_ID = 0x0001;

/**
 * Compute IEEE 802.3 CRC-32 over a Uint8Array with optional running seed.
 * @param {Uint8Array} bytes
 * @param {number} [seed=0]
 * @returns {number} Unsigned 32-bit CRC-32
 */
export function crc32(bytes, seed = 0) {
  let crc = (seed ^ 0xffffffff) >>> 0;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Normalize and validate a ZIP entry path, blocking traversal and invalid chars.
 * @param {string} rawPath
 * @param {boolean} [isDir=false]
 * @returns {string}
 */
export function normalizeZipPath(rawPath, isDir = false) {
  if (typeof rawPath !== 'string') {
    throw new Error('ZIP dosya yolu metin (string) olmalıdır.');
  }
  if (rawPath.includes('\0')) {
    throw new Error('ZIP dosya yolunda NUL baytı bulunamaz.');
  }
  if (rawPath.startsWith('/') || rawPath.startsWith('\\')) {
    throw new Error(`Mutlak ZIP dosya yolu reddedildi: ${rawPath}`);
  }
  if (/^[A-Za-z]:/.test(rawPath)) {
    throw new Error(`Sürücü harfi içeren ZIP yolu reddedildi: ${rawPath}`);
  }
  const slashNorm = rawPath.replace(/\\/g, '/');
  const rawSegments = slashNorm.split('/');
  const cleanSegments = [];
  for (let i = 0; i < rawSegments.length; i++) {
    const seg = rawSegments[i];
    if (seg === '') {
      continue;
    }
    if (seg === '.' || seg === '..') {
      throw new Error(`Güvensiz ZIP dosya yolu reddedildi: ${rawPath}`);
    }
    if (/^[A-Za-z]:/.test(seg) && cleanSegments.length === 0) {
      throw new Error(`Sürücü harfi içeren ZIP yolu reddedildi: ${rawPath}`);
    }
    cleanSegments.push(seg);
  }
  if (cleanSegments.length === 0) {
    throw new Error('ZIP dosya yolu boş olamaz.');
  }
  const joined = cleanSegments.join('/');
  return isDir ? `${joined}/` : joined;
}

function encodeDosDateTime(dateInput) {
  const d = dateInput instanceof Date && !Number.isNaN(dateInput.getTime())
    ? dateInput
    : new Date();
  let year = d.getFullYear();
  let month = d.getMonth() + 1;
  let day = d.getDate();
  let hours = d.getHours();
  let minutes = d.getMinutes();
  let seconds = d.getSeconds();

  if (year < 1980) {
    year = 1980;
    month = 1;
    day = 1;
    hours = 0;
    minutes = 0;
    seconds = 0;
  } else if (year > 2107) {
    year = 2107;
    month = 12;
    day = 31;
    hours = 23;
    minutes = 59;
    seconds = 58;
  }

  const dosTime = ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | ((seconds >> 1) & 0x1f);
  const dosDate = (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f);
  return { dosTime, dosDate };
}

function decodeDosDateTime(dosDate, dosTime) {
  const year = ((dosDate >>> 9) & 0x7f) + 1980;
  const month = Math.max(1, Math.min(12, (dosDate >>> 5) & 0x0f)) - 1;
  const day = Math.max(1, Math.min(31, dosDate & 0x1f));
  const hours = (dosTime >>> 11) & 0x1f;
  const minutes = (dosTime >>> 5) & 0x3f;
  const seconds = (dosTime & 0x1f) * 2;
  return new Date(year, month, day, hours, minutes, seconds);
}

function writeUint64LE(view, offset, value) {
  const big = typeof value === 'bigint' ? value : BigInt(Math.floor(value));
  view.setBigUint64(offset, big, true);
}

function readUint64LE(view, offset) {
  return Number(view.getBigUint64(offset, true));
}

function isBlobLike(value) {
  return typeof Blob !== 'undefined' && value instanceof Blob;
}

function toUint8ArraySync(data) {
  if (data == null) return new Uint8Array(0);
  if (typeof data === 'string') return TEXT_ENCODER.encode(data);
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return null;
}

async function computeBlobCrc32(blob, onChunkProgress) {
  const total = blob.size;
  let runningCrc = 0;
  let offset = 0;
  while (offset < total) {
    const end = Math.min(total, offset + ZIP_CHUNK_BYTES);
    const buf = await blob.slice(offset, end).arrayBuffer();
    runningCrc = crc32(new Uint8Array(buf), runningCrc);
    offset = end;
    if (typeof onChunkProgress === 'function') {
      onChunkProgress(offset, total);
    }
  }
  return runningCrc >>> 0;
}

function supportsRawDeflateStream() {
  return typeof CompressionStream === 'function';
}

function supportsRawInflateStream() {
  return typeof DecompressionStream === 'function';
}

async function rawDeflateBytes(source) {
  const cs = new CompressionStream('deflate-raw');
  const blobInput = isBlobLike(source) ? source : new Blob([source]);
  const compressedStream = blobInput.stream().pipeThrough(cs);
  const outBuf = await new Response(compressedStream).arrayBuffer();
  return new Uint8Array(outBuf);
}

async function rawInflateBytes(bytes) {
  if (!supportsRawInflateStream()) {
    throw new Error('Bu ortam DEFLATE açma (DecompressionStream) desteği sunmuyor.');
  }
  const ds = new DecompressionStream('deflate-raw');
  const outBuf = await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer();
  return new Uint8Array(outBuf);
}

function concatUint8Arrays(chunks) {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

async function materializePartsToUint8Array(parts) {
  const arrays = [];
  for (const part of parts) {
    if (part instanceof Uint8Array) {
      arrays.push(part);
    } else if (isBlobLike(part)) {
      arrays.push(new Uint8Array(await part.arrayBuffer()));
    } else if (part instanceof ArrayBuffer) {
      arrays.push(new Uint8Array(part));
    } else if (ArrayBuffer.isView(part)) {
      arrays.push(new Uint8Array(part.buffer, part.byteOffset, part.byteLength));
    }
  }
  return concatUint8Arrays(arrays);
}

class ZipObject {
  constructor({
    name,
    dir = false,
    date = new Date(),
    comment = '',
    unixPermissions = null,
    compression = null,
    data = null,
    _rawCompressed = null,
    _compressionMethod = 0,
    _expectedCrc = 0,
    _uncompressedSize = 0,
  }) {
    this.name = name;
    this.dir = Boolean(dir);
    this.date = date instanceof Date ? date : new Date();
    this.comment = comment || '';
    this.unixPermissions = unixPermissions;
    this.compression = compression;
    this._data = data;
    this._rawCompressed = _rawCompressed;
    this._compressionMethod = _compressionMethod;
    this._expectedCrc = _expectedCrc >>> 0;
    this._uncompressedSize = _uncompressedSize;
  }

  async _resolveUint8Array() {
    if (this.dir) return new Uint8Array(0);

    if (this._rawCompressed !== null) {
      let decoded;
      if (this._compressionMethod === 0) {
        decoded = this._rawCompressed;
      } else if (this._compressionMethod === 8) {
        decoded = await rawInflateBytes(this._rawCompressed);
      } else {
        throw new Error(`Desteklenmeyen ZIP sıkıştırma yöntemi: ${this._compressionMethod}`);
      }
      if (decoded.byteLength !== this._uncompressedSize) {
        throw new Error(
          `ZIP girdi boyutu uyuşmuyor (${this.name}): beklenen ${this._uncompressedSize}, okunan ${decoded.byteLength}`
        );
      }
      const actualCrc = crc32(decoded);
      if (actualCrc !== this._expectedCrc) {
        throw new Error(
          `ZIP CRC-32 doğrulama hatası (${this.name}): beklenen 0x${this._expectedCrc.toString(16)}, bulunan 0x${actualCrc.toString(16)}`
        );
      }
      return decoded;
    }

    const syncBytes = toUint8ArraySync(this._data);
    if (syncBytes !== null) return syncBytes;
    if (isBlobLike(this._data)) {
      return new Uint8Array(await this._data.arrayBuffer());
    }
    return new Uint8Array(0);
  }

  async async(type = 'uint8array') {
    const bytes = await this._resolveUint8Array();
    const t = String(type || 'uint8array').toLowerCase();
    if (t === 'uint8array') return bytes;
    if (t === 'arraybuffer') {
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }
    if (t === 'string' || t === 'text') {
      return TEXT_DECODER.decode(bytes);
    }
    if (t === 'blob') {
      return new Blob([bytes], { type: 'application/octet-stream' });
    }
    throw new Error(`Desteklenmeyen çıktı türü: ${type}`);
  }
}

export class JSZip {
  constructor(prefix = '', root = null) {
    this._root = root || this;
    this._prefix = prefix;
    if (!root) {
      this.files = Object.create(null);
    } else {
      this.files = root.files;
    }
  }

  file(name, data, options = {}) {
    if (arguments.length === 1) {
      if (typeof name !== 'string') return null;
      try {
        const key = normalizeZipPath(this._prefix + name, false);
        return this._root.files[key] || null;
      } catch {
        return null;
      }
    }

    const isDir = Boolean(options && options.dir);
    const fullName = normalizeZipPath(this._prefix + name, isDir);
    const entry = new ZipObject({
      name: fullName,
      dir: isDir,
      date: options && options.date ? options.date : new Date(),
      comment: options && options.comment ? String(options.comment) : '',
      unixPermissions: options && options.unixPermissions != null ? options.unixPermissions : null,
      compression: options && options.compression ? String(options.compression).toUpperCase() : null,
      data: isDir ? new Uint8Array(0) : data,
    });
    this._root.files[fullName] = entry;
    return this;
  }

  folder(name) {
    if (typeof name !== 'string' || !name.trim()) {
      return this;
    }
    const dirPath = normalizeZipPath(this._prefix + name, true);
    if (!this._root.files[dirPath]) {
      this._root.files[dirPath] = new ZipObject({
        name: dirPath,
        dir: true,
        date: new Date(),
        data: new Uint8Array(0),
      });
    }
    return new JSZip(dirPath, this._root);
  }

  remove(name) {
    const key = normalizeZipPath(this._prefix + name, false);
    const dirPrefix = `${key}/`;
    for (const existing of Object.keys(this._root.files)) {
      if (existing === key || existing === dirPrefix || existing.startsWith(dirPrefix)) {
        delete this._root.files[existing];
      }
    }
    return this;
  }

  async generateAsync(options = {}, onUpdate = null) {
    const outType = String(options.type || 'blob').toLowerCase();
    const defaultCompression = String(options.compression || 'STORE').toUpperCase();
    const forceZip64 = Boolean(options.forceZip64);
    const entries = Object.values(this._root.files);

    const totalWorkBytes = entries.reduce((acc, entry) => {
      if (entry.dir) return acc + 1;
      if (entry._data == null && entry._rawCompressed !== null) {
        return acc + Math.max(1, entry._uncompressedSize || entry._rawCompressed.byteLength || 1);
      }
      const sync = toUint8ArraySync(entry._data);
      if (sync) return acc + Math.max(1, sync.byteLength);
      if (isBlobLike(entry._data)) return acc + Math.max(1, entry._data.size);
      return acc + 1;
    }, 0) || 1;

    let processedWorkBytes = 0;
    const emitProgress = (currentFile, extra = 0) => {
      if (typeof onUpdate !== 'function') return;
      const pct = Math.min(99, Math.max(0, ((processedWorkBytes + extra) / totalWorkBytes) * 98));
      onUpdate({ percent: Number(pct.toFixed(1)), currentFile });
    };

    const parts = [];
    const centralRecords = [];
    let currentOffset = 0;

    for (const entry of entries) {
      const nameBytes = TEXT_ENCODER.encode(entry.name);
      if (nameBytes.byteLength > MAX_UINT16) {
        throw new Error(`ZIP dosya adı çok uzun (${nameBytes.byteLength} bayt > ${MAX_UINT16} bayt sınırı).`);
      }
      const commentBytes = entry.comment ? TEXT_ENCODER.encode(entry.comment) : new Uint8Array(0);
      if (commentBytes.byteLength > MAX_UINT16) {
        throw new Error(`ZIP girdi açıklaması çok uzun (${commentBytes.byteLength} bayt > ${MAX_UINT16} bayt sınırı).`);
      }
      const { dosTime, dosDate } = encodeDosDateTime(entry.date);
      const requestedComp = entry.compression || defaultCompression;

      let method = 0;
      let uncompressedSize = 0;
      let compressedSize = 0;
      let entryCrc = 0;
      let payloadPart = new Uint8Array(0);

      if (!entry.dir) {
        const resolvedBytes = (entry._data == null && entry._rawCompressed !== null)
          ? await entry._resolveUint8Array()
          : toUint8ArraySync(entry._data);
        if (resolvedBytes !== null) {
          uncompressedSize = resolvedBytes.byteLength;
          entryCrc = crc32(resolvedBytes);
          if (requestedComp === 'DEFLATE' && uncompressedSize > 0 && supportsRawDeflateStream()) {
            const deflated = await rawDeflateBytes(resolvedBytes);
            method = 8;
            payloadPart = deflated;
            compressedSize = deflated.byteLength;
          } else {
            method = 0;
            payloadPart = resolvedBytes;
            compressedSize = uncompressedSize;
          }
          processedWorkBytes += Math.max(1, uncompressedSize);
          emitProgress(entry.name);
        } else if (isBlobLike(entry._data)) {
          const blob = entry._data;
          uncompressedSize = blob.size;
          entryCrc = await computeBlobCrc32(blob, (done) => emitProgress(entry.name, done));
          if (requestedComp === 'DEFLATE' && uncompressedSize > 0 && supportsRawDeflateStream()) {
            const deflated = await rawDeflateBytes(blob);
            method = 8;
            payloadPart = deflated;
            compressedSize = deflated.byteLength;
          } else {
            method = 0;
            payloadPart = blob;
            compressedSize = uncompressedSize;
          }
          processedWorkBytes += Math.max(1, uncompressedSize);
          emitProgress(entry.name);
        } else {
          processedWorkBytes += 1;
          emitProgress(entry.name);
        }
      } else {
        processedWorkBytes += 1;
        emitProgress(entry.name);
      }

      const lfhNeedsZip64 = forceZip64 || uncompressedSize >= MAX_UINT32 || compressedSize >= MAX_UINT32;
      const offsetNeedsZip64 = forceZip64 || currentOffset >= MAX_UINT32;
      const versionNeeded = (lfhNeedsZip64 || offsetNeedsZip64) ? 45 : 20;

      // Local File Header extra field (ZIP64 sizes if required)
      let lfhExtra = new Uint8Array(0);
      if (lfhNeedsZip64) {
        lfhExtra = new Uint8Array(20);
        const ev = new DataView(lfhExtra.buffer);
        ev.setUint16(0, EXTRA_ZIP64_ID, true);
        ev.setUint16(2, 16, true);
        writeUint64LE(ev, 4, uncompressedSize);
        writeUint64LE(ev, 12, compressedSize);
      }

      const lfh = new Uint8Array(30 + nameBytes.byteLength + lfhExtra.byteLength);
      const lv = new DataView(lfh.buffer);
      lv.setUint32(0, SIG_LFH, true);
      lv.setUint16(4, versionNeeded, true);
      lv.setUint16(6, FLAG_UTF8, true);
      lv.setUint16(8, method, true);
      lv.setUint16(10, dosTime, true);
      lv.setUint16(12, dosDate, true);
      lv.setUint32(14, entryCrc >>> 0, true);
      lv.setUint32(18, lfhNeedsZip64 ? MAX_UINT32 : compressedSize, true);
      lv.setUint32(22, lfhNeedsZip64 ? MAX_UINT32 : uncompressedSize, true);
      lv.setUint16(26, nameBytes.byteLength, true);
      lv.setUint16(28, lfhExtra.byteLength, true);
      lfh.set(nameBytes, 30);
      if (lfhExtra.byteLength > 0) lfh.set(lfhExtra, 30 + nameBytes.byteLength);

      const localHeaderOffset = currentOffset;
      parts.push(lfh);
      currentOffset += lfh.byteLength;

      if (compressedSize > 0) {
        parts.push(payloadPart);
        currentOffset += compressedSize;
      }

      // Build Central Directory Header
      const cdExtraFields = [];
      if (lfhNeedsZip64) {
        cdExtraFields.push(uncompressedSize, compressedSize);
      }
      if (offsetNeedsZip64) {
        cdExtraFields.push(localHeaderOffset);
      }
      let cdExtra = new Uint8Array(0);
      if (cdExtraFields.length > 0) {
        cdExtra = new Uint8Array(4 + cdExtraFields.length * 8);
        const cev = new DataView(cdExtra.buffer);
        cev.setUint16(0, EXTRA_ZIP64_ID, true);
        cev.setUint16(2, cdExtraFields.length * 8, true);
        for (let i = 0; i < cdExtraFields.length; i++) {
          writeUint64LE(cev, 4 + i * 8, cdExtraFields[i]);
        }
      }

      const unixMode = entry.unixPermissions != null
        ? entry.unixPermissions
        : (entry.dir ? 0o040755 : 0o100644);
      const extAttr = ((unixMode & 0xffff) << 16) | (entry.dir ? 0x10 : 0);

      const cdh = new Uint8Array(46 + nameBytes.byteLength + cdExtra.byteLength + commentBytes.byteLength);
      const cv = new DataView(cdh.buffer);
      cv.setUint32(0, SIG_CDH, true);
      cv.setUint16(4, (3 << 8) | versionNeeded, true); // Unix + version
      cv.setUint16(6, versionNeeded, true);
      cv.setUint16(8, FLAG_UTF8, true);
      cv.setUint16(10, method, true);
      cv.setUint16(12, dosTime, true);
      cv.setUint16(14, dosDate, true);
      cv.setUint32(16, entryCrc >>> 0, true);
      cv.setUint32(20, lfhNeedsZip64 ? MAX_UINT32 : compressedSize, true);
      cv.setUint32(24, lfhNeedsZip64 ? MAX_UINT32 : uncompressedSize, true);
      cv.setUint16(28, nameBytes.byteLength, true);
      cv.setUint16(30, cdExtra.byteLength, true);
      cv.setUint16(32, commentBytes.byteLength, true);
      cv.setUint16(34, 0, true); // disk number start
      cv.setUint16(36, 0, true); // internal file attrs
      cv.setUint32(38, extAttr >>> 0, true);
      cv.setUint32(42, offsetNeedsZip64 ? MAX_UINT32 : localHeaderOffset, true);
      cdh.set(nameBytes, 46);
      if (cdExtra.byteLength > 0) cdh.set(cdExtra, 46 + nameBytes.byteLength);
      if (commentBytes.byteLength > 0) cdh.set(commentBytes, 46 + nameBytes.byteLength + cdExtra.byteLength);
      centralRecords.push(cdh);
    }

    const centralOffset = currentOffset;
    let centralSize = 0;
    for (const rec of centralRecords) {
      parts.push(rec);
      centralSize += rec.byteLength;
    }

    const entryCount = centralRecords.length;
    const needsZip64Eocd = forceZip64
      || entryCount >= MAX_UINT16
      || centralSize >= MAX_UINT32
      || centralOffset >= MAX_UINT32;

    if (needsZip64Eocd) {
      const zip64EocdOffset = centralOffset + centralSize;

      const z64 = new Uint8Array(56);
      const zv = new DataView(z64.buffer);
      zv.setUint32(0, SIG_ZIP64_EOCD, true);
      writeUint64LE(zv, 4, 44); // size of remaining ZIP64 EOCD
      zv.setUint16(12, (3 << 8) | 45, true);
      zv.setUint16(14, 45, true);
      zv.setUint32(16, 0, true);
      zv.setUint32(20, 0, true);
      writeUint64LE(zv, 24, entryCount);
      writeUint64LE(zv, 32, entryCount);
      writeUint64LE(zv, 40, centralSize);
      writeUint64LE(zv, 48, centralOffset);
      parts.push(z64);

      const loc = new Uint8Array(20);
      const lov = new DataView(loc.buffer);
      lov.setUint32(0, SIG_ZIP64_LOCATOR, true);
      lov.setUint32(4, 0, true);
      writeUint64LE(lov, 8, zip64EocdOffset);
      lov.setUint32(16, 1, true);
      parts.push(loc);
    }

    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, SIG_EOCD, true);
    ev.setUint16(4, 0, true);
    ev.setUint16(6, 0, true);
    ev.setUint16(8, entryCount >= MAX_UINT16 || needsZip64Eocd ? MAX_UINT16 : entryCount, true);
    ev.setUint16(10, entryCount >= MAX_UINT16 || needsZip64Eocd ? MAX_UINT16 : entryCount, true);
    ev.setUint32(12, centralSize >= MAX_UINT32 || needsZip64Eocd ? MAX_UINT32 : centralSize, true);
    ev.setUint32(16, centralOffset >= MAX_UINT32 || needsZip64Eocd ? MAX_UINT32 : centralOffset, true);
    ev.setUint16(20, 0, true);
    parts.push(eocd);

    if (typeof onUpdate === 'function') {
      onUpdate({ percent: 100, currentFile: null });
    }

    if (outType === 'blob') {
      return new Blob(parts, { type: 'application/zip' });
    }
    const flat = await materializePartsToUint8Array(parts);
    if (outType === 'uint8array') return flat;
    if (outType === 'arraybuffer') {
      return flat.buffer.slice(flat.byteOffset, flat.byteOffset + flat.byteLength);
    }
    throw new Error(`Desteklenmeyen generateAsync çıktı türü: ${outType}`);
  }

  static async loadAsync(input) {
    let bytes = toUint8ArraySync(input);
    if (bytes === null) {
      if (isBlobLike(input)) {
        bytes = new Uint8Array(await input.arrayBuffer());
      } else {
        throw new Error('JSZip.loadAsync için Uint8Array, ArrayBuffer veya Blob bekleniyor.');
      }
    }
    if (bytes.byteLength < 22) {
      throw new Error('Geçersiz ZIP arşivi: dosya çok kısa.');
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    // Locate EOCD scanning backwards
    const minSearchPos = Math.max(0, bytes.byteLength - 22 - 65535);
    let eocdPos = -1;
    for (let pos = bytes.byteLength - 22; pos >= minSearchPos; pos--) {
      if (view.getUint32(pos, true) === SIG_EOCD) {
        const commentLen = view.getUint16(pos + 20, true);
        if (pos + 22 + commentLen === bytes.byteLength) {
          eocdPos = pos;
          break;
        }
      }
    }
    if (eocdPos < 0) {
      throw new Error('Geçersiz ZIP arşivi: EOCD imzası bulunamadı.');
    }

    let entryCount = view.getUint16(eocdPos + 10, true);
    let cdSize = view.getUint32(eocdPos + 12, true);
    let cdOffset = view.getUint32(eocdPos + 16, true);

    // Check for ZIP64 EOCD Locator immediately before EOCD
    if (eocdPos >= 20 && view.getUint32(eocdPos - 20, true) === SIG_ZIP64_LOCATOR) {
      const z64Offset = readUint64LE(view, eocdPos - 12);
      if (z64Offset + 56 <= bytes.byteLength && view.getUint32(z64Offset, true) === SIG_ZIP64_EOCD) {
        entryCount = readUint64LE(view, z64Offset + 32);
        cdSize = readUint64LE(view, z64Offset + 40);
        cdOffset = readUint64LE(view, z64Offset + 48);
      }
    }

    if (cdOffset + cdSize > bytes.byteLength) {
      throw new Error('Geçersiz ZIP arşivi: Merkez Dizin sınır dışı.');
    }

    const zip = new JSZip();
    let ptr = cdOffset;
    for (let i = 0; i < entryCount; i++) {
      if (ptr + 46 > bytes.byteLength || view.getUint32(ptr, true) !== SIG_CDH) {
        throw new Error('Geçersiz ZIP arşivi: bozuk Merkez Dizin kaydı.');
      }
      const method = view.getUint16(ptr + 10, true);
      const dosTime = view.getUint16(ptr + 12, true);
      const dosDate = view.getUint16(ptr + 14, true);
      const expectedCrc = view.getUint32(ptr + 16, true);
      let compSize = view.getUint32(ptr + 20, true);
      let uncompSize = view.getUint32(ptr + 24, true);
      const nameLen = view.getUint16(ptr + 28, true);
      const extraLen = view.getUint16(ptr + 30, true);
      const commentLen = view.getUint16(ptr + 32, true);
      const extAttr = view.getUint32(ptr + 38, true);
      let lfhOffset = view.getUint32(ptr + 42, true);

      const nameStart = ptr + 46;
      const extraStart = nameStart + nameLen;
      const commentStart = extraStart + extraLen;
      const nextPtr = commentStart + commentLen;
      if (nextPtr > bytes.byteLength) {
        throw new Error('Geçersiz ZIP arşivi: kesik Merkez Dizin girdisi.');
      }

      const rawName = TEXT_DECODER.decode(bytes.subarray(nameStart, extraStart));
      const comment = commentLen > 0
        ? TEXT_DECODER.decode(bytes.subarray(commentStart, nextPtr))
        : '';

      // Parse ZIP64 extra field if any sentinel value is present
      if (uncompSize === MAX_UINT32 || compSize === MAX_UINT32 || lfhOffset === MAX_UINT32) {
        let ep = extraStart;
        const extraEnd = extraStart + extraLen;
        while (ep + 4 <= extraEnd) {
          const eid = view.getUint16(ep, true);
          const esz = view.getUint16(ep + 2, true);
          ep += 4;
          if (eid === EXTRA_ZIP64_ID && ep + esz <= extraEnd) {
            let zp = ep;
            if (uncompSize === MAX_UINT32 && zp + 8 <= ep + esz) {
              uncompSize = readUint64LE(view, zp);
              zp += 8;
            }
            if (compSize === MAX_UINT32 && zp + 8 <= ep + esz) {
              compSize = readUint64LE(view, zp);
              zp += 8;
            }
            if (lfhOffset === MAX_UINT32 && zp + 8 <= ep + esz) {
              lfhOffset = readUint64LE(view, zp);
            }
            break;
          }
          ep += esz;
        }
      }

      // Locate payload via Local File Header
      if (lfhOffset + 30 > bytes.byteLength || view.getUint32(lfhOffset, true) !== SIG_LFH) {
        throw new Error(`Geçersiz ZIP Yerel Dosya Başlığı: ${rawName}`);
      }
      const lfhNameLen = view.getUint16(lfhOffset + 26, true);
      const lfhExtraLen = view.getUint16(lfhOffset + 28, true);
      const dataStart = lfhOffset + 30 + lfhNameLen + lfhExtraLen;
      const dataEnd = dataStart + compSize;
      if (dataEnd > bytes.byteLength) {
        throw new Error(`Kesik ZIP girdi verisi: ${rawName}`);
      }

      const isDir = rawName.endsWith('/') || ((extAttr & 0x10) !== 0 && uncompSize === 0);
      const safeName = normalizeZipPath(rawName, isDir);
      const rawCompressed = bytes.slice(dataStart, dataEnd);

      zip.files[safeName] = new ZipObject({
        name: safeName,
        dir: isDir,
        date: decodeDosDateTime(dosDate, dosTime),
        comment,
        unixPermissions: (extAttr >>> 16) || null,
        _rawCompressed: rawCompressed,
        _compressionMethod: method,
        _expectedCrc: expectedCrc,
        _uncompressedSize: uncompSize,
      });

      ptr = nextPtr;
    }

    return zip;
  }
}

if (typeof globalThis !== 'undefined' && !globalThis.JSZip) {
  globalThis.JSZip = JSZip;
}

export default JSZip;
