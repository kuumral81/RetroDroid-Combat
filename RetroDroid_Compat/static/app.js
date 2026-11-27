/**
 * RetroDroid Compat v5.4.0 — Modular XSS-Free Frontend Application
 *
 * - Zero external CDN dependencies (imports local offline ./vendor/jszip.js)
 * - Zero innerHTML with dynamic data & zero inline on* event handlers
 * - Full alignment with live M2 FastAPI server.py endpoints & schemas
 * - Pure business logic exported for direct Node 24 unit testing
 */

import { JSZip } from './vendor/jszip.js';

// ============================================================================
// 1. CONSTANTS, PROFILES & CATALOG DATA
// ============================================================================
export const APP_VERSION = '5.4.0';
export const STORAGE_KEY = 'retrodroid_compat_state_v1';
export const API_TOKEN_SESSION_KEY = 'retrodroid_api_token_v1';
export const UPLOAD_SESSION_KEY = 'retrodroid_upload_session_v1';

export const MAX_FILE_BYTES = 5 * 1024 * 1024 * 1024; // 5 GiB (5120 MiB)
export const CLIENT_ZIP_MAX_BYTES = 512 * 1024 * 1024; // 512 MiB browser RAM guard
export const SANDBOX_QUOTA_MB = 32 * 1024; // 32 GB
export const DONUT_CIRCUMFERENCE = 2 * Math.PI * 48; // ~301.5929

export const CONTAINER_EXTS = new Set(['XAPK', 'APK+OBB', 'APKS', 'APKM', 'ZIP']);
export const ALLOWED_GAME_EXTS = new Set(['APK', 'XAPK', 'APKS', 'APKM', 'ZIP', 'APK+OBB']);
export const ALLOWED_UPLOAD_EXTS = ['.apk', '.xapk', '.apks', '.apkm', '.zip', '.obb'];
export const ALLOWED_TABS = new Set(['library', 'patcher', 'engine', 'system']);

export const ACTIVE_JOB_STATUSES = new Set(['queued', 'running', 'processing']);
export const TERMINAL_JOB_STATUSES = new Set(['done', 'error', 'canceled', 'interrupted']);

export const ALLOWED_ENGINE_ABI = [
  'Otomatik ABI Denetimi (ARM64 + 32-bit Uyarı)',
  'Yalnızca 64-bit Cihazlar (ARM64-v8a / 16 KB Kontrol)',
  'Hibrit 32/64-bit Cihazlar (ARMv7a + ARM64)',
];

export const ALLOWED_ENGINE_RENDERER = [
  'Standart Android 14–16 Profili (API 28 Hedef)',
  'Geniş Ekran 20:9 + Yüksek FPS Önizleme',
  'Klasik 2D / Düşük Kaynak Önizleme',
];

function isPlainObject(val) {
  return Boolean(val && typeof val === 'object' && !Array.isArray(val));
}

function ownGet(map, key, fallback = undefined) {
  return (map && typeof key === 'string' && Object.hasOwn(map, key)) ? map[key] : fallback;
}

const LEGACY_ABI_MIGRATION = Object.freeze(Object.assign(Object.create(null), {
  'RetroBridge JIT v4 (Önerilen)': ALLOWED_ENGINE_ABI[0],
  'Houdini-Compat Dinamik Çevirici': ALLOWED_ENGINE_ABI[1],
  'Saf NDK-Translation (Yüksek Kararlılık)': ALLOWED_ENGINE_ABI[2],
}));

const LEGACY_RENDERER_MIGRATION = Object.freeze(Object.assign(Object.create(null), {
  'Vulkan ANGLE Wrapper (Yüksek Hız)': ALLOWED_ENGINE_RENDERER[0],
  'OpenGL ES 3.2 Uyumluluk Katmanı': ALLOWED_ENGINE_RENDERER[2],
  'Legacy GLES 2.0 Yazılım Emülasyonu': ALLOWED_ENGINE_RENDERER[2],
}));

const LEGACY_MODULE_MIGRATION = Object.freeze(Object.assign(Object.create(null), {
  targetSdk: 'sdkChecklist',
  armBridge: 'abiAudit',
  xapkObb: 'obbGuide',
  notchFix: 'aspectNote',
  gles2: 'previewProfile',
  resign: 'signNote',
}));

// Honest Web Preview / Profile Notes (explicitly separate from real server APK patches)
export const PATCH_MODULES = [
  {
    id: 'sdkChecklist',
    title: 'Android 14–17 Kurulum Eşiği Raporu',
    desc: 'JSON raporuna ve kurulum rehberine Android 14 (API 23) ve Android 15–17 (API 24) eşik notlarını ekler.',
    defaultOn: true,
  },
  {
    id: 'abiAudit',
    title: '32-bit / 64-bit ABI & 16 KB ELF Raporu',
    desc: 'Kütüphane kartında ve raporda 32-bit kısıtı ile 16 KB ELF64 PT_LOAD analiz özetini vurgular.',
    defaultOn: true,
  },
  {
    id: 'obbGuide',
    title: 'Android/obb Kurulum Rehberi',
    desc: 'OBB içeren paketlerde KURULUM_REHBERI.txt içine adım adım /Android/obb/<paket>/ yönergeleri ekler.',
    defaultOn: true,
  },
  {
    id: 'aspectNote',
    title: 'Geniş Ekran Önizleme Profili',
    desc: 'Tarayıcı kontrol önizlemesinde modern geniş ekran yerleşimini varsayılan olarak işaretler.',
    defaultOn: true,
  },
  {
    id: 'previewProfile',
    title: 'Kontrol & FPS Profili Kaydı',
    desc: 'Oyun için seçilen FPS, ölçek ve özel klavye/gamepad yerleşimini yedeklere dahil eder.',
    defaultOn: true,
  },
  {
    id: 'signNote',
    title: 'İmza Değişikliği Kurulum Uyarısı',
    desc: 'Yeniden imzalanmış APK kurulmadan önce orijinal sürümün kaldırılması gerektiğini not düşer.',
    defaultOn: true,
  },
];

export const ENGINE_PROFILES = [
  {
    id: 'max_compat',
    name: 'Maksimum Kurulum Uyumu',
    shortName: 'Maks. Uyum',
    desc: 'API 28 hedefi, v1/v2/v3 imzalama, OBB rehberi ve 16 KB/ABI raporlama açık. Eski 3D ve XAPK paketleri için dengeli önayar.',
    badge: 'Önerilen',
    color: 'emerald',
    defaultTargetSdk: 28,
    defaultServerFlags: {
      patchTargetSdk: true,
      resign: true,
      addLegacyStorage: false,
      enableCleartext: false,
      addNotchSupport: false,
      forceExtractNativeLibs: false,
      allowDowngrade: false,
    },
    defaultModules: PATCH_MODULES.map(m => m.id),
    abi: ALLOWED_ENGINE_ABI[0],
    renderer: ALLOWED_ENGINE_RENDERER[0],
    ram: 4096,
  },
  {
    id: 'performance',
    name: 'Geniş Ekran & Modern Hedef',
    shortName: 'Modern',
    desc: 'API 31+ hedefi ve geniş ekran (max_aspect 2.4) manifest bayrağı önayarı. 90 FPS tarayıcı önizlemesi ile birlikte gelir.',
    badge: 'API 31+',
    color: 'sky',
    defaultTargetSdk: 31,
    defaultServerFlags: {
      patchTargetSdk: true,
      resign: true,
      addLegacyStorage: false,
      enableCleartext: false,
      addNotchSupport: true,
      forceExtractNativeLibs: false,
      allowDowngrade: false,
    },
    defaultModules: ['sdkChecklist', 'abiAudit', 'obbGuide', 'aspectNote', 'signNote'],
    abi: ALLOWED_ENGINE_ABI[1],
    renderer: ALLOWED_ENGINE_RENDERER[1],
    ram: 6144,
  },
  {
    id: 'legacy_2d',
    name: 'Eski Android 2.3–6.0 Paketleri',
    shortName: 'Klasik',
    desc: 'API 28 hedefiyle birlikte eski depolama (requestLegacyExternalStorage) ve cleartext HTTP bayraklarını hazırlar.',
    badge: 'Klasik',
    color: 'amber',
    defaultTargetSdk: 28,
    defaultServerFlags: {
      patchTargetSdk: true,
      resign: true,
      addLegacyStorage: true,
      enableCleartext: true,
      addNotchSupport: false,
      forceExtractNativeLibs: true,
      allowDowngrade: false,
    },
    defaultModules: ['sdkChecklist', 'abiAudit', 'previewProfile', 'signNote'],
    abi: ALLOWED_ENGINE_ABI[2],
    renderer: ALLOWED_ENGINE_RENDERER[2],
    ram: 2048,
  },
];

export const DEMO_PACKAGES = [
  {
    id: 'demo-mc4',
    name: 'Modern Combat 4: Zero Hour (Örnek)',
    fileName: 'Modern_Combat_4_Zero_Hour_v1.2.2e.xapk',
    ext: 'XAPK',
    sizeMB: 3932.16,
    legacyAndroid: 'Android 4.0',
    legacyApi: 14,
    minSdk: 9,
    arch: 'armeabi-v7a (32-bit)',
    is32BitOnly: true,
    hasObb: true,
    genre: 'fps',
    accent: 'emerald',
    signature: 'Örnek Profil (Sunucu Analizi Yok)',
    packageId: 'com.gameloft.android.ANMP.GloftM4HM',
  },
  {
    id: 'demo-nova3',
    name: 'N.O.V.A. 3: Freedom Edition (Örnek)',
    fileName: 'NOVA_3_Freedom_Edition_v1.0.8.xapk',
    ext: 'XAPK',
    sizeMB: 2201.6,
    legacyAndroid: 'Android 4.1',
    legacyApi: 16,
    minSdk: 10,
    arch: 'armeabi-v7a (32-bit)',
    is32BitOnly: true,
    hasObb: true,
    genre: 'scifi',
    accent: 'sky',
    signature: 'Örnek Profil (Sunucu Analizi Yok)',
    packageId: 'com.gameloft.android.ANMP.GloftN3HM',
  },
  {
    id: 'demo-gtavc',
    name: 'GTA: Vice City v1.03 (Örnek)',
    fileName: 'GTA_Vice_City_Classic_v1.03.xapk',
    ext: 'XAPK',
    sizeMB: 1454.08,
    legacyAndroid: 'Android 4.4',
    legacyApi: 19,
    minSdk: 10,
    arch: 'armeabi-v7a (32-bit)',
    is32BitOnly: true,
    hasObb: true,
    genre: 'city',
    accent: 'violet',
    signature: 'Örnek Profil (Sunucu Analizi Yok)',
    packageId: 'com.rockstargames.gtavc',
  },
  {
    id: 'demo-flappy',
    name: 'Flappy Bird Classic v1.3 (Örnek)',
    fileName: 'Flappy_Bird_Classic_v1.3.apk',
    ext: 'APK',
    sizeMB: 1.2,
    legacyAndroid: 'Android 2.3',
    legacyApi: 9,
    minSdk: 9,
    arch: 'Saf Java / DEX',
    is32BitOnly: false,
    hasObb: false,
    genre: 'arcade',
    accent: 'amber',
    signature: 'Örnek Profil (Sunucu Analizi Yok)',
    packageId: 'com.dotgears.flappybird',
  },
];

export const LEGACY_ANDROID_VERSIONS = [
  { ver: 'Android 2.3–4.3', codename: 'Gingerbread → Jelly Bean', api: 'API 9–18', status: 'Yama Önerilir', note: 'Android 14+ engeller; API 28 yükseltmesi gerekir' },
  { ver: 'Android 4.4–5.1', codename: 'KitKat → Lollipop', api: 'API 19–22', status: 'Yama Önerilir', note: 'Android 14 (min 23) ve 15–17 (min 24) engeller' },
  { ver: 'Android 6.0', codename: 'Marshmallow', api: 'API 23', status: 'Android 15+ Engeli', note: 'Android 14 kurar; Android 15–17 min API 24 ister' },
  { ver: 'Android 7.0–8.1', codename: 'Nougat → Oreo', api: 'API 24–27', status: 'Eşik Geçer', note: 'Android 14–17 kurulum eşiğini karşılar' },
  { ver: 'Android 9.0', codename: 'Pie', api: 'API 28', status: 'Önerilen Hedef', note: 'Eski oyunlar için en dengeli targetSdk hedefi' },
  { ver: 'Android 10–11', codename: 'Q → R', api: 'API 29–30', status: 'ZIP_STORED', note: 'resources.arsc sıkıştırılmamış ve v2+ imza zorunlu' },
  { ver: 'Android 12–14', codename: 'S → Upside Down Cake', api: 'API 31–34', status: 'exported Zorunlu', note: 'intent-filter bileşenlerine android:exported eklenir' },
  { ver: 'Android 15–17', codename: 'Vanilla Ice Cream+', api: 'API 35–36', status: '16 KB ELF Denetimi', note: 'Min kurulum API 24 • 64-bit .so 16 KB PT_LOAD analizi' },
];

export const CONTROL_KEY_OPTIONS = [
  ['ArrowUp', 'Yukarı Ok'], ['ArrowDown', 'Aşağı Ok'], ['ArrowLeft', 'Sol Ok'], ['ArrowRight', 'Sağ Ok'],
  ['KeyW', 'W'], ['KeyA', 'A'], ['KeyS', 'S'], ['KeyD', 'D'], ['KeyJ', 'J'], ['KeyK', 'K'],
  ['KeyU', 'U'], ['KeyI', 'I'], ['KeyZ', 'Z'], ['KeyX', 'X'], ['KeyC', 'C'], ['KeyV', 'V'],
  ['Space', 'Boşluk'], ['Enter', 'Enter'],
];

const CONTROL_ACTION_LABELS = Object.freeze(Object.assign(Object.create(null), {
  UP: 'Yukarı',
  DOWN: 'Aşağı',
  LEFT: 'Sol',
  RIGHT: 'Sağ',
  A: 'A',
  B: 'B',
  X: 'X',
  Y: 'Y',
}));

const PATCH_METHOD_LABELS = Object.freeze(Object.assign(Object.create(null), {
  binary_axml: 'Binary AXML (Hızlı)',
  slim_apktool: 'Slim-Apktool (Tam XML)',
  fallback_binary_axml: 'Yedek Binary AXML',
  fallback_resign: 'Yedek Güvenli İmzalama',
  resign_only: 'Yalnızca Hizala & İmzala',
}));

const JOB_STATUS_META = Object.freeze(Object.assign(Object.create(null), {
  uploading: { label: 'Yükleniyor', badge: 'rd-badge--sky' },
  analyzed: { label: 'Analiz Edildi', badge: 'rd-badge--indigo' },
  queued: { label: 'Kuyrukta', badge: 'rd-badge--sky' },
  running: { label: 'İşleniyor', badge: 'rd-badge--sky' },
  processing: { label: 'İşleniyor', badge: 'rd-badge--sky' },
  done: { label: 'Tamam', badge: 'rd-badge--emerald' },
  error: { label: 'Hata', badge: 'rd-badge--rose' },
  canceled: { label: 'İptal', badge: 'rd-badge--amber' },
  interrupted: { label: 'Kesildi', badge: 'rd-badge--amber' },
}));

// Static constant SVG templates (NEVER concatenated with user or server strings)
const STATIC_SVGS = Object.freeze(Object.assign(Object.create(null), {
  fps: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="8"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><circle cx="12" cy="12" r="2" fill="currentColor"/></svg>',
  scifi: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 2L4 7v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V7l-8-5z"/><path d="M9 12l2 2 4-4"/></svg>',
  city: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 21h18M5 21V7l6-4v18M19 21V11l-8-3"/><path d="M8 10h.01M8 14h.01M15 14h.01M15 17h.01"/></svg>',
  arcade: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="2" y="6" width="20" height="12" rx="4"/><path d="M6 12h4M8 10v4"/><circle cx="15" cy="11" r="1" fill="currentColor"/><circle cx="17.5" cy="13" r="1" fill="currentColor"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>',
}));

// ============================================================================
// 2. PURE LOGIC, VALIDATION & CONTRACT HELPERS (EXPORTED FOR UNIT TESTS)
// ============================================================================

export class ApiHttpError extends Error {
  constructor(message, status = 0, retryAfter = null) {
    super(message);
    this.name = 'ApiHttpError';
    this.status = Number(status) || 0;
    this.retryAfter = retryAfter;
  }
}

export function asSafeString(val, fallback = '') {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean') return String(val);
  return fallback;
}

export function asSafeFiniteNumber(val, fallback = 0) {
  if (typeof val === 'number') {
    return Number.isFinite(val) ? val : fallback;
  }
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!trimmed) return fallback;
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : fallback;
  }
  return fallback;
}

export function escapeHtml(str) {
  return asSafeString(str, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function validateRenderApiUrl(raw) {
  if (raw === null || raw === undefined) {
    return { valid: true, normalized: '' };
  }
  if (typeof raw !== 'string') {
    return { valid: false, normalized: '', error: 'Geçersiz URL biçimi. Örnek: https://ornek.onrender.com' };
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    return { valid: true, normalized: '' };
  }
  if (/[\x00-\x1f\x7f]/.test(trimmed)) {
    return { valid: false, normalized: '', error: 'Sunucu adresinde kontrol karakteri bulunamaz.' };
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, normalized: '', error: 'Geçersiz URL biçimi. Örnek: https://ornek.onrender.com' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, normalized: '', error: 'Yalnızca http:// veya https:// sunucu adreslerine izin verilir.' };
  }
  if (parsed.username || parsed.password) {
    return { valid: false, normalized: '', error: 'Sunucu adresinde kullanıcı adı veya parola bulunamaz.' };
  }
  if (!parsed.hostname) {
    return { valid: false, normalized: '', error: 'Geçerli bir alan adı veya IP adresi girin.' };
  }
  const cleanPath = parsed.pathname.replace(/\/+$/, '');
  return { valid: true, normalized: `${parsed.origin}${cleanPath}` };
}

export function validateApiToken(raw) {
  if (raw === null || raw === undefined) {
    return { valid: true, token: '' };
  }
  if (typeof raw !== 'string') {
    return { valid: false, token: '', error: 'API anahtarı geçersiz veri tipinde.' };
  }
  if (/[\x00-\x1f\x7f]/.test(raw)) {
    return {
      valid: false,
      token: '',
      error: 'API anahtarında kontrol karakteri (satır sonu / NUL / sekme) bulunamaz.',
    };
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    return { valid: true, token: '' };
  }
  if (trimmed.length > 512) {
    return {
      valid: false,
      token: '',
      error: 'API anahtarı çok uzun (maksimum 512 karakter).',
    };
  }
  if (/[^\x20-\x7e]/.test(trimmed)) {
    return {
      valid: false,
      token: '',
      error: 'API anahtarı yalnızca standart ASCII karakterler içerebilir (Türkçe karakter veya emoji kullanılamaz).',
    };
  }
  return { valid: true, token: trimmed };
}

export function buildAuthHeaders(apiToken = '') {
  const check = validateApiToken(apiToken);
  if (!check.valid || !check.token) return {};
  return { Authorization: `Bearer ${check.token}` };
}

export function buildSafeDownloadUrl(base, rawPath, apiToken = '') {
  if (typeof rawPath !== 'string') return null;
  const trimmedPath = rawPath.trim();
  if (
    !trimmedPath.startsWith('/api/')
    || trimmedPath.startsWith('//')
    || trimmedPath.includes('\\')
    || trimmedPath.includes('#')
  ) {
    return null;
  }
  if (/[\x00-\x1f\x7f]/.test(trimmedPath)) return null;

  const qIdx = trimmedPath.indexOf('?');
  const rawPathname = qIdx >= 0 ? trimmedPath.slice(0, qIdx) : trimmedPath;
  if (rawPathname.includes('//')) return null;

  const rawSegments = rawPathname.split('/');
  for (let i = 1; i < rawSegments.length; i++) {
    const seg = rawSegments[i];
    if (seg === '.' || seg === '..') return null;
    let decodedSeg;
    try {
      decodedSeg = decodeURIComponent(seg);
    } catch {
      return null;
    }
    if (
      decodedSeg === '.'
      || decodedSeg === '..'
      || decodedSeg.includes('/')
      || decodedSeg.includes('\\')
      || /[\x00-\x1f\x7f]/.test(decodedSeg)
    ) {
      return null;
    }
  }

  let parsed;
  try {
    parsed = new URL(trimmedPath, 'http://local.invalid');
  } catch {
    return null;
  }
  if (
    parsed.origin !== 'http://local.invalid'
    || !parsed.pathname.startsWith('/api/')
    || parsed.hash
  ) {
    return null;
  }
  try {
    const decodedPathname = decodeURIComponent(parsed.pathname);
    if (/(^|\/)\.\.?(\/|$)/.test(decodedPathname) || decodedPathname.includes('\\')) {
      return null;
    }
  } catch {
    return null;
  }

  const baseCheck = validateRenderApiUrl(base || '');
  if (!baseCheck.valid) return null;

  const tokCheck = validateApiToken(apiToken);
  const tok = tokCheck.valid ? tokCheck.token : '';
  if (tok && parsed.pathname.startsWith('/api/download')) {
    parsed.searchParams.set('token', tok);
  }
  const searchStr = parsed.search.replace(/\+/g, '%20');
  return `${baseCheck.normalized}${parsed.pathname}${searchStr}`;
}

export function controlLayoutDefaults() {
  return {
    size: 100,
    opacity: 85,
    side: 'standard',
    mapping: {
      UP: 'ArrowUp',
      DOWN: 'ArrowDown',
      LEFT: 'ArrowLeft',
      RIGHT: 'ArrowRight',
      A: 'Space',
      B: 'KeyX',
      X: 'Enter',
      Y: 'KeyZ',
    },
  };
}

export function validPackageId(value) {
  return /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(String(value || ''));
}

export function isContainerFormat(ext) {
  return CONTAINER_EXTS.has(String(ext || '').toUpperCase());
}

export function formatSizeFromMB(mb) {
  const val = Number(mb);
  if (!Number.isFinite(val) || val < 0) return '0.00 MB';
  if (val >= 1024) return `${(val / 1024).toFixed(2)} GB`;
  if (val >= 10) return `${val.toFixed(1)} MB`;
  return `${val.toFixed(2)} MB`;
}

export function formatSdkSummary(legacyAndroid, legacyApi, minSdk = 0) {
  const androidStr = String(legacyAndroid || '').trim();
  const apiNum = Number(legacyApi);
  const minNum = Number(minSdk);

  if (androidStr && /\(API\s*\d+\)/i.test(androidStr)) {
    return androidStr;
  }
  if (/^targetSdk\s+\d+/i.test(androidStr)) {
    if (/\(min\s+\d+/i.test(androidStr)) return androidStr;
    return minNum > 0 ? `${androidStr} (min ${minNum})` : androidStr;
  }
  if (androidStr && androidStr !== 'Bilinmiyor' && apiNum > 0) {
    return `${androidStr} (API ${apiNum})`;
  }
  if (apiNum > 0) {
    return minNum > 0 ? `targetSdk ${apiNum} (min ${minNum})` : `targetSdk ${apiNum}`;
  }
  return androidStr || 'Bilinmiyor';
}

export function createDefaultState() {
  return {
    activeTab: 'library',
    activeProfile: 'max_compat',
    renderApiUrl: '',
    cacheMB: 120,
    engineSettings: {
      abi: ALLOWED_ENGINE_ABI[0],
      renderer: ALLOWED_ENGINE_RENDERER[0],
      ram: 4096,
      scopedObb: true,
      audioFix: true,
    },
    games: [
      {
        id: 'demo-gtavc',
        name: 'GTA: Vice City v1.03 (Örnek)',
        fileName: 'GTA_Vice_City_Classic_v1.03.xapk',
        ext: 'XAPK',
        sizeMB: 1454.08,
        legacyAndroid: 'Android 4.4',
        legacyApi: 19,
        minSdk: 10,
        arch: 'armeabi-v7a (32-bit)',
        is32BitOnly: true,
        hasObb: true,
        genre: 'city',
        accent: 'violet',
        signature: 'Örnek Profil (Sunucu Analizi Yok)',
        packageId: 'com.rockstargames.gtavc',
        compatScore: 72,
        patchedAt: new Date().toISOString(),
        modules: PATCH_MODULES.map(m => m.id),
        settings: {
          fps: 60,
          resolutionScale: 125,
          controlMode: 'Sanal Gamepad Katmanı',
          controlLayout: controlLayoutDefaults(),
        },
      },
      {
        id: 'demo-flappy',
        name: 'Flappy Bird Classic v1.3 (Örnek)',
        fileName: 'Flappy_Bird_Classic_v1.3.apk',
        ext: 'APK',
        sizeMB: 1.2,
        legacyAndroid: 'Android 2.3',
        legacyApi: 9,
        minSdk: 9,
        arch: 'Saf Java / DEX',
        is32BitOnly: false,
        hasObb: false,
        genre: 'arcade',
        accent: 'amber',
        signature: 'Örnek Profil (Sunucu Analizi Yok)',
        packageId: 'com.dotgears.flappybird',
        compatScore: 80,
        patchedAt: new Date().toISOString(),
        modules: ['sdkChecklist', 'abiAudit', 'previewProfile', 'signNote'],
        settings: {
          fps: 60,
          resolutionScale: 100,
          controlMode: 'Eski Dokunmatik Ölçekleme',
          controlLayout: controlLayoutDefaults(),
        },
      },
    ],
  };
}

export function normalizeGame(game, index = 0) {
  if (!isPlainObject(game)) return null;
  const defaults = {
    id: `recovered-${index}`,
    name: 'İsimsiz paket',
    fileName: 'bilinmeyen.apk',
    ext: 'APK',
    sizeMB: 0,
    legacyAndroid: 'Bilinmiyor',
    legacyApi: 0,
    minSdk: 0,
    arch: 'Bilinmiyor',
    is32BitOnly: false,
    hasObb: false,
    genre: 'arcade',
    accent: 'sky',
    signature: 'Doğrulanmadı',
    packageId: '',
    compatScore: 0,
    modules: [],
    settings: {},
  };

  const validModIds = new Set(PATCH_MODULES.map(m => m.id));
  const rawMods = Array.isArray(game.modules) ? game.modules : [];
  const mappedMods = [];
  for (const rawId of rawMods) {
    if (typeof rawId !== 'string') continue;
    const nextId = validModIds.has(rawId) ? rawId : ownGet(LEGACY_MODULE_MIGRATION, rawId);
    if (typeof nextId === 'string' && validModIds.has(nextId) && !mappedMods.includes(nextId)) {
      mappedMods.push(nextId);
    }
  }

  const extUpper = (asSafeString(game.ext, '') || 'APK').toUpperCase();
  const safeExt = ALLOWED_GAME_EXTS.has(extUpper) ? extUpper : 'APK';
  const defLayout = controlLayoutDefaults();
  const rawSettings = isPlainObject(game.settings) ? game.settings : {};
  const rawLayout = isPlainObject(rawSettings.controlLayout) ? rawSettings.controlLayout : {};
  const allowedKeyValues = new Set(CONTROL_KEY_OPTIONS.map(([code]) => code));
  const safeMapping = { ...defLayout.mapping };
  if (isPlainObject(rawLayout.mapping)) {
    for (const action of Object.keys(defLayout.mapping)) {
      const candidate = ownGet(rawLayout.mapping, action);
      if (typeof candidate === 'string' && allowedKeyValues.has(candidate)) {
        safeMapping[action] = candidate;
      }
    }
  }

  const allowedControlModes = new Set([
    'Sanal Gamepad Katmanı',
    'Eski Dokunmatik Ölçekleme',
    'Bluetooth / USB Kontrolcü',
  ]);
  const rawMode = asSafeString(rawSettings.controlMode, '') || 'Sanal Gamepad Katmanı';

  const rawSizeMB = asSafeFiniteNumber(game.sizeMB, 0);
  const rawLegacyApi = asSafeFiniteNumber(game.legacyApi, 0);
  const rawMinSdk = asSafeFiniteNumber(game.minSdk, 0);
  const rawCompatScore = asSafeFiniteNumber(game.compatScore, 0);
  const rawFps = asSafeFiniteNumber(rawSettings.fps, 60);
  const rawResScale = asSafeFiniteNumber(rawSettings.resolutionScale, 100);
  const rawLayoutSize = asSafeFiniteNumber(rawLayout.size, defLayout.size);
  const rawLayoutOpacity = asSafeFiniteNumber(rawLayout.opacity, defLayout.opacity);

  const safe = {
    id: (asSafeString(game.id, '') || defaults.id).slice(0, 120),
    name: (asSafeString(game.name, '') || asSafeString(game.fileName, '') || defaults.name).slice(0, 200),
    fileName: (asSafeString(game.fileName, '') || asSafeString(game.name, '') || defaults.fileName).slice(0, 240),
    ext: safeExt,
    sizeMB: rawSizeMB >= 0 ? rawSizeMB : 0,
    legacyAndroid: (asSafeString(game.legacyAndroid, '') || defaults.legacyAndroid).slice(0, 120),
    legacyApi: rawLegacyApi >= 0 ? rawLegacyApi : 0,
    minSdk: rawMinSdk >= 0 ? rawMinSdk : 0,
    arch: (asSafeString(game.arch, '') || defaults.arch).slice(0, 160),
    is32BitOnly: Boolean(game.is32BitOnly),
    hasObb: Boolean(game.hasObb),
    genre: ['fps', 'scifi', 'city', 'arcade'].includes(game.genre) ? game.genre : 'arcade',
    accent: ['emerald', 'sky', 'violet', 'amber'].includes(game.accent) ? game.accent : 'sky',
    signature: (asSafeString(game.signature, '') || defaults.signature).slice(0, 200),
    packageId: asSafeString(game.packageId, '').slice(0, 200),
    compatScore: Math.min(100, Math.max(0, Math.round(rawCompatScore))),
    patchedAt: typeof game.patchedAt === 'string' ? game.patchedAt : new Date().toISOString(),
    modules: mappedMods,
    settings: {
      fps: [30, 60, 90, 120].includes(rawFps) ? rawFps : 60,
      resolutionScale: Math.min(150, Math.max(75, rawResScale || 100)),
      controlMode: allowedControlModes.has(rawMode) ? rawMode : 'Sanal Gamepad Katmanı',
      controlLayout: {
        size: Math.min(140, Math.max(70, rawLayoutSize || defLayout.size)),
        opacity: Math.min(100, Math.max(30, rawLayoutOpacity || defLayout.opacity)),
        side: ['standard', 'reversed'].includes(rawLayout.side) ? rawLayout.side : defLayout.side,
        mapping: safeMapping,
      },
    },
  };

  if (typeof game.serverJobId === 'string' && /^[0-9a-f]{12}$/.test(game.serverJobId)) {
    safe.serverJobId = game.serverJobId;
  }
  if (isPlainObject(game.inspector)) {
    safe.inspector = game.inspector;
  }
  if (isPlainObject(game.patchSummary)) {
    safe.patchSummary = game.patchSummary;
  }
  if (typeof game.repatchAvailable === 'boolean') {
    safe.repatchAvailable = game.repatchAvailable;
  }

  return safe;
}

export function sanitizeAppState(rawState) {
  const defaults = createDefaultState();
  if (!isPlainObject(rawState)) {
    return defaults;
  }

  const activeTab = ALLOWED_TABS.has(rawState.activeTab) ? rawState.activeTab : defaults.activeTab;
  const profileIds = new Set(ENGINE_PROFILES.map(p => p.id));
  const activeProfile = profileIds.has(rawState.activeProfile) ? rawState.activeProfile : defaults.activeProfile;

  const urlCheck = validateRenderApiUrl(asSafeString(rawState.renderApiUrl, ''));
  const renderApiUrl = urlCheck.valid ? urlCheck.normalized : '';

  const rawCache = asSafeFiniteNumber(rawState.cacheMB, Number.NaN);
  const cacheMB = Number.isFinite(rawCache)
    ? Math.min(SANDBOX_QUOTA_MB, Math.max(0, Math.round(rawCache)))
    : defaults.cacheMB;

  const rawEng = isPlainObject(rawState.engineSettings) ? rawState.engineSettings : {};

  const rawAbi = typeof rawEng.abi === 'string' ? rawEng.abi : '';
  const migratedAbi = ownGet(LEGACY_ABI_MIGRATION, rawAbi);
  const abi = ALLOWED_ENGINE_ABI.includes(rawAbi)
    ? rawAbi
    : (typeof migratedAbi === 'string' ? migratedAbi : defaults.engineSettings.abi);

  const rawRenderer = typeof rawEng.renderer === 'string' ? rawEng.renderer : '';
  const migratedRenderer = ownGet(LEGACY_RENDERER_MIGRATION, rawRenderer);
  const renderer = ALLOWED_ENGINE_RENDERER.includes(rawRenderer)
    ? rawRenderer
    : (typeof migratedRenderer === 'string' ? migratedRenderer : defaults.engineSettings.renderer);

  const rawRam = asSafeFiniteNumber(rawEng.ram, Number.NaN);
  const ram = Number.isFinite(rawRam)
    ? Math.min(8192, Math.max(1024, Math.round(rawRam / 512) * 512))
    : defaults.engineSettings.ram;

  const games = Array.isArray(rawState.games)
    ? rawState.games.map((g, idx) => normalizeGame(g, idx)).filter(Boolean)
    : defaults.games;

  return {
    activeTab,
    activeProfile,
    renderApiUrl,
    cacheMB,
    engineSettings: {
      abi,
      renderer,
      ram,
      scopedObb: typeof rawEng.scopedObb === 'boolean' ? rawEng.scopedObb : defaults.engineSettings.scopedObb,
      audioFix: typeof rawEng.audioFix === 'boolean' ? rawEng.audioFix : defaults.engineSettings.audioFix,
    },
    games,
  };
}

export function createBackupPayload(state) {
  const clean = sanitizeAppState(state);
  return {
    app: 'RetroDroid Compat',
    version: APP_VERSION,
    exportedAt: new Date().toISOString(),
    state: clean,
  };
}

export function shouldRetryHttpStatus(status) {
  const code = Number(status) || 0;
  if (code === 0 || code === 408 || code === 429) return true;
  if (code >= 500 && code <= 599) return true;
  return false;
}

export function shouldClearUploadSessionOnFinishError(status) {
  const code = Number(status) || 0;
  return code >= 400 && code < 500 && !shouldRetryHttpStatus(code) && code !== 401;
}

export function computeUploadPlan(totalSize, serverInitData = {}) {
  const size = Number(totalSize) || 0;
  const chunkSizeBytes = Number(serverInitData.chunkSizeBytes)
    || (Number(serverInitData.chunkSizeMB) > 0 ? Number(serverInitData.chunkSizeMB) * 1024 * 1024 : 8 * 1024 * 1024);
  const computedTotalChunks = size > 0 ? Math.max(1, Math.ceil(size / chunkSizeBytes)) : 0;
  const totalChunks = Number(serverInitData.totalChunks) > 0
    ? Number(serverInitData.totalChunks)
    : computedTotalChunks;
  return { totalSize: size, chunkSizeBytes, totalChunks };
}

export function canResumeUploadSession(saved, fileMeta, base) {
  if (!isPlainObject(saved) || !fileMeta) return false;
  if (typeof saved.jobId !== 'string' || !/^[0-9a-f]{12}$/.test(saved.jobId)) return false;
  return (
    String(saved.base || '') === String(base || '')
    && saved.fileName === fileMeta.name
    && Number(saved.totalSize) === Number(fileMeta.size)
    && Number(saved.lastModified || 0) === Number(fileMeta.lastModified || 0)
  );
}

export function computeMissingChunkIndices(totalChunks, receivedChunks = []) {
  const got = new Set((Array.isArray(receivedChunks) ? receivedChunks : []).map(Number));
  const missing = [];
  for (let i = 0; i < totalChunks; i++) {
    if (!got.has(i)) missing.push(i);
  }
  return missing;
}

export function formatEta(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (!Number.isFinite(s)) return '—';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h} sa ${m} dk`;
  if (m > 0) return `${m} dk ${String(sec).padStart(2, '0')} sn`;
  return `${sec} sn`;
}

export function formatSpeedAndEta(bytesSent, elapsedSeconds, remainingBytes) {
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds <= 0.05 || bytesSent <= 0) {
    return 'Hız hesaplanıyor...';
  }
  const bytesPerSec = bytesSent / elapsedSeconds;
  const mbPerSec = bytesPerSec / (1024 * 1024);
  const etaSec = remainingBytes > 0 && bytesPerSec > 0 ? remainingBytes / bytesPerSec : 0;
  return `${mbPerSec.toFixed(1)} MB/s • Kalan: ${formatEta(etaSec)}`;
}

export function validateUploadFile(file, maxBytes = MAX_FILE_BYTES) {
  if (!file || typeof file.name !== 'string') {
    return { valid: false, title: 'Dosya Seçilmedi', message: 'Lütfen geçerli bir dosya seçin.' };
  }
  const lower = file.name.toLowerCase();
  const hasExt = ALLOWED_UPLOAD_EXTS.some(ext => lower.endsWith(ext));
  if (!hasExt) {
    return {
      valid: false,
      title: 'Desteklenmeyen Dosya Uzantısı',
      message: `"${file.name}" geçerli bir Android paketi değil. Desteklenen biçimler: .apk, .xapk, .apks, .apkm, .zip ve .obb`,
    };
  }
  if (!Number.isFinite(file.size) || file.size <= 0) {
    return {
      valid: false,
      title: 'Boş Dosya (0 Bayt)',
      message: '0 bayt boyutundaki dosyalar analiz edilemez veya yüklenemez.',
    };
  }
  if (file.size > maxBytes) {
    const sizeGB = (file.size / (1024 * 1024 * 1024)).toFixed(2);
    const maxGB = (maxBytes / (1024 * 1024 * 1024)).toFixed(2);
    return {
      valid: false,
      title: `Maksimum ${maxGB} GB Dosya Boyutu Aşıldı!`,
      message: `Seçilen paket (${sizeGB} GB), desteklenen maksimum ${maxGB} GB sınırını aşıyor.`,
    };
  }
  return { valid: true };
}

export function validateApkObbPair({ apkFile, obbFile, packageId, apkHeaderBytes = null, maxBytes = MAX_FILE_BYTES }) {
  const pkgId = String(packageId || '').trim();
  if (!apkFile || !obbFile) {
    return { valid: false, error: 'Hem bir APK hem de bir OBB dosyası seçmelisiniz.' };
  }
  if (!String(apkFile.name || '').toLowerCase().endsWith('.apk')) {
    return { valid: false, error: 'İlk alan için .apk uzantılı bir dosya seçilmelidir.' };
  }
  if (!String(obbFile.name || '').toLowerCase().endsWith('.obb')) {
    return { valid: false, error: 'İkinci alan için .obb uzantılı bir dosya seçilmelidir.' };
  }
  if (!apkFile.size || !obbFile.size) {
    return { valid: false, error: 'Boş (0 bayt) APK veya OBB dosyası kullanılamaz.' };
  }
  const totalBytes = apkFile.size + obbFile.size;
  if (apkFile.size > maxBytes || obbFile.size > maxBytes || totalBytes > maxBytes) {
    return { valid: false, error: 'APK + OBB toplam boyutu 5 GB sınırını aşıyor.' };
  }
  if (apkHeaderBytes) {
    const arr = apkHeaderBytes instanceof Uint8Array ? apkHeaderBytes : new Uint8Array(apkHeaderBytes);
    if (arr.length < 2 || arr[0] !== 0x50 || arr[1] !== 0x4b) {
      return { valid: false, error: 'Seçilen APK dosyasında geçerli PK/ZIP bayt başlığı (0x504B) bulunamadı.' };
    }
  }
  if (!validPackageId(pkgId)) {
    return { valid: false, error: 'Paket kimliği geçersiz. Örnek biçim: com.studyo.oyun' };
  }

  const obbName = String(obbFile.name);
  const obbMatch = obbName.match(/^(main|patch)\.(\d+)\.([A-Za-z0-9_.]+)\.obb$/i);
  if (obbMatch && obbMatch[3] !== pkgId) {
    return {
      valid: false,
      error: `OBB dosyasındaki paket kimliği (${obbMatch[3]}) ile girilen kimlik (${pkgId}) birebir (büyük/küçük harf dahil) eşleşmiyor.`,
    };
  }
  const resolvedObbName = obbMatch ? obbName : `main.1.${pkgId}.obb`;
  return {
    valid: true,
    packageId: pkgId,
    resolvedObbName,
    isStandardObbName: Boolean(obbMatch),
    totalBytes,
  };
}

export function syncPairMetadataWithServer(pairState, serverData) {
  const srvPkg = String(serverData?.packageId || '').trim();
  const isRealPkg = Boolean(srvPkg && srvPkg.toLowerCase() !== 'bilinmiyor' && validPackageId(srvPkg));
  const nextPkgId = isRealPkg ? srvPkg : pairState.packageId;
  const verCodeRaw = String(serverData?.versionCode || '').trim();
  const verCode = /^\d+$/.test(verCodeRaw) ? verCodeRaw : '1';
  const rawObbName = String(pairState.obbFile?.name || pairState.obbName || '');
  const obbMatch = rawObbName.match(/^(main|patch)\.(\d+)\.([A-Za-z0-9_.]+)\.obb$/i);
  const nextObbName = (obbMatch && obbMatch[3] === nextPkgId)
    ? rawObbName
    : `main.${verCode}.${nextPkgId}.obb`;

  return {
    packageId: nextPkgId,
    versionCode: verCode,
    resolvedObbName: nextObbName,
    changed: nextPkgId !== pairState.packageId || nextObbName !== pairState.resolvedObbName,
  };
}

export function resolveActiveObbFiles(sessionStore, scopeId, staged = []) {
  if (scopeId) {
    const entry = sessionStore ? sessionStore.get(scopeId) : null;
    return Array.isArray(entry?.obbFolderFiles) ? entry.obbFolderFiles : [];
  }
  return Array.isArray(staged) ? staged : [];
}

export function resolveObbUploadTarget(selectedPkg, lastPatched) {
  if (selectedPkg) {
    if (selectedPkg.serverJobId) {
      return { ok: true, game: selectedPkg, jobId: selectedPkg.serverJobId };
    }
    if (lastPatched && selectedPkg.id === lastPatched.id && lastPatched.serverJobId) {
      return { ok: true, game: lastPatched, jobId: lastPatched.serverJobId };
    }
    return {
      ok: false,
      game: selectedPkg,
      jobId: null,
      reason: 'Seçili paket henüz sunucuda analiz edilmedi (örnek veya yerel paket). Önce gerçek APK yükleyip sunucu analizini tamamlayın.',
    };
  }
  if (lastPatched && lastPatched.serverJobId) {
    return { ok: true, game: lastPatched, jobId: lastPatched.serverJobId };
  }
  return {
    ok: false,
    game: null,
    jobId: null,
    reason: 'Önce sunucuda analiz edilmiş bir APK seçin.',
  };
}

export function buildScopedObbUploadPlan(sessionStore, gameId) {
  if (!sessionStore || !gameId) return [];
  const entry = sessionStore.get(gameId);
  if (!isPlainObject(entry)) return [];

  if (Array.isArray(entry.obbFolderFiles) && entry.obbFolderFiles.length > 0) {
    return entry.obbFolderFiles.map((file, idx) => ({
      file,
      uploadName: file.webkitRelativePath || file.name || `obb_${idx}.obb`,
    }));
  }
  if (entry.obbFile) {
    return [{
      file: entry.obbFile,
      uploadName: entry.obbTargetName || entry.obbFile.name || 'main.1.unknown.obb',
    }];
  }
  return [];
}

export function mergeSessionEntryOnUpsert({
  oldEntry = null,
  curEntry = null,
  pkg = null,
  serverSignedResult = null,
} = {}) {
  const oldObj = isPlainObject(oldEntry) ? oldEntry : null;
  const curObj = isPlainObject(curEntry) ? curEntry : {};
  const pkgObj = isPlainObject(pkg) ? pkg : {};
  const nextEntry = {};

  const hasNewSingle = Boolean(pkgObj.rawFile || curObj.singleFile);
  const hasNewPair = Boolean((pkgObj.apkFile && pkgObj.obbFile) || (curObj.apkFile && curObj.obbFile));

  if (hasNewSingle) {
    nextEntry.singleFile = pkgObj.rawFile || curObj.singleFile;
    nextEntry.obbFolderFiles = Array.isArray(curObj.obbFolderFiles) ? curObj.obbFolderFiles : [];
  } else if (hasNewPair) {
    nextEntry.apkFile = pkgObj.apkFile || curObj.apkFile;
    nextEntry.obbFile = pkgObj.obbFile || curObj.obbFile;
    nextEntry.obbTargetName = pkgObj.obbTargetName || curObj.obbTargetName;
    nextEntry.obbFolderFiles = Array.isArray(curObj.obbFolderFiles) ? curObj.obbFolderFiles : [];
  } else {
    if (oldObj?.singleFile) nextEntry.singleFile = oldObj.singleFile;
    else if (oldObj?.apkFile && oldObj?.obbFile) {
      nextEntry.apkFile = oldObj.apkFile;
      nextEntry.obbFile = oldObj.obbFile;
      if (oldObj.obbTargetName) nextEntry.obbTargetName = oldObj.obbTargetName;
    }
    if (Array.isArray(curObj.obbFolderFiles)) {
      nextEntry.obbFolderFiles = curObj.obbFolderFiles;
    }
  }

  if (serverSignedResult && isPlainObject(serverSignedResult)) {
    const activeJobId = pkgObj.serverJobId || serverSignedResult.jobId || null;
    nextEntry.serverJobId = activeJobId;
    nextEntry.serverDownloadUrl = serverSignedResult.downloadUrl;
    nextEntry.serverFileName = serverSignedResult.fileName;
    nextEntry.serverVerified = Boolean(serverSignedResult.verified);
    nextEntry.serverTargetSdk = serverSignedResult.targetSdk;
    nextEntry.serverIs32BitOnly = Boolean(serverSignedResult.is32BitOnly);
    nextEntry.serverSplitBundle = serverSignedResult.splitBundle || null;
    nextEntry.serverObbDownloads = Array.isArray(serverSignedResult.obbDownloads)
      ? serverSignedResult.obbDownloads
      : [];

    const curJobMatches = Boolean(
      activeJobId
      && curObj.serverObbUploaded
      && curObj.obbUploadedJobId === activeJobId
    );
    const oldJobMatches = Boolean(
      activeJobId
      && oldObj?.serverObbUploaded
      && oldObj?.obbUploadedJobId === activeJobId
      && oldObj?.serverJobId === activeJobId
    );
    if (curJobMatches || oldJobMatches) {
      nextEntry.serverObbUploaded = true;
      nextEntry.obbUploadedJobId = activeJobId;
    }
  }

  return nextEntry;
}

export function canOfferFullXapk(game, entry, sessionStore = null) {
  if (!isPlainObject(game) || !isPlainObject(entry)) return false;
  const activeJobId = game.serverJobId || entry.serverJobId || null;
  if (!activeJobId || !entry.serverVerified) return false;
  const scopedObbs = sessionStore ? buildScopedObbUploadPlan(sessionStore, game.id) : [];
  const uploadedForThisJob = Boolean(
    entry.serverObbUploaded
    && entry.obbUploadedJobId === activeJobId
  );
  return Boolean(
    game.hasObb
    || scopedObbs.length > 0
    || uploadedForThisJob
    || (Array.isArray(entry.serverObbDownloads) && entry.serverObbDownloads.length > 0)
  );
}

export function pushModalStackEntry(stack, modalId, activeEl = null, modalContainsActive = false) {
  if (!Array.isArray(stack) || !modalId) return null;
  const existingIdx = stack.findIndex(m => m && m.id === modalId);
  let preservedTrigger = null;
  if (existingIdx >= 0) {
    preservedTrigger = stack[existingIdx].triggerEl || null;
    stack.splice(existingIdx, 1);
  }
  const triggerEl = existingIdx >= 0
    ? preservedTrigger
    : (!modalContainsActive && activeEl ? activeEl : null);
  const entry = { id: modalId, triggerEl };
  stack.push(entry);
  return entry;
}

export function buildObbChunkInitFlags(fileIndex) {
  return { replaceExisting: fileIndex === 0 ? 'true' : 'false' };
}

export function isActiveJobStatus(status) {
  return ACTIVE_JOB_STATUSES.has(String(status || '').toLowerCase());
}

export function isTerminalJobStatus(status) {
  return TERMINAL_JOB_STATUSES.has(String(status || '').toLowerCase());
}

export function computeMonotonicProgress(currentPct, nextPct) {
  const cur = Number.isFinite(Number(currentPct)) ? Number(currentPct) : 0;
  const nxt = Number.isFinite(Number(nextPct)) ? Math.round(Number(nextPct)) : cur;
  return Math.max(cur, Math.min(100, Math.max(0, nxt)));
}

export function resolveSplitBundleFileName(splitBundle) {
  if (!isPlainObject(splitBundle)) return 'SplitPaket.apks';
  return String(splitBundle.fileName || splitBundle.name || 'SplitPaket.apks');
}

export function resolveElf16kReport(source) {
  if (!isPlainObject(source)) return null;
  if (isPlainObject(source.elf16k)) return source.elf16k;
  if (isPlainObject(source.inspector?.elf16k)) return source.inspector.elf16k;
  if (isPlainObject(source.elf16kReport)) return source.elf16kReport;
  return null;
}

export function resolveAuthoritativeHasObb(serverData, fallbackHasObb = false) {
  if (serverData && Array.isArray(serverData.obbFiles)) {
    return serverData.obbFiles.length > 0;
  }
  if (serverData && typeof serverData.hasObb === 'boolean') {
    return serverData.hasObb;
  }
  return Boolean(fallbackHasObb);
}

export function buildPatchSignParams(input = {}) {
  const mode = input.mode === 'resign_only' ? 'resign_only' : 'patch_and_sign';
  const rawSdk = Number(input.targetSdk);
  const clampedSdk = Number.isFinite(rawSdk)
    ? Math.min(36, Math.max(24, Math.round(rawSdk)))
    : 28;
  const isResignOnly = mode === 'resign_only';
  return {
    jobId: String(input.jobId || ''),
    targetSdk: String(clampedSdk),
    mode,
    resign: String(input.resign !== undefined ? Boolean(input.resign) : true),
    background: String(input.background !== undefined ? Boolean(input.background) : true),
    patchTargetSdk: String(isResignOnly ? false : (input.patchTargetSdk !== undefined ? Boolean(input.patchTargetSdk) : true)),
    addLegacyStorage: String(isResignOnly ? false : Boolean(input.addLegacyStorage)),
    enableCleartext: String(isResignOnly ? false : Boolean(input.enableCleartext)),
    addNotchSupport: String(isResignOnly ? false : Boolean(input.addNotchSupport)),
    forceExtractNativeLibs: String(isResignOnly ? false : Boolean(input.forceExtractNativeLibs)),
    allowDowngrade: String(isResignOnly ? false : Boolean(input.allowDowngrade)),
  };
}

export function applyServerPatchResultToGame(game, serverResult) {
  if (!isPlainObject(serverResult)) return { ...game };
  const next = { ...game };
  if (serverResult.targetSdk) {
    next.legacyApi = Number(serverResult.targetSdk);
    next.minSdk = Number(serverResult.minSdk || next.minSdk || 0);
    next.legacyAndroid = formatSdkSummary(`targetSdk ${serverResult.targetSdk}`, serverResult.targetSdk, next.minSdk);
  }
  if (serverResult.packageId && serverResult.packageId.toLowerCase() !== 'bilinmiyor') {
    next.packageId = serverResult.packageId;
  }
  if (serverResult.appLabel) next.name = serverResult.appLabel;
  if (typeof serverResult.sizeMB === 'number' && serverResult.sizeMB > 0) {
    next.sizeMB = serverResult.sizeMB;
  } else if (typeof serverResult.sizeBytes === 'number' && serverResult.sizeBytes > 0) {
    next.sizeMB = Number((serverResult.sizeBytes / 1048576).toFixed(2));
  }
  if (Array.isArray(serverResult.abis) && serverResult.abis.length > 0) {
    next.arch = serverResult.abis.join(', ');
  }
  if (typeof serverResult.is32BitOnly === 'boolean') {
    next.is32BitOnly = serverResult.is32BitOnly;
  }
  if (isPlainObject(serverResult.inspector)) {
    next.inspector = serverResult.inspector;
    if (typeof serverResult.inspector.compatScore === 'number') {
      next.compatScore = serverResult.inspector.compatScore;
    }
  } else if (typeof serverResult.compatScore === 'number') {
    next.compatScore = serverResult.compatScore;
  }
  if (isPlainObject(serverResult.patchSummary)) {
    next.patchSummary = serverResult.patchSummary;
  }
  if (typeof serverResult.repatchAvailable === 'boolean') {
    next.repatchAvailable = serverResult.repatchAvailable;
  }
  if (serverResult.jobId) next.serverJobId = serverResult.jobId;
  return next;
}

export function upsertGameInLibrary(games, newGame, { isLocalSimulation = false } = {}) {
  const list = Array.isArray(games) ? games.slice() : [];
  const candidate = { ...newGame };
  if (isLocalSimulation) {
    delete candidate.serverJobId;
    delete candidate.patchSummary;
    delete candidate.repatchAvailable;
  }

  let existingIdx = list.findIndex(g => g.id === candidate.id);
  if (existingIdx < 0 && validPackageId(candidate.packageId)) {
    existingIdx = list.findIndex(g => g.packageId === candidate.packageId);
  }
  if (existingIdx < 0 && !validPackageId(candidate.packageId)) {
    existingIdx = list.findIndex(g => g.fileName === candidate.fileName);
  }

  let replacedOldId = null;
  if (existingIdx >= 0) {
    const existing = list[existingIdx];
    replacedOldId = existing.id !== candidate.id ? existing.id : null;
    if (isPlainObject(existing.settings)) {
      candidate.settings = {
        ...candidate.settings,
        ...existing.settings,
        controlLayout: {
          ...controlLayoutDefaults(),
          ...(isPlainObject(candidate.settings?.controlLayout) ? candidate.settings.controlLayout : {}),
          ...(isPlainObject(existing.settings?.controlLayout) ? existing.settings.controlLayout : {}),
          mapping: {
            ...controlLayoutDefaults().mapping,
            ...(isPlainObject(candidate.settings?.controlLayout?.mapping) ? candidate.settings.controlLayout.mapping : {}),
            ...(isPlainObject(existing.settings?.controlLayout?.mapping) ? existing.settings.controlLayout.mapping : {}),
          },
        },
      };
    }
    list[existingIdx] = candidate;
    return { games: list, replacedOldId, index: existingIdx };
  }

  list.unshift(candidate);
  return { games: list, replacedOldId: null, index: 0 };
}

export function computeJobExpiresInSeconds(job, serverTime = null, ttlSeconds = 3600) {
  if (!job || typeof job !== 'object') return 0;
  if (typeof job.expiresInSeconds === 'number' && Number.isFinite(job.expiresInSeconds)) {
    return Math.max(0, Math.round(job.expiresInSeconds));
  }
  const srvNow = Number(serverTime);
  const expiryBase = Number(job.finishedAt || job.updatedAt || job.createdAt || 0);
  if (!Number.isFinite(srvNow) || srvNow <= 0 || expiryBase <= 0) return 0;
  return Math.max(0, Math.round(ttlSeconds - Math.max(0, srvNow - expiryBase)));
}

export function filterLibraryGames(games, filter = 'ALL', searchQuery = '') {
  const q = String(searchQuery || '').trim().toLowerCase();
  return (Array.isArray(games) ? games : []).filter(g => {
    const matchesQuery = !q
      || String(g.name || '').toLowerCase().includes(q)
      || String(g.legacyAndroid || '').toLowerCase().includes(q)
      || String(g.ext || '').toLowerCase().includes(q)
      || String(g.packageId || '').toLowerCase().includes(q);
    if (!matchesQuery) return false;
    if (filter === 'XAPK') return isContainerFormat(g.ext);
    if (filter === 'APK') return String(g.ext || '').toUpperCase() === 'APK';
    if (filter === 'BRIDGE') {
      return Boolean(
        g.is32BitOnly
        || /armv7|armeabi|armv5|x86(?!_64)/i.test(String(g.arch || ''))
        || (Array.isArray(g.modules) && g.modules.includes('abiAudit'))
      );
    }
    return true;
  });
}

export function computeStorageBreakdown(games, cacheMB = 0, quotaMB = SANDBOX_QUOTA_MB) {
  const list = Array.isArray(games) ? games : [];
  let containerMB = 0;
  let apkMB = 0;
  let largestMB = 0;

  for (const g of list) {
    const sz = Number.isFinite(Number(g.sizeMB)) && Number(g.sizeMB) >= 0 ? Number(g.sizeMB) : 0;
    if (sz > largestMB) largestMB = sz;
    if (isContainerFormat(g.ext)) containerMB += sz;
    else apkMB += sz;
  }

  const safeCacheMB = Number.isFinite(Number(cacheMB)) && Number(cacheMB) >= 0 ? Number(cacheMB) : 0;
  const totalUsedMB = containerMB + apkMB + safeCacheMB;
  const freeMB = Math.max(0, quotaMB - totalUsedMB);
  const usedPct = quotaMB > 0 ? Math.min(100, (totalUsedMB / quotaMB) * 100) : 0;

  // Proportional SVG donut normalization (never overflows 360° when totalUsedMB > quotaMB)
  const C = DONUT_CIRCUMFERENCE;
  const denom = Math.max(quotaMB, totalUsedMB, 1);
  let containerArc = (containerMB / denom) * C;
  let apkArc = (apkMB / denom) * C;
  let cacheArc = (safeCacheMB / denom) * C;

  const arcSum = containerArc + apkArc + cacheArc;
  if (arcSum > C) {
    const scale = C / arcSum;
    containerArc *= scale;
    apkArc *= scale;
    cacheArc *= scale;
  }

  return {
    containerMB,
    apkMB,
    cacheMB: safeCacheMB,
    totalUsedMB,
    freeMB,
    usedPct,
    largestMB,
    largestPct: Math.min(100, (largestMB / 5120) * 100),
    circumference: C,
    arcs: {
      container: containerArc,
      apk: apkArc,
      cache: cacheArc,
      apkOffset: -containerArc,
      cacheOffset: -(containerArc + apkArc),
    },
  };
}

export function validateControlMapping(mapping) {
  const byCode = new Map();
  const actions = Object.keys(CONTROL_ACTION_LABELS);
  for (const action of actions) {
    const code = mapping?.[action];
    if (!code) continue;
    if (!byCode.has(code)) byCode.set(code, []);
    byCode.get(code).push(action);
  }
  const duplicates = [];
  for (const [code, controls] of byCode.entries()) {
    if (controls.length > 1) {
      duplicates.push({ code, controls });
    }
  }
  return { valid: duplicates.length === 0, duplicates };
}

export function computeSandboxStep({ player, keys, dt, width, height, speedPxPerSec = 252 }) {
  const safeDt = Math.min(0.1, Math.max(0, Number(dt) || 0));
  const step = speedPxPerSec * safeDt;
  let x = Number(player.x) || 0;
  let y = Number(player.y) || 0;
  let pulse = Number(player.pulse) || 0;

  const keySet = keys instanceof Set ? keys : new Set(Array.isArray(keys) ? keys : []);
  if (keySet.has('UP')) y -= step;
  if (keySet.has('DOWN')) y += step;
  if (keySet.has('LEFT')) x -= step;
  if (keySet.has('RIGHT')) x += step;
  if (keySet.has('A') || keySet.has('X')) pulse = 1;
  else pulse *= Math.pow(0.9, safeDt * 60);

  const margin = 30;
  const maxX = Math.max(margin, (Number(width) || 300) - margin);
  const maxY = Math.max(margin, (Number(height) || 200) - margin);
  x = Math.max(margin, Math.min(maxX, x));
  y = Math.max(margin, Math.min(maxY, y));

  return { x, y, pulse };
}

export function computeHiDpiDimensions(cssWidth, cssHeight, devicePixelRatio = 1) {
  const w = Math.max(1, Math.round(Number(cssWidth) || 1));
  const h = Math.max(1, Math.round(Number(cssHeight) || 1));
  const dpr = Math.min(3, Math.max(1, Number(devicePixelRatio) || 1));
  return {
    cssWidth: w,
    cssHeight: h,
    dpr,
    backingWidth: Math.round(w * dpr),
    backingHeight: Math.round(h * dpr),
  };
}

export function checkClientZipBudget(files, maxBytes = CLIENT_ZIP_MAX_BYTES) {
  const list = Array.isArray(files) ? files : [];
  let totalBytes = 0;
  for (const f of list) {
    if (f && Number.isFinite(Number(f.size))) {
      totalBytes += Math.max(0, Number(f.size));
    }
  }
  if (totalBytes > maxBytes) {
    return {
      ok: false,
      totalBytes,
      maxBytes,
      reason: `Tarayıcı ZIP limiti (${Math.round(maxBytes / 1048576)} MB) aşıldı (${formatSizeFromMB(totalBytes / 1048576)}). Doğrudan indirme veya Sunucu Tam XAPK seçeneğini kullanın.`,
    };
  }
  return { ok: true, totalBytes, maxBytes };
}

// ============================================================================
// 3. BROWSER RUNTIME (GUARDED FOR SAFE NODE.JS ESM IMPORT)
// ============================================================================

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  bootBrowserApp();
}

function bootBrowserApp() {
  // --- Runtime State ---
  let appState = loadState();
  let currentFilter = 'ALL';
  let currentSearch = '';
  let selectedPackage = null;
  let activeModuleIds = new Set(PATCH_MODULES.map(m => m.id));
  let isUploading = false;
  let isPatching = false;
  let isBuildingFullXapk = false;
  let isExportingZip = false;
  let lastPatchedGame = null;
  let editingGameId = null;
  let confirmCallback = null;
  let downloadingTarget = null;

  // Per-game / per-job scoped session store (binary Files, scoped OBBs, server artifacts)
  const sessionFileStore = new Map();
  let stagedObbFiles = []; // Used only before a package is selected; scoped upon attach

  let pairedApkFile = null;
  let pairedObbFile = null;
  let pairedPackageId = '';

  let renderServerOnline = false;
  let renderAuthRequired = false;
  let renderMaxUploadMB = 5120;
  let renderChunkSizeMB = 8;
  let lastKeystoreSha256 = '';
  let healthCheckSeq = 0;
  let patchLinkExpiryTimer = null;

  // Cancellation controllers
  let activeUploadController = null;
  let activePollController = null;
  let activeServerJobId = null;

  // Sandbox state
  let sandboxAnimFrame = null;
  let sandboxTelemetryInterval = null;
  let sandboxActiveGame = null;
  let sandboxHudVisible = true;
  let sandboxVpadVisible = true;
  let sandboxCanvasMetrics = { cssWidth: 640, cssHeight: 400, dpr: 1 };
  let sandboxPlayerRef = null;
  let sandboxStarsRef = [];
  const pressedKeys = new Set();
  let sandboxTimeouts = [];

  // WCAG Focus Trap / Restore stack
  const openModalStack = []; // [{ id, triggerEl }]

  // --- Safe DOM Helpers (Zero innerHTML) ---
  function byId(id) {
    return document.getElementById(id);
  }

  function clearNode(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function createStaticSvg(iconKey) {
    const markup = ownGet(STATIC_SVGS, iconKey) || STATIC_SVGS.arcade;
    const doc = new DOMParser().parseFromString(markup, 'image/svg+xml');
    const svgEl = doc.documentElement;
    return document.importNode(svgEl, true);
  }

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'className') node.className = v;
      else if (k === 'textContent') node.textContent = String(v);
      else if (k === 'dataset' && typeof v === 'object') {
        for (const [dk, dv] of Object.entries(v)) {
          if (dv !== undefined && dv !== null) node.dataset[dk] = String(dv);
        }
      } else if (k === 'checked' || k === 'disabled' || k === 'selected') {
        node[k] = Boolean(v);
      } else {
        node.setAttribute(k, v === true ? '' : String(v));
      }
    }
    const list = Array.isArray(children) ? children : [children];
    for (const child of list) {
      if (child === null || child === undefined || child === false) continue;
      if (typeof child === 'string' || typeof child === 'number') {
        node.appendChild(document.createTextNode(String(child)));
      } else {
        node.appendChild(child);
      }
    }
    return node;
  }

  // --- Session & Local Storage Helpers ---
  function getApiToken() {
    try {
      const raw = sessionStorage.getItem(API_TOKEN_SESSION_KEY) || '';
      const check = validateApiToken(raw);
      return check.valid ? check.token : '';
    } catch {
      return '';
    }
  }

  function setApiToken(token) {
    const check = validateApiToken(token);
    if (!check.valid) return false;
    try {
      if (check.token) sessionStorage.setItem(API_TOKEN_SESSION_KEY, check.token);
      else sessionStorage.removeItem(API_TOKEN_SESSION_KEY);
    } catch {
      // sessionStorage unavailable
    }
    return true;
  }

  function getSavedUploadSession() {
    try {
      const raw = sessionStorage.getItem(UPLOAD_SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function saveUploadSession(sessionObj) {
    try {
      if (sessionObj) sessionStorage.setItem(UPLOAD_SESSION_KEY, JSON.stringify(sessionObj));
      else sessionStorage.removeItem(UPLOAD_SESSION_KEY);
    } catch {
      // ignore storage quota
    }
  }

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return createDefaultState();
      const parsed = JSON.parse(raw);
      return sanitizeAppState(parsed);
    } catch (err) {
      console.warn('Kayıtlı veri okunamadı; varsayılan durum yüklendi:', err);
      return createDefaultState();
    }
  }

  function saveState() {
    try {
      const clean = sanitizeAppState(appState);
      appState = clean;
      localStorage.setItem(STORAGE_KEY, JSON.stringify(clean));
    } catch (err) {
      console.warn('Yerel kayıt yapılamadı:', err);
      showToast('Ayarlar kaydedilemedi. Tarayıcı depolama alanını kontrol edin.', 'error');
    }
  }

  function getRenderApiBase() {
    const check = validateRenderApiUrl(appState.renderApiUrl || '');
    return check.valid ? check.normalized : '';
  }

  // --- Toast & Clipboard ---
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      // fallback below
    }
    const ta = el('textarea', { className: 'sr-only' });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {
      ok = false;
    }
    ta.remove();
    return ok;
  }

  function showToast(message, type = 'success') {
    const container = byId('toast-container');
    if (!container) return;
    const dotType = type === 'error' ? 'rose' : type === 'warn' ? 'amber' : type === 'info' ? 'sky' : 'emerald';
    const toast = el('div', { className: `rd-toast rd-toast--${type}` }, [
      el('span', { className: `rd-dot rd-dot--${dotType}` }),
      el('span', { textContent: message }),
    ]);
    container.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('rd-toast--leaving');
      setTimeout(() => toast.remove(), 260);
    }, 3400);
  }

  // --- Fetch With Timeout, Auth Headers & Abort Propagation ---
  async function fetchWithTimeout(url, options = {}, timeoutMs = 30000, parentSignal = null) {
    const controller = new AbortController();
    let timedOut = false;
    const onParentAbort = () => controller.abort();
    if (parentSignal) {
      if (parentSignal.aborted) {
        const abortErr = new DOMException('İşlem kullanıcı tarafından iptal edildi.', 'AbortError');
        throw abortErr;
      }
      parentSignal.addEventListener('abort', onParentAbort, { once: true });
    }
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    try {
      const mergedHeaders = new Headers(options.headers || {});
      const authHeaders = buildAuthHeaders(getApiToken());
      for (const [k, v] of Object.entries(authHeaders)) {
        if (!mergedHeaders.has(k)) mergedHeaders.set(k, v);
      }
      const res = await fetch(url, { ...options, headers: mergedHeaders, signal: controller.signal });
      return res;
    } catch (err) {
      if (timedOut) {
        throw new ApiHttpError('Sunucu isteği zaman aşımına uğradı.', 408);
      }
      throw err;
    } finally {
      clearTimeout(timer);
      if (parentSignal) parentSignal.removeEventListener('abort', onParentAbort);
    }
  }

  function handleUnauthorizedUI() {
    const tokenInput = byId('render-api-token');
    const authBadge = byId('render-auth-badge');
    if (tokenInput) {
      tokenInput.classList.add('rd-input--error');
      tokenInput.focus();
    }
    if (authBadge) {
      authBadge.textContent = 'Yetkisiz (401) — API Anahtarı Gerekli';
      authBadge.className = 'rd-badge rd-badge--rose';
    }
    showToast('Sunucu API anahtarı istiyor (HTTP 401). Lütfen geçerli anahtarı girip kaydedin.', 'error');
  }

  async function readJsonOrThrow(res, fallbackMsg) {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (res.status === 401) handleUnauthorizedUI();
      const retryAfterRaw = res.headers?.get('Retry-After');
      const retryAfter = retryAfterRaw ? Number(retryAfterRaw) : null;
      throw new ApiHttpError(
        data.detail || `${fallbackMsg} (HTTP ${res.status})`,
        res.status,
        Number.isFinite(retryAfter) ? retryAfter : null
      );
    }
    return data;
  }

  // --- WCAG 2.1 AA Focus Management & Modal Stack ---
  function getFocusableElements(container) {
    if (!container) return [];
    const selector = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    return Array.from(container.querySelectorAll(selector)).filter(node => node.offsetParent !== null);
  }

  function openDialogEl(modalEl) {
    if (!modalEl) return;
    const activeEl = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const insideModal = Boolean(activeEl && modalEl.contains(activeEl));
    modalEl.classList.remove('hidden');
    pushModalStackEntry(openModalStack, modalEl.id, activeEl, insideModal);
    const focusables = getFocusableElements(modalEl);
    if (focusables.length > 0) focusables[0].focus();
  }

  function closeDialogEl(modalEl) {
    if (!modalEl) return;
    modalEl.classList.add('hidden');
    const idx = openModalStack.findIndex(m => m.id === modalEl.id);
    let triggerEl = null;
    if (idx >= 0) {
      triggerEl = openModalStack[idx].triggerEl;
      openModalStack.splice(idx, 1);
    }
    if (triggerEl && typeof triggerEl.focus === 'function' && document.contains(triggerEl)) {
      triggerEl.focus();
    }
  }

  function handleGlobalFocusTrap(e) {
    if (e.key !== 'Tab' || openModalStack.length === 0) return;
    const top = openModalStack[openModalStack.length - 1];
    const modalEl = byId(top.id);
    if (!modalEl || modalEl.classList.contains('hidden')) return;
    const focusables = getFocusableElements(modalEl);
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (!modalEl.contains(document.activeElement)) {
      e.preventDefault();
      (e.shiftKey ? last : first).focus();
      return;
    }
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  // --- Safe Download Trigger ---
  function triggerServerFileDownload(rawPath, downloadName) {
    const safeUrl = buildSafeDownloadUrl(getRenderApiBase(), rawPath, getApiToken());
    if (!safeUrl) {
      showToast('Güvensiz veya geçersiz indirme adresi engellendi.', 'error');
      return false;
    }
    const anchor = el('a', {
      href: safeUrl,
      download: downloadName || 'retrodroid_paket',
      rel: 'noopener',
    });
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    return true;
  }

  function triggerBlobDownload(blobOrFile, downloadName) {
    const url = URL.createObjectURL(blobOrFile);
    const a = el('a', {
      href: url,
      download: downloadName,
      rel: 'noopener',
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  // ==========================================================================
  // 4. NAVIGATION (WCAG TABLIST + ARROW KEYS)
  // ==========================================================================
  function switchTab(tabId) {
    const targetId = ALLOWED_TABS.has(tabId) ? tabId : 'library';
    appState.activeTab = targetId;
    saveState();

    document.querySelectorAll('.tab-section').forEach(sec => {
      sec.classList.toggle('hidden', sec.id !== `tab-${targetId}`);
    });

    document.querySelectorAll('.nav-btn').forEach(btn => {
      const isActive = btn.dataset.tab === targetId;
      btn.classList.toggle('nav-btn--active', isActive);
      btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
      btn.tabIndex = isActive ? 0 : -1;
    });

    const mainEl = byId('main-content');
    if (mainEl) mainEl.scrollTop = 0;
    window.scrollTo(0, 0);

    if (targetId === 'system') renderSystemTab();
    if (targetId === 'library') renderLibrary();
    if (targetId === 'engine') renderEngineTab();
  }

  // ==========================================================================
  // 5. TAB 1: LIBRARY (ZERO XSS, CONSISTENT CONTAINER FILTERS)
  // ==========================================================================
  function getAccentTileClass(accent) {
    if (accent === 'sky') return 'rd-icon-tile--sky';
    if (accent === 'violet') return 'rd-icon-tile--violet';
    if (accent === 'amber') return 'rd-icon-tile--amber';
    return 'rd-icon-tile--emerald';
  }

  function renderLibrary() {
    const grid = byId('library-grid');
    const emptyBox = byId('library-empty');
    if (!grid || !emptyBox) return;

    const totalMB = appState.games.reduce((sum, g) => sum + (g.sizeMB || 0), 0);
    byId('stat-game-count').textContent = String(appState.games.length);
    byId('stat-total-size').textContent = formatSizeFromMB(totalMB);

    const filtered = filterLibraryGames(appState.games, currentFilter, currentSearch);
    clearNode(grid);

    if (filtered.length === 0) {
      emptyBox.classList.remove('hidden');
      return;
    }
    emptyBox.classList.add('hidden');

    for (const game of filtered) {
      const extBadgeClass = isContainerFormat(game.ext) ? 'rd-badge--emerald' : 'rd-badge--sky';
      const scoreBadgeClass = game.compatScore >= 85
        ? 'rd-badge--emerald'
        : game.compatScore >= 65
          ? 'rd-badge--sky'
          : 'rd-badge--amber';

      const iconTile = el('div', { className: `rd-icon-tile rd-icon-tile--lg ${getAccentTileClass(game.accent)}` }, [
        createStaticSvg(game.genre),
      ]);

      const badgesRow = el('div', { className: 'rd-row-wrap' }, [
        el('span', { className: 'rd-badge', textContent: `${game.settings.fps} FPS` }),
        el('span', { className: 'rd-badge rd-badge--sky', textContent: `Ölçek %${game.settings.resolutionScale}` }),
        game.is32BitOnly
          ? el('span', { className: 'rd-badge rd-badge--amber', textContent: '32-bit ABI' })
          : null,
        game.hasObb
          ? el('span', { className: 'rd-badge rd-badge--violet', textContent: 'OBB Mevcut' })
          : null,
        game.patchSummary?.manifestPatched
          ? el('span', { className: 'rd-badge rd-badge--emerald', textContent: 'Sunucuda Yamalandı' })
          : null,
        sessionFileStore.has(game.id)
          ? el('span', { className: 'rd-badge rd-badge--emerald', textContent: 'İndirmeye Hazır' })
          : null,
      ]);

      const card = el('article', { className: 'glass-card glass-card-hover rd-game-card' }, [
        el('div', { className: 'rd-stack-sm' }, [
          el('div', { className: 'rd-row-between' }, [
            el('div', { className: 'rd-row rd-min-w-0' }, [
              iconTile,
              el('div', { className: 'rd-min-w-0' }, [
                el('h3', { className: 'rd-game-title truncate', textContent: game.name }),
                el('div', { className: 'rd-game-meta' }, [
                  el('span', { className: `rd-badge ${extBadgeClass}`, textContent: game.ext }),
                  el('span', { className: 'mono', textContent: formatSizeFromMB(game.sizeMB) }),
                  el('span', { textContent: '•' }),
                  el('span', {
                    className: 'rd-game-meta-sdk',
                    textContent: formatSdkSummary(game.legacyAndroid, game.legacyApi, game.minSdk),
                  }),
                ]),
              ]),
            ]),
            el('span', { className: `rd-badge ${scoreBadgeClass} rd-shrink-0`, textContent: `%${game.compatScore}` }),
          ]),
          badgesRow,
        ]),
        el('div', { className: 'rd-row rd-divider' }, [
          el('button', {
            type: 'button',
            className: 'rd-btn neon-btn rd-flex-1',
            dataset: { action: 'launch', gameId: game.id },
          }, [
            createStaticSvg('play'),
            el('span', { textContent: 'Önizlemeyi Aç' }),
          ]),
          el('button', {
            type: 'button',
            className: 'rd-btn rd-btn--sky rd-btn--icon',
            dataset: { action: 'download', gameId: game.id },
            'aria-label': `${game.name} dosyasını cihaza indir`,
            title: 'Dosyayı Cihaza İndir',
          }, [createStaticSvg('download')]),
          el('button', {
            type: 'button',
            className: 'rd-btn rd-btn--icon',
            dataset: { action: 'settings', gameId: game.id },
            'aria-label': `${game.name} ayarlarını aç`,
            title: 'Hızlı Ayarlar',
          }, [createStaticSvg('settings')]),
        ]),
      ]);
      grid.appendChild(card);
    }
  }

  // ==========================================================================
  // 6. SERVER HEALTH, AUTH TOKEN, KEYSTORE INFO & JOBS HISTORY (F01, F09, F10)
  // ==========================================================================
  function updateRenderStatusUI(state, text) {
    const dot = byId('render-status-dot');
    const lbl = byId('render-status-text');
    const hDot = byId('header-server-dot');
    const hLbl = byId('header-server-label');

    if (state === 'online') {
      if (dot) dot.className = 'rd-dot rd-dot--lg rd-dot--emerald';
      if (hDot) hDot.className = 'rd-dot rd-dot--emerald';
      if (hLbl) hLbl.textContent = 'Sunucu Aktif';
    } else if (state === 'degraded') {
      if (dot) dot.className = 'rd-dot rd-dot--lg rd-dot--amber';
      if (hDot) hDot.className = 'rd-dot rd-dot--amber';
      if (hLbl) hLbl.textContent = 'Sunucu Kısıtlı';
    } else if (state === 'waking') {
      if (dot) dot.className = 'rd-dot rd-dot--lg rd-dot--amber rd-dot--pulse';
      if (hDot) hDot.className = 'rd-dot rd-dot--amber rd-dot--pulse';
      if (hLbl) hLbl.textContent = 'Kontrol Ediliyor';
    } else {
      if (dot) dot.className = 'rd-dot rd-dot--lg rd-dot--slate';
      if (hDot) hDot.className = 'rd-dot rd-dot--slate';
      if (hLbl) hLbl.textContent = 'Yerel Mod';
    }
    if (lbl) lbl.textContent = text;
  }

  function renderServerHealthChips(data) {
    const chips = byId('server-health-chips');
    const authBadge = byId('render-auth-badge');
    if (!chips) return;
    clearNode(chips);

    if (!data) {
      chips.classList.add('hidden');
      return;
    }
    chips.classList.remove('hidden');

    const statusOk = data.status === 'ok';
    chips.appendChild(el('span', {
      className: `rd-badge ${statusOk ? 'rd-badge--emerald' : 'rd-badge--amber'}`,
      textContent: `Durum: ${statusOk ? 'Hazır (OK)' : 'Kısıtlı (Degraded)'}`,
    }));
    const freeDisk = data.diskFreeMB ?? data.freeDiskMB;
    if (typeof freeDisk === 'number') {
      chips.appendChild(el('span', {
        className: 'rd-badge rd-badge--sky mono',
        textContent: `Boş Disk: ${formatSizeFromMB(freeDisk)}`,
      }));
    }
    chips.appendChild(el('span', {
      className: `rd-badge ${data.zipalign16kSupported ? 'rd-badge--emerald' : 'rd-badge--amber'}`,
      textContent: data.zipalign16kSupported ? 'zipalign -P 16 KB ✓' : 'zipalign 4 KB (-p 4)',
    }));
    chips.appendChild(el('span', {
      className: `rd-badge ${data.authRequired ? 'rd-badge--indigo' : 'rd-badge--emerald'}`,
      textContent: data.authRequired ? 'API Anahtarı Zorunlu' : 'Açık Erişim',
    }));

    if (isPlainObject(data.toolVersions)) {
      const toolSummary = Object.entries(data.toolVersions)
        .filter(([, v]) => Boolean(v))
        .slice(0, 4)
        .map(([k, v]) => `${k}: ${String(v).split('\n')[0].slice(0, 24)}`)
        .join(' • ');
      if (toolSummary) {
        chips.appendChild(el('span', {
          className: 'rd-badge mono',
          textContent: toolSummary,
        }));
      }
    }

    if (authBadge) {
      renderAuthRequired = Boolean(data.authRequired);
      const hasToken = Boolean(getApiToken());
      if (renderAuthRequired && !hasToken) {
        authBadge.textContent = 'API Anahtarı Gerekli';
        authBadge.className = 'rd-badge rd-badge--amber';
      } else if (renderAuthRequired && hasToken) {
        authBadge.textContent = 'API Anahtarı Ayarlı';
        authBadge.className = 'rd-badge rd-badge--emerald';
      } else {
        authBadge.textContent = hasToken ? 'İsteğe Bağlı Anahtar Ayarlı' : 'Anahtar Gerekmiyor';
        authBadge.className = 'rd-badge';
      }
    }
  }

  async function refreshKeystoreInfo() {
    const box = byId('keystore-info-box');
    if (!box) return;
    if (!renderServerOnline || (renderAuthRequired && !getApiToken())) {
      box.classList.add('hidden');
      return;
    }
    const base = getRenderApiBase();
    try {
      const res = await fetchWithTimeout(`${base}/api/keystore-info`, { method: 'GET' }, 20000);
      if (res.status === 401) {
        handleUnauthorizedUI();
        box.classList.add('hidden');
        return;
      }
      if (!res.ok) {
        box.classList.add('hidden');
        return;
      }
      const info = await res.json();
      if (!info || !info.ready) {
        box.classList.add('hidden');
        return;
      }
      lastKeystoreSha256 = String(info.sha256 || '');
      byId('keystore-alias').textContent = info.alias || 'retrodroid';
      byId('keystore-algo').textContent = info.algorithm || 'RSA-2048';
      byId('keystore-persist').textContent = info.persistent ? 'Kalıcı Disk' : 'Geçici Depolama';
      byId('keystore-persist').className = `rd-badge ${info.persistent ? 'rd-badge--emerald' : 'rd-badge--amber'}`;
      byId('keystore-valid-until').textContent = info.validUntil ? `Geçerlilik: ${info.validUntil}` : '';
      byId('keystore-sha256').textContent = `SHA-256: ${lastKeystoreSha256 || '—'}`;
      box.classList.remove('hidden');
    } catch {
      box.classList.add('hidden');
    }
  }

  async function checkRenderServer(showNotification = false) {
    const seq = ++healthCheckSeq;
    const base = getRenderApiBase();
    const isLocalFileWithoutUrl = window.location.protocol === 'file:' && !base;
    if (isLocalFileWithoutUrl) {
      renderServerOnline = false;
      renderServerHealthChips(null);
      byId('keystore-info-box')?.classList.add('hidden');
      updateRenderStatusUI('offline', 'Yerel dosya modundasın. Gerçek APK imzalama için yukarıya sunucu adresini (https://...) gir.');
      return false;
    }

    updateRenderStatusUI('waking', 'APK sunucusuna bağlanılıyor (uyku modundaysa 30–55 sn sürebilir)...');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 55000);
    try {
      const res = await fetch(`${base}/health`, { signal: controller.signal });
      if (!res.ok) throw new ApiHttpError(`HTTP ${res.status}`, res.status);
      const data = await res.json();
      if (seq !== healthCheckSeq) return false; // Superseded by a newer check

      renderServerOnline = true;
      renderMaxUploadMB = Number(data.maxUploadMB) || 5120;
      renderChunkSizeMB = Number(data.chunkSizeMB) || 8;
      renderAuthRequired = Boolean(data.authRequired);

      const limitLabel = renderMaxUploadMB >= 1024
        ? `${(renderMaxUploadMB / 1024).toFixed(1)} GB`
        : `${renderMaxUploadMB} MB`;
      const healthState = data.status === 'degraded' ? 'degraded' : 'online';
      updateRenderStatusUI(
        healthState,
        `Bağlı: ${data.engine || `RetroDroid Server v${APP_VERSION}`} • Limit: ${limitLabel} (${renderChunkSizeMB} MB parça)${data.status === 'degraded' ? ' • Bazı araçlar eksik' : ''}`
      );
      renderServerHealthChips(data);

      const tokenInput = byId('render-api-token');
      if (tokenInput) tokenInput.classList.remove('rd-input--error');

      if (showNotification) {
        showToast(
          data.status === 'degraded'
            ? 'Sunucu bağlı ancak bazı Android araçları eksik (degraded).'
            : 'APK sunucusu aktif ve hazır!',
          data.status === 'degraded' ? 'warn' : 'success'
        );
      }

      if (!renderAuthRequired || getApiToken()) {
        await Promise.all([refreshKeystoreInfo(), refreshPatchJobsHistory()]);
      } else if (showNotification) {
        showToast('Bu sunucuda API_TOKEN koruması aktif. İşlem yapmak için anahtarı girin.', 'warn');
      }
      return true;
    } catch {
      if (seq !== healthCheckSeq) return false;
      renderServerOnline = false;
      renderServerHealthChips(null);
      byId('keystore-info-box')?.classList.add('hidden');
      updateRenderStatusUI('offline', 'APK sunucusuna ulaşılamadı (yerel tarayıcı modu aktif). Adresi kontrol edip tekrar deneyin.');
      if (showNotification) showToast('Sunucuya bağlanılamadı. Sunucu uyanıyor veya adres hatalı olabilir.', 'warn');
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  function clearLinkExpiryTimer() {
    if (patchLinkExpiryTimer) {
      clearInterval(patchLinkExpiryTimer);
      patchLinkExpiryTimer = null;
    }
    const elBox = byId('patch-link-expiry');
    if (elBox) {
      elBox.classList.add('hidden');
      elBox.textContent = '';
    }
  }

  function startLinkExpiryCountdown(seconds) {
    const elBox = byId('patch-link-expiry');
    if (!elBox) return;
    if (patchLinkExpiryTimer) {
      clearInterval(patchLinkExpiryTimer);
      patchLinkExpiryTimer = null;
    }
    if (!seconds || seconds <= 0) {
      elBox.classList.add('hidden');
      return;
    }
    elBox.classList.remove('hidden');
    const startedMono = performance.now();
    const initialSecs = Math.round(seconds);

    const update = () => {
      const elapsed = Math.floor((performance.now() - startedMono) / 1000);
      const left = Math.max(0, initialSecs - elapsed);
      if (left <= 0) {
        if (patchLinkExpiryTimer) {
          clearInterval(patchLinkExpiryTimer);
          patchLinkExpiryTimer = null;
        }
        elBox.textContent = 'İndirme linki süresi doldu (sunucu geçici dosyaları temizlenmiş olabilir).';
        return;
      }
      const m = Math.floor(left / 60);
      const s = left % 60;
      elBox.textContent = `Sunucu indirme linki yaklaşık ${m} dk ${String(s).padStart(2, '0')} sn daha geçerlidir.`;
    };
    update();
    patchLinkExpiryTimer = setInterval(update, 1000);
  }

  async function refreshPatchJobsHistory() {
    const listEl = byId('patch-jobs-list');
    if (!listEl) return 0;
    const base = getRenderApiBase();
    if (renderAuthRequired && !getApiToken()) {
      clearNode(listEl);
      listEl.appendChild(el('div', { className: 'rd-field-hint', textContent: 'İş geçmişini görmek için API anahtarını girin.' }));
      return 0;
    }
    try {
      const res = await fetchWithTimeout(`${base}/api/jobs`, { method: 'GET' }, 25000);
      if (!res.ok) {
        if (res.status === 401) handleUnauthorizedUI();
        return 0;
      }
      const data = await res.json();
      const jobs = Array.isArray(data.jobs) ? data.jobs : [];
      const ttlSeconds = Number(data.linkTtlSeconds) || 3600;
      const serverTime = Number(data.serverTime) || null;
      const token = getApiToken();

      clearNode(listEl);
      if (!jobs.length) {
        listEl.appendChild(el('div', { className: 'rd-field-hint', textContent: 'Henüz sunucu işi yok.' }));
        return 0;
      }

      for (const j of jobs) {
        if (!isPlainObject(j)) continue;
        const meta = ownGet(JOB_STATUS_META, j.status) || { label: String(j.status || 'Bilinmiyor'), badge: 'rd-badge' };
        const timeStr = j.createdAt ? new Date(j.createdAt * 1000).toLocaleTimeString('tr-TR') : '';
        const expSec = computeJobExpiresInSeconds(j, serverTime, ttlSeconds);
        const expText = expSec > 0 ? ` • ${Math.ceil(expSec / 60)} dk` : '';

        const actions = [];
        actions.push(el('span', { className: `rd-badge ${meta.badge}`, textContent: meta.label }));

        if (j.downloadUrl) {
          const safeApkUrl = buildSafeDownloadUrl(base, j.downloadUrl, token);
          if (safeApkUrl) {
            actions.push(el('a', {
              href: safeApkUrl,
              download: j.fileName || `${j.jobId}.apk`,
              rel: 'noopener',
              className: 'rd-btn rd-btn--xs rd-btn--emerald',
              textContent: 'APK',
            }));
          }
        }

        if (j.fullXapkStatus === 'done' && j.fullXapkDownloadUrl) {
          const safeXapkUrl = buildSafeDownloadUrl(base, j.fullXapkDownloadUrl, token);
          if (safeXapkUrl) {
            actions.push(el('a', {
              href: safeXapkUrl,
              download: `${j.packageId || j.jobId}_Full_Signed.xapk`,
              rel: 'noopener',
              className: 'rd-btn rd-btn--xs rd-btn--violet',
              textContent: 'Tam XAPK',
            }));
          }
        }

        const jobIsActive = isActiveJobStatus(j.status) || isActiveJobStatus(j.fullXapkStatus);
        if (jobIsActive) {
          actions.push(el('button', {
            type: 'button',
            className: 'rd-btn rd-btn--xs rd-btn--rose',
            dataset: { jobAction: 'cancel', jobId: j.jobId },
            textContent: 'İptal',
          }));
        } else {
          actions.push(el('button', {
            type: 'button',
            className: 'rd-btn rd-btn--xs',
            dataset: { jobAction: 'delete', jobId: j.jobId },
            'aria-label': `${j.fileName || j.jobId} işini sunucudan sil`,
            textContent: 'Sil',
          }));
        }

        const row = el('div', { className: 'rd-job-row' }, [
          el('div', { className: 'rd-min-w-0' }, [
            el('div', { className: 'rd-flag-title truncate', textContent: j.appLabel || j.fileName || j.jobId }),
            el('div', {
              className: 'rd-field-hint mono truncate',
              textContent: `${timeStr}${j.packageId ? ` • ${j.packageId}` : ''} • API ${j.targetSdk ?? '-'} • %${j.progress ?? 0}${expText}`,
            }),
          ]),
          el('div', { className: 'rd-row-wrap rd-shrink-0' }, actions),
        ]);
        listEl.appendChild(row);
      }

      const preferredJob = jobs.find(j => lastPatchedGame?.serverJobId && j.jobId === lastPatchedGame.serverJobId)
        || jobs.find(j => j.status === 'done');
      return preferredJob ? computeJobExpiresInSeconds(preferredJob, serverTime, ttlSeconds) : 0;
    } catch {
      return 0;
    }
  }

  async function cancelServerJob(jobId) {
    if (!jobId) return;
    const base = getRenderApiBase();
    try {
      const res = await fetchWithTimeout(`${base}/api/patch-cancel/${jobId}`, { method: 'POST' }, 20000);
      await readJsonOrThrow(res, 'İptal isteği başarısız');
      if (activePollController && activeServerJobId === jobId) {
        activePollController.abort();
      }
      showToast(`İş (${jobId}) için iptal komutu gönderildi.`, 'warn');
      refreshPatchJobsHistory();
    } catch (err) {
      showToast(`İş iptal edilemedi: ${err.message}`, 'error');
    }
  }

  async function deleteServerJob(jobId) {
    if (!jobId) return;
    const base = getRenderApiBase();
    try {
      const res = await fetchWithTimeout(`${base}/api/jobs/${jobId}`, { method: 'DELETE' }, 20000);
      await readJsonOrThrow(res, 'İş silinemedi');
      showToast(`Sunucu işi (${jobId}) temizlendi.`, 'info');
      if (lastPatchedGame?.serverJobId === jobId) {
        clearLinkExpiryTimer();
      }
      refreshPatchJobsHistory();
    } catch (err) {
      showToast(`İş silinemedi: ${err.message}`, 'error');
    }
  }

  // ==========================================================================
  // 7. RESUMABLE CHUNKED UPLOAD WITH CANCEL, 4XX FAIL-FAST & LIVE ETA (F03)
  // ==========================================================================
  function setUploadingLock(locked) {
    isUploading = locked;
    const dropzone = byId('dropzone');
    if (dropzone) {
      dropzone.classList.toggle('is-disabled', locked);
      dropzone.setAttribute('aria-busy', locked ? 'true' : 'false');
    }
    [
      'file-input',
      'btn-browse-file',
      'btn-pair-analyze',
      'btn-start-patch',
      'btn-browse-obb-folder',
      'btn-browse-obb-files',
      'btn-clear-obb-folder',
    ].forEach(id => {
      const node = byId(id);
      if (node) node.disabled = locked || (id === 'btn-start-patch' && isPatching);
    });
    const obbUploadBtn = byId('btn-upload-obb-folder');
    if (obbUploadBtn) {
      obbUploadBtn.disabled = locked || getActiveObbFiles().length === 0;
    }
    document.querySelectorAll('#demo-packages-grid button').forEach(btn => {
      btn.disabled = locked;
    });
  }

  function setRenderUploadProgress(visible, label = '', pct = 0, speedText = '') {
    const box = byId('render-upload-progress-box');
    if (!box) return;
    if (!visible) {
      box.classList.add('hidden');
      return;
    }
    box.classList.remove('hidden');
    byId('render-upload-label').textContent = label;
    byId('render-upload-pct').textContent = `${Math.round(pct)}%`;
    byId('render-upload-bar').style.width = `${Math.min(100, Math.max(0, pct))}%`;
    if (speedText !== undefined) {
      byId('render-upload-speed').textContent = speedText;
    }
  }

  async function uploadApkToRenderForAnalysis(file) {
    const base = getRenderApiBase();
    const totalSize = file.size;
    activeUploadController = new AbortController();
    const signal = activeUploadController.signal;
    setUploadingLock(true);

    try {
      let jobId = null;
      let chunkSizeBytes = Math.max(2, renderChunkSizeMB || 8) * 1024 * 1024;
      let totalChunks = Math.max(1, Math.ceil(totalSize / chunkSizeBytes));
      let receivedSet = new Set();

      // Step 1: Attempt resume from sessionStorage + GET /api/upload/status/{job_id}
      const saved = getSavedUploadSession();
      if (canResumeUploadSession(saved, file, base)) {
        setRenderUploadProgress(true, 'Önceki yükleme oturumu kontrol ediliyor...', 1, 'Sunucu durumu sorgulanıyor...');
        try {
          const stRes = await fetchWithTimeout(`${base}/api/upload/status/${saved.jobId}`, { method: 'GET' }, 30000, signal);
          if (stRes.ok) {
            const st = await stRes.json();
            if (st.status === 'uploading' && !st.complete && Number(st.totalSize) === totalSize) {
              jobId = st.jobId;
              const plan = computeUploadPlan(totalSize, st);
              chunkSizeBytes = plan.chunkSizeBytes;
              totalChunks = plan.totalChunks;
              receivedSet = new Set((st.receivedChunks || []).map(Number));
              setRenderUploadProgress(
                true,
                `Kaldığı yerden devam ediliyor (${receivedSet.size}/${totalChunks} parça)`,
                Math.min(94, (receivedSet.size / totalChunks) * 95),
                'Önceki parçalar korundu'
              );
            } else {
              saveUploadSession(null);
            }
          } else {
            saveUploadSession(null);
          }
        } catch (err) {
          if (err.name === 'AbortError') throw err;
          saveUploadSession(null);
        }
      }

      // Step 2: Initialize fresh session if not resumed (OMIT totalChunks so server chooses authoritative plan)
      if (!jobId) {
        setRenderUploadProgress(true, 'Sunucu yükleme oturumu açılıyor...', 1, 'Oturum hazırlanıyor...');
        const initFd = new FormData();
        initFd.append('fileName', file.name);
        initFd.append('totalSize', String(totalSize));
        initFd.append('purpose', 'apk');

        const initRes = await fetchWithTimeout(`${base}/api/upload/init`, { method: 'POST', body: initFd }, 60000, signal);
        const initData = await readJsonOrThrow(initRes, 'Yükleme oturumu başlatılamadı');
        jobId = initData.jobId;
        const plan = computeUploadPlan(totalSize, initData);
        chunkSizeBytes = plan.chunkSizeBytes;
        totalChunks = plan.totalChunks;
        saveUploadSession({
          base,
          fileName: file.name,
          totalSize,
          lastModified: file.lastModified || 0,
          jobId,
          chunkSizeBytes,
          totalChunks,
        });
      }

      // Step 3: Upload missing chunks with 4xx fail-fast, live MB/s + ETA
      const missingIndices = computeMissingChunkIndices(totalChunks, Array.from(receivedSet));
      let uploadedTotalBytes = Array.from(receivedSet).reduce(
        (acc, idx) => acc + Math.min(chunkSizeBytes, totalSize - idx * chunkSizeBytes),
        0
      );
      let sessionSentBytes = 0;
      const transferStartedAt = performance.now();

      for (const idx of missingIndices) {
        const start = idx * chunkSizeBytes;
        const end = Math.min(totalSize, start + chunkSizeBytes);
        const slice = file.slice(start, end);

        let chunkOk = false;
        let lastErr = null;
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            const cfd = new FormData();
            cfd.append('jobId', jobId);
            cfd.append('chunkIndex', String(idx));
            cfd.append('totalChunks', String(totalChunks));
            cfd.append('chunk', slice, `chunk_${idx}.part`);

            const cres = await fetchWithTimeout(`${base}/api/upload/chunk`, { method: 'POST', body: cfd }, 120000, signal);
            await readJsonOrThrow(cres, `Parça ${idx + 1} yükleme hatası`);
            chunkOk = true;
            break;
          } catch (err) {
            if (err.name === 'AbortError') throw err;
            lastErr = err;
            const status = err instanceof ApiHttpError ? err.status : 0;
            if (!shouldRetryHttpStatus(status)) {
              if (status >= 400 && status < 500) saveUploadSession(null);
              throw err;
            }
            const waitMs = (err instanceof ApiHttpError && err.retryAfter)
              ? Math.min(15, Math.max(1, err.retryAfter)) * 1000
              : 1000 * (attempt + 1);
            await new Promise((resolve, reject) => {
              const t = setTimeout(resolve, waitMs);
              signal.addEventListener('abort', () => {
                clearTimeout(t);
                reject(new DOMException('İşlem kullanıcı tarafından iptal edildi.', 'AbortError'));
              }, { once: true });
            });
          }
        }
        if (!chunkOk) throw lastErr || new Error('Parça aktarımı başarısız.');

        const chunkLen = end - start;
        uploadedTotalBytes += chunkLen;
        sessionSentBytes += chunkLen;
        receivedSet.add(idx);

        const elapsedSec = (performance.now() - transferStartedAt) / 1000;
        const remainingBytes = Math.max(0, totalSize - uploadedTotalBytes);
        const pct = Math.min(95, (uploadedTotalBytes / totalSize) * 95);
        setRenderUploadProgress(
          true,
          `Parçalı yükleme: ${formatSizeFromMB(uploadedTotalBytes / 1048576)} / ${formatSizeFromMB(totalSize / 1048576)} (${receivedSet.size}/${totalChunks})`,
          pct,
          formatSpeedAndEta(sessionSentBytes, elapsedSec, remainingBytes)
        );
      }

      // Step 4: Finalize & inspect on server (clear stale sessionStorage on permanent 4xx)
      setRenderUploadProgress(true, 'Sunucuda APK / XAPK manifest, ELF 16 KB ve imza analizi yapılıyor...', 97, 'Analiz ediliyor...');
      const finFd = new FormData();
      finFd.append('jobId', jobId);
      let finData;
      try {
        const finRes = await fetchWithTimeout(`${base}/api/upload/finish`, { method: 'POST', body: finFd }, 300000, signal);
        finData = await readJsonOrThrow(finRes, 'Sunucu analizi tamamlanamadı');
      } catch (finErr) {
        const finStatus = finErr instanceof ApiHttpError ? finErr.status : 0;
        if (shouldClearUploadSessionOnFinishError(finStatus)) {
          saveUploadSession(null);
        }
        throw finErr;
      }

      saveUploadSession(null);
      setRenderUploadProgress(true, 'Sunucu analizi tamamlandı!', 100, 'Tamamlandı');
      setTimeout(() => setRenderUploadProgress(false), 750);
      return finData;
    } catch (err) {
      setRenderUploadProgress(false);
      if (err.name === 'AbortError') {
        showToast('Yükleme iptal edildi. Aynı dosyayı yeniden seçerek kaldığınız yerden devam edebilirsiniz.', 'warn');
      }
      throw err;
    } finally {
      activeUploadController = null;
      setUploadingLock(false);
    }
  }

  // ==========================================================================
  // 8. SCOPED OBB MANAGEMENT, CHUNKED OBB UPLOAD & APK+OBB PAIRING (F08)
  // ==========================================================================
  function getActiveObbScopeId() {
    if (selectedPackage?.id) return selectedPackage.id;
    if (lastPatchedGame?.id) return lastPatchedGame.id;
    return null;
  }

  function getActiveObbFiles() {
    return resolveActiveObbFiles(sessionFileStore, getActiveObbScopeId(), stagedObbFiles);
  }

  function setActiveObbFiles(files) {
    const scopeId = getActiveObbScopeId();
    if (scopeId) {
      const entry = sessionFileStore.get(scopeId) || {};
      entry.obbFolderFiles = files;
      entry.obbUploadedJobId = '';
      entry.serverObbUploaded = false;
      sessionFileStore.set(scopeId, entry);
      stagedObbFiles = [];
    } else {
      stagedObbFiles = files;
    }
  }

  function setObbUploadProgress(visible, label = '', pct = 0) {
    const box = byId('obb-upload-progress-box');
    if (!box) return;
    if (!visible) {
      box.classList.add('hidden');
      return;
    }
    box.classList.remove('hidden');
    byId('obb-upload-label').textContent = label;
    byId('obb-upload-pct').textContent = `${Math.round(pct)}%`;
    byId('obb-upload-bar').style.width = `${Math.min(100, Math.max(0, pct))}%`;
  }

  function updateFullXapkButtonVisibility() {
    const fullXapkButton = byId('btn-download-full-xapk');
    if (!fullXapkButton || !lastPatchedGame) return;
    const saved = sessionFileStore.get(lastPatchedGame.id) || {};
    const canBuild = canOfferFullXapk(lastPatchedGame, saved, sessionFileStore);
    fullXapkButton.classList.toggle('hidden', !canBuild);
  }

  function renderObbFolderSelection() {
    const list = byId('obb-folder-list');
    const count = byId('obb-folder-count');
    const uploadBtn = byId('btn-upload-obb-folder');
    if (!list || !count || !uploadBtn) return;

    const files = getActiveObbFiles();
    const total = files.reduce((sum, file) => sum + (file.size || 0), 0);
    count.textContent = `${files.length} OBB • ${formatSizeFromMB(total / 1048576)}`;
    uploadBtn.disabled = isUploading || files.length === 0;

    clearNode(list);
    if (!files.length) {
      list.textContent = 'Bu paket için henüz OBB seçilmedi.';
    } else {
      for (const file of files) {
        const row = el('div', { className: 'rd-obb-item' }, [
          el('span', { className: 'truncate', textContent: file.webkitRelativePath || file.name }),
          el('span', { className: 'rd-shrink-0 mono', textContent: formatSizeFromMB(file.size / 1048576) }),
        ]);
        list.appendChild(row);
      }
    }
    updateFullXapkButtonVisibility();
  }

  function handleObbFilesPicked(fileList) {
    const picked = Array.from(fileList || []).filter(f => f.name.toLowerCase().endsWith('.obb') && f.size > 0);
    setActiveObbFiles(picked);
    renderObbFolderSelection();
    if (selectedPackage?.packageId && validPackageId(selectedPackage.packageId)) {
      byId('pair-package-id').value = selectedPackage.packageId;
    }
    byId('obb-folder-status').textContent = picked.length
      ? `${picked.length} adet .obb seçildi (yalnızca aktif pakete bağlı). Sunucu aktarımı için APK önce analiz edilmiş olmalı.`
      : 'Seçimde geçerli (boş olmayan) .obb dosyası bulunamadı.';
  }

  async function uploadObbFilesLegacyMultipart(jobId, items, signal = null) {
    const base = getRenderApiBase();
    const fd = new FormData();
    items.forEach((item, index) => {
      const uploadName = item.uploadName || item.file.webkitRelativePath || item.file.name || `obb_${index}.obb`;
      fd.append('files', item.file, uploadName);
    });
    const res = await fetchWithTimeout(`${base}/api/attach-obb/${jobId}`, { method: 'POST', body: fd }, 300000, signal);
    return readJsonOrThrow(res, 'OBB aktarımı başarısız');
  }

  async function uploadObbFilesToRender(jobId, rawItems) {
    if (!jobId || !Array.isArray(rawItems) || !rawItems.length) {
      throw new Error('Sunucu işi veya OBB dosyası bulunamadı.');
    }
    const items = rawItems.map((it, idx) => (
      it && it.file
        ? { file: it.file, uploadName: it.uploadName || it.file.webkitRelativePath || it.file.name || `obb_${idx}.obb` }
        : { file: it, uploadName: it.webkitRelativePath || it.name || `obb_${idx}.obb` }
    ));

    const base = getRenderApiBase();
    const totalBatchBytes = items.reduce((s, it) => s + (it.file.size || 0), 0) || 1;
    let uploadedBatchBytes = 0;
    let lastFinishData = null;

    const obbController = new AbortController();
    activeUploadController = obbController;
    const signal = obbController.signal;
    setUploadingLock(true);

    setObbUploadProgress(true, 'OBB parçalı aktarımı başlatılıyor...', 2);
    try {
      for (let i = 0; i < items.length; i++) {
        const { file, uploadName } = items[i];
        const initFd = new FormData();
        initFd.append('fileName', uploadName);
        initFd.append('totalSize', String(file.size));
        initFd.append('replaceExisting', buildObbChunkInitFlags(i).replaceExisting);

        const initRes = await fetchWithTimeout(
          `${base}/api/attach-obb/${jobId}/init`,
          { method: 'POST', body: initFd },
          60000,
          signal
        );
        if (initRes.status === 404 || initRes.status === 405) {
          // Only fall back to legacy multipart when chunked endpoint is unsupported
          setObbUploadProgress(true, 'OBB dosyaları tek parça olarak aktarılıyor...', 35);
          const legacyData = await uploadObbFilesLegacyMultipart(jobId, items, signal);
          setObbUploadProgress(true, 'OBB aktarımı tamamlandı!', 100);
          setTimeout(() => setObbUploadProgress(false), 700);
          return legacyData;
        }
        const initData = await readJsonOrThrow(initRes, 'OBB yükleme oturumu başlatılamadı');
        const uploadId = initData.uploadId;
        const { chunkSizeBytes, totalChunks } = computeUploadPlan(file.size, initData);

        for (let idx = 0; idx < totalChunks; idx++) {
          const start = idx * chunkSizeBytes;
          const end = Math.min(file.size, start + chunkSizeBytes);
          const slice = file.slice(start, end);

          let chunkOk = false;
          let lastErr = null;
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              const cfd = new FormData();
              cfd.append('uploadId', uploadId);
              cfd.append('chunkIndex', String(idx));
              cfd.append('totalChunks', String(totalChunks));
              cfd.append('chunk', slice, `obb_chunk_${idx}.part`);

              const cres = await fetchWithTimeout(
                `${base}/api/attach-obb/${jobId}/chunk`,
                { method: 'POST', body: cfd },
                120000,
                signal
              );
              await readJsonOrThrow(cres, `OBB parça ${idx + 1} hatası`);
              chunkOk = true;
              break;
            } catch (err) {
              if (err.name === 'AbortError') throw err;
              lastErr = err;
              const status = err instanceof ApiHttpError ? err.status : 0;
              if (!shouldRetryHttpStatus(status)) throw err;
              await new Promise((resolve, reject) => {
                const t = setTimeout(resolve, 1000 * (attempt + 1));
                signal.addEventListener('abort', () => {
                  clearTimeout(t);
                  reject(new DOMException('İşlem kullanıcı tarafından iptal edildi.', 'AbortError'));
                }, { once: true });
              });
            }
          }
          if (!chunkOk) throw lastErr || new Error('OBB parçası aktarılamadı.');

          uploadedBatchBytes += (end - start);
          const pct = Math.min(96, (uploadedBatchBytes / totalBatchBytes) * 96);
          setObbUploadProgress(
            true,
            `OBB (${i + 1}/${items.length}): ${uploadName} (${idx + 1}/${totalChunks})`,
            pct
          );
        }

        const finFd = new FormData();
        finFd.append('uploadId', uploadId);
        const finRes = await fetchWithTimeout(
          `${base}/api/attach-obb/${jobId}/finish`,
          { method: 'POST', body: finFd },
          120000,
          signal
        );
        lastFinishData = await readJsonOrThrow(finRes, 'OBB dosyası tamamlanamadı');
      }

      setObbUploadProgress(true, 'Tüm OBB dosyaları sunucuya aktarıldı!', 100);
      setTimeout(() => setObbUploadProgress(false), 750);
      return lastFinishData;
    } catch (err) {
      setObbUploadProgress(false);
      throw err;
    } finally {
      if (activeUploadController === obbController) {
        activeUploadController = null;
      }
      setUploadingLock(false);
    }
  }

  async function uploadObbFolderToRender() {
    if (isUploading || isPatching) {
      showToast('Aktif yükleme veya yamalama sürerken OBB aktarımı başlatılamaz.', 'warn');
      return;
    }
    const target = resolveObbUploadTarget(selectedPackage, lastPatchedGame);
    if (!target.ok) {
      byId('obb-folder-status').textContent = target.reason;
      showToast(target.reason, 'warn');
      return;
    }
    const { game, jobId } = target;
    const files = getActiveObbFiles();
    if (!files.length) {
      showToast('Önce OBB dosyalarını seçin.', 'warn');
      return;
    }

    const btn = byId('btn-upload-obb-folder');
    btn.disabled = true;
    btn.textContent = 'OBB aktarılıyor...';
    try {
      const data = await uploadObbFilesToRender(jobId, files);
      const entry = sessionFileStore.get(game.id) || {};
      entry.obbFolderFiles = files;
      entry.obbUploadedJobId = jobId;
      entry.serverObbUploaded = true;
      sessionFileStore.set(game.id, entry);

      const warnings = (Array.isArray(data?.files) ? data.files : [])
        .map(f => f && f.warning)
        .filter(Boolean);
      const sizeBytes = data?.totalSizeBytes ?? data?.sizeBytes ?? 0;
      const warnSuffix = warnings.length ? ` • Uyarı: ${warnings.join(' | ')}` : '';
      byId('obb-folder-status').textContent = `${data.count} OBB dosyası sunucuya aktarıldı (${formatSizeFromMB(sizeBytes / 1048576)}).${warnSuffix}`;
      showToast('OBB dosyaları sunucuya aktarıldı.', warnings.length ? 'warn' : 'success');
      updateFullXapkButtonVisibility();
    } catch (err) {
      const isAborted = err?.name === 'AbortError';
      const msg = isAborted ? 'OBB aktarımı kullanıcı tarafından iptal edildi.' : err.message;
      byId('obb-folder-status').textContent = msg;
      showToast(isAborted ? msg : `OBB aktarılamadı: ${msg}`, isAborted ? 'warn' : 'error');
    } finally {
      btn.disabled = isUploading || getActiveObbFiles().length === 0;
      btn.textContent = 'Sunucuya OBB Aktar';
    }
  }

  function setPairStatus(message, isError = false) {
    const elStatus = byId('pair-status');
    if (!elStatus) return;
    elStatus.textContent = message;
    elStatus.className = isError ? 'rd-field-hint rd-metric-value--rose' : 'rd-field-hint';
  }

  async function analyzeApkObbPair() {
    if (isUploading || isPatching) {
      showToast('Aktif yükleme veya yamalama sürerken yeni eşleştirme başlatılamaz.', 'warn');
      return;
    }
    pairedApkFile = byId('pair-apk-input').files[0] || null;
    pairedObbFile = byId('pair-obb-input').files[0] || null;
    pairedPackageId = byId('pair-package-id').value.trim();

    let headerBytes = null;
    if (pairedApkFile && pairedApkFile.size > 0) {
      try {
        headerBytes = new Uint8Array(await pairedApkFile.slice(0, 4).arrayBuffer());
      } catch {
        headerBytes = new Uint8Array(0);
      }
    }

    const check = validateApkObbPair({
      apkFile: pairedApkFile,
      obbFile: pairedObbFile,
      packageId: pairedPackageId,
      apkHeaderBytes: headerBytes,
      maxBytes: MAX_FILE_BYTES,
    });
    if (!check.valid) {
      setPairStatus(check.error, true);
      showToast(check.error, 'error');
      return;
    }

    let resolvedObbName = check.resolvedObbName;
    byId('btn-pair-export').disabled = false;
    setPairStatus(`Eşleştirme hazır: ${pairedApkFile.name} + ${pairedObbFile.name}. Hedef: Android/obb/${pairedPackageId}/${resolvedObbName}`);

    const cleanTitle = pairedApkFile.name.replace(/\.apk$/i, '').replace(/[_\-.]+/g, ' ').trim();
    const pairId = `pair-${Date.now()}`;
    sessionFileStore.set(pairId, {
      apkFile: pairedApkFile,
      obbFile: pairedObbFile,
      obbTargetName: resolvedObbName,
      obbFolderFiles: [],
    });

    const pairedPackage = {
      id: pairId,
      name: cleanTitle || pairedPackageId,
      fileName: `${pairedApkFile.name} + ${pairedObbFile.name}`,
      ext: 'APK+OBB',
      sizeMB: check.totalBytes / 1048576,
      legacyAndroid: 'Analiz gerekli',
      legacyApi: 0,
      minSdk: 0,
      arch: 'APK içinden doğrulanmadı',
      is32BitOnly: false,
      hasObb: true,
      genre: 'arcade',
      accent: 'sky',
      signature: '0x504B (Geçerli PK/APK)',
      isRealFile: true,
      packageId: pairedPackageId,
      apkFile: pairedApkFile,
      obbFile: pairedObbFile,
      obbTargetName: resolvedObbName,
      serverJobId: null,
      serverWarnings: [],
    };
    selectPackageForPatching(pairedPackage);
    showToast('APK ve OBB eşleştirildi. Sunucu bağlantısı varsa gerçek analiz başlatılıyor.', 'info');

    if (!renderServerOnline && (getRenderApiBase() || window.location.protocol.startsWith('http'))) {
      await checkRenderServer(false);
    }

    if (renderServerOnline && pairedApkFile.size / 1048576 <= renderMaxUploadMB) {
      try {
        const srv = await uploadApkToRenderForAnalysis(pairedApkFile);
        const synced = syncPairMetadataWithServer(
          { packageId: pairedPackageId, resolvedObbName, obbFile: pairedObbFile },
          srv
        );
        pairedPackageId = synced.packageId;
        resolvedObbName = synced.resolvedObbName;
        byId('pair-package-id').value = pairedPackageId;

        pairedPackage.serverJobId = srv.jobId;
        pairedPackage.packageId = synced.packageId;
        pairedPackage.obbTargetName = resolvedObbName;
        if (srv.appLabel) pairedPackage.name = srv.appLabel;
        pairedPackage.minSdk = Number(srv.minSdk) || 0;
        pairedPackage.legacyApi = Number(srv.targetSdk || srv.minSdk || 0);
        pairedPackage.legacyAndroid = formatSdkSummary('', srv.targetSdk, srv.minSdk);
        pairedPackage.arch = Array.isArray(srv.abis) ? srv.abis.join(', ') : pairedPackage.arch;
        pairedPackage.is32BitOnly = Boolean(srv.is32BitOnly);
        pairedPackage.inspector = srv.inspector || null;
        pairedPackage.elf16kReport = resolveElf16kReport(srv);
        pairedPackage.compatScore = typeof srv.compatScore === 'number' ? srv.compatScore : pairedPackage.compatScore;
        pairedPackage.serverWarnings = Array.isArray(srv.warnings) ? srv.warnings : [];
        pairedPackage.signature = '0x504B • Sunucu Analiz ✓';

        sessionFileStore.set(pairId, {
          apkFile: pairedApkFile,
          obbFile: pairedObbFile,
          obbTargetName: resolvedObbName,
          serverJobId: srv.jobId,
          obbFolderFiles: [],
        });

        // Upload OBB with canonical resolvedObbName (e.g. main.<ver>.<pkg>.obb)
        await uploadObbFilesToRender(srv.jobId, [{ file: pairedObbFile, uploadName: resolvedObbName }]);
        const pairedEntry = sessionFileStore.get(pairId) || {};
        pairedEntry.serverObbUploaded = true;
        pairedEntry.obbUploadedJobId = srv.jobId;
        sessionFileStore.set(pairId, pairedEntry);

        setPairStatus(`Sunucu analizi tamamlandı. OBB hedefi: Android/obb/${pairedPackageId}/${resolvedObbName}`);
        byId('obb-folder-status').textContent = `Eşleştirilen OBB (${resolvedObbName}) sunucuya aktarıldı.`;
        selectPackageForPatching(pairedPackage);
        showToast('APK sunucuda analiz edildi; OBB kanonik adla aktarıldı.', 'success');
      } catch (err) {
        if (err.name !== 'AbortError') {
          pairedPackage.serverWarnings = [`Sunucu APK/OBB aktarımı başarısız: ${err.message}. Yerel eşleştirme korundu.`];
          selectPackageForPatching(pairedPackage);
          showToast('Sunucu aktarımı tamamlanamadı; yerel eşleştirme korundu.', 'warn');
        }
      }
    } else if (renderServerOnline) {
      pairedPackage.serverWarnings = [`APK dosyası sunucu yükleme sınırını (${renderMaxUploadMB} MB) aşıyor.`];
      selectPackageForPatching(pairedPackage);
    }
  }

  async function exportApkObbBundle() {
    if (isExportingZip) {
      showToast('Başka bir ZIP paketleme işlemi sürüyor, lütfen bekleyin.', 'warn');
      return;
    }
    const check = validateApkObbPair({
      apkFile: pairedApkFile,
      obbFile: pairedObbFile,
      packageId: pairedPackageId,
    });
    if (!check.valid) {
      setPairStatus(check.error, true);
      return;
    }
    const budget = checkClientZipBudget([pairedApkFile, pairedObbFile]);
    if (!budget.ok) {
      setPairStatus(budget.reason, true);
      showToast(budget.reason, 'warn');
      return;
    }

    isExportingZip = true;
    const button = byId('btn-pair-export');
    button.disabled = true;
    button.textContent = 'ZIP hazırlanıyor...';
    try {
      const zip = new JSZip();
      const targetObb = selectedPackage?.obbTargetName || check.resolvedObbName;
      zip.file(pairedApkFile.name, pairedApkFile);
      zip.file(`Android/obb/${pairedPackageId}/${targetObb}`, pairedObbFile);
      zip.file(
        'RETRODROID-README.txt',
        `RetroDroid Compat v${APP_VERSION} — APK + OBB Kurulum Paketi\n`
        + `Paket kimliği: ${pairedPackageId}\n`
        + `OBB hedefi: Android/obb/${pairedPackageId}/${targetObb}\n\n`
        + '1) APK dosyasını Android paket yükleyicisiyle kurun.\n'
        + '2) OBB dosyasını telefon hafızasında belirtilen Android/obb klasörüne kopyalayın.\n'
      );
      const blob = await zip.generateAsync({ type: 'blob', compression: 'STORE' });
      triggerBlobDownload(blob, `${pairedPackageId.replace(/\./g, '_')}_APK_OBB.zip`);
      setPairStatus(`ZIP hazırlandı: APK kökte, OBB Android/obb/${pairedPackageId}/${targetObb} altında.`);
      showToast('APK + OBB kurulum ZIP paketi indirildi.', 'success');
    } catch (err) {
      console.error(err);
      setPairStatus(`ZIP oluşturulamadı: ${err.message || 'bilinmeyen hata'}`, true);
      showToast('ZIP oluşturulamadı.', 'error');
    } finally {
      isExportingZip = false;
      button.disabled = false;
      button.textContent = 'Kurulum klasörünü ZIP indir';
    }
  }

  // ==========================================================================
  // 9. FILE SELECTION, DEMO PACKAGES & ENHANCED F05 INSPECTOR
  // ==========================================================================
  function showUploadError(title, msg) {
    byId('upload-error-title').textContent = title;
    byId('upload-error-msg').textContent = msg;
    byId('upload-error-box').classList.remove('hidden');
  }

  function hideUploadError() {
    byId('upload-error-box').classList.add('hidden');
  }

  function renderDemoPackages() {
    const container = byId('demo-packages-grid');
    if (!container) return;
    clearNode(container);

    for (const pkg of DEMO_PACKAGES) {
      const btn = el('button', { type: 'button', className: 'rd-demo-btn' }, [
        el('div', { className: `rd-icon-tile ${getAccentTileClass(pkg.accent)}` }, [createStaticSvg(pkg.genre)]),
        el('div', { className: 'rd-min-w-0 rd-flex-1' }, [
          el('div', { className: 'rd-flag-title truncate', textContent: pkg.name }),
          el('div', {
            className: 'rd-field-hint mono truncate',
            textContent: `${pkg.ext} • ${formatSizeFromMB(pkg.sizeMB)} • ${formatSdkSummary(pkg.legacyAndroid, pkg.legacyApi, pkg.minSdk)}`,
          }),
        ]),
        el('span', { className: 'rd-shrink-0' }, [createStaticSvg('chevron')]),
      ]);
      btn.addEventListener('click', () => {
        if (isUploading || isPatching) {
          showToast('Aktif işlem sürerken paket değiştirilemez.', 'warn');
          return;
        }
        hideUploadError();
        selectPackageForPatching({ ...pkg, isRealFile: false });
        showToast(`${pkg.name} örnek profili inceleme için yüklendi.`, 'info');
      });
      container.appendChild(btn);
    }
  }

  async function handleRealFile(file) {
    if (isUploading || isPatching) {
      showToast('Aktif yükleme veya yamalama sürerken paket değiştirilemez.', 'warn');
      return;
    }
    hideUploadError();

    const check = validateUploadFile(file, MAX_FILE_BYTES);
    if (!check.valid) {
      showUploadError(check.title, check.message);
      showToast(check.title, 'error');
      return;
    }

    const fileName = file.name;
    const lower = fileName.toLowerCase();
    const isApk = lower.endsWith('.apk');
    const isXapk = lower.endsWith('.xapk');
    const isSplitContainer = lower.endsWith('.apks') || lower.endsWith('.apkm') || lower.endsWith('.zip');
    const isContainerLike = isXapk || isSplitContainer;
    const isObb = lower.endsWith('.obb');

    if (isObb) {
      try {
        const obbInput = byId('pair-obb-input');
        const transfer = new DataTransfer();
        transfer.items.add(file);
        obbInput.files = transfer.files;
        pairedObbFile = file;
      } catch {
        setPairStatus('Bu tarayıcı sürüklenen OBB dosyasını alana aktaramadı. OBB alanından elle seçin.', true);
        byId('pair-obb-input')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        return;
      }
      setPairStatus(`OBB seçildi: ${fileName}. Şimdi eşleşen APK dosyasını ve paket kimliğini girin.`);
      byId('pair-apk-input')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      showToast('OBB alındı. APK ile eşleştirme bölümünü tamamlayın.', 'info');
      return;
    }

    const sizeMB = file.size / 1048576;
    let signatureText = 'Okunamadı';
    let isValidPK = false;
    try {
      const bytes = new Uint8Array(await file.slice(0, 4).arrayBuffer());
      if (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
        isValidPK = true;
        const hex = Array.from(bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join('');
        signatureText = `0x${hex} (Geçerli PK/ZIP)`;
      } else {
        const hex = Array.from(bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join('');
        signatureText = `0x${hex || '00'} (Uyarı: PK Başlığı Yok)`;
      }
    } catch {
      signatureText = 'Başlık Okuma Hatası';
    }

    const cleanTitle = fileName
      .replace(/\.(xapk|apks|apkm|zip|apk)$/i, '')
      .replace(/[_\-.]+/g, ' ')
      .trim() || 'Özel Oyun Paketi';

    const ext = isXapk ? 'XAPK'
      : lower.endsWith('.apks') ? 'APKS'
      : lower.endsWith('.apkm') ? 'APKM'
      : lower.endsWith('.zip') ? 'ZIP'
      : 'APK';

    const customId = `custom-${Date.now()}`;
    const existingStaged = stagedObbFiles.length ? stagedObbFiles.slice() : [];
    stagedObbFiles = [];
    sessionFileStore.set(customId, {
      singleFile: file,
      obbFolderFiles: existingStaged,
    });

    const analyzedPkg = {
      id: customId,
      name: cleanTitle,
      fileName,
      ext,
      sizeMB: Math.max(sizeMB, 0.01),
      legacyAndroid: 'Sunucu analizi gerekli',
      legacyApi: 0,
      minSdk: 0,
      arch: 'Doğrulanmadı',
      is32BitOnly: false,
      hasObb: isXapk,
      genre: isContainerLike ? 'fps' : 'arcade',
      accent: isContainerLike ? 'emerald' : 'sky',
      signature: signatureText,
      isValidPK,
      isRealFile: true,
      rawFile: file,
      packageId: `com.legacy.${cleanTitle.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16) || 'app'}`,
      serverJobId: null,
      serverWarnings: [],
    };

    if ((isApk || isContainerLike) && isValidPK) {
      if (!renderServerOnline && (getRenderApiBase() || window.location.protocol.startsWith('http'))) {
        await checkRenderServer(false);
      }
      if (renderServerOnline && sizeMB <= renderMaxUploadMB) {
        try {
          const srv = await uploadApkToRenderForAnalysis(file);
          analyzedPkg.serverJobId = srv.jobId;
          if (srv.packageId && srv.packageId.toLowerCase() !== 'bilinmiyor') {
            analyzedPkg.packageId = srv.packageId;
          }
          if (srv.appLabel) analyzedPkg.name = srv.appLabel;
          analyzedPkg.minSdk = Number(srv.minSdk) || 0;
          analyzedPkg.legacyApi = Number(srv.targetSdk || srv.minSdk || 0);
          analyzedPkg.legacyAndroid = formatSdkSummary('', srv.targetSdk, srv.minSdk);
          analyzedPkg.arch = Array.isArray(srv.abis) ? srv.abis.join(', ') : analyzedPkg.arch;
          analyzedPkg.is32BitOnly = Boolean(srv.is32BitOnly);
          // Authoritative server hasObb (HIGH-09): split-only .apks with obbFiles: [] => false
          analyzedPkg.hasObb = resolveAuthoritativeHasObb(srv, false);
          analyzedPkg.inspector = srv.inspector || null;
          analyzedPkg.elf16kReport = resolveElf16kReport(srv);
          if (typeof srv.compatScore === 'number') analyzedPkg.compatScore = srv.compatScore;
          analyzedPkg.serverWarnings = Array.isArray(srv.warnings) ? srv.warnings : [];
          analyzedPkg.signature = `${signatureText} • Sunucu Analiz ✓`;

          const entry = sessionFileStore.get(customId) || {};
          entry.singleFile = file;
          entry.serverJobId = srv.jobId;
          sessionFileStore.set(customId, entry);

          selectPackageForPatching(analyzedPkg);
          showToast(`Sunucu analizi tamamlandı: ${analyzedPkg.packageId}`, 'success');
          return;
        } catch (err) {
          if (err.name === 'AbortError') return;
          analyzedPkg.serverWarnings = [
            `Sunucu aktarımı başarısız: ${err.message}. Yerel moddasınız — dosya henüz yamalanmadı.`,
          ];
        }
      } else if (!renderServerOnline) {
        analyzedPkg.serverWarnings = [
          'Sunucu şu an bağlı değil. Gerçek APK yamalamak için "Bağlantıyı Test Et / Uyandır" butonuna basıp dosyayı tekrar seçin.',
        ];
      } else if (sizeMB > renderMaxUploadMB) {
        analyzedPkg.serverWarnings = [
          `Dosya (${formatSizeFromMB(sizeMB)}) sunucu limitini (${renderMaxUploadMB} MB) aşıyor.`,
        ];
      }
    }

    selectPackageForPatching(analyzedPkg);
    showToast(
      isValidPK
        ? `Geçerli ${ext} paketi (PK başlığı) doğrulandı: ${formatSizeFromMB(analyzedPkg.sizeMB)}`
        : 'Uyarı: Standart PK/ZIP başlığı tespit edilmedi.',
      isValidPK ? 'success' : 'warn'
    );
  }

  function renderPackageInspector(pkg) {
    const data = isPlainObject(pkg?.inspector) ? pkg.inspector : null;
    const statusEl = byId('pkg-inspector-status');
    const scoreEl = byId('pkg-inspector-score');
    const permCountEl = byId('pkg-inspector-permission-count');
    const dexCountEl = byId('pkg-inspector-dex-count');
    const sigEl = byId('pkg-inspector-signature');
    const floorEl = byId('pkg-inspector-install-floor');
    const elfEl = byId('pkg-inspector-16k');
    const arscEl = byId('pkg-inspector-arsc');
    const expEl = byId('pkg-inspector-exported');
    const checklistEl = byId('pkg-inspector-checklist');
    const permListEl = byId('pkg-inspector-permissions');
    const dexListEl = byId('pkg-inspector-dex');
    const schemesEl = byId('pkg-inspector-schemes');
    const certEl = byId('pkg-inspector-cert');

    if (!statusEl || !permListEl) return;

    if (!data) {
      statusEl.textContent = 'Sunucu analizi gerekli';
      statusEl.className = 'rd-badge rd-badge--amber';
      if (scoreEl) {
        scoreEl.textContent = 'Puan: —';
        scoreEl.className = 'rd-badge rd-badge--indigo';
      }
      permCountEl.textContent = '—';
      dexCountEl.textContent = '—';
      sigEl.textContent = '—';
      sigEl.className = 'rd-metric-value';
      clearNode(floorEl); floorEl.textContent = 'Sunucu analizi bekleniyor.';
      clearNode(elfEl); elfEl.textContent = 'Sunucu analizi bekleniyor.';
      clearNode(arscEl); arscEl.textContent = 'Sunucu analizi bekleniyor.';
      clearNode(expEl); expEl.textContent = 'Sunucu analizi bekleniyor.';
      clearNode(checklistEl); checklistEl.textContent = 'Sunucu analizi sonrasında kontrol maddeleri listelenir.';
      clearNode(permListEl); permListEl.textContent = 'Manifest izinlerini görmek için sunucuya bağlanıp APK yükleyin.';
      clearNode(dexListEl); dexListEl.textContent = 'DEX ve imza ayrıntıları sunucu analizinden sonra gösterilir.';
      schemesEl.textContent = 'v1 / v2 / v3: henüz kontrol edilmedi.';
      certEl.textContent = 'Sertifika SHA-256: —';
      return;
    }

    const dex = isPlainObject(data.dex) ? data.dex : {};
    const signature = isPlainObject(data.signature) ? data.signature : {};
    const permissions = Array.isArray(data.permissions)
      ? data.permissions.filter(p => (typeof p === 'string' || typeof p === 'number') && String(p).trim() !== '')
      : [];
    const dexFiles = Array.isArray(dex.files) ? dex.files.filter(d => isPlainObject(d)) : [];
    const compatScore = typeof data.compatScore === 'number'
      ? data.compatScore
      : (typeof pkg.compatScore === 'number' ? pkg.compatScore : null);

    statusEl.textContent = 'Gerçek APK İncelemesi ✓';
    statusEl.className = 'rd-badge rd-badge--emerald';
    if (scoreEl) {
      if (compatScore !== null) {
        scoreEl.textContent = `Kanıta Dayalı Puan: %${compatScore}`;
        scoreEl.className = `rd-badge ${compatScore >= 85 ? 'rd-badge--emerald' : compatScore >= 60 ? 'rd-badge--amber' : 'rd-badge--rose'}`;
      } else {
        scoreEl.textContent = 'Puan: —';
      }
    }

    permCountEl.textContent = String(data.permissionCount ?? permissions.length);
    dexCountEl.textContent = String(dex.fileCount ?? dexFiles.length);
    sigEl.textContent = signature.verified ? 'Doğrulandı ✓' : 'Doğrulanmadı';
    sigEl.className = `rd-metric-value ${signature.verified ? 'rd-metric-value--emerald' : 'rd-metric-value--amber'}`;

    // Install Floor Status (Android 14 min 23, Android 15-17 min 24)
    clearNode(floorEl);
    const floor = isPlainObject(data.installFloorStatus)
      ? data.installFloorStatus
      : (isPlainObject(pkg?.installFloorStatus) ? pkg.installFloorStatus : null);
    if (floor) {
      const fMap = Object.assign(Object.create(null), {
        ok: { label: 'Android 14–17 Uyumlu', cls: 'rd-badge--emerald' },
        blocked_android15_plus: { label: 'Android 15–17 Engelli (min API 24)', cls: 'rd-badge--amber' },
        blocked_android14_plus: { label: 'Android 14–17 Engelli (min API 23/24)', cls: 'rd-badge--rose' },
        unknown: { label: 'Belirsiz', cls: 'rd-badge' },
      });
      const fm = ownGet(fMap, floor.status, fMap.unknown);
      floorEl.appendChild(el('span', { className: `rd-badge ${fm.cls}`, textContent: fm.label }));
      if (floor.summary) {
        floorEl.appendChild(el('div', { className: 'rd-field-hint', textContent: String(floor.summary) }));
      }
    } else {
      floorEl.textContent = 'Bilgi raporlanmadı.';
    }

    // 16 KB ELF64 PT_LOAD alignment (inspector.elf16k || pkg.elf16kReport)
    clearNode(elfEl);
    const elf16k = resolveElf16kReport(pkg) || resolveElf16kReport(data);
    const psStatus = data.pageSize16kStatus || elf16k?.status || 'unknown';
    const psMap = Object.assign(Object.create(null), {
      compatible: { label: '16 KB Uyumlu ✓', cls: 'rd-badge--emerald' },
      incompatible: { label: '16 KB Uyumsuz (4 KB hizalı)', cls: 'rd-badge--rose' },
      not_applicable_pure_java: { label: 'Saf Java/DEX (Uygulanmaz)', cls: 'rd-badge--sky' },
      not_applicable_32bit_only: { label: 'Yalnızca 32-bit (64-bit yok)', cls: 'rd-badge--amber' },
      unknown: { label: 'Doğrulanamadı', cls: 'rd-badge' },
    });
    const pm = ownGet(psMap, psStatus, psMap.unknown);
    elfEl.appendChild(el('span', { className: `rd-badge ${pm.cls}`, textContent: pm.label }));
    if (elf16k?.summary) {
      elfEl.appendChild(el('div', { className: 'rd-field-hint', textContent: String(elf16k.summary) }));
    }
    const unalignedFiles = Array.isArray(elf16k?.unalignedFiles)
      ? elf16k.unalignedFiles.filter(f => (typeof f === 'string' && f.trim() !== '') || isPlainObject(f))
      : [];
    if (unalignedFiles.length > 0) {
      const details = el('details', { className: 'rd-field-hint' }, [
        el('summary', { textContent: `Hizasız .so dosyaları (${unalignedFiles.length})` }),
        ...unalignedFiles.slice(0, 12).map(f => el('div', {
          className: 'mono break-all',
          textContent: typeof f === 'string' ? `• ${f}` : `• ${f.path || f.file || JSON.stringify(f)}`,
        })),
      ]);
      elfEl.appendChild(details);
    }

    // resources.arsc compression
    clearNode(arscEl);
    const arscCompressed = Boolean(data.resourcesArscCompressed ?? pkg.resourcesArscCompressed);
    arscEl.appendChild(el('span', {
      className: `rd-badge ${arscCompressed ? 'rd-badge--rose' : 'rd-badge--emerald'}`,
      textContent: arscCompressed ? 'ZIP_DEFLATED — Android 11+ Hatası!' : 'ZIP_STORED ✓',
    }));

    // API 31+ missing android:exported components
    clearNode(expEl);
    const missCount = data.missingExportedCount ?? pkg.missingExportedCount;
    if (missCount === null || missCount === undefined) {
      expEl.appendChild(el('span', { className: 'rd-badge', textContent: 'Denetlenemedi' }));
    } else if (missCount === 0) {
      expEl.appendChild(el('span', { className: 'rd-badge rd-badge--emerald', textContent: '0 Eksik Bileşen ✓' }));
    } else {
      expEl.appendChild(el('span', { className: 'rd-badge rd-badge--amber', textContent: `${missCount} Bileşende Eksik` }));
      const rawComps = Array.isArray(data.missingExportedComponents) ? data.missingExportedComponents : [];
      const comps = rawComps.filter(c => (typeof c === 'string' && c.trim() !== '') || isPlainObject(c));
      comps.slice(0, 5).forEach(c => {
        const label = typeof c === 'string' ? c : `<${c.tag || 'component'}> ${c.name || ''}`.trim();
        expEl.appendChild(el('div', { className: 'mono truncate rd-field-hint', textContent: label }));
      });
    }

    // Evidence-based Compat Checklist
    clearNode(checklistEl);
    const rawChecklist = Array.isArray(data.compatChecklist) ? data.compatChecklist
      : (Array.isArray(pkg.compatChecklist) ? pkg.compatChecklist : []);
    const checklist = rawChecklist.filter(item => isPlainObject(item));
    if (!checklist.length) {
      checklistEl.textContent = 'Kontrol listesi verisi raporlanmadı.';
    } else {
      const pillMap = Object.assign(Object.create(null), {
        pass: { label: 'GEÇTİ', cls: 'rd-badge--emerald' },
        warn: { label: 'UYARI', cls: 'rd-badge--amber' },
        fail: { label: 'ENGEL', cls: 'rd-badge--rose' },
        info: { label: 'BİLGİ', cls: 'rd-badge--sky' },
      });
      for (const item of checklist) {
        const pmItem = ownGet(pillMap, item.status, pillMap.info);
        const impactText = typeof item.impact === 'number' && Number.isFinite(item.impact) && item.impact < 0
          ? ` (${item.impact})`
          : '';
        checklistEl.appendChild(el('div', { className: 'rd-checklist-item' }, [
          el('span', { className: 'rd-checklist-msg', textContent: String(item.message || item.id || 'Kontrol maddesi') }),
          el('span', { className: `rd-badge ${pmItem.cls} rd-shrink-0`, textContent: `${pmItem.label}${impactText}` }),
        ]));
      }
    }

    // Permissions
    clearNode(permListEl);
    if (!permissions.length) {
      permListEl.appendChild(el('div', { textContent: 'Manifestte uses-permission kaydı bulunamadı.' }));
    } else {
      for (const name of permissions) {
        permListEl.appendChild(el('div', { className: 'mono break-all', textContent: `• ${String(name)}` }));
      }
    }

    // DEX files & signature schemes
    clearNode(dexListEl);
    if (!dexFiles.length) {
      dexListEl.appendChild(el('div', { textContent: 'classes*.dex bulunamadı.' }));
    } else {
      for (const d of dexFiles) {
        dexListEl.appendChild(el('div', {
          className: 'mono',
          textContent: `${d.name || 'classes.dex'} • DEX ${d.version || '?'} • ${Number(d.classes || 0).toLocaleString('tr-TR')} sınıf • ${Number(d.methods || 0).toLocaleString('tr-TR')} metot`,
        }));
      }
      dexListEl.appendChild(el('div', {
        className: 'mono rd-metric-value--sky',
        textContent: `Toplam: ${Number(dex.totalClasses || 0).toLocaleString('tr-TR')} sınıf / ${Number(dex.totalMethods || 0).toLocaleString('tr-TR')} metot`,
      }));
    }

    const schemeNames = ['v1', 'v2', 'v3', 'v31']
      .filter(k => Boolean(ownGet(signature, k)))
      .map(k => (k === 'v31' ? 'v3.1' : k));
    schemesEl.textContent = `Doğrulanan şemalar: ${schemeNames.length ? schemeNames.join(' • ') : 'yok'}. ${signature.message || ''}`;
    certEl.textContent = `Sertifika SHA-256: ${signature.certificateSha256 || 'raporlanmadı'}`;
  }

  function updateServerFlagsUI() {
    const mode = byId('patch-server-mode')?.value || 'patch_and_sign';
    const isResignOnly = mode === 'resign_only';
    const manifestFlagIds = [
      'flag-patch-target-sdk',
      'flag-legacy-storage',
      'flag-cleartext',
      'flag-notch-support',
      'flag-extract-native-libs',
      'flag-allow-downgrade',
    ];
    for (const id of manifestFlagIds) {
      const cb = byId(id);
      if (!cb) continue;
      cb.disabled = isResignOnly;
      const card = cb.closest('.rd-flag-card');
      if (card) {
        card.classList.toggle('rd-flag-card--disabled', isResignOnly);
        card.classList.toggle('rd-flag-card--active', !isResignOnly && cb.checked);
      }
    }
    const resignCb = byId('flag-resign');
    if (resignCb) {
      const card = resignCb.closest('.rd-flag-card');
      if (card) card.classList.toggle('rd-flag-card--active', resignCb.checked);
    }

    const hintEl = byId('server-patch-flags-hint');
    if (hintEl) {
      if (isResignOnly) {
        hintEl.textContent = 'Yalnızca Hizala & İmzala modu seçili: AndroidManifest.xml değiştirilmeyecek.';
      } else {
        const anyManifest = byId('flag-patch-target-sdk')?.checked
          || byId('flag-legacy-storage')?.checked
          || byId('flag-cleartext')?.checked
          || byId('flag-notch-support')?.checked
          || byId('flag-extract-native-libs')?.checked;
        hintEl.textContent = anyManifest
          ? 'Seçili manifest bayrakları doğrudan sunucudaki APK içine işlenecektir.'
          : 'Hiçbir manifest bayrağı seçili değil: yalnızca zipalign ve imzalama adımları çalıştırılır.';
      }
    }

    const sdkVal = Number(byId('patch-target-sdk')?.value || 28);
    const sdkHint = byId('patch-target-sdk-hint');
    if (sdkHint) {
      if (sdkVal >= 31) {
        sdkHint.textContent = `API ${sdkVal}: Sunucu intent-filter içeren bileşenlere otomatik android:exported="true" ekler (slim-apktool).`;
      } else if (sdkVal >= 29) {
        sdkHint.textContent = `API ${sdkVal}: Android 10+ Scoped Storage / resources.arsc ZIP_STORED kuralları geçerlidir.`;
      } else if (sdkVal === 24) {
        sdkHint.textContent = 'API 24: Android 15–17 cihazlar için izin verilen en düşük kurulum eşiğidir.';
      } else {
        sdkHint.textContent = `API ${sdkVal}: Android 14 (min API 23) ve Android 15–17 (min API 24) kurulum engelini güvenle aşar.`;
      }
    }
  }

  function applyProfileDefaultsToPatchForm(profile) {
    if (!profile) return;
    const sdkSel = byId('patch-target-sdk');
    if (sdkSel && profile.defaultTargetSdk) sdkSel.value = String(profile.defaultTargetSdk);
    const f = profile.defaultServerFlags || {};
    const setCb = (id, val) => { const node = byId(id); if (node && typeof val === 'boolean') node.checked = val; };
    setCb('flag-patch-target-sdk', f.patchTargetSdk);
    setCb('flag-resign', f.resign);
    setCb('flag-legacy-storage', f.addLegacyStorage);
    setCb('flag-cleartext', f.enableCleartext);
    setCb('flag-notch-support', f.addNotchSupport);
    setCb('flag-extract-native-libs', f.forceExtractNativeLibs);
    setCb('flag-allow-downgrade', f.allowDowngrade);
    updateServerFlagsUI();
  }

  function renderPatchModulesInitial() {
    const list = byId('patch-modules-list');
    if (!list) return;
    clearNode(list);

    for (const mod of PATCH_MODULES) {
      const checked = activeModuleIds.has(mod.id);
      const checkbox = el('input', {
        type: 'checkbox',
        className: 'sr-only toggle-checkbox',
        dataset: { modId: mod.id },
        checked,
      });
      const label = el('label', {
        className: `rd-flag-card ${checked ? 'rd-flag-card--note-active' : ''}`,
        dataset: { modCard: mod.id },
      }, [
        el('div', {}, [
          el('span', { className: 'rd-flag-title', textContent: mod.title }),
          el('span', { className: 'rd-flag-desc', textContent: mod.desc }),
        ]),
        el('span', { className: 'toggle-wrap' }, [
          checkbox,
          el('span', { className: 'toggle-track' }, [el('span', { className: 'toggle-thumb' })]),
        ]),
      ]);
      list.appendChild(label);
    }
    syncPatchModulesInPlace();
  }

  // Focus-preserving in-place DOM update (LOW-07)
  function syncPatchModulesInPlace() {
    const list = byId('patch-modules-list');
    if (!list) return;
    list.querySelectorAll('input[data-mod-id]').forEach(cb => {
      const id = cb.dataset.modId;
      const checked = activeModuleIds.has(id);
      if (cb.checked !== checked) cb.checked = checked;
      const card = cb.closest('.rd-flag-card');
      if (card) card.classList.toggle('rd-flag-card--note-active', checked);
    });
    const countEl = byId('active-modules-count');
    if (countEl) countEl.textContent = `${activeModuleIds.size}/${PATCH_MODULES.length} Not Aktif`;
    updateCompatBadgeDisplay();
  }

  function updateCompatBadgeDisplay() {
    const badge = byId('pkg-compat-estimate');
    if (!badge || !selectedPackage) return;
    const serverScore = selectedPackage.inspector?.compatScore ?? selectedPackage.compatScore;
    if (typeof serverScore === 'number' && selectedPackage.inspector) {
      badge.textContent = `Sunucu Uyum Puanı: %${serverScore}`;
      badge.className = `rd-badge ${serverScore >= 85 ? 'rd-badge--emerald' : serverScore >= 60 ? 'rd-badge--amber' : 'rd-badge--rose'}`;
    } else {
      badge.textContent = 'Önizleme Profili (Sunucu Puanı Yok)';
      badge.className = 'rd-badge rd-badge--indigo';
    }
  }

  function selectPackageForPatching(pkg) {
    if (isPatching) {
      showToast('Yama işlemi sürerken paket değiştirilemez.', 'warn');
      return;
    }
    selectedPackage = pkg;
    stagedObbFiles = [];

    const profile = ENGINE_PROFILES.find(p => p.id === appState.activeProfile) || ENGINE_PROFILES[0];
    activeModuleIds = new Set(profile.defaultModules);
    if (isContainerFormat(pkg.ext) || pkg.hasObb) activeModuleIds.add('obbGuide');

    const card = byId('selected-package-card');
    card.classList.remove('hidden');

    const iconBox = byId('pkg-icon-box');
    iconBox.className = `rd-icon-tile rd-icon-tile--lg ${getAccentTileClass(pkg.accent)}`;
    clearNode(iconBox);
    iconBox.appendChild(createStaticSvg(pkg.genre));

    byId('pkg-name').textContent = pkg.name;
    byId('pkg-filename').textContent = pkg.fileName;

    const extBadge = byId('pkg-ext-badge');
    extBadge.textContent = pkg.ext;
    extBadge.className = `rd-badge ${isContainerFormat(pkg.ext) ? 'rd-badge--emerald' : 'rd-badge--sky'}`;

    byId('pkg-size').textContent = formatSizeFromMB(pkg.sizeMB);
    byId('pkg-android').textContent = formatSdkSummary(pkg.legacyAndroid, pkg.legacyApi, pkg.minSdk);

    const sigEl = byId('pkg-signature');
    sigEl.textContent = pkg.signature;
    sigEl.className = pkg.signature.includes('Uyarı') || pkg.signature.includes('Boş')
      ? 'rd-metric-value rd-metric-value--amber mono truncate'
      : 'rd-metric-value rd-metric-value--emerald mono truncate';

    byId('pkg-arch').textContent = `${pkg.arch} • ${pkg.hasObb ? 'OBB Var' : 'OBB Yok'}`;
    renderPackageInspector(pkg);

    const warnBox = byId('pkg-server-warnings');
    clearNode(warnBox);
    if (Array.isArray(pkg.serverWarnings) && pkg.serverWarnings.length > 0) {
      for (const w of pkg.serverWarnings) {
        warnBox.appendChild(el('div', { textContent: `• ${w}` }));
      }
      warnBox.classList.remove('hidden');
    } else {
      warnBox.classList.add('hidden');
    }

    byId('patcher-terminal-panel').classList.add('hidden');
    byId('patch-summary-box').classList.add('hidden');
    syncPatchModulesInPlace();
    renderObbFolderSelection();
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ==========================================================================
  // 10. PATCH & SIGN PIPELINE, POLLING, CANCEL & PATCH SUMMARY (F06, F09, F11)
  // ==========================================================================
  function renderPatchSummary(summary, repatchAvailable) {
    const box = byId('patch-summary-box');
    if (!box) return;
    clearNode(box);
    if (!isPlainObject(summary)) {
      box.classList.add('hidden');
      return;
    }
    box.classList.remove('hidden');

    const methodText = ownGet(PATCH_METHOD_LABELS, summary.method) || String(summary.method || 'Bilinmiyor');
    const headerBadges = [
      el('span', { className: 'rd-badge rd-badge--indigo', textContent: `Yöntem: ${methodText}` }),
      el('span', {
        className: `rd-badge ${summary.manifestPatched ? 'rd-badge--emerald' : 'rd-badge--amber'}`,
        textContent: summary.manifestPatched ? 'Manifest Yamalandı ✓' : 'Manifest Değiştirilmedi',
      }),
      el('span', {
        className: `rd-badge ${summary.resigned ? 'rd-badge--emerald' : 'rd-badge--amber'}`,
        textContent: summary.resigned ? 'v1/v2/v3 İmzalandı' : 'İmzasız',
      }),
    ];
    if (summary.oldTargetSdk || summary.effectiveTargetSdk) {
      headerBadges.push(el('span', {
        className: 'rd-badge rd-badge--sky mono',
        textContent: `targetSdk: ${summary.oldTargetSdk ?? '?'} → ${summary.effectiveTargetSdk ?? '?'}`,
      }));
    }
    if (summary.skippedDowngrade) {
      headerBadges.push(el('span', {
        className: 'rd-badge rd-badge--amber',
        textContent: 'Düşürme Atlandı (allowDowngrade=false)',
      }));
    }
    box.appendChild(el('div', { className: 'rd-row-wrap' }, headerBadges));

    const appliedChanges = Array.isArray(summary.appliedChanges)
      ? summary.appliedChanges.filter(ch => ch !== null && ch !== undefined && ch !== '')
      : [];
    if (appliedChanges.length > 0) {
      box.appendChild(el('div', { className: 'rd-row-wrap' }, [
        el('span', { className: 'rd-field-hint', textContent: 'Uygulanan değişiklikler:' }),
        ...appliedChanges.map(ch => el('span', { className: 'rd-badge rd-badge--emerald mono', textContent: String(ch) })),
      ]));
    }

    const patchedSplits = Array.isArray(summary.patchedSplits)
      ? summary.patchedSplits.filter(Boolean)
      : [];
    if (patchedSplits.length > 0) {
      box.appendChild(el('div', {
        className: 'rd-field-hint mono',
        textContent: `Yamalanan Split APK'lar (${patchedSplits.length}): ${patchedSplits.join(', ')}`,
      }));
    }

    if (summary.fallbackReason) {
      box.appendChild(el('div', {
        className: 'rd-subbox rd-subbox--amber rd-field-hint',
        textContent: `Yedek Mod Gerekçesi: ${summary.fallbackReason}`,
      }));
    }

    if (repatchAvailable === false) {
      box.appendChild(el('div', {
        className: 'rd-subbox rd-subbox--sky rd-field-hint',
        textContent: 'Bilgi: Düşük disk koruması nedeniyle büyük kaynak APK temizlendi; tekrar yamalamak için dosyayı yeniden yükleyin.',
      }));
    }
  }

  async function pollServerOperation({ base, statusPath, appendLog, onProgress, maxMinutes = 45 }) {
    const startedAt = Date.now();
    let shownLogs = 0;
    let delay = 1200;
    let transientErrors = 0;

    activePollController = new AbortController();
    const signal = activePollController.signal;

    try {
      while (true) {
        if (signal.aborted) {
          throw new DOMException('İşlem iptal edildi.', 'AbortError');
        }
        if (Date.now() - startedAt > maxMinutes * 60 * 1000) {
          throw new Error('Sunucu işlemi izleme zaman aşımına uğradı.');
        }

        let st;
        try {
          const res = await fetchWithTimeout(`${base}${statusPath}`, { method: 'GET' }, 30000, signal);
          st = await readJsonOrThrow(res, 'Durum sorgusu hatası');
          transientErrors = 0;
        } catch (err) {
          if (err.name === 'AbortError') throw err;
          const status = err instanceof ApiHttpError ? err.status : 0;
          // Fail-fast on permanent 4xx errors (HIGH-14)
          if (!shouldRetryHttpStatus(status)) throw err;
          transientErrors++;
          if (transientErrors > 10) throw err;
          await new Promise(r => setTimeout(r, 2500));
          continue;
        }

        if (appendLog && Array.isArray(st.logs)) {
          while (shownLogs < st.logs.length) {
            appendLog('API', 'emerald', st.logs[shownLogs]);
            shownLogs++;
          }
        }
        if (typeof st.progress === 'number' && typeof onProgress === 'function') {
          onProgress(st.progress, st.stage || '');
        }
        if (st.status === 'done') return st;
        if (st.status === 'canceled') {
          const cancelErr = new Error(st.error || 'İşlem kullanıcı tarafından iptal edildi.');
          cancelErr.code = 'JOB_CANCELED';
          throw cancelErr;
        }
        if (st.status === 'interrupted') {
          throw new Error(st.error || 'Sunucu yeniden başlatıldığı için işlem kesildi.');
        }
        if (st.status === 'error') {
          throw new Error(st.error || 'Sunucu işlemi başarısız oldu.');
        }

        await new Promise((resolve, reject) => {
          const t = setTimeout(resolve, delay);
          signal.addEventListener('abort', () => {
            clearTimeout(t);
            reject(new DOMException('İşlem iptal edildi.', 'AbortError'));
          }, { once: true });
        });
        delay = Math.min(delay + 200, 2600);
      }
    } finally {
      activePollController = null;
    }
  }

  function ensureNotifyPermission() {
    try {
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().catch(() => {});
      }
    } catch {
      // Notifications unsupported
    }
  }

  function notifyPatch(title, body) {
    try {
      if (!('Notification' in window) || Notification.permission !== 'granted') return;
      new Notification(title, { body, tag: 'retrodroid-patch', silent: true });
    } catch {
      // ignore
    }
  }

  async function runCompatibilityPatcher() {
    if (!selectedPackage || isPatching || isUploading) return;
    isPatching = true;
    clearLinkExpiryTimer();

    if (selectedPackage.serverJobId) ensureNotifyPermission();
    byId('btn-download-full-xapk')?.classList.add('hidden');
    byId('patch-summary-box')?.classList.add('hidden');
    byId('terminal-xapk-progress-box')?.classList.add('hidden');

    const btnPatch = byId('btn-start-patch');
    const btnCancel = byId('btn-cancel-patch');
    btnPatch.disabled = true;

    const panel = byId('patcher-terminal-panel');
    const logsEl = byId('terminal-logs');
    const bar = byId('patch-progress-bar');
    const pctLabel = byId('patch-percent-label');
    const statusTitle = byId('terminal-status-title');
    const statusDot = byId('terminal-status-dot');
    const completeActions = byId('patch-complete-actions');

    let currentPct = 0;
    const setMonotonicProgress = (nextPct) => {
      currentPct = computeMonotonicProgress(currentPct, nextPct);
      bar.style.width = `${currentPct}%`;
      pctLabel.textContent = `${currentPct}%`;
    };

    const appendLog = (tag, colorKey, msg) => {
      const time = new Date().toTimeString().slice(0, 8);
      const line = el('div', { className: 'rd-log-line' }, [
        el('span', { className: 'rd-log-time', textContent: `[${time}]` }),
        el('span', { className: `rd-log-tag rd-log-tag--${colorKey}`, textContent: `[${tag}]` }),
        el('span', {
          className: colorKey === 'rose' ? 'rd-log-msg rd-log-msg--rose' : 'rd-log-msg',
          textContent: msg,
        }),
      ]);
      logsEl.appendChild(line);
      logsEl.scrollTop = logsEl.scrollHeight;
    };

    try {
      panel.classList.remove('hidden');
      completeActions.classList.add('hidden');
      clearNode(logsEl);
      bar.style.width = '0%';
      pctLabel.textContent = '0%';
      statusTitle.textContent = `"${selectedPackage.name}" İşleniyor...`;
      statusDot.className = 'rd-dot rd-dot--lg rd-dot--sky rd-dot--pulse';
      panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

      const pkg = selectedPackage;
      const mods = Array.from(activeModuleIds);
      const completeMsgEl = byId('patch-complete-msg');
      let serverSignedResult = null;
      let rawServerResult = null;

      if (pkg.serverJobId && renderServerOnline) {
        activeServerJobId = pkg.serverJobId;
        btnCancel?.classList.remove('hidden');

        const patchParams = buildPatchSignParams({
          jobId: pkg.serverJobId,
          targetSdk: Number(byId('patch-target-sdk')?.value || 28),
          mode: byId('patch-server-mode')?.value || 'patch_and_sign',
          resign: Boolean(byId('flag-resign')?.checked),
          background: true,
          patchTargetSdk: Boolean(byId('flag-patch-target-sdk')?.checked),
          addLegacyStorage: Boolean(byId('flag-legacy-storage')?.checked),
          enableCleartext: Boolean(byId('flag-cleartext')?.checked),
          addNotchSupport: Boolean(byId('flag-notch-support')?.checked),
          forceExtractNativeLibs: Boolean(byId('flag-extract-native-libs')?.checked),
          allowDowngrade: Boolean(byId('flag-allow-downgrade')?.checked),
        });

        // Monotonic progress starts cleanly at 10% (MED-11: no 55% -> 20% backward jump!)
        setMonotonicProgress(10);
        appendLog('SUNUCU', 'sky', `Gerçek APK işlemi başlatılıyor (Job: ${pkg.serverJobId}) • Hedef API: ${patchParams.targetSdk} • Mod: ${patchParams.mode}`);

        const fd = new FormData();
        for (const [k, v] of Object.entries(patchParams)) {
          fd.append(k, v);
        }

        const base = getRenderApiBase();
        const res = await fetchWithTimeout(`${base}/api/patch-sign`, { method: 'POST', body: fd }, 60000);
        const data = await readJsonOrThrow(res, 'Sunucu yamalama hatası');

        let result = data;
        let usedPolling = false;
        // Handle ALL active statuses including live M2 'running' (not just queued/processing!)
        if (isActiveJobStatus(data.status)) {
          usedPolling = true;
          appendLog('SUNUCU', 'sky', 'İş arka planda başlatıldı — canlı ilerleme ve loglar izleniyor...');
          const pollStatus = await pollServerOperation({
            base,
            statusPath: `/api/patch-status/${data.jobId || pkg.serverJobId}`,
            appendLog,
            onProgress: (pct, stage) => {
              const mapped = Math.min(96, Math.round(pct));
              setMonotonicProgress(mapped);
              if (stage) statusTitle.textContent = `${pkg.name} — ${stage}`;
            },
          });
          result = pollStatus.result;
          appendLog('SUNUCU', 'emerald', 'Sunucu işlemi tamamlandı.');
        }

        if (!result || typeof result !== 'object') {
          throw new Error('Sunucu işlem sonucu boş döndü.');
        }
        if (!usedPolling && Array.isArray(result.logs)) {
          result.logs.forEach(l => appendLog('API', 'emerald', l));
        }
        if (Array.isArray(result.warnings) && result.warnings.length > 0) {
          result.warnings.forEach(w => appendLog('UYARI', 'amber', w));
        }
        appendLog('KURULUM', 'sky', 'ÖNEMLİ: Telefonunuzda bu oyunun eski/orijinal sürümü yüklüyse yeni imzalı APK kurulmadan önce eski sürümü kaldırın.');

        setMonotonicProgress(100);
        rawServerResult = result;
        serverSignedResult = {
          downloadUrl: result.downloadUrl,
          fileName: result.fileName,
          sizeBytes: result.sizeBytes,
          sizeMB: result.sizeMB,
          verified: Boolean(result.verified),
          targetSdk: result.targetSdk,
          minSdk: result.minSdk,
          packageId: result.packageId,
          appLabel: result.appLabel,
          abis: result.abis,
          is32BitOnly: Boolean(result.is32BitOnly),
          inspector: result.inspector || pkg.inspector || null,
          compatScore: result.compatScore,
          patchSummary: result.patchSummary || null,
          repatchAvailable: result.repatchAvailable,
          splitBundle: result.splitBundle
            ? {
              ...result.splitBundle,
              fileName: resolveSplitBundleFileName(result.splitBundle),
            }
            : null,
          obbDownloads: Array.isArray(result.obbDownloads) ? result.obbDownloads : [],
        };
      } else {
        // Honest Local Profile Mode (does NOT modify APK bytes)
        const steps = [
          { pct: 20, tag: 'PROFİL', color: 'sky', msg: `Yerel profil kaydı hazırlanıyor: ${pkg.fileName} (${formatSizeFromMB(pkg.sizeMB)})` },
          { pct: 45, tag: 'DOĞRULA', color: 'emerald', msg: `Yerel başlık bilgisi: ${pkg.signature} • Paket ID: ${pkg.packageId}` },
          { pct: 75, tag: 'NOTLAR', color: 'amber', msg: `Seçili rapor/rehber notları (${mods.length} adet) kaydediliyor. Gerçek APK ikili yaması için sunucu bağlantısı gerekir.` },
          { pct: 100, tag: 'TAMAM', color: 'emerald', msg: 'Yerel profil kütüphaneye kaydedildi (APK dosyası değiştirilmedi).' },
        ];
        for (const step of steps) {
          await new Promise(r => setTimeout(r, 220));
          appendLog(step.tag, step.color, step.msg);
          setMonotonicProgress(step.pct);
        }
      }

      // Mutate newGame from serverSignedResult BEFORE upsert / saveState / renderLibrary (HIGH-08)
      let newGame = {
        ...pkg,
        patchedAt: new Date().toISOString(),
        modules: mods,
        settings: {
          fps: appState.activeProfile === 'performance' ? 90 : 60,
          resolutionScale: 100,
          controlMode: isContainerFormat(pkg.ext) ? 'Sanal Gamepad Katmanı' : 'Eski Dokunmatik Ölçekleme',
          controlLayout: pkg.settings?.controlLayout || controlLayoutDefaults(),
        },
      };
      if (rawServerResult) {
        newGame = applyServerPatchResultToGame(newGame, rawServerResult);
      }

      // Safe upsert preserving saved settings & pruning old sessionFileStore key (MED-07)
      const upsertRes = upsertGameInLibrary(appState.games, newGame, {
        isLocalSimulation: !serverSignedResult,
      });
      appState.games = upsertRes.games;
      const storedGame = appState.games[upsertRes.index];

      const oldEntry = (upsertRes.replacedOldId && sessionFileStore.has(upsertRes.replacedOldId))
        ? sessionFileStore.get(upsertRes.replacedOldId)
        : null;
      if (upsertRes.replacedOldId) {
        sessionFileStore.delete(upsertRes.replacedOldId);
      }
      const curEntry = sessionFileStore.get(storedGame.id) || {};
      const nextEntry = mergeSessionEntryOnUpsert({
        oldEntry,
        curEntry,
        pkg,
        serverSignedResult,
      });
      if (Object.keys(nextEntry).length > 0) {
        sessionFileStore.set(storedGame.id, nextEntry);
      } else {
        sessionFileStore.delete(storedGame.id);
      }

      appState.cacheMB = Math.min(2048, (appState.cacheMB || 120) + 18);
      saveState();
      renderLibrary();

      lastPatchedGame = storedGame;
      if (selectedPackage && selectedPackage.id === storedGame.id) {
        selectedPackage = { ...selectedPackage, ...storedGame };
        byId('pkg-android').textContent = formatSdkSummary(storedGame.legacyAndroid, storedGame.legacyApi, storedGame.minSdk);
        byId('pkg-size').textContent = formatSizeFromMB(storedGame.sizeMB);
        renderPackageInspector(selectedPackage);
        updateCompatBadgeDisplay();
      }

      if (serverSignedResult) {
        const signatureVerified = Boolean(serverSignedResult.verified);
        statusTitle.textContent = signatureVerified
          ? `Gerçek İmzalı APK Hazır! (API ${serverSignedResult.targetSdk} • Doğrulandı ✓)`
          : `APK yeniden paketlendi; imza doğrulanmadı (API ${serverSignedResult.targetSdk}).`;
        if (completeMsgEl) {
          completeMsgEl.textContent = signatureVerified
            ? `${serverSignedResult.fileName} apksigner ile imzalandı ve doğrulandı.`
            : `${serverSignedResult.fileName} imzasız bırakıldı. Kurulum için yeniden imzalama seçeneğini açın.`;
        }
        renderPatchSummary(serverSignedResult.patchSummary, serverSignedResult.repatchAvailable);
        updateFullXapkButtonVisibility();
        showToast(
          signatureVerified ? `${serverSignedResult.fileName} sunucuda imzalandı ve doğrulandı.` : 'APK paketlendi ancak imzalanmadı.',
          signatureVerified ? 'success' : 'warn'
        );
        refreshPatchJobsHistory().then(ttl => startLinkExpiryCountdown(ttl));
        notifyPatch(
          'RetroDroid: Yamalama tamamlandı',
          signatureVerified ? `${storedGame.name} için imzalı APK hazır.` : `${storedGame.name} imzasız paketlendi.`
        );
      } else {
        statusTitle.textContent = 'Yerel profil kaydı tamamlandı (APK değiştirilmedi)';
        if (completeMsgEl) {
          completeMsgEl.textContent = 'Paket profili kütüphaneye eklendi (gerçek APK yaması için sunucu bağlantısı gerekir).';
        }
        showToast(`${storedGame.name} profili kütüphaneye eklendi.`, 'info');
      }

      statusDot.className = 'rd-dot rd-dot--lg rd-dot--emerald';
      completeActions.classList.remove('hidden');
    } catch (err) {
      const isCanceled = err?.name === 'AbortError' || err?.code === 'JOB_CANCELED';
      const errMsg = isCanceled ? 'İşlem kullanıcı tarafından iptal edildi.' : (err?.message || 'Bilinmeyen hata oluştu.');
      appendLog(isCanceled ? 'İPTAL' : 'HATA', isCanceled ? 'amber' : 'rose', errMsg);
      statusTitle.textContent = isCanceled ? 'İşlem iptal edildi' : 'İşlem tamamlanamadı';
      statusDot.className = `rd-dot rd-dot--lg ${isCanceled ? 'rd-dot--amber' : 'rd-dot--rose'}`;
      showToast(isCanceled ? errMsg : `Hata: ${errMsg}`, isCanceled ? 'warn' : 'error');
      if (!isCanceled) notifyPatch('RetroDroid: Yamalama başarısız', errMsg);
      refreshPatchJobsHistory();
    } finally {
      activeServerJobId = null;
      btnCancel?.classList.add('hidden');
      btnPatch.disabled = isUploading;
      isPatching = false;
    }
  }

  // ==========================================================================
  // 11. ASYNC FULL XAPK BUILDER WITH INLINE PROGRESS & CANCEL (F08, MED-10)
  // ==========================================================================
  function setFullXapkProgress(visible, label = '', pct = 0) {
    const dlModalOpen = !byId('modal-download-package')?.classList.contains('hidden');
    if (dlModalOpen) {
      setDownloadProgress(visible, label, pct);
    }
    const inlineBox = byId('terminal-xapk-progress-box');
    if (inlineBox) {
      if (!visible) {
        inlineBox.classList.add('hidden');
      } else {
        inlineBox.classList.remove('hidden');
        byId('terminal-xapk-label').textContent = label;
        byId('terminal-xapk-pct').textContent = `${Math.round(pct)}%`;
        byId('terminal-xapk-bar').style.width = `${Math.min(100, Math.max(0, pct))}%`;
      }
    }
    const obbStatus = byId('obb-folder-status');
    if (obbStatus && visible && label) {
      obbStatus.textContent = `${label} (%${Math.round(pct)})`;
    }
  }

  async function downloadFullSignedXapk(targetGame = null, triggerBtn = null) {
    if (isBuildingFullXapk) {
      showToast('Tam XAPK paketi şu anda hazırlanıyor, lütfen bekleyin...', 'info');
      return;
    }
    const game = (targetGame && targetGame.id) ? targetGame : lastPatchedGame;
    const entry = game ? (sessionFileStore.get(game.id) || {}) : {};
    const jobId = (game && game.serverJobId) || entry.serverJobId;
    if (!game || !jobId) {
      showToast('Tam XAPK için sunucuda tamamlanmış bir imzalama işi gerekli.', 'warn');
      return;
    }

    isBuildingFullXapk = true;
    activeServerJobId = jobId;
    const btn = triggerBtn || byId('btn-download-full-xapk');
    const btnCancel = byId('btn-cancel-patch');
    const prevBtnText = btn ? btn.textContent : '';
    if (btn && btn.id === 'btn-download-full-xapk') {
      btn.disabled = true;
      btn.textContent = 'Tam XAPK hazırlanıyor...';
    }
    btnCancel?.classList.remove('hidden');

    let xapkPct = 5;
    setFullXapkProgress(true, 'Sunucuda İmzalı Tam XAPK hazırlanıyor...', xapkPct);

    try {
      // Strictly scoped per-game OBB upload (zero cross-game leakage — HIGH-06)
      const scopedObbItems = buildScopedObbUploadPlan(sessionFileStore, game.id);
      const needsObbUpload = scopedObbItems.length > 0 && (!entry.serverObbUploaded || entry.obbUploadedJobId !== jobId);
      if (needsObbUpload) {
        setFullXapkProgress(true, 'Paket OBB dosyaları sunucuya aktarılıyor...', 15);
        const data = await uploadObbFilesToRender(jobId, scopedObbItems);
        entry.serverObbUploaded = true;
        entry.obbUploadedJobId = jobId;
        sessionFileStore.set(game.id, entry);
        byId('obb-folder-status').textContent = `${data.count} OBB dosyası sunucuya aktarıldı.`;
      }

      const base = getRenderApiBase();
      const fd = new FormData();
      fd.append('background', 'true');
      const buildRes = await fetchWithTimeout(`${base}/api/full-xapk/${jobId}`, { method: 'POST', body: fd }, 60000);
      const buildData = await readJsonOrThrow(buildRes, 'Tam XAPK başlatılamadı');

      let finalResult = buildData;
      if (isActiveJobStatus(buildData.status)) {
        const pollRes = await pollServerOperation({
          base,
          statusPath: `/api/full-xapk-status/${jobId}`,
          onProgress: (pct, stage) => {
            xapkPct = computeMonotonicProgress(xapkPct, Math.min(96, pct));
            setFullXapkProgress(true, stage || 'İmzalı Tam XAPK birleştiriliyor...', xapkPct);
          },
        });
        finalResult = pollRes.result;
      }

      if (!finalResult || !finalResult.downloadUrl) {
        throw new Error('Tam XAPK indirme adresi alınamadı.');
      }
      setFullXapkProgress(true, 'İmzalı Tam XAPK indiriliyor!', 100);
      setTimeout(() => setFullXapkProgress(false), 1200);

      const dlName = finalResult.fileName || `${(game.packageId || 'retrodroid').replace(/[^A-Za-z0-9._-]/g, '_')}_Full_Signed.xapk`;
      triggerServerFileDownload(finalResult.downloadUrl, dlName);

      const warnings = Array.isArray(finalResult.warnings) ? finalResult.warnings : [];
      if (warnings.length) {
        showToast(`Tam XAPK hazır (Uyarı: ${warnings[0]})`, 'warn');
      } else {
        showToast(`İmzalı Tam XAPK hazırlandı (${formatSizeFromMB((finalResult.sizeBytes || 0) / 1048576)}).`, 'success');
      }
      refreshPatchJobsHistory();
    } catch (err) {
      setFullXapkProgress(false);
      const isCanceled = err?.name === 'AbortError' || err?.code === 'JOB_CANCELED';
      showToast(
        isCanceled ? 'Tam XAPK oluşturma iptal edildi.' : `Tam XAPK oluşturulamadı: ${err.message}`,
        isCanceled ? 'warn' : 'error'
      );
    } finally {
      isBuildingFullXapk = false;
      activeServerJobId = null;
      btnCancel?.classList.add('hidden');
      if (btn && btn.id === 'btn-download-full-xapk') {
        btn.disabled = false;
        btn.textContent = prevBtnText || 'İmzalı Tam XAPK + OBB';
      }
    }
  }

  // ==========================================================================
  // 12. REPORTS, DOWNLOAD CENTER & VALIDATED BACKUP IMPORT/EXPORT (F12)
  // ==========================================================================
  function buildCompatibilityReportObj(game) {
    const activeMods = Array.isArray(game.modules) ? game.modules : Array.from(activeModuleIds);
    return {
      engine: `RetroDroid Compat Engine v${APP_VERSION}`,
      generatedAt: new Date().toISOString(),
      package: {
        name: game.name,
        fileName: game.fileName,
        packageId: game.packageId,
        format: game.ext,
        sizeMB: Number((game.sizeMB || 0).toFixed(2)),
        maxLimitGB: 5.0,
        signatureCheck: game.signature,
        legacyAndroid: game.legacyAndroid,
        legacyApiLevel: game.legacyApi,
        minSdk: game.minSdk || 0,
        sourceArchitecture: game.arch,
        is32BitOnly: Boolean(game.is32BitOnly),
        obbPresent: Boolean(game.hasObb),
      },
      compatibility: {
        scorePercent: typeof game.compatScore === 'number' ? game.compatScore : 0,
        targetAndroidHost: 'Android 14–17 (API 34–36)',
        profileNotes: activeMods.map(id => {
          const m = PATCH_MODULES.find(x => x.id === id);
          return m ? m.title : id;
        }),
        engineProfile: appState.activeProfile,
        abiAuditNote: appState.engineSettings.abi,
        previewProfileNote: appState.engineSettings.renderer,
      },
      inspector: game.inspector || null,
      patchSummary: game.patchSummary || null,
      launchSettings: game.settings || {
        fps: 60,
        resolutionScale: 100,
        controlMode: 'Sanal Gamepad Katmanı',
      },
    };
  }

  function buildInstallGuideText(game, obbName) {
    const pkgId = game.packageId || 'com.oyun.paket';
    const lines = [
      '====================================================',
      `RetroDroid Compat v${APP_VERSION} — Cihaz Kurulum & Uyumluluk Notu`,
      '====================================================',
      `Oyun Adı        : ${game.name}`,
      `Paket Kimliği   : ${pkgId}`,
      `Biçim / Boyut   : ${game.ext} (${formatSizeFromMB(game.sizeMB || 0)})`,
      `SDK Bilgisi     : ${formatSdkSummary(game.legacyAndroid, game.legacyApi, game.minSdk)}`,
      `Mimari          : ${game.arch}`,
      `Profil          : ${appState.activeProfile}`,
      '',
      'KURULUM ADIMLARI (ANDROID):',
      '1) Cihazda aynı oyunun eski/orijinal sürümü varsa önce kaldırın (imza farklı olabilir).',
      '2) APK dosyasını telefonunuzun İndirilenler (Downloads) klasöründen açarak kurun.',
    ];
    if (game.hasObb || obbName) {
      const targetObb = obbName || `main.1.${pkgId}.obb`;
      lines.push('3) OBB dosyasını telefon hafızasında şu klasöre kopyalayın:');
      lines.push(`   /Dahili Depolama/Android/obb/${pkgId}/${targetObb}`);
      if (appState.engineSettings.scopedObb) {
        lines.push('4) Android 11+ cihazlarda dosya yöneticisine SAF (Klasör Erişimi) izni verin veya ZArchiver / Shizuku kullanın.');
      }
    }
    if (appState.engineSettings.audioFix) {
      lines.push('');
      lines.push('ANDROID KURULUM EŞİĞİ NOTU:');
      lines.push('- Android 14: en düşük targetSdk = 23');
      lines.push('- Android 15–17: en düşük targetSdk = 24');
      lines.push('- 64-bit zorunlu cihazlarda yalnızca 32-bit (.so) içeren APK kurulamayabilir.');
    }
    return lines.join('\n');
  }

  function downloadCompatibilityReport(game) {
    if (!game) return;
    const report = buildCompatibilityReportObj(game);
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json;charset=utf-8' });
    const safeName = (game.name || 'paket').toLowerCase().replace(/[^a-z0-9]+/g, '_');
    const dlName = `retrodroid_rapor_${safeName}.json`;
    triggerBlobDownload(blob, dlName);
    showToast(`Uyumluluk raporu (${dlName}) indirildi.`, 'info');
  }

  function openDownloadModalById(gameId) {
    const game = appState.games.find(g => g.id === gameId);
    if (game) openDownloadModal(game);
  }

  function openDownloadModal(game) {
    if (!game) return;
    downloadingTarget = game;
    byId('dl-game-title').textContent = game.name || 'Paket';
    byId('dl-game-meta').textContent = `${game.ext} • ${formatSizeFromMB(game.sizeMB || 0)} • ${game.packageId || 'Paket ID yok'}`;
    byId('dl-progress-box').classList.add('hidden');
    renderDownloadModalBody();
    openDialogEl(byId('modal-download-package'));
  }

  function closeDownloadModal() {
    closeDialogEl(byId('modal-download-package'));
    downloadingTarget = null;
  }

  function setDownloadProgress(visible, label = '', pct = 0) {
    const box = byId('dl-progress-box');
    if (!box) return;
    if (!visible) {
      box.classList.add('hidden');
      return;
    }
    box.classList.remove('hidden');
    byId('dl-progress-label').textContent = label;
    byId('dl-progress-pct').textContent = `${Math.round(pct)}%`;
    byId('dl-progress-bar').style.width = `${Math.min(100, Math.max(0, pct))}%`;
  }

  function renderDownloadModalBody() {
    const game = downloadingTarget;
    if (!game) return;

    const entry = sessionFileStore.get(game.id) || null;
    const banner = byId('dl-status-banner');
    const list = byId('dl-options-list');
    const reattachBox = byId('dl-reattach-box');
    clearNode(list);

    const addOptionBtn = ({ title, subtitle, badge, accent = 'slate', onClick }) => {
      const btn = el('button', {
        type: 'button',
        className: `rd-dl-option ${accent !== 'slate' ? `rd-dl-option--${accent}` : ''}`,
      }, [
        el('div', { className: 'rd-min-w-0' }, [
          el('p', { className: 'rd-dl-title truncate', textContent: title }),
          el('p', { className: 'rd-dl-sub', textContent: subtitle }),
        ]),
        el('span', { className: 'rd-badge mono rd-shrink-0', textContent: badge }),
      ]);
      btn.addEventListener('click', onClick);
      list.appendChild(btn);
    };

    const safeBase = (game.packageId || game.name || 'retrodroid_paket')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '_');

    if (entry && entry.serverDownloadUrl) {
      if (canOfferFullXapk(game, entry, sessionFileStore)) {
        addOptionBtn({
          title: 'İmzalı Tam XAPK + OBB Paketi Oluştur & İndir (.xapk)',
          subtitle: `İmzalı APK${entry.serverSplitBundle ? ' + Split' : ''} + OBB tek XAPK v2 dosyasında (ZArchiver / XAPK Installer ile kurun)`,
          badge: 'TAM XAPK',
          accent: 'emerald',
          onClick: () => downloadFullSignedXapk(game),
        });
      }
      if (entry.serverSplitBundle) {
        const splitName = resolveSplitBundleFileName(entry.serverSplitBundle);
        addOptionBtn({
          title: entry.serverVerified
            ? 'Tüm Parçalı (Split) İmzalı Paketi İndir (.apks)'
            : 'Tüm Parçalı (Split) Paketi İndir — İmzasız (.apks)',
          subtitle: `${splitName} (${formatSizeFromMB((entry.serverSplitBundle.sizeBytes || 0) / 1048576)}) • ${entry.serverVerified ? "Tüm Split APK'lar aynı anahtarla imzalandı" : 'İmzasız bırakıldı'}`,
          badge: entry.serverVerified ? 'İMZALI APKS' : 'İMZASIZ APKS',
          accent: entry.serverVerified ? 'emerald' : 'slate',
          onClick: () => {
            if (triggerServerFileDownload(entry.serverSplitBundle.downloadUrl, splitName)) {
              showToast(`${splitName} cihazınıza indiriliyor...`, 'success');
            }
          },
        });
      }
      addOptionBtn({
        title: entry.serverVerified
          ? (entry.serverSplitBundle ? 'Yalnızca Ana İmzalı APK İndir (.apk)' : 'Sunucu İmzalı & Doğrulanmış APK İndir (.apk)')
          : 'Sunucu Paketlenmiş APK İndir — İmzasız (.apk)',
        subtitle: `${entry.serverFileName || game.fileName} • API ${entry.serverTargetSdk || 28} • ${entry.serverVerified ? 'v1/v2/v3 İmza Doğrulandı ✓' : 'İmzasız (kurulum için imzalama gerekir)'}${entry.serverIs32BitOnly ? ' • Yalnızca 32-bit!' : ''}`,
        badge: entry.serverVerified ? 'İMZALI APK' : 'İMZASIZ APK',
        accent: entry.serverVerified ? (entry.serverSplitBundle ? 'sky' : 'emerald') : 'slate',
        onClick: () => {
          const fname = entry.serverFileName || 'uyumlu.apk';
          if (triggerServerFileDownload(entry.serverDownloadUrl, fname)) {
            showToast(`${fname} cihazınıza indiriliyor...`, 'success');
          }
        },
      });
      if (Array.isArray(entry.serverObbDownloads)) {
        for (const obb of entry.serverObbDownloads) {
          addOptionBtn({
            title: 'XAPK İçinden Çıkan OBB Dosyasını İndir',
            subtitle: `${obb.name} (${formatSizeFromMB((obb.sizeBytes || 0) / 1048576)}) → /Android/obb/${game.packageId}/`,
            badge: '.OBB',
            accent: 'violet',
            onClick: () => {
              if (triggerServerFileDownload(obb.downloadUrl, obb.name)) {
                showToast(`${obb.name} indiriliyor...`, 'info');
              }
            },
          });
        }
      }
    }

    if (entry && entry.apkFile && entry.obbFile) {
      const obbName = entry.obbTargetName || entry.obbFile.name;
      banner.className = 'rd-subbox rd-subbox--emerald rd-field-hint';
      banner.textContent = `APK (${formatSizeFromMB(entry.apkFile.size / 1048576)}) ve OBB (${formatSizeFromMB(entry.obbFile.size / 1048576)}) bu oturumda hazır.`;
      reattachBox.classList.add('hidden');

      addOptionBtn({
        title: 'Kurulum Klasörü Paketi İndir (.zip)',
        subtitle: `APK kökte + Android/obb/${game.packageId}/${obbName} + uyumluluk raporu (maks. 512 MB tarayıcı limiti)`,
        badge: '.ZIP',
        accent: 'emerald',
        onClick: () => downloadZipBundleForGame(game, entry),
      });
      addOptionBtn({
        title: 'APK Dosyasını Doğrudan İndir',
        subtitle: `${entry.apkFile.name} — Ek bellek kullanmadan doğrudan indir`,
        badge: '.APK',
        accent: 'sky',
        onClick: () => {
          triggerBlobDownload(entry.apkFile, entry.apkFile.name);
          showToast(`${entry.apkFile.name} indiriliyor.`, 'success');
        },
      });
      addOptionBtn({
        title: 'OBB Dosyasını Kanonik Adla İndir',
        subtitle: `${obbName} — /Android/obb/${game.packageId}/ içine taşıyın`,
        badge: '.OBB',
        accent: 'violet',
        onClick: () => {
          triggerBlobDownload(entry.obbFile, obbName);
          showToast(`${obbName} indiriliyor.`, 'success');
        },
      });
    } else if (entry && entry.singleFile) {
      const file = entry.singleFile;
      const extMatch = file.name.match(/\.[a-z0-9]+$/i);
      const extUpper = extMatch ? extMatch[0].toUpperCase() : '.APK';
      banner.className = 'rd-subbox rd-subbox--emerald rd-field-hint';
      banner.textContent = `Yüklediğiniz gerçek dosya (${file.name} • ${formatSizeFromMB(file.size / 1048576)}) doğrudan indirmeye hazır.`;
      reattachBox.classList.add('hidden');

      addOptionBtn({
        title: `Doğrudan Paketi Cihaza İndir (${extUpper})`,
        subtitle: `${file.name} — Ek RAM kullanmadan doğrudan indirilir`,
        badge: extUpper,
        accent: 'emerald',
        onClick: () => {
          triggerBlobDownload(file, file.name);
          showToast(`${file.name} indiriliyor.`, 'success');
        },
      });
      addOptionBtn({
        title: 'Kurulum Paketi + Rapor İndir (.zip)',
        subtitle: file.size > CLIENT_ZIP_MAX_BYTES
          ? '512 MB üzeri dosya: Tarayıcı ZIP belleği yerine Doğrudan İndir veya Sunucu Tam XAPK kullanın.'
          : `${file.name} + retrodroid_rapor.json + KURULUM_REHBERI.txt tek ZIP içinde`,
        badge: '.ZIP',
        accent: 'sky',
        onClick: () => downloadZipBundleForGame(game, entry),
      });
    } else {
      banner.className = 'rd-subbox rd-subbox--amber rd-field-hint';
      banner.textContent = 'Bu kayıt bir örnek profil veya önceki oturumdan kalma kayıt. Gerçek APK/OBB dosyaları güvenlik gereği sayfa yenilenince bellekte tutulmaz.';
      reattachBox.classList.remove('hidden');

      addOptionBtn({
        title: 'Uyumluluk & OBB Klasör Şablonu İndir (.zip)',
        subtitle: `retrodroid_rapor.json + KURULUM_REHBERI.txt${game.hasObb ? ` + Android/obb/${game.packageId}/ yol notu` : ''}`,
        badge: '.ZIP',
        accent: 'sky',
        onClick: () => downloadZipBundleForGame(game, null),
      });
    }

    addOptionBtn({
      title: 'Uyumluluk Raporunu İndir (.json)',
      subtitle: `retrodroid_rapor_${safeBase}.json`,
      badge: '.JSON',
      accent: 'slate',
      onClick: () => downloadCompatibilityReport(game),
    });
  }

  async function downloadZipBundleForGame(game, entry) {
    if (isExportingZip) {
      showToast('Başka bir ZIP arşivi oluşturuluyor, lütfen bekleyin.', 'warn');
      return;
    }
    const payloadFiles = [];
    if (entry?.apkFile && entry?.obbFile) payloadFiles.push(entry.apkFile, entry.obbFile);
    else if (entry?.singleFile) payloadFiles.push(entry.singleFile);

    const budget = checkClientZipBudget(payloadFiles);
    if (!budget.ok) {
      showToast(budget.reason, 'warn');
      return;
    }

    isExportingZip = true;
    const safeBase = (game.packageId || game.name || 'retrodroid_paket')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '_');

    setDownloadProgress(true, 'Çevrimdışı ZIP arşivi hazırlanıyor...', 8);
    try {
      const zip = new JSZip();
      const reportObj = buildCompatibilityReportObj(game);
      let obbName = '';

      if (entry && entry.apkFile && entry.obbFile) {
        obbName = entry.obbTargetName || entry.obbFile.name;
        zip.file(entry.apkFile.name, entry.apkFile);
        zip.file(`Android/obb/${game.packageId}/${obbName}`, entry.obbFile);
      } else if (entry && entry.singleFile) {
        zip.file(entry.singleFile.name, entry.singleFile);
      } else if (game.hasObb && game.packageId) {
        zip.file(
          `Android/obb/${game.packageId}/OBB_DOSYASINI_BURAYA_KOYUN.txt`,
          `Bu oyunun .obb dosyasını telefonunuzda /Android/obb/${game.packageId}/ klasörüne yerleştirin.\n`
        );
      }

      zip.file('retrodroid_rapor.json', JSON.stringify(reportObj, null, 2));
      zip.file('KURULUM_REHBERI.txt', buildInstallGuideText(game, obbName));

      const blob = await zip.generateAsync(
        { type: 'blob', compression: 'STORE' },
        (meta) => {
          setDownloadProgress(true, 'Paket derleniyor...', meta.percent || 0);
        }
      );

      const dlName = `${safeBase}_RetroDroid_Paket.zip`;
      triggerBlobDownload(blob, dlName);
      setDownloadProgress(true, 'İndirme başlatıldı!', 100);
      setTimeout(() => setDownloadProgress(false), 1200);
      showToast(`${dlName} cihazınıza indirildi.`, 'success');
    } catch (err) {
      console.error('ZIP paketleme hatası:', err);
      setDownloadProgress(false);
      showToast('ZIP oluşturulamadı. Doğrudan dosya indirmeyi deneyin.', 'error');
    } finally {
      isExportingZip = false;
    }
  }

  function teardownTransientState() {
    lastPatchedGame = null;
    selectedPackage = null;
    downloadingTarget = null;
    editingGameId = null;
    pairedApkFile = null;
    pairedObbFile = null;
    pairedPackageId = '';
    stagedObbFiles = [];
    sessionFileStore.clear();
    clearLinkExpiryTimer();
    byId('selected-package-card')?.classList.add('hidden');
    byId('patcher-terminal-panel')?.classList.add('hidden');
    const urlInput = byId('render-api-url');
    if (urlInput) urlInput.value = appState.renderApiUrl || '';
    renderObbFolderSelection();
  }

  function exportAppBackup() {
    const backup = createBackupPayload(appState);
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json;charset=utf-8' });
    const dateStr = new Date().toISOString().slice(0, 10);
    const fileName = `retrodroid_yedek_${dateStr}.json`;
    triggerBlobDownload(blob, fileName);
    showToast(`Uygulama yedeği (${fileName}) indirildi.`, 'success');
  }

  async function importAppBackup(file) {
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const importedState = parsed && parsed.state ? parsed.state : parsed;
      if (!importedState || !Array.isArray(importedState.games)) {
        showToast('Geçersiz yedek dosyası biçimi.', 'error');
        return;
      }
      appState = sanitizeAppState(importedState);
      teardownTransientState();
      saveState();
      renderLibrary();
      renderEngineTab();
      renderSystemTab();
      updateHeaderProfileBadge();
      switchTab(appState.activeTab);
      showToast(`Yedek doğrulandı ve geri yüklendi (${appState.games.length} paket).`, 'success');
    } catch (err) {
      console.error('Yedek geri yükleme hatası:', err);
      showToast('Yedek dosyası okunamadı. Geçerli bir RetroDroid .json yedeği seçin.', 'error');
    }
  }

  // ==========================================================================
  // 13. TAB 3 (PROFILES) & TAB 4 (SYSTEM + NORMALIZED SVG DONUT)
  // ==========================================================================
  function renderEngineTab() {
    const grid = byId('profiles-grid');
    if (!grid) return;
    clearNode(grid);

    for (const prof of ENGINE_PROFILES) {
      const isActive = appState.activeProfile === prof.id;
      const card = el('button', {
        type: 'button',
        className: `rd-profile-card ${isActive ? 'rd-profile-card--active' : ''}`,
        'aria-pressed': isActive ? 'true' : 'false',
      }, [
        el('div', { className: 'rd-stack-xs' }, [
          el('div', { className: 'rd-row-between' }, [
            el('span', { className: `rd-badge rd-badge--pill ${isActive ? 'rd-badge--emerald' : ''}`, textContent: prof.badge }),
            isActive
              ? el('span', { className: 'rd-badge rd-badge--emerald', textContent: 'AKTİF' })
              : null,
          ]),
          el('h3', { className: 'rd-heading rd-heading--sm', textContent: prof.name }),
          el('p', { className: 'rd-field-hint', textContent: prof.desc }),
        ]),
        el('div', { className: 'rd-row-between rd-divider mono rd-field-hint' }, [
          el('span', { textContent: `Hedef: API ${prof.defaultTargetSdk}` }),
          el('span', { textContent: `RAM Etiketi: ${prof.ram} MB` }),
        ]),
      ]);

      card.addEventListener('click', () => {
        appState.activeProfile = prof.id;
        appState.engineSettings.abi = prof.abi;
        appState.engineSettings.renderer = prof.renderer;
        appState.engineSettings.ram = prof.ram;
        activeModuleIds = new Set(prof.defaultModules);
        applyProfileDefaultsToPatchForm(prof);
        syncPatchModulesInPlace();
        saveState();
        renderEngineTab();
        updateHeaderProfileBadge();
        showToast(`"${prof.name}" profili aktif edildi.`, 'success');
      });

      grid.appendChild(card);
    }

    byId('engine-abi').value = appState.engineSettings.abi;
    byId('engine-renderer').value = appState.engineSettings.renderer;
    byId('engine-ram').value = String(appState.engineSettings.ram);
    byId('engine-ram-val').textContent = `${appState.engineSettings.ram} MB`;
    byId('engine-scoped-obb').checked = appState.engineSettings.scopedObb;
    byId('engine-audio-fix').checked = appState.engineSettings.audioFix;
  }

  function updateHeaderProfileBadge() {
    const prof = ENGINE_PROFILES.find(p => p.id === appState.activeProfile) || ENGINE_PROFILES[0];
    const badge = byId('header-profile-badge');
    if (badge) badge.textContent = prof.shortName;
  }

  function renderSystemTab() {
    const stats = computeStorageBreakdown(appState.games, appState.cacheMB, SANDBOX_QUOTA_MB);

    byId('sys-largest-pkg').textContent = `${formatSizeFromMB(stats.largestMB)} / 5.00 GB`;
    byId('sys-largest-bar').style.width = `${stats.largestPct.toFixed(1)}%`;

    byId('sandbox-used-pct').textContent = `%${stats.usedPct.toFixed(1)}`;
    byId('donut-total-gb').textContent = formatSizeFromMB(stats.totalUsedMB);
    byId('storage-xapk-val').textContent = formatSizeFromMB(stats.containerMB);
    byId('storage-apk-val').textContent = formatSizeFromMB(stats.apkMB);
    byId('storage-cache-val').textContent = formatSizeFromMB(stats.cacheMB);
    byId('storage-free-val').textContent = formatSizeFromMB(stats.freeMB);

    const C = stats.circumference;
    const dXapk = byId('donut-xapk');
    const dApk = byId('donut-apk');
    const dCache = byId('donut-cache');

    dXapk.style.strokeDasharray = `${stats.arcs.container.toFixed(2)} ${C.toFixed(2)}`;
    dXapk.style.strokeDashoffset = '0';
    dXapk.style.display = stats.containerMB > 0 ? '' : 'none';

    dApk.style.strokeDasharray = `${stats.arcs.apk.toFixed(2)} ${C.toFixed(2)}`;
    dApk.style.strokeDashoffset = `${stats.arcs.apkOffset.toFixed(2)}`;
    dApk.style.display = stats.apkMB > 0 ? '' : 'none';

    dCache.style.strokeDasharray = `${stats.arcs.cache.toFixed(2)} ${C.toFixed(2)}`;
    dCache.style.strokeDashoffset = `${stats.arcs.cacheOffset.toFixed(2)}`;
    dCache.style.display = stats.cacheMB > 0 ? '' : 'none';

    const verGrid = byId('android-versions-grid');
    clearNode(verGrid);
    for (const item of LEGACY_ANDROID_VERSIONS) {
      verGrid.appendChild(el('div', { className: 'rd-version-card' }, [
        el('div', { className: 'rd-min-w-0' }, [
          el('div', { className: 'rd-row-wrap' }, [
            el('span', { className: 'rd-flag-title', textContent: item.ver }),
            el('span', { className: 'mono rd-metric-value--sky', textContent: item.api }),
          ]),
          el('p', { className: 'rd-field-hint truncate', textContent: `${item.codename} • ${item.note}` }),
        ]),
        el('span', { className: 'rd-badge rd-badge--emerald rd-shrink-0', textContent: item.status }),
      ]));
    }
  }

  // ==========================================================================
  // 14. GAME SETTINGS, CONTROL EDITOR & VIRTUAL SANDBOX PREVIEW (F14)
  // ==========================================================================
  function updateFpsButtonStyles(selectedFps) {
    document.querySelectorAll('.fps-opt').forEach(btn => {
      const isSelected = Number(btn.dataset.fps) === Number(selectedFps);
      btn.classList.toggle('fps-opt--active', isSelected);
      btn.dataset.selected = isSelected ? 'true' : 'false';
      btn.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    });
  }

  function openGameSettings(gameId) {
    const game = appState.games.find(g => g.id === gameId);
    if (!game) return;
    editingGameId = gameId;

    byId('settings-game-title').textContent = game.name;
    updateFpsButtonStyles(game.settings.fps);
    byId('settings-res-range').value = String(game.settings.resolutionScale);
    byId('settings-res-label').textContent = `%${game.settings.resolutionScale}`;
    byId('settings-control-mode').value = game.settings.controlMode;
    openDialogEl(byId('modal-game-settings'));
  }

  function closeGameSettings() {
    closeDialogEl(byId('modal-game-settings'));
    editingGameId = null;
  }

  function openConfirmModal(title, message, onConfirm) {
    byId('confirm-title').textContent = title;
    byId('confirm-message').textContent = message;
    confirmCallback = onConfirm;
    openDialogEl(byId('modal-confirm'));
  }

  function closeConfirmModal() {
    closeDialogEl(byId('modal-confirm'));
    confirmCallback = null;
  }

  function renderControlLayoutError(validation) {
    const errEl = byId('control-layout-error');
    const selects = Array.from(document.querySelectorAll('[data-control-map]'));
    selects.forEach(s => s.classList.remove('rd-select--error'));

    if (!validation || validation.valid) {
      if (errEl) {
        errEl.classList.add('hidden');
        errEl.textContent = '';
      }
      return;
    }

    const conflictingControls = new Set();
    const parts = validation.duplicates.map(dup => {
      dup.controls.forEach(c => conflictingControls.add(c));
      const keyLabel = (CONTROL_KEY_OPTIONS.find(([v]) => v === dup.code) || [dup.code, dup.code])[1];
      const names = dup.controls.map(c => ownGet(CONTROL_ACTION_LABELS, c, c)).join(' ve ');
      return `"${keyLabel}" tuşu hem ${names} için seçilmiş`;
    });

    selects.forEach(s => {
      if (conflictingControls.has(s.dataset.controlMap)) {
        s.classList.add('rd-select--error');
      }
    });
    if (errEl) {
      errEl.textContent = `Çakışan tuş ataması: ${parts.join('; ')}. Her tuş yalnızca bir kontrole atanabilir.`;
      errEl.classList.remove('hidden');
    }
  }

  function openControlLayoutEditor() {
    const game = appState.games.find(g => g.id === editingGameId);
    if (!game) return;
    const layout = { ...controlLayoutDefaults(), ...(game.settings.controlLayout || {}) };
    layout.mapping = { ...controlLayoutDefaults().mapping, ...(game.settings.controlLayout?.mapping || {}) };

    byId('control-layout-side').value = layout.side;
    byId('control-layout-size').value = String(layout.size);
    byId('control-layout-size-label').textContent = `%${layout.size}`;
    byId('control-layout-opacity').value = String(layout.opacity);
    byId('control-layout-opacity-label').textContent = `%${layout.opacity}`;

    const mapGrid = byId('control-layout-mappings');
    clearNode(mapGrid);
    for (const [actionKey, actionLabel] of Object.entries(CONTROL_ACTION_LABELS)) {
      const sel = el('select', {
        className: 'rd-select',
        dataset: { controlMap: actionKey },
      }, CONTROL_KEY_OPTIONS.map(([val, lbl]) => el('option', {
        value: val,
        textContent: lbl,
        selected: layout.mapping[actionKey] === val,
      })));
      sel.addEventListener('change', () => {
        const curMapping = {};
        document.querySelectorAll('[data-control-map]').forEach(s => { curMapping[s.dataset.controlMap] = s.value; });
        renderControlLayoutError(validateControlMapping(curMapping));
      });
      mapGrid.appendChild(el('label', { className: 'rd-label' }, [
        el('span', { textContent: actionLabel }),
        sel,
      ]));
    }
    renderControlLayoutError({ valid: true, duplicates: [] });
    openDialogEl(byId('modal-control-layout'));
  }

  function closeControlLayoutEditor() {
    closeDialogEl(byId('modal-control-layout'));
  }

  function saveControlLayoutEditor(reset = false) {
    const game = appState.games.find(g => g.id === editingGameId);
    if (!game) return;
    const layout = controlLayoutDefaults();
    if (!reset) {
      layout.size = Number(byId('control-layout-size').value);
      layout.opacity = Number(byId('control-layout-opacity').value);
      layout.side = byId('control-layout-side').value;
      document.querySelectorAll('[data-control-map]').forEach(select => {
        layout.mapping[select.dataset.controlMap] = select.value;
      });
      const validation = validateControlMapping(layout.mapping);
      renderControlLayoutError(validation);
      if (!validation.valid) {
        showToast('Aynı klavye tuşu birden fazla kontrole atanamaz.', 'error');
        return;
      }
    }
    game.settings.controlLayout = layout;
    if (sandboxActiveGame && sandboxActiveGame.id === game.id) {
      sandboxActiveGame = game;
      applySandboxControlLayout(game);
    }
    saveState();
    if (reset) {
      openControlLayoutEditor();
      showToast('Kontrol düzeni varsayılana sıfırlandı.', 'info');
    } else {
      closeControlLayoutEditor();
      showToast('Özel kontrol düzeni kaydedildi.', 'success');
    }
  }

  function applySandboxControlLayout(game) {
    const root = byId('sandbox-vpad');
    if (!root) return;
    const layout = { ...controlLayoutDefaults(), ...(game?.settings?.controlLayout || {}) };
    const dpad = root.children[0];
    const actions = root.children[1];
    root.style.opacity = String(layout.opacity / 100);
    if (dpad) {
      dpad.style.order = layout.side === 'reversed' ? '2' : '1';
      dpad.style.transform = `scale(${layout.size / 100})`;
      dpad.style.transformOrigin = layout.side === 'reversed' ? 'right bottom' : 'left bottom';
    }
    if (actions) {
      actions.style.order = layout.side === 'reversed' ? '1' : '2';
      actions.style.transform = `scale(${layout.size / 100})`;
      actions.style.transformOrigin = layout.side === 'reversed' ? 'left bottom' : 'right bottom';
    }
  }

  function getSandboxKeyMap() {
    const mapping = { ...controlLayoutDefaults().mapping, ...(sandboxActiveGame?.settings?.controlLayout?.mapping || {}) };
    const map = Object.create(null);
    for (const [control, code] of Object.entries(mapping)) {
      if (code && typeof code === 'string') map[code] = control;
    }
    return map;
  }

  function clearAllPressedKeys() {
    pressedKeys.clear();
    document.querySelectorAll('.vpad-btn.pressed').forEach(b => b.classList.remove('pressed'));
    updateInputHud();
  }

  function clearSandboxTimeouts() {
    sandboxTimeouts.forEach(id => clearTimeout(id));
    sandboxTimeouts = [];
  }

  function resizeSandboxCanvas() {
    const canvas = byId('sandbox-canvas');
    const viewport = byId('sandbox-viewport');
    if (!canvas || !viewport) return;
    const dims = computeHiDpiDimensions(
      viewport.clientWidth || window.innerWidth,
      viewport.clientHeight || window.innerHeight,
      window.devicePixelRatio || 1
    );
    sandboxCanvasMetrics = dims;
    canvas.width = dims.backingWidth;
    canvas.height = dims.backingHeight;
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.setTransform(dims.dpr, 0, 0, dims.dpr, 0, 0);

    // Re-clamp player & stars inside new logical viewport bounds
    if (sandboxPlayerRef) {
      const clamped = computeSandboxStep({
        player: sandboxPlayerRef,
        keys: [],
        dt: 0,
        width: dims.cssWidth,
        height: dims.cssHeight,
      });
      sandboxPlayerRef.x = clamped.x;
      sandboxPlayerRef.y = clamped.y;
    }
    for (const s of sandboxStarsRef) {
      if (s.x > dims.cssWidth) s.x = Math.random() * dims.cssWidth;
      if (s.y > dims.cssHeight) s.y = Math.random() * dims.cssHeight;
    }
  }

  function launchGame(gameId) {
    const game = appState.games.find(g => g.id === gameId);
    if (!game) return;
    clearSandboxTimeouts();
    if (sandboxAnimFrame) { cancelAnimationFrame(sandboxAnimFrame); sandboxAnimFrame = null; }
    if (sandboxTelemetryInterval) { clearInterval(sandboxTelemetryInterval); sandboxTelemetryInterval = null; }
    clearAllPressedKeys();

    sandboxActiveGame = game;
    applySandboxControlLayout(game);

    const overlay = byId('sandbox-overlay');
    const bootLayer = byId('sandbox-boot-layer');
    const bootSteps = byId('boot-steps');

    byId('sandbox-game-name').textContent = `${game.name} — Web Önizleme`;
    byId('sandbox-game-meta').textContent =
      `Simülasyon Önizlemesi • ${formatSdkSummary(game.legacyAndroid, game.legacyApi, game.minSdk)} • ${game.ext}`;
    byId('boot-title').textContent = `${game.name} Kontrol Önizlemesi Hazırlanıyor...`;
    byId('hud-scale').textContent = `%${game.settings.resolutionScale}`;

    bootLayer.classList.remove('hidden');
    clearNode(bootSteps);
    openDialogEl(overlay);
    resizeSandboxCanvas();

    const sequence = [
      `> Web kontrol önizleme sahnesi başlatılıyor (Profil RAM etiketi: ${appState.engineSettings.ram} MB)...`,
      `> Paket özeti: ${game.packageId || game.fileName} • ${game.arch}`,
      game.hasObb
        ? `> OBB referans yolu: /Android/obb/${game.packageId}/`
        : '> Tekil APK profili yüklendi (OBB gerekmiyor).',
      `> Hedef önizleme profili: ${game.settings.fps} FPS • Ölçek %${game.settings.resolutionScale}`,
      '> NOT: Bu ekran tarayıcı kontrol ve profil önizlemesidir; gerçek Android APK çalıştırmaz.',
    ];

    sequence.forEach((line, idx) => {
      sandboxTimeouts.push(setTimeout(() => {
        if (!sandboxActiveGame) return;
        bootSteps.appendChild(el('div', {
          className: idx === sequence.length - 1 ? 'rd-metric-value--amber' : '',
          textContent: line,
        }));
      }, idx * 240));
    });

    sandboxTimeouts.push(setTimeout(() => {
      if (!sandboxActiveGame) return;
      bootLayer.classList.add('hidden');
      startSandboxLoop();
    }, sequence.length * 240 + 350));
  }

  function exitSandbox() {
    clearSandboxTimeouts();
    clearAllPressedKeys();
    sandboxActiveGame = null;
    sandboxPlayerRef = null;
    sandboxStarsRef = [];
    if (sandboxAnimFrame) { cancelAnimationFrame(sandboxAnimFrame); sandboxAnimFrame = null; }
    if (sandboxTelemetryInterval) { clearInterval(sandboxTelemetryInterval); sandboxTelemetryInterval = null; }
    closeDialogEl(byId('sandbox-overlay'));
    showToast('Web önizleme sahnesi kapatıldı.', 'info');
  }

  function startSandboxLoop() {
    const canvas = byId('sandbox-canvas');
    const ctx = canvas.getContext('2d');
    let t = 0;

    const { cssWidth: initW, cssHeight: initH } = sandboxCanvasMetrics;
    sandboxPlayerRef = { x: initW * 0.5, y: initH * 0.5, pulse: 0 };
    sandboxStarsRef = Array.from({ length: 65 }, () => ({
      x: Math.random() * initW,
      y: Math.random() * initH,
      speed: 45 + Math.random() * 120, // px/s
      size: 1 + Math.random() * 2,
    }));

    const targetFps = [30, 60, 90, 120].includes(sandboxActiveGame.settings.fps)
      ? sandboxActiveGame.settings.fps
      : 60;
    const frameIntervalMs = 1000 / targetFps;
    const baseRam = isContainerFormat(sandboxActiveGame.ext) ? 1420 : 310;

    let lastRenderTime = performance.now();
    let frameCounter = 0;
    let fpsSampleStart = lastRenderTime;

    if (sandboxTelemetryInterval) clearInterval(sandboxTelemetryInterval);
    sandboxTelemetryInterval = setInterval(() => {
      if (!sandboxActiveGame) return;
      const now = performance.now();
      const elapsedSec = Math.max(0.1, (now - fpsSampleStart) / 1000);
      const measuredFps = Math.min(targetFps, Math.round(frameCounter / elapsedSec));
      frameCounter = 0;
      fpsSampleStart = now;
      byId('hud-fps').textContent = `${measuredFps || targetFps}/${targetFps}`;
      byId('hud-ram').textContent = `${baseRam} MB`;
    }, 700);

    function frame(now) {
      if (!sandboxActiveGame) return;
      const elapsedMs = now - lastRenderTime;
      if (elapsedMs < frameIntervalMs * 0.92) {
        sandboxAnimFrame = requestAnimationFrame(frame);
        return;
      }
      const dt = Math.min(0.1, elapsedMs / 1000);
      lastRenderTime = now;
      frameCounter++;
      t += dt * 1.5;

      const w = sandboxCanvasMetrics.cssWidth;
      const h = sandboxCanvasMetrics.cssHeight;
      ctx.setTransform(sandboxCanvasMetrics.dpr, 0, 0, sandboxCanvasMetrics.dpr, 0, 0);

      // Delta-time physics step (LOW-06)
      sandboxPlayerRef = computeSandboxStep({
        player: sandboxPlayerRef,
        keys: pressedKeys,
        dt,
        width: w,
        height: h,
        speedPxPerSec: 252,
      });

      const grad = ctx.createLinearGradient(0, 0, 0, h);
      if (sandboxActiveGame.genre === 'city') {
        grad.addColorStop(0, '#130724');
        grad.addColorStop(0.55, '#2b0f3f');
        grad.addColorStop(1, '#090d1a');
      } else if (sandboxActiveGame.genre === 'arcade') {
        grad.addColorStop(0, '#091b2a');
        grad.addColorStop(0.65, '#0f2f3f');
        grad.addColorStop(1, '#0b1812');
      } else {
        grad.addColorStop(0, '#070c17');
        grad.addColorStop(0.6, '#0d1a2c');
        grad.addColorStop(1, '#061116');
      }
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);

      ctx.fillStyle = 'rgba(148, 163, 184, 0.55)';
      for (const s of sandboxStarsRef) {
        s.x -= s.speed * dt;
        if (s.x < 0) {
          s.x = w;
          s.y = Math.random() * h;
        }
        ctx.fillRect(s.x, s.y, s.size, s.size);
      }

      const horizon = h * 0.56;
      ctx.strokeStyle = sandboxActiveGame.genre === 'city'
        ? 'rgba(232, 121, 249, 0.25)'
        : 'rgba(16, 185, 129, 0.24)';
      ctx.lineWidth = 1;

      for (let i = 0; i < 12; i++) {
        const offset = ((t * 40 + i * 28) % 336) / 336;
        const y = horizon + Math.pow(offset, 1.8) * (h - horizon);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      const cx = w / 2;
      for (let i = -8; i <= 8; i++) {
        ctx.beginPath();
        ctx.moveTo(cx + i * 24, horizon);
        ctx.lineTo(cx + i * 160, h);
        ctx.stroke();
      }

      const radius = 20 + sandboxPlayerRef.pulse * 16;
      ctx.beginPath();
      ctx.arc(sandboxPlayerRef.x, sandboxPlayerRef.y, radius, 0, Math.PI * 2);
      ctx.strokeStyle = sandboxPlayerRef.pulse > 0.15 ? '#38bdf8' : '#10b981';
      ctx.lineWidth = 2.5;
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(sandboxPlayerRef.x - 10, sandboxPlayerRef.y);
      ctx.lineTo(sandboxPlayerRef.x + 10, sandboxPlayerRef.y);
      ctx.moveTo(sandboxPlayerRef.x, sandboxPlayerRef.y - 10);
      ctx.lineTo(sandboxPlayerRef.x, sandboxPlayerRef.y + 10);
      ctx.stroke();

      ctx.fillStyle = 'rgba(241, 245, 249, 0.9)';
      ctx.font = '700 15px Inter, system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(sandboxActiveGame.name.toUpperCase(), w / 2, horizon - 38);

      ctx.fillStyle = 'rgba(251, 191, 36, 0.9)';
      ctx.font = '600 11px ui-monospace, monospace';
      ctx.fillText(
        `WEB KONTROL ÖNİZLEMESİ (SİMÜLASYON) • ${targetFps} FPS • ${formatSdkSummary(sandboxActiveGame.legacyAndroid, sandboxActiveGame.legacyApi, sandboxActiveGame.minSdk)}`,
        w / 2,
        horizon - 16
      );

      sandboxAnimFrame = requestAnimationFrame(frame);
    }

    sandboxAnimFrame = requestAnimationFrame(frame);
  }

  function updateInputHud() {
    const hudEl = byId('hud-input-status');
    if (!hudEl) return;
    hudEl.textContent = pressedKeys.size === 0
      ? 'GİRDİ: Hazır (Klavye / Sanal Gamepad)'
      : `GİRDİ AKTİF: ${Array.from(pressedKeys).join(' + ')}`;
  }

  // ==========================================================================
  // 15. DELEGATED EVENT WIRING & BOOTSTRAP
  // ==========================================================================
  function initEvents() {
    // Hydrate saved URL & session API token
    const renderUrlInput = byId('render-api-url');
    if (renderUrlInput) renderUrlInput.value = appState.renderApiUrl || '';
    const tokenInput = byId('render-api-token');
    if (tokenInput) tokenInput.value = getApiToken();

    // Global delegated clicks (tab switches & modal close buttons — zero inline onclick)
    document.addEventListener('click', (e) => {
      const tabTrigger = e.target.closest('[data-switch-tab]');
      if (tabTrigger) {
        switchTab(tabTrigger.dataset.switchTab);
        return;
      }
      const closeTrigger = e.target.closest('[data-close-modal]');
      if (closeTrigger) {
        const which = closeTrigger.dataset.closeModal;
        if (which === 'game-settings') closeGameSettings();
        else if (which === 'download-package') closeDownloadModal();
      }
    });

    // Delegated Library Card Actions (CRIT-01 zero XSS)
    byId('library-grid')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-action][data-game-id]');
      if (!btn) return;
      const { action, gameId } = btn.dataset;
      if (action === 'launch') launchGame(gameId);
      else if (action === 'download') openDownloadModalById(gameId);
      else if (action === 'settings') openGameSettings(gameId);
    });

    // Delegated Server Jobs Actions (Cancel / Delete)
    byId('patch-jobs-list')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-job-action][data-job-id]');
      if (!btn) return;
      const { jobAction, jobId } = btn.dataset;
      if (jobAction === 'cancel') cancelServerJob(jobId);
      else if (jobAction === 'delete') deleteServerJob(jobId);
    });

    // Server URL save with strict scheme validation (MED-12)
    byId('btn-save-render-url').addEventListener('click', () => {
      const raw = byId('render-api-url').value;
      const check = validateRenderApiUrl(raw);
      if (!check.valid) {
        byId('render-api-url').classList.add('rd-input--error');
        showToast(check.error, 'error');
        return;
      }
      byId('render-api-url').classList.remove('rd-input--error');
      byId('render-api-url').value = check.normalized;
      appState.renderApiUrl = check.normalized;
      saveState();
      showToast(
        check.normalized ? `Sunucu adresi kaydedildi: ${check.normalized}` : 'Aynı kaynak sunucu adresi kullanılacak.',
        'info'
      );
      checkRenderServer(true);
    });

    byId('btn-check-render').addEventListener('click', () => checkRenderServer(true));

    // Optional API Token (sessionStorage ONLY — F10, strictly ASCII/CRLF validated)
    byId('btn-save-api-token').addEventListener('click', () => {
      const raw = byId('render-api-token').value;
      const check = validateApiToken(raw);
      if (!check.valid) {
        byId('render-api-token').classList.add('rd-input--error');
        showToast(check.error, 'error');
        return;
      }
      setApiToken(check.token);
      byId('render-api-token').value = check.token;
      byId('render-api-token').classList.remove('rd-input--error');
      showToast(check.token ? 'API anahtarı yalnızca bu oturuma kaydedildi.' : 'Oturumdaki API anahtarı temizlendi.', 'info');
      checkRenderServer(true);
    });

    byId('btn-clear-api-token').addEventListener('click', () => {
      byId('render-api-token').value = '';
      byId('render-api-token').classList.remove('rd-input--error');
      setApiToken('');
      showToast('API anahtarı oturumdan temizlendi.', 'info');
      checkRenderServer(false);
    });

    // Keystore SHA-256 copy
    byId('btn-copy-keystore-sha').addEventListener('click', async () => {
      if (!lastKeystoreSha256) return;
      const ok = await copyText(lastKeystoreSha256);
      showToast(ok ? 'Sertifika SHA-256 parmak izi kopyalandı.' : 'Kopyalanamadı.', ok ? 'success' : 'error');
    });

    // Upload Cancel buttons (APK/XAPK chunked upload & OBB chunked upload)
    byId('btn-cancel-upload').addEventListener('click', () => {
      if (activeUploadController) activeUploadController.abort();
    });
    byId('btn-cancel-obb-upload').addEventListener('click', () => {
      if (activeUploadController) activeUploadController.abort();
    });

    // Active Patch / Full XAPK Cancel button
    byId('btn-cancel-patch').addEventListener('click', () => {
      if (activeServerJobId) cancelServerJob(activeServerJobId);
    });

    // Tablist navigation + ArrowLeft/ArrowRight/Home/End (WCAG 2.1 AA)
    const tabButtons = Array.from(document.querySelectorAll('.nav-btn'));
    tabButtons.forEach((btn, idx) => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
      btn.addEventListener('keydown', (e) => {
        let nextIdx = -1;
        if (e.key === 'ArrowRight') nextIdx = (idx + 1) % tabButtons.length;
        else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + tabButtons.length) % tabButtons.length;
        else if (e.key === 'Home') nextIdx = 0;
        else if (e.key === 'End') nextIdx = tabButtons.length - 1;
        if (nextIdx >= 0) {
          e.preventDefault();
          tabButtons[nextIdx].focus();
          switchTab(tabButtons[nextIdx].dataset.tab);
        }
      });
    });

    // Library search & filters
    byId('library-search').addEventListener('input', (e) => {
      currentSearch = e.target.value;
      renderLibrary();
    });
    document.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        currentFilter = pill.dataset.filter;
        document.querySelectorAll('.filter-pill').forEach(p => {
          const active = p.dataset.filter === currentFilter;
          p.classList.toggle('filter-pill--active', active);
          p.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
        renderLibrary();
      });
    });

    // Dropzone & file input (non-nested-interactive region + native #btn-browse-file button)
    const dropzone = byId('dropzone');
    const fileInput = byId('file-input');
    ['dragover', 'drop'].forEach(evt => window.addEventListener(evt, e => e.preventDefault()));

    dropzone.addEventListener('click', (e) => {
      if (!isUploading && e.target !== fileInput) fileInput.click();
    });
    byId('btn-browse-file').addEventListener('click', (e) => {
      e.stopPropagation();
      if (!isUploading) fileInput.click();
    });
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleRealFile(e.target.files[0]);
        fileInput.value = '';
      }
    });
    ['dragenter', 'dragover'].forEach(evt => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!isUploading) dropzone.classList.add('dropzone-active');
      });
    });
    ['dragleave', 'drop'].forEach(evt => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dropzone-active');
      });
    });
    dropzone.addEventListener('drop', (e) => {
      if (!isUploading && e.dataTransfer?.files?.[0]) {
        handleRealFile(e.dataTransfer.files[0]);
      }
    });

    // APK + OBB pair & mobile/desktop OBB browsers
    byId('btn-pair-analyze').addEventListener('click', analyzeApkObbPair);
    byId('btn-pair-export').addEventListener('click', exportApkObbBundle);
    byId('pair-apk-input').addEventListener('change', () => {
      pairedApkFile = byId('pair-apk-input').files[0] || null;
      byId('btn-pair-export').disabled = true;
      setPairStatus('APK değişti. Eşleştirmeyi yeniden doğrulayın.');
    });
    byId('pair-obb-input').addEventListener('change', () => {
      pairedObbFile = byId('pair-obb-input').files[0] || null;
      byId('btn-pair-export').disabled = true;
      setPairStatus('OBB değişti. Eşleştirmeyi yeniden doğrulayın.');
    });

    const obbFolderInput = byId('obb-folder-input');
    const obbFilesInput = byId('obb-files-input');
    byId('btn-browse-obb-folder').addEventListener('click', () => { if (!isUploading) obbFolderInput.click(); });
    byId('btn-browse-obb-files').addEventListener('click', () => { if (!isUploading) obbFilesInput.click(); });
    obbFolderInput.addEventListener('change', (e) => {
      if (!isUploading) handleObbFilesPicked(e.target.files);
      obbFolderInput.value = '';
    });
    obbFilesInput.addEventListener('change', (e) => {
      if (!isUploading) handleObbFilesPicked(e.target.files);
      obbFilesInput.value = '';
    });
    byId('btn-upload-obb-folder').addEventListener('click', uploadObbFolderToRender);
    byId('btn-clear-obb-folder').addEventListener('click', () => {
      if (isUploading) return;
      setActiveObbFiles([]);
      obbFolderInput.value = '';
      obbFilesInput.value = '';
      renderObbFolderSelection();
      byId('obb-folder-status').textContent = 'Bu paket için OBB seçimi temizlendi.';
    });

    // Server patch flags & targetSdk change handlers (in-place focus-preserving)
    byId('patch-target-sdk').addEventListener('change', updateServerFlagsUI);
    byId('patch-server-mode').addEventListener('change', updateServerFlagsUI);
    byId('server-patch-flags').addEventListener('change', (e) => {
      if (isPatching && e.target instanceof HTMLInputElement) {
        e.target.checked = !e.target.checked;
        return;
      }
      updateServerFlagsUI();
    });

    // Profile notes toggle (in-place focus-preserving — LOW-07)
    byId('patch-modules-list').addEventListener('change', (e) => {
      const cb = e.target;
      if (!(cb instanceof HTMLInputElement) || !cb.dataset.modId) return;
      if (isPatching) {
        cb.checked = !cb.checked;
        return;
      }
      if (cb.checked) activeModuleIds.add(cb.dataset.modId);
      else activeModuleIds.delete(cb.dataset.modId);
      syncPatchModulesInPlace();
    });

    // Patcher actions
    byId('btn-start-patch').addEventListener('click', runCompatibilityPatcher);
    byId('btn-refresh-jobs').addEventListener('click', async () => {
      const ttl = await refreshPatchJobsHistory();
      showToast('Sunucu iş geçmişi yenilendi.', 'info');
      if (lastPatchedGame?.serverJobId) startLinkExpiryCountdown(ttl);
    });
    byId('btn-download-full-xapk').addEventListener('click', (e) => downloadFullSignedXapk(lastPatchedGame, e.currentTarget));
    byId('btn-download-selected-pkg').addEventListener('click', () => { if (selectedPackage) openDownloadModal(selectedPackage); });
    byId('btn-download-patched-pkg').addEventListener('click', () => { if (lastPatchedGame) openDownloadModal(lastPatchedGame); });
    byId('btn-download-report').addEventListener('click', () => downloadCompatibilityReport(lastPatchedGame));
    byId('btn-launch-patched').addEventListener('click', () => { if (lastPatchedGame) launchGame(lastPatchedGame.id); });

    // Game settings & control layout modals
    document.querySelectorAll('.fps-opt').forEach(btn => {
      btn.addEventListener('click', () => updateFpsButtonStyles(btn.dataset.fps));
    });
    byId('settings-res-range').addEventListener('input', (e) => {
      byId('settings-res-label').textContent = `%${e.target.value}`;
    });
    byId('btn-edit-control-layout').addEventListener('click', openControlLayoutEditor);
    byId('btn-close-control-layout').addEventListener('click', closeControlLayoutEditor);
    byId('btn-save-control-layout').addEventListener('click', () => saveControlLayoutEditor(false));
    byId('btn-reset-control-layout').addEventListener('click', () => saveControlLayoutEditor(true));
    byId('control-layout-size').addEventListener('input', (e) => {
      byId('control-layout-size-label').textContent = `%${e.target.value}`;
    });
    byId('control-layout-opacity').addEventListener('input', (e) => {
      byId('control-layout-opacity-label').textContent = `%${e.target.value}`;
    });

    byId('btn-save-game-settings').addEventListener('click', () => {
      const game = appState.games.find(g => g.id === editingGameId);
      if (!game) return;
      const activeFpsBtn = document.querySelector('.fps-opt[data-selected="true"]');
      game.settings.fps = activeFpsBtn ? Number(activeFpsBtn.dataset.fps) : 60;
      game.settings.resolutionScale = Number(byId('settings-res-range').value);
      game.settings.controlMode = byId('settings-control-mode').value;
      saveState();
      renderLibrary();
      closeGameSettings();
      showToast(`${game.name} ayarları kaydedildi.`, 'success');
    });

    byId('btn-download-game-modal').addEventListener('click', () => {
      const game = appState.games.find(g => g.id === editingGameId);
      if (!game) return;
      closeGameSettings();
      openDownloadModal(game);
    });
    byId('btn-export-game-report').addEventListener('click', () => {
      const game = appState.games.find(g => g.id === editingGameId);
      downloadCompatibilityReport(game);
    });

    byId('btn-delete-game-modal').addEventListener('click', () => {
      const game = appState.games.find(g => g.id === editingGameId);
      if (!game) return;
      openConfirmModal(
        'Paketi Kütüphaneden Sil',
        `"${game.name}" paket kaydını ve oturumdaki dosya referanslarını kaldırmak istediğinize emin misiniz?`,
        () => {
          sessionFileStore.delete(game.id);
          appState.games = appState.games.filter(g => g.id !== game.id);
          if (selectedPackage?.id === game.id) {
            selectedPackage = null;
            byId('selected-package-card')?.classList.add('hidden');
          }
          if (lastPatchedGame?.id === game.id) {
            lastPatchedGame = null;
            clearLinkExpiryTimer();
          }
          if (downloadingTarget?.id === game.id) closeDownloadModal();
          saveState();
          renderLibrary();
          renderSystemTab();
          renderObbFolderSelection();
          closeGameSettings();
          showToast(`${game.name} kütüphaneden kaldırıldı.`, 'warn');
        }
      );
    });

    // Download modal local file reattach (MERGES into sessionFileStore & validates size — MED-09)
    const dlReattachInput = byId('dl-reattach-input');
    byId('btn-dl-reattach').addEventListener('click', () => dlReattachInput.click());
    dlReattachInput.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      dlReattachInput.value = '';
      if (!file || !downloadingTarget) return;
      if (file.size <= 0 || file.size > MAX_FILE_BYTES) {
        showToast('Dosya boş (0 bayt) olamaz ve 5.00 GB sınırını aşamaz.', 'error');
        return;
      }
      const prev = sessionFileStore.get(downloadingTarget.id) || {};
      stagedObbFiles = [];
      sessionFileStore.set(downloadingTarget.id, { ...prev, singleFile: file });
      renderLibrary();
      renderDownloadModalBody();
      showToast(`${file.name} oturuma bağlandı!`, 'success');
    });

    // Modal backdrop clicks & global Escape / Focus trap
    byId('modal-game-settings').addEventListener('click', (e) => { if (e.target.id === 'modal-game-settings') closeGameSettings(); });
    byId('modal-control-layout').addEventListener('click', (e) => { if (e.target.id === 'modal-control-layout') closeControlLayoutEditor(); });
    byId('modal-download-package').addEventListener('click', (e) => { if (e.target.id === 'modal-download-package') closeDownloadModal(); });
    byId('modal-confirm').addEventListener('click', (e) => { if (e.target.id === 'modal-confirm') closeConfirmModal(); });

    byId('btn-confirm-cancel').addEventListener('click', closeConfirmModal);
    byId('btn-confirm-ok').addEventListener('click', () => {
      const cb = confirmCallback;
      closeConfirmModal();
      if (typeof cb === 'function') cb();
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        handleGlobalFocusTrap(e);
        return;
      }
      if (e.key === 'Escape') {
        if (!byId('modal-confirm').classList.contains('hidden')) closeConfirmModal();
        else if (!byId('modal-control-layout').classList.contains('hidden')) closeControlLayoutEditor();
        else if (!byId('modal-download-package').classList.contains('hidden')) closeDownloadModal();
        else if (!byId('modal-game-settings').classList.contains('hidden')) closeGameSettings();
        else if (sandboxActiveGame) exitSandbox();
        return;
      }
      if (!sandboxActiveGame) return;
      const keyMap = getSandboxKeyMap();
      const mapped = ownGet(keyMap, e.code) || ownGet(keyMap, e.key);
      if (mapped) {
        e.preventDefault();
        pressedKeys.add(mapped);
        const btn = document.querySelector(`.vpad-btn[data-vkey="${mapped}"]`);
        if (btn) btn.classList.add('pressed');
        updateInputHud();
      }
    });

    window.addEventListener('keyup', (e) => {
      if (!sandboxActiveGame) return;
      const keyMap = getSandboxKeyMap();
      const mapped = ownGet(keyMap, e.code) || ownGet(keyMap, e.key);
      if (mapped) {
        pressedKeys.delete(mapped);
        const btn = document.querySelector(`.vpad-btn[data-vkey="${mapped}"]`);
        if (btn) btn.classList.remove('pressed');
        updateInputHud();
      }
    });

    // Clear stuck keys on window blur or tab hidden (LOW-06)
    window.addEventListener('blur', clearAllPressedKeys);
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) clearAllPressedKeys();
    });
    window.addEventListener('resize', () => {
      if (sandboxActiveGame) resizeSandboxCanvas();
    });

    // Engine/Profile settings
    byId('engine-abi').addEventListener('change', (e) => {
      appState.engineSettings.abi = e.target.value;
      saveState();
      showToast('ABI denetim profili güncellendi.', 'info');
    });
    byId('engine-renderer').addEventListener('change', (e) => {
      appState.engineSettings.renderer = e.target.value;
      saveState();
      showToast('Önizleme ekran profili güncellendi.', 'info');
    });
    byId('engine-ram').addEventListener('input', (e) => {
      const val = Number(e.target.value);
      byId('engine-ram-val').textContent = `${val} MB`;
      appState.engineSettings.ram = val;
      saveState();
    });
    byId('engine-scoped-obb').addEventListener('change', (e) => {
      appState.engineSettings.scopedObb = e.target.checked;
      saveState();
    });
    byId('engine-audio-fix').addEventListener('change', (e) => {
      appState.engineSettings.audioFix = e.target.checked;
      saveState();
    });

    // System tab actions
    byId('btn-clear-cache').addEventListener('click', () => {
      appState.cacheMB = 32;
      saveState();
      renderSystemTab();
      showToast('Yerel önizleme önbelleği temizlendi.', 'success');
    });

    byId('btn-copy-sysinfo').addEventListener('click', async () => {
      const summary = [
        `RetroDroid Compat v${APP_VERSION} — Sistem Tanı Raporu`,
        `Aktif Profil: ${appState.activeProfile}`,
        `ABI Denetim Notu: ${appState.engineSettings.abi}`,
        `Önizleme Profili: ${appState.engineSettings.renderer}`,
        `Hedef Bellek Etiketi: ${appState.engineSettings.ram} MB`,
        'Maksimum Paket Limiti: 5.00 GB (5120 MB)',
        `Kayıtlı Paket Sayısı: ${appState.games.length}`,
      ].join('\n');
      const ok = await copyText(summary);
      showToast(ok ? 'Sistem tanı raporu panoya kopyalandı.' : 'Panoya kopyalanamadı.', ok ? 'success' : 'error');
    });

    byId('btn-export-backup').addEventListener('click', exportAppBackup);
    const backupInput = byId('backup-file-input');
    byId('btn-import-backup').addEventListener('click', () => backupInput.click());
    backupInput.addEventListener('change', (e) => {
      if (e.target.files?.[0]) {
        importAppBackup(e.target.files[0]);
        backupInput.value = '';
      }
    });

    byId('btn-reset-app').addEventListener('click', () => {
      openConfirmModal(
        'Varsayılan Verileri Sıfırla',
        'Eklediğiniz tüm oyunlar ve özel profil ayarları sıfırlanarak başlangıç durumuna dönülecek.',
        () => {
          appState = createDefaultState();
          teardownTransientState();
          saveState();
          renderLibrary();
          renderEngineTab();
          renderSystemTab();
          updateHeaderProfileBadge();
          switchTab('library');
          showToast('Uygulama varsayılan ayarlara sıfırlandı.', 'info');
        }
      );
    });

    // Sandbox controls
    byId('btn-exit-sandbox').addEventListener('click', exitSandbox);
    byId('btn-toggle-hud').addEventListener('click', (e) => {
      sandboxHudVisible = !sandboxHudVisible;
      byId('sandbox-hud').classList.toggle('hidden', !sandboxHudVisible);
      e.currentTarget.textContent = sandboxHudVisible ? 'HUD: Açık' : 'HUD: Kapalı';
    });
    byId('btn-toggle-vpad').addEventListener('click', (e) => {
      sandboxVpadVisible = !sandboxVpadVisible;
      byId('sandbox-vpad').classList.toggle('hidden', !sandboxVpadVisible);
      e.currentTarget.textContent = sandboxVpadVisible ? 'Kontrol: Açık' : 'Kontrol: Kapalı';
    });

    document.querySelectorAll('.vpad-btn').forEach(btn => {
      const key = btn.dataset.vkey;
      const press = (e) => {
        e.preventDefault();
        pressedKeys.add(key);
        btn.classList.add('pressed');
        updateInputHud();
      };
      const release = (e) => {
        e.preventDefault();
        pressedKeys.delete(key);
        btn.classList.remove('pressed');
        updateInputHud();
      };
      btn.addEventListener('mousedown', press);
      btn.addEventListener('mouseup', release);
      btn.addEventListener('mouseleave', release);
      btn.addEventListener('touchstart', press, { passive: false });
      btn.addEventListener('touchend', release, { passive: false });
      btn.addEventListener('touchcancel', release, { passive: false });
    });
  }

  function startApp() {
    renderPatchModulesInitial();
    const activeProf = ENGINE_PROFILES.find(p => p.id === appState.activeProfile) || ENGINE_PROFILES[0];
    applyProfileDefaultsToPatchForm(activeProf);
    initEvents();
    renderDemoPackages();
    renderLibrary();
    renderEngineTab();
    renderSystemTab();
    renderObbFolderSelection();
    updateHeaderProfileBadge();
    switchTab(appState.activeTab || 'library');
    // Single race-safe initial health check (automatically fetches /api/keystore-info & /api/jobs once online)
    checkRenderServer(false);
  }

  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', startApp);
  } else {
    startApp();
  }
}
