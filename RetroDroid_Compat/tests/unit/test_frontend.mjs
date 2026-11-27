/**
 * RetroDroid Compat v5.4.0 — Comprehensive Frontend Unit Test Suite (Node 24 node:test)
 *
 * Zero external dependencies. Directly imports static/app.js and static/vendor/jszip.js,
 * plus audits index.html and static/styles.css across all 9 M3 verification groups.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  APP_VERSION,
  MAX_FILE_BYTES,
  CLIENT_ZIP_MAX_BYTES,
  SANDBOX_QUOTA_MB,
  DONUT_CIRCUMFERENCE,
  PATCH_MODULES,
  ENGINE_PROFILES,
  DEMO_PACKAGES,
  ALLOWED_ENGINE_ABI,
  ALLOWED_ENGINE_RENDERER,
  escapeHtml,
  validateRenderApiUrl,
  validateApiToken,
  buildAuthHeaders,
  buildSafeDownloadUrl,
  controlLayoutDefaults,
  validPackageId,
  isContainerFormat,
  formatSizeFromMB,
  formatSdkSummary,
  normalizeGame,
  sanitizeAppState,
  createBackupPayload,
  shouldRetryHttpStatus,
  shouldClearUploadSessionOnFinishError,
  computeUploadPlan,
  canResumeUploadSession,
  computeMissingChunkIndices,
  formatEta,
  formatSpeedAndEta,
  validateUploadFile,
  validateApkObbPair,
  syncPairMetadataWithServer,
  resolveActiveObbFiles,
  resolveObbUploadTarget,
  buildScopedObbUploadPlan,
  mergeSessionEntryOnUpsert,
  canOfferFullXapk,
  pushModalStackEntry,
  buildObbChunkInitFlags,
  isActiveJobStatus,
  isTerminalJobStatus,
  computeMonotonicProgress,
  resolveSplitBundleFileName,
  resolveElf16kReport,
  resolveAuthoritativeHasObb,
  buildPatchSignParams,
  applyServerPatchResultToGame,
  upsertGameInLibrary,
  computeJobExpiresInSeconds,
  filterLibraryGames,
  computeStorageBreakdown,
  validateControlMapping,
  computeSandboxStep,
  computeHiDpiDimensions,
  checkClientZipBudget,
} from '../../static/app.js';

import { JSZip, crc32, normalizeZipPath } from '../../static/vendor/jszip.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../..');

const indexHtml = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');
const stylesCss = fs.readFileSync(path.join(ROOT_DIR, 'static', 'styles.css'), 'utf8');
const appJsSource = fs.readFileSync(path.join(ROOT_DIR, 'static', 'app.js'), 'utf8');
const jszipSource = fs.readFileSync(path.join(ROOT_DIR, 'static', 'vendor', 'jszip.js'), 'utf8');

// ============================================================================
// GROUP 1: Static Asset, Offline, Security, DOM ID & WCAG 2.1 AA Hygiene
// ============================================================================
test('G1.1 Zero external CDN URLs or remote scripts/stylesheets in HTML and CSS', () => {
  const forbiddenCDNs = [
    'cdn.tailwindcss.com',
    'cdn.jsdelivr.net',
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'unpkg.com',
    'cdnjs.cloudflare.com',
  ];
  for (const host of forbiddenCDNs) {
    assert.equal(indexHtml.includes(host), false, `index.html must not reference ${host}`);
    assert.equal(stylesCss.includes(host), false, `styles.css must not reference ${host}`);
    assert.equal(appJsSource.includes(host), false, `app.js must not reference ${host}`);
  }
  assert.equal(/<script[^>]+src=["']https?:\/\//i.test(indexHtml), false, 'No external <script src="http...">');
  assert.equal(/<link[^>]+href=["']https?:\/\//i.test(indexHtml), false, 'No external <link href="http...">');
  assert.equal(/@import\s+url\s*\(/i.test(stylesCss), false, 'No CSS @import url(...)');
  assert.match(indexHtml, /<link\s+rel="stylesheet"\s+href="\/static\/styles\.css"/);
  assert.match(indexHtml, /<script\s+type="module"\s+src="\/static\/app\.js"><\/script>/);
});

test('G1.2 Zero inline <style>, inline <script> bodies, inline style=, or inline on* handlers', () => {
  assert.equal(/<style\b/i.test(indexHtml), false, 'index.html must not contain <style> blocks');
  const scriptTags = [...indexHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.equal(scriptTags.length, 1, 'index.html should contain only the single module script tag');
  assert.equal(scriptTags[0][2].trim(), '', 'Module <script> tag must have empty inline body');
  assert.equal(/\bon[a-z]+\s*=/i.test(indexHtml), false, 'index.html must contain zero inline on* attributes');
  assert.equal(/\bstyle\s*=/i.test(indexHtml), false, 'index.html must contain zero inline style= attributes');
  assert.equal(/\.innerHTML\s*=/.test(appJsSource), false, 'app.js must never assign innerHTML');
  assert.equal(/onclick\s*=/i.test(appJsSource), false, 'app.js must not build onclick attributes');
});

test('G1.3 Zero !important overrides in static/styles.css and responsive/a11y rules present', () => {
  assert.equal(/!important/i.test(stylesCss), false, 'styles.css must contain zero !important overrides');
  assert.match(stylesCss, /:focus-visible/);
  assert.match(stylesCss, /prefers-reduced-motion:\s*reduce/);
  assert.match(stylesCss, /@media\s*\(max-width:\s*700px\)/);
});

test('G1.4 Dead hidden #status-clock & updateStatusClock removed; index.html ends with trailing LF', () => {
  assert.equal(indexHtml.includes('status-clock'), false, 'Dead #status-clock must be removed');
  assert.equal(appJsSource.includes('updateStatusClock'), false, 'Dead updateStatusClock timer must be removed');
  assert.equal(indexHtml.endsWith('\n'), true, 'index.html must end with trailing newline');
});

test('G1.5 100% DOM ID uniqueness & cross-reference integrity between app.js and index.html', () => {
  const htmlIds = [...indexHtml.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
  const htmlIdSet = new Set(htmlIds);
  assert.equal(htmlIds.length, htmlIdSet.size, 'index.html must have zero duplicate IDs');

  const jsIdRefs = [
    ...appJsSource.matchAll(/\b(?:byId|getElementById)\(\s*['"]([a-zA-Z0-9_-]+)['"]\s*\)/g),
  ].map(m => m[1]);
  assert.ok(jsIdRefs.length >= 60, 'Expected substantial DOM ID bindings in app.js');

  const missing = [...new Set(jsIdRefs)].filter(id => !htmlIdSet.has(id));
  assert.deepEqual(missing, [], `All DOM IDs referenced in app.js must exist in index.html; missing: ${missing.join(', ')}`);
});

test('G1.6 WCAG 2.1 AA ARIA landmarks, dialogs, tablist, tabpanels and icon button labels', () => {
  assert.match(indexHtml, /role="tablist"/);
  const tabs = [...indexHtml.matchAll(/role="tab"/g)];
  const panels = [...indexHtml.matchAll(/role="tabpanel"/g)];
  assert.equal(tabs.length, 4, 'Must have 4 role="tab" controls');
  assert.equal(panels.length, 4, 'Must have 4 role="tabpanel" sections');
  assert.match(indexHtml, /aria-selected="true"/);
  assert.match(indexHtml, /aria-controls="tab-library"/);

  for (const dialogId of [
    'modal-game-settings',
    'modal-confirm',
    'modal-control-layout',
    'modal-download-package',
    'sandbox-overlay',
  ]) {
    const dialogPattern = new RegExp(`id="${dialogId}"[^>]*role="dialog"[^>]*aria-modal="true"[^>]*aria-labelledby="[^"]+"`);
    assert.match(indexHtml, dialogPattern, `Dialog #${dialogId} must declare role="dialog", aria-modal="true", aria-labelledby`);
  }
  assert.match(indexHtml, /aria-label="Oyun ayarları penceresini kapat"/);
  assert.match(indexHtml, /aria-label="İndirme merkezini kapat"/);
  assert.match(indexHtml, /aria-label="Yukarı yön tuşu"/);
});

test('G1.7 Honesty & version 5.4.0 consistency (zero fictional JIT/Vulkan claims, zero 5.3.1 leftovers)', () => {
  assert.equal(APP_VERSION, '5.4.0');
  assert.equal(indexHtml.includes('5.4.0'), true);
  assert.equal(indexHtml.includes('5.3.1'), false, 'index.html must have zero 5.3.1 references');
  assert.equal(appJsSource.includes('5.3.1'), false, 'app.js must have zero 5.3.1 references');
  assert.equal(jszipSource.includes('5.4.0'), true);

  const fictionalClaims = [
    'RetroBridge JIT',
    'Houdini-Compat',
    'Vulkan ANGLE',
    'Snapdragon 8 Gen',
    'Shader & JIT',
  ];
  for (const phrase of fictionalClaims) {
    assert.equal(indexHtml.includes(phrase), false, `index.html must not advertise fictional "${phrase}"`);
    for (const prof of ENGINE_PROFILES) {
      assert.equal(JSON.stringify(prof).includes(phrase), false, `ENGINE_PROFILES must not contain "${phrase}"`);
    }
    for (const mod of PATCH_MODULES) {
      assert.equal(JSON.stringify(mod).includes(phrase), false, `PATCH_MODULES must not contain "${phrase}"`);
    }
    for (const opt of [...ALLOWED_ENGINE_ABI, ...ALLOWED_ENGINE_RENDERER]) {
      assert.equal(opt.includes(phrase), false, `Engine select options must not contain "${phrase}"`);
    }
  }
  assert.ok(DEMO_PACKAGES.length === 4);
});

test('G1.8 TargetSDK selector supports full Android 15-17 range API 24-36', () => {
  for (const api of ['24', '26', '28', '29', '30', '31', '33', '34', '35', '36']) {
    assert.match(indexHtml, new RegExp(`<option value="${api}"`), `Missing targetSdk API ${api} option`);
  }
});

test('G1.9 Every CSS class used in index.html and static/app.js is defined in static/styles.css', () => {
  const cssClasses = new Set([...stylesCss.matchAll(/\.([a-zA-Z_-][a-zA-Z0-9_-]*)/g)].map(m => m[1]));
  const htmlClasses = new Set();
  for (const m of indexHtml.matchAll(/\bclass="([^"]+)"/g)) {
    for (const c of m[1].trim().split(/\s+/)) htmlClasses.add(c);
  }
  const missingHtml = [...htmlClasses].filter(c => c !== 'dark' && c !== 'toggle-checkbox' && !cssClasses.has(c));
  assert.deepEqual(missingHtml, [], `Undefined HTML classes: ${missingHtml.join(', ')}`);

  const jsClasses = new Set();
  for (const m of appJsSource.matchAll(/className\s*[:=]\s*['"]([^'"]+)['"]/g)) {
    for (const c of m[1].trim().split(/\s+/)) jsClasses.add(c);
  }
  for (const m of appJsSource.matchAll(/classList\.(?:add|remove|toggle)\(\s*['"]([^'"]+)['"]/g)) {
    jsClasses.add(m[1]);
  }
  const missingJs = [...jsClasses].filter(c => c !== 'dark' && !cssClasses.has(c));
  assert.deepEqual(missingJs, [], `Undefined JS classes: ${missingJs.join(', ')}`);
});

// ============================================================================
// GROUP 2: XSS, URL & Auth Guards (F10)
// ============================================================================
test('G2.1 validateRenderApiUrl accepts empty and clean http/https, rejects dangerous schemes & creds', () => {
  assert.deepEqual(validateRenderApiUrl(''), { valid: true, normalized: '' });
  assert.deepEqual(validateRenderApiUrl('  https://api.example.com/// '), {
    valid: true,
    normalized: 'https://api.example.com',
  });
  assert.deepEqual(validateRenderApiUrl('http://127.0.0.1:8000/sub/'), {
    valid: true,
    normalized: 'http://127.0.0.1:8000/sub',
  });

  for (const bad of [
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'ftp://example.com',
    'file:///etc/passwd',
    'not-a-url',
    'https://user:pass@example.com',
  ]) {
    assert.equal(validateRenderApiUrl(bad).valid, false, `Must reject ${bad}`);
  }
});

test('G2.2 buildSafeDownloadUrl strictly validates /api/ prefix and appends ?token= only on /api/download*', () => {
  assert.equal(
    buildSafeDownloadUrl('https://rd.example.com/', '/api/download/0123456789ab/game.apk', 'my secret+tok'),
    'https://rd.example.com/api/download/0123456789ab/game.apk?token=my%20secret%2Btok'
  );
  assert.equal(
    buildSafeDownloadUrl('', '/api/download-full-xapk/0123456789ab', 'abc123'),
    '/api/download-full-xapk/0123456789ab?token=abc123'
  );
  assert.equal(
    buildSafeDownloadUrl('', '/api/download-obb/0123456789ab/0', ''),
    '/api/download-obb/0123456789ab/0'
  );
  // Non-download /api/ paths must NOT leak token in query string
  assert.equal(
    buildSafeDownloadUrl('', '/api/jobs', 'secret'),
    '/api/jobs'
  );

  for (const badPath of [
    'https://evil.com/malware.apk',
    '//evil.com/api/download/123',
    'javascript:alert(1)',
    '/etc/passwd',
    '/api/download/..\\secret',
    '/api/download/123\r\nSet-Cookie:x=1',
  ]) {
    assert.equal(buildSafeDownloadUrl('', badPath, 'tok'), null, `Must reject ${badPath}`);
  }
  assert.equal(buildSafeDownloadUrl('javascript:alert(1)', '/api/download/1234567890ab/a.apk'), null);
});

test('G2.3 buildAuthHeaders returns Authorization Bearer only when token is non-empty', () => {
  assert.deepEqual(buildAuthHeaders(''), {});
  assert.deepEqual(buildAuthHeaders('   '), {});
  assert.deepEqual(buildAuthHeaders('tok-999'), { Authorization: 'Bearer tok-999' });
});

test('G2.4 escapeHtml escapes all dangerous HTML/attribute characters', () => {
  const escaped = escapeHtml(`<img src="x" onerror='alert(1)&'>`);
  assert.equal(escaped, '&lt;img src=&quot;x&quot; onerror=&#39;alert(1)&amp;&#39;&gt;');
});

test('G2.5 createBackupPayload emits v5.4.0 and NEVER includes API tokens or raw binary handles', () => {
  const dirtyState = {
    activeTab: 'library',
    activeProfile: 'max_compat',
    apiToken: 'SUPER_SECRET_TOKEN',
    renderApiUrl: 'https://srv.example.com',
    games: [
      { id: 'g1', name: 'Test', ext: 'APK', sizeMB: 5, rawFile: { secret: true }, apkFile: {}, obbFile: {} },
    ],
  };
  const payload = createBackupPayload(dirtyState);
  assert.equal(payload.version, '5.4.0');
  assert.equal('apiToken' in payload.state, false);
  assert.equal(JSON.stringify(payload).includes('SUPER_SECRET_TOKEN'), false);
  assert.equal('rawFile' in payload.state.games[0], false);
  assert.equal('apkFile' in payload.state.games[0], false);
  assert.equal('obbFile' in payload.state.games[0], false);
});

// ============================================================================
// GROUP 3: State Whitelisting & Legacy v5.3.1 Migration (F12)
// ============================================================================
test('G3.1 sanitizeAppState whitelists activeTab, activeProfile, cacheMB, renderApiUrl & strips unknown keys', () => {
  const cleaned = sanitizeAppState({
    activeTab: 'evil-tab',
    activeProfile: 'hacked',
    renderApiUrl: 'javascript:alert(1)',
    cacheMB: 999999999,
    unknownExtra: 'drop-me',
    apiToken: 'never-persist',
    engineSettings: { ram: 99999, scopedObb: 'bad', abi: 'evil', renderer: 'evil' },
    games: [],
  });
  assert.equal(cleaned.activeTab, 'library');
  assert.equal(cleaned.activeProfile, 'max_compat');
  assert.equal(cleaned.renderApiUrl, '');
  assert.equal(cleaned.cacheMB, SANDBOX_QUOTA_MB);
  assert.equal('unknownExtra' in cleaned, false);
  assert.equal('apiToken' in cleaned, false);
  assert.equal(cleaned.engineSettings.ram, 8192);
  assert.equal(cleaned.engineSettings.abi, ALLOWED_ENGINE_ABI[0]);
  assert.equal(cleaned.engineSettings.renderer, ALLOWED_ENGINE_RENDERER[0]);
});

test('G3.2 sanitizeAppState & normalizeGame gracefully migrate legacy v5.3.1 backups', () => {
  const legacyBackup = {
    activeTab: 'patcher',
    activeProfile: 'legacy_2d',
    renderApiUrl: 'https://retrodroid.onrender.com/',
    cacheMB: 420,
    engineSettings: {
      abi: 'RetroBridge JIT v4 (Önerilen)',
      renderer: 'Vulkan ANGLE Wrapper (Yüksek Hız)',
      ram: 4096,
      scopedObb: true,
      audioFix: false,
    },
    games: [
      {
        id: 'old-game',
        name: 'Classic Game',
        fileName: 'classic.xapk',
        ext: 'XAPK',
        sizeMB: 250,
        modules: ['targetSdk', 'armBridge', 'xapkObb', 'notchFix', 'gles2', 'resign'],
        settings: { fps: 120, resolutionScale: 125, controlMode: 'Sanal Gamepad Katmanı' },
      },
    ],
  };
  const migrated = sanitizeAppState(legacyBackup);
  assert.equal(migrated.activeTab, 'patcher');
  assert.equal(migrated.activeProfile, 'legacy_2d');
  assert.equal(migrated.renderApiUrl, 'https://retrodroid.onrender.com');
  assert.equal(migrated.engineSettings.abi, ALLOWED_ENGINE_ABI[0]);
  assert.equal(migrated.engineSettings.renderer, ALLOWED_ENGINE_RENDERER[0]);
  assert.deepEqual(migrated.games[0].modules, [
    'sdkChecklist', 'abiAudit', 'obbGuide', 'aspectNote', 'previewProfile', 'signNote',
  ]);
  assert.equal(migrated.games[0].settings.fps, 120);
});

test('G3.3 normalizeGame sanitizes invalid ext, negative sizes, and out-of-range settings', () => {
  const g = normalizeGame({
    id: 'x',
    ext: 'EXE',
    sizeMB: -50,
    compatScore: 999,
    settings: { fps: 999, resolutionScale: 500, controlLayout: { size: 999, opacity: 5, side: 'invalid' } },
  });
  assert.equal(g.ext, 'APK');
  assert.equal(g.sizeMB, 0);
  assert.equal(g.compatScore, 100);
  assert.equal(g.settings.fps, 60);
  assert.equal(g.settings.resolutionScale, 150);
  assert.equal(g.settings.controlLayout.size, 140);
  assert.equal(g.settings.controlLayout.opacity, 30);
  assert.equal(g.settings.controlLayout.side, 'standard');
});

// ============================================================================
// GROUP 4: Resumable Chunked Upload, Retry & File Validation (F03)
// ============================================================================
test('G4.1 computeUploadPlan strictly honors server chunkSizeBytes and totalChunks', () => {
  const plan = computeUploadPlan(25 * 1024 * 1024, {
    chunkSizeBytes: 4 * 1024 * 1024,
    chunkSizeMB: 4,
    totalChunks: 7,
  });
  assert.equal(plan.chunkSizeBytes, 4 * 1024 * 1024);
  assert.equal(plan.totalChunks, 7);

  const fallbackPlan = computeUploadPlan(10 * 1024 * 1024, { chunkSizeMB: 4 });
  assert.equal(fallbackPlan.chunkSizeBytes, 4 * 1024 * 1024);
  assert.equal(fallbackPlan.totalChunks, 3);
});

test('G4.2 shouldRetryHttpStatus fails fast on permanent 4xx and retries 0/408/429/5xx', () => {
  for (const noRetry of [400, 401, 403, 404, 405, 409, 413, 422]) {
    assert.equal(shouldRetryHttpStatus(noRetry), false, `HTTP ${noRetry} must fail-fast`);
  }
  for (const retryable of [0, 408, 429, 500, 502, 503, 504]) {
    assert.equal(shouldRetryHttpStatus(retryable), true, `HTTP ${retryable} should retry`);
  }
});

test('G4.3 canResumeUploadSession & computeMissingChunkIndices accurately resume partial uploads', () => {
  const saved = {
    base: 'https://api.test',
    fileName: 'big.xapk',
    totalSize: 50000000,
    lastModified: 1700000000,
    jobId: '0123456789ab',
  };
  assert.equal(canResumeUploadSession(saved, { name: 'big.xapk', size: 50000000, lastModified: 1700000000 }, 'https://api.test'), true);
  assert.equal(canResumeUploadSession(saved, { name: 'other.xapk', size: 50000000, lastModified: 1700000000 }, 'https://api.test'), false);
  assert.equal(canResumeUploadSession(saved, { name: 'big.xapk', size: 50000000, lastModified: 1700000000 }, 'https://other.test'), false);
  assert.equal(canResumeUploadSession({ ...saved, jobId: 'bad-id' }, { name: 'big.xapk', size: 50000000, lastModified: 1700000000 }, 'https://api.test'), false);

  assert.deepEqual(computeMissingChunkIndices(5, [0, 2, 4]), [1, 3]);
  assert.deepEqual(computeMissingChunkIndices(3, [0, 1, 2]), []);
});

test('G4.4 formatEta, formatSpeedAndEta & validateUploadFile (0-byte, >5 GiB, extensions)', () => {
  assert.equal(formatEta(45), '45 sn');
  assert.equal(formatEta(125), '2 dk 05 sn');
  assert.match(formatSpeedAndEta(20 * 1024 * 1024, 2, 40 * 1024 * 1024), /10\.0 MB\/s • Kalan: 4 sn/);

  assert.equal(validateUploadFile({ name: 'empty.apk', size: 0 }).valid, false);
  assert.equal(validateUploadFile({ name: 'huge.xapk', size: MAX_FILE_BYTES + 1 }).valid, false);
  assert.equal(validateUploadFile({ name: 'malware.exe', size: 1024 }).valid, false);
  assert.equal(validateUploadFile({ name: 'game.apks', size: 1024 }).valid, true);
  assert.equal(validateUploadFile({ name: 'game.apkm', size: 1024 }).valid, true);
});

// ============================================================================
// GROUP 5: OBB Pair Analyzer, Canonical Naming & Per-Game Scoping (F08)
// ============================================================================
test('G5.1 validateApkObbPair enforces PK header, extensions, exact-case packageId & canonical naming', () => {
  const pkHeader = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
  const badHeader = new Uint8Array([0x00, 0x00, 0x00, 0x00]);

  assert.equal(
    validateApkObbPair({
      apkFile: { name: 'game.apk', size: 1000 },
      obbFile: { name: 'data.obb', size: 2000 },
      packageId: 'com.Studio.Game',
      apkHeaderBytes: badHeader,
    }).valid,
    false,
    'Non-PK APK must be rejected'
  );

  // Exact-case mismatch must be rejected (MED-08)
  assert.equal(
    validateApkObbPair({
      apkFile: { name: 'game.apk', size: 1000 },
      obbFile: { name: 'main.12.com.studio.game.obb', size: 2000 },
      packageId: 'com.Studio.Game',
      apkHeaderBytes: pkHeader,
    }).valid,
    false,
    'Case mismatch in OBB package ID must fail'
  );

  // Non-standard OBB name yields canonical main.1.<pkg>.obb
  const okRes = validateApkObbPair({
    apkFile: { name: 'game.apk', size: 1000 },
    obbFile: { name: 'data.obb', size: 2000 },
    packageId: 'com.Studio.Game',
    apkHeaderBytes: pkHeader,
  });
  assert.equal(okRes.valid, true);
  assert.equal(okRes.resolvedObbName, 'main.1.com.Studio.Game.obb');
});

test('G5.2 syncPairMetadataWithServer ignores "bilinmiyor" and updates canonical OBB name from versionCode', () => {
  const initial = {
    packageId: 'com.user.guessed',
    resolvedObbName: 'main.1.com.user.guessed.obb',
    obbFile: { name: 'raw_data.obb' },
  };
  const ignored = syncPairMetadataWithServer(initial, { packageId: 'bilinmiyor', versionCode: '42' });
  assert.equal(ignored.packageId, 'com.user.guessed');
  assert.equal(ignored.resolvedObbName, 'main.42.com.user.guessed.obb');

  const synced = syncPairMetadataWithServer(initial, { packageId: 'com.real.Game', versionCode: '108' });
  assert.equal(synced.packageId, 'com.real.Game');
  assert.equal(synced.resolvedObbName, 'main.108.com.real.Game.obb');
  assert.equal(synced.changed, true);
});

test('G5.3 buildScopedObbUploadPlan isolates OBB state per game & buildObbChunkInitFlags sets replaceExisting', () => {
  const store = new Map();
  store.set('game-A', { obbFolderFiles: [{ name: 'main.1.com.a.obb', size: 10 }] });
  store.set('game-B', { obbFile: { name: 'raw.obb', size: 20 }, obbTargetName: 'main.5.com.b.obb' });

  const planA = buildScopedObbUploadPlan(store, 'game-A');
  assert.equal(planA.length, 1);
  assert.equal(planA[0].uploadName, 'main.1.com.a.obb');

  const planB = buildScopedObbUploadPlan(store, 'game-B');
  assert.equal(planB.length, 1);
  assert.equal(planB[0].uploadName, 'main.5.com.b.obb');

  // Unrelated game C gets zero OBB files (zero cross-game leakage!)
  assert.deepEqual(buildScopedObbUploadPlan(store, 'game-C'), []);

  assert.deepEqual(buildObbChunkInitFlags(0), { replaceExisting: 'true' });
  assert.deepEqual(buildObbChunkInitFlags(1), { replaceExisting: 'false' });
  assert.deepEqual(buildObbChunkInitFlags(2), { replaceExisting: 'false' });
});

// ============================================================================
// GROUP 6: Patch Payload, M2 Live Statuses, Monotonicity, Upsert & Expiry
// ============================================================================
test('G6.1 buildPatchSignParams emits all 11 live M2 Form keys, clamps API 24-36, handles resign_only', () => {
  const params = buildPatchSignParams({
    jobId: 'abcdef012345',
    targetSdk: 36,
    mode: 'patch_and_sign',
    resign: true,
    background: true,
    patchTargetSdk: true,
    addLegacyStorage: true,
    enableCleartext: true,
    addNotchSupport: true,
    forceExtractNativeLibs: true,
    allowDowngrade: false,
  });
  assert.deepEqual(Object.keys(params).sort(), [
    'addLegacyStorage',
    'addNotchSupport',
    'allowDowngrade',
    'background',
    'enableCleartext',
    'forceExtractNativeLibs',
    'jobId',
    'mode',
    'patchTargetSdk',
    'resign',
    'targetSdk',
  ]);
  assert.equal(params.targetSdk, '36');
  assert.equal(params.addLegacyStorage, 'true');
  assert.equal(params.allowDowngrade, 'false');

  // Clamping below 24 and above 36
  assert.equal(buildPatchSignParams({ targetSdk: 19 }).targetSdk, '24');
  assert.equal(buildPatchSignParams({ targetSdk: 99 }).targetSdk, '36');

  // resign_only forces all manifest patch flags to false
  const resignParams = buildPatchSignParams({
    mode: 'resign_only',
    patchTargetSdk: true,
    addLegacyStorage: true,
    resign: true,
  });
  assert.equal(resignParams.patchTargetSdk, 'false');
  assert.equal(resignParams.addLegacyStorage, 'false');
  assert.equal(resignParams.resign, 'true');
});

test('G6.2 Active & terminal M2 statuses include running, canceled, interrupted', () => {
  for (const active of ['queued', 'running', 'processing']) {
    assert.equal(isActiveJobStatus(active), true, `${active} must be active`);
    assert.equal(isTerminalJobStatus(active), false);
  }
  for (const term of ['done', 'error', 'canceled', 'interrupted']) {
    assert.equal(isActiveJobStatus(term), false, `${term} must not be active`);
    assert.equal(isTerminalJobStatus(term), true, `${term} must be terminal`);
  }
});

test('G6.3 computeMonotonicProgress never regresses backwards (MED-11)', () => {
  assert.equal(computeMonotonicProgress(10, 35), 35);
  assert.equal(computeMonotonicProgress(55, 20), 55);
  assert.equal(computeMonotonicProgress(96, 120), 100);
});

test('G6.4 applyServerPatchResultToGame mutates game BEFORE save & upsert preserves settings', () => {
  const baseGame = {
    id: 'custom-2',
    name: 'Old Name',
    fileName: 'game.apk',
    ext: 'APK',
    sizeMB: 40,
    legacyApi: 19,
    minSdk: 14,
    legacyAndroid: 'Android 4.4',
    packageId: 'com.acme.retro',
    compatScore: 50,
    settings: { fps: 60, resolutionScale: 100, controlMode: 'Sanal Gamepad Katmanı', controlLayout: controlLayoutDefaults() },
  };
  const updated = applyServerPatchResultToGame(baseGame, {
    jobId: '0123456789ab',
    targetSdk: 28,
    minSdk: 14,
    sizeMB: 42.5,
    abis: ['arm64-v8a'],
    is32BitOnly: false,
    inspector: { compatScore: 95 },
    patchSummary: { method: 'binary_axml', manifestPatched: true },
    repatchAvailable: true,
  });
  assert.equal(updated.legacyApi, 28);
  assert.equal(updated.legacyAndroid, 'targetSdk 28 (min 14)');
  assert.equal(updated.compatScore, 95);
  assert.equal(updated.patchSummary.method, 'binary_axml');

  const existingLibrary = [
    {
      ...baseGame,
      id: 'custom-1',
      settings: { fps: 120, resolutionScale: 150, controlMode: 'Bluetooth / USB Kontrolcü', controlLayout: controlLayoutDefaults() },
    },
  ];
  const up = upsertGameInLibrary(existingLibrary, updated);
  assert.equal(up.games.length, 1);
  assert.equal(up.replacedOldId, 'custom-1');
  assert.equal(up.games[0].legacyApi, 28);
  assert.equal(up.games[0].settings.fps, 120, 'Existing user FPS preference must be preserved');
  assert.equal(up.games[0].settings.resolutionScale, 150);

  // Local mode strips stale server metadata
  const localUp = upsertGameInLibrary([], updated, { isLocalSimulation: true });
  assert.equal('serverJobId' in localUp.games[0], false);
  assert.equal('patchSummary' in localUp.games[0], false);
});

test('G6.5 Live M2 schema helpers: hasObb, splitBundle.fileName, elf16k, clock-skew expiry & SDK format', () => {
  // Authoritative server hasObb (split-only .apks with obbFiles: [] => false)
  assert.equal(resolveAuthoritativeHasObb({ obbFiles: [] }, true), false);
  assert.equal(resolveAuthoritativeHasObb({ obbFiles: [{ name: 'main.1.a.obb' }] }, false), true);

  // splitBundle.fileName preferred over legacy .name
  assert.equal(resolveSplitBundleFileName({ fileName: 'game_splits.apks' }), 'game_splits.apks');
  assert.equal(resolveSplitBundleFileName({ name: 'legacy_splits.apks' }), 'legacy_splits.apks');

  // inspector.elf16k OR top-level elf16kReport
  assert.equal(resolveElf16kReport({ inspector: { elf16k: { status: 'compatible' } } }).status, 'compatible');
  assert.equal(resolveElf16kReport({ elf16kReport: { status: 'incompatible' } }).status, 'incompatible');

  // Clock-skew-safe expiry prefers server expiresInSeconds, then serverTime
  assert.equal(computeJobExpiresInSeconds({ expiresInSeconds: 1842, finishedAt: 100 }, 999999, 3600), 1842);
  assert.equal(computeJobExpiresInSeconds({ finishedAt: 10000 }, 10600, 3600), 3000);

  // Zero duplicate (API X)
  assert.equal(formatSdkSummary('targetSdk 28 (min 14)', 28, 14), 'targetSdk 28 (min 14)');
  assert.equal(formatSdkSummary('Android 4.4 (API 19)', 19, 10), 'Android 4.4 (API 19)');
  assert.equal(formatSdkSummary('Android 4.4', 19, 10), 'Android 4.4 (API 19)');
  assert.equal(formatSdkSummary('', 28, 14), 'targetSdk 28 (min 14)');
});

// ============================================================================
// GROUP 7: Library Filters & System Storage Donut Normalization (F13)
// ============================================================================
test('G7.1 Consistent CONTAINER_EXTS across filterLibraryGames and computeStorageBreakdown', () => {
  const games = [
    { id: '1', name: 'A', ext: 'XAPK', sizeMB: 1000, legacyAndroid: 'API 19', packageId: 'com.a.a' },
    { id: '2', name: 'B', ext: 'APKS', sizeMB: 500, legacyAndroid: 'API 21', packageId: 'com.b.b' },
    { id: '3', name: 'C', ext: 'APKM', sizeMB: 300, legacyAndroid: 'API 23', packageId: 'com.c.c' },
    { id: '4', name: 'D', ext: 'ZIP', sizeMB: 200, legacyAndroid: 'API 19', packageId: 'com.d.d' },
    { id: '5', name: 'E', ext: 'APK+OBB', sizeMB: 400, legacyAndroid: 'API 19', packageId: 'com.e.e' },
    { id: '6', name: 'F', ext: 'APK', sizeMB: 100, legacyAndroid: 'API 14', packageId: 'com.f.f', is32BitOnly: true },
  ];

  for (const ext of ['XAPK', 'APK+OBB', 'APKS', 'APKM', 'ZIP']) {
    assert.equal(isContainerFormat(ext), true);
  }
  assert.equal(isContainerFormat('APK'), false);

  assert.equal(filterLibraryGames(games, 'XAPK', '').length, 5);
  assert.equal(filterLibraryGames(games, 'APK', '').length, 1);
  assert.equal(filterLibraryGames(games, 'BRIDGE', '').length, 1);

  const breakdown = computeStorageBreakdown(games, 200, SANDBOX_QUOTA_MB);
  assert.equal(breakdown.containerMB, 2400);
  assert.equal(breakdown.apkMB, 100);
  assert.equal(breakdown.totalUsedMB, 2700);
});

test('G7.2 SVG Donut normalizes arcs proportionally when totalUsedMB exceeds 32 GB quota (MED-05)', () => {
  const hugeGames = [
    { id: '1', ext: 'XAPK', sizeMB: 30000 },
    { id: '2', ext: 'APK', sizeMB: 20000 },
  ];
  const stats = computeStorageBreakdown(hugeGames, 10000, SANDBOX_QUOTA_MB);
  assert.equal(stats.totalUsedMB, 60000);
  assert.equal(stats.freeMB, 0);
  assert.equal(stats.usedPct, 100);

  const arcSum = stats.arcs.container + stats.arcs.apk + stats.arcs.cache;
  assert.ok(arcSum <= DONUT_CIRCUMFERENCE + 0.01, `Arc sum ${arcSum} must never exceed circumference ${DONUT_CIRCUMFERENCE}`);
  assert.ok(Math.abs(stats.arcs.container / DONUT_CIRCUMFERENCE - 0.5) < 0.01);
  assert.ok(Math.abs(stats.arcs.apk / DONUT_CIRCUMFERENCE - (20000 / 60000)) < 0.01);
});

// ============================================================================
// GROUP 8: Control Layout Editor & Sandbox Physics / HiDPI (F14)
// ============================================================================
test('G8.1 validateControlMapping accepts unique bindings and rejects duplicates with conflicting controls', () => {
  const validRes = validateControlMapping(controlLayoutDefaults().mapping);
  assert.equal(validRes.valid, true);
  assert.deepEqual(validRes.duplicates, []);

  const dupRes = validateControlMapping({
    ...controlLayoutDefaults().mapping,
    A: 'Space',
    B: 'Space',
  });
  assert.equal(dupRes.valid, false);
  assert.equal(dupRes.duplicates.length, 1);
  assert.equal(dupRes.duplicates[0].code, 'Space');
  assert.deepEqual(dupRes.duplicates[0].controls, ['A', 'B']);
});

test('G8.2 computeSandboxStep enforces delta-time consistency, dt clamp, bounds & computeHiDpiDimensions', () => {
  // 2 steps of 0.05s equals 1 step of 0.1s (FPS-independent physics!)
  const start = { x: 100, y: 100, pulse: 0 };
  const s1 = computeSandboxStep({ player: start, keys: ['RIGHT'], dt: 0.05, width: 600, height: 400 });
  const s2 = computeSandboxStep({ player: s1, keys: ['RIGHT'], dt: 0.05, width: 600, height: 400 });
  const direct = computeSandboxStep({ player: start, keys: ['RIGHT'], dt: 0.1, width: 600, height: 400 });
  assert.ok(Math.abs(s2.x - direct.x) < 1e-6);

  // Spike dt > 0.1 is clamped to 0.1
  const spiked = computeSandboxStep({ player: start, keys: ['RIGHT'], dt: 5.0, width: 600, height: 400 });
  assert.equal(spiked.x, direct.x);

  // Viewport bounds clamp
  const clamped = computeSandboxStep({ player: { x: 1000, y: -50, pulse: 0 }, keys: [], dt: 0, width: 320, height: 240 });
  assert.equal(clamped.x, 290);
  assert.equal(clamped.y, 30);

  // HiDPI scaling clamped 1..3
  assert.deepEqual(computeHiDpiDimensions(800, 600, 2), {
    cssWidth: 800,
    cssHeight: 600,
    dpr: 2,
    backingWidth: 1600,
    backingHeight: 1200,
  });
  assert.equal(computeHiDpiDimensions(500, 400, 5).dpr, 3);
});

// ============================================================================
// GROUP 9: Client ZIP RAM Guard & Genuine Offline JSZip Engine (F12, F15)
// ============================================================================
test('G9.1 checkClientZipBudget enforces 512 MiB client-side ZIP ceiling', () => {
  assert.equal(checkClientZipBudget([{ size: CLIENT_ZIP_MAX_BYTES }]).ok, true);
  assert.equal(checkClientZipBudget([{ size: 300 * 1024 * 1024 }, { size: 250 * 1024 * 1024 }]).ok, false);
});

test('G9.2 IEEE 802.3 CRC-32 matches standard test vector', () => {
  const bytes = new TextEncoder().encode('123456789');
  assert.equal(crc32(bytes), 0xcbf43926);
  // Running seed check
  const p1 = crc32(bytes.subarray(0, 4), 0);
  const p2 = crc32(bytes.subarray(4), p1);
  assert.equal(p2, 0xcbf43926);
});

test('G9.3 Offline JSZip STORE roundtrip with UTF-8 Turkish filenames, binary & Blob + progress callback', async () => {
  const zip = new JSZip();
  const binaryPayload = new Uint8Array(65536);
  for (let i = 0; i < binaryPayload.length; i++) binaryPayload[i] = (i * 31) & 0xff;
  const blobPayload = new Blob([new TextEncoder().encode('OBB-BINARY-DATA-ŞĞÜİÖÇ')]);

  zip.file('KURULUM_REHBERİ.txt', 'Merhaba RetroDroid v5.4.0 — Şğüİöç!');
  zip.folder('Android/obb/com.test.oyun').file('main.1.com.test.oyun.obb', blobPayload);
  zip.file('payload.bin', binaryPayload);

  const progressEvents = [];
  const blob = await zip.generateAsync({ type: 'blob', compression: 'STORE' }, (meta) => {
    progressEvents.push(meta.percent);
  });
  assert.ok(progressEvents.length >= 2);
  assert.equal(progressEvents[progressEvents.length - 1], 100);

  const bytes = new Uint8Array(await blob.arrayBuffer());
  assert.equal(bytes[0], 0x50);
  assert.equal(bytes[1], 0x4b);
  assert.equal(bytes[2], 0x03);
  assert.equal(bytes[3], 0x04);

  const loaded = await JSZip.loadAsync(bytes);
  assert.equal(await loaded.file('KURULUM_REHBERİ.txt').async('string'), 'Merhaba RetroDroid v5.4.0 — Şğüİöç!');
  assert.equal(await loaded.file('Android/obb/com.test.oyun/main.1.com.test.oyun.obb').async('string'), 'OBB-BINARY-DATA-ŞĞÜİÖÇ');
  const recoveredBin = await loaded.file('payload.bin').async('uint8array');
  assert.deepEqual(recoveredBin, binaryPayload);
});

test('G9.4 Offline JSZip DEFLATE roundtrip compresses repetitive data & restores exact bytes', async () => {
  const zip = new JSZip();
  const repetitive = 'RetroDroid Compat v5.4.0 '.repeat(400);
  zip.file('report.json', repetitive);

  const deflatedBytes = await zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
  assert.ok(deflatedBytes.byteLength < repetitive.length / 4, 'DEFLATE output should be significantly smaller');

  const loaded = await JSZip.loadAsync(deflatedBytes);
  assert.equal(await loaded.file('report.json').async('string'), repetitive);
});

test('G9.5 Offline JSZip ZIP64 roundtrip & CRC-32 tamper detection', async () => {
  const zip = new JSZip();
  zip.file('zip64_test.txt', 'ZIP64 extra field verification payload');
  const z64Bytes = await zip.generateAsync({ type: 'uint8array', compression: 'STORE', forceZip64: true });

  const loaded = await JSZip.loadAsync(z64Bytes);
  assert.equal(await loaded.file('zip64_test.txt').async('string'), 'ZIP64 extra field verification payload');

  // Corrupt one payload byte and verify CRC-32 verification rejects it
  const tampered = new Uint8Array(z64Bytes);
  const needle = new TextEncoder().encode('verification');
  let foundIdx = -1;
  for (let i = 0; i <= tampered.length - needle.length; i++) {
    let ok = true;
    for (let j = 0; j < needle.length; j++) {
      if (tampered[i + j] !== needle[j]) { ok = false; break; }
    }
    if (ok) { foundIdx = i; break; }
  }
  assert.ok(foundIdx > 0);
  tampered[foundIdx] ^= 0xff;
  const loadedTampered = await JSZip.loadAsync(tampered);
  await assert.rejects(
    () => loadedTampered.file('zip64_test.txt').async('string'),
    /CRC-32/
  );
});

test('G9.6 Offline JSZip blocks path traversal, drive letters, NUL bytes & empty paths', () => {
  const zip = new JSZip();
  for (const badPath of ['../escape.txt', 'a/../../escape.txt', 'C:/Windows/win.ini', 'bad\0name.txt', '', '/']) {
    assert.throws(() => normalizeZipPath(badPath), `normalizeZipPath must reject ${JSON.stringify(badPath)}`);
    assert.throws(() => zip.file(badPath, 'x'), `zip.file must reject ${JSON.stringify(badPath)}`);
  }
});

test('G9.7 formatSizeFromMB & validPackageId edge cases', () => {
  assert.equal(formatSizeFromMB(0.5), '0.50 MB');
  assert.equal(formatSizeFromMB(42.5), '42.5 MB');
  assert.equal(formatSizeFromMB(2048), '2.00 GB');
  assert.equal(validPackageId('com.example.game_2'), true);
  assert.equal(validPackageId('notvalid'), false);
  assert.equal(validPackageId('123.bad.pkg'), false);
});

// ============================================================================
// GROUP 10: M3 Iteration 2 Adversarial Regressions (Prototype, Auth, Traversal,
//           OBB Isolation, Upsert Pruning, JSZip Roundtrip/Bounds, Modal & DOM)
// ============================================================================
test('G10.1 Prototype keys (toString/valueOf/constructor/__proto__/hasOwnProperty) & non-plain inspector rejected', () => {
  const cleaned = sanitizeAppState({
    engineSettings: { abi: 'toString', renderer: 'valueOf' },
    games: [
      {
        id: 'proto-g',
        name: 'Proto Test',
        ext: 'APK',
        modules: ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf', 'targetSdk'],
        inspector: ['not', 'an', 'object'],
        patchSummary: ['array-summary'],
        settings: ['invalid-array'],
      },
      ['array-instead-of-game'],
    ],
  });

  assert.equal(typeof cleaned.engineSettings.abi, 'string');
  assert.equal(cleaned.engineSettings.abi, ALLOWED_ENGINE_ABI[0]);
  assert.equal(typeof cleaned.engineSettings.renderer, 'string');
  assert.equal(cleaned.engineSettings.renderer, ALLOWED_ENGINE_RENDERER[0]);

  assert.equal(cleaned.games.length, 1);
  assert.deepEqual(cleaned.games[0].modules, ['sdkChecklist']);
  assert.equal('inspector' in cleaned.games[0], false, 'Array inspector must be stripped');
  assert.equal('patchSummary' in cleaned.games[0], false, 'Array patchSummary must be stripped');

  const normWithObj = normalizeGame({
    id: 'ok-g',
    ext: 'APK',
    inspector: { compatScore: 88, compatChecklist: [null, 'bad', { id: 'sdk', status: 'constructor', message: 'ok' }] },
    patchSummary: { method: 'toString', manifestPatched: true },
  });
  assert.equal(normWithObj.inspector.compatScore, 88);
  assert.equal(normWithObj.patchSummary.manifestPatched, true);
  assert.equal(normalizeGame(['not-a-game']), null);
});

test('G10.2 validateApiToken & buildAuthHeaders reject CRLF, control chars & non-ASCII without crashing Headers', () => {
  assert.deepEqual(validateApiToken(''), { valid: true, token: '' });
  assert.deepEqual(validateApiToken('   '), { valid: true, token: '' });
  assert.deepEqual(validateApiToken('  rd_live_token-123  '), { valid: true, token: 'rd_live_token-123' });

  const hostileTokens = [
    'tok\r\nX-Evil: 1',
    'tok\r',
    'tok\n',
    'tok\0null',
    'tok\twith-tab',
    'tok\x7fdel',
    'şifre_Türkçe_123',
    'parola_ğüşıöç_ÇÖİŞÜĞ',
    'bearer_🔑_emoji',
    'latin1_\u00e9_\u00ff',
    'x'.repeat(600),
  ];

  for (const bad of hostileTokens) {
    const res = validateApiToken(bad);
    assert.equal(res.valid, false, `Token ${JSON.stringify(bad)} must be rejected`);
    assert.ok(res.error && res.error.length > 5, 'Must return Turkish validation error');
    const hdrObj = buildAuthHeaders(bad);
    assert.deepEqual(hdrObj, {}, `buildAuthHeaders(${JSON.stringify(bad)}) must return {}`);
    // Must NEVER throw TypeError in WHATWG Headers
    const h = new Headers(hdrObj);
    assert.equal(h.get('Authorization'), null);
  }

  const validHdr = new Headers(buildAuthHeaders('valid_ASCII_Token-42!'));
  assert.equal(validHdr.get('Authorization'), 'Bearer valid_ASCII_Token-42!');
});

test('G10.3 buildSafeDownloadUrl blocks dot-segments (.. / . / %2e%2e / malformed %) and #fragment token leaks', () => {
  const traversalAndFragmentVectors = [
    '/api/../etc/passwd',
    '/api/./download/0123456789ab/a.apk',
    '/api/download/../../other',
    '/api/download/0123456789ab/..',
    '/api/download/%2e%2e/other',
    '/api/download/%2E%2E/%2e%2e/other',
    '/api/download/.%2e/other',
    '/api/download/%2e/other',
    '/api/download/%2e%2e%2fother',
    '/api/download/0123456789ab/%ZZbad.apk',
    '/api/download//0123456789ab/a.apk',
    '/api/download/0123456789ab/a.apk#frag',
    '/api/download-full-xapk/0123456789ab#section',
  ];

  for (const vec of traversalAndFragmentVectors) {
    assert.equal(
      buildSafeDownloadUrl('https://rd.example.com', vec, 'secret_tok'),
      null,
      `Must reject unsafe download path: ${vec}`
    );
    assert.equal(
      buildSafeDownloadUrl('', vec, 'secret_tok'),
      null,
      `Must reject relative unsafe download path: ${vec}`
    );
  }

  // Valid filenames containing dots and URL-encoded # (%23) must continue to work
  assert.equal(
    buildSafeDownloadUrl('', '/api/download/0123456789ab/Modern.Combat_v1.2.2e%231.apk', 'sec_1'),
    '/api/download/0123456789ab/Modern.Combat_v1.2.2e%231.apk?token=sec_1'
  );
  // Invalid token must never inject CRLF into download URL
  assert.equal(
    buildSafeDownloadUrl('', '/api/download/0123456789ab/game.apk', 'bad\r\ntok'),
    '/api/download/0123456789ab/game.apk'
  );
});

test('G10.4 Per-game OBB isolation: resolveActiveObbFiles, resolveObbUploadTarget, mergeSessionEntryOnUpsert & canOfferFullXapk', () => {
  // 1) Staged OBBs must NEVER leak once a scopeId (e.g. Demo A, Demo B, or reattached entry) is active
  const store = new Map();
  const staged = [{ name: 'main.1.com.staged.obb', size: 1024 }];
  assert.equal(resolveActiveObbFiles(store, null, staged).length, 1);
  assert.deepEqual(resolveActiveObbFiles(store, 'demo-mc4', staged), []);
  assert.deepEqual(resolveActiveObbFiles(store, 'demo-nova3', staged), []);
  store.set('reattached-1', { singleFile: { name: 'game.apk', size: 500 } });
  assert.deepEqual(resolveActiveObbFiles(store, 'reattached-1', staged), []);

  // 2) Cross-game OBB upload guard: Demo / local package must NEVER fall back to lastPatchedGame.serverJobId
  const patchedGameA = { id: 'custom-a', name: 'Game A', serverJobId: '1f7534410a80' };
  const demoPkgB = { id: 'demo-mc4', name: 'Demo MC4', isRealFile: false };
  const crossCheck = resolveObbUploadTarget(demoPkgB, patchedGameA);
  assert.equal(crossCheck.ok, false);
  assert.equal(crossCheck.jobId, null);
  assert.match(crossCheck.reason, /sunucuda analiz edilmedi/);

  const validWhenNullSelected = resolveObbUploadTarget(null, patchedGameA);
  assert.equal(validWhenNullSelected.ok, true);
  assert.equal(validWhenNullSelected.jobId, '1f7534410a80');

  // 3) Same-packageId upsert: replacing v1 APK+OBB pair with standalone v2 APK prunes stale v1 apkFile/obbFile/serverObbUploaded
  const oldPairEntry = {
    apkFile: { name: 'v1.apk', size: 1000 },
    obbFile: { name: 'main.7.com.retro.reviewtest.obb', size: 50000 },
    obbTargetName: 'main.7.com.retro.reviewtest.obb',
    obbFolderFiles: [{ name: 'extra_v1.obb', size: 2048 }],
    serverJobId: '111111111111',
    serverVerified: true,
    serverObbUploaded: true,
    obbUploadedJobId: '111111111111',
    serverObbDownloads: [{ name: 'main.7.com.retro.reviewtest.obb', downloadUrl: '/api/download-obb/111111111111/0' }],
  };
  const v2File = { name: 'v2_standalone.apk', size: 1200 };
  const mergedV2 = mergeSessionEntryOnUpsert({
    oldEntry: oldPairEntry,
    curEntry: { singleFile: v2File, obbFolderFiles: [], serverJobId: '222222222222' },
    pkg: { id: 'custom-v2', rawFile: v2File, serverJobId: '222222222222', hasObb: false },
    serverSignedResult: {
      downloadUrl: '/api/download/222222222222/v2_signed.apk',
      fileName: 'v2_signed.apk',
      verified: true,
      targetSdk: 34,
      obbDownloads: [],
    },
  });

  assert.equal(mergedV2.singleFile, v2File);
  assert.equal('apkFile' in mergedV2, false, 'Stale v1 apkFile must be omitted');
  assert.equal('obbFile' in mergedV2, false, 'Stale v1 obbFile must be omitted');
  assert.equal('obbTargetName' in mergedV2, false, 'Stale v1 obbTargetName must be omitted');
  assert.deepEqual(mergedV2.obbFolderFiles, []);
  assert.equal('serverObbUploaded' in mergedV2, false, 'Stale serverObbUploaded must not cross jobs');
  assert.equal('obbUploadedJobId' in mergedV2, false, 'Stale obbUploadedJobId must not cross jobs');
  assert.deepEqual(mergedV2.serverObbDownloads, []);

  // Full XAPK must stay hidden on plain OBB-less re-upload (even if someone injected mismatched obbUploadedJobId)
  const v2Store = new Map([['custom-v2', mergedV2]]);
  const v2Game = { id: 'custom-v2', serverJobId: '222222222222', hasObb: false };
  assert.equal(canOfferFullXapk(v2Game, mergedV2, v2Store), false);
  assert.equal(
    canOfferFullXapk(
      v2Game,
      { ...mergedV2, serverObbUploaded: true, obbUploadedJobId: '111111111111' },
      v2Store
    ),
    false,
    'Mismatched obbUploadedJobId must NOT enable Full XAPK'
  );
  assert.equal(
    canOfferFullXapk(
      v2Game,
      { ...mergedV2, serverObbUploaded: true, obbUploadedJobId: '222222222222' },
      v2Store
    ),
    true,
    'Matching obbUploadedJobId on verified job enables Full XAPK'
  );

  // Reverse direction: standalone -> APK+OBB pair omits stale singleFile
  const newApk = { name: 'pair_v3.apk', size: 1500 };
  const newObb = { name: 'main.3.com.retro.reviewtest.obb', size: 9000 };
  const mergedPair = mergeSessionEntryOnUpsert({
    oldEntry: mergedV2,
    curEntry: { apkFile: newApk, obbFile: newObb, obbTargetName: newObb.name, obbFolderFiles: [] },
    pkg: { id: 'pair-v3', apkFile: newApk, obbFile: newObb, obbTargetName: newObb.name, serverJobId: '333333333333' },
    serverSignedResult: {
      downloadUrl: '/api/download/333333333333/pair_v3_signed.apk',
      fileName: 'pair_v3_signed.apk',
      verified: true,
      targetSdk: 28,
      obbDownloads: [],
    },
  });
  assert.equal('singleFile' in mergedPair, false, 'Stale singleFile must be omitted on pair replacement');
  assert.equal(mergedPair.apkFile, newApk);
  assert.equal(mergedPair.obbFile, newObb);
});

test('G10.5 Offline JSZip loadAsync -> generateAsync roundtrip, /etc/passwd & C:secret.txt rejection, >65535-byte header bounds', async () => {
  // 1) Re-serializing loaded archives (DEFLATE and STORE) preserves exact bytes + new files
  const z1 = new JSZip();
  z1.file('existing_deflate.txt', 'RetroDroid-DEFLATE-Payload-ŞĞÜİÖÇ-'.repeat(25));
  z1.file('existing_empty.txt', '');
  const bytes1 = await z1.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });

  const loaded1 = await JSZip.loadAsync(bytes1);
  loaded1.file('added.txt', 'new-entry-after-load');
  const reExportedStore = await loaded1.generateAsync({ type: 'uint8array', compression: 'STORE' });
  const reloadedStore = await JSZip.loadAsync(reExportedStore);
  assert.equal(
    await reloadedStore.file('existing_deflate.txt').async('string'),
    'RetroDroid-DEFLATE-Payload-ŞĞÜİÖÇ-'.repeat(25)
  );
  assert.equal(await reloadedStore.file('existing_empty.txt').async('string'), '');
  assert.equal(await reloadedStore.file('added.txt').async('string'), 'new-entry-after-load');

  const reExportedDeflate = await reloadedStore.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
  const reloadedDeflate = await JSZip.loadAsync(reExportedDeflate);
  assert.equal(
    await reloadedDeflate.file('existing_deflate.txt').async('string'),
    'RetroDroid-DEFLATE-Payload-ŞĞÜİÖÇ-'.repeat(25)
  );

  // 2) Reject absolute POSIX (/etc/passwd), backslash (\Windows\win.ini), and Windows drive-relative (C:secret.txt)
  for (const unsafe of ['/etc/passwd', '\\Windows\\win.ini', 'C:secret.txt', 'd:data/file.obb', 'a/./b.txt', 'a\\..\\b.txt']) {
    assert.throws(() => normalizeZipPath(unsafe), `Must reject ${unsafe}`);
    const zBad = new JSZip();
    assert.throws(() => zBad.file(unsafe, 'x'), `zip.file must reject ${unsafe}`);
  }

  // Also verify JSZip.loadAsync rejects an archive whose raw header has '/etc/passwd'
  const cleanZip = new JSZip();
  cleanZip.file('Xetc/passwd', 'root:x:0:0');
  const rawZip = await cleanZip.generateAsync({ type: 'uint8array', compression: 'STORE' });
  const needle = new TextEncoder().encode('Xetc/passwd');
  for (let i = 0; i <= rawZip.length - needle.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (rawZip[i + j] !== needle[j]) { match = false; break; }
    }
    if (match) rawZip[i] = 0x2f; // Replace 'X' with '/' -> '/etc/passwd' in LFH & CDH
  }
  await assert.rejects(() => JSZip.loadAsync(rawZip), /Mutlak ZIP dosya yolu reddedildi/);

  // 3) Reject > 65535-byte filename and > 65535-byte comment in generateAsync (no uint16 wraparound)
  const zHugeName = new JSZip();
  zHugeName.file('a'.repeat(70000), 'payload');
  await assert.rejects(() => zHugeName.generateAsync({ type: 'uint8array' }), /65535/);

  const zHugeComment = new JSZip();
  zHugeComment.file('ok.txt', 'payload', { comment: 'c'.repeat(70000) });
  await assert.rejects(() => zHugeComment.generateAsync({ type: 'uint8array' }), /65535/);
});

test('G10.6 Modal triggerEl preservation, finish 4xx upload session hygiene & non-nested #dropzone markup', () => {
  // 1) Re-opening/re-rendering an already-open modal (e.g. Reset inside Control Layout Editor) preserves original triggerEl
  const stack = [];
  const editLayoutBtn = { id: 'btn-edit-control-layout' };
  const resetBtnInsideModal = { id: 'btn-reset-control-layout' };
  pushModalStackEntry(stack, 'modal-game-settings', { id: 'card-settings-btn' }, false);
  pushModalStackEntry(stack, 'modal-control-layout', editLayoutBtn, false);
  assert.equal(stack.length, 2);
  assert.equal(stack[1].triggerEl, editLayoutBtn);

  // Re-render while already open (clicking Reset inside modal-control-layout)
  pushModalStackEntry(stack, 'modal-control-layout', resetBtnInsideModal, true);
  assert.equal(stack.length, 2);
  assert.equal(stack[1].triggerEl, editLayoutBtn, 'Original triggerEl must be preserved on modal re-render');

  // 2) Permanent 4xx on /api/upload/finish clears stale sessionStorage upload session
  for (const perm4xx of [400, 404, 413, 422]) {
    assert.equal(shouldClearUploadSessionOnFinishError(perm4xx), true, `HTTP ${perm4xx} must clear upload session`);
  }
  for (const keepStatus of [0, 401, 408, 429, 500, 503]) {
    assert.equal(shouldClearUploadSessionOnFinishError(keepStatus), false, `HTTP ${keepStatus} must retain upload session`);
  }

  // 3) #dropzone in index.html must NOT have role="button" or nest interactive controls inside <button>/<a>/[role="button"]
  const dropzoneOpenTag = indexHtml.match(/<div\s+id="dropzone"[^>]*>/i);
  assert.ok(dropzoneOpenTag, '#dropzone element must exist in index.html');
  assert.equal(/role="button"/i.test(dropzoneOpenTag[0]), false, '#dropzone must not use role="button" around nested <button>');
  assert.match(dropzoneOpenTag[0], /role="region"/i);

  const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
  const tagStack = [];
  const tagRegex = /<\/?([a-zA-Z0-9-]+)([^>]*)>/g;
  let m;
  while ((m = tagRegex.exec(indexHtml)) !== null) {
    const full = m[0];
    const tagName = m[1].toLowerCase();
    const attrs = m[2] || '';
    if (full.startsWith('</')) {
      for (let i = tagStack.length - 1; i >= 0; i--) {
        if (tagStack[i].tagName === tagName) {
          tagStack.splice(i);
          break;
        }
      }
      continue;
    }
    const isInteractiveControl = tagName === 'button' || tagName === 'a' || /\brole\s*=\s*["']button["']/i.test(attrs);
    if (isInteractiveControl) {
      const ancestorInteractive = tagStack.find(anc => anc.isInteractiveControl);
      assert.equal(
        ancestorInteractive,
        undefined,
        `Interactive <${tagName}> must never be nested inside interactive <${ancestorInteractive?.tagName}>`
      );
    }
    const selfClosing = full.endsWith('/>') || voidTags.has(tagName);
    if (!selfClosing) {
      tagStack.push({ tagName, isInteractiveControl });
    }
  }
  assert.match(indexHtml, /id="btn-browse-file"/);
  assert.match(indexHtml, /id="btn-cancel-obb-upload"/);
  assert.equal(/@import/i.test(stylesCss), false, 'styles.css must have zero @import rules');
  assert.equal(/url\s*\(/i.test(stylesCss), false, 'styles.css must have zero url(...) references');
  assert.ok(
    stylesCss.lastIndexOf('.hidden.hidden') > stylesCss.indexOf('.rd-btn {'),
    '.hidden.hidden must appear after .rd-btn so hidden buttons compute display:none'
  );
});

test('G10.7 Defensive coercion: hostile {toString:1, valueOf:1} objects never throw in sanitizeAppState/normalizeGame', () => {
  const hostileJson = JSON.parse(
    '{"games":[{"id":{"toString":1,"valueOf":1},"name":{"toString":1},"fileName":{"toString":1},"ext":{"toString":1},"sizeMB":{"valueOf":1},"legacyAndroid":{"toString":1},"legacyApi":{"valueOf":1},"minSdk":{"valueOf":1},"arch":{"toString":1},"signature":{"toString":1},"packageId":{"toString":1},"compatScore":{"valueOf":1},"settings":{"fps":{"valueOf":1},"resolutionScale":{"valueOf":1},"controlMode":{"toString":1},"controlLayout":{"size":{"valueOf":1},"opacity":{"valueOf":1}}}}],"renderApiUrl":{"toString":1},"cacheMB":{"valueOf":1},"engineSettings":{"ram":{"valueOf":1}}}'
  );

  const sanitized = sanitizeAppState(hostileJson);
  assert.equal(sanitized.renderApiUrl, '');
  assert.equal(Number.isFinite(sanitized.cacheMB), true);
  assert.equal(Number.isFinite(sanitized.engineSettings.ram), true);
  assert.equal(sanitized.games.length, 1);

  const g = sanitized.games[0];
  assert.equal(g.id, 'recovered-0');
  assert.equal(g.name, 'İsimsiz paket');
  assert.equal(g.fileName, 'bilinmeyen.apk');
  assert.equal(g.ext, 'APK');
  assert.equal(g.sizeMB, 0);
  assert.equal(g.legacyApi, 0);
  assert.equal(g.minSdk, 0);
  assert.equal(g.compatScore, 0);
  assert.equal(g.settings.fps, 60);
  assert.equal(g.settings.resolutionScale, 100);
  assert.equal(g.settings.controlMode, 'Sanal Gamepad Katmanı');
  assert.equal(g.settings.controlLayout.size, 100);
  assert.equal(g.settings.controlLayout.opacity, 85);

  const nullProto = Object.create(null);
  assert.equal(validateRenderApiUrl(nullProto).valid, false);
  assert.equal(validateRenderApiUrl({ toString: 1, valueOf: 1 }).valid, false);
  assert.equal(escapeHtml({ toString: 1, valueOf: 1 }), '');
  assert.equal(normalizeGame({ id: nullProto, sizeMB: nullProto }).id, 'recovered-0');
});


