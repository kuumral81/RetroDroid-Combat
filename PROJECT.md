# Project: RetroDroid Compat v5.4.0 (Bug Fixes, Hardening & Feature Development)

> **Source Archive (IMMUTABLE — DO NOT MODIFY):** `/home/antigravity/RetroDroid_Compat_v5.3.1_temiz.zip` (symlink to `/home/antigravity/upload/RetroDroid_Compat_v5.3.1_temiz.zip`, SHA-256 `d0e91199c51e882d02d03f8eae7a9d8c8b6c4c5c0ad22662e81cc3dfb133ad8f`)
> **Original User Request:** `/home/antigravity/.agents/teamwork/ORIGINAL_REQUEST.md` (`"Geliştirme ve hata düzeltme"`)
> **Step 0 Survey Sources:**
> - `/home/antigravity/.agents/teamwork/explorer_survey_1/handoff.md` (Architecture, Inventory, Env, 16 bugs)
> - `/home/antigravity/.agents/teamwork/explorer_survey_2/handoff.md` (Deep Audit: 48 defects — 7 Critical, 16 High, 16 Medium, 9 Low)
> - `/home/antigravity/.agents/teamwork/explorer_survey_3/handoff.md` (8 Spec Compliance Gaps, 13 Improvements P0–P2, 4-Tier Linux VM Testability Strategy)

---

## Architecture

RetroDroid Compat is a Dockerized (Debian 12 bookworm / Render-ready) full-stack web application for inspecting, manifest-patching, aligning, re-signing, and repackaging legacy Android `.apk`, `.xapk`, `.apks`, `.apkm`, `.zip`, and `.obb` files.

### System Components & Data Flow
1. **Core Android Engine Package (`retrodroid/`)**:
   - `config.py`: Env-driven settings (`WORK_DIR`, `KEYSTORE_PATH`, `KEYSTORE_PASS`, `MAX_UPLOAD_MB`, `CHUNK_SIZE_MB`, `JOB_TTL_SECONDS`, `DISK_FREE_FLOOR_MB`, `MAX_CONCURRENT_PATCHES`, `MAX_ARCHIVE_ENTRIES`, `API_TOKEN`, `ALLOWED_ORIGINS`, `RATE_LIMIT_PER_MIN`, `JAVA_HEAP_MB`), filename sanitization, atomic JSON writes, `JAVA_TOOL_OPTIONS`-filtered command runner, structured logging.
   - `keystore.py`: RSA-2048 JKS lifecycle with env-var password passing (`-storepass:env` / `--ks-pass env:`), atomic `0o600` permissions, `fcntl.flock` startup lock, mandatory `keytool -list` verification, non-destructive recovery, and public SHA-256 certificate metadata.
   - `axml.py`: Hardened binary AXML patcher parsing AXML StringPool to explicitly target `<uses-sdk>`, strict header/chunk/attribute bounds checks, `Res_value.dataType` validation (`0x10`/`0x11`), and `minSdkVersion` floor enforcement (no blind downgrade).
   - `inspector.py`: Single-pass ZIP + `aapt dump badging` inspector (root-only `classes*.dex`, apostrophe-safe app label, full ABI + split ABI detection including `armeabi`/`mips`, pure-Python ELF64 16 KB `PT_LOAD` alignment analyzer, `resources.arsc` compression check, API 31+ unexported component count, Android 14 (API 23) / Android 15–17 (API 24) install floor verdict, and evidence-based compatibility checklist & score).
   - `patcher.py`: Slim-`apktool` manifest XML patcher (`targetSdkVersion` creation/update, `android:exported="true"`, `requestLegacyExternalStorage`, `usesCleartextTraffic`, `android.max_aspect` + `resizeableActivity`, `extractNativeLibs`), safe `apktool.yml` YAML updater (handles `sdkInfo: null`, `{}`, codenames like `'M'`), streaming APK rewriter (case-insensitive `META-INF` strip including `STAMP-CERT-SHA256`, ZIP entry dedup, decompression byte cap, pre-1980 timestamp clamp, `ZIP_STORED` for `resources.arsc` & `*.so`), `zipalign` (`-P 16` auto-detect fallback to `-p 4`), `apksigner` v1+v2+v3 signing via env password, split APK manifest patching & atomic `.apks` bundle assembly.
   - `containers.py`: Spec-compliant `.xapk` (`manifest.json`) & `.apkm` (`info.json`) container unpacker with Windows backslash normalization, filename sanitization, ZIP bomb/traversal/encryption/collision checks, non-colliding extraction paths, OBB path anti-double-nesting normalizer & `(main|patch).<ver>.<pkg>.obb` validator, and XAPK v2 builder (`total_size`, `permissions`, `icon.png`, `split_apks`, `expansions`, ZIP64 atomic output).
   - `jobs.py`: Reference-counted `ACTIVE_JOBS` tracker, per-job locks, `UPLOAD_LOCKS` lifecycle cleanup, atomic disk-backed `job_state.json` (survives restarts within TTL), subprocess cancellation registry (`Popen`), `.last_activity` heartbeat, and activity-safe TTL / low-disk cleanup.
2. **HTTP API & Composition Root (`server.py`)**:
   - Preserves `uvicorn server:app` entrypoint and re-exports core helpers for compatibility.
   - FastAPI `lifespan` startup/shutdown (no deprecated `@app.on_event`), all blocking I/O & subprocesses offloaded via `asyncio.to_thread` (or sync route threadpool), optional `API_TOKEN` auth, configurable `ALLOWED_ORIGINS`, per-IP rate limiting, security response headers, and strict `/api/download` allowlist.
   - Serves `index.html` at `GET /` and static assets at `GET /static/*`.
3. **Frontend SPA (`index.html`, `static/styles.css`, `static/app.js`, `static/vendor/`)**:
   - XSS-free DOM construction (zero inline `onclick` string interpolation, strict `http/https` `renderApiUrl` validation, `/api/` download URL verification).
   - Resumable chunked uploads (`GET /api/upload/status/{job_id}`), cancel via `AbortController`, live MB/s + ETA, chunked multi-GB OBB uploads, mobile `<input accept=".obb" multiple>` fallback, per-game OBB scoping, canonical OBB naming, real server manifest patch toggles cleanly separated from preview/profile notes, API 24–36 + 16 KB ELF diagnostics UI, WCAG 2.1 AA accessibility, and offline-capable assets.
4. **Deployment & Packaging (`Dockerfile`, `.dockerignore`, `requirements.txt`, `README.txt`)**:
   - Hardened non-root Debian 12 bookworm container with `exec uvicorn`, `--proxy-headers`, `HEALTHCHECK`, env-configurable `WORK_DIR`, CVE-free Python dependencies, accurate Turkish v5.4.0 docs, and clean normalized release zip `/home/antigravity/RetroDroid_Compat_v5.4.0.zip`.

---

## Code Layout

Working repository root: `/home/antigravity/RetroDroid_Compat/`

```text
/home/antigravity/RetroDroid_Compat/
├── server.py                      # M2: FastAPI app, routes, middleware, static mount (entrypoint: uvicorn server:app)
├── retrodroid/
│   ├── __init__.py                # M1: Package exports & version ("5.4.0")
│   ├── config.py                  # M1: Env config, sanitization, atomic JSON, run_cmd, logging
│   ├── keystore.py                # M1: Keystore lifecycle, env secret passing, SHA-256 cert info
│   ├── axml.py                    # M1: Hardened binary AXML parser & targetSdk patcher
│   ├── inspector.py               # M1: Single-pass APK/DEX/ABI/ELF64-16KB/apksigner inspector
│   ├── patcher.py                 # M1: Slim-apktool XML/YAML, stream_rewrite_apk, align/sign, splits
│   ├── containers.py              # M1: XAPK/APKM/APKS/ZIP unpacker, OBB normalizer, XAPK v2 builder
│   └── jobs.py                    # M2: Active-job tracking, locks, persistence, cancellation, janitor
├── index.html                     # M3: Semantic WCAG 2.1 AA SPA shell
├── static/
│   ├── styles.css                 # M3: Consolidated offline-capable CSS (replaces Play CDN / !important overrides)
│   ├── app.js                     # M3: Modular XSS-free frontend application logic
│   └── vendor/                    # M3: Vendored offline JSZip (or SRI-verified local bundle)
├── Dockerfile                     # M4: Hardened Debian 12 image (non-root, exec, HEALTHCHECK, --proxy-headers)
├── .dockerignore                  # M4: Excludes tests/, .venv/, .env, *.jks, *.pass, *.apk, *.xapk, *.zip
├── requirements.txt               # M1 (pins created) / M4 (verified CVE-free)
├── README.txt                     # M4: Updated Turkish v5.4.0 documentation
├── scripts/
│   └── build_release_zip.py       # M4: Deterministic release archive builder (0o755/0o644, LF, no dev/test files)
├── tests/
│   ├── unit/                      # Implementation Track unit tests (exclusive per-milestone ownership)
│   │   ├── test_core_engines.py   # M1
│   │   ├── test_backend_api.py    # M2
│   │   ├── test_frontend.mjs      # M3
│   │   └── test_packaging.py      # M4
│   └── e2e/                       # E2E Testing Track (opaque-box) + Final Milestone Tier 5
│       ├── conftest.py            # E2E Track
│       ├── fixtures_apk.py        # E2E Track: Real aapt/keytool synthetic APK/XAPK/APKS/APKM/ELF16K builder
│       ├── run_e2e.sh             # E2E Track: Canonical runner (--tier 1|2|3|4|5|all)
│       ├── test_tier1_features.py # E2E Track: >= 5 tests per feature
│       ├── test_tier2_boundaries.py # E2E Track: >= 5 boundary/corner/negative tests per feature
│       ├── test_tier3_interactions.py # E2E Track: Pairwise cross-feature combinations
│       ├── test_tier4_workloads.py # E2E Track: Real-world multi-feature scenarios (API + Chromium + concurrency)
│       └── test_tier5_adversarial.py # M5 Phase 2: White-box adversarial hardening tests
└── .venv/                         # M1: Isolated Python 3.11 venv (excluded from Docker & release zip)

Release Deliverable: /home/antigravity/RetroDroid_Compat_v5.4.0.zip (built in M4, rebuilt & verified after M5)
```

---

## Feature Inventory

Every feature, bug cluster (all 48 defects from `explorer_survey_2` + 16 from `explorer_survey_1`), and development improvement (all 13 proposals from `explorer_survey_3`) is assigned to a milestone (zero unassigned):

| # | Feature | Description & Defect/Improvement Coverage | Milestone | Source |
|---|---|---|---|---|
| F01 | **Server Health, Keystore Info & Startup Lifespan** | `GET /health` (`status: ok\|degraded`, `serverTime`, `workDir`, `toolVersions`, `zipalign16kSupported`, `keystoreFingerprintSha256`, `authRequired`), `GET /api/keystore-info`, FastAPI `lifespan` (replaces `@app.on_event`), structured logging with `jobId`. Covers LOW-01, MED-16, IMP-B4. | M1, M2 | survey_1, survey_2, survey_3 |
| F02 | **Secure Keystore Lifecycle & JVM Diagnostics** | Env-var secret passing (`-storepass:env` / `--ks-pass env:`), atomic `0o600` `.pass` & `.jks`, `fcntl.flock`, mandatory `keytool -list` verification, non-destructive failure/opt-in backup instead of silent wipe, `len >= 6` validation, `JAVA_TOOL_OPTIONS` stderr stripping & configurable `JAVA_HEAP_MB`. Covers HIGH-01, HIGH-02, HIGH-03, LOW-09, IMP-B2. | M1 | survey_2, survey_3 |
| F03 | **Resumable Chunked Upload & Single-Shot Analysis** | `POST /api/upload/init`, `/chunk`, `/finish`, `GET /api/upload/status/{job_id}`, `POST /api/analyze`; `initData.chunkSizeMB` adherence, 4xx fail-fast, resumable `sessionStorage` recovery, `AbortController` cancel + live MB/s & ETA, `isUploading` lock, 0-byte rejection, filename sanitization + length cap (`<=120`). Covers CRIT-01, CRIT-02, HIGH-14, MED-04, LOW-05, IMP-B1, IMP-C1. | M2, M3 | survey_1, survey_2, survey_3 |
| F04 | **Spec-Compliant Container Unpacking & Guardrails** | Parse XAPK `manifest.json` & APKM `info.json` before `score_base`; normalize Windows `\` paths; sanitize inner basenames; block zip-slip, encrypted entries, >`MAX_ARCHIVE_ENTRIES`, oversized entries, zip bombs (actual decompression cap), duplicate APK/OBB collisions; extract to isolated `_extracted/` avoiding self-truncation. Covers CRIT-01, CRIT-05, HIGH-11, HIGH-12, IMP-A3. | M1 | survey_1, survey_2, survey_3 |
| F05 | **Single-Pass APK Inspector & Android 15/16/17 Diagnostics** | Single-pass ZIP scan + `aapt dump badging` (root-only `classes*.dex`, apostrophe-safe label, `armeabi`/`mips` split ABI), pure-Python ELF64 16 KB `PT_LOAD` alignment audit, `resources.arsc` compression check, API 31+ missing `exported` count, API 24+ Android 15/16/17 install floor + API 36 support, evidence-based `compatChecklist` & `compatScore`, split ABI preservation post-patch. Covers HIGH-13, MED-02, MED-03, MED-16, IMP-A2, IMP-C2. | M1, M3 | survey_1, survey_2, survey_3 |
| F06 | **Hardened Binary AXML & Real Manifest Compatibility Patcher** | StringPool `<uses-sdk>` verification, bounds/`dataType` checks, `minSdk` floor & no-silent-downgrade in `axml.py`; safe `apktool.yml` YAML update (`sdkInfo: null`, `{}`, `'M'`), create missing `<uses-sdk>`/`targetSdkVersion`; wire real flags (`patchTargetSdk`, `addLegacyStorage`, `enableCleartext`, `addNotchSupport`, `forceExtractNativeLibs`, API 31+ `android:exported`); explicit `patchSummary` & fallback stderr transparency. Covers CRIT-03, CRIT-04, HIGH-12, HIGH-15, IMP-A1, IMP-A4. | M1, M2, M3 | survey_1, survey_2, survey_3 |
| F07 | **Streaming APK Rewrite, Alignment, Signing & Split `.apks`** | Case-insensitive `META-INF` strip (incl. `STAMP-CERT-SHA256`), duplicate entry dedup, cumulative decompression cap, pre-1980 ZIP timestamp clamp, `ZIP_STORED` for `resources.arsc` & `*.so`, pre-write slim-APK size check, `zipalign` (`-P 16` auto-detect / `-p 4`), env-secret `apksigner` v1+v2+v3, split APK API 31+ `exported` check & atomic `.apks` bundle, isolated `_work/<uuid>` temp dir, safe `src_apk` retention (>180 MB kept until verified + disk check). Covers CRIT-05, CRIT-06, CRIT-07, HIGH-01, HIGH-12, HIGH-13, MED-02. | M1, M2 | survey_1, survey_2, survey_3 |
| F08 | **OBB Pairing, Chunked OBB Upload & Async XAPK v2 Builder** | Per-game/job scoped OBB state (`sessionFileStore`), canonical `main.<ver>.<pkg>.obb` upload naming, mobile `<input accept=".obb" multiple>` fallback, chunked OBB upload endpoints + legacy multipart with `try/finally` close, anti-double-nesting OBB path normalizer, `POST /api/full-xapk/{job_id}` (sync + `background=true` + `/api/full-xapk-status/{job_id}`) emitting XAPK v2 `manifest.json` (`total_size`, `permissions`, `icon.png`, `split_apks`, `expansions`), atomic unique-temp `/api/download-obb/{job_id}/{obb_index}`. Covers HIGH-05, HIGH-06, HIGH-07, HIGH-09, HIGH-10, HIGH-11, MED-06, MED-08, MED-10, LOW-02, IMP-A3. | M1, M2, M3 | survey_1, survey_2, survey_3 |
| F09 | **Non-Blocking Async Server, Persistent Jobs, Cancel & Janitor** | Offload all blocking I/O & subprocesses via `asyncio.to_thread` / sync routes; atomic `job_state.json` persistence surviving restarts; `POST /api/patch-cancel/{job_id}` (`Popen` cancel); `DELETE /api/jobs/{job_id}`; ref-counted `ACTIVE_JOBS` + per-job locks + `.last_activity` heartbeat; `UPLOAD_LOCKS` cleanup; locked `logs` append; `serverTime`/`expiresInSeconds` clock-skew fix; env-configurable `WORK_DIR`, `JOB_TTL_SECONDS`, `CHUNK_SIZE_MB`, `DISK_FREE_FLOOR_MB`. Covers CRIT-02, HIGH-05, MED-04, MED-13, LOW-03, IMP-B1, IMP-B3. | M2, M3 | survey_1, survey_2, survey_3 |
| F10 | **API Security, Download Allowlist, XSS Elimination & CVE-Free Deps** | Upgrade `fastapi`/`starlette`/`uvicorn`/`python-multipart` (+ `PyYAML`) eliminating CVE-2024-47874, CVE-2025-54121, CVE-2024-53981, CVE-2026-42561, CVE-2026-24486; URL-encoded `downloadUrl`; `/api/download` artifact allowlist + `.is_file()`; env `ALLOWED_ORIGINS` (safe default, not wildcard `*`), optional `API_TOKEN`, per-IP rate limit, security headers middleware; eliminate all inline `onclick`/`href` XSS in frontend. Covers CRIT-01, HIGH-04, HIGH-16, MED-04, IMP-B2. | M1, M2, M3 | survey_1, survey_2, survey_3 |
| F11 | **Honest Patch Controls, Progress UX & Post-Patch Persistence** | Cleanly divide "Gerçek Sunucu APK Yamaları" from "Web Önizleme / Profil Notları", remove fictional JIT/Vulkan/Scoped-OBB runtime claims, apply `serverSignedResult` mutations BEFORE `saveState()`/`renderLibrary()`, set `hasObb` from authoritative server `obbFiles`, monotonic progress bar (no 55%→20% jump), `checkRenderServer` timer/race/duplicate-fetch/URL fixes, clear expiry timer on new patch. Covers HIGH-08, HIGH-09, HIGH-15, MED-11, MED-12, MED-15, IMP-A1. | M3 | survey_1, survey_2, survey_3 |
| F12 | **Download Center, Reports & Validated State/Backup** | Visible inline Full XAPK progress when triggered outside modal, 512 MB RAM guard & concurrency lock on client-side `JSZip`, strict whitelist validation on `loadState()`/`importAppBackup()` (`activeTab`, `activeProfile`, `cacheMB`, `renderApiUrl`), clean transient state teardown on delete/reset, merge on file reattach, `download` + `rel="noopener"` on links. Covers HIGH-15, MED-09, MED-10, MED-13. | M3 | survey_1, survey_2 |
| F13 | **Game Library, Consistent Filters & Storage Dashboard** | Consistent container grouping (`XAPK`, `APK+OBB`, `APKS`, `APKM`, `ZIP`) across Library filter pills and System tab storage breakdown, proportional SVG donut normalization when `totalUsedMB > quota`, upsert by `id`/`packageId` preserving saved per-game settings & pruning old `sessionFileStore` keys. Covers MED-05, MED-07. | M3 | survey_1, survey_2 |
| F14 | **Control Layout Editor & Virtual Sandbox Preview** | Reject duplicate key bindings in editor, clear `pressedKeys` on `window` blur, delta-time (`dt`) movement respecting FPS setting, HiDPI `devicePixelRatio` canvas scaling + bounds re-clamp, honest simulation labels. Covers LOW-06, MED-15. | M3 | survey_1, survey_2 |
| F15 | **Production Static Assets & WCAG 2.1 AA Accessibility** | Split inline CSS/JS into `static/styles.css` & `static/app.js`, self-hosted offline-capable styling & vendored `static/vendor/jszip.min.js` (no Play CDN dependency or unpinned CDN without SRI), remove `!important` redesign overrides & dead hidden status-bar/30s timer, focus-preserving module toggles, ARIA `dialog`/`aria-modal`/`tablist`/`aria-label`/focus restore, clean SDK text formatting. Covers MED-14, LOW-07, LOW-08, IMP-C3, IMP-D1. | M3 | survey_2, survey_3 |
| F16 | **Container Hardening, Documentation & Release Packaging** | Hardened `Dockerfile` (`exec uvicorn`, `--proxy-headers`, non-root `appuser`, `HEALTHCHECK`, tool checks incl. `zipalign` & `keytool`, `retrodroid/` + `static/` copy), expanded `.dockerignore`, accurate Turkish v5.4.0 `README.txt` (fixing keystore fallback & `/var/data` `WORK_DIR`), deterministic `scripts/build_release_zip.py` producing `0o755`/`0o644` LF `/home/antigravity/RetroDroid_Compat_v5.4.0.zip`. Covers MED-01, MED-16, LOW-04, IMP-D2. | M4 | survey_1, survey_2, survey_3 |
| F17 | **Opaque-Box E2E Test Suite (Tiers 1–4)** | Independent requirement-driven E2E suite (`tests/e2e/`) with real `aapt`-compiled synthetic APKs/XAPKs/APKS/APKM/ELF16K fixtures, live `uvicorn` HTTP API verification + real `aapt`/`zipalign -c`/`apksigner verify` CLI validation, headless Chromium browser UI E2E, and concurrency/security/fault-injection E2E across Tiers 1–4 (>= 180 tests). Publishes `TEST_INFRA.md` & `TEST_READY.md`. | E2E Track | survey_3, Project Pattern |
| F18 | **Final E2E Acceptance & Tier 5 Adversarial Hardening** | Phase 1: sequential Tier 1 → Tier 2 → Tier 3 → Tier 4 pass (100% green). Phase 2: white-box Tier 5 adversarial challenger loop finding remaining code/test gaps & fixing until 0 gaps remain. Final regeneration & verification of `/home/antigravity/RetroDroid_Compat_v5.4.0.zip`. | M5 | Project Pattern |

---

## Milestones

| # | Name | Scope (Features) | Exclusive Write Ownership | Dependencies | Status | Sub-Orch Conv ID |
|---|---|---|---|---|---|---|
| **M1** | **Workspace Bootstrap, Toolchain & Core Android Engines** | F01 (config/logging), F02, F04, F05 (engine), F06 (engine), F07 (engine), F08 (containers/OBB engine), F10 (CVE-free `requirements.txt`) | Extract zip → `/home/antigravity/RetroDroid_Compat/`, VM `apt` Android tools, `.venv`, `requirements.txt`, `retrodroid/{__init__,config,keystore,axml,inspector,patcher,containers}.py`, `tests/unit/test_core_engines.py` | none | DONE (Iter 4 5/5 PASS, 68/68 pytest, Auditor CLEAN) | `e0a1ffae2ddc258029e037f6d057ee29` (`sub_orch_m1_r4`) |
| **M2** | **FastAPI Server, Async Pipeline, Jobs & API Security** | F01, F03 (backend), F06 (API flags), F07 (pipeline), F08 (endpoints), F09, F10 (backend) | `retrodroid/jobs.py`, `server.py`, `tests/unit/test_backend_api.py` | M1 | DONE (Iter 2 3/3 PASS, 33 M2 + 68 M1 = 101/101 pytest, Auditor CLEAN) | `86597e64a25fbcf42d7f3a04c915212d` (`orchestrator_8`) |
| **M3** | **Frontend SPA Overhaul: Security, State, UX & Accessibility** | F03 (UI), F05 (UI), F06 (UI), F08 (UI), F09 (UI), F10 (XSS), F11, F12, F13, F14, F15 | `index.html`, `static/styles.css`, `static/app.js`, `static/vendor/*`, `tests/unit/test_frontend.mjs` (+ surgical post-M3 `static/` assertion update in `tests/unit/test_backend_api.py:307` in Iter 2) | M1 (sequential after M2) | DONE (Iter 2 3/3 PASS, 46/46 Node, 101/101 pytest, live Chromium E2E, Auditor CLEAN) | `e1496bbbc61d455af40008e0c9f158fd` (`orchestrator_12`) |
| **E2E** | **Opaque-Box E2E Testing Track (Tiers 1–4)** | F17 | `/home/antigravity/TEST_INFRA.md`, `/home/antigravity/TEST_READY.md`, `/home/antigravity/RetroDroid_Compat/tests/e2e/*` | M1 (sequential after M4) | DONE (`TEST_READY.md` published; 211/211 Tiers 1–4 + 26/26 Tier 5 = 237/237 E2E passing; verified under M5 Iter 2 3/3 PASS) | `cc34fe7a745ed2a4550bc59e71724ee7` (`orchestrator_15`) |
| **M4** | **Container Hardening, Docs & Release Packaging** | F16 | `Dockerfile`, `.dockerignore`, `README.txt`, `scripts/build_release_zip.py`, `tests/unit/test_packaging.py`, `/home/antigravity/RetroDroid_Compat_v5.4.0.zip` | M2, M3 | DONE (Iter 1 3/3 PASS: `aud_m4_r12` CLEAN, `rev_m4_r13` APPROVE, `chal_m4_r13` APPROVE; 122/122 pytest, 46/46 Node, live Debian 12 Docker) | `f072c05b5bd86b0468acacdaf6470387` (`orchestrator_13`) |
| **M5** | **Final Milestone: 100% E2E Pass (Tiers 1–4) + Tier 5 Adversarial Hardening** | F18 | Any targeted bug fixes across `RetroDroid_Compat/`, `tests/e2e/test_tier5_adversarial.py`, final `/home/antigravity/RetroDroid_Compat_v5.4.0.zip` | M4, E2E (`TEST_READY.md`) | DONE (Iter 2 3/3 UNANIMOUS PASS: `aud_m5_iter2_r13` CLEAN, `rev_m5_iter2_r13` APPROVE, `chal_m5_iter2_r15` APPROVE; 408/408 tests, 0 ruff, deterministic v5.4.0.zip `179,788 B` SHA-256 `abe0d65dbd5f005d758aadca85121daad7e52916341e9abae507dd08bfe45573`) | `cc34fe7a745ed2a4550bc59e71724ee7` (`orchestrator_15`) |

---

## Interface Contracts

### 1. Internal Python Engine Contracts (`retrodroid/*` ↔ `server.py`)

#### `retrodroid/config.py`
- `APP_VERSION: str = "5.4.0"`
- `get_settings() -> Settings` (reads env dynamically or reloadable for tests):
  - `WORK_DIR: Path` (env `WORK_DIR`, default `/tmp/retrodroid_jobs`)
  - `KEYSTORE_PATH: Path` (env `KEYSTORE_PATH`, default `/var/data/retrodroid.jks`, fallback `WORK_DIR / "_keystore" / "retrodroid.jks"`)
  - `KEYSTORE_PASS: str` (env `KEYSTORE_PASS`, default `""`)
  - `KEYSTORE_AUTO_REGEN: bool` (env `KEYSTORE_AUTO_REGEN`, default `False`)
  - `MAX_UPLOAD_MB: int` (default `5120`), `CHUNK_SIZE_MB: int` (default `8`), `JOB_TTL_SECONDS: int` (default `3600`), `DISK_FREE_FLOOR_MB: int` (default `1500`)
  - `MAX_CONCURRENT_PATCHES: int` (default `1`), `MAX_ARCHIVE_ENTRIES: int` (default `25000`), `MAX_DECOMPRESSED_BYTES: int` (default `10 * 1024**3`)
  - `API_TOKEN: str` (env `API_TOKEN` or `API_ACCESS_TOKEN`, default `""`)
  - `ALLOWED_ORIGINS: list[str]` (env `ALLOWED_ORIGINS`, default `["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:10000", "http://127.0.0.1:10000"]`)
  - `RATE_LIMIT_PER_MIN: int` (env `RATE_LIMIT_PER_MIN`, default `120`; `0` disables)
  - `JAVA_HEAP_MB: int` (env `JAVA_HEAP_MB`, default `256`)
- `sanitize_filename(name: str, default: str = "file.apk", max_len: int = 120) -> str`: strips path components (normalizing `\` → `/`), replaces chars outside `[A-Za-z0-9._-]` with `_`, strips leading dots/underscores, truncates stem preserving extension so `len <= max_len`.
- `safe_url_download(job_id: str, filename: str) -> str`: returns `f"/api/download/{job_id}/{urllib.parse.quote(filename, safe='')}"`.
- `write_json_atomic(path: Path, data: Any) -> None`: writes unique `.tmp` sibling + `fsync` + `os.replace`.
- `clean_java_output(stderr: str, stdout: str) -> str`: strips `Picked up JAVA_TOOL_OPTIONS:` noise lines and combines non-empty output cleanly.
- `run_cmd(cmd: list[str], timeout: int = 180, env: dict[str, str] | None = None, cancel_event: threading.Event | None = None, on_proc: Callable[[subprocess.Popen], None] | None = None) -> CmdResult`: runs subprocess with optional cancel support & clean output helper.
- `copy_stream_limited(src, dst, max_bytes: int, label: str) -> int`.

#### `retrodroid/keystore.py`
- `ensure_signing_keystore(settings: Settings | None = None) -> KeystoreState`:
  - Uses `fcntl.flock` lock file for process safety.
  - Creates `.pass` atomically with `os.open(..., 0o600)` when auto-generating; validates `len(password) >= 6`.
  - ALWAYS verifies existing keystore via `keytool -list -v -keystore <ks> -storepass:env RD_KS_PASS` (password passed ONLY via child `env`, never `argv`).
  - If existing keystore fails verification: raises `KeystoreError` (and sets `ready=False`, never silently deletes!) unless `KEYSTORE_AUTO_REGEN=True` (in which case backs up to `.bak.<ts>` before regenerating).
  - Sets `0o600` on keystore file; caches public cert metadata (`sha256`, `subject`, `validUntil`, `alias`, `algorithm`).
- `get_keystore_info() -> dict`: safe public metadata (NEVER returns password).

#### `retrodroid/axml.py`
- `patch_binary_axml_target_sdk(axml_bytes: bytes, new_target_sdk: int, allow_downgrade: bool = False) -> dict`:
  - Strict bounds validation (`8 <= fhdr <= n`, `8 <= chdr <= csize`, `attr_start >= 20`, `attr_size >= 20`, `a_off + 20 <= pos + csize`) — NEVER raises `struct.error` on corrupt AXML (returns `{"patched": False, "error": "..."}`).
  - Parses AXML StringPool (UTF-8 & UTF-16LE) and verifies enclosing `START_ELEMENT` tag name == `"uses-sdk"`.
  - Checks `Res_value.dataType` (`0x10` TYPE_INT_DEC or `0x11` TYPE_INT_HEX) before reading integer values; detects string/reference types cleanly.
  - Enforces `effective_target = max(new_target_sdk, old_min)` if `old_min` is integer, and respects `allow_downgrade=False` (skips downward change if `old_target > new_target_sdk` with explicit `skippedDowngrade: True` + `effectiveTargetSdk`).
  - Returns `{patched: bool, data: bytes, oldMinSdk: int|None, oldTargetSdk: int|None, newTargetSdk: int|None, skippedDowngrade: bool, reason: str|None}`.

#### `retrodroid/inspector.py`
- `inspect_elf_16k_alignment(elf_bytes: bytes) -> dict`: pure-Python ELF64 `PT_LOAD` `p_align` parser (`>= 16384`).
- `inspect_apk(apk_path: Path, container_info: dict | None = None, preverified_sig_text: str | None = None) -> dict`:
  - Single-pass ZIP scan (checks `AndroidManifest.xml` presence BEFORE calling `aapt`, extracts root-only `classes*.dex` counts/versions, `lib/<abi>/*.so` ABIs, ELF64 16 KB `PT_LOAD` status, `resources.arsc` compression flag, `META-INF` signature presence).
  - Single `aapt dump badging` call (extracts `packageId`, `versionCode`, `versionName`, apostrophe-safe `appLabel`, `minSdk`, `targetSdk`, and `uses-permission` — falling back to `aapt dump permissions` only if badging omitted them).
  - Counts API 31+ unexported components (via `aapt dump xmltree <apk> AndroidManifest.xml`).
  - Runs `apksigner verify --verbose --print-certs` (or reuses `preverified_sig_text`).
  - Merges split ABIs (including `armeabi`, `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`, `mips`, `mips64`) from `container_info`.
  - Computes `installFloorStatus` (Android 14 min 23, Android 15–17 min 24), `pageSize16kStatus`, `elf16kReport`, `resourcesArscCompressed`, `missingExportedCount`, `compatChecklist`, `compatScore` (0–100), and contextual `warnings`.

#### `retrodroid/patcher.py`
- `ManifestPatchOptions` dataclass: `target_sdk: int = 28`, `patch_target_sdk: bool = True`, `add_legacy_storage: bool = False`, `enable_cleartext: bool = False`, `add_notch_support: bool = False`, `force_extract_native_libs: bool = False`, `allow_downgrade: bool = False`.
- `patch_manifest_xml_apktool(manifest_path: Path, opts: ManifestPatchOptions) -> dict`:
  - Creates `<uses-sdk>` and/or `android:targetSdkVersion` if absent; enforces `minSdk` floor & `allow_downgrade`.
  - Applies requested manifest attributes (`requestLegacyExternalStorage`, `usesCleartextTraffic`, `resizeableActivity` + `<meta-data android:name="android.max_aspect" android:value="2.4"/>`, `extractNativeLibs`, and API 31+ `android:exported="true"` on components with `<intent-filter>`).
  - Returns `{changed: bool, appliedChanges: list[str], oldTargetSdk, newTargetSdk}`.
- `update_apktool_yml(yml_path: Path, target_sdk: int) -> bool`: YAML-safe update handling `sdkInfo: null`, `sdkInfo: {}`, numeric and non-numeric (`'M'`, `null`) `targetSdkVersion` cleanly.
- `stream_rewrite_apk(src_apk: Path, dst_apk: Path, manifest_override: bytes | None = None, arsc_override: bytes | None = None, res_overrides: dict[str, bytes] | None = None, max_decompressed_bytes: int = ...) -> dict`:
  - Case-insensitive `META-INF/` signature stripping (`*.SF`, `*.RSA`, `*.DSA`, `*.EC`, `*.MF`, `SIG-*`, `STAMP-CERT-SHA256`).
  - Deduplicates duplicate ZIP entry names.
  - Clamps pre-1980 DOS `date_time` to `(1980, 1, 1, 0, 0, 0)`.
  - Enforces cumulative decompressed byte cap via `copy_stream_limited`.
  - Forces `ZIP_STORED` on `resources.arsc` and `*.so`; preserves ZIP64.
- `detect_zipalign_16k() -> bool` & `align_and_sign_apk(src_apk: Path, dst_apk: Path, keystore_state: KeystoreState, resign: bool = True, timeout: int = 300, verify_out: list[str] | None = None, cancel_event: threading.Event | None = None) -> list[str]`:
  - Uses `zipalign -P 16 -f 4` if supported else `zipalign -f -p 4`.
  - Passes keystore password via `env:RD_KS_PASS` (NEVER `argv`).
- `patch_and_sign_pipeline(...) -> dict`: full orchestrator using isolated `_work/<uuid>` temp dir, safe `src_apk` retention (only deletes `src_apk` AFTER verified `signed` exists AND only if low disk, updating metadata `repatchAvailable`), split APK manifest patching & atomic `.apks` bundle creation, returning complete result + `patchSummary`.

#### `retrodroid/containers.py`
- `unpack_container_if_needed(uploaded_path: Path, job_dir: Path, max_entries: int = 25000, max_bytes: int = ...) -> tuple[Path, dict]`:
  - Normalizes `\` → `/` everywhere; blocks path traversal, encrypted entries, entry count/size bombs, duplicate sanitized APK names.
  - Parses XAPK `manifest.json` (`split_apks` / `apk` / `expansions`) and APKM `info.json` before falling back to `score_base`.
  - Extracts base APK into `job_dir / "_extracted" / safe_name` (preventing self-truncation when `uploaded_path.name == inner_name`).
  - Assigns unique index-prefixed disambiguated names if duplicate OBB basenames exist in subdirs.
- `normalize_obb_relpath(raw_name: str, package_id: str) -> str`: strips redundant leading `Android/obb/<pkg>/` or `<pkg>/` to prevent double-nesting; validates `(main|patch).<ver>.<pkg>.obb` and reports warnings/suggestions.
- `build_full_xapk(job_dir: Path, patch_result: dict, container_meta: dict | None, extra_obb_meta: list[dict], progress_cb=None, cancel_event=None) -> dict`:
  - Atomically writes `*_RetroDroid_Full_Signed.xapk` (ZIP64, `ZIP_STORED`) containing signed base APK, signed splits, container/extra OBBs under `Android/obb/<pkg>/`, extracted `icon.png` (if available), `RETRODROID-INSTALL.txt`, and spec-compliant XAPK v2 `manifest.json` (`xapk_version: 2`, `package_name`, `name`, `version_code`, `version_name`, `min_sdk_version`, `target_sdk_version`, `total_size`, `permissions`, `expansions`, `split_apks`).

---

### 2. HTTP REST API Contract (`server.py` ↔ `index.html`/`static/app.js` ↔ E2E Suite)

All `/api/*` endpoints honor optional `API_TOKEN` via `Authorization: Bearer <token>` or `X-API-Token: <token>` (and `?token=<token>` on `GET /api/download*` for browser `<a download>`). When `API_TOKEN` is unset (default), no auth header is required.

| Method & Path | Request | Success Response (JSON / File) | Error Codes |
|---|---|---|---|
| `GET /` | — | `200 text/html` (`index.html`) | — |
| `GET /static/{path}` | — | `200` CSS/JS/vendor static file | `404` |
| `GET /health` | Optional `?strict=true` | `200` `{status: "ok"\|"degraded", healthy: bool, version: "5.4.0", serverTime, diskFreeMB, workDir, maxUploadMB, chunkSizeMB, jobTtlSeconds, maxConcurrentPatches, activePatches, keystoreReady, keystoreFingerprintSha256, authRequired, tools, toolVersions, zipalign16kSupported}` (`503` if `strict=true` and degraded) | `503` (`strict=true`) |
| `GET /api/keystore-info` | — | `200` `{ready, alias, algorithm, sha256, subject, validUntil, persistent, path}` | `401` |
| `POST /api/upload/init` | Form: `fileName`, `totalSize`, `totalChunks`, optional `jobId`, `purpose` | `200` `{jobId, fileName, sanitizedFileName, totalSize, totalChunks, chunkSizeMB, maxUploadMB}` | `400`, `401`, `413`, `429` |
| `GET /api/upload/status/{job_id}` | — | `200` `{jobId, fileName, totalSize, totalChunks, chunkSizeMB, receivedChunks, missingChunks, complete, status}` | `400`, `401`, `404` |
| `POST /api/upload/chunk` | Form: `jobId`, `chunkIndex`, `totalChunks`; File: `chunk` | `200` `{ok: true, jobId, chunkIndex, receivedCount, totalChunks}` | `400`, `401`, `404`, `413` |
| `POST /api/upload/finish` | Form: `jobId` | `200` `{jobId, fileName, sanitizedFileName, sizeBytes, sizeMB, containerType, innerApkName, splitApks, obbFiles, hasObb, ...inspect_apk_fields}` | `400`, `401`, `404`, `413`, `422` |
| `POST /api/analyze` | File: `file` | `200` Same schema as `/api/upload/finish` | `400`, `401`, `413`, `422` |
| `POST /api/patch-sign` | Form: `jobId`, `targetSdk=28`, `mode="patch_and_sign"`, `resign=true`, `background=false`, `patchTargetSdk=true`, `addLegacyStorage=false`, `enableCleartext=false`, `addNotchSupport=false`, `forceExtractNativeLibs=false`, `allowDowngrade=false` | `200` (sync: full result with `downloadUrl`, `inspector`, `patchSummary`, `logs`, `repatchAvailable`, `serverTime`; background: `{jobId, status: "running", progress, stage}`) | `400`, `401`, `404`, `409` (job active), `429` (slot full), `500` |
| `GET /api/patch-status/{job_id}` | — | `200` `{jobId, status, progress, stage, logs, result, error, createdAt, updatedAt, serverTime, expiresInSeconds}` | `400`, `401`, `404` |
| `POST /api/patch-cancel/{job_id}` | — | `200` `{ok: true, jobId, status: "canceled"}` | `400`, `401`, `404`, `409` |
| `GET /api/jobs` | — | `200` `{jobs: [...], linkTtlSeconds, serverTime}` | `401` |
| `DELETE /api/jobs/{job_id}` | — | `200` `{ok: true, jobId, deleted: true}` | `400`, `401`, `404`, `409` |
| `POST /api/attach-obb/{job_id}` | Multipart `files` (also supports chunked `/api/attach-obb/{job_id}/init`, `/chunk`, `/finish`) | `200` `{ok: true, jobId, count, totalSizeBytes, files: [{name, normalizedPath, sizeBytes, validObbName, warning}]}` | `400`, `401`, `404`, `409`, `413` |
| `POST /api/full-xapk/{job_id}` | Optional Form: `background=false` | `200` (sync: `{ok: true, jobId, fileName, downloadUrl, sizeBytes, sizeMB, manifest, warnings}`; background: `{jobId, status: "running", progress, stage}`) | `400`, `401`, `404`, `409` |
| `GET /api/full-xapk-status/{job_id}` | — | `200` `{jobId, status, progress, stage, result, error, serverTime}` | `400`, `401`, `404` |
| `GET /api/download-full-xapk/{job_id}` | — | `200 application/octet-stream` | `400`, `401`, `404` |
| `GET /api/download/{job_id}/{filename}` | — | `200` Allowlisted output artifact only (NEVER raw upload, `.json`, `.pass`, `.jks`, `_work`) | `400`, `401`, `403`, `404` |
| `GET /api/download-obb/{job_id}/{obb_index}` | — | `200 application/octet-stream` (unique temp extraction) | `400`, `401`, `404` |

### 3. Security & Compatibility Invariants
- All responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- `job_id` strictly validated against `^[0-9a-f]{12}$` on every job route (rejects traversal/invalid IDs with `400`).
- Zero inline `onclick="..."` with dynamic string interpolation in `index.html`/`static/app.js`; zero unescaped `href` interpolation.
- Zero keystore passwords in subprocess `argv` (`keytool`/`apksigner` receive password strictly via child `env`).
- Zero blocking I/O or subprocesses on the FastAPI asyncio event loop (`/health` stays `< 200 ms` during active upload finish / patch).
- Original archive `/home/antigravity/RetroDroid_Compat_v5.3.1_temiz.zip` remains completely unmodified.
