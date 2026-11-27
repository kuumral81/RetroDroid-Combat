# RetroDroid Compat v5.4.0 — E2E Readiness Manifest (`TEST_READY.md`)

**Status:** READY & VERIFIED (100% PASS across Tiers 1–5 + Unit + Node suites)
**Canonical Runner:** `bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier all`

## Exact Test Counts by Tier & Suite

| Suite / Tier | File | Count | Target Floor | Mode |
|---|---|---:|---:|---|
| **Tier 1 (Features F01–F16)** | `tests/e2e/test_tier1_features.py` | **93** | >= 80 (>= 5/feature) | Opaque-box live HTTP + CLI |
| **Tier 2 (Boundaries & Negative)** | `tests/e2e/test_tier2_boundaries.py` | **88** | >= 80 | Opaque-box live HTTP |
| **Tier 3 (Cross-Feature Interactions)** | `tests/e2e/test_tier3_interactions.py` | **20** | >= 18 | Opaque-box live HTTP + CLI + Restart |
| **Tier 4 (Real-World Workloads + Chromium)** | `tests/e2e/test_tier4_workloads.py` | **10** | >= 8 | Live API Workloads (4) + Offline Chromium UI (6) |
| **Tier 5 (Adversarial Hardening)** | `tests/e2e/test_tier5_adversarial.py` | **26** | >= 15 | White-box ASGI Cancel, Coercion, TCP RST, Packaging |
| **E2E Total (Tiers 1–5)** | `tests/e2e/` | **237** | >= 201 | Full E2E |
| Unit — Core Engines (M1) | `tests/unit/test_core_engines.py` | **68** | — | Real Android toolchain unit |
| Unit — Backend API & Jobs (M2) | `tests/unit/test_backend_api.py` | **33** | — | FastAPI/JobManager unit |
| Unit — Packaging & Hardening (M4/M5) | `tests/unit/test_packaging.py` | **23** | — | Docker/README/Release ZIP unit |
| Unit — Frontend SPA & JSZip (M3/M5) | `tests/unit/test_frontend.mjs` | **47** | — | Node `node:test` ES module |
| **Grand Total Automated Tests** | All suites | **408** | — | 100% Genuine & Passing |

## Feature Coverage Checklist (`F01`–`F18`)

- [x] **F01** — Server Health (`/health`, `/health?strict=true`), Keystore Info (`/api/keystore-info`), Lifespan & Security Headers (Tier 1: 9 tests; Tier 2: degraded 503)
- [x] **F02** — Secure Keystore Lifecycle (`0o600`, `keytool -list`, non-destructive degraded mode, `KEYSTORE_AUTO_REGEN` `.bak.*` backup) (Tier 1: 5 tests; Tier 4/5: recovery + secret isolation)
- [x] **F03** — Resumable Chunked Upload (`/init`, `/status`, `/chunk`, `/finish`) & Single-Shot `/api/analyze` (Tier 1: 6 tests; Tier 2: 18 boundary tests; Tier 3: resume + flags)
- [x] **F04** — Spec-Compliant Container Unpacking (`XAPK`, `APKM`, `APKS`, `ZIP`, backslash paths, zip-slip/encrypted/duplicate rejection) (Tier 1: 6 tests; Tier 2: 7 hostile container tests)
- [x] **F05** — Single-Pass APK Inspector & Android 15–17 Diagnostics (apostrophe label, root-only multi-DEX, ELF64 16 KB vs 4 KB `PT_LOAD`, ARM32, compressed `resources.arsc`, unexported components, install floor, score) (Tier 1: 7 tests; Tier 3: post-patch preservation)
- [x] **F06** — Hardened Binary AXML & Real Manifest Patcher (`targetSdk` 28/31/34/36, `android:exported="true"`, `requestLegacyExternalStorage`, `usesCleartextTraffic`, `resizeableActivity` + `android.max_aspect`, `extractNativeLibs`, `<uses-sdk>` creation, `allowDowngrade`, `minSdk` floor) (Tier 1: 7 tests; Tier 2: 13 tests; Tier 3: all-5-flags CLI verify)
- [x] **F07** — Streaming APK Rewrite, Alignment, Signing & Split `.apks` (`apksigner verify` v1+v2+v3, `zipalign -c`, `META-INF` strip, `ZIP_STORED` `resources.arsc` & `*.so`, `resign_only`, split `.apks` bundle) (Tier 1: 6 tests; Tier 3: repatch & APKM split verification)
- [x] **F08** — OBB Pairing, Chunked OBB Upload & Async Full XAPK v2 Builder (multipart & chunked OBB, anti-double-nesting, collisions, sync & background Full XAPK v2 + `manifest.json`, temp OBB download cleanup) (Tier 1: 6 tests; Tier 2: 6 tests; Tier 3/4: full XAPK + Chromium OBB isolation)
- [x] **F09** — Non-Blocking Async Server, Persistent Jobs, Cancel & Janitor (background poll, `/health` < 200ms during patch, `job_state.json` restart persistence, interrupted recovery, cancel + delete) (Tier 1: 5 tests; Tier 3/4: restart durability & concurrency)
- [x] **F10** — API Security, Download Allowlist, XSS Elimination & CVE-Free Deps (`API_TOKEN` Bearer/`X-API-Token`/`?token=`, CORS, rate limit `429`, download allowlist `403`, Range `206`/`416`, XSS browser verification) (Tier 1: 6 tests; Tier 2: 16 tests; Tier 4: Chromium XSS & auth flow)
- [x] **F11** — Honest Patch Controls, Progress UX & Post-Patch Persistence (Tier 1: 5 tests; Tier 4: Chromium live flag toggle + patch)
- [x] **F12** — Download Center, Reports & Validated State/Backup (Tier 1: 5 tests; Tier 4: Chromium Download Center & Backup export/import)
- [x] **F13** — Game Library, Consistent Filters & Storage Dashboard (Tier 1: 5 tests; Tier 4: Chromium search/filters & SVG donut)
- [x] **F14** — Control Layout Editor & Virtual Sandbox Preview (Tier 1: 5 tests; Tier 4: Chromium modal reset + HiDPI canvas sandbox)
- [x] **F15** — Production Static Assets & WCAG 2.1 AA Accessibility (Tier 1: 5 tests; Tier 4: 100% offline guard + ARIA/Escape/focus restore)
- [x] **F16** — Container Hardening, Documentation & Release Packaging (Tier 1: 5 tests; Tier 4: standalone extracted release zip live boot & sign; Tier 5: packaging hardening)
- [x] **F17 / F18** — Opaque-Box E2E Tiers 1–4 + Tier 5 Adversarial Hardening (all 8 surgical fixes proven + TCP RST + symlink + secret isolation + v5.3.1 immutability)
