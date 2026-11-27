# RetroDroid Compat v5.4.0 — E2E Test Infrastructure (`TEST_INFRA.md`)

## Overview
Independent opaque-box (Tiers 1–4) and white-box adversarial hardening (Tier 5) end-to-end test infrastructure for **RetroDroid Compat v5.4.0** (`/home/antigravity/RetroDroid_Compat/tests/e2e/`).

All E2E tests execute against **real live `uvicorn server:app` subprocesses**, **real Android CLI tools** (`aapt`, `apktool`, `zipalign`, `apksigner`, `keytool`, `java`), and **real headless Chromium** via Playwright (`PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright`) with all non-localhost network traffic aborted to prove 100% offline capability.

## Canonical Runner Command
```bash
bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier all
```
Per-tier execution:
- `bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier 1` — Feature coverage (`F01`–`F16`)
- `bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier 2` — Boundary, corner & negative/error-handling
- `bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier 3` — Pairwise cross-feature interactions
- `bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier 4` — Real-world multi-feature API workloads & offline Chromium UI E2E
- `bash /home/antigravity/RetroDroid_Compat/tests/e2e/run_e2e.sh --tier 5` — White-box adversarial hardening & surgical regression probes

## Infrastructure Modules
1. **`tests/e2e/fixtures_apk.py`**:
   - Compiles genuine Android APKs on-the-fly with real `aapt package` against `/usr/share/android-framework-res/framework-res.apk` and signs fixtures via real `keytool`/`apksigner`.
   - Builds session-cached synthetic corpus (`E2ECorpus`): legacy APK (`minSdk=19, targetSdk=21`, apostrophe label), API 31+ unexported activity/receiver APK, modern `targetSdk=34` APK, missing-`<uses-sdk>` APK, valid 16 KB ELF64 (`p_align=16384`) & legacy 4 KB ELF64 (`p_align=4096`) `.so` APKs, 32-bit-only `armeabi-v7a` APK, compressed `resources.arsc` + fake `META-INF` APK, multi-DEX APK (3 root DEX + nested `assets/classes9.dex`), XSS-labeled APK, XAPK v2 (splits + OBB + `manifest.json` + `icon.png`, plus Windows backslash variant), APKM (`info.json`), APKS bundle, plain ZIP containers, and negative/hostile payloads (corrupt AXML, zip-slip, encrypted ZIP, missing manifest, duplicate APK names, garbage, 0-byte).
   - Provides real CLI output verifiers (`verify_apk_with_aapt`, `verify_apk_xmltree`, `verify_apk_with_zipalign`, `verify_apk_with_apksigner`).
2. **`tests/e2e/conftest.py`**:
   - Manages isolated live `uvicorn server:app` subprocess fixtures (`live_server`, `auth_server`, `degraded_server`, `server_factory`) with ephemeral TCP ports, isolated `WORK_DIR` & `KEYSTORE_PATH`, proxy-stripped environment (`trust_env=False` in `httpx.Client` to avoid `NO_PROXY` IPv6 bracket parsing issues), and clean `SIGTERM` teardown.
3. **`tests/e2e/run_e2e.sh`**:
   - Self-contained bash runner enforcing `PYTHONDONTWRITEBYTECODE=1`, isolated temporary `PYTHONPYCACHEPREFIX` and `pytest --basetemp` (auto-deleted via `trap EXIT`), `pytest -p no:cacheprovider`, and `PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright`.

## Runtime & Environment Requirements
- Python 3.12 venv: `/home/antigravity/RetroDroid_Compat/.venv/bin/python` (`pytest`, `httpx`, `playwright`, `anyio`, `uvicorn`, `fastapi`)
- Android toolchain: `/usr/bin/aapt`, `/usr/bin/apktool`, `/usr/bin/zipalign`, `/usr/bin/apksigner`, `/usr/bin/keytool`, `/usr/bin/java`, `/usr/share/android-framework-res/framework-res.apk`
- Node.js (`node`) for direct ES module frontend unit & Tier 5 coercion checks
- Playwright Chromium browser binaries at `/opt/ms-playwright`
