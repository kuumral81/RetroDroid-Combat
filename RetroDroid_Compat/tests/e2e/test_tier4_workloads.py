"""Opaque-box E2E Tier 4 Real-World Multi-Feature Workload & Live Chromium UI Tests (10 tests).

Includes:
- 4 multi-feature end-to-end API/CLI workloads (concurrency + non-blocking /health, full restart
  durability, degraded keystore recovery, and standalone extracted release-zip boot + sign).
- 6 live headless Chromium Playwright browser UI E2E tests (100% offline — every non-localhost
  network request is aborted, asserting zero ``pageerror``, zero XSS execution, and real browser
  download verification via ``apksigner`` & ``aapt``).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import time
import urllib.parse
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from playwright.sync_api import Browser, Page, Route, sync_playwright

from tests.e2e.conftest import (
    PYTHON_EXE,
    REPO_ROOT,
    LiveServer,
    _clean_env,
    _find_free_port,
    upload_via_analyze,
    upload_via_chunks,
)
from tests.e2e.fixtures_apk import (
    E2ECorpus,
    verify_apk_with_aapt,
    verify_apk_with_apksigner,
    verify_apk_with_zipalign,
    verify_apk_xmltree,
)

os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/ms-playwright")


@pytest.fixture(scope="module")
def chromium_browser() -> Iterator[Browser]:
    """Single headless Chromium browser reused across Tier 4 browser workload tests."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-proxy-server"])
        try:
            yield browser
        finally:
            browser.close()


def _attach_offline_guard(page: Page) -> list[str]:
    """Abort any non-localhost network request to prove 100% offline capability."""
    blocked: list[str] = []

    def _handle_route(route: Route) -> None:
        parsed = urllib.parse.urlparse(route.request.url)
        if parsed.scheme in ("data", "blob") or parsed.hostname in ("127.0.0.1", "localhost"):
            route.continue_()
        else:
            blocked.append(route.request.url)
            route.abort("blockedbyclient")

    page.route("**/*", _handle_route)
    return blocked


# ===========================================================================
# API & Standalone Release Workloads (4 tests)
# ===========================================================================


def test_t4_workload_multi_game_concurrent_pipeline_with_nonblocking_health(
    live_server: LiveServer,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    """Analyze 3 games, patch 2 concurrently while hammering /health (<200ms), then CLI-verify all."""
    with live_server.client() as c:
        an_leg = upload_via_analyze(c, apk_corpus.legacy_apk)
        an_xapk = upload_via_analyze(c, apk_corpus.xapk_v2)
        an_apkm = upload_via_analyze(c, apk_corpus.apkm_bundle)

    def _patch_job(jid: str, sdk: str) -> dict[str, Any]:
        with live_server.client() as c:
            r = c.post(
                "/api/patch-sign",
                data={"jobId": jid, "targetSdk": sdk, "addLegacyStorage": "true", "resign": "true"},
            )
            assert r.status_code == 200, r.text
            return r.json()

    health_latencies: list[float] = []

    def _hammer_health() -> None:
        with live_server.client(timeout=10.0) as c:
            for _ in range(8):
                t0 = time.perf_counter()
                r = c.get("/health")
                health_latencies.append((time.perf_counter() - t0) * 1000.0)
                assert r.status_code == 200
                time.sleep(0.05)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_leg = pool.submit(_patch_job, an_leg["jobId"], "28")
        f_xapk = pool.submit(_patch_job, an_xapk["jobId"], "34")
        f_health = pool.submit(_hammer_health)
        res_leg = f_leg.result()
        res_xapk = f_xapk.result()
        f_health.result()

    assert max(health_latencies) < 200.0, f"/health latency spike: {health_latencies}"

    # Also patch third game (APKM) and build Full XAPK for XAPK job
    res_apkm = _patch_job(an_apkm["jobId"], "28")

    with live_server.client() as c:
        use_16k = bool(c.get("/health").json().get("zipalign16kSupported"))
        for label, res, expected_sdk in (
            ("legacy", res_leg, 28),
            ("xapk", res_xapk, 34),
            ("apkm", res_apkm, 28),
        ):
            out = tmp_path / f"{label}_verified.apk"
            out.write_bytes(c.get(res["downloadUrl"]).content)
            assert verify_apk_with_aapt(out)["targetSdk"] == expected_sdk
            ok_al, msg_al = verify_apk_with_zipalign(out, page_16k=use_16k)
            assert ok_al, f"{label}: {msg_al}"
            ok_sig, msg_sig = verify_apk_with_apksigner(out)
            assert ok_sig, f"{label}: {msg_sig}"

        rx = c.post(f"/api/full-xapk/{an_xapk['jobId']}")
        assert rx.status_code == 200


def test_t4_workload_full_lifecycle_restart_durability_and_cleanup(
    server_factory: Any,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    """Chunked XAPK upload -> patch -> attach extra OBB -> server restart -> Full XAPK -> CLI verify -> delete."""
    shared_work = tmp_path / "lifecycle_work"
    shared_ks = tmp_path / "lifecycle_ks" / "retrodroid.jks"

    srv1 = server_factory(work_dir=shared_work, keystore_path=shared_ks)
    with srv1.client() as c1:
        _, fin = upload_via_chunks(c1, apk_corpus.xapk_v2, chunk_size=4096)
        jid = fin["jobId"]
        rp = c1.post(
            "/api/patch-sign",
            data={"jobId": jid, "targetSdk": "34", "addNotchSupport": "true"},
        )
        assert rp.status_code == 200
        dl_url = rp.json()["downloadUrl"]
        assert (
            c1.post(
                f"/api/attach-obb/{jid}",
                files=[("files", ("patch.42.com.retro.xapkgame.obb", apk_corpus.obb_patch.read_bytes(), "application/octet-stream"))],
            ).status_code
            == 200
        )
    srv1.stop()

    srv2 = server_factory(work_dir=shared_work, keystore_path=shared_ks)
    with srv2.client() as c2:
        rx = c2.post(f"/api/full-xapk/{jid}")
        assert rx.status_code == 200
        xapk_path = tmp_path / "restarted_full.xapk"
        xapk_path.write_bytes(c2.get(f"/api/download-full-xapk/{jid}").content)
        apk_path = tmp_path / "restarted_signed.apk"
        apk_path.write_bytes(c2.get(dl_url).content)
        assert verify_apk_with_aapt(apk_path)["targetSdk"] == 34
        ok_sig, sig_msg = verify_apk_with_apksigner(apk_path)
        assert ok_sig, sig_msg
        with zipfile.ZipFile(xapk_path, "r") as zf:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            assert len(manifest["expansions"]) == 2
        assert c2.delete(f"/api/jobs/{jid}").status_code == 200
        assert not (shared_work / jid).exists()


def test_t4_workload_degraded_keystore_recovery_to_signed_production(
    server_factory: Any,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    """Boot degraded with corrupt JKS -> verify 503 strict health -> reboot with AUTO_REGEN -> full sign."""
    work_dir = tmp_path / "rec_work"
    ks_path = tmp_path / "rec_ks" / "retrodroid.jks"
    ks_path.parent.mkdir(parents=True, exist_ok=True)
    ks_path.write_bytes(b"CORRUPTED_JKS_HEADER")
    os.chmod(ks_path, 0o600)

    srv_deg = server_factory(
        work_dir=work_dir,
        keystore_path=ks_path,
        extra_env={"KEYSTORE_AUTO_REGEN": "false", "KEYSTORE_PASS": "BrokenPass99"},
    )
    with srv_deg.client() as c_deg:
        assert c_deg.get("/health").status_code == 200
        assert c_deg.get("/health?strict=true").status_code == 503
    srv_deg.stop()
    assert ks_path.read_bytes() == b"CORRUPTED_JKS_HEADER"

    srv_rec = server_factory(
        work_dir=work_dir,
        keystore_path=ks_path,
        extra_env={"KEYSTORE_AUTO_REGEN": "true"},
    )
    with srv_rec.client() as c_rec:
        assert c_rec.get("/health?strict=true").status_code == 200
        an = upload_via_analyze(c_rec, apk_corpus.legacy_apk)
        rp = c_rec.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28"})
        assert rp.status_code == 200
        out = tmp_path / "recovered_signed.apk"
        out.write_bytes(c_rec.get(rp.json()["downloadUrl"]).content)
        ok_sig, sig_msg = verify_apk_with_apksigner(out)
        assert ok_sig, sig_msg
    assert len(list(ks_path.parent.glob("retrodroid.jks.bak.*"))) == 1


def test_t4_workload_release_zip_standalone_boot_and_live_patch_sign(
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    """Extract shipped RetroDroid_Compat_v5.4.0.zip, boot standalone uvicorn, patch & verify real APK."""
    release_zip = REPO_ROOT.parent / "RetroDroid_Compat_v5.4.0.zip"
    assert release_zip.is_file()
    extract_dir = tmp_path / "standalone_release"
    with zipfile.ZipFile(release_zip, "r") as zf:
        zf.extractall(extract_dir)
    app_dir = extract_dir / "RetroDroid_Compat_v5.4.0"
    assert (app_dir / "server.py").is_file()

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = _clean_env(
        {
            "PYTHONPATH": str(app_dir),
            "WORK_DIR": str(tmp_path / "standalone_work"),
            "KEYSTORE_PATH": str(tmp_path / "standalone_ks" / "retrodroid.jks"),
            "RATE_LIMIT_PER_MIN": "0",
        }
    )
    proc = subprocess.Popen(
        [PYTHON_EXE, "-B", "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(app_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 25.0
        with httpx.Client(base_url=base_url, trust_env=False, timeout=60.0) as c:
            while time.monotonic() < deadline:
                try:
                    if c.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            else:
                raise AssertionError("Standalone release zip server failed to start")

            assert c.get("/").status_code == 200
            assert c.get("/static/app.js").status_code == 200
            an = upload_via_analyze(c, apk_corpus.legacy_apk)
            rp = c.post("/api/patch-sign", data={"jobId": an["jobId"], "targetSdk": "28"})
            assert rp.status_code == 200
            out = tmp_path / "standalone_signed.apk"
            out.write_bytes(c.get(rp.json()["downloadUrl"]).content)
            ok_sig, sig_msg = verify_apk_with_apksigner(out)
            assert ok_sig, sig_msg
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ===========================================================================
# Live Headless Chromium Playwright Browser UI E2E Scenarios (6 tests)
# ===========================================================================


def test_t4_browser_offline_xss_upload_patch_and_apksigner_verify(
    chromium_browser: Browser,
    live_server: LiveServer,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    """100% offline Chromium E2E: upload XSS APK -> 0 XSS -> toggle flags -> patch -> browser download -> apksigner."""
    context = chromium_browser.new_context(accept_downloads=True)
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    blocked_external = _attach_offline_guard(page)

    try:
        page.goto(live_server.base_url, wait_until="networkidle")
        page.click("#nav-tab-patcher")
        page.wait_for_selector("#render-status-text")

        # Upload XSS-labeled APK through real <input type="file">
        page.set_input_files("#file-input", str(apk_corpus.xss_label_apk))
        page.wait_for_selector("#selected-package-card:not(.hidden)", timeout=30000)
        page.wait_for_function(
            "() => document.getElementById('pkg-name')?.textContent?.includes('XSS Game')",
            timeout=30000,
        )

        # Verify ZERO XSS execution and literal escaped label rendering
        assert page.evaluate("() => window.__XSS_FIRED === undefined") is True
        assert "<img" in page.locator("#pkg-name").inner_text()

        # Enable real server manifest patch flags (sr-only custom toggle inputs inside <label>)
        page.locator("#flag-legacy-storage").check(force=True)
        page.locator("#flag-cleartext").check(force=True)
        page.locator("#flag-notch-support").check(force=True)

        # Trigger live server patch + sign
        page.click("#btn-start-patch")
        page.wait_for_selector("#patch-complete-actions:not(.hidden)", timeout=60000)

        # Open Download Center modal and download signed APK through browser download event
        page.click("#btn-download-patched-pkg")
        page.wait_for_selector("#modal-download-package:not(.hidden)", timeout=10000)
        dl_btn = page.locator("#dl-options-list button.rd-dl-option").first
        dl_btn.wait_for(state="visible", timeout=10000)
        with page.expect_download(timeout=30000) as dl_info:
            dl_btn.click()
        download = dl_info.value
        saved_apk = tmp_path / download.suggested_filename
        download.save_as(str(saved_apk))

        assert saved_apk.is_file() and saved_apk.stat().st_size > 1000
        ok_sig, sig_msg = verify_apk_with_apksigner(saved_apk)
        assert ok_sig, sig_msg
        tree = verify_apk_xmltree(saved_apk)
        assert "requestLegacyExternalStorage" in tree
        assert "usesCleartextTraffic" in tree
        assert "android.max_aspect" in tree

        assert page.evaluate("() => window.__XSS_FIRED === undefined") is True
        assert page_errors == [], f"Unexpected browser pageerror: {page_errors}"
        assert blocked_external == [], f"External non-localhost network requests attempted: {blocked_external}"
    finally:
        context.close()


def test_t4_browser_obb_upload_and_per_game_isolation_with_full_xapk(
    chromium_browser: Browser,
    live_server: LiveServer,
    apk_corpus: E2ECorpus,
    tmp_path: Path,
) -> None:
    """Chromium E2E: upload APK -> patch -> attach OBB -> download Full XAPK -> verify demo card has no OBB leak."""
    context = chromium_browser.new_context(accept_downloads=True)
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    blocked_external = _attach_offline_guard(page)

    try:
        page.goto(live_server.base_url, wait_until="networkidle")
        page.click("#nav-tab-patcher")
        page.set_input_files("#file-input", str(apk_corpus.legacy_apk))
        page.wait_for_function(
            "() => document.getElementById('pkg-name')?.textContent?.includes('Legacy Quest')",
            timeout=30000,
        )

        # Patch APK first
        page.click("#btn-start-patch")
        page.wait_for_selector("#patch-complete-actions:not(.hidden)", timeout=60000)

        # Attach OBB via mobile-compatible file input and upload to active job
        page.set_input_files("#obb-files-input", str(apk_corpus.obb_main))
        page.wait_for_function(
            "() => !document.getElementById('btn-upload-obb-folder')?.disabled",
            timeout=10000,
        )
        page.click("#btn-upload-obb-folder")
        page.wait_for_selector("#btn-download-full-xapk:not(.hidden)", timeout=30000)

        with page.expect_download(timeout=45000) as dl_info:
            page.click("#btn-download-full-xapk")
        xapk_dl = tmp_path / dl_info.value.suggested_filename
        dl_info.value.save_as(str(xapk_dl))
        with zipfile.ZipFile(xapk_path := xapk_dl, "r") as zf:
            assert "manifest.json" in zf.namelist()
            assert any(n.endswith(".obb") for n in zf.namelist())
        assert xapk_path.stat().st_size > 1000

        # Switch to a built-in Demo package and confirm OBB count does NOT leak from the uploaded game
        page.locator("#demo-packages-grid button").first.click()
        page.wait_for_function(
            "() => (document.getElementById('obb-folder-count')?.textContent || '').trim().startsWith('0')",
            timeout=10000,
        )

        assert page_errors == [], page_errors
        assert blocked_external == [], blocked_external
    finally:
        context.close()


def test_t4_browser_backup_export_reset_and_reimport_state(
    chromium_browser: Browser,
    live_server: LiveServer,
    tmp_path: Path,
) -> None:
    """Chromium E2E: export JSON backup on System tab, inspect schema, modify, and re-import cleanly."""
    context = chromium_browser.new_context(accept_downloads=True)
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    blocked_external = _attach_offline_guard(page)

    try:
        page.goto(live_server.base_url, wait_until="networkidle")
        page.click("#nav-tab-system")
        page.wait_for_selector("#donut-xapk")

        with page.expect_download(timeout=15000) as dl_info:
            page.click("#btn-export-backup")
        backup_path = tmp_path / dl_info.value.suggested_filename
        dl_info.value.save_as(str(backup_path))

        payload = json.loads(backup_path.read_text(encoding="utf-8"))
        assert payload["app"] == "RetroDroid Compat"
        assert payload["version"] == "5.4.0"
        assert isinstance(payload["state"]["games"], list)

        # Mutate cacheMB in backup and re-import via #backup-file-input
        payload["state"]["cacheMB"] = 512
        edited_backup = tmp_path / "edited_backup.json"
        edited_backup.write_text(json.dumps(payload), encoding="utf-8")
        page.set_input_files("#backup-file-input", str(edited_backup))
        page.wait_for_function(
            "() => (document.getElementById('storage-cache-val')?.textContent || '').includes('512')",
            timeout=10000,
        )

        assert page_errors == [], page_errors
        assert blocked_external == [], blocked_external
    finally:
        context.close()


def test_t4_browser_modal_accessibility_keyboard_escape_and_focus_restore(
    chromium_browser: Browser,
    live_server: LiveServer,
) -> None:
    """Chromium E2E: nested modals expose ARIA dialog/modal, Reset preserves trigger, Escape restores focus."""
    context = chromium_browser.new_context()
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    blocked_external = _attach_offline_guard(page)

    try:
        page.goto(live_server.base_url, wait_until="networkidle")
        page.click("#nav-tab-library")
        settings_btn = page.locator('#library-grid [data-action="settings"]').first
        settings_btn.click()
        page.wait_for_selector("#modal-game-settings:not(.hidden)")
        assert page.locator("#modal-game-settings").get_attribute("role") == "dialog"
        assert page.locator("#modal-game-settings").get_attribute("aria-modal") == "true"

        page.click("#btn-edit-control-layout")
        page.wait_for_selector("#modal-control-layout:not(.hidden)")

        # Clicking Reset inside nested modal must preserve original triggerEl (#btn-edit-control-layout)
        page.click("#btn-reset-control-layout")
        page.keyboard.press("Escape")
        page.wait_for_selector("#modal-control-layout", state="hidden", timeout=10000)
        assert page.evaluate("() => document.activeElement?.id") == "btn-edit-control-layout"

        page.keyboard.press("Escape")
        page.wait_for_selector("#modal-game-settings", state="hidden", timeout=10000)

        assert page_errors == [], page_errors
        assert blocked_external == [], blocked_external
    finally:
        context.close()


def test_t4_browser_api_token_auth_flow_live(
    chromium_browser: Browser,
    auth_server: LiveServer,
    apk_corpus: E2ECorpus,
) -> None:
    """Chromium E2E against API_TOKEN-protected server: enter token -> keystore info loads -> analyze succeeds."""
    context = chromium_browser.new_context()
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    blocked_external = _attach_offline_guard(page)

    try:
        page.goto(auth_server.base_url, wait_until="networkidle")
        page.click("#nav-tab-patcher")
        page.wait_for_selector("#render-api-token")

        page.fill("#render-api-token", auth_server.api_token)
        page.click("#btn-save-api-token")
        page.click("#btn-check-render")
        page.wait_for_function(
            "() => (document.getElementById('keystore-sha256')?.textContent || '').trim().length >= 32",
            timeout=15000,
        )

        # Now upload & analyze an APK using the saved API token
        page.set_input_files("#file-input", str(apk_corpus.legacy_apk))
        page.wait_for_function(
            "() => document.getElementById('pkg-name')?.textContent?.includes('Legacy Quest')",
            timeout=30000,
        )

        assert page_errors == [], page_errors
        assert blocked_external == [], blocked_external
    finally:
        context.close()


def test_t4_browser_library_filters_search_and_sandbox_preview(
    chromium_browser: Browser,
    live_server: LiveServer,
) -> None:
    """Chromium E2E: filter/search library cards, launch HiDPI sandbox canvas preview, toggle HUD/VPad, exit."""
    context = chromium_browser.new_context()
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    blocked_external = _attach_offline_guard(page)

    try:
        page.goto(live_server.base_url, wait_until="networkidle")
        page.click("#nav-tab-library")
        initial_cards = page.locator('#library-grid [data-action="launch"]').count()
        assert initial_cards >= 2

        page.fill("#library-search", "Flappy")
        page.wait_for_function(
            "() => document.querySelectorAll('#library-grid [data-action=\"launch\"]').length === 1",
            timeout=5000,
        )
        page.fill("#library-search", "")
        page.wait_for_function(
            f"() => document.querySelectorAll('#library-grid [data-action=\"launch\"]').length === {initial_cards}",
            timeout=5000,
        )

        # Launch Virtual Sandbox Preview
        page.locator('#library-grid [data-action="launch"]').first.click()
        page.wait_for_selector("#sandbox-overlay:not(.hidden)", timeout=10000)
        canvas_w = page.evaluate("() => document.getElementById('sandbox-canvas')?.width || 0")
        assert canvas_w > 0

        page.click("#btn-toggle-hud")
        page.click("#btn-toggle-vpad")
        page.click("#btn-exit-sandbox")
        page.wait_for_selector("#sandbox-overlay", state="hidden", timeout=10000)

        assert page_errors == [], page_errors
        assert blocked_external == [], blocked_external
    finally:
        context.close()
