FROM python:3.11-slim-bookworm

# Install headless Java runtime and Android APK analysis/packaging/signing CLI tools
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends \
        default-jre-headless \
        apktool \
        aapt \
        zipalign \
        apksigner \
        android-framework-res \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build-time verification of all 6 required binaries (java, keytool, aapt, apktool, zipalign, apksigner)
RUN command -v java \
    && command -v keytool \
    && command -v aapt \
    && command -v apktool \
    && command -v zipalign \
    && command -v apksigner \
    && java -version \
    && keytool -help >/dev/null \
    && aapt version \
    && apktool --version \
    && apksigner --version \
    && (zipalign 2>&1 || true) | grep -qi "zipalign"

# Do NOT set JAVA_TOOL_OPTIONS globally (retrodroid/config.py applies JAVA_HEAP_MB cleanly per JVM subprocess)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000 \
    WORK_DIR="/tmp/retrodroid_jobs" \
    KEYSTORE_PATH="/var/data/retrodroid.jks" \
    MAX_UPLOAD_MB="5120" \
    MAX_CONCURRENT_PATCHES="1" \
    MAX_ARCHIVE_ENTRIES="25000" \
    JAVA_HEAP_MB="256"

# Create non-root appuser and pre-create writable work/persistent directories
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/appuser --shell /usr/sbin/nologin appuser \
    && install -d -m 0755 -o appuser -g appuser /app /var/data /var/data/jobs /tmp/retrodroid_jobs

WORKDIR /app

COPY --chown=appuser:appuser requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=appuser:appuser server.py index.html README.txt /app/
COPY --chown=appuser:appuser retrodroid/ /app/retrodroid/
COPY --chown=appuser:appuser static/ /app/static/

RUN find /app -type d -exec chmod 0755 {} + \
    && find /app -type f -exec chmod 0644 {} +

USER appuser

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os, sys, urllib.request; r = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f\"http://127.0.0.1:{os.environ.get('PORT') or '10000'}/health\", timeout=4); sys.exit(0 if r.status == 200 else 1)"]

CMD ["sh", "-c", "exec uvicorn server:app --host 0.0.0.0 --port ${PORT:-10000} --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 120"]
