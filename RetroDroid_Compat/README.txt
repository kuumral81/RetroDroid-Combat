RetroDroid Compat — Render & Docker Sunucu Paketi (v5.4.0)
==========================================================

RetroDroid Compat v5.4.0; eski ve modern Android paketlerini (.apk, .xapk,
.apks, .apkm, .zip ve ek .obb verileri) inceleyen, AndroidManifest.xml uyumluluk
yamaları uygulayan, hizalayan (zipalign 4 KB / 16 KB), v1+v2+v3 şemalarıyla
yeniden imzalayan (apksigner) ve standart XAPK v2 / APKS paketleri üreten
modüler, Docker ve Render uyumlu tam yığın (full-stack) web uygulamasıdır.

MİMARİ BİLEŞENLER (v5.4.0)
--------------------------
- server.py
  Asenkron FastAPI bileşim kökü (giriş noktası: `uvicorn server:app`). Lifespan
  başlangıç/kapanış yönetimi, güvenlik yanıt başlıkları (X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy), dinamik CORS, IP bazlı
  dakikalık hız sınırı, isteğe bağlı `API_TOKEN` kimlik doğrulaması ve katı
  `/api/download` çıktı izin listesi (allowlist) içerir. Tüm bloklayıcı G/Ç ve
  alt süreç çağrıları `asyncio.to_thread` veya arka plan iş parçacıklarında
  çalıştırılır; olay döngüsü (event loop) bloklanmaz.
- retrodroid/config.py
  Ortam değişkeni tabanlı yapılandırma (`Settings`), güvenli dosya adı temizleme
  (`sanitize_filename`, <=120 karakter), atomik JSON yazımı (`write_json_atomic`),
  JVM `JAVA_TOOL_OPTIONS` stderr gürültüsünü temizleyen alt süreç yürütücüsü
  (`run_cmd`, `JAVA_HEAP_MB`) ve `jobId` korelasyonlu / parola maskelemeli
  yapılandırılmış JSON günlükleme.
- retrodroid/keystore.py
  `fcntl.flock` kilitli RSA-2048 JKS imzalama anahtarı yaşam döngüsü. Parolalar
  komut satırı argümanlarında (`argv`) asla geçirilmez; yalnızca alt süreç ortam
  değişkeni (`RD_KS_PASS` -> `-storepass:env` / `--ks-pass env:`) ile iletilir.
  Atomik `0o600` dosya izinleri, her başlangıçta zorunlu `keytool -list -v`
  doğrulaması ve yıkıcı olmayan (non-destructive) anahtar kurtarma sağlar.
- retrodroid/axml.py
  Sıkı başlık/öznitelik sınır kontrollerine ve `Res_value.dataType` (`0x10` /
  `0x11`) doğrulamasına sahip ikili (binary) AXML ayrıştırıcısı. StringPool
  üzerinden yalnızca `<uses-sdk>` etiketini hedefler ve `minSdkVersion` tabanını
  koruyarak sessiz sürüm düşürmeyi engeller.
- retrodroid/inspector.py
  Tek geçişli ZIP + `aapt dump badging` APK müfettişi: kök dizin `classes*.dex`
  analizi, kesme işareti güvenli uygulama adı, `armeabi`/`mips` dahil tam ve
  split ABI birleştirme, saf Python ELF64 16 KB bellek sayfası (`PT_LOAD`
  `p_align >= 16384`) hizalama denetimi, `resources.arsc` sıkıştırma kontrolü,
  API 31+ eksik `android:exported` bileşen sayımı, Android 14 (API 23) ve
  Android 15–17 (API 24+) kurulum tabanı kararı ve 0–100 uyumluluk puanı.
- retrodroid/patcher.py
  Slim-`apktool` manifest XML yamacısı, güvenli `apktool.yml` YAML güncelleyicisi,
  büyük/küçük harf duyarsız `META-INF` (`STAMP-CERT-SHA256` dahil) temizleyen ve
  `resources.arsc` ile `*.so` girdilerini `ZIP_STORED` olarak yazan akışlı APK
  yeniden yazıcısı, `zipalign` (`-P 16` otomatik algılama veya `-p 4`),
  `apksigner` v1+v2+v3 imzalama ve split `.apks` paketleme hattı.
- retrodroid/containers.py
  Standart uyumlu `.xapk` (`manifest.json`) ve `.apkm` (`info.json`) açıcı,
  Windows `\` yol normalizasyonu, zip-slip / şifreli girdi / ZIP bombası /
  çakışma korumaları, izole `_extracted/` çıkarımı, çift iç içe geçmeyi önleyen
  OBB yol normalizasyonu (`(main|patch).<ver>.<pkg>.obb`) ve ZIP64 atomik XAPK v2
  (`total_size`, `permissions`, `icon.png`, `split_apks`, `expansions`) üreticisi.
- retrodroid/jobs.py
  Referans sayaçlı aktif iş takibi (`ACTIVE_JOBS`), iş bazlı kilitler, yeniden
  başlatmalarda korunan atomik `job_state.json`, alt süreç (`Popen`) iptal kaydı,
  `.last_activity` kalp atışı ve aktif işleri koruyan TTL / düşük disk temizliği.
- index.html, static/styles.css, static/app.js, static/vendor/jszip.js
  Çevrimdışı çalışabilen, XSS-güvenli (sıfır satır içi `onclick` metin ekleme),
  WCAG 2.1 AA erişilebilirlik uyumlu tek sayfa arayüzü (SPA), kaldığı yerden
  devam edebilen parçalı yükleme (resumable upload) ve yerel JSZip kütüphanesi.

DESTEKLENEN DOSYA BİÇİMLERİ
---------------------------
- .apk  : Tekil Android uygulama paketi
- .xapk : Base APK + split APK + OBB içeren XAPK kapsayıcısı
- .apks : Split APK seti arşivi
- .apkm : APKMirror paket kapsayıcısı (`info.json` destekli)
- .zip  : İçinde APK ve/veya OBB bulunan arşiv
- .obb  : Mevcut bir işe tekli veya parçalı olarak eklenebilen genişletme dosyası

GERÇEK SUNUCU YAMALARI VE WEB ÖNİZLEME AYRIMI (ÖNEMLİ SINIRLAMALAR)
-------------------------------------------------------------------
1. Gerçek Sunucu APK Yamaları (`/api/patch-sign`):
   - `patchTargetSdk` (`targetSdkVersion` oluşturma veya API 24–36 aralığına yükseltme;
     `allowDowngrade=false` iken yüksek `targetSdk` düşürülmez ve `minSdk` altına inmez)
   - API 31+ (Android 12+) `<intent-filter>` içeren bileşenlere eksik `android:exported="true"` ekleme
   - `addLegacyStorage` (`android:requestLegacyExternalStorage="true"`)
   - `enableCleartext` (`android:usesCleartextTraffic="true"`)
   - `addNotchSupport` (`android:resizeableActivity="true"` ve `android.max_aspect=2.4`)
   - `forceExtractNativeLibs` (`android:extractNativeLibs="true"`)
   - `zipalign` (`-P 16` destekleniyorsa 16 KB, aksi halde `-p 4` hizalama) ve
     `apksigner` ile v1+v2+v3 yeniden imzalama, split `.apks` ve Tam XAPK v2 + OBB üretimi.
2. Web Önizleme / Sanal Kutu (Sandbox) Profil Ayarları:
   - Arayüzdeki sanal kontrol düzeni düzenleyicisi, ekran oranı, çözünürlük ve FPS
     profilleri YALNIZCA tarayıcı içi görsel önizleme / simülasyon katmanıdır.
   - Bu proje 32-bit ARM -> 64-bit ARM (`ARM32 -> ARM64`) ikili JIT çevirisi YAPMAZ,
     OpenGL ES -> Vulkan grafik/shader çevirisi YAPMAZ ve tarayıcıda gerçek bir
     Android işletim sistemi veya native APK çalışma zamanı (emulator) ÇALIŞTIRMAZ.
3. Android 14 / 15–17 Kurulum Tabanı ve 16 KB Bellek Sayfası Tanılaması:
   - Android 14 (API 34) `targetSdkVersion < 23` olan APK'ların kurulumunu engeller;
     Android 15–17 (API 35–36+) ise kurulum tabanını `targetSdkVersion >= 24`
     seviyesine yükseltir (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`).
   - Müfettiş, `lib/arm64-v8a/*.so` ve `lib/x86_64/*.so` dosyalarındaki ELF64
     `PT_LOAD` segmentlerinin `p_align >= 16384` (16 KB) hizalamasını denetler.
     `zipalign -P 16` ZIP girdi hizalamasını düzeltir; ancak 4 KB sayfa boyutuyla
     derlenmiş native `.so` kütüphanelerinin Android 15+ 16 KB çekirdeklerde
     çalışması için geliştirici tarafından NDK ile yeniden derlenmesi gerekebilir.
4. Yeniden İmzalama ve Kaynak Sınırları:
   - Yeniden imzalama orijinal geliştirici imzasını değiştirir; cihazda yüklü
     orijinal sürümün kaldırılması gerekebilir.
   - `MAX_UPLOAD_MB=5120` uygulama sınırıdır; barındırma planınızın RAM ve disk
     kapasitesini artırmaz. Çok GB'lık paketler için kalıcı disk kullanın.

ORTAM DEĞİŞKENLERİ (`retrodroid/config.py`)
-------------------------------------------
- `PORT`
  Sunucu HTTP dinleme portu (Docker/Render varsayılanı: `10000`).
- `WORK_DIR`
  Yükleme, arşiv açma ve yamalama iş dizini (varsayılan: `/tmp/retrodroid_jobs`).
- `KEYSTORE_PATH`
  İmzalama anahtarı birincil yolu (varsayılan: `/var/data/retrodroid.jks`).
  Birincil dizin yazılamazsa otomatik olarak `<WORK_DIR>/_keystore/retrodroid.jks`
  (varsayılan `WORK_DIR` ile `/tmp/retrodroid_jobs/_keystore/retrodroid.jks`)
  yoluna geri döner.
- `KEYSTORE_PASS`
  Keystore parolası (varsayılan: `""`). Boş bırakılırsa `<KEYSTORE_PATH>.pass`
  dosyasından okunur veya ilk kurulumda kriptografik olarak üretilip `0o600`
  izinle kaydedilir. Ayarlanırsa en az 6 karakter olmalıdır.
- `KEYSTORE_ALIAS`
  Keystore içindeki özel anahtar takma adı (varsayılan: `retrodroid`).
- `KEYSTORE_AUTO_REGEN`
  Mevcut keystore doğrulanamazsa veya parolası eksik/uyumsuzsa anahtarı
  `<KEYSTORE_PATH>.bak.<zaman_damgası>` olarak yedekleyip yeni anahtar üretme
  izni (varsayılan: `false`). `false` iken mevcut keystore asla silinmez.
- `MAX_UPLOAD_MB`
  Azami yükleme boyutu, MB cinsinden (varsayılan: `5120`).
- `CHUNK_SIZE_MB`
  Parçalı yükleme parça boyutu, MB cinsinden (varsayılan: `8`).
- `JOB_TTL_SECONDS`
  Tamamlanan işlerin diskte saklanma süresi, saniye cinsinden (varsayılan: `3600`).
- `DISK_FREE_FLOOR_MB`
  Düşük disk temizliği için asgari boş alan eşiği, MB (varsayılan: `1500`).
- `MAX_CONCURRENT_PATCHES`
  Aynı anda çalışabilecek ağır APK yamalama iş sayısı (varsayılan: `1`).
- `MAX_ARCHIVE_ENTRIES`
  Arşivlerde izin verilen azami dosya/girdi sayısı (varsayılan: `25000`).
- `MAX_DECOMPRESSED_BYTES`
  Arşiv açma ve APK yeniden yazmada toplam açılmış bayt sınırı
  (varsayılan: `10737418240`, yani 10 GiB).
- `API_TOKEN` (veya `API_ACCESS_TOKEN`)
  `/api/*` uç noktaları için isteğe bağlı erişim anahtarı (varsayılan: `""` —
  boşsa kimlik doğrulama kapalıdır). Ayarlandığında `Authorization: Bearer <token>`,
  `X-API-Token: <token>` veya yalnızca `/api/download*` indirme bağlantılarında
  `?token=<token>` sorgu parametresi doğrulanır.
- `ALLOWED_ORIGINS`
  Virgülle ayrılmış CORS izinli kaynak listesi (varsayılan:
  `http://localhost:8000,http://127.0.0.1:8000,http://localhost:10000,http://127.0.0.1:10000`).
- `RATE_LIMIT_PER_MIN`
  IP başına dakikadaki azami istek sınırı (varsayılan: `120`; `0` devre dışı bırakır).
- `JAVA_HEAP_MB`
  Java araçlarına (`java`, `keytool`, `apktool`, `apksigner`) alt süreç bazında
  verilen azami JVM yığın belleği `-Xmx<MB>m` (varsayılan: `256`).
- `LOG_LEVEL`
  Yapılandırılmış JSON günlük seviyesi (varsayılan: `INFO`).

KEYSTORE GÜVENLİĞİ VE RENDER PERSISTENT DISK KURULUMU
-----------------------------------------------------
1. Birincil ve Geri Dönüş (Fallback) Yolu:
   - Varsayılan birincil yol `/var/data/retrodroid.jks` dosyasıdır.
   - `/var/data` dizini mevcut değilse veya yazılabilir değilse sunucu otomatik
     olarak `<WORK_DIR>/_keystore/retrodroid.jks` (varsayılan ayarlarda
     `/tmp/retrodroid_jobs/_keystore/retrodroid.jks`) yolunu `0o700` dizin ve
     `0o600` dosya izinleriyle kullanır; `/api/keystore-info` yanıtında
     `persistent: false` olarak bildirir. Sağlık uç noktaları açısından
     `GET /health` canlılık (liveness) kontrolü olarak HTTP 200 döndürür
     (`status: "ok"` veya `"degraded"`), `GET /health?strict=true` ise hazırlık
     (readiness) kontrolü olarak bozulmuş (`degraded`) durumda HTTP 503 döndürür.
2. Yıkıcı Olmayan (Non-Destructive) Başlangıç Doğrulaması:
   - Mevcut `.jks` dosyası her açılışta `keytool -list -v` ile doğrulanır.
   - Parola eksikse veya doğrulama başarısız olursa mevcut keystore ASLA sessizce
     silinmez (`keystoreReady: false` durumuna geçer). Yalnızca
     `KEYSTORE_AUTO_REGEN=true` açıkça verildiğinde bozuk dosya
     `retrodroid.jks.bak.<ts>` adıyla yedeklenir ve yeni RSA-2048 anahtar üretilir.
3. Render Persistent Disk Yapılandırması (Önerilen):
   - Render Web Service (Docker runtime) üzerinde Persistent Disk ekleyin ve
     bağlama noktasını `mountPath: /var/data` olarak ayarlayın.
   - Hem imza kimliğinin korunması hem de büyük yükleme/yamalama dosyalarının
     geçici konteyner belleği yerine kalıcı diske yazılması için şu iki ortam
     değişkenini birlikte tanımlayın:
       KEYSTORE_PATH=/var/data/retrodroid.jks
       WORK_DIR=/var/data/jobs
   - İsteğe bağlı olarak güçlü bir `KEYSTORE_PASS` (en az 6 karakter) ve herkese
     açık dağıtımlarda `API_TOKEN` tanımlayın.

TEK WORKER (SINGLE-WORKER) DAĞITIM KURALI
-----------------------------------------
`uvicorn` sunucusu mutlaka **tek worker** (`--workers 1` / varsayılan tek süreç)
olarak çalıştırılmalıdır. `JobManager` aktif iş referans sayaçları (`ACTIVE_JOBS`),
iş kilitleri, alt süreç iptal kayıtları (`Popen`) ve IP hız sınırı sayaçları
süreç içi (in-process) bellekte yönetilir; çoklu worker (`--workers > 1`)
kullanımı iş kilitlerinin ve eşzamanlılık sınırlarının süreçler arasında
bölünmesine yol açar.

HTTP REST API UÇ NOKTALARI
--------------------------
- `GET    /`                                    : SPA web arayüzü (`index.html`)
- `GET    /static/{asset_path}`                 : Statik CSS/JS/vendor dosyaları
- `GET    /health` (`?strict=true` destekli)    : Sunucu, disk, araç ve keystore sağlığı
- `GET    /api/keystore-info`                   : Genel keystore sertifika özeti (SHA-256)
- `POST   /api/upload/init`                     : Parçalı yükleme oturumu başlatma / sürdürme
- `GET    /api/upload/status/{job_id}`          : Alınan ve eksik parçaları sorgulama
- `POST   /api/upload/chunk`                    : Tekil dosya parçası yükleme
- `POST   /api/upload/finish`                   : Yüklemeyi birleştirme, açma ve APK analizi
- `POST   /api/analyze`                         : Tek istekte doğrudan dosya yükleme ve analiz
- `POST   /api/patch-sign`                      : Senkron veya arka planda manifest yama + imza
- `GET    /api/patch-status/{job_id}`           : Yamalama ilerleme durumu, loglar ve sonuç
- `POST   /api/patch-cancel/{job_id}`           : Çalışan yamalama / alt süreci iptal etme
- `GET    /api/jobs`                            : Mevcut iş geçmişi ve kalan TTL süreleri
- `DELETE /api/jobs/{job_id}`                   : İşi ve diskteki geçici dosyalarını silme
- `POST   /api/attach-obb/{job_id}`             : İşe çoklu `.obb` ekleme (`/init`, `/chunk`, `/finish` parçalı uç noktaları dahil)
- `POST   /api/full-xapk/{job_id}`              : İmzalı base/split APK + OBB ile Tam XAPK v2 üretimi
- `GET    /api/full-xapk-status/{job_id}`       : Arka plan Tam XAPK üretim durumu
- `GET    /api/download-full-xapk/{job_id}`     : Üretilen Tam XAPK v2 paketini indirme
- `GET    /api/download/{job_id}/{filename}`    : Yalnızca izin listesindeki çıktı paketini indirme
- `GET    /api/download-obb/{job_id}/{obb_index}`: Konteyner içindeki OBB dosyasını atomik indirme

YEREL GELİŞTİRME, DOCKER VE SÜRÜM PAKETLEME
-------------------------------------------
1. Yerel Çalıştırma (Python 3.11+ ve Android CLI araçları kurulu ortamda):
     python3 -m venv .venv
     ./.venv/bin/pip install -r requirements.txt
     ./.venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000

2. Docker ile Derleme ve Çalıştırma (Debian 12 bookworm, root olmayan `appuser`):
     docker build -t retrodroid-compat:5.4.0 .
     docker run --rm -p 10000:10000 \
       -e WORK_DIR=/var/data/jobs \
       -e KEYSTORE_PATH=/var/data/retrodroid.jks \
       retrodroid-compat:5.4.0

3. Deterministik Dağıtım Arşivi Üretimi (`RetroDroid_Compat_v5.4.0.zip`):
     ./.venv/bin/python scripts/build_release_zip.py \
       --root . \
       --output ../RetroDroid_Compat_v5.4.0.zip
