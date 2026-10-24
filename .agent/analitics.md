# Analisis Komprehensif Kerentanan PHP2Shell (CVE-2026-109618 & CVE-2026-109619) & Integrasi Standar Keamanan OWASP, Security-Hardening, dan Server-Hardening

> **Dokumen Intelijen Keamanan, Panduan Remediasi, Server Hardening & Standar Audit OWASP**  
> **Terakhir Diperbarui:** 24 Oktober 2026  
> **Status:** Analisis Teknis Pasif & Defensif  
> **Tingkat Keparahan:** Kritis (CVSS v3.x: **9.8** / CVSS v4.0: **9.2**)  
> **Klasifikasi Otoritas Nasional:** TLP Level Clear (Badan Siber dan Sandi Negara / ID-SIRTII)

---

## 1. Ringkasan Eksekutif & Klasifikasi Ancaman

Pada tanggal 21–22 Oktober 2026, komunitas keamanan siber global dan Badan Siber dan Sandi Negara (BSSN) melalui ID-SIRTII/CC menerbitkan Security Advisory darurat terkait dua kerentanan *Remote Code Execution* (RCE) tingkat kritis pada interpreter inti (*core*) PHP:
* **CVE-2026-109618**: RCE via *Out-Of-Memory* (OOM) Bailout / Memory Corruption.
* **CVE-2026-109619**: RCE via *Stale Global State* / Heap Use-After-Free (UAF).

### Parameter Penilaian Risiko (BSSN & NVD):
* **Skor Keparahan:** **9.8 Critical (CVSS 3.x)** / **9.2 Critical (CVSS 4.0)**
* **Vektor Eksploitasi:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Jarak jauh, tanpa autentikasi, kompleksitas rendah, tanpa interaksi pengguna, dampak maksimal terhadap kerahasiaan, integritas, dan ketersediaan).
* **Klasifikasi Kelemahan Perangkat Lunak (CWE):**
  * **CWE-1325:** *Improperly Controlled Sequential Memory Allocation* (Pengelolaan alokasi memori berurutan yang tidak tepat saat penanganan kesalahan).
  * **CWE-824:** *Access of Uninitialized Pointer* (Akses pointer yang belum terinisialisasi saat alur eksekusi terinterupsi).
  * **CWE-755:** *Improper Handling of Exceptional Conditions* (Penanganan kondisi eksepsional OOM yang tidak aman).
  * **CWE-416:** *Use After Free* (Penggunaan kembali memori yang telah dibebaskan pada fitur pelacakan unggahan sesi).

---

## 2. Analisis Mekanisme Teknis di Core PHP

### A. CVE-2026-109618 (Zend Engine OOM Bailout / Memory Corruption)
1. **Akar Masalah:** PHP memanfaatkan fungsi `longjmp()` saat menangani kesalahan kehabisan memori (*Out-of-Memory / OOM*), yang secara mendadak menghentikan alur kerja saat ini (*bailout*).
2. **Kondisi Invalid State:** Bila OOM terjadi pada fase inisialisasi request awal (*pre-RINIT*) atau saat parser memproses request multipart berukuran besar dengan hierarki array bertingkat (nested keys), konteks memori request ditinggalkan dalam status setengah teralokasi (*partially initialized*).
3. **Penyimpangan Eksekusi:** Prosedur pembersihan (*cleanup*) atau request berikutnya yang diproses oleh *worker* yang sama memperlakukan alamat memori tidak valid tersebut sebagai pointer sah, memicu kerusakan memori terstruktur (*controlled memory corruption*) yang berakhir pada pengambilalihan kontrol alur eksekusi (RCE).

### B. CVE-2026-109619 (Stale Global State & Heap Use-After-Free)
1. **Akar Masalah:** Terjadi pada subsistem inti PHP yang menangani pelacakan kemajuan unggahan (`session.upload_progress`).
2. **Kondisi Stale Pointers:** Saat terjadi *fatal error* atau interupsi request di tengah jalan, struktur global internal PHP masih menyimpan pointer yang merujuk ke blok memori request yang telah dibebaskan (*freed memory*).
3. **Pemicu UAF:** Request baru yang masuk ke *worker* yang sama membaca atau menulis kembali ke area memori bebas tersebut (*Heap Use-After-Free*). Penyerang dapat mengotori serializer worker (`PS(serializer)`), memanipulasi *hash table*, atau menimpa *function pointer* eksekutor (`EG()`) untuk memanggil fungsi perintah shell (seperti `zif_system`).

---

## 3. Matriks Versi & Status Perbaikan

### A. Versi Upstream Resmi (The PHP Group)

| Cabang PHP | Versi Terancam | Versi Patch Resmi (Fixed) | Catatan |
| :--- | :--- | :--- | :--- |
| **PHP 8.5** | $\le$ 8.5.11 | **8.5.12** | Rilis patch darurat 21 Okt 2026 |
| **PHP 8.4** | $\le$ 8.4.26 | **8.4.27** | Rilis patch darurat 21 Okt 2026 |
| **PHP 8.3** | $\le$ 8.3.35 | **8.3.36** | Rilis patch darurat 21 Okt 2026 |
| **PHP 8.2** | $\le$ 8.2.34 | **8.2.35** | Rilis patch darurat 21 Okt 2026 |
| **PHP 8.1 ke bawah** | Semua rilis | *Tidak ada rilis upstream* | Status EOL (Wajib backport / upgrade) |

---

### B. Versi Distribusi Resmi Ubuntu (Canonical Security Notice)

Canonical telah merilis paket perbaikan resmi (*backported security updates*) untuk seluruh rilis Ubuntu yang didukung, termasuk versi LTS yang upstream-nya sudah berstatus EOL:

| Rilis Ubuntu | Codename | Versi Default | Versi Paket Patch Resmi (Fixed) |
| :--- | :--- | :--- | :--- |
| **Ubuntu 24.04 LTS** | Noble Numbat | PHP 8.3 | **`8.3.6-0ubuntu0.24.04.13`** |
| **Ubuntu 22.04 LTS** | Jammy Jellyfish | PHP 8.1 | **`8.1.2-1ubuntu2.28`** *(Official Canonical Backport)* |
| **Ubuntu 26.04** | Resolute | PHP 8.5 | **`8.5.4-0ubuntu1.5`** |
| **Ubuntu 26.10** | Stonking | PHP 8.5 | **`8.5.9-0ubuntu2.1`** |
| **Ubuntu 20.04 / 18.04** | Focal / Bionic | PHP 7.4 / 7.2 | Tersedia melalui **Ubuntu Pro (ESM)** |

---

## 4. Analisis Ekosistem Repositori & Alat Keamanan

Berdasarkan telaah mendalam terhadap repositori keamanan publik yang beredar:

### 1. `faizaldjau/php2shell-scanner` (Fork dari `assetnote/php2shell-scanner`)
* **Tipe:** Active Network Scanner / Non-Destructive Audit Tool.
* **Metode Audit:** Baseline request (42 bytes) dilanjutkan 3 probe multipart progresif (1 MiB, 8 MiB, 20 MiB) dengan parameter nested keys 62 tingkat (`a[][a][a]...`) via `h11` async.
* **Indikator Kerentanan:** Teks fatal error memory exhausted, differential empty HTTP 500, HTTP 502/503/504 dari proxy, atau HTTP 200 kosong.

### 2. `ikow/php2shell-poc`
* **Tipe:** Exploit Lab & Defensive Ruleset.
* **5 Rantai Serangan:** Chain A (Session injection + LFI), Chain B (UAF `var_destroy` via `/proc/self/mem`), Chain C (Serializer mismatch worker), Chains D & E (Advanced chains).
* **Artefak Deteksi:** Menyediakan 13 rules Suricata, 5 rules Sigma, 7 rules ModSecurity, dan modul Lua Nginx.

### 3. `9bie/php2shell-bypass-aslr-exp`
* **Tipe:** Low-Level Binary Exploit Research (Apache `mod_php` Prefork).
* **Karakteristik Kunci:** Blind exploitation tanpa butuh `display_errors = On` pada default `memory_limit = 128M`, bypass ASLR deterministik, serta teknik *Worker Pinning* menahan 149 koneksi Apache prefork.

### 4. `openai/php2shell-checker`
* **Tipe:** Audit Tool / Agent Skill (Node.js).
* **Fungsi:** Verifikasi versi aman berbasis URL (`phpcheck-url`) atau biner server lokal (`phpcheck-server`) dengan return code terstandar (`0` = OK, `1` = Vulnerable).

### 5. `devploit/php2shell`
* **Tipe:** Calibration & Safe Testing Framework (Python).
* **Fungsi:** Profil offset biner per build OS dan menerapkan *Safety Stop* mencegah server crash saat pengujian.

### 6. `murrez/php2shell`
* **Tipe:** Hybrid Reconnaissance CLI (Python Standard Library murni).
* **Fungsi:** Memadukan audit kelemahan core PHP dengan *Auto-LFI Discovery* untuk otomatis mengeksploitasi session upload poisoning.

---

## 5. Panduan Praktis Khusus Infrastruktur SIPP (Pengadilan)

Pada server aplikasi SIPP di lingkungan Mahkamah Agung / Pengadilan, arsitektur yang beroperasi umumnya terbagi atas:

| Sistem Operasi | Kombinasi Webserver | Tindakan Utama |
| :--- | :--- | :--- |
| **Ubuntu 24.04 LTS** | Nginx + PHP-FPM / Apache | **Patching biner via APT** |
| **Rocky / AlmaLinux (8/9)** | Nginx / Apache + PHP-FPM | **Patching biner via DNF (Remi)** |
| **CentOS 7 (Legacy)** | Apache `mod_php` (PHP 5.6) | **Hardening `php.ini`, WAF & Isolasi Jaringan** |

### Prosedur Hardening Khusus CentOS 7 & PHP 5.6 (Tanpa Patch Biner)
1. **Kunci Konfigurasi `php.ini`:**
   ```ini
   session.upload_progress.enabled = Off
   max_input_nesting_level = 16
   max_input_vars = 1500
   expose_php = Off
   display_errors = Off
   ```
2. **Aktifkan Aturan Pemblokir di ModSecurity Apache:**
   ```apache
   SecRule REQUEST_BODY|ARGS_NAMES "@contains PHP_SESSION_UPLOAD_PROGRESS" \
       "id:2026101,phase:2,deny,status:403,log,msg:'PHP2Shell Exploit Attempt on SIPP Blocked'"
   ```
3. **Konfigurasi Proteksi di Nginx Reverse Proxy (Frontend):**
   ```nginx
   client_max_body_size 50M;
   location / {
       if ($request_body ~* "PHP_SESSION_UPLOAD_PROGRESS") {
           return 403;
       }
       proxy_pass http://ip_backend_sipp:80;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
   }
   ```

---

## 6. Analisis Repositori & Standar Keamanan OWASP

* **`SpiderLabs/owasp-modsecurity-crs` (OWASP Core Rule Set / CRS):** WAF standar industri untuk ModSecurity/Coraza/Nginx. Memeriksa pelanggaran protokol multipart (`REQUEST-920`), deteksi injeksi PHP (`REQUEST-933`), dan penangkal LFI (`REQUEST-930`).
* **`OWASP/Top10`:** Memetakan PHP2Shell ke **A06 (Vulnerable and Outdated Components)**, **A05 (Security Misconfiguration)**, dan **A03 (Injection)**.
* **`ahmed313x/OWASP-Web-Checklist` & `tanprathan/OWASP-Testing-Checklist`:** Berbasis **WSTG v4.2**, memeriksa fingerprinting, direktori backup tertinggal, cookie session, dan sanitasi parameter.
* **`OWASP/OWASPWebGoatPHP`:** Referensi kerentanan kode PHP nyata (insecure upload, type juggling, deserialization flaws).

---

## 7. Pilar Security-Hardening (Prinsip Pertahanan Aplikasi & Kode)

Mengintegrasikan prinsip *Security by Design* dan pola hardening aplikasi:

### A. Three-Tier Boundary System
1. **Always Do (Wajib):**
   * *Input Validation di Boundary:* Seluruh input eksternal divalidasi skemanya (panjang, tipe, enum, format).
   * *Output Encoding:* Seluruh data keluaran di-escape otomatis untuk mencegah XSS.
   * *Parameterized Queries:* Gunakan PDO / prepared statements untuk seluruh query database.
   * *Secure Cookie Attributes:* Seluruh cookie sesi wajib `HttpOnly`, `Secure`, dan `SameSite=Lax` atau `Strict`.
   * *Security Headers:* CSP (`default-src 'self'`), HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
2. **Ask First (Konfirmasi Tim Keamanan):**
   * Perubahan alur autentikasi, penambahan handler upload berkas baru, perubahan CORS, pengubahan rate limiting.
3. **Never Do (Larangan Keras):**
   * Jangan simpan kredensial/rahasia di kode sumber atau commit history.
   * Jangan gunakan `eval()` atau include file dinamis langsung dari input (`include($_GET['page'])`).
   * Jangan mengekspos rincian internal error atau stack trace ke pengguna.

### B. Proteksi Unggahan Berkas (File Upload Safety)
* Selalu validasi *MIME Type* dan *Magic Bytes* (header biner berkas asli), bukan hanya memeriksa ekstensi file.
* Berkas unggahan (seperti putusan perkara PDF pada SIPP) harus disimpan di luar *document root* publik atau di folder dengan opsi `noexec` (tanpa izin eksekusi skrip).

### C. Proteksi Permintaan Sisi Server (SSRF Defense)
* Setiap modul pengambil URL eksternal (misal integrasi API antar-lembaga) harus memvalidasi skema (`https://`), memeriksa allowlist domain tujuan, dan menolak seluruh rentang IP privat/lokal (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`).

---

## 8. Pilar Server-Hardening (Pengerasan Sistem Operasi & Web Server)

Menerapkan pengerasan sistem pada host Ubuntu, Rocky/AlmaLinux, dan CentOS 7:

### A. Web Server Hardening (Apache & Nginx)
1. **Menonaktifkan Banner Versi (Information Disclosure):**
   * *Apache:* `ServerTokens Prod`, `ServerSignature Off`
   * *Nginx:* `server_tokens off;`
   * *PHP:* `expose_php = Off`
2. **Pembatasan Metode HTTP:**
   * Hanya izinkan metode `GET`, `POST`, `HEAD`. Blokir metode berbahaya seperti `TRACE`, `TRACK`, `DELETE`, `PUT`, `OPTIONS` jika tidak digunakan:
     ```apache
     <LimitExcept GET POST HEAD>
         Require all denied
     </LimitExcept>
     ```
3. **Konfigurasi Header Keamanan Baku:**
   ```nginx
   add_header X-Frame-Options "SAMEORIGIN" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-XSS-Protection "1; mode=block" always;
   add_header Referrer-Policy "strict-origin-when-cross-origin" always;
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```
4. **Proteksi Buffer & Request Limiting:**
   * Batasi `client_max_body_size 50M`, `client_body_buffer_size 128k` untuk meredam serangan memory exhaustion.

### B. OS & Runtime Hardening (Linux Host)
1. **Prinsip Hak Akses Minimal (*Least Privilege*):**
   * Pastikan service web server (`www-data` atau `apache`) tidak tergabung dalam grup `sudo` / `wheel`.
   * Kepemilikan file web root (`/var/www/html/`): Direktori dimiliki oleh user admin non-root dengan permission `755` untuk direktori dan `644` untuk file; web server hanya memiliki izin tulis (*write*) pada direktori upload spesifik.
2. **Pengamanan SSH & Akses Jaringan:**
   * Nonaktifkan login root (`PermitRootLogin no`) dan autentikasi password jika memungkinkan (`PasswordAuthentication no`).
   * Pasang firewall lokal (`UFW` di Ubuntu atau `firewalld` di Alma/Rocky/CentOS) dan hanya buka port 80/443 ke publik.

---

## 9. Pilar OWASP Top 10 Testing Methodology (WSTG v4.2)

Daftar uji operasional yang diintegrasikan ke dalam audit:

| ID Kontrol | Nama Pengujian | Indikator Kegagalan Audit |
| :--- | :--- | :--- |
| **WSTG-INFO-02** | Fingerprint Web Server | Server menampilkan versi detail PHP, Apache, atau OS di header. |
| **WSTG-CONF-04** | Backup & Unreferenced Files | Direktori `.git/`, `.env`, `sipp_backup.sql`, `info.php` dapat diakses langsung. |
| **WSTG-CONF-06** | HTTP Methods Testing | Server mengizinkan metode `TRACE` (rawan XST) atau `OPTIONS` terbuka. |
| **WSTG-CONF-07** | Strict-Transport-Security | Situs melayani HTTPS tanpa header HSTS (`Strict-Transport-Security`). |
| **WSTG-SESS-02** | Cookie Security Attributes | Cookie sesi (`PHPSESSID`) tidak memiliki flag `HttpOnly`, `Secure`, atau `SameSite`. |
| **WSTG-INPV-11** | Command Injection Testing | Input rentan memanggil eksekusi biner OS (menjadi jembatan RCE). |
| **WSTG-INPV-12** | Local File Inclusion (LFI) | Parameter halaman (`?page=`) membaca file arbitrary lokal (Chain A PHP2Shell). |
| **WSTG-VULN-01** | Outdated Components (A06) | Versi runtime PHP terdeteksi $\le$ rilis patch aman PHP2Shell. |

---

*Dokumen ini merupakan panduan terpadu intelijen kerentanan, remediasi arsitektur SIPP, serta standar audit OWASP, Security-Hardening, dan Server-Hardening.*
