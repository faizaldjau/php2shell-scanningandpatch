# Proj-PHP2Shell: Cybersecurity Audit, Safe PoC Verification & Automated Hardening Platform
### SIPP Mahkamah Agung Republik Indonesia Edition
*Compliant with Surat Edaran Ditjen Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026*

---

## 📌 Deskripsi Platform

**Proj-PHP2Shell** adalah platform audit keamanan siber, simulasi pengujian penetrasi defensif (*Safe Non-Destructive PoC*), dan otomasi remediasi/hardening yang dirancang khusus untuk mendeteksi kerentanan kritis **PHP2Shell (CVE-2026-109618 & CVE-2026-109619)** serta celah **OWASP Top 10**.

Platform ini dioptimalkan khusus untuk lingkungan infrastruktur peradilan di Indonesia, khususnya **Sistem Informasi Penelusuran Perkara (SIPP)** di Pengadilan Tingkat Pertama dan Tingkat Banding di lingkungan Mahkamah Agung RI, baik yang masih berjalan di atas **CentOS 7 PHP 5.4/5.6 (Legacy EOL)** maupun server modern berbasis **Ubuntu 22.04/24.04 dan AlmaLinux/RHEL**.

---

## 🚀 Fitur Utama

1. **Multi-Engine Web Vulnerability Scanner (Tab 1):**
   * **Assetnote Progressive Memory Fuzzer (`scanner.py`):** Menguji ketahanan alokasi memori Zend Heap terhadap manipulasi multipart form boundary secara bertahap (1 MiB, 8 MiB, 20 MiB).
   * **OpenAI Banner & Build Checker (`phpcheck.js`):** Mengidentifikasi versi PHP, status rilis perbaikan resmi upstream (8.2.35, 8.3.36, 8.4.27, 8.5.12), dan status cabang EOL.
   * **Direct Origin Targeting (Bypass Cloudflare/WAF):** Mengarahkan koneksi pengujian langsung ke IP fisik server origin via cURL `CURLOPT_RESOLVE`, soket Python, dan Node.js SNI, melewati masking dan respon filter Cloudflare HTTP 403.
   * **OWASP Top 10 Baseline Audit:** Memeriksa keberadaan header keamanan (`CSP`, `HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`), direktori sensitif (`.git`, `.env`, `phpinfo.php`), dan metode HTTP berbahaya.
   * **Audit Massal (Bulk Scanning):** Mendukung pengunggahan berkas teks (`.txt`) berisi daftar ratusan domain satker peradilan dengan sistem antrean asynchronous.

2. **Authorized In-Host SSH Audit & Remediation (Tab 2):**
   * **⚡ Patch Keamanan Instan (All-in-One Full Remediation):**
     * Tombol eksekusi satu-klik dengan **Popup Konfirmasi Interaktif Modern** yang menampilkan transparansi rencana tindakan teknis sebelum eksekusi dimulai (Target Host, Deteksi OS, Versi PHP, Service aktif, dan rincian langkah).
     * Mengeksekusi rangkaian remediasi lengkap: Auto-Backup konfigurasi `php.ini.bak.<timestamp>` -> Pembaruan Biner PHP (Biner Resmi MA-RI di CentOS 7 atau APT/DNF di Ubuntu/RHEL) -> Penguncian Hardening Parameter `php.ini` & Pool FPM -> Uji Sintaks Keamanan (*configtest*) -> Pemuatan Ulang Layanan (*Graceful Restart*) -> Verifikasi Keamanan Pasca-Patch.
   * **Audit Mendalam & Mitigasi Mutlak CVE-2026-115560 (Advisori PHP 23 Oktober 2026):**
     * **Evaluasi 4 Kondisi Simultan:** Memeriksa konfigurasi awal `session.serialize_handler` (`php_binary` / `php_serialize`), memindai kode aplikasi CodeIgniter 3 SIPP terhadap pemanggilan `ini_set('session.serialize_handler')` sebelum `session_start()`, serta status aktif `session.upload_progress.enabled`.
     * **FPM Pool Anti-Override Hardening:** Menginjeksi direktif `php_admin_value[session.upload_progress.enabled] = Off` ke seluruh berkas pool FPM (`/etc/php-fpm.d/*.conf`, `/etc/php/*/fpm/pool.d/*.conf`, dan repositori Remi `/etc/opt/remi/*/php-fpm.d/*.conf`). Parameter `php_admin_value` menjamin pengaturan ini **tidak dapat dioverride** oleh skrip PHP manapun.
     * **Safety Pre-Restart Syntax Verification (`configtest`):** Menjalankan `php-fpm -t` dan `apachectl configtest` / `httpd -t` sebelum me-reload service. Jika uji sintaks mendeteksi kekeliruan, restart dibatalkan otomatis untuk menjamin **Zero-Downtime** pada server perkara pengadilan.
   * **🚨 Tindakan Tanggap Darurat & Karantina Insiden (Post-Compromise Quarantine):**
     * **Isolasi Berkas Sesi Beracun:** Memindahkan file sesi di `/tmp/sess_*` atau `/var/lib/php/session/` yang mengandung objek serialisasi berbahaya ke `/var/quarantine/sessions/` dengan hak akses `chmod 000`.
     * **Karantina Webshell Direktori Upload:** Menonaktifkan skrip PHP asing di folder berkas perkara SIPP dengan me-rename menjadi `*.quarantined` dan menguncinya dengan `chmod 000`.
     * **Terminasi Reverse Shell Aktif:** Mendeteksi dan menghentikan (*kill -9*) proses shell interaktif liar (`nc`, `bash -i`, socket Python/Perl) dan memindai koneksi jaringan keluar tak wajar.
   * **Pemisahan Cerdas Berbasis Distro (CentOS 7 vs Ubuntu/RHEL):**
     * **CentOS 7 SIPP:** Menampilkan tombol otomatisasi **`[Pasang Patch MA-RI]`** untuk mengunduh dan memasang paket biner resmi kustom `php-5.6-mari-centos7-20261024.tar.gz` (`s.id/cvemari`) sesuai instruksi Surat Ditjen Badilum No. 135/DJU.3/TI1.1.1/X/2026.
     * **Ubuntu / Debian:** Tombol CentOS disembunyikan; menampilkan tombol **`[Update Keamanan (APT)]`** untuk memperbarui paket PHP resmi Canonical.
     * **AlmaLinux / Rocky / RHEL:** Menampilkan tombol **`[Update Keamanan (DNF)]`** dengan dukungan repository Remi.
   * **Pemeriksaan Jejak Penyusupan / IoC (*Indicators of Compromise*):**
     * Berbasis riset exploit `junaire`: Memindai `/tmp/sess_*` dan `/var/lib/php/session` terhadap pola injeksi deserialisasi `upload_progress_|[OaCr]:`.
     * Memindai log web server terhadap tanda kegagalan deserialisasi: `Failed to decode session object` / `Session object destruction failed`.
     * Memindai berkas skrip PHP liar di direktori upload berkas perkara SIPP tanpa menghasilkan *false positive* pada berkas core CodeIgniter / WordPress.
     * Memindai persistensi backdoor di cron jobs (`/var/spool/cron`, `/etc/cron*`).
   * **Kunci Konfigurasi php.ini & Zona Waktu Peradilan (date.timezone):**
     * Mematikan `session.upload_progress.enabled = Off`, mengunci `max_input_nesting_level = 16`, serta mematikan `display_errors` dan `expose_php`.
     * **Pengecekan & Dropdown Zona Waktu MA-RI:** Menyediakan pilihan dropdown zona waktu hukum pengadilan (`Asia/Makassar` untuk WITA, `Asia/Jakarta` untuk WIB, `Asia/Jayapura` untuk WIT, atau `UTC / Pertahankan`) yang dapat diterapkan saat Hardening/Patch, serta kartu telemetri kepatuhan `date.timezone` untuk menjamin integritas jam perkara SIPP & e-Court.
   * **Konektivitas SSH Andal (PuTTY-Parity & Zero-Key-Leak):**
     * Mengisolasi otentikasi password dengan `look_for_keys=False` dan `allow_agent=False` agar tidak terjadi benturan dengan kunci privat lokal Windows (`.ssh/id_ed25519`).
     * Mendukung *fallback* otomatis ke mode *Keyboard-Interactive* (PAM) yang kompatibel penuh dengan OpenSSH versi modern (`OpenSSH 10.2p1`).
   * **Zero-Persistence Privacy:** Password SSH, private key, dan sudo credentials ditransmisikan via pipa memori proses (STDIN) dan tidak pernah disimpan ke database atau disk lokal.

3. **Perisai Konfigurasi & Generator Skrip Mitigasi (Tab 3):**
   * Menyediakan snippet konfigurasi siap pakai: `php.ini`, perisai *Nginx Reverse Proxy Shield*, *Apache ModSecurity OWASP CRS*, *Suricata IDS Rules*, dan skrip Bash mitigasi otomatis.

4. **Simulasi Pengujian Penetrasi Aman / Safe PoC (Tab 5):**
   * Memverifikasi keterbukaan celah secara non-destruktif (*Zero Payload, Zero Shell*) melalui evaluasi alokasi heap Zend.

---

## 📋 Kebutuhan Sistem & Dependensi

Platform ini dirancang fleksibel untuk berjalan di atas **Windows (Laragon)** maupun **Linux (Ubuntu / AlmaLinux / CentOS)**.

### 1. Web Stack & PHP
* **PHP:** Versi **8.1** atau lebih tinggi (Direkomendasikan **PHP 8.2 / 8.3**).
* **Ekstensi PHP Wajib:**
  * `curl` (Wajib untuk Pre-Flight, CURLOPT_RESOLVE, dan OWASP Auditor)
  * `openssl` (Wajib untuk komunikasi TLS/HTTPS)
  * `json` (Wajib untuk komunikasi REST API)
  * `mbstring` (Wajib untuk manipulasi string multibyte)
  * `fileinfo` (Wajib untuk validasi berkas upload massal)
* **Konfigurasi `php.ini`:**
  * `proc_open` dan `shell_exec` harus diizinkan (tidak masuk dalam `disable_functions`).

### 2. Python Environment
* **Python:** Versi **3.9** ke atas (Direkomendasikan **Python 3.12 / 3.13**).
* **Pustaka Python (via pip):**
  * `paramiko >= 3.0.0` (Untuk eksekusi audit dan hardening via SSH)
  * `h11 >= 0.14.0` (Untuk engine memory fuzzer HTTP/1.1 Duplex)
  * `tqdm >= 4.64.0` (Untuk progress tracking engine scanner)

### 3. Node.js Environment
* **Node.js:** Versi **18.0.0 LTS** ke atas (Direkomendasikan **Node.js 20 LTS** atau **22 LTS**).
* Memanfaatkan modul native built-in: `fetch`, `node:util`, `node:https`, `node:http`.

---

## 🛠️ Panduan Instalasi di Windows (Menggunakan Laragon)

### Langkah 1: Penempatan Proyek
Pastikan Laragon sudah terpasang di `C:\laragon`. Salin atau clone repositori ini ke dalam direktori `www`:
```powershell
# Path instalasi:
C:\laragon\www\proj-php2shell\
```

### Langkah 2: Verifikasi Ekstensi PHP di Laragon
1. Klik kanan ikon Laragon di System Tray -> **PHP** -> **Extensions**.
2. Pastikan ekstensi berikut memiliki tanda centang (aktif):
   * `curl`
   * `openssl`
   * `mbstring`
   * `fileinfo`

### Langkah 3: Instalasi Dependensi Python
Buka Terminal Laragon (atau PowerShell) lalu jalankan:
```powershell
# Menuju direktori proyek
cd C:\laragon\www\proj-php2shell

# Instal dependensi Python
pip install -r requirements.txt
```
*Jika menggunakan Laragon Python bawaan:*
```powershell
C:\laragon\bin\python\python-3.13\python.exe -m pip install -r requirements.txt
```

### Langkah 4: Verifikasi Node.js
Pastikan Node.js terdeteksi di PATH sistem:
```powershell
node -v
# Output diharapkan: v18.x.x, v20.x.x, atau v22.x.x
```

### Langkah 5: Menjalankan Aplikasi
1. Buka aplikasi Laragon, klik **Start All** (memulai Apache & MySQL).
2. Buka browser web dan akses alamat:
   ```
   http://localhost/proj-php2shell/
   ```

---

## 🐧 Panduan Instalasi di Linux (Ubuntu / AlmaLinux)

### Pada Ubuntu / Debian (22.04 / 24.04 LTS):
```bash
# 1. Update paket & instal web server + PHP
sudo apt update
sudo apt install -y apache2 php8.3 php8.3-curl php8.3-mbstring php8.3-xml python3 python3-pip nodejs

# 2. Clone repositori ke /var/www/html
cd /var/www/html
sudo git clone https://github.com/faizaldjau/proj-php2shell.git
cd proj-php2shell

# 3. Instal dependensi Python
sudo pip3 install -r requirements.txt --break-system-packages

# 4. Beri hak akses direktori storage untuk Task Queue
sudo mkdir -p storage/tasks storage/reports
sudo chown -R www-data:www-data storage/
sudo chmod -R 775 storage/

# 5. Akses via browser:
# http://IP_SERVER/proj-php2shell/
```

### Pada AlmaLinux / Rocky Linux / RHEL (8 / 9):
```bash
# 1. Aktifkan repositori Remi & instal PHP 8.2/8.3
sudo dnf install -y epel-release
sudo dnf install -y https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %rhel).rpm
sudo dnf module reset php -y
sudo dnf module enable php:remi-8.3 -y
sudo dnf install -y httpd php php-curl php-mbstring php-json python3 python3-pip nodejs

# 2. Tempatkan kode di /var/www/html/proj-php2shell
cd /var/www/html/proj-php2shell
sudo pip3 install -r requirements.txt

# 3. Hak akses direktori storage
sudo mkdir -p storage/tasks storage/reports
sudo chown -R apache:apache storage/
sudo chmod -R 775 storage/
sudo systemctl restart httpd
```

---

## 🎯 Panduan Penggunaan Fitur Unggulan

### 1. Audit Direct Origin (Bypass Cloudflare WAF)
Banyak situs peradilan dilindungi oleh Cloudflare yang menyamarkan IP asli dan memblokir paket probe uji fuzzer dengan status `HTTP 403 Forbidden`. Untuk menguji kondisi kesehatan Apache/PHP server fisik asli secara objektif:
1. Buka **Tab 1 (Web Scanner)** atau **Tab 5 (Simulasi Safe PoC)**.
2. Masukkan URL publik satker (contoh: `https://pa-sidoarjo.go.id/`).
3. Pada kolom **`Direct Origin IP / Bypass Cloudflare (Opsional)`**, masukkan IP publik asli server Anda (misal: `103.xxx.xxx.xxx`) atau IP LAN internal (`192.168.1.50`).
4. Klik **Mulai Audit**. Scanner akan membypass Cloudflare dan menguji langsung proses runtime PHP pada server origin.

### 2. Otomasi Patch Resmi Mahkamah Agung RI (CentOS 7 SIPP)
1. Buka **Tab 2 (Authorized SSH Audit)**.
2. Masukkan kredensial SSH server SIPP Anda (Host, Port, User `root`, dan Password/Private Key).
3. Klik **Jalankan Audit SSH Internal**.
4. Jika server terdeteksi berjalan pada **CentOS 7 PHP 5.4/5.6**:
   * Sistem otomatis menampilkan banner rujukan Surat Dirjen Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026.
   * Klik tombol kuning **`[Pasang Patch MA-RI]`**.
   * Script otomatis mengunduh paket resmi biner MA-RI (`s.id/cvemari`), memasang PHP 5.6 patched, dan me-restart layanan.
   * Telemetri server akan langsung terverifikasi dengan status: **`Custom Built MA RI: 2026-10-24`**.

### 3. Deteksi Jejak Penyusupan (Indicators of Compromise)
1. Pada Tab 2, klik tombol **`[Cek Jejak Penyusupan]`**.
2. Scanner internal akan memeriksa apakah server sudah pernah disusupi sebelumnya dengan mendeteksi file session poisoned di `/tmp/sess_*`, error log deserialization failure, dan web shell tersembunyi di folder berkas perkara.

---

## 🔒 Kebijakan Keamanan & Zero-Persistence Kredensial

* **Zero Credential Persistence:** Kredensial SSH (kata sandi, passphrase, private key `.pem`/`.id_rsa`) dan otorisasi sudo **tidak pernah dicatat ke file teks, log disk, maupun database Laragon**. Data dikirimkan secara langsung melalui memory pipe STDIN ke subproses Python berisolasi.
* **Safe PoC Non-Destruktif:** Pengujian kerentanan PHP2Shell dirancang khusus hanya untuk memicu respon Zend Heap Exhaustion sementara dan memverifikasi batas parsing boundary, **tanpa membuat webshell, tanpa remote code execution berbahaya, dan tanpa memodifikasi data database perkara**.

---

## ⚖️ Lisensi & Disclaimer

Aplikasi ini dikembangkan sebagai alat bantu audit keamanan, verifikasi kepatuhan teknis, dan mitigasi bagi **Tenaga Pranata Komputer, Administrator Jaringan, dan Tim Satgas TI di lingkungan Mahkamah Agung RI dan Badan Peradilan di Bawahnya**.

Dilarang keras menyalahgunakan alat ini untuk melakukan pemindaian atau pengujian tanpa hak (*unauthorized testing*) terhadap sistem atau server di luar wewenang dan izin tertulis satker Anda.
