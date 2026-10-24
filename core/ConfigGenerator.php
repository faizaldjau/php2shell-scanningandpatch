<?php
/**
 * Configuration & Hardening Template Generator
 * 
 * Generates tailored, production-ready configuration snippets and bash scripts
 * for Apache, Nginx, PHP-FPM, php.ini, and OS-specific environments.
 * Integrates authentic detection & CRS rules from cloned engines.
 */

class ConfigGenerator {

    /**
     * Get Authentic Engine Rule File Content
     */
    public static function getEngineFile(string $engineKey): string {
        $baseDir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'engines';
        $map = [
            'p2s_modsecurity' => $baseDir . '/p2s-poc-toolkit/detection/modsecurity.conf',
            'p2s_suricata'    => $baseDir . '/p2s-poc-toolkit/detection/php2shell.rules',
            'p2s_sigma'       => $baseDir . '/p2s-poc-toolkit/detection/php2shell.yaml',
            'p2s_lua'         => $baseDir . '/p2s-poc-toolkit/detection/php2shell.lua',
            'owasp_crs_php'   => $baseDir . '/owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf',
            'owasp_crs_proto' => $baseDir . '/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf',
        ];

        if (isset($map[$engineKey]) && file_exists($map[$engineKey])) {
            return file_get_contents($map[$engineKey]);
        }

        return "# Engine file tidak ditemukan pada repository lokal: {$engineKey}";
    }

    /**
     * Generate hardened php.ini directives
     */
    public static function generatePhpIni(array $options = []): string {
        $nesting = (int)($options['nesting_level'] ?? 16);
        $maxVars = (int)($options['max_vars'] ?? 1500);

        return <<<INI
; ==============================================================================
; PHP2Shell & Server Hardening Directives for php.ini
; SIPP Court & Production Web Application Standard
; ==============================================================================

; 1. MENUTUP VEKTOR UTAMA PHP2SHELL (CVE-2026-109618 & CVE-2026-109619)
; Nonaktifkan fitur pelacakan kemajuan unggahan sesi.
; Aplikasi SIPP dan CMS modern tidak bergantung pada fitur internal ini.
session.upload_progress.enabled = Off
session.upload_progress.cleanup = Off

; 2. BATASI KEDALAMAN HIERARKI ARRAY (ANTI-OOM FUZZING PROBE)
; Eksploit memori menggunakan probe nested keys sedalam 62 tingkat (a[][a][a]...).
; Menurunkan nilai ke $nesting langsung menolak payload sebelum alokasi heap Zend terjadi.
max_input_nesting_level = $nesting
max_input_vars = $maxVars

; 3. PENCEGAHAN KEBOCORAN INFORMASI (OWASP A05: SECURITY MISCONFIGURATION)
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On

; 4. PENGUATAN KEAMANAN COOKIE SESI (OWASP A01 / A07)
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
session.use_strict_mode = 1

; ==============================================================================
; Setelah menyimpan file ini, restart layanan PHP-FPM / Apache!
; ==============================================================================
INI;
    }

    /**
     * Generate Nginx Shield Configuration
     */
    public static function generateNginx(string $domain = 'sipp.pn-contoh.go.id', int $maxUpload = 50): string {
        return <<<NGINX
# ==============================================================================
# Nginx Hardening Shield against PHP2Shell (CVE-2026-109618/19) & OWASP Top 10
# Tempatkan pada file konfigurasi vhost /etc/nginx/conf.d/$domain.conf
# ==============================================================================

server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;

    # SSL TLS Settings (A02: Cryptographic Failures)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # 1. SEMBUNYIKAN BANNER SERVER
    server_tokens off;

    # 2. BATASI UKURAN BODY & BUFFER (REDAM PROBE EXHAUSTION)
    client_max_body_size {$maxUpload}M;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;

    # 3. SECURITY HEADERS BAKU (OWASP A05)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 4. BLOKIR PERINTAH HTTP METODE BERBAHAYA
    if (\$request_method !~ ^(GET|HEAD|POST)\$ ) {
        return 405;
    }

    # 5. BLOKIR BERKAS SENSITIF (.git, .env)
    location ~ /\.(?!well-known).* {
        deny all;
        access_log off;
        log_not_found off;
    }

    # 6. PENANGKAL LANGSUNG PAYLOAD PHP2SHELL
    location / {
        if (\$request_body ~* "PHP_SESSION_UPLOAD_PROGRESS") {
            return 403;
        }

        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php-fpm.sock; # Sesuaikan dengan socket server Anda
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 120s;
    }
}
NGINX;
    }

    /**
     * Generate Nginx Reverse Proxy Shield for Legacy SIPP (CentOS 7 Backend)
     */
    public static function generateReverseProxy(string $domain = 'sipp.pn-contoh.go.id', string $backendIp = '192.168.1.50'): string {
        return <<<NGINX
# ==============================================================================
# Nginx Reverse Proxy Shield (Frontend) -> Backend Apache SIPP ($backendIp)
# Solusi Terbaik Mengamankan Server SIPP CentOS 7 / PHP 5.6 yang Sudah EOL
# ==============================================================================

server {
    listen 443 ssl http2;
    server_name $domain;

    # SSL Termination di Nginx Lini Depan
    server_tokens off;
    client_max_body_size 50M;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        # Saring dan bunuh request eksploitasi PHP2Shell sebelum menyentuh CentOS 7
        if (\$request_body ~* "PHP_SESSION_UPLOAD_PROGRESS") {
            return 403;
        }

        proxy_pass http://$backendIp:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_connect_timeout 60s;
        proxy_read_timeout 120s;
    }
}
NGINX;
    }

    /**
     * Generate Apache ModSecurity Rules
     */
    public static function generateModSecurity(): string {
        return <<<APACHE
# ==============================================================================
# ModSecurity Custom Defense Rules for PHP2Shell (CVE-2026-109618/19)
# Tambahkan ke /etc/httpd/conf.d/mod_security.conf (CentOS/Alma)
# atau /etc/apache2/mods-enabled/security2.conf (Ubuntu)
# ==============================================================================

<IfModule mod_security2.c>
    SecRuleEngine On

    # Rule 1: Tangkal langsung string PHP_SESSION_UPLOAD_PROGRESS pada multipart POST
    SecRule REQUEST_BODY|ARGS_NAMES "@contains PHP_SESSION_UPLOAD_PROGRESS" \
        "id:2026101,phase:2,deny,status:403,log,auditlog,msg:'PHP2Shell Session Upload Progress Exploit Blocked'"

    # Rule 2: Tangkal payload array nesting berulang ekstrem (> 15 kedalaman)
    SecRule REQUEST_BODY "@rx (?:\[[^\]]*\]){15,}" \
        "id:2026102,phase:2,deny,status:403,log,auditlog,msg:'PHP2Shell Nested Array Fuzzing Blocked'"

    # Rule 3: Tangkal pembacaan file sensitif melalui LFI (Chain A)
    SecRule ARGS "@rx (?:etc/passwd|proc/self/environ|sess_[a-zA-Z0-9]+)" \
        "id:2026103,phase:2,deny,status:403,log,msg:'Potential LFI / Session Poisoning Access Blocked'"
</IfModule>

# Pengerasan Header Apache (A05: Security Misconfiguration)
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
APACHE;
    }

    /**
     * Generate Bash Remediation Scripts
     */
    public static function generateBashScript(string $osType): string {
        switch ($osType) {
            case 'ubuntu':
                return <<<BASH
#!/usr/bin/env bash
# ==============================================================================
# Automated Remediation Script for Ubuntu 24.04 / 22.04 LTS
# ==============================================================================
set -e

echo "[*] Memperbarui indeks repositori apt..."
sudo apt update

echo "[*] Menginstal paket perbaikan resmi PHP2Shell dari Canonical..."
sudo apt --only-upgrade install -y php* libapache2-mod-php* php*-fpm php*-cli

echo "[*] Memeriksa dan mengunci session.upload_progress di seluruh php.ini..."
for ini in $(find /etc/php -name php.ini 2>/dev/null); do
    echo "    - Mengonfigurasi \$ini"
    sudo cp "\$ini" "\$ini.bak_php2shell"
    sudo sed -i -E 's/^[; ]*session.upload_progress.enabled[ ]*=.*/session.upload_progress.enabled = Off/' "\$ini"
    sudo sed -i -E 's/^[; ]*expose_php[ ]*=.*/expose_php = Off/' "\$ini"
done

echo "[*] Merestart layanan web server dan PHP-FPM..."
sudo systemctl restart php*-fpm 2>/dev/null || true
sudo systemctl restart apache2 2>/dev/null || true
sudo systemctl restart nginx 2>/dev/null || true

echo "[+] Remediasi Ubuntu selesai! Verifikasi versi: php -v"
BASH;

            case 'bash_mari_centos7':
                return <<<BASH
#!/usr/bin/env bash
# ==============================================================================
# Skrip Resmi Mitigasi SIPP CentOS 7 — Mahkamah Agung Republik Indonesia
# Rujukan: Surat Dirjen Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026 (s.id/cvemari)
# Video Panduan: https://drive.google.com/open?id=1XKdEt3faVS8YPbSPaiaU_YsXTsg56Mul
# ==============================================================================
set -e

echo "[*] Mengunduh paket patch biner resmi PHP 5.6 Mahkamah Agung RI..."
cd /root
curl -kL https://office.pt-yogyakarta.go.id/php-5.6-mari-centos7-20261024.tar.gz -o php-5.6-mari-centos7-20261024.tar.gz

echo "[*] Mengekstrak paket distribusi..."
tar -zxvf php-5.6-mari-centos7-20261024.tar.gz

echo "[*] Menjalankan skrip instalasi patch..."
cd php56-dist
chmod +x install.sh
./install.sh

echo "[*] Merestart layanan web server SIPP..."
systemctl restart httpd 2>/dev/null || true
systemctl restart php-fpm 2>/dev/null || true
systemctl restart rh-php56-php-fpm 2>/dev/null || true

echo ""
echo "=============================================================================="
echo "[+] VERIFIKASI INSTALASI:"
php -v
echo "=============================================================================="
echo "Pastikan output di atas memuat teks: (Custom Built MA RI: 2026-10-24)"
BASH;

            case 'centos7':
                return <<<BASH
#!/usr/bin/env bash
# ==============================================================================
# Hardening & Remediation Script for CentOS 7 & PHP 5.6 (Legacy SIPP)
# Tanpa patch biner upstream -> Menerapkan penguncian konfigurasi runtime
# ==============================================================================
set -e

echo "[*] Mencari seluruh file php.ini di CentOS 7..."
for ini in /etc/php.ini /etc/opt/rh/rh-php56/php.ini; do
    if [ -f "\$ini" ]; then
        echo "    - Mengunci \$ini..."
        sudo cp "\$ini" "\$ini.bak_php2shell"
        # 1. Matikan upload progress
        sudo sed -i -E 's/^[; ]*session.upload_progress.enabled[ ]*=.*/session.upload_progress.enabled = Off/' "\$ini"
        # 2. Batasi nesting level
        if grep -q "max_input_nesting_level" "\$ini"; then
            sudo sed -i -E 's/^[; ]*max_input_nesting_level[ ]*=.*/max_input_nesting_level = 16/' "\$ini"
        else
            echo "max_input_nesting_level = 16" | sudo tee -a "\$ini" >/dev/null
        fi
        # 3. Sembunyikan versi
        sudo sed -i -E 's/^[; ]*expose_php[ ]*=.*/expose_php = Off/' "\$ini"
        sudo sed -i -E 's/^[; ]*display_errors[ ]*=.*/display_errors = Off/' "\$ini"
    fi
done

echo "[*] Merestart layanan web server SIPP..."
sudo systemctl restart httpd 2>/dev/null || true
sudo systemctl restart php-fpm 2>/dev/null || true
sudo systemctl restart rh-php56-php-fpm 2>/dev/null || true

echo "[+] Hardening CentOS 7 SIPP selesai! Parameter session.upload_progress telah dinonaktifkan."
BASH;

            case 'almalinux':
            default:
                return <<<BASH
#!/usr/bin/env bash
# ==============================================================================
# Automated Remediation Script for Rocky Linux / AlmaLinux (8/9)
# ==============================================================================
set -e

echo "[*] Mengupgrade paket PHP dari repositori sistem / Remi..."
sudo dnf --enablerepo=remi upgrade -y php php-fpm php-cli

echo "[*] Mengunci konfigurasi php.ini..."
for ini in /etc/php.ini /etc/php.d/*.ini; do
    if [ -f "\$ini" ]; then
        sudo sed -i -E 's/^[; ]*session.upload_progress.enabled[ ]*=.*/session.upload_progress.enabled = Off/' "\$ini" 2>/dev/null || true
    fi
done

echo "[*] Merestart service..."
sudo systemctl restart php-fpm
sudo systemctl restart httpd 2>/dev/null || sudo systemctl restart nginx 2>/dev/null || true

echo "[+] Remediasi AlmaLinux / Rocky Linux Selesai!"
BASH;
        }
    }
}
