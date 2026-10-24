<?php
/**
 * OWASP Top 10 & Server Hardening Baseline Auditor
 * 
 * Performs non-destructive security checks against target web application:
 * - A01: Broken Access Control & Session Security (Cookie attributes)
 * - A02: Cryptographic Failures (HSTS, TLS enforcement)
 * - A05: Security Misconfiguration (Information Leakage, Security Headers, HTTP Methods, Exposed Files)
 * 
 * Built with strict input validation and zero unsafe execution.
 */

class OwaspAuditor {

    private int $timeout;
    private bool $verifySsl;
    private ?string $originIp = null;

    public function __construct(int $timeout = 15, bool $verifySsl = false) {
        $this->timeout = $timeout;
        $this->verifySsl = $verifySsl;
    }

    /**
     * Run full OWASP baseline audit on target URL
     * Supports optional Direct Origin IP Targeting (Bypass Cloudflare)
     */
    public function audit(string $url, ?string $originIp = null): array {
        $cleanUrl = $this->sanitizeUrl($url);
        if (!$cleanUrl) {
            return [
                'success' => false,
                'error' => 'Invalid target URL format. Must start with http:// or https://'
            ];
        }

        $this->originIp = !empty($originIp) && filter_var($originIp, FILTER_VALIDATE_IP) ? trim($originIp) : null;

        $results = [
            'target' => $cleanUrl,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'score' => 100,
            'grade' => 'A',
            'findings' => [],
            'headers_analyzed' => [],
            'cookies_analyzed' => [],
            'methods_allowed' => [],
            'sensitive_files' => []
        ];

        // 1. Fetch Root Headers & Response
        $mainResponse = $this->fetchHeadOrGet($cleanUrl);
        if (!$mainResponse['success']) {
            return [
                'success' => false,
                'target' => $cleanUrl,
                'error' => 'Unable to connect to target: ' . htmlspecialchars($mainResponse['error'])
            ];
        }

        $headers = $mainResponse['headers'];
        $results['headers_analyzed'] = $headers;

        // 2. Audit Security Headers (A05: Security Misconfiguration & A02: Cryptographic Failures)
        $this->auditSecurityHeaders($cleanUrl, $headers, $results);

        // 3. Audit Server Fingerprinting & Information Leakage
        $this->auditServerFingerprint($headers, $results);

        // 4. Audit Cookie Security (A01 / A07)
        if (!empty($mainResponse['cookies'])) {
            $this->auditCookies($mainResponse['cookies'], $cleanUrl, $results);
        }

        // 5. Audit Dangerous HTTP Methods (WSTG-CONF-06)
        $this->auditHttpMethods($cleanUrl, $results);

        // 6. Audit Sensitive Files Exposure (WSTG-CONF-04)
        $this->auditSensitiveFiles($cleanUrl, $results);

        // 7. Calculate Final Score & Grade
        $score = max(0, min(100, $results['score']));
        $results['score'] = $score;
        if ($score >= 85) {
            $results['grade'] = 'A';
        } elseif ($score >= 70) {
            $results['grade'] = 'B';
        } elseif ($score >= 55) {
            $results['grade'] = 'C';
        } elseif ($score >= 40) {
            $results['grade'] = 'D';
        } else {
            $results['grade'] = 'F';
        }

        $results['success'] = true;
        return $results;
    }

    private function sanitizeUrl(string $url): ?string {
        $url = trim($url);
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }

        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['host'])) {
            return null;
        }

        $scheme = strtolower($parsed['scheme'] ?? 'http');
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }

        $host = $parsed['host'];
        $port = isset($parsed['port']) ? ':' . (int)$parsed['port'] : '';
        $path = $parsed['path'] ?? '/';
        if (empty($path)) {
            $path = '/';
        }

        return $scheme . '://' . $host . $port . $path;
    }

    private function fetchHeadOrGet(string $url, string $method = 'GET'): array {
        $ch = curl_init();
        $opts = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => ($method === 'HEAD'),
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_SSL_VERIFYPEER => $this->verifySsl,
            CURLOPT_SSL_VERIFYHOST => $this->verifySsl ? 2 : 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Proj-PHP2Shell-Auditor/1.0'
        ];

        if ($this->originIp) {
            $parsed = parse_url($url);
            $host = $parsed['host'] ?? '';
            $port = isset($parsed['port']) ? (int)$parsed['port'] : ((strtolower($parsed['scheme'] ?? '') === 'https') ? 443 : 80);
            if (!empty($host)) {
                $opts[CURLOPT_RESOLVE] = [
                    "{$host}:80:{$this->originIp}",
                    "{$host}:443:{$this->originIp}",
                    "{$host}:{$port}:{$this->originIp}"
                ];
            }
        }

        curl_setopt_array($ch, $opts);

        $rawResponse = curl_exec($ch);
        if ($rawResponse === false) {
            $error = curl_error($ch);
            curl_close($ch);
            return ['success' => false, 'error' => $error];
        }

        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $headerText = substr($rawResponse, 0, $headerSize);
        $headers = [];
        $cookies = [];

        foreach (explode("\r\n", $headerText) as $line) {
            if (strpos($line, ':') !== false) {
                [$key, $val] = explode(':', $line, 2);
                $keyTrim = strtolower(trim($key));
                $valTrim = trim($val);
                $headers[$keyTrim] = $valTrim;

                if ($keyTrim === 'set-cookie') {
                    $cookies[] = $valTrim;
                }
            }
        }

        return [
            'success' => true,
            'http_code' => $httpCode,
            'headers' => $headers,
            'cookies' => $cookies
        ];
    }

    private function auditSecurityHeaders(string $url, array $headers, array &$results): void {
        $isHttps = (strpos($url, 'https://') === 0);

        // 1. HSTS (Strict-Transport-Security)
        if ($isHttps) {
            if (!isset($headers['strict-transport-security'])) {
                $results['score'] -= 10;
                $results['findings'][] = [
                    'category' => 'A02: Cryptographic Failures',
                    'severity' => 'MEDIUM',
                    'title' => 'Missing HTTP Strict Transport Security (HSTS)',
                    'desc' => 'Header Strict-Transport-Security tidak ditemukan. Tanpa HSTS, koneksi rentan terhadap serangan SSL Strip dan Man-In-The-Middle.',
                    'remediation' => 'Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                ];
            }
        } else {
            $results['score'] -= 20;
            $results['findings'][] = [
                'category' => 'A02: Cryptographic Failures',
                'severity' => 'HIGH',
                'title' => 'Unencrypted HTTP Connection',
                'desc' => 'Situs melayani trafik tanpa enkripsi HTTPS. Data kredensial dan sesi perkara dapat disadap.',
                'remediation' => 'Pasang sertifikat TLS/SSL (misal Let\'s Encrypt) dan lakukan redirect 301 dari HTTP ke HTTPS.'
            ];
        }

        // 2. Content-Security-Policy (CSP)
        if (!isset($headers['content-security-policy'])) {
            $results['score'] -= 15;
            $results['findings'][] = [
                'category' => 'A05: Security Misconfiguration',
                'severity' => 'MEDIUM',
                'title' => 'Missing Content Security Policy (CSP)',
                'desc' => 'Header Content-Security-Policy tidak terpasang. CSP sangat efektif meredam serangan XSS dan data injection.',
                'remediation' => 'Terapkan minimal: Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\';'
            ];
        }

        // 3. X-Frame-Options (Clickjacking Protection)
        if (!isset($headers['x-frame-options'])) {
            $results['score'] -= 10;
            $results['findings'][] = [
                'category' => 'A05: Security Misconfiguration',
                'severity' => 'MEDIUM',
                'title' => 'Missing X-Frame-Options Header',
                'desc' => 'Header X-Frame-Options tidak aktif, memungkinkan halaman SIPP di-embed ke dalam iframe situs jahat (Clickjacking).',
                'remediation' => 'Tambahkan header: X-Frame-Options: SAMEORIGIN'
            ];
        }

        // 4. X-Content-Type-Options (MIME Sniffing)
        if (!isset($headers['x-content-type-options']) || strtolower($headers['x-content-type-options']) !== 'nosniff') {
            $results['score'] -= 10;
            $results['findings'][] = [
                'category' => 'A05: Security Misconfiguration',
                'severity' => 'LOW',
                'title' => 'Missing X-Content-Type-Options (nosniff)',
                'desc' => 'Browser dapat melakukan MIME-sniffing terhadap berkas unggahan, membuka celah eksekusi skrip.',
                'remediation' => 'Tambahkan header: X-Content-Type-Options: nosniff'
            ];
        }

        // 5. Referrer-Policy
        if (!isset($headers['referrer-policy'])) {
            $results['score'] -= 5;
            $results['findings'][] = [
                'category' => 'A05: Security Misconfiguration',
                'severity' => 'LOW',
                'title' => 'Missing Referrer-Policy Header',
                'desc' => 'URL lengkap beserta parameter sensitif dapat bocor ke situs eksternal saat navigasi keluar.',
                'remediation' => 'Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin'
            ];
        }
    }

    private function auditServerFingerprint(array $headers, array &$results): void {
        // X-Powered-By
        if (isset($headers['x-powered-by'])) {
            $results['score'] -= 15;
            $results['findings'][] = [
                'category' => 'A05: Security Misconfiguration',
                'severity' => 'HIGH',
                'title' => 'Information Disclosure: X-Powered-By Exposed',
                'desc' => 'Header membocorkan versi teknologi: "' . htmlspecialchars($headers['x-powered-by']) . '". Ini mempermudah penyerang memetakan sasaran PHP2Shell.',
                'remediation' => 'Di php.ini, ubah parameter: expose_php = Off'
            ];
        }

        // Server Banner
        if (isset($headers['server'])) {
            $serverVal = $headers['server'];
            // Check if version is leaked (e.g. Apache/2.4.6 or nginx/1.18.0)
            if (preg_match('#[0-9]+\.[0-9]+#', $serverVal)) {
                $results['score'] -= 10;
                $results['findings'][] = [
                    'category' => 'A05: Security Misconfiguration',
                    'severity' => 'MEDIUM',
                    'title' => 'Information Disclosure: Detailed Server Version in Header',
                    'desc' => 'Header Server membocorkan versi spesifik perangkat lunak: "' . htmlspecialchars($serverVal) . '".',
                    'remediation' => 'Apache: ServerTokens Prod, ServerSignature Off. Nginx: server_tokens off;'
                ];
            }
        }
    }

    private function auditCookies(array $cookies, string $url, array &$results): void {
        $isHttps = (strpos($url, 'https://') === 0);

        foreach ($cookies as $cookieStr) {
            $parts = array_map('trim', explode(';', $cookieStr));
            $nameVal = array_shift($parts);
            $cName = explode('=', $nameVal)[0] ?? 'Cookie';

            $hasHttpOnly = false;
            $hasSecure = false;
            $hasSameSite = false;

            foreach ($parts as $attr) {
                $attrLower = strtolower($attr);
                if ($attrLower === 'httponly') $hasHttpOnly = true;
                if ($attrLower === 'secure') $hasSecure = true;
                if (strpos($attrLower, 'samesite') === 0) $hasSameSite = true;
            }

            $results['cookies_analyzed'][] = [
                'name' => $cName,
                'httponly' => $hasHttpOnly,
                'secure' => $hasSecure,
                'samesite' => $hasSameSite
            ];

            if (!$hasHttpOnly) {
                $results['score'] -= 10;
                $results['findings'][] = [
                    'category' => 'A01: Broken Access Control',
                    'severity' => 'HIGH',
                    'title' => "Insecure Cookie ($cName): Missing HttpOnly Flag",
                    'desc' => "Cookie sesi '$cName' dapat dibaca oleh skrip JavaScript, memperbesar dampak pencurian token saat terjadi XSS.",
                    'remediation' => 'Konfigurasi session.cookie_httponly = 1 di php.ini atau set flag HttpOnly pada aplikasi.'
                ];
            }

            if ($isHttps && !$hasSecure) {
                $results['score'] -= 10;
                $results['findings'][] = [
                    'category' => 'A02: Cryptographic Failures',
                    'severity' => 'MEDIUM',
                    'title' => "Insecure Cookie ($cName): Missing Secure Flag",
                    'desc' => "Cookie '$cName' dapat dikirim melalui kanal HTTP biasa tanpa enkripsi jika pengguna beralih protokol.",
                    'remediation' => 'Konfigurasi session.cookie_secure = 1 di php.ini.'
                ];
            }

            if (!$hasSameSite) {
                $results['score'] -= 5;
                $results['findings'][] = [
                    'category' => 'A01: Broken Access Control',
                    'severity' => 'LOW',
                    'title' => "Cookie ($cName): Missing SameSite Attribute",
                    'desc' => "Cookie '$cName' tidak memiliki atribut SameSite (Lax/Strict) yang berfungsi meredam serangan Cross-Site Request Forgery (CSRF).",
                    'remediation' => 'Tambahkan session.cookie_samesite = "Lax" di php.ini.'
                ];
            }
        }
    }

    private function auditHttpMethods(string $url, array &$results): void {
        $parsed = parse_url($url);
        $base = ($parsed['scheme'] ?? 'http') . '://' . ($parsed['host'] ?? '') . (isset($parsed['port']) ? ':' . $parsed['port'] : '') . '/';

        // Test TRACE
        $traceResp = $this->fetchHeadOrGet($base, 'TRACE');
        if ($traceResp['success'] && in_array($traceResp['http_code'], [200, 204], true)) {
            $results['score'] -= 15;
            $results['findings'][] = [
                'category' => 'A05: Security Misconfiguration',
                'severity' => 'HIGH',
                'title' => 'Dangerous HTTP Method Allowed: TRACE (Cross-Site Tracing)',
                'desc' => 'Metode HTTP TRACE aktif di web server. Hal ini memungkinkan penyerang mencuri kredensial cookie HttpOnly melalui teknik XST.',
                'remediation' => 'Apache: TraceEnable Off. Nginx: Batasi metode hanya GET, POST, HEAD.'
            ];
            $results['methods_allowed'][] = 'TRACE';
        }

        // Test OPTIONS to discover allowed methods
        $optionsResp = $this->fetchHeadOrGet($base, 'OPTIONS');
        if ($optionsResp['success'] && !empty($optionsResp['headers']['allow'])) {
            $results['methods_allowed'] = array_map('trim', explode(',', $optionsResp['headers']['allow']));
        }
    }

    private function auditSensitiveFiles(string $url, array &$results): void {
        $parsed = parse_url($url);
        $base = ($parsed['scheme'] ?? 'http') . '://' . ($parsed['host'] ?? '') . (isset($parsed['port']) ? ':' . $parsed['port'] : '') . '/';

        $checks = [
            '.git/HEAD' => ['pattern' => 'ref: refs/', 'desc' => 'Repositori Git Publik'],
            '.env' => ['pattern' => 'DB_', 'desc' => 'Environment & Database Secrets'],
            'phpinfo.php' => ['pattern' => 'PHP Version', 'desc' => 'Halaman Diagnostik PHP Info'],
            'info.php' => ['pattern' => 'PHP Version', 'desc' => 'Halaman Diagnostik PHP Info']
        ];

        foreach ($checks as $file => $meta) {
            $testUrl = $base . $file;
            $ch = curl_init();
            $sOpts = [
                CURLOPT_URL => $testUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => false,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_USERAGENT => 'Mozilla/5.0 Proj-PHP2Shell-Auditor/1.0'
            ];
            if ($this->originIp) {
                $pHost = parse_url($testUrl, PHP_URL_HOST);
                if ($pHost) {
                    $sOpts[CURLOPT_RESOLVE] = [
                        "{$pHost}:80:{$this->originIp}",
                        "{$pHost}:443:{$this->originIp}"
                    ];
                }
            }
            curl_setopt_array($ch, $sOpts);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($code === 200 && is_string($body) && strpos($body, $meta['pattern']) !== false) {
                $results['score'] -= 20;
                $results['sensitive_files'][] = [
                    'path' => '/' . $file,
                    'type' => $meta['desc']
                ];
                $results['findings'][] = [
                    'category' => 'A05: Security Misconfiguration',
                    'severity' => 'CRITICAL',
                    'title' => "Exposed Sensitive File: /$file (" . $meta['desc'] . ')',
                    'desc' => "Berkas sensitif /$file terbuka dan dapat diunduh langsung tanpa autentikasi, membocorkan rahasia sistem.",
                    'remediation' => "Hapus berkas /$file dari web root publik atau blokir akses via .htaccess / Nginx (deny all)."
                ];
            }
        }
    }
}
