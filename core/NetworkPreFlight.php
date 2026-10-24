<?php
/**
 * Network Pre-Flight Validation Engine (Anti-Halusinasi & Reachability Gate)
 * 
 * Verifies DNS resolution, TCP port reachability, and HTTP handshake
 * BEFORE any vulnerability probe or OWASP audit runs.
 * Prevents false "safe" or "0/100" reports on offline / intranet hosts.
 */

class NetworkPreFlight {

    /**
     * Complete Pre-Flight Reachability Gate
     * Supports optional Direct Origin IP Targeting (Bypass Cloudflare / Reverse Proxy)
     */
    public static function verifyTarget(string $rawUrl, int $timeout = 4, ?string $originIp = null): array {
        $cleanUrl = self::normalizeUrl($rawUrl);
        if (!$cleanUrl) {
            return [
                'reachable' => false,
                'error_type' => 'INVALID_URL',
                'title' => 'Format Target Tidak Valid',
                'message' => 'Format domain atau URL yang dimasukkan tidak valid. Harap gunakan format seperti https://example.com atau alamat IP.'
            ];
        }

        $parsed = parse_url($cleanUrl);
        $host = $parsed['host'] ?? '';
        $scheme = strtolower($parsed['scheme'] ?? 'http');
        $port = isset($parsed['port']) ? (int)$parsed['port'] : ($scheme === 'https' ? 443 : 80);

        $originIp = !empty($originIp) ? trim($originIp) : null;
        $isDirectOrigin = false;

        // 1. DNS Resolution or Direct Origin IP Evaluation
        if ($originIp) {
            if (!filter_var($originIp, FILTER_VALIDATE_IP)) {
                return [
                    'reachable' => false,
                    'error_type' => 'INVALID_ORIGIN_IP',
                    'title' => 'Format Direct Origin IP Tidak Valid',
                    'message' => "Alamat Origin IP '{$originIp}' bukan merupakan alamat IPv4 atau IPv6 yang valid."
                ];
            }
            $resolvedIp = $originIp;
            $isDirectOrigin = true;
        } else {
            $isIp = (bool)filter_var($host, FILTER_VALIDATE_IP);
            $resolvedIp = $host;

            if (!$isIp) {
                $dnsIp = gethostbyname($host);
                if ($dnsIp === $host) {
                    // Resolution failed
                    return [
                        'reachable' => false,
                        'error_type' => 'DNS_RESOLUTION_FAILED',
                        'title' => 'DNS Resolution Failed (Domain Intranet / Tidak Terdaftar)',
                        'message' => "Domain '{$host}' tidak dapat di-resolve melalui DNS pada mesin ini. Jika target adalah domain intranet lokal pengadilan (seperti sipplokal.pn-*.go.id), pastikan komputer terhubung ke VPN / jaringan lokal pengadilan setempat, atau masukkan Direct Origin IP server."
                    ];
                }
                $resolvedIp = $dnsIp;
            }
        }

        // 2. TCP Port Reachability Check
        $socket = @fsockopen($resolvedIp, $port, $errno, $errstr, $timeout);
        if (!$socket) {
            return [
                'reachable' => false,
                'error_type' => 'TCP_CONNECTION_FAILED',
                'title' => "Koneksi ke Port $port Gagal",
                'message' => "Gagal membuka koneksi TCP ke " . ($isDirectOrigin ? "Origin IP {$originIp}" : "{$host} ({$resolvedIp})") . " pada port {$port}. Error: {$errstr} (Kode: {$errno}). Web server sedang offline atau port diblokir firewall."
            ];
        }
        fclose($socket);

        // 3. Quick HTTP Protocol Ping (with CURLOPT_RESOLVE if Origin IP is set)
        $ch = curl_init();
        $curlOpts = [
            CURLOPT_URL => $cleanUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'Mozilla/5.0 Proj-PHP2Shell-PreFlight/1.0'
        ];

        if ($isDirectOrigin && $originIp) {
            $curlOpts[CURLOPT_RESOLVE] = [
                "{$host}:80:{$originIp}",
                "{$host}:443:{$originIp}",
                "{$host}:{$port}:{$originIp}"
            ];
        }

        curl_setopt_array($ch, $curlOpts);

        $resp = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($resp === false && $httpCode === 0) {
            return [
                'reachable' => false,
                'error_type' => 'HTTP_HANDSHAKE_FAILED',
                'title' => 'HTTP Handshake Gagal',
                'message' => "Target terbuka pada port TCP tetapi gagal merespon protokol HTTP. Keterangan: {$curlError}"
            ];
        }

        // Auto-upgrade / follow canonical redirects (e.g. HTTP -> HTTPS)
        $redirectedUrl = null;
        if (!empty($effectiveUrl) && $effectiveUrl !== $cleanUrl) {
            $parsedEff = parse_url($effectiveUrl);
            if (!empty($parsedEff['host'])) {
                $redirectedUrl = $effectiveUrl;
                $cleanUrl = $effectiveUrl;
                $host = $parsedEff['host'];
                $scheme = strtolower($parsedEff['scheme'] ?? $scheme);
                $port = isset($parsedEff['port']) ? (int)$parsedEff['port'] : ($scheme === 'https' ? 443 : 80);
            }
        }

        return [
            'reachable' => true,
            'clean_url' => $cleanUrl,
            'original_url' => $rawUrl,
            'redirected_url' => $redirectedUrl,
            'host' => $host,
            'resolved_ip' => $resolvedIp,
            'direct_origin_ip' => $originIp,
            'is_direct_origin' => $isDirectOrigin,
            'port' => $port,
            'scheme' => $scheme,
            'http_code' => $httpCode
        ];
    }

    public static function normalizeUrl(string $url): ?string {
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

        return $scheme . '://' . $parsed['host'] . (isset($parsed['port']) ? ':' . $parsed['port'] : '') . ($parsed['path'] ?? '/');
    }
}
