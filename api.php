<?php
/**
 * REST API Controller for Proj-PHP2Shell
 * 
 * Strict OWASP compliant request router:
 * - Content-Type validation
 * - Security headers enforcement
 * - Parameter sanitization and validation
 * - Zero unhandled exception leakage
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');

require_once __DIR__ . '/core/AuditRunner.php';
require_once __DIR__ . '/core/TaskQueue.php';
require_once __DIR__ . '/core/SshHardener.php';
require_once __DIR__ . '/core/ConfigGenerator.php';

$action = $_GET['action'] ?? $_POST['action'] ?? '';

try {
    switch ($action) {
        case 'start_scan':
            handleStartScan();
            break;

        case 'scan_status':
            handleScanStatus();
            break;

        case 'list_scans':
            handleListScans();
            break;

        case 'ssh_audit':
            handleSshAudit();
            break;

        case 'ssh_harden':
            handleSshHarden();
            break;

        case 'ssh_mari_patch':
            handleSshMariPatch();
            break;

        case 'ssh_distro_upgrade':
            handleSshDistroUpgrade();
            break;

        case 'ssh_instant_patch':
            handleSshInstantPatch();
            break;

        case 'ssh_check_compromise':
            handleSshCheckCompromise();
            break;

        case 'ssh_quarantine':
            handleSshQuarantine();
            break;

        case 'get_config':
            handleGetConfig();
            break;

        case 'demo_test':
            handleDemoTest();
            break;

        default:
            echo json_encode([
                'success' => false,
                'error' => 'Aksi tidak dikenali atau parameter action hilang.'
            ]);
            break;
    }
} catch (Throwable $e) {
    // OWASP A05: Do not expose raw exception stack traces
    error_log('[API Error] ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    echo json_encode([
        'success' => false,
        'error' => 'Terjadi kesalahan sistem internal: ' . htmlspecialchars($e->getMessage())
    ]);
}

/**
 * Handle Start Scan (Single or Uploaded File)
 */
function handleStartScan(): void {
    $runner = new AuditRunner();
    $queue = new TaskQueue();

    // Check if file upload was provided
    if (isset($_FILES['target_file']) && $_FILES['target_file']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['target_file'];
        // Validate file size (max 2MB)
        if ($file['size'] > 2 * 1024 * 1024) {
            echo json_encode(['success' => false, 'error' => 'Ukuran berkas melebihi batas 2MB.']);
            return;
        }

        // Validate extension (.txt)
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if ($ext !== 'txt') {
            echo json_encode(['success' => false, 'error' => 'Format berkas harus berupa file teks (.txt).']);
            return;
        }

        $lines = file($file['tmp_name'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $hosts = [];
        foreach ($lines as $line) {
            $h = trim($line);
            if (!empty($h) && strpos($h, '#') !== 0) {
                $hosts[] = $h;
            }
        }
        $hosts = array_values(array_unique($hosts));

        if (empty($hosts)) {
            echo json_encode(['success' => false, 'error' => 'Berkas teks tidak memuat daftar host/domain yang valid.']);
            return;
        }

        $options = [
            'sapi' => $_POST['sapi'] ?? 'auto',
            'timeout' => (int)($_POST['timeout'] ?? 30),
            'path' => $_POST['custom_path'] ?? ''
        ];

        $scanId = $queue->createTask($hosts, $options);

        // Run process in background (or trigger initial execution)
        echo json_encode([
            'success' => true,
            'is_bulk' => true,
            'scan_id' => $scanId,
            'total_hosts' => count($hosts),
            'message' => 'Tugas audit massal berhasil dibuat.'
        ]);
        return;
    }

    // Handle single target
    $targetUrl = trim($_POST['target_url'] ?? '');
    if (empty($targetUrl)) {
        echo json_encode(['success' => false, 'error' => 'Target URL atau domain wajib diisi.']);
        return;
    }

    $originIp = trim($_POST['origin_ip'] ?? '');

    $options = [
        'sapi' => $_POST['sapi'] ?? 'auto',
        'timeout' => (int)($_POST['timeout'] ?? 30),
        'path' => $_POST['custom_path'] ?? ''
    ];
    if (!empty($originIp) && filter_var($originIp, FILTER_VALIDATE_IP)) {
        $options['origin_ip'] = $originIp;
    }

    $result = $runner->auditSingle($targetUrl, $options);
    echo json_encode($result);
}

/**
 * Handle Polling of Task Progress & Worker Step Execution
 */
function handleScanStatus(): void {
    $scanId = trim($_GET['scan_id'] ?? '');
    if (empty($scanId)) {
        echo json_encode(['success' => false, 'error' => 'Parameter scan_id wajib disertakan.']);
        return;
    }

    $queue = new TaskQueue();
    $task = $queue->getTask($scanId);
    if (!$task) {
        echo json_encode(['success' => false, 'error' => 'Tugas audit tidak ditemukan.']);
        return;
    }

    // If pending or running, execute one host per poll cycle (step-by-step background processing)
    if (in_array($task['status'], ['pending', 'running'], true)) {
        $processed = $task['processed_hosts'];
        $total = $task['total_hosts'];

        if ($processed < $total) {
            $host = $task['hosts'][$processed];
            $task['status'] = 'running';
            $task['current_host'] = $host;
            $queue->saveTask($scanId, $task);

            $runner = new AuditRunner();
            $res = $runner->auditSingle($host, $task['options'] ?? []);

            $task['results'][] = $res;
            $task['processed_hosts'] = $processed + 1;
            $task['progress'] = (int)((($processed + 1) / $total) * 100);

            if ($task['processed_hosts'] >= $total) {
                $task['status'] = 'completed';
                $task['current_host'] = '';
                $task['progress'] = 100;
            }
            $queue->saveTask($scanId, $task);
        }
    }

    echo json_encode([
        'success' => true,
        'data' => $task
    ]);
}

/**
 * Handle List of Scans
 */
function handleListScans(): void {
    $queue = new TaskQueue();
    $scans = $queue->listScans(15);
    echo json_encode(['success' => true, 'data' => $scans]);
}

/**
 * Handle SSH In-Host Audit
 */
function handleSshAudit(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'audit',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null
    ]);
    echo json_encode($result);
}

/**
 * Handle SSH In-Host Automated Remediation
 */
function handleSshHarden(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'harden',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null,
        'options' => [
            'nesting_level' => 16,
            'disable_upload_progress' => true,
            'timezone' => $_POST['timezone'] ?? ''
        ]
    ]);
    echo json_encode($result);
}

/**
 * Handle SSH Official Mahkamah Agung RI CentOS 7 SIPP Patch
 */
function handleSshMariPatch(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'mari_patch',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null
    ]);
    echo json_encode($result);
}

/**
 * Handle SSH Distro-native Security Package Upgrade (Ubuntu/Debian apt or AlmaLinux/RHEL dnf)
 */
function handleSshDistroUpgrade(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'distro_upgrade',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null
    ]);
    echo json_encode($result);
}

/**
 * Handle SSH Instant Full Security Remediation & Patching (All-in-One: Binary Patch + php.ini Hardening + Service Reload)
 */
function handleSshInstantPatch(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'instant_patch',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null,
        'options' => [
            'nesting_level' => 16,
            'disable_upload_progress' => true,
            'timezone' => $_POST['timezone'] ?? ''
        ]
    ]);
    echo json_encode($result);
}

/**
 * Handle SSH In-Host Indicators of Compromise (IoC) Assessment
 */
function handleSshCheckCompromise(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'check_compromise',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null
    ]);
    echo json_encode($result);
}

/**
 * Handle SSH Emergency Incident Quarantine Action
 */
function handleSshQuarantine(): void {
    $hardener = new SshHardener();
    $result = $hardener->execute([
        'action' => 'quarantine',
        'host' => $_POST['host'] ?? '',
        'port' => (int)($_POST['port'] ?? 22),
        'user' => $_POST['user'] ?? 'root',
        'password' => $_POST['password'] ?? null,
        'private_key' => $_POST['private_key'] ?? null,
        'sudo_password' => $_POST['sudo_password'] ?? null
    ]);
    echo json_encode($result);
}

/**
 * Handle Config Snippet Generation
 */
function handleGetConfig(): void {
    $type = $_GET['type'] ?? 'phpini';
    $domain = trim($_GET['domain'] ?? 'sipp.pn-contoh.go.id');
    if (!preg_match('/^[a-zA-Z0-9.-]+$/', $domain)) {
        $domain = 'sipp.pn-contoh.go.id';
    }

    $config = '';
    switch ($type) {
        case 'phpini':
            $config = ConfigGenerator::generatePhpIni();
            break;
        case 'nginx':
            $config = ConfigGenerator::generateNginx($domain);
            break;
        case 'reverse_proxy':
            $config = ConfigGenerator::generateReverseProxy($domain);
            break;
        case 'modsecurity':
            $config = ConfigGenerator::generateModSecurity();
            break;
        case 'bash_ubuntu':
            $config = ConfigGenerator::generateBashScript('ubuntu');
            break;
        case 'bash_centos7':
            $config = ConfigGenerator::generateBashScript('centos7');
            break;
        case 'bash_mari_centos7':
            $config = ConfigGenerator::generateBashScript('bash_mari_centos7');
            break;
        case 'bash_almalinux':
            $config = ConfigGenerator::generateBashScript('almalinux');
            break;
        case 'p2s_modsecurity':
        case 'p2s_suricata':
        case 'p2s_sigma':
        case 'p2s_lua':
        case 'owasp_crs_php':
        case 'owasp_crs_proto':
            $config = ConfigGenerator::getEngineFile($type);
            break;
        default:
            $config = ConfigGenerator::generatePhpIni();
            break;
    }

    echo json_encode([
        'success' => true,
        'type' => $type,
        'content' => $config
    ]);
}

/**
 * Handle Safe PoC Pen-Test Simulation Demo
 */
function handleDemoTest(): void {
    $targetUrl = trim($_POST['target_url'] ?? $_GET['target_url'] ?? '');
    if (empty($targetUrl)) {
        echo json_encode(['success' => false, 'error' => 'Target URL wajib disertakan untuk simulasi.']);
        return;
    }

    $originIp = trim($_POST['origin_ip'] ?? $_GET['origin_ip'] ?? '');
    $preflight = NetworkPreFlight::verifyTarget($targetUrl, 4, $originIp);
    if (!$preflight['reachable']) {
        echo json_encode([
            'success' => true,
            'reachable' => false,
            'target' => $targetUrl,
            'direct_origin_ip' => $originIp ?: null,
            'is_direct_origin' => !empty($originIp),
            'status' => 'UNREACHABLE',
            'urgency' => 'OFFLINE',
            'alert_title' => 'KONEKSI KE TARGET GAGAL / HOST OFFLINE',
            'alert_subtitle' => $preflight['title'],
            'action_message' => $preflight['message'],
            'tested_at' => gmdate('Y-m-d\TH:i:s\Z')
        ]);
        return;
    }

    $runner = new AuditRunner();
    $result = $runner->auditSingle($preflight['clean_url'], ['timeout' => 20, 'origin_ip' => $originIp]);

    $p2s = $result['php2shell'] ?? [];
    $isVuln = ($p2s['vulnerable'] ?? false) === true;
    $isPotentiallyVuln = ($p2s['status'] ?? '') === 'POTENTIALLY_VULNERABLE';
    $evidence = $p2s['evidence'] ?? null;
    $phpVersion = $p2s['php_version'] ?? 'Unknown';

    if ($isVuln) {
        $alertTitle = 'PENETRASI BERHASIL DIKONFIRMASI RENTAN';
        $alertSubtitle = 'Handler alokasi memori PHP memicu Zend Heap Exhaustion akibat parsing Session Upload Progress (CVE-2026-109618/19)! Celah terbuka lebar dan dapat dieksploitasi.';
        $urgency = 'CRITICAL';
        $actionMessage = 'SEGERA LAKUKAN PATCH & HARDENING PADA SERVER INI!';
    } elseif ($isPotentiallyVuln) {
        $alertTitle = 'VERSI PHP TERDETEKSI BELUM DIPATCH';
        $alertSubtitle = "Versi PHP ($phpVersion) rentan terhadap CVE-2026-109618/19. Probe memori saat ini tertahan (kemungkinan upload progress nonaktif atau di-filter oleh web server/WAF).";
        $urgency = 'HIGH';
        $actionMessage = 'Disarankan segera memperbarui versi PHP atau menerapkan aturan hardening.';
    } else {
        $alertTitle = 'PENETRASI DITOLAK / SERVER TERLINDUNGI';
        $alertSubtitle = 'Target tidak merespons payload multipart fuzzer dengan crash alokasi memori. Server telah aman.';
        $urgency = 'SAFE';
        $actionMessage = 'Server ini telah memenuhi standar proteksi PHP2Shell.';
    }

    echo json_encode([
        'success' => true,
        'reachable' => true,
        'target' => $preflight['clean_url'],
        'original_target' => $targetUrl,
        'redirected_to' => $preflight['redirected_url'] ?? null,
        'direct_origin_ip' => $originIp ?: null,
        'is_direct_origin' => !empty($originIp),
        'resolved_ip' => $result['resolved_ip'] ?? $preflight['resolved_ip'] ?? '',
        'status' => $isVuln ? 'VULNERABLE' : ($isPotentiallyVuln ? 'POTENTIALLY_VULNERABLE' : 'SAFE'),
        'urgency' => $urgency,
        'alert_title' => $alertTitle,
        'alert_subtitle' => $alertSubtitle,
        'action_message' => $actionMessage,
        'php_version' => $phpVersion,
        'reason' => $p2s['reason'] ?? '',
        'evidence' => $evidence,
        'probe_verdict' => $p2s['probe']['verdict'] ?? ($isVuln ? 'VULNERABLE' : 'SAFE'),
        'checker_status' => $p2s['checker']['patch_status'] ?? 'unknown',
        'tested_at' => gmdate('Y-m-d\TH:i:s\Z')
    ]);
}
