<?php
/**
 * In-Host SSH Auditor and Hardener Wrapper
 * 
 * Safely invokes engine/ssh_runner.py using proc_open with STDIN pipe
 * to avoid leaking credentials to the process command line or disk logs.
 */

class SshHardener {

    private string $pythonBin;
    private string $scriptPath;

    public function __construct() {
        // Use Laragon Python path or fallback to system python
        $laragonPython = 'C:\\laragon\\bin\\python\\python-3.13\\python.exe';
        if (file_exists($laragonPython)) {
            $this->pythonBin = $laragonPython;
        } else {
            $this->pythonBin = 'python';
        }
        $this->scriptPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'engine' . DIRECTORY_SEPARATOR . 'ssh_runner.py';
    }

    /**
     * Executes In-Host Audit or Hardening via SSH
     */
    public function execute(array $params): array {
        // Validate required fields
        $host = trim($params['host'] ?? '');
        $user = trim($params['user'] ?? '');
        $port = (int)($params['port'] ?? 22);
        $action = in_array($params['action'] ?? '', ['audit', 'harden', 'mari_patch', 'distro_upgrade', 'instant_patch', 'check_compromise', 'quarantine'], true) ? $params['action'] : 'audit';

        if (empty($host) || empty($user)) {
            return [
                'success' => false,
                'error' => 'Host dan User SSH wajib diisi.'
            ];
        }

        // Host validation (IP address or valid domain)
        if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
            return [
                'success' => false,
                'error' => 'Format Host/IP tidak valid.'
            ];
        }

        $payload = [
            'action' => $action,
            'host' => $host,
            'port' => $port,
            'user' => $user,
            'password' => $params['password'] ?? null,
            'private_key' => $params['private_key'] ?? null,
            'sudo_password' => $params['sudo_password'] ?? null,
            'options' => $params['options'] ?? []
        ];

        $descriptors = [
            0 => ['pipe', 'r'], // STDIN (read by python)
            1 => ['pipe', 'w'], // STDOUT (read by php)
            2 => ['pipe', 'w']  // STDERR (read by php)
        ];

        $cmd = escapeshellarg($this->pythonBin) . ' ' . escapeshellarg($this->scriptPath);
        $process = proc_open($cmd, $descriptors, $pipes);

        if (!is_resource($process)) {
            return [
                'success' => false,
                'error' => 'Gagal menginisialisasi proses SSH Runner.'
            ];
        }

        // Write payload to STDIN and close pipe
        fwrite($pipes[0], json_encode($payload));
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        $result = json_decode($stdout, true);
        if ($result === null) {
            return [
                'success' => false,
                'error' => 'Respon SSH Runner tidak valid: ' . ($stderr ?: $stdout)
            ];
        }

        return $result;
    }
}
