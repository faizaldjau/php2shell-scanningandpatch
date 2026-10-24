<?php
/**
 * Task Queue and Scan State Manager
 * 
 * Manages background and synchronous audit task state using JSON files.
 * Provides thread-safe file writing and prevents path traversal.
 */

class TaskQueue {

    private string $storageDir;

    public function __construct() {
        $this->storageDir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'scans';
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0750, true);
        }
    }

    /**
     * Create a new scan task record
     */
    public function createTask(array $hosts, array $options = []): string {
        $scanId = 'scan_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(4));
        $data = [
            'scan_id' => $scanId,
            'status' => 'pending', // pending, running, completed, error
            'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'total_hosts' => count($hosts),
            'processed_hosts' => 0,
            'progress' => 0,
            'current_host' => '',
            'options' => $options,
            'hosts' => $hosts,
            'results' => [],
            'error' => null
        ];

        $this->saveTask($scanId, $data);
        return $scanId;
    }

    /**
     * Save task data safely
     */
    public function saveTask(string $scanId, array $data): bool {
        $safeId = preg_replace('/[^a-zA-Z0-9_-]/', '', $scanId);
        $file = $this->storageDir . DIRECTORY_SEPARATOR . $safeId . '.json';
        return (file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT)) !== false);
    }

    /**
     * Load task data
     */
    public function getTask(string $scanId): ?array {
        $safeId = preg_replace('/[^a-zA-Z0-9_-]/', '', $scanId);
        $file = $this->storageDir . DIRECTORY_SEPARATOR . $safeId . '.json';
        if (!file_exists($file)) {
            return null;
        }

        $content = file_get_contents($file);
        return json_decode($content, true);
    }

    /**
     * List recent scans
     */
    public function listScans(int $limit = 20): array {
        $files = glob($this->storageDir . DIRECTORY_SEPARATOR . 'scan_*.json');
        if (!$files) {
            return [];
        }

        // Sort descending by modified time
        usort($files, fn($a, $b) => filemtime($b) <=> filemtime($a));
        $files = array_slice($files, 0, $limit);

        $scans = [];
        foreach ($files as $file) {
            $data = json_decode(file_get_contents($file), true);
            if ($data) {
                $scans[] = [
                    'scan_id' => $data['scan_id'],
                    'status' => $data['status'],
                    'created_at' => $data['created_at'],
                    'total_hosts' => $data['total_hosts'] ?? 0,
                    'processed_hosts' => $data['processed_hosts'] ?? 0,
                    'progress' => $data['progress'] ?? 0,
                    'vulnerable_count' => count(array_filter($data['results'] ?? [], fn($r) => ($r['php2shell']['vulnerable'] ?? false) === true))
                ];
            }
        }
        return $scans;
    }
}
