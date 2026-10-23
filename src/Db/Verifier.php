<?php

namespace Malikad\Php2ShellGuard\Db;

class Verifier
{
    public function verify($rootDir = null)
    {
        $advDir = $rootDir ? rtrim($rootDir, '/\\') . '/data/advisories' : __DIR__ . '/../../data/advisories';
        if (!is_dir($advDir)) {
            return array(
                'valid' => false,
                'checked_files' => array(),
                'errors' => array("Advisory directory not found: {$advDir}")
            );
        }

        $files = array();
        $handle = opendir($advDir);
        if ($handle) {
            while (false !== ($entry = readdir($handle))) {
                if ($entry !== '.' && $entry !== '..' && substr($entry, -5) === '.json') {
                    $files[] = $entry;
                }
            }
            closedir($handle);
        }
        sort($files);

        $errors = array();
        $now = time();

        foreach ($files as $file) {
            $filePath = $advDir . '/' . $file;
            $raw = file_get_contents($filePath);
            $data = json_decode($raw, true);

            if (!is_array($data)) {
                $errors[] = "{$file}: invalid JSON format";
                continue;
            }

            $arrRes = $this->verifyAdvisoryArray($data);
            foreach ($arrRes['errors'] as $err) {
                $errors[] = "{$file}: {$err}";
            }

            // Confidence check
            if (isset($data['mitigations']) && is_array($data['mitigations'])) {
                $validConf = array('official', 'official-partial', 'vendor-reported', 'reasoning-based');
                foreach ($data['mitigations'] as $m) {
                    if (isset($m['confidence']) && !in_array($m['confidence'], $validConf, true)) {
                        $errors[] = "{$file}: mitigation " . (isset($m['id']) ? $m['id'] : '?') . " has invalid confidence label '{$m['confidence']}'";
                    }
                }
            }

            // Freshness check: within 30 days
            if (!empty($data['last_verified'])) {
                $verifiedTime = strtotime($data['last_verified'] . ' UTC');
                if ($verifiedTime) {
                    $ageDays = floor(($now - $verifiedTime) / 86400);
                    if ($ageDays > 30) {
                        $errors[] = "{$file}: last_verified ({$data['last_verified']}) is older than 30 days ({$ageDays} days)";
                    }
                }
            }
        }

        return array(
            'valid' => empty($errors),
            'checked_files' => $files,
            'errors' => $errors
        );
    }

    public function verifyAdvisoryArray(array $advisory)
    {
        $errors = array();
        $required = array('id', 'title', 'product', 'cves', 'severity', 'published', 'branches', 'mitigations', 'sources', 'exploitation', 'last_verified');
        foreach ($required as $key) {
            if (!array_key_exists($key, $advisory)) {
                $errors[] = 'Missing required field: ' . $key;
            }
        }
        if (!isset($advisory['sources']) || count($advisory['sources']) < 2) {
            $errors[] = 'Two-source rule violated: at least 2 independent sources are required.';
        }
        return array('valid' => empty($errors), 'errors' => $errors);
    }
}
