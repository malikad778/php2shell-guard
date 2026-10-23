<?php

namespace Malikad\Php2ShellGuard\Db;

class Updater
{
    private $advisoriesDir;
    private $backupDir;
    private $baseUrl;

    public function __construct($advisoriesDir = null, $backupDir = null, $baseUrl = null)
    {
        $base = realpath(__DIR__ . '/../../data/advisories') ?: (dirname(dirname(__DIR__)) . '/data/advisories');
        $this->advisoriesDir = $advisoriesDir ?: $base;
        $this->backupDir = $backupDir ?: (dirname($this->advisoriesDir) . '/advisories.bak');
        $this->baseUrl = $baseUrl ?: 'https://raw.githubusercontent.com/malikad778/php2shell-guard/main/data/advisories/';
    }

    public function getUpdateUrl($filename)
    {
        return rtrim($this->baseUrl, '/') . '/' . rawurlencode($filename);
    }

    public function updateFile($filename, $expectedChecksum = null, $dryRun = false)
    {
        $url = $this->getUpdateUrl($filename);
        $content = @file_get_contents($url);
        if ($content === false) {
            throw new \RuntimeException("Failed to download advisory file from: {$url}");
        }

        $actualChecksum = hash('sha256', $content);
        if ($expectedChecksum !== null && strtolower($actualChecksum) !== strtolower($expectedChecksum)) {
            throw new \RuntimeException("Checksum mismatch for {$filename}. Expected {$expectedChecksum}, got {$actualChecksum}");
        }

        // Verify JSON syntax
        $decoded = json_decode($content, true);
        if (!$decoded || !isset($decoded['id'])) {
            throw new \RuntimeException("Downloaded advisory {$filename} is not valid advisory JSON");
        }

        $destFile = rtrim($this->advisoriesDir, '/\\') . DIRECTORY_SEPARATOR . basename($filename);

        if ($dryRun) {
            return array(
                'dry_run' => true,
                'file' => $filename,
                'sha256' => $actualChecksum,
                'destination' => $destFile
            );
        }

        // Backup existing
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
        if (file_exists($destFile)) {
            copy($destFile, rtrim($this->backupDir, '/\\') . DIRECTORY_SEPARATOR . basename($filename));
        }

        file_put_contents($destFile, $content);

        return array(
            'updated' => true,
            'dry_run' => false,
            'file' => $filename,
            'sha256' => $actualChecksum,
            'destination' => $destFile
        );
    }

    public function backupDatabase()
    {
        if (!is_dir($this->advisoriesDir)) {
            return false;
        }
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
        $files = scandir($this->advisoriesDir);
        foreach ($files as $file) {
            if ($file !== '.' && $file !== '..' && is_file($this->advisoriesDir . '/' . $file)) {
                copy($this->advisoriesDir . '/' . $file, $this->backupDir . '/' . $file);
            }
        }
        return true;
    }

    public function restoreBackup()
    {
        if (!is_dir($this->backupDir)) {
            return false;
        }
        $files = scandir($this->backupDir);
        foreach ($files as $file) {
            if ($file !== '.' && $file !== '..' && is_file($this->backupDir . '/' . $file)) {
                copy($this->backupDir . '/' . $file, $this->advisoriesDir . '/' . $file);
            }
        }
        return true;
    }
}
