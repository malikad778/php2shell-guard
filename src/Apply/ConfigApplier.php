<?php

namespace Malikad\Php2ShellGuard\Apply;

class ConfigApplier
{
    private $backupRoot;
    private $rootDir;

    public function __construct($backupRoot = '.php2shell-guard/backups', $rootDir = null)
    {
        $this->backupRoot = $backupRoot;
        $this->rootDir = $rootDir ?: realpath(__DIR__ . '/../..') ?: dirname(dirname(__DIR__));
    }

    public function getTargetDefaults($target)
    {
        $map = array(
            'php-ini' => array(
                'template' => 'templates/php-ini/99-php2shell-mitigation.ini',
                'destination' => '/etc/php/8.3/fpm/conf.d/99-php2shell-mitigation.ini',
                'validator' => 'php -v',
                'reload' => 'systemctl restart php8.3-fpm 2>&1',
            ),
            'fpm' => array(
                'template' => 'templates/fpm/zz-php2shell-pool.conf',
                'destination' => '/etc/php/8.3/fpm/pool.d/zz-php2shell-pool.conf',
                'validator' => 'php-fpm8.3 -t 2>&1 || php-fpm -t 2>&1',
                'reload' => 'systemctl reload php8.3-fpm 2>&1',
            ),
            'nginx' => array(
                'template' => 'templates/nginx/php2shell-mitigation.conf',
                'destination' => '/etc/nginx/conf.d/php2shell-mitigation.conf',
                'validator' => 'nginx -t 2>&1',
                'reload' => 'systemctl reload nginx 2>&1',
            ),
            'apache' => array(
                'template' => 'templates/apache/php2shell-mitigation.conf',
                'destination' => '/etc/apache2/conf-available/php2shell-mitigation.conf',
                'validator' => 'apache2ctl -t 2>&1 || httpd -t 2>&1',
                'reload' => 'systemctl reload apache2 2>&1',
            ),
        );

        return isset($map[$target]) ? $map[$target] : null;
    }

    public function applyTarget($target, $destinationPath = null, $dryRun = true, $reload = false, $customValidator = null)
    {
        $defaults = $this->getTargetDefaults($target);
        if (!$defaults) {
            throw new \InvalidArgumentException("Unknown mitigation target '{$target}'. Supported: php-ini, fpm, nginx, apache.");
        }

        $templateFile = rtrim($this->rootDir, '/\\') . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $defaults['template']);
        if (!file_exists($templateFile)) {
            throw new \RuntimeException("Template file not found: {$templateFile}");
        }

        $snippetContent = file_get_contents($templateFile);
        $dest = $destinationPath ?: $defaults['destination'];
        $validator = $customValidator ?: $defaults['validator'];
        $reloadCmd = $defaults['reload'];

        return $this->applySnippet($dest, $snippetContent, $dryRun, $validator, $reload ? $reloadCmd : null);
    }

    public function applySnippet($destinationPath, $snippetContent, $dryRun = true, $validatorCommand = null, $reloadCommand = null)
    {
        $timestamp = gmdate('Ymd_His');
        $backupDir = rtrim($this->backupRoot, '/\\') . DIRECTORY_SEPARATOR . $timestamp;
        $backupFile = $backupDir . DIRECTORY_SEPARATOR . basename($destinationPath) . '.bak';

        if ($dryRun) {
            return array(
                'applied' => false,
                'dry_run' => true,
                'destination' => $destinationPath,
                'planned_backup' => $backupFile,
                'validator' => $validatorCommand,
                'message' => 'Dry run only. To apply changes with backup and validation, specify --yes.'
            );
        }

        // 1. Create backup if existing destination exists
        $hadExisting = file_exists($destinationPath);
        if ($hadExisting) {
            if (!is_dir($backupDir)) {
                mkdir($backupDir, 0755, true);
            }
            if (!copy($destinationPath, $backupFile)) {
                throw new \RuntimeException("Failed to create backup copy at: {$backupFile}");
            }
        }

        // 2. Ensure parent directory of destination exists and write snippet
        $destDir = dirname($destinationPath);
        if (!is_dir($destDir)) {
            mkdir($destDir, 0755, true);
        }

        file_put_contents($destinationPath, $snippetContent);

        // 3. Validation
        if (!empty($validatorCommand)) {
            $output = array();
            $exitCode = 0;
            @exec($validatorCommand, $output, $exitCode);

            if ($exitCode !== 0) {
                // Validation failed -> Automatic Rollback
                if ($hadExisting && file_exists($backupFile)) {
                    copy($backupFile, $destinationPath);
                    $rollbackMsg = 'Restored original file from backup.';
                } else {
                    @unlink($destinationPath);
                    $rollbackMsg = 'Removed invalid snippet file.';
                }

                return array(
                    'applied' => false,
                    'rolled_back' => true,
                    'dry_run' => false,
                    'destination' => $destinationPath,
                    'backup_file' => $hadExisting ? $backupFile : null,
                    'validation_exit_code' => $exitCode,
                    'validation_output' => implode("\n", $output),
                    'error' => "Configuration validation failed! Automatically rolled back. {$rollbackMsg}"
                );
            }
        }

        // 4. Reload if requested
        $reloaded = false;
        $reloadOutput = null;
        if (!empty($reloadCommand)) {
            $rOutput = array();
            $rExit = 0;
            @exec($reloadCommand, $rOutput, $rExit);
            $reloaded = ($rExit === 0);
            $reloadOutput = implode("\n", $rOutput);
        }

        return array(
            'applied' => true,
            'rolled_back' => false,
            'dry_run' => false,
            'destination' => $destinationPath,
            'backup_file' => $hadExisting ? $backupFile : null,
            'reloaded' => $reloaded,
            'reload_output' => $reloadOutput,
            'message' => 'Configuration validated and applied successfully.'
        );
    }

    public function rollback($backupFile, $destinationPath)
    {
        if (!file_exists($backupFile)) {
            throw new \RuntimeException("Backup file not found: {$backupFile}");
        }

        if (!copy($backupFile, $destinationPath)) {
            throw new \RuntimeException("Failed to restore backup to {$destinationPath}");
        }

        return array(
            'rolled_back' => true,
            'destination' => $destinationPath,
            'restored_from' => $backupFile
        );
    }
}
