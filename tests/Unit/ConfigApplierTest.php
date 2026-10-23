<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Apply\ConfigApplier;

class ConfigApplierTest
{
    public function run()
    {
        $tmpDir = sys_get_temp_dir() . '/php2shell_test_' . uniqid();
        mkdir($tmpDir, 0755, true);
        $backupDir = $tmpDir . '/backups';
        $targetFile = $tmpDir . '/test-config.ini';

        file_put_contents($targetFile, "original_setting = 1\n");

        $applier = new ConfigApplier($backupDir, __DIR__ . '/../..');

        // 1. Dry run
        $dryRes = $applier->applySnippet($targetFile, "new_setting = 2\n", true);
        if ($dryRes['applied'] !== false || !$dryRes['dry_run']) {
            throw new \RuntimeException('ConfigApplier dry-run failed to return dry_run=true');
        }
        if (file_get_contents($targetFile) !== "original_setting = 1\n") {
            throw new \RuntimeException('ConfigApplier dry-run modified target file');
        }

        // 2. Successful apply with passing validator (echo test)
        $passValidator = PHP_OS_FAMILY === 'Windows' ? 'cmd /c exit 0' : 'true';
        $applyRes = $applier->applySnippet($targetFile, "new_setting = 2\n", false, $passValidator);
        if (!$applyRes['applied'] || $applyRes['rolled_back']) {
            throw new \RuntimeException('ConfigApplier failed to apply with passing validator');
        }
        if (file_get_contents($targetFile) !== "new_setting = 2\n") {
            throw new \RuntimeException('ConfigApplier did not update target file');
        }
        if (!file_exists($applyRes['backup_file']) || file_get_contents($applyRes['backup_file']) !== "original_setting = 1\n") {
            throw new \RuntimeException('ConfigApplier failed to create valid backup file');
        }

        // 3. Failed validation -> Automatic Rollback
        $failValidator = PHP_OS_FAMILY === 'Windows' ? 'cmd /c exit 1' : 'false';
        $failRes = $applier->applySnippet($targetFile, "invalid_setting = 999\n", false, $failValidator);
        if ($failRes['applied'] !== false || !$failRes['rolled_back']) {
            throw new \RuntimeException('ConfigApplier failed to trigger rollback on validator failure');
        }
        if (file_get_contents($targetFile) !== "new_setting = 2\n") {
            throw new \RuntimeException('ConfigApplier rollback failed to restore previous file content');
        }

        // Clean up
        @unlink($targetFile);
        if (file_exists($applyRes['backup_file'])) {
            @unlink($applyRes['backup_file']);
        }
        @rmdir(dirname($applyRes['backup_file']));
        @rmdir($backupDir);
        @rmdir($tmpDir);

        return true;
    }
}
