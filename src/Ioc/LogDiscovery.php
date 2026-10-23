<?php

namespace Malikad\Php2ShellGuard\Ioc;

class LogDiscovery
{
    private $ignoredDirectories = array(
        'fixtures',
        'vendor',
        'node_modules',
        '.git',
        '.idea',
        'cache',
    );

    public function discover($targetPath = '.')
    {
        $discovered = array();

        // 1. If explicit file was passed and exists
        if (is_file($targetPath)) {
            $discovered[] = realpath($targetPath) ?: $targetPath;
            return $discovered;
        }

        // 2. Read PHP ini error_log if defined
        $iniErrorLog = ini_get('error_log');
        if (!empty($iniErrorLog) && $iniErrorLog !== 'no value' && is_file($iniErrorLog) && is_readable($iniErrorLog)) {
            $discovered[] = realpath($iniErrorLog) ?: $iniErrorLog;
        }

        // 3. Check common daemon error log paths
        $systemPaths = array(
            '/var/log/php-fpm/www-error.log',
            '/var/log/php-fpm/error.log',
            '/var/log/php-fpm.log',
            '/var/log/php8.4-fpm.log',
            '/var/log/php8.3-fpm.log',
            '/var/log/php8.2-fpm.log',
            '/var/log/php8.1-fpm.log',
            '/var/log/php/error.log',
            '/var/log/apache2/error.log',
            '/var/log/httpd/error_log',
            '/var/log/nginx/error.log',
            '/var/log/syslog',
            '/var/log/messages',
        );

        foreach ($systemPaths as $path) {
            if (is_file($path) && is_readable($path)) {
                $discovered[] = $path;
            }
        }

        // 4. Search directory for *.log files, excluding fixtures/vendor/node_modules
        if (is_dir($targetPath)) {
            $this->scanDirectoryForLogs($targetPath, $discovered, 0, 3);
        }

        return array_values(array_unique($discovered));
    }

    private function scanDirectoryForLogs($dir, array &$results, $currentDepth, $maxDepth)
    {
        if ($currentDepth > $maxDepth) {
            return;
        }

        $items = @scandir($dir);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $fullPath = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item;

            if (is_dir($fullPath)) {
                if ($this->isIgnoredDirectory($item)) {
                    continue;
                }
                $this->scanDirectoryForLogs($fullPath, $results, $currentDepth + 1, $maxDepth);
            } elseif (is_file($fullPath)) {
                if (preg_match('/\.log$/i', $item)) {
                    $results[] = realpath($fullPath) ?: $fullPath;
                }
            }
        }
    }

    private function isIgnoredDirectory($dirname)
    {
        return in_array(strtolower($dirname), $this->ignoredDirectories, true);
    }
}
