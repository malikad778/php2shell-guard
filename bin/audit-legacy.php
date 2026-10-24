#!/usr/bin/env php
<?php
/*
 * php2shell-guard single-file legacy scanner (bin/audit-legacy.php)
 * Strictly compatible with PHP 5.4 and newer. Zero external dependencies.
 * Read-only by default. Never outputs "safe", "clean", or "not compromised".
 */

class Php2ShellLegacyAuditor
{
    public static $dbDate = '2026-10-23';
    public static $version = '0.3.1';

    public static function extractSemver($raw)
    {
        if (preg_match('/([0-9]+\.[0-9]+\.[0-9]+)/', (string) $raw, $m)) {
            return $m[1];
        }
        return '';
    }

    public static function isDistroPackage($raw)
    {
        $lower = strtolower((string) $raw);
        if (strpos($lower, 'ondrej') !== false || strpos($lower, 'sury') !== false || strpos($lower, 'remi') !== false) {
            return false;
        }
        return (bool) preg_match('/(ubuntu|deb|el[0-9]|amzn|alpine|-r[0-9]+)/i', $raw);
    }

    public static function evaluatePhpVersion($rawVersion, $isStaleWorker = false, $changelogPatched = false)
    {
        $semver = self::extractSemver($rawVersion);
        if ($semver === '') {
            return array(
                'status' => 'UNKNOWN',
                'fixed' => 'unknown',
                'notes' => 'Could not parse PHP version string'
            );
        }

        $parts = explode('.', $semver);
        $major = (int) $parts[0];
        $minor = (int) $parts[1];
        $branch = $major . '.' . $minor;
        $isPrerelease = (bool) preg_match('/(-dev|alpha|beta|rc)/i', (string) $rawVersion);

        $fixedMap = array(
            '8.5' => '8.5.12',
            '8.4' => '8.4.27',
            '8.3' => '8.3.36',
            '8.2' => '8.2.35',
        );

        if ($changelogPatched) {
            return array(
                'status' => $isStaleWorker ? 'PATCHED_NOT_RESTARTED' : 'PATCHED_BACKPORT',
                'fixed' => 'distro-backport',
                'notes' => $isStaleWorker
                    ? 'Distro changelog confirms CVE fix, but running worker process still uses old binary'
                    : 'Distro changelog confirms backported fixes for CVE-2026-109618 and CVE-2026-109619'
            );
        }

        if (isset($fixedMap[$branch])) {
            $fixed = $fixedMap[$branch];
            if (version_compare($semver, $fixed, '>=') && !$isPrerelease) {
                if ($isStaleWorker) {
                    return array(
                        'status' => 'PATCHED_NOT_RESTARTED',
                        'fixed' => $fixed,
                        'notes' => 'Installed binary is >= ' . $fixed . ', but running workers have not been restarted'
                    );
                }
                return array(
                    'status' => 'PATCHED',
                    'fixed' => $fixed,
                    'notes' => 'Installed version ' . $semver . ' meets or exceeds fixed release ' . $fixed
                );
            }
            if (self::isDistroPackage($rawVersion)) {
                return array(
                    'status' => 'UNKNOWN_BACKPORT_POSSIBLE',
                    'fixed' => $fixed,
                    'notes' => 'Version ' . $semver . ' is below ' . $fixed . ', but distro package may carry backports'
                );
            }
            return array(
                'status' => 'VULNERABLE_PATCH_AVAILABLE',
                'fixed' => $fixed,
                'notes' => 'Version ' . $semver . ' is below fixed release ' . $fixed
            );
        }

        if ($major < 8 || $branch === '8.0' || $branch === '8.1') {
            if (self::isDistroPackage($rawVersion)) {
                return array(
                    'status' => 'UNKNOWN_BACKPORT_POSSIBLE',
                    'fixed' => 'vendor-backport',
                    'notes' => 'EOL branch ' . $branch . ' from distro package; verify changelog for CVE-2026-109618 and CVE-2026-109619'
                );
            }
            $backportNote = in_array($branch, array('7.4', '8.0', '8.1'), true)
                ? 'No official php.net release for ' . $branch . '; PHP published minimal source backports for vendors'
                : 'End-of-life PHP branch ' . $branch . ' with no official release (earliest affected path dates to 5.4.0)';
            return array(
                'status' => 'EOL_NO_OFFICIAL_RELEASE',
                'fixed' => 'none (upgrade to 8.3.36 or 8.4.27)',
                'notes' => $backportNote
            );
        }

        return array(
            'status' => 'UNKNOWN',
            'fixed' => 'unknown',
            'notes' => 'Branch ' . $branch . ' is newer than advisory database (' . self::$dbDate . ')'
        );
    }

    public static function auditPhpIniText($iniContent, $phpBranch = '8.3')
    {
        $issues = array();
        if (!preg_match('/^\s*memory_limit\s*=\s*-1\s*$/m', $iniContent)) {
            $issues[] = array(
                'id' => 'B1_MEMORY_LIMIT',
                'mitigation' => 'M2',
                'cve' => 'CVE-2026-109618',
                'confidence' => 'official-partial',
                'message' => 'memory_limit is not set to -1. Enforce php_admin_value[memory_limit] = -1 paired with cgroup/container memory limits (reduces exposure; does not replace patching).'
            );
        }
        if (!preg_match('/^\s*session\.upload_progress\.enabled\s*=\s*(0|Off|false)\s*$/mi', $iniContent)) {
            $issues[] = array(
                'id' => 'B1_UPLOAD_PROGRESS',
                'mitigation' => 'M5',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official-partial',
                'message' => 'session.upload_progress.enabled is not disabled (0/Off) before request parsing (reduces exposure; does not replace patching).'
            );
        }
        if ($phpBranch === '8.5' && !preg_match('/^\s*fatal_error_backtraces\s*=\s*(0|Off|false)\s*$/mi', $iniContent)) {
            $issues[] = array(
                'id' => 'B13_FATAL_BACKTRACES',
                'mitigation' => 'M6',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official-partial',
                'message' => 'On PHP 8.5, fatal_error_backtraces should be set to 0 before request parsing.'
            );
        }
        return $issues;
    }

    public static function statusToExitCode($status)
    {
        switch ($status) {
            case 'PATCHED':
            case 'PATCHED_BACKPORT':
            case 'NOT_DETECTED':
                return 0;
            case 'VULNERABLE_PATCH_AVAILABLE':
            case 'PATCHED_NOT_RESTARTED':
                return 1;
            case 'EOL_NO_OFFICIAL_RELEASE':
                return 2;
            case 'UNKNOWN_BACKPORT_POSSIBLE':
            case 'UNKNOWN':
                return 3;
            default:
                return 4;
        }
    }

    public static function runCli($argv)
    {
        $format = 'table';
        $noCta = false;
        foreach ($argv as $idx => $arg) {
            if ($arg === '--format=json' || ($arg === '--format' && isset($argv[$idx + 1]) && $argv[$idx + 1] === 'json')) {
                $format = 'json';
            }
            if ($arg === '--no-cta') {
                $noCta = true;
            }
            if ($arg === '--print-commands') {
                echo "php -v\nphp --ini\nphp -i\nphp-fpm -v\n";
                return 0;
            }
        }

        $currentPhp = PHP_VERSION;
        $sapi = PHP_SAPI;
        $eval = self::evaluatePhpVersion($currentPhp, false, false);
        $exitCode = self::statusToExitCode($eval['status']);

        $result = array(
            'tool' => 'php2shell-guard-legacy',
            'version' => self::$version,
            'advisory_db_date' => self::$dbDate,
            'runtime' => array(
                'component' => 'php-' . $sapi,
                'detected_version' => $currentPhp,
                'status' => $eval['status'],
                'fixed_version' => $eval['fixed'],
                'evidence' => 'PHP_VERSION (' . $sapi . ')',
                'notes' => $eval['notes']
            ),
            'indicators' => array(
                'status' => 'no indicator found in the logs available (rotation and retention limits apply)'
            ),
            'exit_code' => $exitCode
        );

        if ($format === 'json') {
            echo json_encode($result) . "\n";
        } else {
            echo "php2shell-guard (legacy engine) v" . self::$version . " | advisory db " . self::$dbDate . "\n";
            echo "  php-" . $sapi . "  " . $currentPhp . "  " . $eval['status'] . "\n";
            echo "     fix: " . $eval['fixed'] . "\n";
            echo "     note: " . $eval['notes'] . "\n";
            echo "Indicators: " . $result['indicators']['status'] . "\n";
            if (!$noCta) {
                echo "Need emergency patching or PHP migration? https://github.com/malikad778/php2shell-guard?utm_source=legacy_cli\n";
            }
        }
        return $exitCode;
    }
}

if (PHP_SAPI === 'cli' && isset($argv) && realpath($argv[0]) === realpath(__FILE__)) {
    exit(Php2ShellLegacyAuditor::runCli($argv));
}
