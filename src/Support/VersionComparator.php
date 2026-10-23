<?php

namespace Malikad\Php2ShellGuard\Support;

class VersionComparator
{
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
        return (bool) preg_match('/(ubuntu|deb|el[0-9]|amzn|alpine|-r[0-9]+)/i', (string) $raw);
    }

    public static function evaluateProduct($product, $rawVersion, $staleWorker = false, $changelogPatched = false)
    {
        $semver = self::extractSemver($rawVersion);
        if ($semver === '') {
            return array(
                'status' => Status::UNKNOWN,
                'fixed' => 'unknown',
                'branch' => 'unknown',
                'notes' => "Could not parse {$product} version string"
            );
        }

        $parts = explode('.', $semver);
        $major = (int) $parts[0];
        $minor = isset($parts[1]) ? (int) $parts[1] : 0;
        $branch = ($product === 'nodejs') ? (string) $major : ($major . '.' . $minor);
        $isPrerelease = (bool) preg_match('/(-dev|alpha|beta|rc)/i', (string) $rawVersion);

        $rules = array('branches' => array(), 'cves' => array());
        try {
            $loader = new \Malikad\Php2ShellGuard\Db\Loader();
            $rules = $loader->getEffectiveRulesForProduct($product);
        } catch (\Exception $e) {}

        $cves = !empty($rules['cves']) ? $rules['cves'] : array();
        $cveStr = !empty($cves) ? implode(' and ', $cves) : 'security advisory rules';

        if ($changelogPatched) {
            return array(
                'status' => $staleWorker ? Status::PATCHED_NOT_RESTARTED : Status::PATCHED_BACKPORT,
                'fixed' => 'distro-backport',
                'branch' => $branch,
                'cves' => $cves,
                'notes' => $staleWorker
                    ? 'Distro changelog confirms security fix, but running worker process still uses old binary'
                    : "Distro changelog confirms backported security fixes ({$cveStr})"
            );
        }

        // 1. Check if branch is dynamically defined in advisories
        if (isset($rules['branches'][$branch])) {
            $bData = $rules['branches'][$branch];

            if (!empty($bData['eol'])) {
                if (self::isDistroPackage($rawVersion)) {
                    return array(
                        'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                        'fixed' => 'vendor-backport',
                        'branch' => $branch,
                        'cves' => $cves,
                        'notes' => "EOL branch {$branch} on distro package; inspect changelog for backported fixes ({$cveStr})"
                    );
                }
                return array(
                    'status' => Status::EOL_NO_OFFICIAL_RELEASE,
                    'fixed' => 'none',
                    'branch' => $branch,
                    'cves' => $cves,
                    'notes' => !empty($bData['has_source_backport'])
                        ? "No official release for {$branch}; upstream published minimal source backports for vendor packaging"
                        : "End-of-life branch {$branch} receives no official security updates"
                );
            }

            if (!empty($bData['fixed'])) {
                $fixed = $bData['fixed'];
                if (version_compare($semver, $fixed, '>=') && !$isPrerelease) {
                    return array(
                        'status' => $staleWorker ? Status::PATCHED_NOT_RESTARTED : Status::PATCHED,
                        'fixed' => $fixed,
                        'branch' => $branch,
                        'cves' => $cves,
                        'notes' => $staleWorker
                            ? "Binary on disk is >= {$fixed}, but running workers have not been restarted"
                            : "Version {$semver} meets or exceeds fixed release {$fixed}"
                    );
                }
                if (self::isDistroPackage($rawVersion)) {
                    return array(
                        'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                        'fixed' => $fixed,
                        'branch' => $branch,
                        'cves' => $cves,
                        'notes' => "Version {$semver} is below {$fixed}, but distro package may carry backports"
                    );
                }
                return array(
                    'status' => Status::VULNERABLE_PATCH_AVAILABLE,
                    'fixed' => $fixed,
                    'branch' => $branch,
                    'cves' => $cves,
                    'notes' => "Version {$rawVersion} is below fixed release {$fixed} ({$cveStr})"
                );
            }
        }

        // 2. Legacy / Fallback defaults for legacy PHP and Node branches
        if ($product === 'php') {
            if ($major < 8 || $branch === '8.0' || $branch === '8.1') {
                if (self::isDistroPackage($rawVersion)) {
                    return array(
                        'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                        'fixed' => 'vendor-backport',
                        'branch' => $branch,
                        'cves' => $cves,
                        'notes' => 'EOL branch ' . $branch . ' from distro package; inspect changelog for CVE-2026-109618 and CVE-2026-109619'
                    );
                }
                $hasSourceBackport = in_array($branch, array('7.4', '8.0', '8.1'), true);
                return array(
                    'status' => Status::EOL_NO_OFFICIAL_RELEASE,
                    'fixed' => 'none (upgrade to 8.3.36 or 8.4.27)',
                    'branch' => $branch,
                    'cves' => $cves,
                    'notes' => $hasSourceBackport
                        ? 'No official php.net release for ' . $branch . '; PHP published minimal source backports for vendors'
                        : 'End-of-life PHP branch ' . $branch . ' with no official release (earliest affected path dates to PHP 5.4.0)'
                );
            }
        } elseif ($product === 'nodejs') {
            if ($major < 22 || in_array($major, array(18, 20, 23, 25), true)) {
                return array(
                    'status' => Status::EOL_NO_OFFICIAL_RELEASE,
                    'fixed' => 'none (upgrade to 22.23.4 or 24.22.1)',
                    'branch' => (string) $major,
                    'cves' => $cves,
                    'notes' => 'Node.js ' . $major . '.x is EOL and receives no fix for CVE-2026-111497'
                );
            }
        }

        return array(
            'status' => Status::UNKNOWN,
            'fixed' => 'unknown',
            'branch' => $branch,
            'cves' => $cves,
            'notes' => "Branch {$branch} is newer than advisory database"
        );
    }

    public static function evaluatePhp($rawVersion, $staleWorker = false, $changelogPatched = false)
    {
        return self::evaluateProduct('php', $rawVersion, $staleWorker, $changelogPatched);
    }

    public static function evaluateNode($rawVersion, $staleWorker = false)
    {
        return self::evaluateProduct('nodejs', $rawVersion, $staleWorker);
    }
}
