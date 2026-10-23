<?php

namespace Malikad\Php2ShellGuard\Upgrade;

class ComposerWhyNot
{
    private $frameworkPhpMatrix = array(
        'laravel/framework' => array(
            '6' => array('min_php' => '7.2', 'max_php' => '8.0', 'upgrade_target' => 'Laravel 10.x / 11.x'),
            '7' => array('min_php' => '7.2', 'max_php' => '8.0', 'upgrade_target' => 'Laravel 10.x / 11.x'),
            '8' => array('min_php' => '7.3', 'max_php' => '8.1', 'upgrade_target' => 'Laravel 10.x / 11.x'),
            '9' => array('min_php' => '8.0', 'max_php' => '8.2', 'upgrade_target' => 'Laravel 10.x / 11.x'),
            '10' => array('min_php' => '8.1', 'max_php' => '8.3', 'upgrade_target' => 'Laravel 11.x for PHP 8.4'),
            '11' => array('min_php' => '8.2', 'max_php' => '8.4', 'upgrade_target' => 'Native PHP 8.3/8.4 support'),
            '12' => array('min_php' => '8.2', 'max_php' => '8.4', 'upgrade_target' => 'Native PHP 8.3/8.4 support'),
        ),
        'phpunit/phpunit' => array(
            '8' => array('min_php' => '7.2', 'max_php' => '8.0', 'upgrade_target' => 'PHPUnit 10.x / 11.x'),
            '9' => array('min_php' => '7.3', 'max_php' => '8.2', 'upgrade_target' => 'PHPUnit 10.x / 11.x'),
        ),
        'doctrine/orm' => array(
            '2' => array('min_php' => '7.1', 'max_php' => '8.2', 'upgrade_target' => 'Doctrine ORM 3.x'),
        )
    );

    public function findBlockers(array $composerData, $targetPhp = '8.3', array $lockData = array())
    {
        $blockers = array();
        $require = isset($composerData['require']) && is_array($composerData['require']) ? $composerData['require'] : array();
        $requireDev = isset($composerData['require-dev']) && is_array($composerData['require-dev']) ? $composerData['require-dev'] : array();
        $allPkgs = array_merge($require, $requireDev);

        // 1. Root require.php
        if (isset($require['php'])) {
            $phpConstraint = $require['php'];
            if (!$this->constraintAllowsPhp($phpConstraint, $targetPhp)) {
                $blockers[] = array(
                    'package' => 'php',
                    'constraint' => $phpConstraint,
                    'reason' => "Root composer.json require.php constraint '{$phpConstraint}' does not satisfy target PHP {$targetPhp}."
                );
            }
        }

        // 2. config.platform.php check
        if (isset($composerData['config']['platform']['php'])) {
            $platPhp = $composerData['config']['platform']['php'];
            if (version_compare($platPhp, $targetPhp, '<')) {
                $blockers[] = array(
                    'package' => 'config.platform.php',
                    'constraint' => $platPhp,
                    'reason' => "composer.json config.platform.php is pinned to '{$platPhp}', which forces composer to resolve packages for an older PHP version than target {$targetPhp}."
                );
            }
        }

        // 3. Known framework compatibility checks
        foreach ($allPkgs as $pkg => $constraint) {
            if (isset($this->frameworkPhpMatrix[$pkg])) {
                $majorMatch = null;
                if (preg_match('/^[\^~>=]*([0-9]+)/', $constraint, $m)) {
                    $majorMatch = $m[1];
                }
                if ($majorMatch && isset($this->frameworkPhpMatrix[$pkg][$majorMatch])) {
                    $info = $this->frameworkPhpMatrix[$pkg][$majorMatch];
                    if (version_compare($targetPhp, $info['max_php'], '>')) {
                        $blockers[] = array(
                            'package' => $pkg,
                            'constraint' => $constraint,
                            'reason' => "{$pkg} {$constraint} only supports up to PHP {$info['max_php']}. Upgrade to {$info['upgrade_target']} for PHP {$targetPhp} compatibility."
                        );
                    }
                }
            }
        }

        // 4. Lock file inspection if available
        if (!empty($lockData['packages']) && is_array($lockData['packages'])) {
            foreach ($lockData['packages'] as $pkgEntry) {
                if (!empty($pkgEntry['name']) && !empty($pkgEntry['require']['php'])) {
                    $pkgPhp = $pkgEntry['require']['php'];
                    if (!$this->constraintAllowsPhp($pkgPhp, $targetPhp)) {
                        $blockers[] = array(
                            'package' => $pkgEntry['name'],
                            'constraint' => $pkgEntry['version'],
                            'reason' => "Locked package {$pkgEntry['name']} ({$pkgEntry['version']}) requires php {$pkgPhp}, blocking target PHP {$targetPhp}."
                        );
                    }
                }
            }
        }

        return $blockers;
    }

    private function constraintAllowsPhp($constraint, $targetPhp)
    {
        $clean = trim($constraint);
        if ($clean === '*' || strpos($clean, '^8') !== false || strpos($clean, '>=8') !== false) {
            return true;
        }
        if (strpos($clean, $targetPhp) !== false) {
            return true;
        }
        if (preg_match('/^>=([0-9]+\.[0-9]+)/', $clean, $m)) {
            return version_compare($targetPhp, $m[1], '>=');
        }
        if (preg_match('/^\^([0-9]+\.[0-9]+)/', $clean, $m)) {
            $minBranch = $m[1];
            $minMajor = (int) explode('.', $minBranch)[0];
            $targetMajor = (int) explode('.', $targetPhp)[0];
            return ($minMajor === $targetMajor && version_compare($targetPhp, $minBranch, '>='));
        }
        return false;
    }
}
