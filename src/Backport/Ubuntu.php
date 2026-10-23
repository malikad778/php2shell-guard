<?php

namespace Malikad\Php2ShellGuard\Backport;

use Malikad\Php2ShellGuard\Support\Status;

class Ubuntu
{
    public function checkPackage($packageVersion, array $backportDb, $release = '24.04')
    {
        $distroData = isset($backportDb['packages']['ubuntu'][$release]) ? $backportDb['packages']['ubuntu'][$release] : null;
        if (!$distroData) {
            return array(
                'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                'fixed_version' => 'distro-backport',
                'notes' => "Ubuntu {$release} backport table not found; check package changelog"
            );
        }

        $pkgInfo = null;
        foreach ($distroData as $pkgName => $info) {
            if (isset($info['fixed_version'])) {
                $pkgInfo = $info;
                break;
            }
        }

        if (!$pkgInfo) {
            return array(
                'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                'fixed_version' => 'distro-backport',
                'notes' => 'No fixed package defined in Ubuntu backport table'
            );
        }

        $cmp = DistroVersionComparator::compareDebian($packageVersion, $pkgInfo['fixed_version']);
        if ($cmp >= 0) {
            return array(
                'status' => Status::PATCHED_BACKPORT,
                'fixed_version' => $pkgInfo['fixed_version'],
                'cves' => $pkgInfo['cves'],
                'upgrade_command' => $pkgInfo['upgrade_command'],
                'notes' => "Installed package {$packageVersion} meets or exceeds fixed Ubuntu backport {$pkgInfo['fixed_version']}"
            );
        }

        return array(
            'status' => Status::VULNERABLE_PATCH_AVAILABLE,
            'fixed_version' => $pkgInfo['fixed_version'],
            'cves' => $pkgInfo['cves'],
            'upgrade_command' => $pkgInfo['upgrade_command'],
            'notes' => "Installed package {$packageVersion} is below fixed Ubuntu backport {$pkgInfo['fixed_version']}"
        );
    }
}
