<?php

namespace Malikad\Php2ShellGuard\Backport;

use Malikad\Php2ShellGuard\Support\Status;

class Debian
{
    public function checkPackage($packageVersion, array $backportDb, $codename = 'bookworm')
    {
        $distroData = isset($backportDb['packages']['debian'][$codename]) ? $backportDb['packages']['debian'][$codename] : null;
        if (!$distroData) {
            return array(
                'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                'fixed_version' => 'distro-backport',
                'notes' => "Debian {$codename} backport table not found; check package changelog"
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
                'notes' => 'No fixed package defined in Debian backport table'
            );
        }

        $cmp = DistroVersionComparator::compareDebian($packageVersion, $pkgInfo['fixed_version']);
        if ($cmp >= 0) {
            return array(
                'status' => Status::PATCHED_BACKPORT,
                'fixed_version' => $pkgInfo['fixed_version'],
                'cves' => $pkgInfo['cves'],
                'upgrade_command' => $pkgInfo['upgrade_command'],
                'notes' => "Installed package {$packageVersion} meets or exceeds fixed Debian backport {$pkgInfo['fixed_version']}"
            );
        }

        return array(
            'status' => Status::VULNERABLE_PATCH_AVAILABLE,
            'fixed_version' => $pkgInfo['fixed_version'],
            'cves' => $pkgInfo['cves'],
            'upgrade_command' => $pkgInfo['upgrade_command'],
            'notes' => "Installed package {$packageVersion} is below fixed Debian backport {$pkgInfo['fixed_version']}"
        );
    }
}
