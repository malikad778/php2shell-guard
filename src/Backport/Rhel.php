<?php

namespace Malikad\Php2ShellGuard\Backport;

use Malikad\Php2ShellGuard\Support\Status;

class Rhel
{
    public function checkPackage($packageVersion, array $backportDb, $release = '9')
    {
        $distroData = isset($backportDb['packages']['rhel'][$release]) ? $backportDb['packages']['rhel'][$release] : null;
        if (!$distroData) {
            return array(
                'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                'fixed_version' => 'distro-backport',
                'notes' => "RHEL {$release} backport table not found; check package changelog"
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
                'notes' => 'No fixed package defined in RHEL backport table'
            );
        }

        $cmp = DistroVersionComparator::compareRhel($packageVersion, $pkgInfo['fixed_version']);
        if ($cmp >= 0) {
            return array(
                'status' => Status::PATCHED_BACKPORT,
                'fixed_version' => $pkgInfo['fixed_version'],
                'cves' => $pkgInfo['cves'],
                'upgrade_command' => $pkgInfo['upgrade_command'],
                'notes' => "Installed package {$packageVersion} meets or exceeds fixed RHEL backport {$pkgInfo['fixed_version']}"
            );
        }

        return array(
            'status' => Status::VULNERABLE_PATCH_AVAILABLE,
            'fixed_version' => $pkgInfo['fixed_version'],
            'cves' => $pkgInfo['cves'],
            'upgrade_command' => $pkgInfo['upgrade_command'],
            'notes' => "Installed package {$packageVersion} is below fixed RHEL backport {$pkgInfo['fixed_version']}"
        );
    }
}
