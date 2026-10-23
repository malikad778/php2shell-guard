<?php

namespace Malikad\Php2ShellGuard\Backport;

use Malikad\Php2ShellGuard\Support\Status;

class Alpine
{
    public function checkPackage($packageVersion, array $backportDb, $branch = '3.21')
    {
        $distroData = isset($backportDb['packages']['alpine'][$branch]) ? $backportDb['packages']['alpine'][$branch] : null;
        if (!$distroData) {
            return array(
                'status' => Status::UNKNOWN_BACKPORT_POSSIBLE,
                'fixed_version' => 'distro-backport',
                'notes' => "Alpine {$branch} backport table not found; check package changelog"
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
                'notes' => 'No fixed package defined in Alpine backport table'
            );
        }

        $cmp = DistroVersionComparator::compareAlpine($packageVersion, $pkgInfo['fixed_version']);
        if ($cmp >= 0) {
            return array(
                'status' => Status::PATCHED_BACKPORT,
                'fixed_version' => $pkgInfo['fixed_version'],
                'cves' => $pkgInfo['cves'],
                'upgrade_command' => $pkgInfo['upgrade_command'],
                'notes' => "Installed package {$packageVersion} meets or exceeds fixed Alpine backport {$pkgInfo['fixed_version']}"
            );
        }

        return array(
            'status' => Status::VULNERABLE_PATCH_AVAILABLE,
            'fixed_version' => $pkgInfo['fixed_version'],
            'cves' => $pkgInfo['cves'],
            'upgrade_command' => $pkgInfo['upgrade_command'],
            'notes' => "Installed package {$packageVersion} is below fixed Alpine backport {$pkgInfo['fixed_version']}"
        );
    }
}
