<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Backport\Alpine;
use Malikad\Php2ShellGuard\Backport\ChangelogParser;
use Malikad\Php2ShellGuard\Backport\Debian;
use Malikad\Php2ShellGuard\Backport\Rhel;
use Malikad\Php2ShellGuard\Backport\Ubuntu;
use Malikad\Php2ShellGuard\Support\Status;

class BackportEngineTest
{
    public function run()
    {
        $backportDb = json_decode(file_get_contents(__DIR__ . '/../../data/backports/distro-backports.json'), true);

        // 1. Debian check
        $debian = new Debian();
        $debVuln = $debian->checkPackage('8.2.26-1~deb12u1', $backportDb, 'bookworm');
        if ($debVuln['status'] !== Status::VULNERABLE_PATCH_AVAILABLE) {
            throw new \RuntimeException('Expected Debian 8.2.26-1~deb12u1 to be VULNERABLE_PATCH_AVAILABLE');
        }
        $debPatched = $debian->checkPackage('8.2.26-1~deb12u2', $backportDb, 'bookworm');
        if ($debPatched['status'] !== Status::PATCHED_BACKPORT) {
            throw new \RuntimeException('Expected Debian 8.2.26-1~deb12u2 to be PATCHED_BACKPORT');
        }

        // 2. Ubuntu check
        $ubuntu = new Ubuntu();
        $ubVuln = $ubuntu->checkPackage('8.3.6-0ubuntu0.24.04.1', $backportDb, '24.04');
        if ($ubVuln['status'] !== Status::VULNERABLE_PATCH_AVAILABLE) {
            throw new \RuntimeException('Expected Ubuntu 8.3.6-0ubuntu0.24.04.1 to be VULNERABLE_PATCH_AVAILABLE');
        }
        $ubPatched = $ubuntu->checkPackage('8.3.6-0ubuntu0.24.04.6', $backportDb, '24.04');
        if ($ubPatched['status'] !== Status::PATCHED_BACKPORT) {
            throw new \RuntimeException('Expected Ubuntu 8.3.6-0ubuntu0.24.04.6 to be PATCHED_BACKPORT');
        }

        // 3. RHEL check
        $rhel = new Rhel();
        $rhelVuln = $rhel->checkPackage('8.2.34-1.el9', $backportDb, '9');
        if ($rhelVuln['status'] !== Status::VULNERABLE_PATCH_AVAILABLE) {
            throw new \RuntimeException('Expected RHEL 8.2.34-1.el9 to be VULNERABLE_PATCH_AVAILABLE');
        }
        $rhelPatched = $rhel->checkPackage('8.2.35-1.el9', $backportDb, '9');
        if ($rhelPatched['status'] !== Status::PATCHED_BACKPORT) {
            throw new \RuntimeException('Expected RHEL 8.2.35-1.el9 to be PATCHED_BACKPORT');
        }

        // 4. Alpine check
        $alpine = new Alpine();
        $alpVuln = $alpine->checkPackage('8.3.35-r0', $backportDb, '3.21');
        if ($alpVuln['status'] !== Status::VULNERABLE_PATCH_AVAILABLE) {
            throw new \RuntimeException('Expected Alpine 8.3.35-r0 to be VULNERABLE_PATCH_AVAILABLE');
        }
        $alpPatched = $alpine->checkPackage('8.3.36-r0', $backportDb, '3.21');
        if ($alpPatched['status'] !== Status::PATCHED_BACKPORT) {
            throw new \RuntimeException('Expected Alpine 8.3.36-r0 to be PATCHED_BACKPORT');
        }

        // 5. Changelog parser check
        $parser = new ChangelogParser();
        $cl = "php8.2 (8.2.26-1~deb12u2) bookworm-security; urgency=high\n  * Fix CVE-2026-109618 out-of-memory corruption\n  * Fix CVE-2026-109619 stale global state\n";
        $clRes = $parser->hasPhp2ShellFixes($cl);
        if (!$clRes['fully_patched'] || !$clRes['CVE-2026-109618'] || !$clRes['CVE-2026-109619']) {
            throw new \RuntimeException('ChangelogParser failed on valid backport changelog');
        }

        return true;
    }
}
