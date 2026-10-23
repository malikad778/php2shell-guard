<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Support\Status;
use Malikad\Php2ShellGuard\Support\VersionComparator;

class VersionComparatorTest
{
    public function run()
    {
        // Branch boundary tests from Section 11 of plan.md
        $cases = array(
            array('8.2.34', false, false, Status::VULNERABLE_PATCH_AVAILABLE),
            array('8.2.35', false, false, Status::PATCHED),
            array('8.3.35', false, false, Status::VULNERABLE_PATCH_AVAILABLE),
            array('8.3.36', false, false, Status::PATCHED),
            array('8.4.26', false, false, Status::VULNERABLE_PATCH_AVAILABLE),
            array('8.4.27', false, false, Status::PATCHED),
            array('8.5.11', false, false, Status::VULNERABLE_PATCH_AVAILABLE),
            array('8.5.12', false, false, Status::PATCHED),
            array('8.3.36-dev', false, false, Status::VULNERABLE_PATCH_AVAILABLE),
            array('8.3.36RC1', false, false, Status::VULNERABLE_PATCH_AVAILABLE),
            array('8.1.29', false, false, Status::EOL_NO_OFFICIAL_RELEASE),
            array('7.4.33', false, false, Status::EOL_NO_OFFICIAL_RELEASE),
            array('5.6.40', false, false, Status::EOL_NO_OFFICIAL_RELEASE),
            array('8.1.2-1ubuntu2.14', false, false, Status::UNKNOWN_BACKPORT_POSSIBLE),
            array('8.2.26-1~deb12u1', false, false, Status::UNKNOWN_BACKPORT_POSSIBLE),
            array('8.2.26-1~deb12u2', false, true, Status::PATCHED_BACKPORT),
            array('8.3.36', true, false, Status::PATCHED_NOT_RESTARTED),
        );

        foreach ($cases as $c) {
            $res = VersionComparator::evaluatePhp($c[0], $c[1], $c[2]);
            if ($res['status'] !== $c[3]) {
                throw new \RuntimeException("Failed PHP boundary check for {$c[0]}: expected {$c[3]}, got {$res['status']}");
            }
        }
        return true;
    }
}
