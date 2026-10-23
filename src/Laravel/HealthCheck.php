<?php

namespace Malikad\Php2ShellGuard\Laravel;

use Malikad\Php2ShellGuard\Detect\PhpDetector;
use Malikad\Php2ShellGuard\Support\Status;

class HealthCheck
{
    public function run()
    {
        $detector = new PhpDetector();
        $cli = $detector->detectCli();

        $status = $cli['status'];
        $isOk = ($status === Status::PATCHED || $status === Status::PATCHED_BACKPORT);
        $isCritical = ($status === Status::VULNERABLE_PATCH_AVAILABLE || $status === Status::EOL_NO_OFFICIAL_RELEASE);

        $severity = $isOk ? 'ok' : ($isCritical ? 'failed' : 'warning');
        $msg = sprintf(
            "PHP CLI %s status: %s (Fixed release: %s)",
            $cli['detected_version'],
            $cli['status'],
            $cli['fixed_version']
        );

        return array(
            'check' => 'php2shell-guard',
            'status' => $severity,
            'message' => $msg,
            'runtime_details' => $cli
        );
    }
}
