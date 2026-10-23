<?php

namespace Malikad\Php2ShellGuard\Support;

class Status
{
    const PATCHED = 'PATCHED';
    const PATCHED_BACKPORT = 'PATCHED_BACKPORT';
    const PATCHED_NOT_RESTARTED = 'PATCHED_NOT_RESTARTED';
    const NOT_DETECTED = 'NOT_DETECTED';
    const VULNERABLE_PATCH_AVAILABLE = 'VULNERABLE_PATCH_AVAILABLE';
    const EOL_NO_OFFICIAL_RELEASE = 'EOL_NO_OFFICIAL_RELEASE';
    const UNKNOWN_BACKPORT_POSSIBLE = 'UNKNOWN_BACKPORT_POSSIBLE';
    const UNKNOWN = 'UNKNOWN';

    public static function toExitCode($status)
    {
        switch ($status) {
            case self::PATCHED:
            case self::PATCHED_BACKPORT:
            case self::NOT_DETECTED:
                return 0;
            case self::VULNERABLE_PATCH_AVAILABLE:
            case self::PATCHED_NOT_RESTARTED:
                return 1;
            case self::EOL_NO_OFFICIAL_RELEASE:
                return 2;
            case self::UNKNOWN_BACKPORT_POSSIBLE:
            case self::UNKNOWN:
                return 3;
            default:
                return 4;
        }
    }
}
