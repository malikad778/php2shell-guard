<?php

namespace Malikad\Php2ShellGuard\Config;

class PhpIniAuditor
{
    public function audit($iniText, $phpBranch = '8.3')
    {
        $findings = array();
        if (!preg_match('/^\s*memory_limit\s*=\s*-1\s*$/m', $iniText)) {
            $findings[] = array(
                'id' => 'B1_MEMORY_LIMIT',
                'mitigation' => 'M2',
                'cve' => 'CVE-2026-109618',
                'confidence' => 'official-partial',
                'message' => 'memory_limit is not set to -1. Enforce php_admin_value[memory_limit] = -1 paired with cgroup/container memory limits (reduces exposure; does not replace patching).'
            );
        }
        if (!preg_match('/^\s*session\.upload_progress\.enabled\s*=\s*(0|Off|false)\s*$/mi', $iniText)) {
            $findings[] = array(
                'id' => 'B1_UPLOAD_PROGRESS',
                'mitigation' => 'M5',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official-partial',
                'message' => 'session.upload_progress.enabled is not disabled (0/Off) before request parsing (reduces exposure; does not replace patching).'
            );
        }
        if ($phpBranch === '8.5' && !preg_match('/^\s*fatal_error_backtraces\s*=\s*(0|Off|false)\s*$/mi', $iniText)) {
            $findings[] = array(
                'id' => 'B13_FATAL_BACKTRACES',
                'mitigation' => 'M6',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official-partial',
                'message' => 'On PHP 8.5, fatal_error_backtraces should be set to 0 before request parsing.'
            );
        }
        return $findings;
    }
}
