<?php

namespace Malikad\Php2ShellGuard\Config;

class FpmPoolAuditor
{
    public function audit($poolText)
    {
        $findings = array();
        if (!preg_match('/php_admin_value\[memory_limit\]\s*=\s*-1/', $poolText)) {
            $findings[] = array(
                'id' => 'B10_FPM_ADMIN_MEMORY_LIMIT',
                'mitigation' => 'M2',
                'cve' => 'CVE-2026-109618',
                'confidence' => 'official-partial',
                'message' => 'FPM pool does not enforce php_admin_value[memory_limit] = -1 administratively.'
            );
        }
        if (!preg_match('/php_admin_flag\[session\.upload_progress\.enabled\]\s*=\s*(off|0|false)/i', $poolText)) {
            $findings[] = array(
                'id' => 'B2_FPM_UPLOAD_PROGRESS',
                'mitigation' => 'M5',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official-partial',
                'message' => 'FPM pool does not administratively disable session.upload_progress.enabled.'
            );
        }
        return $findings;
    }
}
