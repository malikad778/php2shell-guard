<?php

namespace Malikad\Php2ShellGuard\Config;

class ApacheAuditor
{
    public function audit($apacheText)
    {
        $findings = array();
        if (!preg_match('/php_admin_value\s+memory_limit\s+-1/i', $apacheText)) {
            $findings[] = array(
                'id' => 'B10_APACHE_ADMIN_MEMORY_LIMIT',
                'mitigation' => 'M2',
                'cve' => 'CVE-2026-109618',
                'confidence' => 'official-partial',
                'message' => 'Apache vhost/server config does not enforce php_admin_value memory_limit -1.'
            );
        }
        if (!preg_match('/LimitRequestBody\s+[1-9][0-9]*/i', $apacheText)) {
            $findings[] = array(
                'id' => 'B4_APACHE_LIMIT_REQUEST_BODY',
                'mitigation' => 'M4',
                'cve' => 'CVE-2026-109618',
                'confidence' => 'official-partial',
                'message' => 'Apache config does not set a positive LimitRequestBody ceiling.'
            );
        }
        return $findings;
    }
}
