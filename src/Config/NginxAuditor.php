<?php

namespace Malikad\Php2ShellGuard\Config;

class NginxAuditor
{
    public function audit($nginxText)
    {
        $findings = array();
        if (preg_match('/fastcgi_param\s+PHP_(ADMIN_)?VALUE/i', $nginxText)) {
            $findings[] = array(
                'id' => 'B11_NGINX_FASTCGI_PHP_VALUE',
                'mitigation' => 'M7',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official',
                'message' => 'Nginx passes fastcgi_param PHP_VALUE/PHP_ADMIN_VALUE per request, which can create early diagnostics (M7).'
            );
        }
        if (!preg_match('/client_max_body_size\s+[0-9]+[km]/i', $nginxText)) {
            $findings[] = array(
                'id' => 'B12_NGINX_BODY_LIMIT',
                'mitigation' => 'M4',
                'cve' => 'CVE-2026-109618',
                'confidence' => 'official-partial',
                'message' => 'Nginx does not set a bounded client_max_body_size.'
            );
        }
        return $findings;
    }
}
