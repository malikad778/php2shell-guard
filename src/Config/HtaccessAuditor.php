<?php

namespace Malikad\Php2ShellGuard\Config;

class HtaccessAuditor
{
    public function audit($htaccessText)
    {
        $findings = array();
        if (preg_match('/^\s*php_(value|flag)\s+/mi', $htaccessText)) {
            $findings[] = array(
                'id' => 'B11_HTACCESS_PHP_VALUE',
                'mitigation' => 'M7',
                'cve' => 'CVE-2026-109619',
                'confidence' => 'official',
                'message' => '.htaccess contains per-request php_value or php_flag directives which can emit early diagnostics under mod_php (M7).'
            );
        }
        return $findings;
    }
}
