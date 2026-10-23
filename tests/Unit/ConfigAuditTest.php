<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Config\PhpIniAuditor;

class ConfigAuditTest
{
    public function run()
    {
        $auditor = new PhpIniAuditor();
        $vuln = file_get_contents(__DIR__ . '/../fixtures/php-vulnerable.ini');
        $mitigated = file_get_contents(__DIR__ . '/../fixtures/php-mitigated.ini');

        $vulnFindings = $auditor->audit($vuln, '8.5');
        if (count($vulnFindings) < 3) {
            throw new \RuntimeException('Expected at least 3 findings on vulnerable php.ini');
        }

        $okFindings = $auditor->audit($mitigated, '8.5');
        if (count($okFindings) !== 0) {
            throw new \RuntimeException('Expected 0 findings on mitigated php.ini');
        }
        return true;
    }
}
