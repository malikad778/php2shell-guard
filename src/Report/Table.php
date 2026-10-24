<?php

namespace Malikad\Php2ShellGuard\Report;

class Table
{
    public function render(array $reportData, array $options = array())
    {
        $version = isset($reportData['version']) ? $reportData['version'] : '0.3.1';
        $dbDate = isset($reportData['advisory_db_date']) ? $reportData['advisory_db_date'] : '2026-10-23';
        $host = isset($reportData['host']) ? $reportData['host'] : 'localhost';
        $target = isset($reportData['target']) ? $reportData['target'] : '.';
        $runtimes = isset($reportData['runtimes']) && is_array($reportData['runtimes']) ? $reportData['runtimes'] : array();
        $indicators = isset($reportData['indicators']['status']) ? $reportData['indicators']['status'] : 'no indicator found in the logs available (rotation and retention limits apply)';
        $noCta = !empty($options['no_cta']);

        $lines = array();
        $lines[] = "php2shell-guard v{$version}  |  advisory db {$dbDate}  |  read-only scan";
        $lines[] = "";
        $lines[] = "TARGET {$host} ({$target})";

        foreach ($runtimes as $rt) {
            $comp = isset($rt['component']) ? $rt['component'] : 'unknown';
            $ver = isset($rt['detected_version']) ? $rt['detected_version'] : 'none';
            $status = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            $fixed = isset($rt['fixed_version']) ? $rt['fixed_version'] : 'none';
            $traffic = !empty($rt['serves_traffic']) ? '(serves traffic)       ' : '(not serving traffic)  ';

            $lines[] = sprintf("  %-10s %-7s %s %s", $comp, $ver, $traffic, $status);

            if (isset($rt['cves']) && is_array($rt['cves']) && $status !== 'PATCHED' && $status !== 'PATCHED_BACKPORT' && $status !== 'NOT_DETECTED') {
                foreach ($rt['cves'] as $cve) {
                    $lines[] = sprintf("     %-16s fix: %s", $cve, $fixed);
                }
            }
            if (!empty($rt['evidence'])) {
                $lines[] = sprintf("     evidence: %s", $rt['evidence']);
            }
            if (!empty($rt['notes']) && $status !== 'PATCHED') {
                $lines[] = sprintf("     note: %s", $rt['notes']);
            }
        }

        $lines[] = "";
        $lines[] = "Indicators: {$indicators}";
        $lines[] = "Note: Stopgaps reduce exposure only; patching and restarting all workers is the only complete defense.";

        if (!$noCta) {
            $lines[] = "Need emergency patching or a controlled PHP 8.3/8.4 migration? https://github.com/malikad778/php2shell-guard?utm_source=cli&utm_medium=footer";
        }

        return implode("\n", $lines) . "\n";
    }
}
