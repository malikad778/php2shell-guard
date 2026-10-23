<?php

namespace Malikad\Php2ShellGuard\Report;

class Markdown
{
    public function render(array $reportData, array $options = array())
    {
        $brandName = isset($options['brand_name']) ? $options['brand_name'] : 'php2shell-guard';
        $brandContact = isset($options['brand_contact']) ? $options['brand_contact'] : null;
        $noCta = !empty($options['no_cta']);

        $host = isset($reportData['host']) ? $reportData['host'] : (isset($reportData['target']) ? $reportData['target'] : 'localhost');
        $dbDate = isset($reportData['advisory_db_date']) ? $reportData['advisory_db_date'] : '2026-10-23';
        $runtimes = isset($reportData['runtimes']) && is_array($reportData['runtimes']) ? $reportData['runtimes'] : array();
        $indicators = isset($reportData['indicators']['status']) ? $reportData['indicators']['status'] : 'no indicator found in the logs available (rotation and retention limits apply)';

        $lines = array();
        $lines[] = "# {$brandName} Security Audit Report";
        $lines[] = "";
        $lines[] = "**Target:** `{$host}` | **Advisory Database:** `{$dbDate}` | **Mode:** Read-only";
        if ($brandContact) {
            $lines[] = "**Audited By:** {$brandContact}";
        }
        $lines[] = "";

        // Status Summary count
        $statusCounts = array();
        foreach ($runtimes as $rt) {
            $st = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            $statusCounts[$st] = isset($statusCounts[$st]) ? $statusCounts[$st] + 1 : 1;
        }

        $summaryParts = array();
        foreach ($statusCounts as $st => $cnt) {
            $summaryParts[] = "{$cnt} {$st}";
        }
        $lines[] = "> **Summary:** " . (count($summaryParts) > 0 ? implode(', ', $summaryParts) : 'No runtimes evaluated');
        $lines[] = "";

        // Runtimes Table
        $lines[] = "## Runtime Findings";
        $lines[] = "";
        $lines[] = "| Component | Serves Traffic | Detected Version | Status | Fixed Version | CVEs |";
        $lines[] = "|---|---|---|---|---|---|";

        foreach ($runtimes as $rt) {
            $comp = isset($rt['component']) ? $rt['component'] : 'unknown';
            $traffic = !empty($rt['serves_traffic']) ? 'Yes' : 'No';
            $ver = isset($rt['detected_version']) ? $rt['detected_version'] : 'none';
            $status = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            $fixed = isset($rt['fixed_version']) ? $rt['fixed_version'] : 'none';
            $cves = isset($rt['cves']) && is_array($rt['cves']) ? implode(', ', $rt['cves']) : '-';

            $lines[] = "| `{$comp}` | {$traffic} | `{$ver}` | **{$status}** | `{$fixed}` | {$cves} |";
        }
        $lines[] = "";

        // Evidence and Notes
        $lines[] = "## Evidence and Details";
        $lines[] = "";
        foreach ($runtimes as $rt) {
            $comp = isset($rt['component']) ? $rt['component'] : 'unknown';
            $lines[] = "### `{$comp}`";
            if (!empty($rt['evidence'])) {
                $lines[] = "- **Evidence:** `{$rt['evidence']}`";
            }
            if (!empty($rt['notes'])) {
                $lines[] = "- **Notes:** {$rt['notes']}";
            }
            if (!empty($rt['sapi_risk'])) {
                $lines[] = "- **SAPI Risk:** {$rt['sapi_risk']}";
            }
            $lines[] = "";
        }

        // Indicators
        $lines[] = "## Compromise Indicators (Logs & Processes)";
        $lines[] = "";
        $lines[] = "> " . $indicators;
        $lines[] = "";
        $lines[] = "_Note: Absence of indicators does not prove absence of compromise. Log rotation, retention limits, and stealthy in-memory attacks apply._";
        $lines[] = "";

        // Remediation notice
        $lines[] = "## Remediation Guidance";
        $lines[] = "";
        $lines[] = "1. **Patching is mandatory:** Upgrading to >= 8.2.35, 8.3.36, 8.4.27, or 8.5.12 (and >= 22.23.4 / 24.22.1 for Node) is the only permanent defense.";
        $lines[] = "2. **Restart every worker:** A patched binary on disk has no effect until all worker processes and containers are restarted.";
        $lines[] = "3. **Emergency stopgaps reduce exposure only:** Administrative limits (`memory_limit=-1`, `session.upload_progress.enabled=0`, request size limits) do not replace patching.";
        $lines[] = "";

        if (!$noCta) {
            $lines[] = "---";
            $lines[] = "Need emergency patching assistance or a controlled PHP 8.3/8.4 upgrade plan? Contact us at https://github.com/malikad778/php2shell-guard";
        }

        return implode("\n", $lines) . "\n";
    }
}
