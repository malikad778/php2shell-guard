<?php

namespace Malikad\Php2ShellGuard\Report;

class Junit
{
    public function render(array $reportData, array $options = array())
    {
        $runtimes = isset($reportData['runtimes']) && is_array($reportData['runtimes']) ? $reportData['runtimes'] : array();
        $totalTests = count($runtimes);
        $failures = 0;

        foreach ($runtimes as $rt) {
            $status = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            if ($status === 'VULNERABLE_PATCH_AVAILABLE' || $status === 'EOL_NO_OFFICIAL_RELEASE' || $status === 'PATCHED_NOT_RESTARTED') {
                $failures++;
            }
        }

        $xml = array();
        $xml[] = '<?xml version="1.0" encoding="UTF-8"?>';
        $xml[] = sprintf(
            '<testsuites name="php2shell-guard" tests="%d" failures="%d" errors="0" time="0.0">',
            $totalTests,
            $failures
        );
        $xml[] = sprintf(
            '  <testsuite name="runtime-advisory-audit" tests="%d" failures="%d" errors="0" time="0.0">',
            $totalTests,
            $failures
        );

        foreach ($runtimes as $rt) {
            $comp = htmlspecialchars(isset($rt['component']) ? $rt['component'] : 'component', ENT_QUOTES, 'UTF-8');
            $status = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            $detected = htmlspecialchars(isset($rt['detected_version']) ? $rt['detected_version'] : 'none', ENT_QUOTES, 'UTF-8');
            $fixed = htmlspecialchars(isset($rt['fixed_version']) ? $rt['fixed_version'] : 'none', ENT_QUOTES, 'UTF-8');
            $notes = htmlspecialchars(isset($rt['notes']) ? $rt['notes'] : '', ENT_QUOTES, 'UTF-8');

            $xml[] = sprintf('    <testcase classname="runtime" name="%s" time="0.0">', $comp);

            if ($status === 'VULNERABLE_PATCH_AVAILABLE' || $status === 'EOL_NO_OFFICIAL_RELEASE' || $status === 'PATCHED_NOT_RESTARTED') {
                $msg = sprintf("Status: %s (Detected: %s, Fixed: %s)", $status, $detected, $fixed);
                $xml[] = sprintf('      <failure message="%s" type="%s">%s</failure>', htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'), $status, $notes);
            }

            $xml[] = '    </testcase>';
        }

        $xml[] = '  </testsuite>';
        $xml[] = '</testsuites>';

        return implode("\n", $xml) . "\n";
    }
}
