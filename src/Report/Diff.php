<?php

namespace Malikad\Php2ShellGuard\Report;

class Diff
{
    public function compare(array $before, array $after)
    {
        $beforeRuntimes = $this->indexRuntimes($before);
        $afterRuntimes = $this->indexRuntimes($after);

        $remediated = array();
        $persistent = array();
        $regressions = array();
        $unchanged = array();

        $allKeys = array_unique(array_merge(array_keys($beforeRuntimes), array_keys($afterRuntimes)));

        foreach ($allKeys as $key) {
            $b = isset($beforeRuntimes[$key]) ? $beforeRuntimes[$key] : null;
            $a = isset($afterRuntimes[$key]) ? $afterRuntimes[$key] : null;

            if ($b && $a) {
                $bVuln = in_array($b['status'], array('VULNERABLE_PATCH_AVAILABLE', 'EOL_NO_OFFICIAL_RELEASE', 'PATCHED_NOT_RESTARTED'), true);
                $aVuln = in_array($a['status'], array('VULNERABLE_PATCH_AVAILABLE', 'EOL_NO_OFFICIAL_RELEASE', 'PATCHED_NOT_RESTARTED'), true);

                if ($bVuln && !$aVuln) {
                    $remediated[] = array(
                        'component' => $key,
                        'before_version' => $b['detected_version'],
                        'before_status' => $b['status'],
                        'after_version' => $a['detected_version'],
                        'after_status' => $a['status']
                    );
                } elseif ($bVuln && $aVuln) {
                    $persistent[] = array(
                        'component' => $key,
                        'before_version' => $b['detected_version'],
                        'after_version' => $a['detected_version'],
                        'status' => $a['status']
                    );
                } elseif (!$bVuln && $aVuln) {
                    $regressions[] = array(
                        'component' => $key,
                        'before_status' => $b['status'],
                        'after_status' => $a['status']
                    );
                } else {
                    $unchanged[] = array(
                        'component' => $key,
                        'status' => $a['status']
                    );
                }
            }
        }

        return array(
            'summary' => array(
                'remediated_count' => count($remediated),
                'persistent_count' => count($persistent),
                'regressions_count' => count($regressions),
                'status' => count($persistent) === 0 ? 'ALL_REMEDIATED' : 'REMEDIATION_INCOMPLETE'
            ),
            'remediated' => $remediated,
            'persistent' => $persistent,
            'regressions' => $regressions,
            'unchanged' => $unchanged
        );
    }

    public function render(array $reportData, array $options = array())
    {
        if (isset($reportData['before']) && isset($reportData['after'])) {
            $diffData = $this->compare($reportData['before'], $reportData['after']);
        } else {
            $diffData = $reportData;
        }

        $lines = array();
        $lines[] = "php2shell-guard Scan Difference Report";
        $lines[] = "======================================";
        $lines[] = "";
        $summary = isset($diffData['summary']) ? $diffData['summary'] : array();
        $lines[] = sprintf("Overall Result: %s", isset($summary['status']) ? $summary['status'] : 'COMPLETED');
        $lines[] = sprintf("Remediated Findings: %d", isset($summary['remediated_count']) ? $summary['remediated_count'] : 0);
        $lines[] = sprintf("Persistent Findings: %d", isset($summary['persistent_count']) ? $summary['persistent_count'] : 0);
        $lines[] = sprintf("Regressions:         %d", isset($summary['regressions_count']) ? $summary['regressions_count'] : 0);
        $lines[] = "";

        if (!empty($diffData['remediated'])) {
            $lines[] = "[+] REMEDIATED:";
            foreach ($diffData['remediated'] as $rem) {
                $lines[] = sprintf("  - %s: %s (%s) -> %s (%s)", $rem['component'], $rem['before_version'], $rem['before_status'], $rem['after_version'], $rem['after_status']);
            }
            $lines[] = "";
        }

        if (!empty($diffData['persistent'])) {
            $lines[] = "[!] PERSISTENT VULNERABILITIES:";
            foreach ($diffData['persistent'] as $per) {
                $lines[] = sprintf("  - %s: %s (Status: %s)", $per['component'], $per['after_version'], $per['status']);
            }
            $lines[] = "";
        }

        if (!empty($diffData['regressions'])) {
            $lines[] = "[-] REGRESSIONS:";
            foreach ($diffData['regressions'] as $reg) {
                $lines[] = sprintf("  - %s: was %s, now %s", $reg['component'], $reg['before_status'], $reg['after_status']);
            }
            $lines[] = "";
        }

        return implode("\n", $lines) . "\n";
    }

    private function indexRuntimes(array $data)
    {
        $indexed = array();
        $runtimes = isset($data['runtimes']) && is_array($data['runtimes']) ? $data['runtimes'] : array();
        foreach ($runtimes as $rt) {
            $comp = isset($rt['component']) ? $rt['component'] : 'unknown';
            $indexed[$comp] = $rt;
        }
        return $indexed;
    }
}
