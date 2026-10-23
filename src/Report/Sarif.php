<?php

namespace Malikad\Php2ShellGuard\Report;

class Sarif
{
    public function render(array $reportData, array $options = array())
    {
        $toolVersion = isset($reportData['version']) ? $reportData['version'] : '0.3.0';
        $rules = array();
        $results = array();

        $rulesMap = array(
            'CVE-2026-109618' => array(
                'id' => 'PHP2SHELL-109618',
                'name' => 'PhpOutOfMemoryCorruptionRce',
                'shortDescription' => array('text' => 'CVE-2026-109618: PHP Out-of-Memory Corruption Remote Code Execution'),
                'fullDescription' => array('text' => 'Out-of-memory condition during request initialization or cleanup corrupts memory, enabling unauthenticated remote code execution.'),
                'defaultConfiguration' => array('level' => 'error'),
                'helpUri' => 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'
            ),
            'CVE-2026-109619' => array(
                'id' => 'PHP2SHELL-109619',
                'name' => 'PhpStaleGlobalStateRce',
                'shortDescription' => array('text' => 'CVE-2026-109619: PHP Stale Global State Remote Code Execution'),
                'fullDescription' => array('text' => 'Stale global state across reused PHP worker processes permits unauthenticated remote code execution.'),
                'defaultConfiguration' => array('level' => 'error'),
                'helpUri' => 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp'
            ),
            'CVE-2026-111497' => array(
                'id' => 'NODE2SHELL-111497',
                'name' => 'NodeBrotliDecoderOobWrite',
                'shortDescription' => array('text' => 'CVE-2026-111497: Node.js Brotli Decoder Out-of-Bounds Write RCE'),
                'fullDescription' => array('text' => 'Out-of-bounds write in bundled or shared Brotli decoder library allows remote code execution.'),
                'defaultConfiguration' => array('level' => 'error'),
                'helpUri' => 'https://nodejs.org/en/blog/vulnerability'
            ),
        );

        $targetFile = isset($reportData['target']) && is_file($reportData['target']) ? $reportData['target'] : 'server-runtime';
        $runtimes = isset($reportData['runtimes']) && is_array($reportData['runtimes']) ? $reportData['runtimes'] : array();

        foreach ($runtimes as $rt) {
            $status = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            if ($status === 'PATCHED' || $status === 'PATCHED_BACKPORT' || $status === 'NOT_DETECTED') {
                continue;
            }

            $cves = isset($rt['cves']) && is_array($rt['cves']) ? $rt['cves'] : array('CVE-2026-109618');
            $level = ($status === 'VULNERABLE_PATCH_AVAILABLE' || $status === 'EOL_NO_OFFICIAL_RELEASE') ? 'error' : 'warning';

            foreach ($cves as $cve) {
                if (!isset($rules[$cve]) && isset($rulesMap[$cve])) {
                    $rules[$cve] = $rulesMap[$cve];
                }

                $ruleId = isset($rulesMap[$cve]['id']) ? $rulesMap[$cve]['id'] : $cve;
                $msg = sprintf(
                    "%s (%s) is %s: %s (Fix: %s)",
                    isset($rt['component']) ? $rt['component'] : 'runtime',
                    isset($rt['detected_version']) ? $rt['detected_version'] : 'unknown',
                    $status,
                    isset($rt['notes']) ? $rt['notes'] : '',
                    isset($rt['fixed_version']) ? $rt['fixed_version'] : 'none'
                );

                $results[] = array(
                    'ruleId' => $ruleId,
                    'level' => $level,
                    'message' => array('text' => $msg),
                    'locations' => array(
                        array(
                            'physicalLocation' => array(
                                'artifactLocation' => array(
                                    'uri' => $targetFile,
                                    'uriBaseId' => '%SRCROOT%'
                                ),
                                'region' => array('startLine' => 1, 'startColumn' => 1)
                            )
                        )
                    )
                );
            }
        }

        $sarif = array(
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => array(
                array(
                    'tool' => array(
                        'driver' => array(
                            'name' => 'php2shell-guard',
                            'version' => $toolVersion,
                            'informationUri' => 'https://github.com/malikad778/php2shell-guard',
                            'rules' => array_values($rules)
                        )
                    ),
                    'results' => $results
                )
            )
        );

        return json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
