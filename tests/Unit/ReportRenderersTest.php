<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Report\Csv;
use Malikad\Php2ShellGuard\Report\Diff;
use Malikad\Php2ShellGuard\Report\Html;
use Malikad\Php2ShellGuard\Report\Junit;
use Malikad\Php2ShellGuard\Report\Markdown;
use Malikad\Php2ShellGuard\Report\Pdf;
use Malikad\Php2ShellGuard\Report\Sarif;

class ReportRenderersTest
{
    private function getSampleData()
    {
        return array(
            'tool' => 'php2shell-guard',
            'version' => '0.3.0',
            'advisory_db_date' => '2026-10-23',
            'host' => 'prod-web-01',
            'target' => '/var/www/html',
            'runtimes' => array(
                array(
                    'component' => 'php-fpm',
                    'serves_traffic' => true,
                    'detected_version' => '8.3.35',
                    'status' => 'VULNERABLE_PATCH_AVAILABLE',
                    'fixed_version' => '8.3.36',
                    'cves' => array('CVE-2026-109618', 'CVE-2026-109619'),
                    'evidence' => '/usr/sbin/php-fpm8.3 -v',
                    'notes' => 'Version 8.3.35 is below fixed release 8.3.36'
                ),
                array(
                    'component' => 'php-cli',
                    'serves_traffic' => false,
                    'detected_version' => '8.3.36',
                    'status' => 'PATCHED',
                    'fixed_version' => '8.3.36',
                    'cves' => array('CVE-2026-109618', 'CVE-2026-109619'),
                    'evidence' => '/usr/bin/php -v',
                    'notes' => 'Version 8.3.36 meets or exceeds fixed release 8.3.36'
                ),
            ),
            'indicators' => array(
                'count' => 0,
                'status' => 'no indicator found in the logs available (rotation and retention limits apply)'
            )
        );
    }

    public function run()
    {
        $data = $this->getSampleData();
        $options = array(
            'brand_name' => 'Acme Security',
            'brand_contact' => 'security@acme.test',
            'no_cta' => true
        );

        // 1. CSV
        $csv = (new Csv())->render($data, $options);
        if (strpos($csv, 'host,component,serves_traffic') === false || strpos($csv, 'prod-web-01,php-fpm,true,8.3.35') === false) {
            throw new \RuntimeException('CSV report renderer failed header or content check');
        }

        // 2. Markdown
        $md = (new Markdown())->render($data, $options);
        if (strpos($md, '# Acme Security Security Audit Report') === false || strpos($md, '| `php-fpm` | Yes | `8.3.35` |') === false) {
            throw new \RuntimeException('Markdown report renderer failed formatting check');
        }

        // 3. SARIF
        $sarifJson = (new Sarif())->render($data, $options);
        $sarif = json_decode($sarifJson, true);
        if (!$sarif || $sarif['version'] !== '2.1.0' || empty($sarif['runs'][0]['results'])) {
            throw new \RuntimeException('SARIF renderer failed standard 2.1.0 validation');
        }
        if ($sarif['runs'][0]['results'][0]['ruleId'] !== 'PHP2SHELL-109618') {
            throw new \RuntimeException('SARIF result ruleId mismatch');
        }

        // 4. JUnit
        $junitXml = (new Junit())->render($data, $options);
        if (strpos($junitXml, '<testsuites') === false || strpos($junitXml, '<failure message=') === false) {
            throw new \RuntimeException('JUnit report renderer failed XML structure check');
        }

        // 5. HTML
        $html = (new Html())->render($data, $options);
        if (strpos($html, '<!DOCTYPE html>') === false || strpos($html, 'Acme Security') === false || strpos($html, 'VULNERABLE_PATCH_AVAILABLE') === false) {
            throw new \RuntimeException('HTML report renderer failed HTML structure or branding check');
        }

        // 6. PDF
        $pdfHtml = (new Pdf())->render($data, $options);
        if (strpos($pdfHtml, '@page') === false || strpos($pdfHtml, '@media print') === false) {
            throw new \RuntimeException('PDF renderer missing print styling');
        }

        // 7. Diff
        $afterData = $data;
        $afterData['runtimes'][0]['detected_version'] = '8.3.36';
        $afterData['runtimes'][0]['status'] = 'PATCHED';

        $diffRes = (new Diff())->compare($data, $afterData);
        if ($diffRes['summary']['remediated_count'] !== 1 || $diffRes['summary']['persistent_count'] !== 0) {
            throw new \RuntimeException('Diff comparator failed to detect remediated runtime');
        }
        $diffText = (new Diff())->render(array('before' => $data, 'after' => $afterData));
        if (strpos($diffText, '[+] REMEDIATED:') === false) {
            throw new \RuntimeException('Diff renderer text missing [+] REMEDIATED block');
        }

        return true;
    }
}
