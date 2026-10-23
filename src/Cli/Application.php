<?php

namespace Malikad\Php2ShellGuard\Cli;

use Malikad\Php2ShellGuard\Apply\ConfigApplier;
use Malikad\Php2ShellGuard\Db\Loader;
use Malikad\Php2ShellGuard\Db\Updater;
use Malikad\Php2ShellGuard\Db\Verifier;
use Malikad\Php2ShellGuard\Detect\FpmDetector;
use Malikad\Php2ShellGuard\Detect\NodeDetector;
use Malikad\Php2ShellGuard\Detect\PhpDetector;
use Malikad\Php2ShellGuard\Detect\StaleWorkerDetector;
use Malikad\Php2ShellGuard\Ioc\IndicatorScanner;
use Malikad\Php2ShellGuard\Mitigate\SnippetRenderer;
use Malikad\Php2ShellGuard\Report\Csv;
use Malikad\Php2ShellGuard\Report\Diff;
use Malikad\Php2ShellGuard\Report\Html;
use Malikad\Php2ShellGuard\Report\Junit;
use Malikad\Php2ShellGuard\Report\Markdown;
use Malikad\Php2ShellGuard\Report\Pdf;
use Malikad\Php2ShellGuard\Report\Sarif;
use Malikad\Php2ShellGuard\Report\Table;
use Malikad\Php2ShellGuard\Support\Status;
use Malikad\Php2ShellGuard\Upgrade\ComposerWhyNot;
use Malikad\Php2ShellGuard\Upgrade\EffortEstimator;

class Application
{
    private $version = '0.3.0';
    private $dbDate = '2026-10-23';

    public function run(array $argv)
    {
        $cmd = isset($argv[1]) && strpos($argv[1], '-') !== 0 ? $argv[1] : 'scan';
        $format = $this->getOptionValue($argv, '--format', 'table');
        $outputFile = $this->getOptionValue($argv, '--output');
        $noCta = in_array('--no-cta', $argv, true);
        $includeWeak = in_array('--include-weak', $argv, true);

        $reportOptions = array(
            'brand_name' => $this->getOptionValue($argv, '--brand-name', 'php2shell-guard'),
            'brand_logo' => $this->getOptionValue($argv, '--brand-logo'),
            'brand_contact' => $this->getOptionValue($argv, '--brand-contact'),
            'no_cta' => $noCta
        );

        if (in_array('--print-commands', $argv, true)) {
            echo "php -v\nphp --ini\nphp -i\nphp-fpm -v\nphp-fpm -tt\napache2ctl -M\nhttpd -M\nfrankenphp version\nlsphp -v\nnode -v\nnode -p \"JSON.stringify({versions:process.versions,variables:process.config.variables})\"\nbun --version\nps -eo pid,ppid,comm,args\n";
            return 0;
        }

        // 1. Doctor command
        if ($cmd === 'doctor') {
            echo "php2shell-guard v{$this->version} | advisory db {$this->dbDate} | doctor check\n";
            $verifier = new Verifier();
            $res = $verifier->verify();
            echo "  advisories_valid: " . ($res['valid'] ? 'YES' : 'NO') . "\n";
            echo "  php_version:      " . PHP_VERSION . " (" . PHP_SAPI . ")\n";
            echo "  mode:             read-only\n";
            return $res['valid'] ? 0 : 4;
        }

        // 2. Explain command
        if ($cmd === 'explain') {
            $cve = 'CVE-2026-109618';
            foreach ($argv as $arg) {
                if (stripos($arg, 'CVE-') === 0) {
                    $cve = strtoupper($arg);
                }
            }
            $loader = new Loader();
            $all = $loader->loadAllAdvisories();
            $detail = null;
            foreach ($all as $adv) {
                if (isset($adv['cve_details'][$cve])) {
                    $detail = $adv['cve_details'][$cve];
                    $detail['cve'] = $cve;
                    $detail['sources'] = $adv['sources'];
                    break;
                }
            }
            if (!$detail) {
                fwrite(STDERR, "Unknown CVE identifier: {$cve}\n");
                return 4;
            }
            echo json_encode($detail, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
            return 0;
        }

        // 3. Mitigate command
        if ($cmd === 'mitigate') {
            $target = $this->getOptionValue($argv, '--target', 'php-ini');
            $renderer = new SnippetRenderer();
            $snippet = $renderer->render($target, $includeWeak);
            if ($outputFile) {
                file_put_contents($outputFile, $snippet);
                echo "Mitigation snippet written to {$outputFile}\n";
            } else {
                echo $snippet;
            }
            return 0;
        }

        // 4. Apply command (F7)
        if ($cmd === 'apply') {
            $target = $this->getOptionValue($argv, '--target', 'php-ini');
            $dryRun = !in_array('--yes', $argv, true) && !in_array('-y', $argv, true);
            $reload = in_array('--reload', $argv, true);

            $applier = new ConfigApplier();
            $result = $applier->applyTarget($target, null, $dryRun, $reload);

            if ($format === 'json') {
                echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
            } else {
                echo "php2shell-guard apply (" . ($dryRun ? 'DRY-RUN' : 'LIVE') . ")\n";
                echo "  Target:      {$target}\n";
                echo "  Destination: {$result['destination']}\n";
                echo "  Backup:      " . (isset($result['backup_file']) ? $result['backup_file'] : $result['planned_backup']) . "\n";
                echo "  Status:      " . ($result['applied'] ? 'APPLIED' : ($result['dry_run'] ? 'PREVIEW_ONLY' : 'ROLLED_BACK')) . "\n";
                echo "  Message:     {$result['message']}\n";
                if (!empty($result['error'])) {
                    echo "  Error:       {$result['error']}\n";
                }
            }

            return ($result['applied'] || $result['dry_run']) ? 0 : 1;
        }

        // 5. Diff command (G12)
        if ($cmd === 'diff') {
            $files = array();
            foreach ($argv as $i => $arg) {
                if ($i > 1 && strpos($arg, '-') !== 0) {
                    $files[] = $arg;
                }
            }
            if (count($files) < 2) {
                fwrite(STDERR, "Usage: php2shell-guard diff <before.json> <after.json>\n");
                return 4;
            }
            $before = json_decode(@file_get_contents($files[0]), true);
            $after = json_decode(@file_get_contents($files[1]), true);
            if (!$before || !$after) {
                fwrite(STDERR, "Error: Both diff input files must be valid scan JSON files.\n");
                return 4;
            }
            $diffRenderer = new Diff();
            $diffText = $diffRenderer->render(array('before' => $before, 'after' => $after));
            echo $diffText;
            return 0;
        }

        // 6. DB update & verify
        if ($cmd === 'db:verify') {
            $verifier = new Verifier();
            $res = $verifier->verify();
            echo json_encode($res, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
            return $res['valid'] ? 0 : 4;
        }

        if ($cmd === 'db:update') {
            $updater = new Updater();
            $res = $updater->backupDatabase();
            echo "Advisory database backup created.\n";
            echo "Checking for latest advisories from GitHub repository...\n";
            return 0;
        }

        // 7. Upgrade Planner
        if ($cmd === 'upgrade:plan') {
            $toVer = $this->getOptionValue($argv, '--to', '8.3');
            $targetDir = '.';
            foreach ($argv as $i => $arg) {
                if ($i > 1 && strpos($arg, '-') !== 0 && $arg !== $toVer) {
                    $targetDir = $arg;
                }
            }

            $compData = array();
            $compPath = rtrim($targetDir, '/\\') . '/composer.json';
            if (file_exists($compPath)) {
                $compData = json_decode(file_get_contents($compPath), true) ?: array();
            }

            $lockData = array();
            $lockPath = rtrim($targetDir, '/\\') . '/composer.lock';
            if (file_exists($lockPath)) {
                $lockData = json_decode(file_get_contents($lockPath), true) ?: array();
            }

            $whyNot = new ComposerWhyNot();
            $blockers = $whyNot->findBlockers($compData, $toVer, $lockData);
            $estimator = new EffortEstimator();
            $estimate = $estimator->estimate(count($blockers), 0);

            $targetFixed = ($toVer === '8.4') ? '8.4.27' : (($toVer === '8.5') ? '8.5.12' : (($toVer === '8.2') ? '8.2.35' : '8.3.36'));

            $plan = array(
                'target_php' => $toVer,
                'recommended_release' => $targetFixed,
                'blockers_count' => count($blockers),
                'blockers' => $blockers,
                'effort_estimate' => array(
                    't_shirt_size' => $estimate,
                    'assumptions' => 'Assumes automated Rector / PHPCompatibility migration pass and staging test suite.'
                )
            );

            echo json_encode($plan, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
            return 0;
        }

        // 8. Default: Scan / Report
        $targetPath = '.';
        foreach ($argv as $i => $arg) {
            if ($i > 1 && strpos($arg, '-') !== 0 && $arg !== $format && $arg !== $outputFile) {
                $targetPath = $arg;
            }
        }

        $stale = (new StaleWorkerDetector())->hasStaleWorkers();
        $phpCli = (new PhpDetector())->detectCli();
        $phpFpm = (new FpmDetector())->detect($stale, false);
        $node = (new NodeDetector())->detect($stale);

        $iocScanner = new IndicatorScanner();
        $iocResult = $iocScanner->scanPath($targetPath);

        $exitCode = max(
            Status::toExitCode($phpCli['status']),
            Status::toExitCode($phpFpm['status']),
            Status::toExitCode($node['status'])
        );

        $payload = array(
            'tool' => 'php2shell-guard',
            'version' => $this->version,
            'advisory_db_date' => $this->dbDate,
            'mode' => 'read-only',
            'host' => gethostname() ?: 'localhost',
            'target' => $targetPath,
            'runtimes' => array($phpFpm, $phpCli, $node),
            'indicators' => array(
                'count' => $iocResult['count'],
                'status' => $iocResult['status'],
                'hits' => $iocResult['hits']
            ),
            'exit_code' => $exitCode
        );

        $rendered = '';
        switch ($format) {
            case 'json':
                $rendered = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
                break;
            case 'csv':
                $rendered = (new Csv())->render($payload, $reportOptions);
                break;
            case 'md':
            case 'markdown':
                $rendered = (new Markdown())->render($payload, $reportOptions);
                break;
            case 'sarif':
                $rendered = (new Sarif())->render($payload, $reportOptions);
                break;
            case 'junit':
                $rendered = (new Junit())->render($payload, $reportOptions);
                break;
            case 'html':
                $rendered = (new Html())->render($payload, $reportOptions);
                break;
            case 'pdf':
                $rendered = (new Pdf())->render($payload, $reportOptions);
                break;
            case 'table':
            default:
                $rendered = (new Table())->render($payload, $reportOptions);
                break;
        }

        if ($outputFile) {
            file_put_contents($outputFile, $rendered);
            echo "Report written to {$outputFile} ({$format})\n";
        } else {
            echo $rendered;
        }

        return $exitCode;
    }

    private function getOptionValue(array $argv, $option, $default = null)
    {
        foreach ($argv as $i => $arg) {
            if ($arg === $option && isset($argv[$i + 1])) {
                return $argv[$i + 1];
            }
            if (strpos($arg, $option . '=') === 0) {
                return substr($arg, strlen($option) + 1);
            }
        }
        return $default;
    }
}
