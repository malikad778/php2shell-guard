<?php

namespace Malikad\Php2ShellGuard\Laravel;

use Malikad\Php2ShellGuard\Detect\PhpDetector;
use Malikad\Php2ShellGuard\Detect\FpmDetector;
use Malikad\Php2ShellGuard\Detect\NodeDetector;
use Malikad\Php2ShellGuard\Support\Status;

if (!class_exists('Illuminate\Console\Command')) {
    abstract class BaseCommand
    {
        protected $signature;
        protected $description;
        public function info($string) { echo $string . "\n"; }
        public function error($string) { echo "ERROR: " . $string . "\n"; }
        public function warn($string) { echo "WARN: " . $string . "\n"; }
        public function table(array $headers, array $rows) {}
        public function option($key) { return null; }
    }
} else {
    class_alias('Illuminate\Console\Command', 'Malikad\Php2ShellGuard\Laravel\BaseCommand');
}

class Command extends BaseCommand
{
    protected $signature = 'php2shell:audit {--format=table : Output format (table, json)} {--no-cta : Omit footer contact link}';
    protected $description = 'Audit PHP and Node runtimes and INI settings against PHP2Shell (CVE-2026-109618, CVE-2026-109619)';

    public function handle()
    {
        $this->info('Running php2shell-guard runtime audit...');

        $phpCli = (new PhpDetector())->detectCli();
        $phpFpm = (new FpmDetector())->detect(false, false);
        $node = (new NodeDetector())->detect(false);

        $exitCode = max(
            Status::toExitCode($phpCli['status']),
            Status::toExitCode($phpFpm['status']),
            Status::toExitCode($node['status'])
        );

        $headers = array('Component', 'Detected Version', 'Status', 'Fixed Version');
        $rows = array(
            array($phpCli['component'], $phpCli['detected_version'], $phpCli['status'], $phpCli['fixed_version']),
            array($phpFpm['component'], $phpFpm['detected_version'], $phpFpm['status'], $phpFpm['fixed_version']),
            array($node['component'], $node['detected_version'], $node['status'], $node['fixed_version']),
        );

        if (method_exists($this, 'table')) {
            $this->table($headers, $rows);
        }

        if ($exitCode === 0) {
            $this->info('Audit completed: All detected runtimes meet or exceed patched releases.');
        } else {
            $this->warn('Audit completed with findings: Upstream patches or worker restarts are required.');
        }

        return $exitCode;
    }
}
