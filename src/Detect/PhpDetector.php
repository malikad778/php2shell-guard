<?php

namespace Malikad\Php2ShellGuard\Detect;

use Malikad\Php2ShellGuard\Support\VersionComparator;

class PhpDetector
{
    public function detectCli()
    {
        $ver = getenv('PHP2SHELL_MOCK_PHP_CLI_VERSION') ?: PHP_VERSION;
        $eval = VersionComparator::evaluatePhp($ver, false, false);
        return array(
            'component' => 'php-cli',
            'serves_traffic' => false,
            'sapi_risk' => 'low (CLI does not serve web traffic unless running an HTTP worker loop)',
            'detected_version' => $ver,
            'status' => $eval['status'],
            'fixed_version' => $eval['fixed'],
            'evidence' => 'PHP_VERSION (' . PHP_SAPI . ')',
            'notes' => $eval['notes']
        );
    }
}
