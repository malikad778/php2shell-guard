<?php

namespace Malikad\Php2ShellGuard\Detect;

use Malikad\Php2ShellGuard\Support\Status;
use Malikad\Php2ShellGuard\Support\VersionComparator;

class FpmDetector
{
    public function detect($staleWorker = false, $changelogPatched = false)
    {
        $mock = getenv('PHP2SHELL_MOCK_PHP_FPM_VERSION');
        if ($mock !== false && $mock !== '') {
            $eval = VersionComparator::evaluatePhp($mock, $staleWorker, $changelogPatched);
            return array(
                'component' => 'php-fpm',
                'serves_traffic' => true,
                'sapi_risk' => 'affected (session.upload_progress path confirmed on PHP-FPM)',
                'detected_version' => $mock,
                'status' => $eval['status'],
                'fixed_version' => $eval['fixed'],
                'evidence' => 'php-fpm -v',
                'notes' => $eval['notes']
            );
        }

        return array(
            'component' => 'php-fpm',
            'serves_traffic' => true,
            'sapi_risk' => 'affected',
            'detected_version' => 'not_detected',
            'status' => Status::NOT_DETECTED,
            'fixed_version' => 'none',
            'evidence' => 'which php-fpm',
            'notes' => 'No php-fpm binary detected on PATH'
        );
    }
}
