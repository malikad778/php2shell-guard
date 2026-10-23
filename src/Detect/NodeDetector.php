<?php

namespace Malikad\Php2ShellGuard\Detect;

use Malikad\Php2ShellGuard\Support\Status;
use Malikad\Php2ShellGuard\Support\VersionComparator;

class NodeDetector
{
    public function detect($staleWorker = false)
    {
        $ver = getenv('PHP2SHELL_MOCK_NODE_VERSION');
        if ($ver === false || $ver === '') {
            $nullDev = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
            $out = @shell_exec("node -v 2>{$nullDev}");
            $ver = is_string($out) ? trim($out) : '';
        }
        if ($ver === '') {
            return array(
                'component' => 'nodejs',
                'serves_traffic' => true,
                'detected_version' => 'not_detected',
                'status' => Status::NOT_DETECTED,
                'fixed_version' => 'none',
                'evidence' => 'node -v',
                'notes' => 'Node.js runtime not detected'
            );
        }
        $eval = VersionComparator::evaluateNode($ver, $staleWorker);
        return array(
            'component' => 'nodejs',
            'serves_traffic' => true,
            'detected_version' => $ver,
            'status' => $eval['status'],
            'fixed_version' => $eval['fixed'],
            'evidence' => 'node -v',
            'notes' => $eval['notes']
        );
    }
}
