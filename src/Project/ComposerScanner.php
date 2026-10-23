<?php

namespace Malikad\Php2ShellGuard\Project;

use Malikad\Php2ShellGuard\Support\VersionComparator;

class ComposerScanner
{
    public function scanJson($jsonText)
    {
        $data = json_decode($jsonText, true);
        if (!is_array($data)) {
            return array();
        }
        $findings = array();
        if (isset($data['config']['platform']['php'])) {
            $plat = $data['config']['platform']['php'];
            $ver = substr_count($plat, '.') === 1 ? $plat . '.0' : $plat;
            $eval = VersionComparator::evaluatePhp($ver);
            $findings[] = array(
                'source' => 'composer.json:config.platform.php',
                'version' => $plat,
                'status' => $eval['status'],
                'fixed' => $eval['fixed'],
                'notes' => $eval['notes']
            );
        }
        return $findings;
    }
}
