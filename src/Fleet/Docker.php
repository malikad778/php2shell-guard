<?php

namespace Malikad\Php2ShellGuard\Fleet;

use Malikad\Php2ShellGuard\Support\VersionComparator;

class Docker
{
    public function getReadOnlyCommands()
    {
        return array(
            'docker ps --format "{{json .}}"',
            'docker inspect <container_id>',
            'docker images --format "{{json .}}"'
        );
    }

    public function scanHostContainers()
    {
        if (!function_exists('exec')) {
            return array('error' => 'exec() function disabled');
        }

        $output = array();
        $ret = 0;
        @exec('docker ps --format "{{json .}}" 2>&1', $output, $ret);

        if ($ret !== 0) {
            return array(
                'available' => false,
                'error' => implode("\n", $output),
                'containers' => array()
            );
        }

        $findings = array();
        foreach ($output as $line) {
            $c = json_decode(trim($line), true);
            if (!$c || !isset($c['ID'])) {
                continue;
            }

            $cid = $c['ID'];
            $image = isset($c['Image']) ? $c['Image'] : '';
            $names = isset($c['Names']) ? $c['Names'] : $cid;

            // Extract php / node version from image tag if obvious
            $status = 'UNKNOWN';
            $fixed = 'none';
            $semver = VersionComparator::extractSemver($image);

            if (preg_match('/php/i', $image)) {
                if ($semver) {
                    $ev = VersionComparator::evaluatePhp($semver);
                    $status = $ev['status'];
                    $fixed = $ev['fixed'];
                }
            } elseif (preg_match('/node/i', $image)) {
                if ($semver) {
                    $ev = VersionComparator::evaluateNode($semver);
                    $status = $ev['status'];
                    $fixed = $ev['fixed'];
                }
            }

            $findings[] = array(
                'container_id' => $cid,
                'name' => $names,
                'image' => $image,
                'status' => $status,
                'fixed_version' => $fixed,
                'raw' => $c
            );
        }

        return array(
            'available' => true,
            'container_count' => count($findings),
            'containers' => $findings
        );
    }
}
