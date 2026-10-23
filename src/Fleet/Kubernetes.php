<?php

namespace Malikad\Php2ShellGuard\Fleet;

use Malikad\Php2ShellGuard\Support\VersionComparator;

class Kubernetes
{
    public function getReadOnlyCommands()
    {
        return array(
            'kubectl get pods -A -o json',
            'kubectl get deployments -A -o json'
        );
    }

    public function scanCluster($namespace = null)
    {
        if (!function_exists('exec')) {
            return array('error' => 'exec() disabled');
        }

        $cmd = $namespace
            ? sprintf('kubectl get pods -n %s -o json 2>&1', escapeshellarg($namespace))
            : 'kubectl get pods -A -o json 2>&1';

        $output = array();
        $ret = 0;
        @exec($cmd, $output, $ret);

        if ($ret !== 0) {
            return array(
                'available' => false,
                'error' => implode("\n", $output),
                'findings' => array()
            );
        }

        $json = json_decode(implode("\n", $output), true);
        if (!$json || !isset($json['items'])) {
            return array('available' => true, 'findings' => array());
        }

        $findings = array();
        foreach ($json['items'] as $pod) {
            $podName = isset($pod['metadata']['name']) ? $pod['metadata']['name'] : 'pod';
            $podNs = isset($pod['metadata']['namespace']) ? $pod['metadata']['namespace'] : 'default';
            $containers = isset($pod['spec']['containers']) ? $pod['spec']['containers'] : array();

            foreach ($containers as $c) {
                $image = isset($c['image']) ? $c['image'] : '';
                $sem = VersionComparator::extractSemver($image);
                $status = 'NOT_DETECTED';
                $fixed = 'none';

                if (preg_match('/php/i', $image) && $sem) {
                    $ev = VersionComparator::evaluatePhp($sem);
                    $status = $ev['status'];
                    $fixed = $ev['fixed'];
                } elseif (preg_match('/node/i', $image) && $sem) {
                    $ev = VersionComparator::evaluateNode($sem);
                    $status = $ev['status'];
                    $fixed = $ev['fixed'];
                }

                $findings[] = array(
                    'namespace' => $podNs,
                    'pod' => $podName,
                    'container' => isset($c['name']) ? $c['name'] : 'container',
                    'image' => $image,
                    'status' => $status,
                    'fixed_version' => $fixed
                );
            }
        }

        return array(
            'available' => true,
            'pod_count' => count($json['items']),
            'findings' => $findings
        );
    }
}
